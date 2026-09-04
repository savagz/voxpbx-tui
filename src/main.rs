mod ami;
mod app;
mod config;
mod deps;
mod event;
mod keys;
mod logging;
mod setup;
mod sip_capture;
mod sysmon;
mod theme;
mod ui;

use std::time::Duration;

use app::{App, PendingAction, Reload};
use color_eyre::Result;
use config::{AmiConfig, Config};
use crossterm::event::{Event, EventStream};
use event::AppEvent;
use futures_util::StreamExt;
use setup::{SetupForm, SetupMode, SetupOutcome};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::warn;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let _log_guard = logging::init()?;

    let mut terminal = ratatui::init();
    let result = run(&mut terminal).await;
    ratatui::restore();
    result
}

async fn run(terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<AppEvent>(100);
    let mut input = Input::new(tx.clone());
    input.start();
    spawn_signal_task(tx.clone());

    // Primer arranque (o config ilegible): la app pide los datos de Asterisk
    // antes de levantar ninguna tarea de fondo. Una config rota abre el mismo
    // asistente con el motivo a la vista, en vez de matar el proceso.
    let (loaded, load_error) = match Config::load() {
        Ok(config) => (config, None),
        Err(e) => {
            warn!("config ilegible: {e}");
            (None, Some(format!("Config existente ilegible: {e}")))
        }
    };

    let config = match loaded {
        Some(config) => config,
        None => match first_run(terminal, &tx, &mut rx, &mut input, load_error).await? {
            Some(config) => config,
            None => return Ok(()),
        },
    };

    run_app(terminal, config, tx, rx, input).await
}

/// La tarea que lee el teclado tiene que poder pararse: mientras corre `sudo` la
/// terminal es del comando, y dos lectores compitiendo por el mismo tty se comen
/// las teclas del usuario (incluida la contraseña).
struct Input {
    tx: mpsc::Sender<AppEvent>,
    handle: Option<JoinHandle<()>>,
}

impl Input {
    fn new(tx: mpsc::Sender<AppEvent>) -> Self {
        Self { tx, handle: None }
    }

    fn start(&mut self) {
        if self.handle.is_none() {
            self.handle = Some(spawn_input_task(self.tx.clone()));
        }
    }

    fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Asistente de primer arranque: formulario a pantalla completa con los datos de
/// AMI y los chequeos de `libpcap`. Devuelve `None` si el usuario cancela.
async fn first_run(
    terminal: &mut ratatui::DefaultTerminal,
    tx: &mpsc::Sender<AppEvent>,
    rx: &mut mpsc::Receiver<AppEvent>,
    input: &mut Input,
    initial_error: Option<String>,
) -> Result<Option<Config>> {
    let mut form = SetupForm::new(SetupMode::FirstRun, &Config::default());
    form.error = initial_error;
    terminal.draw(|frame| ui::setup::render_fullscreen(frame, &form))?;

    while let Some(event) = rx.recv().await {
        match event {
            AppEvent::Key(key) => match form.on_key(key) {
                SetupOutcome::None => {}
                SetupOutcome::Cancel => return Ok(None),
                SetupOutcome::Recheck => form.recheck(),
                SetupOutcome::TestConnection(ami) => spawn_probe(*ami, tx.clone()),
                SetupOutcome::RunFix(command) => {
                    run_fix(terminal, &command, &mut form, input)
                }
                SetupOutcome::Save(config) => match config.save() {
                    Ok(_) => return Ok(Some(*config)),
                    Err(e) => form.error = Some(format!("No se pudo guardar: {e}")),
                },
            },
            AppEvent::AmiProbeResult(result) => form.on_probe_result(result),
            AppEvent::Shutdown => return Ok(None),
            _ => {}
        }
        terminal.draw(|frame| ui::setup::render_fullscreen(frame, &form))?;
    }

    Ok(None)
}

async fn run_app(
    terminal: &mut ratatui::DefaultTerminal,
    config: Config,
    tx: mpsc::Sender<AppEvent>,
    mut rx: mpsc::Receiver<AppEvent>,
    mut input: Input,
) -> Result<()> {
    let tick_rate = Duration::from_millis(config.ui.tick_rate_ms);

    let (ami_tx, ami_rx) = watch::channel(ami::client::AmiSettings::from_config(&config));
    let (capture_tx, capture_rx) = watch::channel(config.capture.clone());

    spawn_tick_task(tx.clone(), tick_rate);
    ami::client::spawn(ami_rx, tx.clone());
    sysmon::spawn(tx.clone());
    sip_capture::capture::spawn(capture_rx, tx.clone());

    let mut app = App::new(
        config,
        Reload {
            ami: ami_tx,
            capture: capture_tx,
        },
    );

    terminal.draw(|frame| ui::draw(frame, &app))?;

    while let Some(event) = rx.recv().await {
        app.on_event(event);

        if let Some(pending) = app.take_pending() {
            match pending {
                PendingAction::TestConnection(ami) => spawn_probe(*ami, tx.clone()),
                PendingAction::RunFix(command) => {
                    if let Some(form) = app.setup.as_mut() {
                        run_fix(terminal, &command, form, &mut input);
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }
        terminal.draw(|frame| ui::draw(frame, &app))?;
    }

    Ok(())
}

fn spawn_probe(ami: AmiConfig, tx: mpsc::Sender<AppEvent>) {
    tokio::spawn(async move {
        let result = ami::client::probe(&ami).await.map_err(|e| e.to_string());
        let _ = tx.send(AppEvent::AmiProbeResult(result)).await;
    });
}

/// Instalar `libpcap` o dar capabilities necesita que `sudo` hable con la terminal
/// real, así que salimos de la pantalla alterna, corremos el comando a la vista
/// del usuario, y volvemos a entrar re-chequeando el resultado.
fn run_fix(
    terminal: &mut ratatui::DefaultTerminal,
    command: &[String],
    form: &mut SetupForm,
    input: &mut Input,
) {
    input.stop();
    ratatui::restore();

    println!("\n>> {}\n", deps::command_line(command));
    let outcome = deps::run_fix(command);

    println!("\n-- ENTER para volver al panel --");
    let mut discard = String::new();
    let _ = std::io::stdin().read_line(&mut discard);

    *terminal = ratatui::init();
    input.start();

    form.notice = Some(match outcome {
        Ok(true) => "Comando ejecutado correctamente.".to_string(),
        Ok(false) => "El comando terminó con error (ver la salida arriba).".to_string(),
        Err(e) => format!("No se pudo ejecutar el comando: {e}"),
    });
    form.recheck();
}

fn spawn_input_task(tx: mpsc::Sender<AppEvent>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut stream = EventStream::new();
        while let Some(Ok(evt)) = stream.next().await {
            if let Event::Key(key) = evt
                && tx.send(AppEvent::Key(key)).await.is_err()
            {
                break;
            }
        }
    })
}

fn spawn_tick_task(tx: mpsc::Sender<AppEvent>, tick_rate: Duration) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tick_rate);
        loop {
            interval.tick().await;
            if tx.send(AppEvent::Tick).await.is_err() {
                break;
            }
        }
    });
}

/// SIGTERM (systemd stop, `kill`, cierre de sesión) no llega como KeyEvent de
/// crossterm: sin este handler el proceso muere antes de restaurar la terminal.
fn spawn_signal_task(tx: mpsc::Sender<AppEvent>) {
    tokio::spawn(async move {
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => return,
            };
        sigterm.recv().await;
        let _ = tx.send(AppEvent::Shutdown).await;
    });
}
