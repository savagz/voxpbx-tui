pub mod setup;
pub mod tabs;
pub mod widgets;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    widgets::Block,
};

use crate::app::App;
use tabs::Tab;

const SIDEBAR_WIDTH: u16 = 24;
const HEADER_HEIGHT: u16 = 3;

pub fn draw(frame: &mut Frame, app: &App) {
    // Fondo de chapa uniforme: sin esto los huecos entre paneles muestran el color
    // por defecto de la terminal y se rompe la ilusión de frente metálico.
    frame.render_widget(Block::default().style(app.theme.base_style()), frame.area());

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(HEADER_HEIGHT),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(frame.area());

    widgets::header::render(frame, rows[0], app);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(SIDEBAR_WIDTH), Constraint::Min(0)])
        .split(rows[1]);

    widgets::sidebar::render(frame, cols[0], app);
    draw_body(frame, cols[1], app);
    widgets::help_bar::render(frame, rows[2], app);

    if let Some(form) = &app.setup {
        setup::render_overlay(frame, frame.area(), form, &app.theme);
    }
}

fn draw_body(frame: &mut Frame, area: Rect, app: &App) {
    match app.active_tab {
        Tab::Overview => tabs::overview::render(frame, area, app),
        Tab::Calls => tabs::calls::render(frame, area, app),
        Tab::Extensions => tabs::extensions::render(frame, area, app),
        Tab::Queues => tabs::queues::render(frame, area, app),
        Tab::SipTrace => tabs::sip_trace::render(frame, area, app),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Reload;
    use crate::config::Config;
    use crate::setup::{SetupForm, SetupMode};
    use ratatui::{Terminal, backend::TestBackend};
    use tokio::sync::watch;

    fn app() -> App {
        let config = Config::default();
        let (ami, _ami_rx) = watch::channel(crate::ami::client::AmiSettings::from_config(&config));
        let (capture, _capture_rx) = watch::channel(config.capture.clone());
        App::new(config, Reload { ami, capture })
    }

    /// El tablero se dibuja en terminales chicas sin panics de layout: los
    /// paneles industriales usan restas de ancho que hay que mantener saturadas.
    #[test]
    fn dibuja_el_tablero_en_varios_tamanos() {
        let app = app();
        for (w, h) in [(120, 40), (80, 24), (40, 12), (20, 6)] {
            let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
            terminal.draw(|frame| draw(frame, &app)).unwrap();
        }
    }

    #[test]
    fn dibuja_el_asistente_en_varios_tamanos() {
        let form = SetupForm::new(SetupMode::FirstRun, &Config::default());
        for (w, h) in [(120, 40), (80, 24), (60, 20)] {
            let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
            terminal
                .draw(|frame| setup::render_fullscreen(frame, &form))
                .unwrap();
        }
    }

    #[test]
    fn dibuja_el_overlay_de_configuracion_sobre_el_tablero() {
        let mut app = app();
        app.setup = Some(SetupForm::new(SetupMode::Edit, &app.config));
        let mut terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
    }
}
