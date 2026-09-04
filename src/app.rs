use std::collections::VecDeque;

use chrono::Local;
use crossterm::event::{KeyEvent, KeyEventKind};
use tokio::sync::watch;

use crate::ami::client::AmiSettings;
use crate::ami::{Channel, ConnState, CoreStatus, Peer, Queue};
use crate::config::{AmiConfig, CaptureConfig, Config};
use crate::event::AppEvent;
use crate::keys::{self, AppAction};
use crate::setup::{SetupForm, SetupMode, SetupOutcome};
use crate::sip_capture::CaptureStatus;
use crate::sip_capture::analysis::{self, TraceSummary};
use crate::sip_capture::packet::SipPacketRecord;
use crate::sysmon::snapshot::HostSnapshot;
use crate::theme::{Status, Theme};
use crate::ui::tabs::Tab;

const SIP_PACKET_CAP: usize = 2000;

/// Canales de recarga en caliente hacia las tareas de fondo. Guardar en el panel
/// de configuración empuja la config nueva por acá: la conexión AMI y la captura
/// se rehacen solas, sin reiniciar el proceso.
pub struct Reload {
    pub ami: watch::Sender<AmiSettings>,
    pub capture: watch::Sender<CaptureConfig>,
}

/// Trabajo que el bucle principal tiene que hacer fuera de `App` porque necesita
/// async (probar AMI) o adueñarse de la terminal (correr `sudo`).
#[derive(Debug, Clone)]
pub enum PendingAction {
    TestConnection(Box<AmiConfig>),
    RunFix(Vec<String>),
}

pub struct App {
    pub should_quit: bool,
    pub active_tab: Tab,
    pub theme: Theme,
    pub config: Config,
    pub reload: Reload,
    /// Panel de configuración abierto sobre la TUI (`c`).
    pub setup: Option<SetupForm>,
    pub pending: Option<PendingAction>,
    pub toast: Option<(String, Status)>,
    pub ami_conn_state: ConnState,
    pub core_status: Option<CoreStatus>,
    pub channels: Vec<Channel>,
    pub peers: Vec<Peer>,
    pub queues: Vec<Queue>,
    pub host: HostSnapshot,
    pub sip_packets: VecDeque<SipPacketRecord>,
    pub sip_capture_error: Option<String>,
    pub sip_capture_status: Option<CaptureStatus>,
    pub sip_filter_index: Option<usize>,
    pub sip_selected_row: usize,
    /// La lista de SIP Trace sigue al último paquete capturado. Se apaga al
    /// navegar a mano (si no, el cursor pelearía contra el tráfico entrante).
    pub sip_follow: bool,
    pub sip_trace_active: bool,
    pub sip_trace_started_at: Option<chrono::DateTime<Local>>,
    pub sip_trace_summary: Option<TraceSummary>,
}

impl App {
    pub fn new(config: Config, reload: Reload) -> Self {
        Self {
            should_quit: false,
            active_tab: Tab::default(),
            theme: Theme::default(),
            config,
            reload,
            setup: None,
            pending: None,
            toast: None,
            ami_conn_state: ConnState::default(),
            core_status: None,
            channels: Vec::new(),
            peers: Vec::new(),
            queues: Vec::new(),
            host: HostSnapshot::default(),
            sip_packets: VecDeque::with_capacity(SIP_PACKET_CAP),
            sip_capture_error: None,
            sip_capture_status: None,
            sip_filter_index: None,
            sip_selected_row: 0,
            sip_follow: true,
            sip_trace_active: false,
            sip_trace_started_at: None,
            sip_trace_summary: None,
        }
    }

    pub fn take_pending(&mut self) -> Option<PendingAction> {
        self.pending.take()
    }

    pub fn on_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::Key(key) => self.on_key(key),
            AppEvent::Tick => {}
            AppEvent::AmiConnState(state) => self.ami_conn_state = state,
            AppEvent::CoreStatusUpdated(status) => self.core_status = Some(status),
            AppEvent::ChannelsUpdated(channels) => self.channels = channels,
            AppEvent::PeersUpdated(peers) => self.peers = peers,
            AppEvent::QueuesUpdated(queues) => self.queues = queues,
            AppEvent::SysSnapshot(snapshot) => self.host = snapshot,
            AppEvent::SipPacket(record) => self.on_sip_packet(record),
            AppEvent::SipCaptureError(err) => {
                self.sip_capture_error = Some(err);
                self.sip_capture_status = None;
            }
            AppEvent::SipCaptureStatus(status) => {
                self.sip_capture_error = None;
                self.sip_capture_status = Some(status);
            }
            AppEvent::AmiProbeResult(result) => {
                if let Some(setup) = self.setup.as_mut() {
                    setup.on_probe_result(result);
                }
            }
            AppEvent::Shutdown => self.should_quit = true,
            AppEvent::AmiEventRaw(_) => {}
        }
    }

    fn on_sip_packet(&mut self, record: Box<SipPacketRecord>) {
        if self.sip_packets.len() == SIP_PACKET_CAP {
            self.sip_packets.pop_front();
        }
        self.sip_packets.push_back(*record);
    }

    fn on_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        if self.setup.is_some() {
            self.on_setup_key(key);
            return;
        }

        self.toast = None;

        match keys::action_for(key) {
            Some(AppAction::Quit) => self.should_quit = true,
            Some(AppAction::OpenConfig) => {
                self.setup = Some(SetupForm::new(SetupMode::Edit, &self.config));
            }
            Some(AppAction::NextTab) => self.active_tab = self.active_tab.next(),
            Some(AppAction::PrevTab) => self.active_tab = self.active_tab.prev(),
            Some(AppAction::Up) if self.active_tab == Tab::SipTrace => {
                self.sip_follow = false;
                self.sip_selected_row = self.sip_selected_row.saturating_sub(1);
            }
            Some(AppAction::Down) if self.active_tab == Tab::SipTrace => {
                self.sip_follow = false;
                self.sip_selected_row = self.sip_selected_row.saturating_add(1);
            }
            Some(AppAction::Top) if self.active_tab == Tab::SipTrace => {
                self.sip_follow = false;
                self.sip_selected_row = 0;
            }
            Some(AppAction::Follow) if self.active_tab == Tab::SipTrace => {
                self.sip_follow = true;
            }
            Some(AppAction::CycleSipFilter)
                if self.active_tab == Tab::SipTrace && !self.sip_trace_active =>
            {
                self.cycle_sip_filter();
            }
            Some(AppAction::ToggleSipTraceCapture) if self.active_tab == Tab::SipTrace => {
                self.toggle_sip_trace_capture();
            }
            _ => {}
        }
    }

    fn on_setup_key(&mut self, key: KeyEvent) {
        let Some(setup) = self.setup.as_mut() else {
            return;
        };

        match setup.on_key(key) {
            SetupOutcome::None => {}
            SetupOutcome::Cancel => self.setup = None,
            SetupOutcome::Recheck => setup.recheck(),
            SetupOutcome::TestConnection(ami) => {
                self.pending = Some(PendingAction::TestConnection(ami));
            }
            SetupOutcome::RunFix(command) => {
                self.pending = Some(PendingAction::RunFix(command));
            }
            SetupOutcome::Save(config) => self.apply_config(*config),
        }
    }

    /// Guarda en disco y empuja la config nueva a las tareas de fondo. Si el
    /// guardado falla, el panel queda abierto mostrando el motivo.
    fn apply_config(&mut self, config: Config) {
        match config.save() {
            Ok(path) => {
                let capture_changed = config.capture.interface != self.config.capture.interface
                    || config.capture.sip_ports != self.config.capture.sip_ports
                    || config.capture.enabled != self.config.capture.enabled;

                self.config = config;
                let _ = self.reload.ami.send(AmiSettings::from_config(&self.config));
                let _ = self.reload.capture.send(self.config.capture.clone());

                if capture_changed {
                    self.sip_capture_status = None;
                    self.sip_packets.clear();
                    self.sip_selected_row = 0;
                    self.sip_trace_summary = None;
                    self.sip_trace_active = false;
                }

                self.setup = None;
                self.toast = Some((
                    format!("Configuración guardada en {}", path.display()),
                    Status::Ok,
                ));
            }
            Err(e) => {
                if let Some(setup) = self.setup.as_mut() {
                    setup.error = Some(format!("No se pudo guardar: {e}"));
                }
            }
        }
    }

    /// Cicla el selector de extensión entre las extensiones actualmente conectadas
    /// (registradas en AMI), usado tanto para filtrar la vista como para elegir el
    /// objetivo de una captura de trace en vivo.
    fn cycle_sip_filter(&mut self) {
        let connected: Vec<usize> = self
            .peers
            .iter()
            .enumerate()
            .filter(|(_, p)| p.is_registered())
            .map(|(i, _)| i)
            .collect();

        self.sip_follow = true;
        self.sip_filter_index = match self.sip_filter_index {
            None => connected.first().copied(),
            Some(current) => {
                let pos = connected.iter().position(|&i| i == current);
                match pos {
                    Some(p) if p + 1 < connected.len() => Some(connected[p + 1]),
                    _ => None,
                }
            }
        };
        self.sip_selected_row = 0;
    }

    fn toggle_sip_trace_capture(&mut self) {
        if self.sip_trace_active {
            self.stop_sip_trace_capture();
        } else {
            self.start_sip_trace_capture();
        }
    }

    fn start_sip_trace_capture(&mut self) {
        if self.sip_filter_index.and_then(|i| self.peers.get(i)).is_none() {
            self.cycle_sip_filter();
        }
        if self.sip_filter_index.and_then(|i| self.peers.get(i)).is_none() {
            // No hay ninguna extensión conectada para capturar.
            return;
        }
        self.sip_trace_summary = None;
        self.sip_trace_started_at = Some(Local::now());
        self.sip_trace_active = true;
    }

    fn stop_sip_trace_capture(&mut self) {
        self.sip_trace_active = false;
        let Some(started_at) = self.sip_trace_started_at.take() else {
            return;
        };
        let Some(peer) = self.sip_filter_index.and_then(|i| self.peers.get(i)) else {
            return;
        };
        let stopped_at = Local::now();
        // AMI puede devolver la IP vacía o un placeholder: el análisis sigue
        // siendo posible identificando la extensión por las URIs From/To.
        let ip = peer.ip.parse().ok();
        self.sip_trace_summary = Some(analysis::analyze(
            ip,
            peer.name.clone(),
            started_at,
            stopped_at,
            &self.sip_packets,
        ));
    }
}
