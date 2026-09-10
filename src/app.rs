use std::collections::VecDeque;

use chrono::Local;
use crossterm::event::{KeyEvent, KeyEventKind};
#[cfg(test)]
use crossterm::event::{KeyCode, KeyModifiers};
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
    /// Endpoints PJSIP y peers IAX2, aparte de `peers` (chan_sip) para no alterar
    /// la tab de extensiones. Sólo se combinan en `sip_candidate_peers`, para el
    /// selector F de SIP Trace.
    pub pjsip_peers: Vec<Peer>,
    pub iax_peers: Vec<Peer>,
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
    /// Call-ID de la llamada mostrada en la vista de secuencia (ladder). `None`
    /// = lista plana. Se abre con Enter sobre un paquete, se cierra con Esc.
    pub sip_call_flow: Option<String>,
    /// Índice, dentro de los paquetes de esa llamada, del mensaje resaltado.
    /// Sin clamp acá (igual que `sip_selected_row`): se acota al dibujar.
    pub sip_call_flow_selected: usize,
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
            pjsip_peers: Vec::new(),
            iax_peers: Vec::new(),
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
            sip_call_flow: None,
            sip_call_flow_selected: 0,
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
            AppEvent::PjsipPeersUpdated(peers) => self.pjsip_peers = peers,
            AppEvent::IaxPeersUpdated(peers) => self.iax_peers = peers,
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
                if self.sip_call_flow.is_some() {
                    self.sip_call_flow_selected = self.sip_call_flow_selected.saturating_sub(1);
                } else {
                    self.sip_follow = false;
                    self.sip_selected_row = self.sip_selected_row.saturating_sub(1);
                }
            }
            Some(AppAction::Down) if self.active_tab == Tab::SipTrace => {
                if self.sip_call_flow.is_some() {
                    self.sip_call_flow_selected = self.sip_call_flow_selected.saturating_add(1);
                } else {
                    self.sip_follow = false;
                    self.sip_selected_row = self.sip_selected_row.saturating_add(1);
                }
            }
            Some(AppAction::Top) if self.active_tab == Tab::SipTrace => {
                if self.sip_call_flow.is_some() {
                    self.sip_call_flow_selected = 0;
                } else {
                    self.sip_follow = false;
                    self.sip_selected_row = 0;
                }
            }
            Some(AppAction::Follow) if self.active_tab == Tab::SipTrace => {
                if self.sip_call_flow.is_some() {
                    self.sip_call_flow_selected = self.sip_call_flow_packets().len().saturating_sub(1);
                } else {
                    self.sip_follow = true;
                }
            }
            Some(AppAction::CycleSipFilter)
                if self.active_tab == Tab::SipTrace
                    && !self.sip_trace_active
                    && self.sip_call_flow.is_none() =>
            {
                self.cycle_sip_filter();
            }
            Some(AppAction::ToggleSipTraceCapture)
                if self.active_tab == Tab::SipTrace && self.sip_call_flow.is_none() =>
            {
                self.toggle_sip_trace_capture();
            }
            Some(AppAction::ClearSipTrace)
                if self.active_tab == Tab::SipTrace && !self.sip_trace_active =>
            {
                self.clear_sip_trace();
            }
            Some(AppAction::OpenCallFlow)
                if self.active_tab == Tab::SipTrace && self.sip_call_flow.is_none() =>
            {
                self.open_call_flow();
            }
            Some(AppAction::CloseCallFlow) if self.sip_call_flow.is_some() => {
                self.sip_call_flow = None;
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

    /// Extensiones candidatas al selector de SIP Trace: chan_sip + PJSIP + IAX2
    /// combinadas. Van clonadas (listas chicas, decenas de entradas) para no
    /// atarse a los tres `Vec` fuente al indexar.
    pub fn sip_candidate_peers(&self) -> Vec<Peer> {
        self.peers
            .iter()
            .chain(self.pjsip_peers.iter())
            .chain(self.iax_peers.iter())
            .cloned()
            .collect()
    }

    /// Extensión actualmente elegida por el selector F, si hay alguna.
    pub fn sip_selected_peer(&self) -> Option<Peer> {
        self.sip_filter_index
            .and_then(|i| self.sip_candidate_peers().into_iter().nth(i))
    }

    /// Paquetes SIP visibles con el filtro de extensión actual — la misma lista
    /// que dibuja la tabla del tab, para que la selección de teclado y el
    /// render nunca vean cosas distintas.
    pub fn sip_filtered_packets(&self) -> Vec<&SipPacketRecord> {
        match self.sip_selected_peer() {
            Some(peer) => {
                let ip = peer.ip.parse().ok();
                self.sip_packets
                    .iter()
                    .filter(|p| p.involves(ip, &peer.name))
                    .collect()
            }
            None => self.sip_packets.iter().collect(),
        }
    }

    /// Paquete resaltado en la lista plana (respeta seguimiento en vivo).
    pub fn sip_selected_packet(&self) -> Option<&SipPacketRecord> {
        let packets = self.sip_filtered_packets();
        let last = packets.len().checked_sub(1)?;
        let idx = if self.sip_follow { last } else { self.sip_selected_row.min(last) };
        packets.into_iter().nth(idx)
    }

    /// Todos los paquetes de la llamada abierta en la vista de secuencia, en
    /// orden de llegada (ya vienen así en `sip_packets`).
    pub fn sip_call_flow_packets(&self) -> Vec<&SipPacketRecord> {
        match &self.sip_call_flow {
            Some(call_id) => self.sip_packets.iter().filter(|p| &p.call_id == call_id).collect(),
            None => Vec::new(),
        }
    }

    fn clear_sip_trace(&mut self) {
        self.sip_packets.clear();
        self.sip_selected_row = 0;
        self.sip_follow = true;
        self.sip_call_flow = None;
        self.sip_call_flow_selected = 0;
        self.sip_trace_summary = None;
    }

    /// Abre la vista de secuencia en la llamada del paquete actualmente
    /// resaltado, con ese mismo mensaje ya seleccionado adentro.
    fn open_call_flow(&mut self) {
        let Some(selected) = self.sip_selected_packet() else {
            return;
        };
        let call_id = selected.call_id.clone();
        let selected_id = selected.id;
        let idx = self
            .sip_packets
            .iter()
            .filter(|p| p.call_id == call_id)
            .position(|p| p.id == selected_id)
            .unwrap_or(0);
        self.sip_call_flow = Some(call_id);
        self.sip_call_flow_selected = idx;
    }

    /// Cicla el selector de extensión entre las extensiones actualmente conectadas
    /// (registradas en AMI, en cualquiera de las tres tech), usado tanto para
    /// filtrar la vista como para elegir el objetivo de una captura de trace en vivo.
    fn cycle_sip_filter(&mut self) {
        let candidates = self.sip_candidate_peers();
        let connected: Vec<usize> = candidates
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
        if self.sip_selected_peer().is_none() {
            self.cycle_sip_filter();
        }
        if self.sip_selected_peer().is_none() {
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
        let Some(peer) = self.sip_selected_peer() else {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip_capture::packet::{SipSummary, Transport};

    fn app() -> App {
        let config = Config::default();
        let (ami, _ami_rx) = watch::channel(AmiSettings::from_config(&config));
        let (capture, _capture_rx) = watch::channel(config.capture.clone());
        App::new(config, Reload { ami, capture })
    }

    fn packet(id: u64, method: &str, call_id: &str) -> SipPacketRecord {
        SipPacketRecord {
            id,
            ts: Local::now(),
            src: "10.0.0.5:5060".parse().unwrap(),
            dst: "10.0.0.1:5060".parse().unwrap(),
            transport: Transport::Udp,
            summary: SipSummary::Request {
                method: method.to_string(),
                cseq: format!("{id} {method}"),
            },
            call_id: call_id.to_string(),
            from: "<sip:1001@10.0.0.5>".to_string(),
            to: "<sip:1002@10.0.0.1>".to_string(),
            from_user: Some("1001".to_string()),
            to_user: Some("1002".to_string()),
            raw: String::new(),
            has_auth: false,
            reason_header: None,
            warning_header: None,
            contact_value: None,
            expires_header_value: None,
        }
    }

    fn press(app: &mut App, code: KeyCode) {
        app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    #[test]
    fn enter_abre_la_secuencia_de_la_llamada_seguida_y_esc_la_cierra() {
        let mut app = app();
        app.active_tab = Tab::SipTrace;
        app.sip_packets.push_back(packet(0, "INVITE", "call-1"));
        app.sip_packets.push_back(packet(1, "ACK", "call-1"));
        app.sip_packets.push_back(packet(2, "INVITE", "call-2"));
        // sip_follow arranca en true: el paquete "seguido" es el último de
        // TODOS los capturados, no de una llamada en particular — acá cae en
        // call-2 por orden de inserción.
        app.sip_follow = false;
        app.sip_selected_row = 1; // apunta al ACK de call-1

        press(&mut app, KeyCode::Enter);
        assert_eq!(app.sip_call_flow.as_deref(), Some("call-1"));
        assert_eq!(app.sip_call_flow_selected, 1, "debe abrir parado en el ACK elegido");

        press(&mut app, KeyCode::Esc);
        assert!(app.sip_call_flow.is_none());
    }

    #[test]
    fn arriba_abajo_dentro_de_la_secuencia_mueve_el_indice_de_la_llamada_no_la_lista() {
        let mut app = app();
        app.active_tab = Tab::SipTrace;
        app.sip_packets.push_back(packet(0, "INVITE", "call-1"));
        app.sip_packets.push_back(packet(1, "ACK", "call-1"));
        app.sip_selected_row = 5;
        app.sip_follow = false;

        press(&mut app, KeyCode::Enter);
        assert_eq!(app.sip_call_flow_selected, 1);

        press(&mut app, KeyCode::Up);
        assert_eq!(app.sip_call_flow_selected, 0, "Up mueve el índice de la secuencia");
        assert_eq!(app.sip_selected_row, 5, "no debe tocar la selección de la lista plana");
    }

    #[test]
    fn l_limpia_el_buffer_y_cierra_la_secuencia_abierta() {
        let mut app = app();
        app.active_tab = Tab::SipTrace;
        app.sip_packets.push_back(packet(0, "INVITE", "call-1"));
        app.sip_follow = false;
        app.sip_selected_row = 0;

        press(&mut app, KeyCode::Enter);
        assert!(app.sip_call_flow.is_some());

        press(&mut app, KeyCode::Char('l'));
        assert!(app.sip_packets.is_empty());
        assert!(app.sip_call_flow.is_none());
        assert_eq!(app.sip_selected_row, 0);
        assert!(app.sip_follow);
    }

    #[test]
    fn l_no_limpia_mientras_hay_una_captura_grabando() {
        let mut app = app();
        app.active_tab = Tab::SipTrace;
        app.sip_packets.push_back(packet(0, "INVITE", "call-1"));
        app.sip_trace_active = true;

        press(&mut app, KeyCode::Char('l'));
        assert!(!app.sip_packets.is_empty(), "no debe limpiar en medio de una grabación");
    }
}
