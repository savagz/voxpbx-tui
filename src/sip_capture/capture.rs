use std::thread;
use std::time::{Duration, Instant};

use color_eyre::eyre::{Result, eyre};
use tokio::sync::{mpsc, watch};
use tracing::warn;

use crate::config::CaptureConfig;
use crate::event::AppEvent;

use super::CaptureStatus;
use super::link::LinkType;
use super::parser;

/// Cada cuánto revisa el hilo de captura si el panel de configuración cambió la
/// interfaz o los puertos mientras está en espera.
const IDLE_POLL: Duration = Duration::from_millis(250);

/// Cada cuánto se refrescan los contadores (vistos / reconocidos) que muestra la
/// pestaña SIP Trace.
const STATUS_INTERVAL: Duration = Duration::from_secs(1);

/// Arranca la captura pcap en un hilo std bloqueante (`Capture::next_packet` bloquea).
/// Si falla (interfaz inexistente, sin permisos, sin libpcap) se avisa por AppEvent
/// en vez de crashear la TUI: la pestaña SIP Trace debe degradar, no tumbar la app.
///
/// El hilo vive toda la sesión: al cambiar `config_rx` cierra el handle de pcap y
/// vuelve a abrir con la config nueva.
pub fn spawn(mut config_rx: watch::Receiver<CaptureConfig>, app_tx: mpsc::Sender<AppEvent>) {
    thread::spawn(move || {
        loop {
            let config = config_rx.borrow_and_update().clone();

            if config.enabled
                && let Err(e) = run_capture(&config, &app_tx, &config_rx)
            {
                warn!("captura SIP deshabilitada: {e}");
                let _ = app_tx.blocking_send(AppEvent::SipCaptureError(e.to_string()));
            }

            // Sin captura activa (deshabilitada o caída): esperar a que el panel
            // de configuración mande algo distinto.
            loop {
                match config_rx.has_changed() {
                    Ok(true) => break,
                    Ok(false) => thread::sleep(IDLE_POLL),
                    // El emisor murió: la app está cerrando.
                    Err(_) => return,
                }
            }
        }
    });
}

fn run_capture(
    config: &CaptureConfig,
    app_tx: &mpsc::Sender<AppEvent>,
    config_rx: &watch::Receiver<CaptureConfig>,
) -> Result<()> {
    let mut cap = pcap::Capture::from_device(config.interface.as_str())?
        .promisc(true)
        .snaplen(65535)
        .timeout(500)
        .open()?;

    let filter = build_bpf_filter(&config.sip_ports);
    cap.filter(&filter, true)?;

    // La capa de enlace NO es siempre Ethernet: `any` en Linux entrega cooked
    // capture y el loopback una cabecera BSD. Sin resolverla acá, el parser
    // descarta en silencio todos los paquetes y la pestaña queda vacía.
    let datalink = cap.get_datalink();
    let link = LinkType::from_raw(datalink.0).ok_or_else(|| {
        eyre!(
            "capa de enlace no soportada en {} (DLT {}{}). Elegí otra interfaz.",
            config.interface,
            datalink.0,
            datalink
                .get_name()
                .map(|n| format!(", {n}"))
                .unwrap_or_default()
        )
    })?;

    let mut status = CaptureStatus {
        interface: config.interface.clone(),
        link: link.label().to_string(),
        filter: filter.clone(),
        seen: 0,
        parsed: 0,
    };
    let _ = app_tx.blocking_send(AppEvent::SipCaptureStatus(status.clone()));
    let mut last_report = Instant::now();

    loop {
        if config_rx.has_changed().unwrap_or(true) {
            return Ok(());
        }

        match cap.next_packet() {
            Ok(packet) => {
                status.seen += 1;
                if let Some(record) = parser::parse_frame(packet.data, link, &config.sip_ports) {
                    status.parsed += 1;
                    if app_tx.blocking_send(AppEvent::SipPacket(Box::new(record))).is_err() {
                        return Ok(());
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => return Err(e.into()),
        }

        if last_report.elapsed() >= STATUS_INTERVAL {
            last_report = Instant::now();
            if app_tx
                .blocking_send(AppEvent::SipCaptureStatus(status.clone()))
                .is_err()
            {
                return Ok(());
            }
        }
    }
}

fn build_bpf_filter(sip_ports: &[u16]) -> String {
    sip_ports
        .iter()
        .map(|p| format!("port {p}"))
        .collect::<Vec<_>>()
        .join(" or ")
}
