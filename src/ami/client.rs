use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use color_eyre::eyre::{Result, eyre};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tracing::warn;

use crate::config::{AmiConfig, Config, UiConfig};
use crate::event::AppEvent;

use super::protocol::{self, AmiMessage};
use super::{Channel, ConnState, CoreStatus, Peer, Queue, Tech};

/// Todo lo que la tarea AMI necesita para (re)conectarse. Viaja por un `watch`
/// para que el panel de configuración pueda cambiar host/usuario/contraseña sin
/// reiniciar la aplicación.
#[derive(Debug, Clone)]
pub struct AmiSettings {
    pub ami: AmiConfig,
    pub ui: UiConfig,
    /// Secret ya resuelto (archivo o variable de entorno).
    pub secret: String,
}

impl AmiSettings {
    pub fn from_config(config: &Config) -> Self {
        Self {
            ami: config.ami.clone(),
            ui: config.ui.clone(),
            secret: config.effective_secret(),
        }
    }
}

/// Una acción "de lista" (CoreShowChannels, SIPpeers, QueueSummary, ...) responde con
/// `Response: Success` + N `Event:` con el mismo ActionID, cerrado por un evento final
/// que trae `EventList: Complete`. Una acción simple (CoreStatus) trae todo en el
/// `Response: Success` inicial, sin EventList.
enum PendingEntry {
    Single(oneshot::Sender<AmiMessage>),
    List(Vec<AmiMessage>, oneshot::Sender<Vec<AmiMessage>>),
}

type PendingMap = Arc<Mutex<HashMap<String, PendingEntry>>>;

const RECONNECT_BACKOFF: Duration = Duration::from_secs(3);
const CORE_STATUS_INTERVAL: Duration = Duration::from_secs(5);
const ACTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Lanza la tarea de larga duración que mantiene la conexión AMI: login,
/// refresco periódico de estado/canales/peers/colas, y reconexión con backoff si se cae.
///
/// Un cambio en `settings_rx` corta la conexión vigente y reconecta enseguida con
/// los datos nuevos, sin esperar el backoff.
pub fn spawn(mut settings_rx: watch::Receiver<AmiSettings>, app_tx: mpsc::Sender<AppEvent>) {
    tokio::spawn(async move {
        loop {
            let settings = settings_rx.borrow_and_update().clone();

            // Config incompleta (asistente cancelado a medias): quedarse quieto
            // hasta que llegue una config usable, sin martillar el socket.
            if settings.ami.username.is_empty() || settings.ami.host.is_empty() {
                let _ = app_tx
                    .send(AppEvent::AmiConnState(ConnState::Disconnected))
                    .await;
                if settings_rx.changed().await.is_err() {
                    return;
                }
                continue;
            }

            let _ = app_tx
                .send(AppEvent::AmiConnState(ConnState::Connecting))
                .await;

            tokio::select! {
                result = run_connection(&settings, &app_tx) => {
                    let state = match result {
                        Err(e) => {
                            warn!("conexión AMI: {e}");
                            ConnState::LoginFailed
                        }
                        Ok(()) => ConnState::Disconnected,
                    };
                    let _ = app_tx.send(AppEvent::AmiConnState(state)).await;

                    tokio::select! {
                        _ = tokio::time::sleep(RECONNECT_BACKOFF) => {}
                        changed = settings_rx.changed() => {
                            if changed.is_err() { return; }
                        }
                    }
                }
                changed = settings_rx.changed() => {
                    if changed.is_err() { return; }
                }
            }
        }
    });
}

/// Conecta, hace login y devuelve el banner de AMI. Usado por el botón "probar
/// conexión" del panel de configuración: valida credenciales sin tocar la sesión
/// de monitoreo en curso.
pub async fn probe(config: &AmiConfig) -> Result<String> {
    let stream = tokio::time::timeout(
        ACTION_TIMEOUT,
        TcpStream::connect((config.host.as_str(), config.port)),
    )
    .await
    .map_err(|_| eyre!("timeout conectando a {}:{}", config.host, config.port))??;

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let banner = protocol::read_banner(&mut reader).await?;
    login(&mut write_half, &mut reader, config, &config.secret).await?;

    let logoff = protocol::encode_action(&[("Action", "Logoff"), ("ActionID", "probe-off")]);
    let _ = write_half.write_all(logoff.as_bytes()).await;

    Ok(banner.trim().to_string())
}

async fn run_connection(settings: &AmiSettings, app_tx: &mpsc::Sender<AppEvent>) -> Result<()> {
    let config = &settings.ami;
    let ui = &settings.ui;
    let secret = settings.secret.as_str();

    let stream = TcpStream::connect((config.host.as_str(), config.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    protocol::read_banner(&mut reader).await?;

    let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
    let (reader_done_tx, mut reader_done_rx) = oneshot::channel::<Result<()>>();

    login(&mut write_half, &mut reader, config, secret).await?;

    let pending_for_reader = pending.clone();
    let app_tx_for_reader = app_tx.clone();
    tokio::spawn(async move {
        let result = reader_loop(reader, pending_for_reader, app_tx_for_reader).await;
        let _ = reader_done_tx.send(result);
    });

    let _ = app_tx
        .send(AppEvent::AmiConnState(ConnState::Connected))
        .await;

    let mut core_status_iv = tokio::time::interval(CORE_STATUS_INTERVAL);
    let mut channels_iv = tokio::time::interval(Duration::from_secs(ui.refresh_channels_secs));
    let mut peers_iv = tokio::time::interval(Duration::from_secs(ui.refresh_peers_secs));
    let mut queues_iv = tokio::time::interval(Duration::from_secs(ui.refresh_queues_secs));

    loop {
        tokio::select! {
            _ = core_status_iv.tick() => {
                if let Err(e) = refresh_core_status(&mut write_half, &pending, app_tx).await {
                    warn!("CoreStatus: {e}");
                }
            }
            _ = channels_iv.tick() => {
                if let Err(e) = refresh_channels(&mut write_half, &pending, app_tx).await {
                    warn!("CoreShowChannels: {e}");
                }
            }
            _ = peers_iv.tick() => {
                refresh_peers(&mut write_half, &pending, app_tx).await;
            }
            _ = queues_iv.tick() => {
                if let Err(e) = refresh_queues(&mut write_half, &pending, app_tx).await {
                    warn!("QueueSummary: {e}");
                }
            }
            result = &mut reader_done_rx => {
                return result.unwrap_or_else(|_| Err(eyre!("reader AMI terminó inesperadamente")));
            }
        }
    }
}

/// Login se resuelve inline (antes de arrancar el reader_loop dedicado) porque
/// todavía no hay ningún otro consumidor leyendo del socket.
async fn login(
    write_half: &mut OwnedWriteHalf,
    reader: &mut BufReader<OwnedReadHalf>,
    config: &AmiConfig,
    secret: &str,
) -> Result<()> {
    let action = protocol::encode_action(&[
        ("Action", "Login"),
        ("ActionID", "login-1"),
        ("Username", &config.username),
        ("Secret", secret),
    ]);
    write_half.write_all(action.as_bytes()).await?;

    let response = tokio::time::timeout(ACTION_TIMEOUT, protocol::read_message(reader))
        .await
        .map_err(|_| eyre!("timeout esperando respuesta de Login"))??
        .ok_or_else(|| eyre!("AMI cerró la conexión durante Login"))?;

    if response.get("Response").map(String::as_str) != Some("Success") {
        return Err(eyre!(
            "login AMI rechazado: {}",
            response.get("Message").cloned().unwrap_or_default()
        ));
    }

    Ok(())
}

async fn send_single_action(
    write_half: &mut OwnedWriteHalf,
    pending: &PendingMap,
    fields: &[(&str, &str)],
) -> Result<AmiMessage> {
    let action_id = format!("act-{}", uuid::Uuid::new_v4());
    let (tx, rx) = oneshot::channel();
    pending
        .lock()
        .await
        .insert(action_id.clone(), PendingEntry::Single(tx));

    let mut full_fields: Vec<(&str, &str)> = fields.to_vec();
    full_fields.push(("ActionID", &action_id));
    let action = protocol::encode_action(&full_fields);
    write_half.write_all(action.as_bytes()).await?;

    tokio::time::timeout(ACTION_TIMEOUT, rx)
        .await
        .map_err(|_| eyre!("timeout esperando respuesta de {}", fields[0].1))?
        .map_err(|_| eyre!("conexión AMI cerrada esperando {}", fields[0].1))
}

async fn send_list_action(
    write_half: &mut OwnedWriteHalf,
    pending: &PendingMap,
    fields: &[(&str, &str)],
) -> Result<Vec<AmiMessage>> {
    let action_id = format!("act-{}", uuid::Uuid::new_v4());
    let (tx, rx) = oneshot::channel();
    pending
        .lock()
        .await
        .insert(action_id.clone(), PendingEntry::List(Vec::new(), tx));

    let mut full_fields: Vec<(&str, &str)> = fields.to_vec();
    full_fields.push(("ActionID", &action_id));
    let action = protocol::encode_action(&full_fields);
    write_half.write_all(action.as_bytes()).await?;

    tokio::time::timeout(ACTION_TIMEOUT, rx)
        .await
        .map_err(|_| eyre!("timeout esperando lista de {}", fields[0].1))?
        .map_err(|_| eyre!("conexión AMI cerrada esperando lista de {}", fields[0].1))
}

async fn refresh_core_status(
    write_half: &mut OwnedWriteHalf,
    pending: &PendingMap,
    app_tx: &mpsc::Sender<AppEvent>,
) -> Result<()> {
    let response = send_single_action(write_half, pending, &[("Action", "CoreStatus")]).await?;

    let status = CoreStatus {
        description: response.get("CoreStatus").cloned().unwrap_or_default(),
        startup_time: response.get("CoreStartupTime").cloned().unwrap_or_default(),
        reload_time: response.get("CoreReloadTime").cloned().unwrap_or_default(),
        current_calls: response
            .get("CoreCurrentCalls")
            .and_then(|v| v.parse().ok()),
    };

    let _ = app_tx.send(AppEvent::CoreStatusUpdated(status)).await;
    Ok(())
}

async fn refresh_channels(
    write_half: &mut OwnedWriteHalf,
    pending: &PendingMap,
    app_tx: &mpsc::Sender<AppEvent>,
) -> Result<()> {
    let events = send_list_action(write_half, pending, &[("Action", "CoreShowChannels")]).await?;

    let channels = events
        .iter()
        .filter(|e| e.get("Event").map(String::as_str) == Some("CoreShowChannel"))
        .map(|e| Channel {
            channel: e.get("Channel").cloned().unwrap_or_default(),
            state: e.get("ChannelStateDesc").cloned().unwrap_or_default(),
            caller_id: e.get("CallerIDNum").cloned().unwrap_or_default(),
            context: e.get("Context").cloned().unwrap_or_default(),
            extension: e.get("Exten").cloned().unwrap_or_default(),
            duration: e.get("Duration").cloned().unwrap_or_default(),
        })
        .collect();

    let _ = app_tx.send(AppEvent::ChannelsUpdated(channels)).await;
    Ok(())
}

/// Refresca las tres tech de extensiones que puede tener un Asterisk vivo:
/// chan_sip, chan_iax2, y PJSIP (que a diferencia de las otras dos no reporta
/// IP/estado en un único evento, así que hace falta cruzar dos acciones).
///
/// Cada fetch se intenta por separado: si una tech no está cargada en el
/// Asterisk destino (acción inexistente → `Response: Error`, sin eventos), esa
/// falla no debe tirar abajo el refresco de las otras dos.
async fn refresh_peers(
    write_half: &mut OwnedWriteHalf,
    pending: &PendingMap,
    app_tx: &mpsc::Sender<AppEvent>,
) {
    match send_list_action(write_half, pending, &[("Action", "SIPpeers")]).await {
        Ok(events) => {
            let _ = app_tx
                .send(AppEvent::PeersUpdated(parse_sip_peers(&events)))
                .await;
        }
        Err(e) => warn!("SIPpeers: {e}"),
    }

    match send_list_action(write_half, pending, &[("Action", "IAXpeers")]).await {
        Ok(events) => {
            let _ = app_tx
                .send(AppEvent::IaxPeersUpdated(parse_iax_peers(&events)))
                .await;
        }
        Err(e) => warn!("IAXpeers: {e}"),
    }

    let endpoints = send_list_action(write_half, pending, &[("Action", "PJSIPShowEndpoints")]).await;
    let contacts = send_list_action(write_half, pending, &[("Action", "PJSIPShowContacts")]).await;
    match (endpoints, contacts) {
        (Ok(endpoints), Ok(contacts)) => {
            let _ = app_tx
                .send(AppEvent::PjsipPeersUpdated(parse_pjsip_peers(
                    &endpoints, &contacts,
                )))
                .await;
        }
        (Err(e), _) => warn!("PJSIPShowEndpoints: {e}"),
        (_, Err(e)) => warn!("PJSIPShowContacts: {e}"),
    }
}

fn parse_sip_peers(events: &[AmiMessage]) -> Vec<Peer> {
    events
        .iter()
        .filter(|e| e.get("Event").map(String::as_str) == Some("PeerEntry"))
        .map(|e| Peer {
            name: e.get("ObjectName").cloned().unwrap_or_default(),
            ip: e.get("IPaddress").cloned().unwrap_or_default(),
            status: e.get("Status").cloned().unwrap_or_default(),
            tech: Tech::Sip,
        })
        .collect()
}

fn parse_iax_peers(events: &[AmiMessage]) -> Vec<Peer> {
    events
        .iter()
        .filter(|e| e.get("Event").map(String::as_str) == Some("PeerEntry"))
        .map(|e| Peer {
            name: e.get("ObjectName").cloned().unwrap_or_default(),
            ip: e.get("IPaddress").cloned().unwrap_or_default(),
            status: e.get("Status").cloned().unwrap_or_default(),
            tech: Tech::Iax2,
        })
        .collect()
}

/// `PJSIPShowEndpoints` sólo da el nombre del endpoint y su `DeviceState`, sin
/// IP; la IP y el estado real de registro salen de `PJSIPShowContacts`, cruzado
/// por endpoint. El cruce usa el header `Endpoint` de cada contacto (no `AOR`:
/// el evento `ContactList` real de Asterisk no trae ese header, sólo `Endpoint`
/// con el nombre del endpoint dueño del contacto — confirmado contra AMI real,
/// no contra la doc). El header de URI del contacto es `Uri` (no `URI`), y el
/// status de un contacto vivo es el string `Reachable` (no `Avail`).
fn parse_pjsip_peers(endpoints: &[AmiMessage], contacts: &[AmiMessage]) -> Vec<Peer> {
    let mut contacts_by_endpoint: HashMap<&str, Vec<(&str, &str)>> = HashMap::new();
    for c in contacts {
        if c.get("Event").map(String::as_str) != Some("ContactList") {
            continue;
        }
        let Some(endpoint) = c.get("Endpoint") else { continue };
        let uri = c.get("Uri").map(String::as_str).unwrap_or_default();
        let status = c.get("Status").map(String::as_str).unwrap_or_default();
        contacts_by_endpoint
            .entry(endpoint.as_str())
            .or_default()
            .push((uri, status));
    }

    endpoints
        .iter()
        .filter(|e| e.get("Event").map(String::as_str) == Some("EndpointList"))
        .map(|e| {
            let name = e.get("ObjectName").cloned().unwrap_or_default();
            let bindings = contacts_by_endpoint.get(name.as_str());

            let (ip, status) = if let Some((uri, _)) = bindings
                .and_then(|b| b.iter().find(|(_, s)| s.eq_ignore_ascii_case("Reachable")))
            {
                (contact_uri_host(uri), "OK".to_string())
            } else if let Some((uri, _)) = bindings.and_then(|b| b.first()) {
                (contact_uri_host(uri), "UNREACHABLE".to_string())
            } else {
                (String::new(), "UNKNOWN".to_string())
            };

            Peer {
                name,
                ip,
                status,
                tech: Tech::Pjsip,
            }
        })
        .collect()
}

/// Saca el host de una URI de contacto PJSIP (`sip:1002@192.168.1.50:5060` →
/// `192.168.1.50`). No usa `packet::uri_user` porque acá interesa el host, no
/// el usuario, y estas URIs de AMI no traen el `<...>` con display name.
fn contact_uri_host(uri: &str) -> String {
    let without_scheme = uri
        .strip_prefix("sips:")
        .or_else(|| uri.strip_prefix("sip:"))
        .unwrap_or(uri);
    let after_user = match without_scheme.split_once('@') {
        Some((_, host)) => host,
        None => without_scheme,
    };
    let end = after_user.find([':', ';', '>']).unwrap_or(after_user.len());
    after_user[..end].to_string()
}

async fn refresh_queues(
    write_half: &mut OwnedWriteHalf,
    pending: &PendingMap,
    app_tx: &mpsc::Sender<AppEvent>,
) -> Result<()> {
    let events = send_list_action(write_half, pending, &[("Action", "QueueSummary")]).await?;

    let queues = events
        .iter()
        .filter(|e| e.get("Event").map(String::as_str) == Some("QueueSummary"))
        .map(|e| Queue {
            name: e.get("Queue").cloned().unwrap_or_default(),
            logged_in: e.get("LoggedIn").and_then(|v| v.parse().ok()).unwrap_or(0),
            available: e.get("Available").and_then(|v| v.parse().ok()).unwrap_or(0),
            callers_waiting: e.get("Callers").and_then(|v| v.parse().ok()).unwrap_or(0),
        })
        .collect();

    let _ = app_tx.send(AppEvent::QueuesUpdated(queues)).await;
    Ok(())
}

/// Bucle único de lectura del socket: correlaciona respuestas/eventos por ActionID
/// contra `pending` (resolviendo de inmediato las simples, acumulando las de lista
/// hasta su `EventList: Complete`), y reenvía eventos push sin correlacionar.
async fn reader_loop(
    mut reader: BufReader<OwnedReadHalf>,
    pending: PendingMap,
    app_tx: mpsc::Sender<AppEvent>,
) -> Result<()> {
    loop {
        let message = protocol::read_message(&mut reader).await?;
        let Some(message) = message else {
            return Err(eyre!("AMI cerró la conexión"));
        };

        let Some(action_id) = message.get("ActionID").cloned() else {
            if let Some(event) = message.get("Event") {
                let _ = app_tx.send(AppEvent::AmiEventRaw(event.clone())).await;
            }
            continue;
        };

        let mut guard = pending.lock().await;
        match guard.get_mut(&action_id) {
            Some(PendingEntry::Single(_)) => {
                if let Some(PendingEntry::Single(tx)) = guard.remove(&action_id) {
                    drop(guard);
                    let _ = tx.send(message);
                }
            }
            Some(PendingEntry::List(events, _)) => {
                let is_complete = message.get("EventList").map(String::as_str) == Some("Complete");
                // Una acción de lista para un comando no soportado (ej. `SIPpeers` en un
                // Asterisk sin chan_sip cargado) responde de una `Response: Error` y
                // nunca manda `EventList: Complete`. Sin este chequeo, esa entrada se
                // queda pendiente hasta el timeout de 5s (y huérfana en el mapa después),
                // en cada ciclo de refresco.
                let is_error = message.get("Response").map(String::as_str) == Some("Error");
                let is_initial_ack = message.contains_key("Response");

                if is_complete || is_error {
                    if let Some(PendingEntry::List(events, tx)) = guard.remove(&action_id) {
                        drop(guard);
                        let _ = tx.send(events);
                    }
                } else if !is_initial_ack {
                    events.push(message);
                }
            }
            None => {
                drop(guard);
                if let Some(event) = message.get("Event") {
                    let _ = app_tx.send(AppEvent::AmiEventRaw(event.clone())).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(pairs: &[(&str, &str)]) -> AmiMessage {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn parsea_peers_sip() {
        let events = vec![msg(&[
            ("Event", "PeerEntry"),
            ("ObjectName", "1001"),
            ("IPaddress", "192.168.1.10"),
            ("Status", "OK (5 ms)"),
        ])];
        let peers = parse_sip_peers(&events);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "1001");
        assert_eq!(peers[0].ip, "192.168.1.10");
        assert!(peers[0].is_registered());
        assert_eq!(peers[0].tech, Tech::Sip);
    }

    #[test]
    fn parsea_peers_iax2() {
        let events = vec![msg(&[
            ("Event", "PeerEntry"),
            ("ObjectName", "2001"),
            ("IPaddress", "192.168.1.20"),
            ("Status", "UNREACHABLE"),
        ])];
        let peers = parse_iax_peers(&events);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "2001");
        assert!(!peers[0].is_registered());
        assert_eq!(peers[0].tech, Tech::Iax2);
    }

    #[test]
    fn cruza_endpoint_pjsip_con_su_contacto_disponible() {
        let endpoints = vec![msg(&[
            ("Event", "EndpointList"),
            ("ObjectName", "1003"),
        ])];
        let contacts = vec![msg(&[
            ("Event", "ContactList"),
            ("Endpoint", "1003"),
            ("Uri", "sip:1003@192.168.1.30:5060"),
            ("Status", "Reachable"),
        ])];

        let peers = parse_pjsip_peers(&endpoints, &contacts);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].ip, "192.168.1.30");
        assert!(peers[0].is_registered());
        assert_eq!(peers[0].tech, Tech::Pjsip);
    }

    #[test]
    fn endpoint_pjsip_sin_contactos_queda_sin_registrar() {
        let endpoints = vec![msg(&[("Event", "EndpointList"), ("ObjectName", "1004")])];
        let contacts: Vec<AmiMessage> = vec![];

        let peers = parse_pjsip_peers(&endpoints, &contacts);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].ip, "");
        assert!(!peers[0].is_registered());
    }

    #[test]
    fn endpoint_pjsip_con_contacto_no_disponible_reporta_su_ip_igual() {
        let endpoints = vec![msg(&[("Event", "EndpointList"), ("ObjectName", "1005")])];
        let contacts = vec![msg(&[
            ("Event", "ContactList"),
            ("Endpoint", "1005"),
            ("Uri", "sip:1005@192.168.1.40:5060"),
            ("Status", "Unreachable"),
        ])];

        let peers = parse_pjsip_peers(&endpoints, &contacts);
        assert_eq!(peers[0].ip, "192.168.1.40");
        assert!(!peers[0].is_registered());
    }

    #[test]
    fn saca_el_host_de_una_uri_de_contacto() {
        assert_eq!(contact_uri_host("sip:1002@192.168.1.50:5060"), "192.168.1.50");
        assert_eq!(contact_uri_host("sips:1002@10.0.0.1"), "10.0.0.1");
        assert_eq!(contact_uri_host("sip:10.0.0.1:5060"), "10.0.0.1");
    }
}
