use crossterm::event::KeyEvent;

use crate::ami::{Channel, ConnState, CoreStatus, Peer, Queue};
use crate::sip_capture::CaptureStatus;
use crate::sip_capture::packet::SipPacketRecord;
use crate::sysmon::snapshot::HostSnapshot;

#[derive(Debug, Clone)]
pub enum AppEvent {
    Tick,
    Key(KeyEvent),
    AmiConnState(ConnState),
    CoreStatusUpdated(CoreStatus),
    ChannelsUpdated(Vec<Channel>),
    PeersUpdated(Vec<Peer>),
    QueuesUpdated(Vec<Queue>),
    SysSnapshot(HostSnapshot),
    /// Un mensaje SIP capturado. Va en `Box` porque es la variante más pesada del
    /// enum y la que más circula: sin eso, cada evento del canal paga su tamaño.
    SipPacket(Box<SipPacketRecord>),
    SipCaptureError(String),
    /// Latido del hilo de captura: interfaz, capa de enlace y contadores. El
    /// primero de cada sesión de captura además limpia el error anterior.
    SipCaptureStatus(CaptureStatus),
    /// Resultado del botón "probar conexión" del panel de configuración:
    /// `Ok(banner de AMI)` o `Err(motivo del rechazo)`.
    AmiProbeResult(Result<String, String>),
    /// SIGTERM/SIGINT recibido a nivel de proceso: hay que salir ya para restaurar la terminal.
    Shutdown,
    /// Evento AMI push sin procesar (nombre del Event: header). Reservado para
    /// actualización incremental (Newchannel/Hangup/...) en una fase posterior.
    #[allow(dead_code)]
    AmiEventRaw(String),
}
