pub mod analysis;
pub mod capture;
pub mod link;
pub mod packet;
pub mod parser;

/// Estado vivo del hilo de captura. `seen` cuenta lo que pasó el filtro BPF y
/// `parsed` lo que además resultó ser SIP: si `seen` sube y `parsed` queda en
/// cero, el tráfico está llegando pero no se está reconociendo (capa de enlace o
/// puertos mal elegidos), y eso hay que poder verlo desde la TUI.
#[derive(Debug, Clone, Default)]
pub struct CaptureStatus {
    pub interface: String,
    pub link: String,
    pub filter: String,
    pub seen: u64,
    pub parsed: u64,
}
