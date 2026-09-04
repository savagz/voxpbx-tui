pub mod client;
pub mod protocol;

use crate::theme::Status;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    LoginFailed,
}

impl ConnState {
    pub fn label(&self) -> &'static str {
        match self {
            ConnState::Disconnected => "desconectado",
            ConnState::Connecting => "conectando…",
            ConnState::Connected => "conectado",
            ConnState::LoginFailed => "login rechazado",
        }
    }

    pub fn status(&self) -> Status {
        match self {
            ConnState::Disconnected | ConnState::LoginFailed => Status::Error,
            ConnState::Connecting => Status::Warning,
            ConnState::Connected => Status::Ok,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CoreStatus {
    pub description: String,
    pub startup_time: String,
    pub reload_time: String,
    pub current_calls: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Channel {
    pub channel: String,
    pub state: String,
    pub caller_id: String,
    pub context: String,
    pub extension: String,
    pub duration: String,
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub name: String,
    pub ip: String,
    /// Texto crudo del header `Status` de AMI (ej. "OK (5 ms)", "UNREACHABLE", "UNKNOWN").
    pub status: String,
}

impl Peer {
    pub fn is_registered(&self) -> bool {
        self.status.starts_with("OK")
    }
}

#[derive(Debug, Clone)]
pub struct Queue {
    pub name: String,
    pub logged_in: u32,
    pub available: u32,
    pub callers_waiting: u32,
}
