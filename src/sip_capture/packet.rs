use std::net::{IpAddr, SocketAddr};

use chrono::{DateTime, Local};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    pub fn label(&self) -> &'static str {
        match self {
            Transport::Udp => "UDP",
            Transport::Tcp => "TCP",
        }
    }
}

#[derive(Debug, Clone)]
pub enum SipSummary {
    Request { method: String, cseq: String },
    Response { status: String, cseq: String },
}

impl SipSummary {
    pub fn short(&self) -> String {
        match self {
            SipSummary::Request { method, .. } => method.clone(),
            SipSummary::Response { status, .. } => status.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SipPacketRecord {
    pub id: u64,
    pub ts: DateTime<Local>,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub transport: Transport,
    pub summary: SipSummary,
    pub call_id: String,
    pub from: String,
    pub to: String,
    /// Usuario de la URI del header From (la extensión, normalmente).
    pub from_user: Option<String>,
    /// Usuario de la URI del header To.
    pub to_user: Option<String>,
    /// Texto SIP completo (headers + body), para el panel de detalle estilo Wireshark.
    pub raw: String,
}

impl SipPacketRecord {
    /// ¿Este paquete es de la extensión buscada?
    ///
    /// Mirar sólo la IP que reporta AMI no alcanza: el peer puede estar detrás de
    /// NAT, registrado desde otra dirección, o AMI puede devolver la IP vacía. Por
    /// eso también se compara el usuario de las URIs From/To.
    pub fn involves(&self, ip: Option<IpAddr>, user: &str) -> bool {
        if ip.is_some_and(|ip| self.src.ip() == ip || self.dst.ip() == ip) {
            return true;
        }
        !user.is_empty()
            && (self.from_user.as_deref() == Some(user) || self.to_user.as_deref() == Some(user))
    }
}

/// Extrae el usuario de la primera URI SIP que aparezca en el valor de un header.
///
/// `"Ana" <sip:1001@10.0.0.5>;tag=abc` → `1001`. Devuelve `None` para URIs sin
/// parte de usuario (`sip:10.0.0.1`), que es justamente lo que manda un REGISTER
/// en su Request-URI.
pub fn uri_user(value: &str) -> Option<String> {
    let after_scheme = value
        .find("sips:")
        .map(|i| i + "sips:".len())
        .or_else(|| value.find("sip:").map(|i| i + "sip:".len()))?;

    let rest = &value[after_scheme..];
    let end = rest
        .find(['>', ';', ',', ' ', '\t', '"'])
        .unwrap_or(rest.len());
    let (user, _host) = rest[..end].split_once('@')?;

    (!user.is_empty()).then(|| user.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extrae_el_usuario_de_headers_from_y_to() {
        assert_eq!(
            uri_user("\"Ana\" <sip:1001@10.0.0.5>;tag=abc").as_deref(),
            Some("1001")
        );
        assert_eq!(uri_user("<sip:1002@host>").as_deref(), Some("1002"));
        assert_eq!(uri_user("sip:1003@host;transport=udp").as_deref(), Some("1003"));
        assert_eq!(uri_user("<sips:1004@host:5061>").as_deref(), Some("1004"));
    }

    #[test]
    fn devuelve_none_cuando_la_uri_no_tiene_usuario() {
        assert_eq!(uri_user("<sip:10.0.0.1>"), None);
        assert_eq!(uri_user("sin uri"), None);
    }
}
