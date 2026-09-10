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
    Response { status: String, code: u16, cseq: String },
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
    /// Trae `Authorization` o `Proxy-Authorization`. Distingue, en un bucle de
    /// desafíos `401`/`407`, credenciales rechazadas (el cliente sí responde) de
    /// un cliente o proxy que ni siquiera intenta autenticar.
    pub has_auth: bool,
    /// Header `Reason` (RFC 3326) verbatim, cuando está presente. Un `503`
    /// desnudo no dice nada; `Reason: Q.850;cause=34` sí.
    pub reason_header: Option<String>,
    /// Header `Warning` verbatim, cuando está presente.
    pub warning_header: Option<String>,
    /// Valor crudo del header `Contact`, para leer el parámetro `expires` del
    /// binding en un `REGISTER` o su `200`.
    pub contact_value: Option<String>,
    /// Valor crudo del header `Expires`, el fallback cuando `Contact` no trae
    /// su propio parámetro `expires`.
    pub expires_header_value: Option<String>,
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

/// Segundos de vida de un binding de `REGISTER`, según RFC 3261 §10.2.1.1.
///
/// El intervalo puede venir por dos vías: un header `Expires`, o un parámetro
/// `expires` en el `Contact`. Cuando ambos aparecen gana el del `Contact`,
/// porque es el valor por-binding y el header es sólo el default para los
/// bindings que no traen uno propio.
///
/// El parámetro vive DESPUÉS del `>` de cierre: `Contact: <sip:a@h;x=1>;expires=60`
/// tiene `expires` como parámetro del header, no de la URI, aun cuando la URI
/// también tenga los suyos entre `<` y `>`. Confundir ambos hace que
/// `<sip:a@h;expires=60>;expires=3600` se lea como 60 en vez de 3600.
pub fn registration_expiry(contact: Option<&str>, expires_header: Option<&str>) -> Option<u32> {
    if let Some(contact) = contact {
        let params = match contact.find('>') {
            Some(close) => &contact[close + 1..],
            // Sin `<>` no hay parámetros de URI posibles (RFC 3261 §20.10), así
            // que todo `;` de acá es un parámetro del header.
            None => contact,
        };
        for param in params.split(';').skip(1) {
            // Parámetros sin valor (`;ob`, `;lr`) son comunes; `split_once`
            // los salta en vez de abortar toda la función, para que el
            // fallback al header `Expires` siga siendo alcanzable.
            let Some((name, value)) = param.split_once('=') else {
                continue;
            };
            if name.trim().eq_ignore_ascii_case("expires") {
                return value.trim().trim_matches('"').parse().ok();
            }
        }
    }
    expires_header?.trim().parse().ok()
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

    #[test]
    fn el_expires_de_la_uri_no_es_la_vida_del_binding() {
        let expiry = registration_expiry(
            Some("<sip:a@10.0.0.1;expires=60;transport=udp>;expires=3600"),
            None,
        );
        assert_eq!(expiry, Some(3600));
    }

    #[test]
    fn un_expires_de_uri_solo_cae_al_header_expires() {
        let expiry = registration_expiry(Some("<sip:a@10.0.0.1;expires=0>"), Some("3600"));
        assert_eq!(expiry, Some(3600));
    }

    #[test]
    fn el_parametro_del_header_contact_gana_sobre_el_header_expires() {
        let expiry = registration_expiry(Some("<sip:a@10.0.0.1>;expires=60"), Some("3600"));
        assert_eq!(expiry, Some(60));
    }

    #[test]
    fn un_addr_spec_sin_brackets_expone_su_expires_directo() {
        let expiry = registration_expiry(Some("sip:a@10.0.0.1;expires=120"), None);
        assert_eq!(expiry, Some(120));
    }
}
