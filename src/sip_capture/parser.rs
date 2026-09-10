use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Local;
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use rsip::{Header, SipMessage};
use rsip::prelude::*;

use super::link::LinkType;
use super::packet::{self, SipPacketRecord, SipSummary, Transport};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Parsea una trama capturada por pcap según la capa de enlace del handle;
/// devuelve `None` si no es UDP/TCP sobre uno de los puertos SIP configurados, o
/// si el payload no es un mensaje SIP válido.
pub fn parse_frame(data: &[u8], link: LinkType, sip_ports: &[u16]) -> Option<SipPacketRecord> {
    let headers = match link {
        LinkType::Ethernet => PacketHeaders::from_ethernet_slice(data).ok()?,
        other => PacketHeaders::from_ip_slice(other.ip_payload(data)?).ok()?,
    };

    let (src_ip, dst_ip) = match headers.net.as_ref()? {
        NetHeaders::Ipv4(ip, _) => (IpAddr::from(ip.source), IpAddr::from(ip.destination)),
        NetHeaders::Ipv6(ip, _) => (IpAddr::from(ip.source), IpAddr::from(ip.destination)),
    };

    let (transport, src_port, dst_port) = match headers.transport.as_ref()? {
        TransportHeader::Udp(udp) => (Transport::Udp, udp.source_port, udp.destination_port),
        TransportHeader::Tcp(tcp) => (Transport::Tcp, tcp.source_port, tcp.destination_port),
        _ => return None,
    };

    if !sip_ports.contains(&src_port) && !sip_ports.contains(&dst_port) {
        return None;
    }

    parse_sip_payload(
        headers.payload.slice(),
        SocketAddr::new(src_ip, src_port),
        SocketAddr::new(dst_ip, dst_port),
        transport,
    )
}

fn parse_sip_payload(
    payload: &[u8],
    src: SocketAddr,
    dst: SocketAddr,
    transport: Transport,
) -> Option<SipPacketRecord> {
    // Softphones WebRTC (extensiones `transport=ws`) mandan el SIP envuelto en
    // frames WebSocket sobre TCP, no como texto plano — sin desenvolver acá,
    // `SipMessage::try_from` nunca matchea y esas extensiones quedan mudas en
    // el trace. Primero se intenta el payload tal cual (UDP/TCP planos, el caso
    // común); si falla, se prueba como frame WS.
    let unwrapped;
    let (message, payload) = match SipMessage::try_from(payload) {
        Ok(message) => (message, payload),
        Err(_) => {
            unwrapped = unwrap_websocket_frame(payload)?;
            (SipMessage::try_from(unwrapped.as_slice()).ok()?, unwrapped.as_slice())
        }
    };

    let call_id = message
        .call_id_header()
        .map(|h| h.value().to_string())
        .unwrap_or_default();
    let from = message
        .from_header()
        .map(|h| h.value().to_string())
        .unwrap_or_default();
    let to = message
        .to_header()
        .map(|h| h.value().to_string())
        .unwrap_or_default();
    let cseq = message
        .cseq_header()
        .map(|h| h.value().to_string())
        .unwrap_or_default();

    let raw = String::from_utf8_lossy(payload).into_owned();

    let summary = match &message {
        SipMessage::Request(request) => SipSummary::Request {
            method: request.method().to_string(),
            cseq,
        },
        SipMessage::Response(response) => {
            // La línea de estado se lee del propio wire, no de
            // `StatusCode::Display`: éste ignora el reason phrase real para
            // cualquier código que reconoce (imprime "BusyHere" en vez de
            // "Busy Here"), y ese texto es justo lo que un `Reason`/`Warning`
            // ausente necesita para decir algo útil.
            let status = raw
                .lines()
                .next()
                .and_then(|line| line.strip_prefix("SIP/2.0 "))
                .map(|s| s.trim_end().to_string())
                .unwrap_or_else(|| response.status_code().to_string());
            SipSummary::Response {
                status,
                code: response.status_code().code(),
                cseq,
            }
        }
    };

    // Autorización: sólo importa en la petición que reintenta un desafío
    // `401`/`407` — su ausencia es la firma de un `SilentDrop`.
    let has_auth = message
        .headers()
        .iter()
        .any(|h| matches!(h, Header::Authorization(_) | Header::ProxyAuthorization(_)));

    // RFC 3326: rsip no tiene un header `Reason` tipado, así que llega como
    // `Header::Other`.
    let reason_header = message.headers().iter().find_map(|h| match h {
        Header::Other(name, value) if name.eq_ignore_ascii_case("Reason") => Some(value.clone()),
        _ => None,
    });
    let warning_header = message
        .headers()
        .iter()
        .find_map(|h| match h {
            Header::Warning(w) => Some(w),
            _ => None,
        })
        .map(|w| w.value().to_string());
    let contact_value = message.contact_header().ok().map(|h| h.value().to_string());
    let expires_header_value = message.expires_header().map(|h| h.value().to_string());

    Some(SipPacketRecord {
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        ts: Local::now(),
        src,
        dst,
        transport,
        summary,
        call_id,
        from_user: packet::uri_user(&from),
        to_user: packet::uri_user(&to),
        from,
        to,
        raw,
        has_auth,
        reason_header,
        warning_header,
        contact_value,
        expires_header_value,
    })
}

/// Desenvuelve un frame WebSocket (RFC 6455 §5.2) y devuelve su payload ya
/// desenmascarado. Sólo acepta un frame completo (`FIN=1`) de texto u opcode
/// binario (`0x1`/`0x2`): un mensaje SIP siempre entra en un único frame para
/// cualquier softphone razonable, y frames de continuación/ping/pong/close no
/// traen SIP entero, así que no vale la pena reensamblarlos acá.
fn unwrap_websocket_frame(data: &[u8]) -> Option<Vec<u8>> {
    let &[byte0, byte1, ..] = data else { return None };

    let fin = byte0 & 0x80 != 0;
    let opcode = byte0 & 0x0F;
    if !fin || (opcode != 0x1 && opcode != 0x2) {
        return None;
    }

    let masked = byte1 & 0x80 != 0;
    let mut len = u64::from(byte1 & 0x7F);
    let mut offset = 2usize;

    if len == 126 {
        len = u64::from(u16::from_be_bytes(data.get(offset..offset + 2)?.try_into().ok()?));
        offset += 2;
    } else if len == 127 {
        len = u64::from_be_bytes(data.get(offset..offset + 8)?.try_into().ok()?);
        offset += 8;
    }

    let mask_key = if masked {
        let key = data.get(offset..offset + 4)?;
        offset += 4;
        Some(key)
    } else {
        None
    };

    let len = usize::try_from(len).ok()?;
    let mut body = data.get(offset..offset + len)?.to_vec();
    if let Some(key) = mask_key {
        for (i, b) in body.iter_mut().enumerate() {
            *b ^= key[i % 4];
        }
    }
    Some(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    fn parse_ethernet_frame(data: &[u8], sip_ports: &[u16]) -> Option<SipPacketRecord> {
        parse_frame(data, LinkType::Ethernet, sip_ports)
    }

    const INVITE: &str = "INVITE sip:1002@192.168.1.20 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKabc\r\n\
From: \"1001\" <sip:1001@192.168.1.10>;tag=abc\r\n\
To: <sip:1002@192.168.1.20>\r\n\
Call-ID: test-call-id-123@192.168.1.10\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";

    /// Trama IP pura (sin Ethernet) precedida por `header_len` bytes de basura:
    /// simula lo que entregan `any` (SLL) y el loopback.
    fn build_cooked_frame(sip_text: &str, header_len: usize) -> Vec<u8> {
        let builder = PacketBuilder::ipv4([192, 168, 1, 10], [192, 168, 1, 20], 64).udp(5060, 5060);
        let payload = sip_text.as_bytes();
        let mut frame = vec![0u8; header_len];
        builder.write(&mut frame, payload).unwrap();
        frame
    }

    fn build_udp_frame(sip_text: &str, src_port: u16, dst_port: u16) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 64)
            .udp(src_port, dst_port);

        let payload = sip_text.as_bytes();
        let mut frame = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut frame, payload).unwrap();
        frame
    }

    #[test]
    fn parses_sip_invite_over_udp() {
        let frame = build_udp_frame(INVITE, 5060, 5060);
        let record = parse_ethernet_frame(&frame, &[5060]).expect("debe parsear el INVITE");

        assert_eq!(record.summary.short(), "INVITE");
        assert_eq!(record.call_id, "test-call-id-123@192.168.1.10");
        assert_eq!(record.src.port(), 5060);
        assert_eq!(record.transport, Transport::Udp);
        assert_eq!(record.from_user.as_deref(), Some("1001"));
        assert_eq!(record.to_user.as_deref(), Some("1002"));
    }

    #[test]
    fn ignores_non_sip_ports() {
        let invite = "INVITE sip:1002@192.168.1.20 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.10:4000;branch=z9hG4bKabc\r\n\
Call-ID: x@y\r\nCSeq: 1 INVITE\r\n\r\n";

        let frame = build_udp_frame(invite, 4000, 4000);
        assert!(parse_ethernet_frame(&frame, &[5060, 5061]).is_none());
    }

    #[test]
    fn ignores_udp_payload_that_is_not_sip() {
        let frame = build_udp_frame("not a sip message at all", 5060, 5060);
        assert!(parse_ethernet_frame(&frame, &[5060]).is_none());
    }

    /// La interfaz `any` de Linux entrega cooked capture, no Ethernet: sin este
    /// camino la pestaña SIP Trace queda muda aunque haya tráfico SIP.
    #[test]
    fn parses_sip_over_linux_sll_and_sll2() {
        for link in [LinkType::LinuxSll, LinkType::LinuxSll2] {
            let header_len = match link {
                LinkType::LinuxSll => 16,
                _ => 20,
            };
            let frame = build_cooked_frame(INVITE, header_len);
            let record = parse_frame(&frame, link, &[5060])
                .unwrap_or_else(|| panic!("debe parsear el INVITE sobre {}", link.label()));
            assert_eq!(record.summary.short(), "INVITE");
        }
    }

    /// Asterisk y el softphone en el mismo host hablan por loopback (DLT_NULL).
    #[test]
    fn parses_sip_over_loopback() {
        let frame = build_cooked_frame(INVITE, 4);
        let record = parse_frame(&frame, LinkType::Null, &[5060]).expect("debe parsear loopback");
        assert_eq!(record.summary.short(), "INVITE");
    }

    /// Longitud en formato RFC 6455 §5.2: 1 byte si entra en 7 bits, si no 1
    /// byte marcador (126) + 2 bytes big-endian (alcanza de sobra para un
    /// mensaje SIP, que nunca llega a los 64KB del marcador 127).
    fn ws_len_prefix(len: usize) -> Vec<u8> {
        if len < 126 {
            vec![len as u8]
        } else {
            let mut prefix = vec![126u8];
            prefix.extend_from_slice(&(len as u16).to_be_bytes());
            prefix
        }
    }

    /// Frame WebSocket de texto (`opcode=0x1`, `FIN=1`) sin máscara: lo que manda
    /// Asterisk hacia el softphone.
    fn ws_text_frame(body: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x81u8];
        frame.extend(ws_len_prefix(body.len()));
        frame.extend_from_slice(body);
        frame
    }

    /// Frame WebSocket de texto enmascarado: lo que manda el navegador/softphone
    /// hacia Asterisk — RFC 6455 obliga a enmascarar los frames client→server.
    fn ws_masked_text_frame(body: &[u8], key: [u8; 4]) -> Vec<u8> {
        let mut len_prefix = ws_len_prefix(body.len());
        len_prefix[0] |= 0x80;
        let mut frame = vec![0x81u8];
        frame.extend(len_prefix);
        frame.extend_from_slice(&key);
        frame.extend(body.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        frame
    }

    fn build_tcp_frame(payload: &[u8], src_port: u16, dst_port: u16) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 64)
            .tcp(src_port, dst_port, 1, 65535);

        let mut frame = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut frame, payload).unwrap();
        frame
    }

    #[test]
    fn parses_sip_over_websocket_frame_sin_mascara() {
        let frame = build_tcp_frame(&ws_text_frame(INVITE.as_bytes()), 8088, 54321);
        let record = parse_ethernet_frame(&frame, &[8088]).expect("debe desenvolver el frame WS");
        assert_eq!(record.summary.short(), "INVITE");
        assert_eq!(record.transport, Transport::Tcp);
    }

    #[test]
    fn parses_sip_over_websocket_frame_enmascarado() {
        let frame = build_tcp_frame(
            &ws_masked_text_frame(INVITE.as_bytes(), [0x12, 0x34, 0x56, 0x78]),
            54321,
            8088,
        );
        let record = parse_ethernet_frame(&frame, &[8088]).expect("debe desenmascarar el frame WS");
        assert_eq!(record.summary.short(), "INVITE");
        assert_eq!(record.call_id, "test-call-id-123@192.168.1.10");
    }

    #[test]
    fn ignora_frames_ws_fragmentados_o_de_control() {
        // FIN=0, opcode=texto: frame de continuación, no trae el mensaje entero.
        let mut fragment = vec![0x01u8, INVITE.len() as u8];
        fragment.extend_from_slice(INVITE.as_bytes());
        assert!(unwrap_websocket_frame(&fragment).is_none());

        // Frame de control (close, 0x88), FIN=1.
        assert!(unwrap_websocket_frame(&[0x88, 0x00]).is_none());
    }

    #[test]
    fn ignores_truncated_frame_shorter_than_link_header() {
        assert!(parse_frame(&[0u8; 8], LinkType::LinuxSll2, &[5060]).is_none());
    }
}

