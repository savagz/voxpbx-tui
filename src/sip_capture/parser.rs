use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Local;
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use rsip::SipMessage;
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
    let message = SipMessage::try_from(payload).ok()?;

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

    let summary = match &message {
        SipMessage::Request(request) => SipSummary::Request {
            method: request.method().to_string(),
            cseq,
        },
        SipMessage::Response(response) => SipSummary::Response {
            status: response.status_code().to_string(),
            cseq,
        },
    };

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
        raw: String::from_utf8_lossy(payload).into_owned(),
    })
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

    #[test]
    fn ignores_truncated_frame_shorter_than_link_header() {
        assert!(parse_frame(&[0u8; 8], LinkType::LinuxSll2, &[5060]).is_none());
    }
}

