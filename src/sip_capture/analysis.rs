use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use chrono::{DateTime, Local};

use super::packet::{SipPacketRecord, SipSummary};

/// Umbral de repeticiones de la misma petición (mismo Call-ID + CSeq + método)
/// a partir del cual se considera retransmisión por pérdida de paquete o falta de ACK.
const RETRANSMISSION_THRESHOLD: u32 = 2;

#[derive(Debug, Clone)]
pub struct CallOutcome {
    pub call_id: String,
    pub method: String,
    pub final_status: Option<String>,
    pub retransmissions: u32,
    pub issue: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TraceSummary {
    pub extension: String,
    pub started_at: DateTime<Local>,
    pub stopped_at: DateTime<Local>,
    pub packet_count: usize,
    pub calls: Vec<CallOutcome>,
    /// `None` = sin fallas detectadas. `Some(..)` = resumen de la falla identificada.
    pub fault: Option<String>,
}

/// Analiza los paquetes SIP de la extensión entre `started_at` y `stopped_at` y
/// produce un resumen con diagnóstico de fallas por llamada (sin respuesta,
/// error 4xx/5xx/6xx, o retransmisiones excesivas).
///
/// `peer_ip` es opcional porque AMI no siempre devuelve una IP usable; en ese caso
/// el pertenecer a la extensión se decide sólo por las URIs From/To.
pub fn analyze(
    peer_ip: Option<IpAddr>,
    extension: String,
    started_at: DateTime<Local>,
    stopped_at: DateTime<Local>,
    packets: &VecDeque<SipPacketRecord>,
) -> TraceSummary {
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<&SipPacketRecord>> = HashMap::new();

    for p in packets
        .iter()
        .filter(|p| p.ts >= started_at && p.ts <= stopped_at)
        .filter(|p| p.involves(peer_ip, &extension))
    {
        groups.entry(p.call_id.clone()).or_insert_with(|| {
            order.push(p.call_id.clone());
            Vec::new()
        });
        groups.get_mut(&p.call_id).unwrap().push(p);
    }

    let packet_count: usize = groups.values().map(|g| g.len()).sum();

    if packet_count == 0 {
        return TraceSummary {
            extension,
            started_at,
            stopped_at,
            packet_count: 0,
            calls: Vec::new(),
            fault: Some(
                "No se capturó tráfico SIP de la extensión durante la ventana de captura \
                 (posible extensión caída, sin registro activo, o interfaz/filtro de captura \
                 incorrectos)."
                    .to_string(),
            ),
        };
    }

    let calls: Vec<CallOutcome> = order
        .into_iter()
        .map(|call_id| build_outcome(call_id, &groups))
        .collect();

    let issues: Vec<String> = calls.iter().filter_map(|c| c.issue.clone()).collect();
    let fault = if issues.is_empty() {
        None
    } else {
        Some(issues.join(" | "))
    };

    TraceSummary {
        extension,
        started_at,
        stopped_at,
        packet_count,
        calls,
        fault,
    }
}

fn build_outcome(call_id: String, groups: &HashMap<String, Vec<&SipPacketRecord>>) -> CallOutcome {
    let group = &groups[&call_id];

    let method = group
        .iter()
        .find_map(|p| match &p.summary {
            SipSummary::Request { method, .. } => Some(method.clone()),
            SipSummary::Response { .. } => None,
        })
        .unwrap_or_else(|| "?".to_string());

    let final_status = group.iter().rev().find_map(|p| match &p.summary {
        SipSummary::Response { status, .. } => Some(status.clone()),
        SipSummary::Request { .. } => None,
    });

    let mut seen: HashMap<(String, String), u32> = HashMap::new();
    for p in group.iter() {
        if let SipSummary::Request { method, cseq } = &p.summary {
            *seen.entry((method.clone(), cseq.clone())).or_insert(0) += 1;
        }
    }
    let retransmissions = seen.values().filter(|&&n| n > 1).map(|&n| n - 1).sum();

    let mut issue = match &final_status {
        None => Some(format!(
            "{method}: sin respuesta (posible timeout o extensión inalcanzable)"
        )),
        Some(status) => match status.chars().next() {
            Some('4') => Some(format!("{method}: rechazada con {status}")),
            Some('5') => Some(format!("{method}: error de servidor {status}")),
            Some('6') => Some(format!("{method}: rechazo global {status}")),
            Some('3') => Some(format!("{method}: redirigida ({status})")),
            _ => None,
        },
    };

    if retransmissions >= RETRANSMISSION_THRESHOLD {
        let retrans_msg = format!("{method}: {retransmissions} retransmisiones (posible pérdida de paquetes)");
        issue = Some(match issue {
            Some(existing) => format!("{existing}; {retrans_msg}"),
            None => retrans_msg,
        });
    }

    CallOutcome {
        call_id,
        method,
        final_status,
        retransmissions,
        issue,
    }
}
