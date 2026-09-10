use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use chrono::{DateTime, Local};

use super::packet::{self, SipPacketRecord, SipSummary};

/// Repeticiones de la misma petición (mismo Call-ID + CSeq + método) a partir
/// de las cuales se considera retransmisión por pérdida de paquete o falta de
/// respuesta, y no una duplicación normal.
const RETRANSMISSION_THRESHOLD: u32 = 2;

/// Umbral de post-dial delay: 11.0 s.
///
/// De la Tabla 2/E.721, el objetivo de percentil 95 para una conexión
/// **internacional** bajo carga normal. §2.2(b) define el post-selection
/// delay como el intervalo entre el `SETUP` con toda la selección de dígitos
/// y el primer mensaje que indica disposición de la llamada — `ALERTING`, o
/// en SIP el primer `18x` tras el `INVITE`.
///
/// Se usa el valor internacional (11.0 s) y no el local (6.0 s) ni el de
/// larga distancia (8.0 s) porque una captura no dice qué tipo de llamada
/// contiene: el umbral más permisivo es el único que no marca como falla una
/// llamada que cumplió su objetivo real.
const POST_DIAL_DELAY_SEC: f64 = 11.0;

/// Umbral de ACK ausente: 32.0 s — Timer H, RFC 3261 §17.2.1 (64×T1, T1=500ms
/// por defecto). Es exactamente "tiempo de espera para recibir el ACK": el
/// punto en que la propia especificación deja de esperarlo.
const ACK_TIMEOUT_SEC: f64 = 32.0;

/// Desafíos `401`/`407` necesarios antes de llamarlo bucle. Un único desafío
/// seguido de un reintento exitoso es el handshake normal de digest auth
/// (RFC 3261 §22.2), no una falla.
const AUTH_LOOP_MIN_CHALLENGES: usize = 2;

/// Cómo falla un bucle de autenticación. Los dos casos piden arreglos
/// distintos, así que colapsarlos en "problema de auth" tiraría la respuesta:
/// credenciales malas es un problema de aprovisionamiento; nunca mandar
/// `Authorization` es un cliente que no conoce el realm, o un proxy que
/// descarta el header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthLoopKind {
    /// El UAC responde cada desafío con `Authorization` y lo vuelven a
    /// desafiar — las credenciales están mal.
    CredentialFailure,
    /// El UAC nunca manda `Authorization`.
    SilentDrop,
}

/// Desafíos `401`/`407` repetidos en un diálogo sin llegar a un `2xx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthLoop {
    pub kind: AuthLoopKind,
    pub challenges: usize,
}

/// Un diálogo que terminó en `4xx`/`5xx`/`6xx`.
///
/// `reason_phrase`, `reason_header` y `warning` viajan aparte porque un
/// código genérico frecuentemente no dice nada por sí solo: un `503 Service
/// Unavailable` desnudo y uno con `Reason: Q.850;cause=34;text="no circuit
/// available"` son diagnósticos completamente distintos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalFailure {
    pub code: u16,
    pub reason_phrase: String,
    pub reason_header: Option<String>,
    pub warning: Option<String>,
}

/// Un `2xx` a un `INVITE` que nunca fue confirmado con `ACK`.
///
/// `waited_sec` importa porque el hallazgo depende enteramente de él: recién
/// es una falla pasado el Timer H, y sin ese número no se puede distinguir
/// una falla real de una ventana de captura simplemente impaciente.
#[derive(Debug, Clone, PartialEq)]
pub struct AckMissing {
    pub waited_sec: f64,
    /// Cuántas veces se retransmitió la respuesta, la original incluida. Un
    /// UAS que no recibe su ACK retransmite hasta el Timer H (RFC 3261
    /// §17.2.1), así que más de una transmisión es el propio peer
    /// confirmando que nunca llegó.
    pub answer_transmissions: usize,
}

/// Por qué un diálogo nunca llegó a una respuesta final.
///
/// Separados porque sólo uno de los dos es una afirmación sobre la llamada:
/// `Canceled` es un hecho — alguien mandó `CANCEL`. `NoFinalResponse` es una
/// afirmación sobre la CAPTURA — puede seguir sonando, o la ventana se cerró
/// a mitad de la llamada — y no debería redactarse como si fuera lo mismo
/// que una llamada caída.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbandonedKind {
    Canceled,
    NoFinalResponse,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Abandoned {
    pub kind: AbandonedKind,
    pub elapsed_sec: f64,
}

/// Tiempo entre el `INVITE` y el primer ring-back provisional, por encima
/// del umbral.
#[derive(Debug, Clone, PartialEq)]
pub struct PostDialDelay {
    pub delay_sec: f64,
    pub threshold_sec: f64,
    pub responded_with: u16,
}

/// Cómo un `REGISTER` decepcionó a la extensión.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationFailureKind {
    /// Rechazado directamente.
    Rejected,
    /// Aceptado, pero por menos tiempo del pedido, así que la extensión va a
    /// re-registrarse antes de lo que planeaba.
    ShortenedExpiry,
}

/// Un `REGISTER` que falló, o que tuvo éxito por menos tiempo del pedido.
///
/// Separado de [`FinalFailure`] porque la pregunta del operador es otra —
/// "¿está en línea esta extensión?" y no "¿por qué falló esta llamada?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationFailure {
    pub kind: RegistrationFailureKind,
    pub code: u16,
    pub requested_expiry_sec: Option<u32>,
    pub granted_expiry_sec: Option<u32>,
}

/// Qué tan grave es lo que le pasó a una llamada, para que la UI pueda
/// pintarlo distinto sin conocer los siete tipos de hallazgo uno por uno.
///
/// No es un `bool` porque `NoFinalResponse` sola (la llamada seguía sonando
/// cuando se cerró la captura) no es lo mismo que un `486` o un bucle de
/// autenticación, y tratarlas igual enseña a ignorar la señal real.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Nada disparó — la llamada progresó con normalidad.
    Ok,
    /// Degradación medible, o un desenlace que suele ser normal (colgó el
    /// llamante, la captura se cerró con la llamada todavía sonando).
    Notice,
    /// La llamada falló, o el registro quedó en un estado peor del pedido.
    Fault,
}

#[derive(Debug, Clone)]
pub struct CallOutcome {
    pub call_id: String,
    pub method: String,
    pub final_status: Option<String>,
    pub retransmissions: u32,
    /// Texto para mostrar de un vistazo: la unión de todos los hallazgos
    /// tipados de abajo. `None` sólo cuando ninguno disparó.
    pub issue: Option<String>,
    pub final_failure: Option<FinalFailure>,
    pub auth_loop: Option<AuthLoop>,
    pub ack_missing: Option<AckMissing>,
    pub abandoned: Option<Abandoned>,
    pub post_dial_delay: Option<PostDialDelay>,
    pub registration_failure: Option<RegistrationFailure>,
}

impl CallOutcome {
    /// La peor severidad entre los hallazgos disparados.
    #[must_use]
    pub fn severity(&self) -> Severity {
        if self.final_failure.is_some()
            || self.auth_loop.is_some()
            || self.ack_missing.is_some()
            || matches!(
                self.registration_failure.as_ref().map(|r| r.kind),
                Some(RegistrationFailureKind::Rejected)
            )
        {
            return Severity::Fault;
        }
        if self.abandoned.is_some()
            || self.post_dial_delay.is_some()
            || self.registration_failure.is_some()
            || self.retransmissions >= RETRANSMISSION_THRESHOLD
        {
            return Severity::Notice;
        }
        Severity::Ok
    }
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
/// produce un resumen con diagnóstico de fallas por llamada: error final,
/// bucle de autenticación, ACK ausente, llamada abandonada, post-dial delay
/// excesivo, registro rechazado o acortado, y retransmisiones.
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

/// Segundos entre dos timestamps, ya en punto flotante — todas las
/// detecciones de tiempo comparan contra umbrales en segundos.
fn seconds_between(from: DateTime<Local>, to: DateTime<Local>) -> f64 {
    to.signed_duration_since(from).num_milliseconds() as f64 / 1000.0
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
        SipSummary::Response { .. } => Some(p.summary.short()),
        SipSummary::Request { .. } => None,
    });

    // Un CANCEL cambia lo que significa la respuesta final: un `487 Request
    // Terminated` después de un CANCEL no es una falla, es la confirmación de
    // que colgar funcionó. Se decide primero para que las detecciones de
    // abajo sepan que este diálogo no terminó por sí solo.
    let canceled = group
        .iter()
        .any(|p| matches!(&p.summary, SipSummary::Request { method, .. } if method == "CANCEL"));

    // La respuesta final de verdad: la ÚLTIMA de código `>= 200`, no la
    // primera. Un `401` de un desafío de auth también es `>= 200`, y quedarse
    // con el primero lo confundiría con el desenlace del diálogo aunque el
    // reintento autenticado llegara después a un `200 OK`. Las retransmisiones
    // de la propia respuesta final no cambian nada acá porque comparten
    // código — eso lo cuenta `ack_missing` más abajo.
    let true_final = group.iter().rev().find_map(|p| match &p.summary {
        SipSummary::Response { code, .. } if *code >= 200 => Some(*p),
        _ => None,
    });

    let mut notes: Vec<String> = Vec::new();

    // Detección 1 — error final. No aplica sobre un diálogo cancelado: ahí el
    // desenlace lo cuenta `abandoned`, no un código de error.
    let final_failure = (!canceled)
        .then(|| {
            true_final.and_then(|p| match &p.summary {
                SipSummary::Response { code, status, .. } if (400..700).contains(code) => {
                    let reason_phrase = status
                        .split_once(' ')
                        .map(|(_, reason)| reason.to_string())
                        .unwrap_or_default();
                    Some(FinalFailure {
                        code: *code,
                        reason_phrase,
                        reason_header: p.reason_header.clone(),
                        warning: p.warning_header.clone(),
                    })
                }
                _ => None,
            })
        })
        .flatten();

    // Detección 7 — REGISTER decepcionante. Necesita el REGISTER original
    // para conocer el expiry pedido, así que se busca aparte de la respuesta.
    let registration_failure = (!canceled && method == "REGISTER")
        .then(|| {
            let register_req = group.iter().find(|p| {
                matches!(&p.summary, SipSummary::Request { method, .. } if method == "REGISTER")
            })?;
            let final_msg = true_final?;
            let SipSummary::Response { code, .. } = &final_msg.summary else {
                return None;
            };
            let requested = packet::registration_expiry(
                register_req.contact_value.as_deref(),
                register_req.expires_header_value.as_deref(),
            );
            if (200..300).contains(code) {
                let granted = packet::registration_expiry(
                    final_msg.contact_value.as_deref(),
                    final_msg.expires_header_value.as_deref(),
                );
                match (requested, granted) {
                    (Some(req), Some(grant)) if grant < req => Some(RegistrationFailure {
                        kind: RegistrationFailureKind::ShortenedExpiry,
                        code: *code,
                        requested_expiry_sec: Some(req),
                        granted_expiry_sec: Some(grant),
                    }),
                    _ => None,
                }
            } else if *code >= 300 {
                Some(RegistrationFailure {
                    kind: RegistrationFailureKind::Rejected,
                    code: *code,
                    requested_expiry_sec: requested,
                    granted_expiry_sec: None,
                })
            } else {
                None
            }
        })
        .flatten();

    // Sobre REGISTER, `registration_failure` responde la pregunta con más
    // precisión que el `final_failure` genérico — mostrar las dos duplicaría
    // el mismo hecho con dos redacciones.
    if let Some(ff) = &final_failure
        && registration_failure.is_none()
    {
        let mut text = format!("{method}: falló con {} {}", ff.code, ff.reason_phrase);
        if let Some(reason) = &ff.reason_header {
            text.push_str(&format!(" (Reason: {reason})"));
        } else if let Some(warning) = &ff.warning {
            text.push_str(&format!(" (Warning: {warning})"));
        }
        notes.push(text);
    }
    if let Some(rf) = &registration_failure {
        let text = match rf.kind {
            RegistrationFailureKind::Rejected => {
                format!("REGISTER: rechazado con {}", rf.code)
            }
            RegistrationFailureKind::ShortenedExpiry => format!(
                "REGISTER: aceptado por {}s en vez de los {}s pedidos (se re-registrará antes)",
                rf.granted_expiry_sec.unwrap_or_default(),
                rf.requested_expiry_sec.unwrap_or_default()
            ),
        };
        notes.push(text);
    }

    // Detección 5 — abandonada: canceló el llamante, o nunca llegó respuesta
    // final (y no fue por un CANCEL, que ya tiene su propia rama).
    let abandoned = if canceled || true_final.is_none() {
        let elapsed = match (group.first(), group.last()) {
            (Some(first), Some(last)) => seconds_between(first.ts, last.ts),
            _ => 0.0,
        };
        Some(Abandoned {
            kind: if canceled {
                AbandonedKind::Canceled
            } else {
                AbandonedKind::NoFinalResponse
            },
            elapsed_sec: elapsed,
        })
    } else {
        None
    };
    if let Some(ab) = &abandoned {
        let text = match ab.kind {
            AbandonedKind::Canceled => {
                format!("{method}: cancelada por el llamante a los {:.1}s", ab.elapsed_sec)
            }
            AbandonedKind::NoFinalResponse => format!(
                "{method}: sin respuesta final tras {:.1}s (posible timeout, extensión \
                 inalcanzable, o la llamada seguía sonando al cerrar la captura)",
                ab.elapsed_sec
            ),
        };
        notes.push(text);
    }

    // Detección 2 — bucle de autenticación.
    let challenges = group
        .iter()
        .filter(|p| matches!(&p.summary, SipSummary::Response { code, .. } if *code == 401 || *code == 407))
        .count();
    let reached_2xx = true_final
        .is_some_and(|p| matches!(&p.summary, SipSummary::Response { code, .. } if (200..300).contains(code)));
    let auth_loop = (!canceled && challenges >= AUTH_LOOP_MIN_CHALLENGES && !reached_2xx).then(|| {
        let answered_with_auth = group
            .iter()
            .any(|p| matches!(&p.summary, SipSummary::Request { .. }) && p.has_auth);
        AuthLoop {
            kind: if answered_with_auth {
                AuthLoopKind::CredentialFailure
            } else {
                AuthLoopKind::SilentDrop
            },
            challenges,
        }
    });
    if let Some(al) = &auth_loop {
        let why = match al.kind {
            AuthLoopKind::CredentialFailure => "credenciales rechazadas",
            AuthLoopKind::SilentDrop => "nunca envía Authorization",
        };
        notes.push(format!(
            "{method}: bucle de autenticación, {} desafíos 401/407, {why}",
            al.challenges
        ));
    }

    // Detección 4 — ACK ausente, sólo tiene sentido sobre un INVITE
    // confirmado con 2xx.
    let ack_missing = (method == "INVITE")
        .then(|| {
            let final_msg = true_final?;
            let SipSummary::Response { code, .. } = &final_msg.summary else {
                return None;
            };
            if !(200..300).contains(code) {
                return None;
            }
            let acked = group.iter().any(|p| {
                matches!(&p.summary, SipSummary::Request { method, .. } if method == "ACK")
            });
            if acked {
                return None;
            }
            let answer_transmissions = group
                .iter()
                .filter(|p| matches!(&p.summary, SipSummary::Response { code, .. } if (200..300).contains(code)))
                .count();
            let waited = group
                .last()
                .map(|last| seconds_between(final_msg.ts, last.ts))
                .unwrap_or(0.0);
            (waited >= ACK_TIMEOUT_SEC || answer_transmissions > 1).then_some(AckMissing {
                waited_sec: waited,
                answer_transmissions,
            })
        })
        .flatten();
    if let Some(am) = &ack_missing {
        notes.push(format!(
            "INVITE: 200 OK nunca confirmado con ACK, {:.1}s de espera ({} transmisión(es) de la respuesta)",
            am.waited_sec, am.answer_transmissions
        ));
    }

    // Detección 6 — post-dial delay, sólo sobre INVITE.
    let post_dial_delay = (method == "INVITE")
        .then(|| {
            let invite = group.iter().find(|p| {
                matches!(&p.summary, SipSummary::Request { method, .. } if method == "INVITE")
            })?;
            let ringing = group.iter().find(|p| {
                matches!(&p.summary, SipSummary::Response { code, .. } if (180..190).contains(code))
            })?;
            let SipSummary::Response { code, .. } = &ringing.summary else {
                return None;
            };
            let delay = seconds_between(invite.ts, ringing.ts);
            (delay >= POST_DIAL_DELAY_SEC).then_some(PostDialDelay {
                delay_sec: delay,
                threshold_sec: POST_DIAL_DELAY_SEC,
                responded_with: *code,
            })
        })
        .flatten();
    if let Some(pdd) = &post_dial_delay {
        notes.push(format!(
            "INVITE: {:.1}s hasta el primer {} (umbral {:.0}s, Tabla 2/E.721)",
            pdd.delay_sec, pdd.responded_with, pdd.threshold_sec
        ));
    }

    // Detección 3 — retransmisiones, por (método, CSeq). Cuenta de siempre;
    // ahora también reporta el lapso, porque "7 INVITEs en 32s" es
    // diagnóstico y "se detectaron retransmisiones" no.
    let mut transmissions: HashMap<(&str, &str), Vec<DateTime<Local>>> = HashMap::new();
    for p in group.iter() {
        if let SipSummary::Request { method, cseq } = &p.summary {
            transmissions
                .entry((method.as_str(), cseq.as_str()))
                .or_default()
                .push(p.ts);
        }
    }
    let mut retransmissions: u32 = 0;
    let mut retrans_notes: Vec<String> = Vec::new();
    for ((method, _cseq), mut txs) in transmissions {
        if txs.len() < 2 {
            continue;
        }
        txs.sort();
        let count = txs.len() as u32 - 1;
        retransmissions += count;
        let span = seconds_between(txs[0], txs[txs.len() - 1]);
        retrans_notes.push(format!("{count} retransmisiones de {method} en {span:.1}s"));
    }
    if retransmissions >= RETRANSMISSION_THRESHOLD {
        retrans_notes.sort();
        notes.push(format!(
            "posible pérdida de paquetes ({})",
            retrans_notes.join(", ")
        ));
    }

    CallOutcome {
        call_id,
        method,
        final_status,
        retransmissions,
        issue: (!notes.is_empty()).then(|| notes.join("; ")),
        final_failure,
        auth_loop,
        ack_missing,
        abandoned,
        post_dial_delay,
        registration_failure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip_capture::packet::Transport;
    use chrono::Duration;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    fn base(ts: DateTime<Local>, summary: SipSummary) -> SipPacketRecord {
        SipPacketRecord {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            ts,
            src: "10.0.0.5:5060".parse().unwrap(),
            dst: "10.0.0.1:5060".parse().unwrap(),
            transport: Transport::Udp,
            summary,
            call_id: "call-1".to_string(),
            from: "<sip:1001@10.0.0.5>".to_string(),
            to: "<sip:1002@10.0.0.1>".to_string(),
            from_user: Some("1001".to_string()),
            to_user: Some("1002".to_string()),
            raw: String::new(),
            has_auth: false,
            reason_header: None,
            warning_header: None,
            contact_value: None,
            expires_header_value: None,
        }
    }

    fn request(ts: DateTime<Local>, method: &str, cseq_num: u32) -> SipPacketRecord {
        base(
            ts,
            SipSummary::Request {
                method: method.to_string(),
                cseq: format!("{cseq_num} {method}"),
            },
        )
    }

    fn response(ts: DateTime<Local>, status: &str, code: u16, method: &str, cseq_num: u32) -> SipPacketRecord {
        base(
            ts,
            SipSummary::Response {
                status: status.to_string(),
                code,
                cseq: format!("{cseq_num} {method}"),
            },
        )
    }

    fn window(group: &[SipPacketRecord]) -> (DateTime<Local>, DateTime<Local>) {
        (
            group.first().unwrap().ts - Duration::seconds(1),
            group.last().unwrap().ts + Duration::seconds(1),
        )
    }

    fn analyze_group(group: Vec<SipPacketRecord>) -> CallOutcome {
        let (started_at, stopped_at) = window(&group);
        let mut packets = VecDeque::new();
        packets.extend(group);
        let summary = analyze(None, "1001".to_string(), started_at, stopped_at, &packets);
        summary.calls.into_iter().next().expect("una llamada")
    }

    #[test]
    fn un_final_4xx_se_reporta_con_su_reason_header() {
        let t0 = Local::now();
        let mut busy = response(t0 + Duration::seconds(1), "486 Busy Here", 486, "INVITE", 1);
        busy.reason_header = Some("Q.850;cause=17;text=\"user busy\"".to_string());
        let outcome = analyze_group(vec![request(t0, "INVITE", 1), busy]);

        let ff = outcome.final_failure.expect("debe detectar el final failure");
        assert_eq!(ff.code, 486);
        assert_eq!(ff.reason_phrase, "Busy Here");
        assert!(outcome.issue.unwrap().contains("Q.850;cause=17"));
    }

    #[test]
    fn un_cancel_se_distingue_de_una_llamada_sin_respuesta() {
        let t0 = Local::now();
        let outcome = analyze_group(vec![
            request(t0, "INVITE", 1),
            request(t0 + Duration::seconds(2), "CANCEL", 2),
        ]);

        assert_eq!(
            outcome.abandoned.map(|a| a.kind),
            Some(AbandonedKind::Canceled)
        );
        assert!(outcome.issue.unwrap().contains("cancelada por el llamante"));
    }

    #[test]
    fn una_llamada_sin_ninguna_respuesta_no_se_confunde_con_un_cancel() {
        let t0 = Local::now();
        let outcome = analyze_group(vec![request(t0, "INVITE", 1)]);

        assert_eq!(
            outcome.abandoned.map(|a| a.kind),
            Some(AbandonedKind::NoFinalResponse)
        );
    }

    #[test]
    fn un_solo_desafio_401_no_es_un_bucle() {
        let t0 = Local::now();
        let mut ack_req = request(t0 + Duration::milliseconds(600), "INVITE", 1);
        ack_req.has_auth = true;
        let outcome = analyze_group(vec![
            request(t0, "INVITE", 1),
            response(t0 + Duration::milliseconds(200), "401 Unauthorized", 401, "INVITE", 1),
            ack_req,
            response(t0 + Duration::milliseconds(800), "200 OK", 200, "INVITE", 1),
        ]);

        assert!(outcome.auth_loop.is_none());
    }

    #[test]
    fn credenciales_repetidas_sin_llegar_a_2xx_es_credential_failure() {
        let t0 = Local::now();
        let mut retry1 = request(t0 + Duration::milliseconds(200), "INVITE", 2);
        retry1.has_auth = true;
        let mut retry2 = request(t0 + Duration::milliseconds(400), "INVITE", 3);
        retry2.has_auth = true;
        let outcome = analyze_group(vec![
            request(t0, "INVITE", 1),
            response(t0 + Duration::milliseconds(100), "401 Unauthorized", 401, "INVITE", 1),
            retry1,
            response(t0 + Duration::milliseconds(300), "401 Unauthorized", 401, "INVITE", 2),
            retry2,
            response(t0 + Duration::milliseconds(500), "401 Unauthorized", 401, "INVITE", 3),
        ]);

        assert_eq!(
            outcome.auth_loop.map(|a| a.kind),
            Some(AuthLoopKind::CredentialFailure)
        );
    }

    #[test]
    fn un_proxy_que_descarta_authorization_es_silent_drop() {
        let t0 = Local::now();
        let outcome = analyze_group(vec![
            request(t0, "REGISTER", 1),
            response(t0 + Duration::milliseconds(100), "401 Unauthorized", 401, "REGISTER", 1),
            request(t0 + Duration::milliseconds(200), "REGISTER", 2),
            response(t0 + Duration::milliseconds(300), "401 Unauthorized", 401, "REGISTER", 2),
        ]);

        assert_eq!(
            outcome.auth_loop.map(|a| a.kind),
            Some(AuthLoopKind::SilentDrop)
        );
    }

    #[test]
    fn un_200_sin_ack_y_retransmitido_dispara_ack_missing() {
        let t0 = Local::now();
        let outcome = analyze_group(vec![
            request(t0, "INVITE", 1),
            response(t0 + Duration::seconds(1), "200 OK", 200, "INVITE", 1),
            response(t0 + Duration::seconds(5), "200 OK", 200, "INVITE", 1),
        ]);

        let am = outcome.ack_missing.expect("debe detectar el ACK ausente");
        assert_eq!(am.answer_transmissions, 2);
    }

    #[test]
    fn un_ack_presente_no_dispara_nada() {
        let t0 = Local::now();
        let outcome = analyze_group(vec![
            request(t0, "INVITE", 1),
            response(t0 + Duration::seconds(1), "200 OK", 200, "INVITE", 1),
            request(t0 + Duration::seconds(1) + Duration::milliseconds(50), "ACK", 1),
        ]);

        assert!(outcome.ack_missing.is_none());
    }

    #[test]
    fn un_ring_back_tardio_dispara_post_dial_delay() {
        let t0 = Local::now();
        let outcome = analyze_group(vec![
            request(t0, "INVITE", 1),
            response(t0 + Duration::seconds(15), "180 Ringing", 180, "INVITE", 1),
        ]);

        let pdd = outcome.post_dial_delay.expect("debe detectar el post-dial delay");
        assert_eq!(pdd.responded_with, 180);
        assert!(pdd.delay_sec >= 15.0);
    }

    #[test]
    fn un_ring_back_rapido_no_dispara_nada() {
        let t0 = Local::now();
        let outcome = analyze_group(vec![
            request(t0, "INVITE", 1),
            response(t0 + Duration::seconds(1), "180 Ringing", 180, "INVITE", 1),
            response(t0 + Duration::seconds(2), "200 OK", 200, "INVITE", 1),
            request(t0 + Duration::milliseconds(2050), "ACK", 1),
        ]);

        assert!(outcome.post_dial_delay.is_none());
    }

    #[test]
    fn un_register_rechazado_no_duplica_el_final_failure_generico() {
        let t0 = Local::now();
        let outcome = analyze_group(vec![
            request(t0, "REGISTER", 1),
            response(t0 + Duration::seconds(1), "403 Forbidden", 403, "REGISTER", 1),
        ]);

        assert!(outcome.final_failure.is_some());
        let rf = outcome.registration_failure.expect("debe detectar el rechazo");
        assert_eq!(rf.kind, RegistrationFailureKind::Rejected);
        assert_eq!(rf.code, 403);
        let issue = outcome.issue.unwrap();
        assert_eq!(issue.matches("REGISTER").count(), 1, "no debe repetir el mismo hecho dos veces: {issue}");
    }

    #[test]
    fn un_register_con_expiry_acortado_lo_reporta() {
        let t0 = Local::now();
        let mut req = request(t0, "REGISTER", 1);
        req.contact_value = Some("<sip:1001@10.0.0.5>;expires=3600".to_string());
        let mut ok = response(t0 + Duration::seconds(1), "200 OK", 200, "REGISTER", 1);
        ok.contact_value = Some("<sip:1001@10.0.0.5>;expires=60".to_string());
        let outcome = analyze_group(vec![req, ok]);

        let rf = outcome.registration_failure.expect("debe detectar el acortamiento");
        assert_eq!(rf.kind, RegistrationFailureKind::ShortenedExpiry);
        assert_eq!(rf.requested_expiry_sec, Some(3600));
        assert_eq!(rf.granted_expiry_sec, Some(60));
    }

    #[test]
    fn un_register_exitoso_sin_acortar_no_reporta_nada() {
        let t0 = Local::now();
        let mut req = request(t0, "REGISTER", 1);
        req.contact_value = Some("<sip:1001@10.0.0.5>;expires=3600".to_string());
        let mut ok = response(t0 + Duration::seconds(1), "200 OK", 200, "REGISTER", 1);
        ok.contact_value = Some("<sip:1001@10.0.0.5>;expires=3600".to_string());
        let outcome = analyze_group(vec![req, ok]);

        assert!(outcome.registration_failure.is_none());
        assert!(outcome.issue.is_none());
    }

    #[test]
    fn retransmisiones_reportan_metodo_y_lapso() {
        let t0 = Local::now();
        let outcome = analyze_group(vec![
            request(t0, "INVITE", 1),
            request(t0 + Duration::seconds(1), "INVITE", 1),
            request(t0 + Duration::seconds(3), "INVITE", 1),
            response(t0 + Duration::seconds(4), "200 OK", 200, "INVITE", 1),
            request(t0 + Duration::milliseconds(4050), "ACK", 1),
        ]);

        assert_eq!(outcome.retransmissions, 2);
        assert!(outcome.issue.unwrap().contains("retransmisiones de INVITE"));
    }

    #[test]
    fn una_sola_repeticion_no_llega_al_umbral() {
        let t0 = Local::now();
        let outcome = analyze_group(vec![
            request(t0, "OPTIONS", 1),
            request(t0 + Duration::seconds(1), "OPTIONS", 1),
            response(t0 + Duration::seconds(2), "200 OK", 200, "OPTIONS", 1),
        ]);

        assert_eq!(outcome.retransmissions, 1);
        assert!(outcome.issue.is_none());
    }
}
