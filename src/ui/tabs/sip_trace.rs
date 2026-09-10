use std::collections::HashMap;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::Color,
    text::{Line, Span},
    widgets::{Paragraph, Row, Table, TableState, Wrap},
};

use crate::app::App;
use crate::sip_capture::analysis::{CallOutcome, Severity, TraceSummary};
use crate::sip_capture::packet::SipPacketRecord;
use crate::theme::Status;
use crate::ui::widgets::panel;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let accent = app.theme.tab_accent(4);

    if let Some(err) = &app.sip_capture_error {
        render_error(frame, area, app, err);
        return;
    }

    if app.sip_call_flow.is_some() {
        render_call_flow(frame, area, app, accent);
        return;
    }

    let filtered = app.sip_filtered_packets();
    let notice = notice_height(app, &filtered);
    let mix = u16::from(!filtered.is_empty());

    let (list, detail, summary) = match app.sip_trace_summary {
        Some(_) => (40, 30, 30),
        None => (55, 45, 0),
    };

    let mut constraints = vec![
        Constraint::Length(notice),
        Constraint::Length(mix),
        Constraint::Percentage(list),
        Constraint::Percentage(detail),
    ];
    if summary > 0 {
        constraints.push(Constraint::Percentage(summary));
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    render_notice(frame, chunks[0], app, &filtered);
    render_mix(frame, chunks[1], app, &filtered);
    render_list(frame, chunks[2], app, &filtered, accent);
    let selected = selected_index(app, &filtered).and_then(|i| filtered.get(i)).copied();
    render_detail(frame, chunks[3], app, selected);

    if let Some(trace) = &app.sip_trace_summary {
        render_summary(frame, chunks[4], app, trace);
    }
}

/// Fila actualmente apuntada. Con el seguimiento activo es siempre la última
/// capturada: un trace en vivo que no avanza solo obliga a perseguir el tráfico
/// a mano y da la falsa impresión de que sólo llega un tipo de mensaje.
fn selected_index(app: &App, packets: &[&SipPacketRecord]) -> Option<usize> {
    if packets.is_empty() {
        return None;
    }
    let last = packets.len() - 1;
    Some(if app.sip_follow {
        last
    } else {
        app.sip_selected_row.min(last)
    })
}

fn render_error(frame: &mut Frame, area: Rect, app: &App, err: &str) {
    let theme = &app.theme;
    let block = panel::block(theme, "sip trace · fuera de servicio", theme.error, true);

    let lines = vec![
        Line::from(Span::styled(
            format!("Captura deshabilitada: {err}"),
            theme.style_for(Status::Error),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Verificá que la interfaz configurada exista y que el binario tenga permisos de captura.",
            theme.label_style(),
        )),
        Line::from(vec![
            Span::styled(" C ", theme.plate_style(theme.accent_primary)),
            Span::styled(
                " abre la configuración: ahí se re-chequea libpcap y se aplican los permisos (F10).",
                theme.label_style(),
            ),
        ]),
    ];

    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

fn filter_label(app: &App) -> String {
    match app.sip_selected_peer() {
        Some(peer) => format!("ext {} · {}", peer.name, peer.tech.label()),
        None => "todas las extensiones".to_string(),
    }
}

/// Altura de la banda de aviso: 0 cuando no hay nada que advertir.
fn notice_height(app: &App, filtered: &[&SipPacketRecord]) -> u16 {
    if blind_capture(app) || empty_filter(app, filtered) {
        2
    } else {
        0
    }
}

/// El filtro BPF ve tráfico pero nada resulta SIP legible.
fn blind_capture(app: &App) -> bool {
    app.sip_capture_status
        .as_ref()
        .is_some_and(|s| s.seen > 0 && s.parsed == 0)
}

/// Hay paquetes SIP capturados, pero ninguno es de la extensión elegida.
fn empty_filter(app: &App, filtered: &[&SipPacketRecord]) -> bool {
    app.sip_filter_index.is_some() && filtered.is_empty() && !app.sip_packets.is_empty()
}

fn render_notice(frame: &mut Frame, area: Rect, app: &App, filtered: &[&SipPacketRecord]) {
    if area.height == 0 {
        return;
    }
    let theme = &app.theme;

    let line = if blind_capture(app) {
        let status = app.sip_capture_status.as_ref().expect("blind implica status");
        Line::from(vec![
            Span::styled(" SIN SIP ", theme.plate_style(theme.warning)),
            Span::styled(
                format!(
                    " {} paquetes pasaron el filtro ({}) pero ninguno es SIP legible: revisá los puertos, o el tráfico está cifrado (TLS).",
                    status.seen, status.filter
                ),
                theme.style_for(Status::Warning),
            ),
        ])
    } else if empty_filter(app, filtered) {
        let peer = app
            .sip_selected_peer()
            .expect("empty_filter implica peer");
        Line::from(vec![
            Span::styled(" SIN COINCIDENCIAS ", theme.plate_style(theme.warning)),
            Span::styled(
                format!(
                    " ext {} [{}] (IP según AMI: {}) no aparece en los {} paquetes capturados. F cambia de extensión.",
                    peer.name,
                    peer.tech.label(),
                    if peer.ip.is_empty() { "—" } else { &peer.ip },
                    app.sip_packets.len()
                ),
                theme.style_for(Status::Warning),
            ),
        ])
    } else {
        return;
    };

    frame.render_widget(Paragraph::new(line).wrap(Wrap { trim: true }), area);
}

/// Desglose por tipo de mensaje: responde de un vistazo "¿qué estoy viendo?"
/// sin tener que recorrer la lista.
fn render_mix(frame: &mut Frame, area: Rect, app: &App, packets: &[&SipPacketRecord]) {
    if area.height == 0 || packets.is_empty() {
        return;
    }
    let theme = &app.theme;

    let mut counts: HashMap<String, usize> = HashMap::new();
    for p in packets {
        *counts.entry(p.summary.short()).or_insert(0) += 1;
    }

    let mut mix: Vec<(String, usize)> = counts.into_iter().collect();
    mix.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut spans = vec![Span::styled(" MEZCLA ", theme.plate_style(theme.accent_secondary))];
    for (label, count) in mix.iter().take(8) {
        spans.push(Span::styled(format!("  {label} "), theme.value_style()));
        spans.push(Span::styled(count.to_string(), theme.readout_style()));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_list(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    packets: &[&SipPacketRecord],
    accent: Color,
) {
    let theme = &app.theme;

    let (border, footer, footer_color) = if app.sip_trace_active {
        (theme.error, "● GRABANDO · S detiene".to_string(), theme.error)
    } else {
        (accent, capture_footer(app, packets.len()), theme.fg_muted)
    };

    let block = panel::block(
        theme,
        &format!("sip trace · {}", filter_label(app)),
        border,
        app.sip_trace_active,
    )
    .title_bottom(panel::readout(theme, &footer, footer_color));

    let header = Row::new(["HORA", "ORIGEN", "DESTINO", "MENSAJE", "CALL-ID"])
        .style(theme.table_header_style());

    let rows = packets.iter().map(|p| {
        Row::new([
            p.ts.format("%H:%M:%S%.3f").to_string(),
            p.src.to_string(),
            p.dst.to_string(),
            p.summary.short(),
            p.call_id.clone(),
        ])
        .style(theme.value_style())
    });

    let widths = [
        Constraint::Length(13),
        Constraint::Percentage(22),
        Constraint::Percentage(22),
        Constraint::Percentage(13),
        Constraint::Percentage(30),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(2)
        .row_highlight_style(theme.selected_row_style())
        .highlight_symbol("▶")
        .block(block);

    // El estado es local al dibujado: ratatui calcula el offset para que la fila
    // seleccionada quede a la vista, que es lo que hace scrollear la lista.
    let mut state = TableState::new().with_selected(selected_index(app, packets));
    frame.render_stateful_widget(table, area, &mut state);
}

/// Pie del panel: de dónde sale el tráfico y cuánto de lo capturado se reconoció
/// como SIP. Es el dato que separa "no llega nada" de "llega pero no se parsea".
fn capture_footer(app: &App, shown: usize) -> String {
    let follow = if app.sip_follow {
        "siguiendo (G)"
    } else {
        "detenido (G sigue)"
    };

    match &app.sip_capture_status {
        Some(status) => format!(
            "{} · {} · {} vistos / {} SIP · {shown} en lista · {follow} · ↵ secuencia · L limpiar",
            status.interface, status.link, status.seen, status.parsed
        ),
        None => format!("{shown} paquetes · {follow} · ↵ secuencia · L limpiar"),
    }
}

fn render_detail(frame: &mut Frame, area: Rect, app: &App, selected: Option<&SipPacketRecord>) {
    let theme = &app.theme;
    let block = panel::block(theme, "detalle del mensaje", theme.accent_secondary, false);

    let lines = match selected {
        Some(p) => {
            let (summary_extra, cseq) = match &p.summary {
                crate::sip_capture::packet::SipSummary::Request { method, cseq } => {
                    (format!("REQUEST {method}"), cseq.clone())
                }
                crate::sip_capture::packet::SipSummary::Response { status, cseq, .. } => {
                    (format!("RESPONSE {status}"), cseq.clone())
                }
            };
            vec![
                Line::from(vec![
                    Span::styled(format!("#{} ", p.id), theme.label_style()),
                    Span::styled(summary_extra, theme.style_for_bold()),
                    Span::styled(
                        format!("  [{}]", p.transport.label()),
                        theme.readout_style(),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("FROM  ", theme.label_style()),
                    Span::styled(p.from.clone(), theme.value_style()),
                ]),
                Line::from(vec![
                    Span::styled("TO    ", theme.label_style()),
                    Span::styled(p.to.clone(), theme.value_style()),
                ]),
                Line::from(vec![
                    Span::styled("CSEQ  ", theme.label_style()),
                    Span::styled(cseq, theme.value_style()),
                ]),
                Line::from(""),
                Line::from(Span::styled(p.raw.clone(), theme.value_style())),
            ]
        }
        None => vec![Line::from(Span::styled(
            "Sin paquetes capturados todavía.",
            theme.label_style(),
        ))],
    };

    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: false }),
        area,
    );
}

fn render_summary(frame: &mut Frame, area: Rect, app: &App, summary: &TraceSummary) {
    let theme = &app.theme;

    // La peor severidad entre las llamadas decide el color: un aviso ("todavía
    // sonando", "registro acortado") no debería pintar el panel entero como
    // si la extensión hubiera fallado.
    let worst = summary
        .calls
        .iter()
        .map(CallOutcome::severity)
        .max()
        .unwrap_or(Severity::Ok);
    let (verdict_text, verdict_status) = match (&summary.fault, worst) {
        (Some(fault), Severity::Fault) | (Some(fault), Severity::Ok) => {
            (format!("FALLA: {fault}"), Status::Error)
        }
        (Some(fault), Severity::Notice) => (format!("AVISO: {fault}"), Status::Warning),
        (None, _) => (
            "Sin fallas detectadas en la ventana capturada.".to_string(),
            Status::Ok,
        ),
    };
    let verdict_color = theme.color_for(verdict_status);

    let block = panel::block(
        theme,
        &format!("diagnóstico · ext {}", summary.extension),
        verdict_color,
        true,
    )
    .title_bottom(panel::readout(
        theme,
        &format!(
            "{} → {}",
            summary.started_at.format("%H:%M:%S"),
            summary.stopped_at.format("%H:%M:%S")
        ),
        theme.fg_muted,
    ));

    let mut lines = vec![
        Line::from(vec![
            Span::styled("PAQUETES ", theme.label_style()),
            Span::styled(summary.packet_count.to_string(), theme.readout_style()),
            Span::styled("   LLAMADAS ", theme.label_style()),
            Span::styled(summary.calls.len().to_string(), theme.readout_style()),
        ]),
        Line::from(Span::styled(verdict_text, theme.style_for(verdict_status))),
        Line::from(""),
    ];

    for call in &summary.calls {
        let status = call.final_status.as_deref().unwrap_or("sin respuesta");
        let call_status = match call.severity() {
            Severity::Fault => Status::Error,
            Severity::Notice => Status::Warning,
            Severity::Ok => Status::Ok,
        };
        let mut row = vec![
            Span::styled(format!("{}  ", call.method), theme.style_for_bold()),
            Span::styled(format!("{status}  "), theme.style_for(call_status)),
            Span::styled(call.call_id.clone(), theme.label_style()),
        ];
        if call.retransmissions > 0 {
            row.push(Span::styled(
                format!("  ({} retx)", call.retransmissions),
                theme.style_for(Status::Warning),
            ));
        }
        lines.push(Line::from(row));
        if let Some(issue) = &call.issue {
            lines.push(Line::from(Span::styled(
                format!("  └ {issue}"),
                theme.style_for(call_status),
            )));
        }
    }

    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: false }),
        area,
    );
}

/// Vista de secuencia (ladder) de una llamada: diagrama de flechas a la
/// izquierda, texto crudo del mensaje resaltado a la derecha — como Wireshark
/// "VoIP calls" pero para lo que ve `sip_capture`, sin RTP (no se captura media).
fn render_call_flow(frame: &mut Frame, area: Rect, app: &App, accent: Color) {
    let packets = app.sip_call_flow_packets();
    let call_id = app.sip_call_flow.as_deref().unwrap_or_default();
    let selected = if packets.is_empty() {
        None
    } else {
        Some(app.sip_call_flow_selected.min(packets.len() - 1))
    };

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    render_ladder(frame, chunks[0], app, call_id, &packets, selected, accent);
    render_detail(frame, chunks[1], app, selected.and_then(|i| packets.get(i)).copied());
}

/// Extremos de la llamada: el primer mensaje manda quién es "izquierda" (origen)
/// y quién "derecha" (destino) — típicamente el INVITE inicial, caller→callee.
fn ladder_endpoints(packets: &[&SipPacketRecord]) -> (String, String) {
    match packets.first() {
        Some(p) => (p.src.to_string(), p.dst.to_string()),
        None => (String::new(), String::new()),
    }
}

fn ladder_color(theme: &crate::theme::Theme, p: &SipPacketRecord) -> Color {
    use crate::sip_capture::packet::SipSummary;
    match &p.summary {
        SipSummary::Request { method, .. } if method == "BYE" || method == "CANCEL" => theme.error,
        SipSummary::Request { .. } => theme.accent_primary,
        SipSummary::Response { code, .. } if *code < 200 => theme.warning,
        SipSummary::Response { code, .. } if *code < 300 => theme.ok,
        SipSummary::Response { .. } => theme.error,
    }
}

/// Etiqueta del mensaje tal como la muestra el ladder: método/status, más
/// `(SDP)` si el cuerpo trae oferta/respuesta de media.
fn ladder_label(p: &SipPacketRecord) -> String {
    let has_sdp = p.raw.to_ascii_lowercase().contains("application/sdp");
    if has_sdp {
        format!("{} (SDP)", p.summary.short())
    } else {
        p.summary.short()
    }
}

/// Cabecera del ladder: una dirección pegada a cada extremo del ancho
/// disponible, como los dos "carriles" del diagrama.
fn pad_endpoints(width: usize, left: &str, right: &str) -> String {
    let filler = width.saturating_sub(left.chars().count() + right.chars().count());
    format!("{left}{}{right}", " ".repeat(filler))
}

/// Dibuja el texto de una fila del ladder: tiempo relativo al mensaje anterior
/// más una flecha ASCII centrada con la etiqueta, apuntando según quién mandó
/// el mensaje respecto del primer paquete de la llamada (`left_addr`).
fn ladder_line(width: usize, label: &str, right: bool) -> String {
    let arrow = if right { '►' } else { '◄' };
    let label_len = label.chars().count();
    // Ancho mínimo decente: flecha + espacio + label + espacio. Si no entra,
    // se corta el relleno de guiones pero el label se muestra igual.
    let filler = width.saturating_sub(label_len + 3);
    let left = filler / 2;
    let right_pad = filler - left;
    if right {
        format!("{} {} {}{arrow}", "─".repeat(left), label, "─".repeat(right_pad.saturating_sub(1)))
    } else {
        format!("{arrow}{} {} {}", "─".repeat(left.saturating_sub(1)), label, "─".repeat(right_pad))
    }
}

fn render_ladder(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    call_id: &str,
    packets: &[&SipPacketRecord],
    selected: Option<usize>,
    accent: Color,
) {
    let theme = &app.theme;
    let block = panel::block(theme, &format!("secuencia · {call_id}"), accent, false)
        .title_bottom(panel::readout(
            theme,
            "↑↓ moverse · Esc volver a la lista",
            theme.fg_muted,
        ));

    if packets.is_empty() {
        frame.render_widget(
            Paragraph::new("Esta llamada ya no tiene paquetes en el buffer.")
                .block(block)
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let (left_addr, right_addr) = ladder_endpoints(packets);
    // Ancho de la columna de flechas: lo que sobra del área después de los 2
    // bordes del panel, el gutter de 1 char que reserva `highlight_symbol`, la
    // columna de tiempo (13) y el espaciado entre columnas de la tabla (1).
    let ladder_width = area.width.saturating_sub(2 + 1 + 13 + 1) as usize;

    let header_text = pad_endpoints(ladder_width, &left_addr, &right_addr);
    let header = Row::new([
        Span::raw(""),
        Span::styled(header_text, theme.style_for_bold()),
    ])
    .style(theme.table_header_style());

    let rows = packets.iter().enumerate().map(|(i, p)| {
        // Delta contra el mensaje anterior de la llamada, no contra el inicio:
        // es lo que responde "¿cuánto tardó en contestar esto?" fila a fila.
        let delta = match i.checked_sub(1) {
            Some(prev) => {
                let ms = (p.ts - packets[prev].ts).num_milliseconds().max(0);
                format!("+{:.3}s", ms as f64 / 1000.0)
            }
            None => "+0.000s".to_string(),
        };
        let color = ladder_color(theme, p);
        let right = p.src.to_string() == left_addr;
        let text = ladder_line(ladder_width, &ladder_label(p), right);
        Row::new([
            Span::styled(delta, theme.readout_style()),
            Span::styled(text, theme.style_for_color(color)),
        ])
    });

    let widths = [Constraint::Length(13), Constraint::Min(10)];

    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(theme.selected_row_style())
        .highlight_symbol("▶")
        .block(block);

    let mut state = TableState::new().with_selected(selected);
    frame.render_stateful_widget(table, area, &mut state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ami::Peer;
    use crate::app::Reload;
    use crate::config::Config;
    use crate::sip_capture::packet::{SipSummary, Transport};
    use chrono::Local;
    use ratatui::{Terminal, backend::TestBackend};
    use tokio::sync::watch;

    fn app() -> App {
        let config = Config::default();
        let (ami, _ami_rx) = watch::channel(crate::ami::client::AmiSettings::from_config(&config));
        let (capture, _capture_rx) = watch::channel(config.capture.clone());
        App::new(config, Reload { ami, capture })
    }

    fn packet(id: u64, method: &str, from_user: &str) -> SipPacketRecord {
        SipPacketRecord {
            id,
            ts: Local::now(),
            src: "10.0.0.5:5060".parse().unwrap(),
            dst: "10.0.0.1:5060".parse().unwrap(),
            transport: Transport::Udp,
            summary: SipSummary::Request {
                method: method.to_string(),
                cseq: format!("{id} {method}"),
            },
            call_id: format!("call-{id}"),
            from: format!("<sip:{from_user}@10.0.0.5>"),
            to: "<sip:1002@10.0.0.1>".to_string(),
            from_user: Some(from_user.to_string()),
            to_user: Some("1002".to_string()),
            raw: String::new(),
            has_auth: false,
            reason_header: None,
            warning_header: None,
            contact_value: None,
            expires_header_value: None,
        }
    }

    /// Variante de `packet` que fija el `call_id` a mano, para armar una
    /// secuencia de varios mensajes de la misma llamada.
    fn call_packet(id: u64, method: &str, call_id: &str) -> SipPacketRecord {
        SipPacketRecord {
            call_id: call_id.to_string(),
            ..packet(id, method, "1001")
        }
    }

    /// Respuesta de vuelta (src/dst invertidos respecto de `call_packet`), como
    /// la contestación del callee a un `INVITE`.
    fn call_response(id: u64, status: &str, code: u16, call_id: &str) -> SipPacketRecord {
        SipPacketRecord {
            src: "10.0.0.1:5060".parse().unwrap(),
            dst: "10.0.0.5:5060".parse().unwrap(),
            summary: SipSummary::Response {
                status: status.to_string(),
                code,
                cseq: format!("{id} INVITE"),
            },
            call_id: call_id.to_string(),
            ..packet(id, "unused", "1001")
        }
    }

    fn rendered(app: &App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render(frame, frame.area(), app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..height)
            .map(|row| {
                (0..width)
                    .map(|col| buffer[(col, row)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Regresión: sin scroll la tabla dibujaba siempre desde la fila 0, así que
    /// con el buffer lleno se veían sólo los paquetes más viejos y parecía que
    /// llegaba un único tipo de mensaje.
    #[test]
    fn la_lista_sigue_al_ultimo_paquete_capturado() {
        let mut app = app();
        for id in 0..500 {
            let method = if id == 499 { "INVITE" } else { "OPTIONS" };
            app.sip_packets.push_back(packet(id, method, "1001"));
        }

        let screen = rendered(&app, 110, 30);
        assert!(screen.contains("call-499"), "debe mostrar el último paquete");
        assert!(screen.contains("INVITE"), "debe mostrar el mensaje más reciente");
    }

    #[test]
    fn al_navegar_a_mano_deja_de_seguir_y_muestra_la_fila_elegida() {
        let mut app = app();
        for id in 0..500 {
            app.sip_packets.push_back(packet(id, "OPTIONS", "1001"));
        }
        app.sip_follow = false;
        app.sip_selected_row = 0;

        assert!(rendered(&app, 110, 30).contains("call-0"));
    }

    /// La IP que reporta AMI puede no ser la del tráfico (NAT, registro desde otra
    /// dirección, campo vacío): filtrar sólo por IP dejaba la extensión en blanco.
    #[test]
    fn el_filtro_por_extension_matchea_por_usuario_sip_aunque_la_ip_no_coincida() {
        let mut app = app();
        app.sip_packets.push_back(packet(1, "INVITE", "1001"));
        app.sip_packets.push_back(packet(2, "INVITE", "1009"));
        app.peers = vec![Peer {
            name: "1001".to_string(),
            ip: "192.168.77.77".to_string(),
            status: "OK (1 ms)".to_string(),
            tech: crate::ami::Tech::Sip,
        }];
        app.sip_filter_index = Some(0);

        let filtered = app.sip_filtered_packets();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].call_id, "call-1");
    }

    #[test]
    fn avisa_cuando_la_extension_elegida_no_aparece_en_la_captura() {
        let mut app = app();
        app.sip_packets.push_back(packet(1, "INVITE", "1009"));
        app.peers = vec![Peer {
            name: "1001".to_string(),
            ip: "192.168.77.77".to_string(),
            status: "OK (1 ms)".to_string(),
            tech: crate::ami::Tech::Sip,
        }];
        app.sip_filter_index = Some(0);

        assert!(rendered(&app, 110, 30).contains("SIN COINCIDENCIAS"));
    }

    #[test]
    fn la_secuencia_muestra_las_dos_direcciones_de_la_llamada() {
        let mut app = app();
        app.sip_packets.push_back(call_packet(0, "INVITE", "call-x"));
        app.sip_packets.push_back(call_response(1, "180 Ringing", 180, "call-x"));
        app.sip_packets.push_back(call_response(2, "200 OK", 200, "call-x"));
        app.sip_call_flow = Some("call-x".to_string());
        app.sip_call_flow_selected = 0;

        let screen = rendered(&app, 110, 30);
        assert!(screen.contains("INVITE"), "debe mostrar el request inicial");
        assert!(screen.contains("180 Ringing"), "debe mostrar la respuesta provisional");
        assert!(screen.contains("200 OK"), "debe mostrar la respuesta final");
        assert!(
            screen.to_uppercase().contains("SECUENCIA · CALL-X"),
            "el título lleva el call-id abierto"
        );
        assert!(screen.contains("10.0.0.5:5060"), "debe mostrar el extremo origen");
        assert!(screen.contains("10.0.0.1:5060"), "debe mostrar el extremo destino");
        // Regresión: el detalle usaba el índice de la lista plana (sip_follow /
        // sip_selected_row) en vez del de la secuencia, así que con
        // sip_call_flow_selected=0 igual mostraba el último mensaje capturado.
        assert!(
            screen.contains("#0") && screen.contains("REQUEST INVITE"),
            "el detalle debe mostrar el mensaje #0 (INVITE), el seleccionado en la secuencia"
        );
    }

    #[test]
    fn una_llamada_sin_paquetes_en_el_buffer_no_rompe_el_dibujado() {
        let mut app = app();
        app.sip_call_flow = Some("call-perdida".to_string());

        let screen = rendered(&app, 110, 30);
        assert!(screen.contains("ya no tiene paquetes"));
    }
}
