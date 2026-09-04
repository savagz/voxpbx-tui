use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::app::App;
use crate::theme::{Status, glyph};
use crate::ui::widgets::{gauge, panel};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(area);

    render_status(frame, chunks[0], app);
    render_host_metrics(frame, chunks[1], app);
}

fn render_status(frame: &mut Frame, area: Rect, app: &App) {
    let theme = &app.theme;
    let accent = theme.tab_accent(0);

    let block = panel::block(theme, "central asterisk", accent, false).title_bottom(
        panel::readout(
            theme,
            &format!("uptime {}", format_uptime(app.host.uptime_secs)),
            theme.fg_muted,
        ),
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = vec![Line::from(vec![
        Span::styled(
            format!("{} ", glyph::LED_ON),
            theme.style_for(app.ami_conn_state.status()),
        ),
        Span::styled("ENLACE AMI  ", theme.label_style()),
        Span::styled(
            app.ami_conn_state.label().to_uppercase(),
            theme.style_for(app.ami_conn_state.status()),
        ),
    ])];

    match &app.core_status {
        Some(status) => {
            lines.push(Line::from(vec![
                Span::styled("ESTADO      ", theme.label_style()),
                Span::styled(status.description.clone(), theme.value_style()),
            ]));
            lines.push(Line::from(vec![
                Span::styled("ARRANQUE    ", theme.label_style()),
                Span::styled(status.startup_time.clone(), theme.value_style()),
                Span::styled("   RELOAD  ", theme.label_style()),
                Span::styled(status.reload_time.clone(), theme.value_style()),
            ]));
            lines.push(Line::from(vec![
                Span::styled("EN CURSO    ", theme.label_style()),
                Span::styled(
                    status
                        .current_calls
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "—".to_string()),
                    theme.readout_style(),
                ),
                Span::styled("  llamadas", theme.label_style()),
            ]));
        }
        None => lines.push(Line::from(Span::styled(
            "Esperando CoreStatus del manager…",
            theme.label_style(),
        ))),
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

fn format_uptime(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let minutes = (secs % 3_600) / 60;
    format!("{days}d {hours}h {minutes}m")
}

fn render_host_metrics(frame: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);

    let theme = &app.theme;

    gauge::render(frame, rows[0], theme, "cpu", "", app.host.cpu_pct);
    gauge::render(
        frame,
        rows[1],
        theme,
        "memoria",
        &format!(
            "{:.1} / {:.1} GB",
            app.host.mem_used_gb, app.host.mem_total_gb
        ),
        app.host.mem_pct,
    );
    gauge::render(
        frame,
        rows[2],
        theme,
        "disco",
        &format!(
            "{:.1} / {:.1} GB",
            app.host.disk_used_gb, app.host.disk_total_gb
        ),
        app.host.disk_pct,
    );

    render_capture_notice(frame, rows[3], app);
}

/// Aviso persistente si el análisis SIP no está operativo: es la falla más común
/// (permisos de captura) y desde el tablero se ve de una.
fn render_capture_notice(frame: &mut Frame, area: Rect, app: &App) {
    if area.height == 0 {
        return;
    }
    let theme = &app.theme;

    let line = match (&app.sip_capture_error, app.config.capture.enabled) {
        (Some(err), _) => Line::from(vec![
            Span::styled(" SIP ", theme.plate_style(theme.error)),
            Span::styled(
                format!(" captura caída: {err}  ·  [C] revisar configuración"),
                theme.style_for(Status::Error),
            ),
        ]),
        (None, false) => Line::from(vec![
            Span::styled(" SIP ", theme.plate_style(theme.warning)),
            Span::styled(
                " análisis desactivado  ·  [C] activar",
                theme.style_for(Status::Warning),
            ),
        ]),
        (None, true) => Line::from(vec![
            Span::styled(" SIP ", theme.plate_style(theme.ok)),
            Span::styled(
                format!(
                    " capturando en {} · puertos {}",
                    app.config.capture.interface,
                    app.config
                        .capture
                        .sip_ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                theme.style_for(Status::Ok),
            ),
        ]),
    };

    frame.render_widget(Paragraph::new(line), area);
}
