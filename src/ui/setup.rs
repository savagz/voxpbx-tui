use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    text::{Line, Span},
    widgets::{Clear, Paragraph, Wrap},
};

use crate::deps::{self, CheckState};
use crate::setup::{Field, ProbeState, SetupForm, SetupMode};
use crate::theme::{Status, Theme, glyph, hazard_stripe};

use super::widgets::panel;

/// Ancho de la columna de etiquetas: fija para que los valores queden alineados
/// como en una regleta de bornes.
const LABEL_WIDTH: usize = 22;

/// Primer arranque: el asistente ocupa toda la pantalla, no hay TUI detrás.
pub fn render_fullscreen(frame: &mut Frame, form: &SetupForm) {
    let theme = Theme::default();
    frame.render_widget(
        ratatui::widgets::Block::default().style(theme.base_style()),
        frame.area(),
    );
    render_panel(frame, frame.area(), form, &theme);
}

/// Configuración con la app andando: modal centrado sobre el tablero.
pub fn render_overlay(frame: &mut Frame, area: Rect, form: &SetupForm, theme: &Theme) {
    let modal = panel::centered(area, 82, 92);
    frame.render_widget(Clear, modal);
    render_panel(frame, modal, form, theme);
}

fn render_panel(frame: &mut Frame, area: Rect, form: &SetupForm, theme: &Theme) {
    let title = match form.mode {
        SetupMode::FirstRun => "puesta en marcha · conexión asterisk",
        SetupMode::Edit => "configuración · conexión asterisk",
    };

    let block = panel::block(theme, title, theme.accent_primary, true)
        .title_bottom(panel::readout(theme, "voxpbx", theme.fg_muted));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1),                             // franja de peligro
            Constraint::Length(Field::ALL.len() as u16),       // regleta de campos
            Constraint::Length(2),                             // ayuda del campo activo
            Constraint::Min(5),                                // dependencias + prueba
            Constraint::Length(2),                             // error / aviso
            Constraint::Length(1),                             // teclas
        ])
        .split(inner);

    render_stripe(frame, rows[0], form, theme);
    render_fields(frame, rows[1], form, theme);
    render_hint(frame, rows[2], form, theme);
    render_diagnostics(frame, rows[3], form, theme);
    render_message(frame, rows[4], form, theme);
    render_keys(frame, rows[5], form, theme);
}

fn render_stripe(frame: &mut Frame, area: Rect, form: &SetupForm, theme: &Theme) {
    let text = match form.mode {
        SetupMode::FirstRun => "PRIMER ARRANQUE — CARGÁ LOS DATOS DEL MANAGER DE ASTERISK",
        SetupMode::Edit => "LOS CAMBIOS SE APLICAN EN CALIENTE AL GUARDAR",
    };

    let stripe_width = area
        .width
        .saturating_sub(text.chars().count() as u16 + 2)
        .min(8) as usize;

    let line = Line::from(vec![
        Span::styled(
            hazard_stripe(stripe_width),
            theme.style_for_color(theme.warning),
        ),
        Span::styled(format!(" {text} "), theme.style_for(Status::Warning)),
    ]);

    frame.render_widget(Paragraph::new(line), area);
}

fn render_fields(frame: &mut Frame, area: Rect, form: &SetupForm, theme: &Theme) {
    let lines: Vec<Line> = Field::ALL
        .iter()
        .map(|field| field_line(*field, form, theme))
        .collect();

    frame.render_widget(Paragraph::new(lines), area);
}

fn field_line<'a>(field: Field, form: &SetupForm, theme: &Theme) -> Line<'a> {
    let focused = form.field() == field;
    let value = form.value_of(field);

    let marker = if focused { "▌" } else { " " };
    let label = format!("{:<width$}", field.label(), width = LABEL_WIDTH);

    let value_style = match field {
        Field::Enabled if form.enabled => theme.style_for(Status::Ok),
        Field::Enabled => theme.style_for(Status::Warning),
        _ if focused => theme.selected_row_style(),
        _ => theme.value_style(),
    };

    let mut spans = vec![
        Span::styled(marker.to_string(), theme.style_for_color(theme.accent_primary)),
        Span::styled(
            label,
            if focused {
                theme.style_for_bold()
            } else {
                theme.label_style()
            },
        ),
        Span::styled("│ ", theme.style_for_color(theme.border)),
        Span::styled(value, value_style),
    ];

    if focused && field != Field::Enabled {
        spans.push(Span::styled(
            "▏",
            theme.style_for_color(theme.accent_primary),
        ));
    }

    if field == Field::Interface && !form.interfaces.is_empty() {
        let ips = form
            .selected_interface()
            .map(|i| i.summary())
            .unwrap_or_else(|| "desconocida".to_string());
        spans.push(Span::styled(
            format!("   {ips}  ({} detectadas)", form.interfaces.len()),
            theme.label_style(),
        ));
    }

    Line::from(spans)
}

fn render_hint(frame: &mut Frame, area: Rect, form: &SetupForm, theme: &Theme) {
    let line = Line::from(vec![
        Span::styled(" ▸ ", theme.style_for_color(theme.accent_secondary)),
        Span::styled(form.field().hint().to_string(), theme.label_style()),
    ]);
    frame.render_widget(Paragraph::new(line).wrap(Wrap { trim: true }), area);
}

/// Chequeos de `libpcap`/permisos y resultado de la última prueba de conexión:
/// el diagnóstico va junto a los campos para no tener que salir del asistente.
fn render_diagnostics(frame: &mut Frame, area: Rect, form: &SetupForm, theme: &Theme) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);

    render_deps(frame, cols[0], form, theme);
    render_probe(frame, cols[1], form, theme);
}

fn render_deps(frame: &mut Frame, area: Rect, form: &SetupForm, theme: &Theme) {
    let all_ok = form.deps.all_ok();
    let accent = if all_ok { theme.ok } else { theme.warning };

    let pm_label = form
        .deps
        .package_manager
        .map(|pm| pm.label().to_string())
        .unwrap_or_else(|| "sin gestor".to_string());

    let block = panel::block(theme, "dependencias del análisis sip", accent, false)
        .title_bottom(panel::readout(theme, &pm_label, theme.fg_muted));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = Vec::new();
    for (name, state) in form.deps.checks() {
        let (status, mark) = match state {
            CheckState::Ok(_) => (Status::Ok, glyph::LED_ON),
            CheckState::Missing { .. } => (Status::Error, glyph::LED_OFF),
            CheckState::Unknown(_) => (Status::Warning, glyph::BOLT),
        };

        lines.push(Line::from(vec![
            Span::styled(format!("{mark} "), theme.style_for(status)),
            Span::styled(format!("{name:<20}"), theme.value_style()),
            Span::styled(state.detail().to_string(), theme.label_style()),
        ]));

        if let Some(fix) = state.fix() {
            lines.push(Line::from(vec![
                Span::styled("   └ F10: ", theme.style_for(Status::Warning)),
                Span::styled(deps::command_line(fix), theme.readout_style()),
            ]));
        }
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn render_probe(frame: &mut Frame, area: Rect, form: &SetupForm, theme: &Theme) {
    let (status, title) = match &form.probe {
        ProbeState::Idle => (Status::Info, "prueba de conexión"),
        ProbeState::Running => (Status::Warning, "probando…"),
        ProbeState::Ok(_) => (Status::Ok, "conexión verificada"),
        ProbeState::Failed(_) => (Status::Error, "conexión rechazada"),
    };

    let block = panel::block(theme, title, theme.color_for(status), false);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = match &form.probe {
        ProbeState::Idle => vec![Line::from(Span::styled(
            "F5 conecta y hace login contra AMI con estos datos, sin tocar la sesión actual.",
            theme.label_style(),
        ))],
        ProbeState::Running => vec![Line::from(Span::styled(
            "Conectando al manager…",
            theme.style_for(Status::Warning),
        ))],
        ProbeState::Ok(banner) => vec![
            Line::from(Span::styled(
                "Login aceptado por Asterisk.",
                theme.style_for(Status::Ok),
            )),
            Line::from(Span::styled(banner.clone(), theme.readout_style())),
        ],
        ProbeState::Failed(err) => vec![Line::from(Span::styled(
            err.clone(),
            theme.style_for(Status::Error),
        ))],
    };

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn render_message(frame: &mut Frame, area: Rect, form: &SetupForm, theme: &Theme) {
    let line = if let Some(error) = &form.error {
        Line::from(vec![
            Span::styled(" ERROR ", theme.plate_style(theme.error)),
            Span::styled(format!(" {error}"), theme.style_for(Status::Error)),
        ])
    } else if let Some(notice) = &form.notice {
        Line::from(vec![
            Span::styled(" AVISO ", theme.plate_style(theme.info)),
            Span::styled(format!(" {notice}"), theme.style_for(Status::Info)),
        ])
    } else {
        Line::from("")
    };

    frame.render_widget(Paragraph::new(line).wrap(Wrap { trim: true }), area);
}

fn render_keys(frame: &mut Frame, area: Rect, form: &SetupForm, theme: &Theme) {
    let cancel = match form.mode {
        SetupMode::FirstRun => "salir",
        SetupMode::Edit => "cancelar",
    };

    let spans = vec![
        Span::styled(" ENTER ", theme.plate_style(theme.ok)),
        Span::styled(" guardar   ", theme.label_style()),
        Span::styled(" F5 ", theme.plate_style(theme.accent_secondary)),
        Span::styled(" probar   ", theme.label_style()),
        Span::styled(" F9 ", theme.plate_style(theme.accent_secondary)),
        Span::styled(" rechequear   ", theme.label_style()),
        Span::styled(" F10 ", theme.plate_style(theme.warning)),
        Span::styled(" reparar   ", theme.label_style()),
        Span::styled(" F2 ", theme.plate_style(theme.accent_tertiary)),
        Span::styled(" ver clave   ", theme.label_style()),
        Span::styled(" ESC ", theme.plate_style(theme.error)),
        Span::styled(format!(" {cancel}"), theme.label_style()),
    ];

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}
