use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::app::App;
use crate::theme::{Status, Theme};
use crate::ui::tabs::Tab;

/// Barra inferior: teclas grabadas como capuchones de tecla. Si hay un aviso
/// reciente (config guardada, error), ocupa la barra hasta la próxima tecla.
pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let theme = &app.theme;

    if let Some((message, status)) = &app.toast {
        let line = Line::from(vec![
            Span::styled(" AVISO ", theme.plate_style(theme.color_for(*status))),
            Span::styled(format!(" {message}"), theme.style_for(*status)),
        ]);
        frame.render_widget(Paragraph::new(line).style(theme.base_style()), area);
        return;
    }

    let mut spans = vec![
        key(theme, "TAB", theme.accent_secondary),
        label(theme, "vista"),
        key(theme, "↑↓", theme.accent_secondary),
        label(theme, "navegar"),
        key(theme, "F", theme.accent_secondary),
        label(theme, "extensión"),
        key(theme, "S", theme.ok),
        label(theme, "captura"),
        key(theme, "G", theme.accent_secondary),
        label(theme, "seguir"),
        key(theme, "C", theme.accent_primary),
        label(theme, "config"),
        key(theme, "Q", theme.error),
        label(theme, "salir"),
    ];

    if app.active_tab == Tab::SipTrace {
        if app.sip_call_flow.is_some() {
            spans.push(key(theme, "ESC", theme.accent_secondary));
            spans.push(label(theme, "volver"));
        } else {
            spans.push(key(theme, "↵", theme.accent_secondary));
            spans.push(label(theme, "secuencia"));
        }
        spans.push(key(theme, "L", theme.warning));
        spans.push(label(theme, "limpiar"));
    }

    if app.sip_trace_active {
        spans.push(Span::styled(
            " ● GRABANDO",
            theme.style_for(Status::Error),
        ));
    }

    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(theme.base_style()),
        area,
    );
}

fn key<'a>(theme: &Theme, text: &str, color: ratatui::style::Color) -> Span<'a> {
    Span::styled(format!(" {text} "), theme.plate_style(color))
}

fn label<'a>(theme: &Theme, text: &str) -> Span<'a> {
    Span::styled(format!(" {text}   "), theme.label_style())
}
