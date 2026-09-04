use ratatui::{
    layout::Rect,
    style::Color,
    text::{Line, Span},
    widgets::{Block, BorderType, Borders},
};

use crate::theme::Theme;

/// Caja estándar del tablero: marco de chapa y una "placa" grabada como título.
/// Todo panel de la app se dibuja con esto para que el frente quede parejo.
pub fn block<'a>(theme: &Theme, title: &str, accent: Color, focused: bool) -> Block<'a> {
    let border_color = if focused { accent } else { theme.border };

    Block::default()
        .title(plate(theme, title, accent))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(theme.style_for_color(border_color))
        .style(theme.panel_style())
}

/// Placa de título: barra de color + texto en mayúsculas sobre chapa clara.
pub fn plate<'a>(theme: &Theme, title: &str, accent: Color) -> Line<'a> {
    Line::from(vec![
        Span::styled("▌", theme.style_for_color(accent)),
        Span::styled(
            format!(" {} ", title.to_uppercase()),
            theme.plate_style(accent),
        ),
        Span::styled("▐", theme.style_for_color(accent)),
    ])
}

/// Lectura auxiliar alineada a la derecha del marco (contadores, estado del panel).
pub fn readout<'a>(theme: &Theme, text: &str, color: Color) -> Line<'a> {
    Line::from(vec![
        Span::styled("┤", theme.style_for_color(theme.border)),
        Span::styled(format!(" {text} "), theme.style_for_color(color)),
        Span::styled("├", theme.style_for_color(theme.border)),
    ])
}

/// Rectángulo centrado (porcentaje del área) para overlays modales.
pub fn centered(area: Rect, pct_x: u16, pct_y: u16) -> Rect {
    let width = area.width * pct_x / 100;
    let height = area.height * pct_y / 100;
    Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    }
}
