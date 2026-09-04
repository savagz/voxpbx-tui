use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::theme::{Theme, segmented_bar};

use super::panel;

/// Instrumento de aguja segmentada. Ocupa 3 filas (marco + fila de barra) y se usa
/// para CPU/RAM/disco: mismo lenguaje visual que un tablero de sala de máquinas.
pub fn render(frame: &mut Frame, area: Rect, theme: &Theme, label: &str, detail: &str, pct: f64) {
    let status = theme.status_for_pct(pct);
    let color = theme.color_for(status);

    let mut block = panel::block(theme, label, color, false);
    if !detail.is_empty() {
        block = block.title_bottom(panel::readout(theme, detail, theme.fg_muted));
    }

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Reservamos 8 columnas para la lectura numérica ("100.0%" + aire).
    let bar_width = inner.width.saturating_sub(8).max(1) as usize;
    let (filled, empty) = segmented_bar(pct, bar_width);

    let line = Line::from(vec![
        Span::styled(filled, theme.style_for_color(color)),
        Span::styled(empty, theme.style_for_color(theme.fg_dim)),
        Span::styled(format!(" {pct:>5.1}%"), theme.readout_style()),
    ]);

    frame.render_widget(Paragraph::new(line), inner);
}
