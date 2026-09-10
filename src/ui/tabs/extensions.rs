use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    text::Span,
    widgets::{Row, Table},
};

use crate::app::App;
use crate::theme::{Status, glyph};
use crate::ui::widgets::panel;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let theme = &app.theme;
    let accent = theme.tab_accent(2);

    let peers = app.sip_candidate_peers();
    let registered = peers.iter().filter(|p| p.is_registered()).count();

    let block = panel::block(theme, "extensiones", accent, false).title_bottom(panel::readout(
        theme,
        &format!("{}/{} registradas", registered, peers.len()),
        if registered == peers.len() {
            theme.ok
        } else {
            theme.warning
        },
    ));

    let header =
        Row::new(["", "EXTENSIÓN", "TECH", "IP", "ESTADO"]).style(theme.table_header_style());

    let rows = peers.iter().map(|p| {
        let status = if p.is_registered() {
            Status::Ok
        } else {
            Status::Error
        };
        let led = if p.is_registered() {
            glyph::LED_ON
        } else {
            glyph::LED_OFF
        };
        Row::new([
            Span::styled(led, theme.style_for(status)),
            Span::styled(p.name.clone(), theme.style_for_bold()),
            Span::styled(p.tech.label(), theme.readout_style()),
            Span::styled(p.ip.clone(), theme.readout_style()),
            Span::styled(p.status.to_uppercase(), theme.style_for(status)),
        ])
    });

    let widths = [
        Constraint::Length(1),
        Constraint::Percentage(26),
        Constraint::Percentage(14),
        Constraint::Percentage(26),
        Constraint::Percentage(33),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(2)
        .block(block);

    frame.render_widget(table, area);
}
