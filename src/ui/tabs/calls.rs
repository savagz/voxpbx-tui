use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    widgets::{Row, Table},
};

use crate::app::App;
use crate::ui::widgets::panel;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let theme = &app.theme;
    let accent = theme.tab_accent(1);

    let block = panel::block(theme, "llamadas activas", accent, false).title_bottom(
        panel::readout(theme, &format!("{} canales", app.channels.len()), accent),
    );

    let header = Row::new([
        "CANAL",
        "ESTADO",
        "CALLERID",
        "CONTEXTO",
        "EXTEN",
        "DURACIÓN",
    ])
    .style(theme.table_header_style());

    let rows = app.channels.iter().map(|c| {
        Row::new([
            c.channel.clone(),
            c.state.clone(),
            c.caller_id.clone(),
            c.context.clone(),
            c.extension.clone(),
            c.duration.clone(),
        ])
        .style(theme.value_style())
    });

    let widths = [
        Constraint::Percentage(28),
        Constraint::Percentage(14),
        Constraint::Percentage(16),
        Constraint::Percentage(14),
        Constraint::Percentage(12),
        Constraint::Percentage(16),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(2)
        .block(block);

    frame.render_widget(table, area);
}
