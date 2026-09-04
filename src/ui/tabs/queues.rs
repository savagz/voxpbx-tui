use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    text::Span,
    widgets::{Row, Table},
};

use crate::app::App;
use crate::theme::Status;
use crate::ui::widgets::panel;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let theme = &app.theme;
    let accent = theme.tab_accent(3);

    let waiting: u32 = app.queues.iter().map(|q| q.callers_waiting).sum();

    let block = panel::block(theme, "colas", accent, false).title_bottom(panel::readout(
        theme,
        &format!("{waiting} en espera"),
        if waiting > 0 { theme.warning } else { theme.ok },
    ));

    let header = Row::new(["COLA", "LOGUEADOS", "DISPONIBLES", "ESPERANDO"])
        .style(theme.table_header_style());

    let rows = app.queues.iter().map(|q| {
        let waiting_style = if q.callers_waiting > 0 {
            theme.style_for(Status::Warning)
        } else {
            theme.value_style()
        };
        Row::new(vec![
            Span::styled(q.name.clone(), theme.style_for_bold()),
            Span::styled(q.logged_in.to_string(), theme.readout_style()),
            Span::styled(q.available.to_string(), theme.readout_style()),
            Span::styled(q.callers_waiting.to_string(), waiting_style),
        ])
    });

    let widths = [
        Constraint::Percentage(40),
        Constraint::Percentage(20),
        Constraint::Percentage(20),
        Constraint::Percentage(20),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(2)
        .block(block);

    frame.render_widget(table, area);
}
