use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
};

use crate::app::App;
use crate::theme::glyph;
use crate::ui::tabs::Tab;

/// Columna izquierda: botonera del tablero. Cada pestaña es un pulsador con su
/// LED de identidad; el activo queda "hundido" (fondo en relieve y marco ámbar).
pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let mut constraints = Vec::with_capacity(Tab::ALL.len() + 1);
    for _ in Tab::ALL {
        constraints.push(Constraint::Length(3));
    }
    constraints.push(Constraint::Min(0));

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    for tab in Tab::ALL {
        render_button(frame, rows[tab.index()], tab, app);
    }

    render_legend(frame, rows[Tab::ALL.len()], app);
}

fn render_button(frame: &mut Frame, area: Rect, tab: Tab, app: &App) {
    let theme = &app.theme;
    let selected = tab == app.active_tab;
    let led_color = theme.tab_accent(tab.index());

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(if selected {
            BorderType::Thick
        } else {
            BorderType::Plain
        })
        .border_style(theme.border_style(selected))
        .style(if selected {
            theme.raised_style()
        } else {
            theme.panel_style()
        });

    let label_style = if selected {
        theme.style_for_bold()
    } else {
        theme.tab_inactive_style()
    };

    let glyph = if selected {
        glyph::LED_ON
    } else {
        glyph::LED_OFF
    };

    let line = Line::from(vec![
        Span::styled(format!(" {glyph} "), theme.style_for_color(led_color)),
        Span::styled(tab.title().to_uppercase(), label_style),
    ]);

    frame.render_widget(Paragraph::new(line).block(block), area);
}

/// Pie de la botonera: recordatorio del atajo de configuración, siempre visible
/// para que la config no quede escondida.
fn render_legend(frame: &mut Frame, area: Rect, app: &App) {
    if area.height < 2 {
        return;
    }
    let theme = &app.theme;

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(" [C] ", theme.plate_style(theme.accent_primary)),
            Span::styled(" CONFIGURAR", theme.label_style()),
        ]),
        Line::from(Span::styled("     ASTERISK / SIP", theme.label_style())),
    ];

    frame.render_widget(
        Paragraph::new(lines).style(theme.base_style()),
        area,
    );
}
