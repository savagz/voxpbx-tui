use chrono::Local;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::app::App;
use crate::theme::{Status, glyph};

use super::panel;

/// Franja superior del tablero: identificación del equipo a la izquierda y los
/// pilotos de estado (AMI, captura, reloj) a la derecha, como un frente de rack.
pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let theme = &app.theme;

    let block = panel::block(theme, "voxpbx · unidad de control asterisk", theme.accent_primary, true);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(inner);

    let target = Line::from(vec![
        Span::styled("NODO ", theme.label_style()),
        Span::styled(
            format!("{}:{}", app.config.ami.host, app.config.ami.port),
            theme.readout_style(),
        ),
        Span::styled(format!("  ·  {}", app.config.ami.username), theme.label_style()),
    ]);
    frame.render_widget(Paragraph::new(target), cols[0]);

    let (capture_status, capture_label) = capture_indicator(app);

    let pilots = Line::from(vec![
        led(app, app.ami_conn_state.status(), "AMI"),
        Span::styled(
            format!("{}  ", app.ami_conn_state.label().to_uppercase()),
            theme.style_for(app.ami_conn_state.status()),
        ),
        led(app, capture_status, "SIP"),
        Span::styled(format!("{capture_label}  "), theme.style_for(capture_status)),
        Span::styled(
            Local::now().format("%H:%M:%S").to_string(),
            theme.readout_style(),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(pilots).alignment(Alignment::Right),
        cols[1],
    );
}

fn led<'a>(app: &App, status: Status, tag: &str) -> Span<'a> {
    let glyph = if status == Status::Error {
        glyph::LED_OFF
    } else {
        glyph::LED_ON
    };
    Span::styled(
        format!("{glyph} {tag} "),
        app.theme.style_for(status),
    )
}

fn capture_indicator(app: &App) -> (Status, String) {
    if !app.config.capture.enabled {
        (Status::Warning, "DETENIDA".to_string())
    } else if app.sip_capture_error.is_some() {
        (Status::Error, "FALLA".to_string())
    } else {
        (Status::Ok, app.config.capture.interface.to_uppercase())
    }
}
