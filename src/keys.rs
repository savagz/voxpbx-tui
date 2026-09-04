use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppAction {
    Quit,
    NextTab,
    PrevTab,
    Up,
    Down,
    CycleSipFilter,
    ToggleSipTraceCapture,
    /// Abre el panel de configuración de Asterisk sobre la TUI.
    OpenConfig,
    /// Ir al principio de la lista (deja de seguir el tráfico en vivo).
    Top,
    /// Volver a seguir el último paquete capturado.
    Follow,
}

pub fn action_for(key: KeyEvent) -> Option<AppAction> {
    match key.code {
        KeyCode::Char('q') => Some(AppAction::Quit),
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            Some(AppAction::Quit)
        }
        KeyCode::Char('c') => Some(AppAction::OpenConfig),
        KeyCode::F(1) => Some(AppAction::OpenConfig),
        KeyCode::Tab => Some(AppAction::NextTab),
        KeyCode::BackTab => Some(AppAction::PrevTab),
        KeyCode::Up | KeyCode::Char('k') => Some(AppAction::Up),
        KeyCode::Down | KeyCode::Char('j') => Some(AppAction::Down),
        KeyCode::Home | KeyCode::Char('g') => Some(AppAction::Top),
        KeyCode::End | KeyCode::Char('G') => Some(AppAction::Follow),
        KeyCode::Char('f') => Some(AppAction::CycleSipFilter),
        KeyCode::Char('s') => Some(AppAction::ToggleSipTraceCapture),
        _ => None,
    }
}
