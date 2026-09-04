use ratatui::style::{Color, Modifier, Style};

/// Paleta "industrial": chapa oscura, ámbar de señalización, cian de instrumento.
/// La idea es un panel de control de sala de máquinas — nada de pasteles, todo
/// contraste alto y semántica de tablero (verde marcha / ámbar aviso / rojo alarma).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warning,
    Error,
    Info,
}

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub bg: Color,
    pub bg_panel: Color,
    /// Fondo de cabeceras, barras y celdas "en relieve" (chapa clara).
    pub bg_raised: Color,
    pub bg_selected: Color,

    pub fg: Color,
    pub fg_muted: Color,
    /// Texto/relleno apagado: escala de gauges, guías, separadores.
    pub fg_dim: Color,

    pub border: Color,
    pub border_focused: Color,

    pub ok: Color,
    pub warning: Color,
    pub error: Color,
    pub info: Color,

    /// Ámbar de señalización: color de identidad del producto.
    pub accent_primary: Color,
    /// Cian de instrumento: lecturas y medidas.
    pub accent_secondary: Color,
    /// Acero: elementos neutros con jerarquía.
    pub accent_tertiary: Color,
    /// Azul de servicio: quinto canal de identidad (SIP Trace).
    pub accent_quaternary: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            bg: Color::Rgb(0x0b, 0x0d, 0x0f),
            bg_panel: Color::Rgb(0x12, 0x16, 0x1a),
            bg_raised: Color::Rgb(0x1b, 0x21, 0x27),
            bg_selected: Color::Rgb(0x2b, 0x35, 0x3f),

            fg: Color::Rgb(0xc8, 0xd2, 0xdc),
            fg_muted: Color::Rgb(0x74, 0x82, 0x8e),
            fg_dim: Color::Rgb(0x39, 0x43, 0x4d),

            border: Color::Rgb(0x2c, 0x35, 0x3e),
            border_focused: Color::Rgb(0xf2, 0xa2, 0x1c),

            ok: Color::Rgb(0x3f, 0xbf, 0x63),
            warning: Color::Rgb(0xf2, 0xa2, 0x1c),
            error: Color::Rgb(0xe0, 0x45, 0x3a),
            info: Color::Rgb(0x45, 0xa8, 0xc9),

            accent_primary: Color::Rgb(0xf2, 0xa2, 0x1c),
            accent_secondary: Color::Rgb(0x45, 0xa8, 0xc9),
            accent_tertiary: Color::Rgb(0x8d, 0x9b, 0xa8),
            accent_quaternary: Color::Rgb(0x6f, 0x8f, 0xd9),
        }
    }
}

impl Theme {
    pub fn color_for(&self, status: Status) -> Color {
        match status {
            Status::Ok => self.ok,
            Status::Warning => self.warning,
            Status::Error => self.error,
            Status::Info => self.info,
        }
    }

    pub fn style_for(&self, status: Status) -> Style {
        Style::default().fg(self.color_for(status))
    }

    /// Umbrales usados por los gauges de CPU/RAM/disk: <70% ok, 70-90% warning, >90% error.
    pub fn status_for_pct(&self, pct: f64) -> Status {
        if pct >= 90.0 {
            Status::Error
        } else if pct >= 70.0 {
            Status::Warning
        } else {
            Status::Ok
        }
    }

    pub fn base_style(&self) -> Style {
        Style::default().fg(self.fg).bg(self.bg)
    }

    pub fn panel_style(&self) -> Style {
        Style::default().fg(self.fg).bg(self.bg_panel)
    }

    pub fn raised_style(&self) -> Style {
        Style::default().fg(self.fg).bg(self.bg_raised)
    }

    pub fn border_style(&self, focused: bool) -> Style {
        let color = if focused {
            self.border_focused
        } else {
            self.border
        };
        Style::default().fg(color)
    }

    /// Título de panel: placa metálica grabada (mayúsculas, en relieve).
    pub fn plate_style(&self, color: Color) -> Style {
        Style::default()
            .fg(color)
            .bg(self.bg_raised)
            .add_modifier(Modifier::BOLD)
    }

    /// Cabecera de tabla: fondo en relieve, texto apagado en mayúsculas.
    pub fn table_header_style(&self) -> Style {
        Style::default()
            .fg(self.fg_muted)
            .bg(self.bg_raised)
            .add_modifier(Modifier::BOLD)
    }

    pub fn label_style(&self) -> Style {
        Style::default().fg(self.fg_muted)
    }

    pub fn value_style(&self) -> Style {
        Style::default().fg(self.fg)
    }

    /// Lectura de instrumento: números y medidas, en cian.
    pub fn readout_style(&self) -> Style {
        Style::default()
            .fg(self.accent_secondary)
            .add_modifier(Modifier::BOLD)
    }

    pub fn tab_inactive_style(&self) -> Style {
        Style::default().fg(self.fg_muted)
    }

    pub fn style_for_bold(&self) -> Style {
        Style::default().fg(self.fg).add_modifier(Modifier::BOLD)
    }

    pub fn style_for_color(&self, color: Color) -> Style {
        Style::default().fg(color)
    }

    /// Color de identidad fijo por pestaña (LED de nav):
    /// Overview=ámbar, Calls=verde, Extensions=cian, Queues=rojo, SipTrace=azul.
    pub fn tab_accent(&self, index: usize) -> Color {
        match index {
            0 => self.accent_primary,
            1 => self.ok,
            2 => self.info,
            3 => self.error,
            _ => self.accent_quaternary,
        }
    }

    pub fn selected_row_style(&self) -> Style {
        Style::default()
            .bg(self.bg_selected)
            .fg(self.fg)
            .add_modifier(Modifier::BOLD)
    }
}

/// Glifos del lenguaje visual industrial: LEDs, segmentos de gauge y franja de
/// peligro. Centralizados para que todos los paneles usen exactamente los mismos.
pub mod glyph {
    pub const LED_ON: &str = "◉";
    pub const LED_OFF: &str = "○";
    pub const SEG_FULL: char = '█';
    pub const SEG_EMPTY: char = '─';
    pub const HAZARD: &str = "╱";
    pub const BOLT: &str = "▲";
}

/// Barra segmentada de instrumento: `width` celdas, llenas según `pct`.
/// Devuelve (relleno, vacío) para pintarlos con estilos distintos.
pub fn segmented_bar(pct: f64, width: usize) -> (String, String) {
    let ratio = (pct / 100.0).clamp(0.0, 1.0);
    let filled = ((width as f64) * ratio).round() as usize;
    let filled = filled.min(width);
    (
        glyph::SEG_FULL.to_string().repeat(filled),
        glyph::SEG_EMPTY.to_string().repeat(width - filled),
    )
}

/// Franja de peligro (rayado diagonal) usada en cabeceras de alarma y en el
/// asistente de configuración.
pub fn hazard_stripe(width: usize) -> String {
    glyph::HAZARD.repeat(width)
}
