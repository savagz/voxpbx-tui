use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::config::{AmiConfig, CaptureConfig, Config, SECRET_ENV, UiConfig};
use crate::deps::{self, DepReport, Interface};

/// Panel de configuración: se usa igual en el primer arranque (pantalla completa,
/// sin config previa) y como overlay para editar la conexión con la TUI ya andando.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupMode {
    FirstRun,
    Edit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Host,
    Port,
    User,
    Secret,
    Interface,
    Ports,
    Enabled,
}

impl Field {
    pub const ALL: [Field; 7] = [
        Field::Host,
        Field::Port,
        Field::User,
        Field::Secret,
        Field::Interface,
        Field::Ports,
        Field::Enabled,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Field::Host => "HOST ASTERISK",
            Field::Port => "PUERTO AMI",
            Field::User => "USUARIO AMI",
            Field::Secret => "CONTRASEÑA AMI",
            Field::Interface => "INTERFAZ DE CAPTURA",
            Field::Ports => "PUERTOS SIP",
            Field::Enabled => "ANÁLISIS SIP",
        }
    }

    pub fn hint(&self) -> &'static str {
        match self {
            Field::Host => "IP o nombre del servidor Asterisk (manager.conf)",
            Field::Port => "puerto del Asterisk Manager Interface (5038 por defecto)",
            Field::User => "usuario de manager.conf con permisos de lectura",
            Field::Secret => "se guarda con permisos 0600; la variable de entorno la pisa",
            Field::Interface => "←/→ cicla las interfaces detectadas; elegí aquella por la que pasa el SIP",
            Field::Ports => "lista separada por comas, ej. 5060,5061",
            Field::Enabled => "ESPACIO activa o desactiva la captura de paquetes SIP",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeState {
    Idle,
    Running,
    Ok(String),
    Failed(String),
}

/// Qué debe hacer el llamador después de procesar una tecla.
#[derive(Debug, Clone)]
pub enum SetupOutcome {
    None,
    /// Config validada y lista para guardarse/aplicarse.
    Save(Box<Config>),
    /// Salir del panel sin guardar (en primer arranque = terminar el proceso).
    Cancel,
    /// Probar la conexión AMI con los valores actuales del formulario.
    TestConnection(Box<AmiConfig>),
    /// Volver a correr los chequeos de dependencias.
    Recheck,
    /// Ejecutar el comando de remediación (requiere suspender la TUI).
    RunFix(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct SetupForm {
    pub mode: SetupMode,
    pub focus: usize,
    pub host: String,
    pub port: String,
    pub user: String,
    pub secret: String,
    pub interface: String,
    pub ports: String,
    pub enabled: bool,
    pub secret_visible: bool,
    pub interfaces: Vec<Interface>,
    pub deps: DepReport,
    pub probe: ProbeState,
    pub error: Option<String>,
    pub notice: Option<String>,
    /// El secret vino de `VOXPBX_AMI_SECRET`: no se pide ni se guarda en disco.
    pub secret_from_env: bool,
}

impl SetupForm {
    pub fn new(mode: SetupMode, config: &Config) -> Self {
        let interfaces = deps::interfaces();
        let interface = if config.capture.interface.is_empty() {
            interfaces.first().map(|i| i.name.clone()).unwrap_or_default()
        } else {
            config.capture.interface.clone()
        };

        Self {
            mode,
            focus: 0,
            host: config.ami.host.clone(),
            port: config.ami.port.to_string(),
            user: config.ami.username.clone(),
            secret: config.ami.secret.clone(),
            interface: interface.clone(),
            ports: join_ports(&config.capture.sip_ports),
            enabled: config.capture.enabled,
            secret_visible: false,
            interfaces,
            deps: deps::probe(&interface),
            probe: ProbeState::Idle,
            error: None,
            notice: None,
            secret_from_env: std::env::var(SECRET_ENV).is_ok_and(|v| !v.is_empty()),
        }
    }

    pub fn field(&self) -> Field {
        Field::ALL[self.focus.min(Field::ALL.len() - 1)]
    }

    pub fn value_of(&self, field: Field) -> String {
        match field {
            Field::Host => self.host.clone(),
            Field::Port => self.port.clone(),
            Field::User => self.user.clone(),
            Field::Secret => self.masked_secret(),
            Field::Interface => self.interface.clone(),
            Field::Ports => self.ports.clone(),
            Field::Enabled => if self.enabled { "ACTIVO" } else { "DETENIDO" }.to_string(),
        }
    }

    fn masked_secret(&self) -> String {
        if self.secret_from_env {
            format!("<{SECRET_ENV}>")
        } else if self.secret_visible {
            self.secret.clone()
        } else {
            "•".repeat(self.secret.chars().count())
        }
    }

    fn buffer_mut(&mut self, field: Field) -> Option<&mut String> {
        match field {
            Field::Host => Some(&mut self.host),
            Field::Port => Some(&mut self.port),
            Field::User => Some(&mut self.user),
            Field::Secret => (!self.secret_from_env).then_some(&mut self.secret),
            Field::Interface => Some(&mut self.interface),
            Field::Ports => Some(&mut self.ports),
            Field::Enabled => None,
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) -> SetupOutcome {
        if key.kind != KeyEventKind::Press {
            return SetupOutcome::None;
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

        match key.code {
            KeyCode::Esc => return SetupOutcome::Cancel,
            KeyCode::Char('c') if ctrl => return SetupOutcome::Cancel,
            KeyCode::Enter => return self.build_config(),
            KeyCode::Tab | KeyCode::Down => self.move_focus(1),
            KeyCode::BackTab | KeyCode::Up => self.move_focus(-1),
            KeyCode::Left => self.cycle_interface(-1),
            KeyCode::Right => self.cycle_interface(1),
            KeyCode::Backspace => {
                let field = self.field();
                if let Some(buffer) = self.buffer_mut(field) {
                    buffer.pop();
                }
                self.error = None;
            }
            KeyCode::F(2) => self.secret_visible = !self.secret_visible,
            KeyCode::F(5) => return self.test_connection(),
            KeyCode::F(9) => return SetupOutcome::Recheck,
            KeyCode::F(10) => return self.run_first_fix(),
            KeyCode::Char(' ') if self.field() == Field::Enabled => {
                self.enabled = !self.enabled;
            }
            KeyCode::Char(c) if !ctrl => {
                let field = self.field();
                if let Some(buffer) = self.buffer_mut(field) {
                    buffer.push(c);
                }
                self.error = None;
            }
            _ => {}
        }

        SetupOutcome::None
    }

    fn move_focus(&mut self, delta: isize) {
        let len = Field::ALL.len() as isize;
        self.focus = ((self.focus as isize + delta + len) % len) as usize;
    }

    fn cycle_interface(&mut self, delta: isize) {
        if self.field() != Field::Interface || self.interfaces.is_empty() {
            return;
        }
        let len = self.interfaces.len() as isize;
        let current = self
            .interfaces
            .iter()
            .position(|i| i.name == self.interface)
            .unwrap_or(0) as isize;
        let next = ((current + delta + len) % len) as usize;
        self.interface = self.interfaces[next].name.clone();
    }

    fn test_connection(&mut self) -> SetupOutcome {
        match self.ami_config() {
            Ok(mut ami) => {
                if self.secret_from_env {
                    ami.secret = std::env::var(SECRET_ENV).unwrap_or_default();
                }
                self.probe = ProbeState::Running;
                self.error = None;
                SetupOutcome::TestConnection(Box::new(ami))
            }
            Err(e) => {
                self.error = Some(e);
                SetupOutcome::None
            }
        }
    }

    fn run_first_fix(&mut self) -> SetupOutcome {
        match self
            .deps
            .checks()
            .iter()
            .find_map(|(_, state)| state.fix())
        {
            Some(fix) => SetupOutcome::RunFix(fix.to_vec()),
            None => {
                self.notice = Some("No hay nada que instalar: los chequeos están en verde.".into());
                SetupOutcome::None
            }
        }
    }

    fn ami_config(&self) -> Result<AmiConfig, String> {
        let host = self.host.trim();
        if host.is_empty() {
            return Err("El host de Asterisk no puede quedar vacío.".into());
        }
        let port: u16 = self
            .port
            .trim()
            .parse()
            .map_err(|_| format!("Puerto AMI inválido: '{}'.", self.port.trim()))?;
        if port == 0 {
            return Err("El puerto AMI no puede ser 0.".into());
        }
        let username = self.user.trim();
        if username.is_empty() {
            return Err("El usuario de AMI no puede quedar vacío.".into());
        }
        if self.secret.is_empty() && !self.secret_from_env {
            return Err(format!(
                "Falta la contraseña de AMI (o exportá {SECRET_ENV})."
            ));
        }

        Ok(AmiConfig {
            host: host.to_string(),
            port,
            username: username.to_string(),
            secret: self.secret.clone(),
        })
    }

    fn build_config(&mut self) -> SetupOutcome {
        let ami = match self.ami_config() {
            Ok(ami) => ami,
            Err(e) => {
                self.error = Some(e);
                return SetupOutcome::None;
            }
        };

        let sip_ports = match parse_ports(&self.ports) {
            Ok(ports) => ports,
            Err(e) => {
                self.error = Some(e);
                return SetupOutcome::None;
            }
        };

        if self.enabled && self.interface.trim().is_empty() {
            self.error =
                Some("Elegí una interfaz de captura o desactivá el análisis SIP.".to_string());
            return SetupOutcome::None;
        }

        SetupOutcome::Save(Box::new(Config {
            ami,
            capture: CaptureConfig {
                interface: self.interface.trim().to_string(),
                sip_ports,
                enabled: self.enabled,
            },
            ui: UiConfig::default(),
        }))
    }

    /// Re-corre los chequeos contra la interfaz elegida ahora mismo.
    pub fn recheck(&mut self) {
        self.deps = deps::probe(&self.interface);
        self.notice = Some("Chequeos de dependencias actualizados.".to_string());
    }

    /// IPs de la interfaz elegida, para mostrarlas junto al nombre.
    pub fn selected_interface(&self) -> Option<&Interface> {
        self.interfaces.iter().find(|i| i.name == self.interface)
    }

    pub fn on_probe_result(&mut self, result: Result<String, String>) {
        self.probe = match result {
            Ok(banner) => ProbeState::Ok(banner),
            Err(e) => ProbeState::Failed(e),
        };
    }
}

fn join_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_ports(raw: &str) -> Result<Vec<u16>, String> {
    let ports: Result<Vec<u16>, String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<u16>()
                .map_err(|_| format!("Puerto SIP inválido: '{s}'."))
        })
        .collect();

    let ports = ports?;
    if ports.is_empty() {
        return Err("Indicá al menos un puerto SIP (ej. 5060).".to_string());
    }
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsea_lista_de_puertos_con_espacios() {
        assert_eq!(parse_ports(" 5060 , 5061 ").unwrap(), vec![5060, 5061]);
    }

    #[test]
    fn rechaza_lista_vacia_y_puerto_invalido() {
        assert!(parse_ports("  ").is_err());
        assert!(parse_ports("5060,abc").is_err());
    }
}
