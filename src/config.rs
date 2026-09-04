use color_eyre::eyre::{Result, WrapErr, eyre};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Variable de entorno que, si está presente, gana sobre el secret guardado en
/// disco. Pensada para despliegues donde el secret lo inyecta systemd/vault y no
/// se quiere ningún credencial en el filesystem.
pub const SECRET_ENV: &str = "VOXPBX_AMI_SECRET";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmiConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Secret de AMI. Se guarda en el archivo de config con permisos 0600 y lo
    /// pisa `VOXPBX_AMI_SECRET` si esa variable existe.
    #[serde(default)]
    pub secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    pub interface: String,
    pub sip_ports: Vec<u16>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    pub tick_rate_ms: u64,
    pub refresh_channels_secs: u64,
    pub refresh_peers_secs: u64,
    pub refresh_queues_secs: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub ami: AmiConfig,
    pub capture: CaptureConfig,
    #[serde(default)]
    pub ui: UiConfig,
}

impl Default for AmiConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 5038,
            username: String::new(),
            secret: String::new(),
        }
    }
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: "any".to_string(),
            sip_ports: vec![5060, 5061],
            enabled: true,
        }
    }
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            tick_rate_ms: 250,
            refresh_channels_secs: 2,
            refresh_peers_secs: 5,
            refresh_queues_secs: 3,
        }
    }
}

impl Config {
    /// `Ok(None)` significa "primer arranque": no hay config en ningún lado y hay
    /// que correr el asistente en vez de fallar.
    pub fn load() -> Result<Option<Self>> {
        let Some(path) = Self::existing_path() else {
            return Ok(None);
        };
        let raw = std::fs::read_to_string(&path)
            .wrap_err_with(|| format!("no se pudo leer la config en {}", path.display()))?;
        let config: Config = toml::from_str(&raw)
            .wrap_err_with(|| format!("config inválida en {}", path.display()))?;
        Ok(Some(config))
    }

    pub fn save(&self) -> Result<PathBuf> {
        let path = Self::write_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .wrap_err_with(|| format!("no se pudo crear {}", parent.display()))?;
        }

        let body = toml::to_string_pretty(self).wrap_err("no se pudo serializar la config")?;
        let contents = format!(
            "# Generado por voxpbx-tui. Contiene el secret de AMI: permisos 0600.\n\
             # Para no guardar el secret en disco, dejalo vacío y exportá {SECRET_ENV}.\n\n{body}"
        );
        std::fs::write(&path, contents)
            .wrap_err_with(|| format!("no se pudo escribir {}", path.display()))?;
        restrict_permissions(&path)?;
        Ok(path)
    }

    /// Config ya existente: primero el checkout (modo dev), después el directorio
    /// de config del usuario.
    pub fn existing_path() -> Option<PathBuf> {
        let dev = PathBuf::from("config/voxpbx.toml");
        if dev.exists() {
            return Some(dev);
        }
        let user = user_config_path()?;
        user.exists().then_some(user)
    }

    /// Dónde escribe el asistente: reusa el archivo existente si lo hay, si no
    /// crea el del directorio de config del usuario.
    pub fn write_path() -> Result<PathBuf> {
        if let Some(path) = Self::existing_path() {
            return Ok(path);
        }
        user_config_path()
            .ok_or_else(|| eyre!("no se pudo resolver el directorio de config del usuario"))
    }

    /// Secret efectivo: la variable de entorno gana sobre el archivo.
    pub fn effective_secret(&self) -> String {
        match std::env::var(SECRET_ENV) {
            Ok(v) if !v.is_empty() => v,
            _ => self.ami.secret.clone(),
        }
    }
}

fn user_config_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "voxpbx-tui")
        .map(|dirs| dirs.config_dir().join("config.toml"))
}

#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .wrap_err_with(|| format!("no se pudo aplicar 0600 a {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) -> Result<()> {
    Ok(())
}
