use std::path::Path;
use std::process::{Command, Stdio};

/// Chequeo y remediación de las dependencias del análisis SIP.
///
/// El análisis SIP se apoya en `libpcap`. El binario la enlaza dinámicamente, así
/// que el asistente verifica tres cosas distintas y cada una tiene su propio
/// arreglo: la librería en runtime, los headers (necesarios para recompilar) y el
/// permiso para abrir la interfaz en modo captura.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Apt,
    Dnf,
    Yum,
    Pacman,
    Apk,
    Zypper,
    Brew,
}

impl PackageManager {
    pub fn label(&self) -> &'static str {
        match self {
            PackageManager::Apt => "apt",
            PackageManager::Dnf => "dnf",
            PackageManager::Yum => "yum",
            PackageManager::Pacman => "pacman",
            PackageManager::Apk => "apk",
            PackageManager::Zypper => "zypper",
            PackageManager::Brew => "brew",
        }
    }

    /// Paquete que trae `libpcap` **con headers** (los `-dev`/`-devel` incluyen la
    /// librería runtime, así que un solo paquete cubre ambos chequeos).
    pub fn pcap_package(&self) -> &'static str {
        match self {
            PackageManager::Apt | PackageManager::Apk => "libpcap-dev",
            PackageManager::Dnf | PackageManager::Yum | PackageManager::Zypper => "libpcap-devel",
            PackageManager::Pacman | PackageManager::Brew => "libpcap",
        }
    }

    /// Comando de instalación no interactivo, con `sudo` delante salvo que ya
    /// seamos root o el gestor sea `brew` (que se niega a correr como root).
    pub fn install_command(&self) -> Vec<String> {
        let pkg = self.pcap_package().to_string();
        let base: Vec<String> = match self {
            PackageManager::Apt => vec![
                "sh".into(),
                "-c".into(),
                format!("apt-get update && apt-get install -y {pkg}"),
            ],
            PackageManager::Dnf => vec!["dnf".into(), "install".into(), "-y".into(), pkg],
            PackageManager::Yum => vec!["yum".into(), "install".into(), "-y".into(), pkg],
            PackageManager::Pacman => vec![
                "pacman".into(),
                "-S".into(),
                "--needed".into(),
                "--noconfirm".into(),
                pkg,
            ],
            PackageManager::Apk => vec!["apk".into(), "add".into(), "--no-cache".into(), pkg],
            PackageManager::Zypper => vec![
                "zypper".into(),
                "--non-interactive".into(),
                "install".into(),
                pkg,
            ],
            PackageManager::Brew => return vec!["brew".into(), "install".into(), pkg],
        };

        if is_root() {
            base
        } else {
            let mut with_sudo = vec!["sudo".to_string()];
            with_sudo.extend(base);
            with_sudo
        }
    }
}

pub fn detect_package_manager() -> Option<PackageManager> {
    const CANDIDATES: [(&str, PackageManager); 7] = [
        ("apt-get", PackageManager::Apt),
        ("dnf", PackageManager::Dnf),
        ("yum", PackageManager::Yum),
        ("pacman", PackageManager::Pacman),
        ("apk", PackageManager::Apk),
        ("zypper", PackageManager::Zypper),
        ("brew", PackageManager::Brew),
    ];
    CANDIDATES
        .iter()
        .find(|(bin, _)| which(bin))
        .map(|(_, pm)| *pm)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckState {
    /// Verificado y funcionando.
    Ok(String),
    /// Falta algo y sabemos cómo arreglarlo (comando sugerido).
    Missing { detail: String, fix: Vec<String> },
    /// No se pudo determinar (gestor de paquetes desconocido, etc.).
    Unknown(String),
}

impl CheckState {
    pub fn is_ok(&self) -> bool {
        matches!(self, CheckState::Ok(_))
    }

    pub fn detail(&self) -> &str {
        match self {
            CheckState::Ok(d) | CheckState::Unknown(d) => d,
            CheckState::Missing { detail, .. } => detail,
        }
    }

    pub fn fix(&self) -> Option<&[String]> {
        match self {
            CheckState::Missing { fix, .. } => Some(fix),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DepReport {
    pub package_manager: Option<PackageManager>,
    /// `libpcap` cargable: sin esto no hay captura de ningún tipo.
    pub library: CheckState,
    /// Headers de `libpcap`: sólo hacen falta para recompilar el binario.
    pub headers: CheckState,
    /// Permiso efectivo para abrir la interfaz configurada en modo promiscuo.
    pub permission: CheckState,
}

impl DepReport {
    pub fn all_ok(&self) -> bool {
        self.library.is_ok() && self.headers.is_ok() && self.permission.is_ok()
    }

    /// Chequeos en orden de severidad, para renderizarlos como una lista de LEDs.
    pub fn checks(&self) -> [(&'static str, &CheckState); 3] {
        [
            ("LIBPCAP RUNTIME", &self.library),
            ("LIBPCAP HEADERS", &self.headers),
            ("PERMISO DE CAPTURA", &self.permission),
        ]
    }
}

/// Corre los tres chequeos contra la interfaz que el usuario eligió.
pub fn probe(interface: &str) -> DepReport {
    let pm = detect_package_manager();
    DepReport {
        package_manager: pm,
        library: check_library(pm),
        headers: check_headers(pm),
        permission: check_permission(interface),
    }
}

/// `Device::list` es la prueba real de que `libpcap` está cargada y responde.
fn check_library(pm: Option<PackageManager>) -> CheckState {
    match pcap::Device::list() {
        Ok(devices) => CheckState::Ok(format!("{} interfaces visibles", devices.len())),
        Err(e) => missing_pcap(pm, format!("libpcap no responde: {e}")),
    }
}

fn check_headers(pm: Option<PackageManager>) -> CheckState {
    if pkg_config_has_libpcap() {
        return CheckState::Ok("pkg-config encuentra libpcap".to_string());
    }
    const HEADERS: [&str; 3] = [
        "/usr/include/pcap.h",
        "/usr/include/pcap/pcap.h",
        "/usr/local/include/pcap.h",
    ];
    if HEADERS.iter().any(|p| Path::new(p).exists()) {
        return CheckState::Ok("pcap.h presente".to_string());
    }
    if cfg!(target_os = "macos") {
        // En macOS los headers viven dentro del SDK de Xcode, no en /usr/include.
        return CheckState::Ok("provistos por el SDK del sistema".to_string());
    }
    missing_pcap(pm, "faltan los headers de libpcap (pcap.h)".to_string())
}

fn missing_pcap(pm: Option<PackageManager>, detail: String) -> CheckState {
    match pm {
        Some(pm) => CheckState::Missing {
            detail,
            fix: pm.install_command(),
        },
        None => CheckState::Unknown(format!(
            "{detail} — instalá libpcap con el gestor de paquetes de tu distro"
        )),
    }
}

/// Abrir la interfaz de verdad es el único chequeo honesto de permisos: contempla
/// root, capabilities en el binario y permisos sobre `/dev/bpf*` en macOS.
fn check_permission(interface: &str) -> CheckState {
    if interface.is_empty() {
        return CheckState::Unknown("todavía no elegiste interfaz".to_string());
    }

    let opened = pcap::Capture::from_device(interface).and_then(|c| c.promisc(true).open());

    match opened {
        Ok(_) => CheckState::Ok(format!("se puede capturar en {interface}")),
        Err(e) if is_root() => CheckState::Unknown(format!(
            "corriendo como root pero {interface} no abre: {e}"
        )),
        Err(e) => CheckState::Missing {
            detail: format!("{interface} no abre: {e}"),
            fix: grant_command(),
        },
    }
}

/// En Linux la capability puntual sobre el binario evita correr toda la TUI como
/// root. En macOS no hay equivalente: el arreglo es abrir `/dev/bpf*` al grupo.
fn grant_command() -> Vec<String> {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "target/release/voxpbx-tui".to_string());

    if cfg!(target_os = "macos") {
        vec![
            "sudo".into(),
            "chmod".into(),
            "g+r".into(),
            "/dev/bpf*".into(),
        ]
    } else {
        vec![
            "sudo".into(),
            "setcap".into(),
            "cap_net_raw,cap_net_admin+eip".into(),
            exe,
        ]
    }
}

/// Ejecuta un comando de remediación heredando la terminal — hace falta para que
/// `sudo` pueda pedir la contraseña. El llamador debe haber salido de la pantalla
/// alterna de ratatui antes.
pub fn run_fix(command: &[String]) -> Result<bool, std::io::Error> {
    let Some((program, args)) = command.split_first() else {
        return Ok(false);
    };
    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    Ok(status.success())
}

pub fn command_line(command: &[String]) -> String {
    command.join(" ")
}

/// Una interfaz candidata para la captura, con las IPs que tiene asignadas.
#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub ips: Vec<std::net::IpAddr>,
}

impl Interface {
    /// IPs para mostrar al lado del nombre: sin esto elegir entre `eth0`, `ens18`
    /// y `docker0` es adivinar.
    pub fn summary(&self) -> String {
        if self.name == "any" {
            return "todas las interfaces".to_string();
        }
        if self.ips.is_empty() {
            return "sin dirección".to_string();
        }
        self.ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Interfaces disponibles para capturar, las con IP real primero.
///
/// El orden importa: la primera es la que el asistente propone por defecto, y una
/// interfaz sin dirección (o `any`, que en Linux entrega cooked capture) es peor
/// default que la NIC por la que efectivamente pasa el SIP.
pub fn interfaces() -> Vec<Interface> {
    let devices: Vec<Interface> = pcap::Device::list()
        .unwrap_or_default()
        .into_iter()
        .map(|device| Interface {
            name: device.name,
            ips: device.addresses.into_iter().map(|a| a.addr).collect(),
        })
        .collect();

    with_any(devices)
}

/// Ordena las interfaces detectadas y garantiza que `any` esté siempre al final
/// de la lista, sin duplicarla si `libpcap` ya la reportó (Linux con permisos la
/// incluye; macOS o una lista sin privilegios no).
fn with_any(mut interfaces: Vec<Interface>) -> Vec<Interface> {
    interfaces.retain(|i| i.name != "any");

    interfaces.sort_by(|a, b| {
        let rank = |i: &Interface| {
            let routable = i.ips.iter().any(|ip| !ip.is_loopback());
            match (routable, i.ips.is_empty()) {
                (true, _) => 0,
                (false, false) => 1,
                (false, true) => 2,
            }
        };
        rank(a).cmp(&rank(b)).then_with(|| a.name.cmp(&b.name))
    });

    interfaces.push(Interface {
        name: "any".to_string(),
        ips: Vec::new(),
    });
    interfaces
}

fn which(binary: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {binary}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn pkg_config_has_libpcap() -> bool {
    Command::new("pkg-config")
        .args(["--exists", "libpcap"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn is_root() -> bool {
    // SAFETY: `geteuid` no toma punteros ni puede fallar.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn iface(name: &str, ip: Option<&str>) -> Interface {
        Interface {
            name: name.to_string(),
            ips: ip
                .map(|ip| vec![ip.parse::<IpAddr>().unwrap()])
                .unwrap_or_default(),
        }
    }

    #[test]
    fn any_siempre_aparece_al_final_aunque_libpcap_no_la_liste() {
        let result = with_any(vec![iface("eth0", Some("192.168.1.10"))]);
        assert_eq!(result.last().unwrap().name, "any");
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn no_duplica_any_si_libpcap_ya_la_reporta() {
        let result = with_any(vec![
            iface("eth0", Some("192.168.1.10")),
            iface("any", None),
        ]);
        let any_count = result.iter().filter(|i| i.name == "any").count();
        assert_eq!(any_count, 1);
        assert_eq!(result.last().unwrap().name, "any");
    }

    #[test]
    fn interfaz_con_ip_routeable_va_antes_que_any() {
        let result = with_any(vec![iface("lo", Some("127.0.0.1")), iface("eth0", Some("10.0.0.5"))]);
        assert_eq!(result[0].name, "eth0");
        assert_eq!(result[1].name, "lo");
        assert_eq!(result[2].name, "any");
    }

    #[test]
    fn any_se_resume_como_todas_las_interfaces() {
        let any = iface("any", None);
        assert_eq!(any.summary(), "todas las interfaces");
    }

    #[test]
    fn interfaz_sin_ip_se_resume_como_sin_direccion() {
        assert_eq!(iface("docker0", None).summary(), "sin dirección");
    }

    #[test]
    fn interfaz_con_ip_resume_la_direccion() {
        assert_eq!(
            iface("eth0", Some("10.0.0.5")).summary(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)).to_string()
        );
    }
}
