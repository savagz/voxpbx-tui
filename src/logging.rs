use color_eyre::eyre::Result;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

/// Los logs de la app (reconexiones AMI, errores de captura, etc.) van SIEMPRE a un
/// archivo, nunca a stdout/stderr: escribir ahí mientras ratatui tiene la alternate
/// screen activa corrompería el dibujado de la TUI.
///
/// El `WorkerGuard` devuelto debe mantenerse vivo hasta el final de `main` — al
/// dropearse fuerza el flush del buffer de escritura no bloqueante.
pub fn init() -> Result<WorkerGuard> {
    let dirs = directories::ProjectDirs::from("", "", "voxpbx-tui").ok_or_else(|| {
        color_eyre::eyre::eyre!("no se pudo resolver el directorio de datos del usuario")
    })?;

    let log_dir = dirs.data_dir();
    std::fs::create_dir_all(log_dir)?;

    let file_appender = tracing_appender::rolling::daily(log_dir, "voxpbx-tui.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    Ok(guard)
}
