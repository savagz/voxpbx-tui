pub mod snapshot;

use std::path::Path;
use std::time::Duration;

use sysinfo::{Disks, System};
use tokio::sync::mpsc;

use crate::event::AppEvent;
use snapshot::HostSnapshot;

const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Poller de sysinfo del host local (la TUI corre en el propio server Asterisk,
/// sin red extra). Refresca `System`/`Disks` in-place, nunca los recrea.
pub fn spawn(app_tx: mpsc::Sender<AppEvent>) {
    tokio::spawn(async move {
        let mut sys = System::new_all();
        let mut disks = Disks::new_with_refreshed_list();
        let mut interval = tokio::time::interval(POLL_INTERVAL);

        loop {
            interval.tick().await;
            sys.refresh_cpu_usage();
            sys.refresh_memory();
            disks.refresh(true);

            let cpu_pct = sys.global_cpu_usage() as f64;

            let mem_total = sys.total_memory();
            let mem_used = sys.used_memory();
            let mem_pct = pct(mem_used, mem_total);

            let (disk_total, disk_used) = root_disk_usage(&disks);
            let disk_pct = pct(disk_used, disk_total);

            let snapshot = HostSnapshot {
                cpu_pct,
                mem_pct,
                mem_used_gb: bytes_to_gb(mem_used),
                mem_total_gb: bytes_to_gb(mem_total),
                disk_pct,
                disk_used_gb: bytes_to_gb(disk_used),
                disk_total_gb: bytes_to_gb(disk_total),
                uptime_secs: System::uptime(),
            };

            if app_tx.send(AppEvent::SysSnapshot(snapshot)).await.is_err() {
                break;
            }
        }
    });
}

fn root_disk_usage(disks: &Disks) -> (u64, u64) {
    disks
        .list()
        .iter()
        .find(|d| d.mount_point() == Path::new("/"))
        .or_else(|| disks.list().first())
        .map(|d| {
            let total = d.total_space();
            let available = d.available_space();
            (total, total.saturating_sub(available))
        })
        .unwrap_or((0, 0))
}

fn pct(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        used as f64 / total as f64 * 100.0
    }
}

fn bytes_to_gb(bytes: u64) -> f64 {
    bytes as f64 / 1024.0 / 1024.0 / 1024.0
}
