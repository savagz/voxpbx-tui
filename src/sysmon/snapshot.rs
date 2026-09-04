#[derive(Debug, Clone, Default)]
pub struct HostSnapshot {
    pub cpu_pct: f64,
    pub mem_pct: f64,
    pub mem_used_gb: f64,
    pub mem_total_gb: f64,
    pub disk_pct: f64,
    pub disk_used_gb: f64,
    pub disk_total_gb: f64,
    pub uptime_secs: u64,
}
