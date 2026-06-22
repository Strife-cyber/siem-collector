//! System inventory collector.
//!
//! Unlike the other event-log-based collectors, inventory runs on a timer
//! and periodically collects system state (installed software, running
//! services, hardware info) via WMI queries.
//!
//! This collector does NOT use `EvtQuery` — it runs `wmic` commands or
//! reads registry keys at a configurable interval.

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tokio::time::{Duration, interval};
use tracing::{error, info};

use crate::logs::Collector;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

/// How often to snapshot the system inventory (default: every 6 hours).
const DEFAULT_INVENTORY_INTERVAL: Duration = Duration::from_secs(6 * 3600);

/// Collector for periodic system inventory snapshots.
pub struct WindowsInventoryCollector {
    interval: Duration,
}

impl Default for WindowsInventoryCollector {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INVENTORY_INTERVAL,
        }
    }
}

impl WindowsInventoryCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a custom collection interval.
    pub fn with_interval(interval: Duration) -> Self {
        Self { interval }
    }

    /// Collect one inventory snapshot by shelling out to `wmic`.
    async fn collect_inventory(&self) -> Vec<CollectorLogRecord> {
        let hostname = get_hostname();
        let mut records = Vec::new();

        // Collect installed software list via wmic.
        #[cfg(windows)]
        {
            let commands = [
                (
                    "software",
                    "wmic product get name,version,vendor /format:csv",
                ),
                (
                    "services",
                    "wmic service get name,displayname,startmode,state /format:csv",
                ),
                (
                    "hotfixes",
                    "wmic qfe get hotfixid,description,installedon /format:csv",
                ),
                (
                    "startup",
                    "wmic startup get name,caption,command /format:csv",
                ),
            ];

            for (category, cmd) in &commands {
                match Self::run_wmic(cmd).await {
                    Ok(output) => {
                        let record = CollectorLogRecord::new(
                            SourceType::WindowsInventory,
                            hostname.clone(),
                            format!("[{}]\n{}\n", category, output).into_bytes(),
                        );
                        records.push(record);
                    }
                    Err(e) => {
                        error!("Inventory command '{}' failed: {}", category, e);
                    }
                }
            }
        }

        #[cfg(not(windows))]
        {
            let _ = hostname;
            info!("Inventory collection only supported on Windows");
        }

        records
    }

    /// Execute a `wmic` command and return stdout as a String.
    #[cfg(windows)]
    async fn run_wmic(cmd: &str) -> anyhow::Result<String> {
        // Parse the command into a program and arguments.
        // wmic is typically: `wmic product get ...`
        let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
        let program = parts[0];
        let args = parts.get(1).copied().unwrap_or("");

        let output = tokio::process::Command::new(program)
            .args(args.split_whitespace())
            .output()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to run '{}': {}", cmd, e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("'{}' failed: {}", cmd, stderr);
        }
    }
}

#[async_trait]
impl Collector for WindowsInventoryCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let mut ticker = interval(self.interval);

        loop {
            ticker.tick().await;

            info!("Collecting system inventory snapshot");
            let records = self.collect_inventory().await;

            for record in records {
                if sender.send(record).await.is_err() {
                    info!("Inventory collector receiver dropped, exiting");
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_interval_six_hours() {
        let coll = WindowsInventoryCollector::new();
        assert_eq!(coll.interval, Duration::from_secs(6 * 3600));
    }

    #[test]
    fn custom_interval() {
        let coll = WindowsInventoryCollector::with_interval(Duration::from_secs(60));
        assert_eq!(coll.interval, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn run_with_dropped_receiver_returns_ok() {
        let mut collector = WindowsInventoryCollector::with_interval(Duration::from_millis(10));
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        drop(rx);
        let result = collector.run(tx).await;
        assert!(result.is_ok());
    }
}
