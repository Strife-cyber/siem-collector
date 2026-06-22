//! Linux process snapshot collector.
//!
//! Periodically reads `/proc/*/status` and `/proc/*/cmdline` to collect
//! running process information.  Equivalent to a periodic task-list snapshot.
//!
//! This is NOT real-time — it polls at a configurable interval (default 60 s).

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tokio::time::{Duration, interval};
use tracing::info;

use crate::logs::Collector;
use crate::logs::linux::tailer::read_file_lines;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

const DEFAULT_INTERVAL_SECS: u64 = 60;

pub struct LinuxProcessCollector {
    interval: Duration,
}

impl Default for LinuxProcessCollector {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(DEFAULT_INTERVAL_SECS),
        }
    }
}

impl LinuxProcessCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_interval(interval: Duration) -> Self {
        Self { interval }
    }
}

#[async_trait]
impl Collector for LinuxProcessCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();
        let mut ticker = interval(self.interval);

        loop {
            ticker.tick().await;

            if sender.is_closed() {
                return Ok(());
            }

            // Walk /proc for numeric directories (PIDs).
            let dir = match tokio::fs::read_dir("/proc").await {
                Ok(d) => d,
                Err(_) => continue,
            };

            let mut entries = Vec::new();
            let mut dir = dir;
            while let Ok(Some(entry)) = dir.next_entry().await {
                if let Some(name) = entry.file_name().to_str() {
                    if name.chars().all(|c| c.is_ascii_digit()) {
                        entries.push(entry.path());
                    }
                }
            }
            entries.sort();

            for path in &entries {
                if sender.is_closed() {
                    return Ok(());
                }

                // Read status.
                let status_path = path.join("status");
                read_file_lines(
                    status_path.to_str().unwrap_or(""),
                    SourceType::LinuxProcess,
                    &sender,
                    &hostname,
                )
                .await?;

                // Read cmdline.
                let cmdline_path = path.join("cmdline");
                read_file_lines(
                    cmdline_path.to_str().unwrap_or(""),
                    SourceType::LinuxProcess,
                    &sender,
                    &hostname,
                )
                .await?;
            }

            info!("Process snapshot: {} PIDs collected", entries.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_interval() {
        let c = LinuxProcessCollector::new();
        assert_eq!(c.interval, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn run_with_dropped_receiver_returns_ok() {
        let mut c = LinuxProcessCollector::with_interval(Duration::from_millis(10));
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        drop(rx);
        let result = c.run(tx).await;
        assert!(result.is_ok());
    }
}
