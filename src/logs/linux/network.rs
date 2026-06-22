//! Linux network connection collector.
//!
//! Periodically reads `/proc/net/tcp` and `/proc/net/udp` to collect
//! active network connections.  Equivalent to `netstat -an` or `ss -an`.
//!
//! Polls at a configurable interval (default 30 s).

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tokio::time::{Duration, interval};
use tracing::info;

use crate::logs::Collector;
use crate::logs::linux::tailer::read_file_lines;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

const DEFAULT_INTERVAL_SECS: u64 = 30;

/// Pseudo-files in `/proc/net/` that contain connection state.
const PROC_NET_FILES: &[&str] = &[
    "/proc/net/tcp",
    "/proc/net/tcp6",
    "/proc/net/udp",
    "/proc/net/udp6",
];

pub struct LinuxNetworkCollector {
    interval: Duration,
}

impl Default for LinuxNetworkCollector {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(DEFAULT_INTERVAL_SECS),
        }
    }
}

impl LinuxNetworkCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_interval(interval: Duration) -> Self {
        Self { interval }
    }
}

#[async_trait]
impl Collector for LinuxNetworkCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();
        let mut ticker = interval(self.interval);

        loop {
            ticker.tick().await;

            if sender.is_closed() {
                return Ok(());
            }

            for path in PROC_NET_FILES {
                if sender.is_closed() {
                    return Ok(());
                }
                read_file_lines(path, SourceType::LinuxNetwork, &sender, &hostname).await?;
            }

            info!("Network connection snapshot collected");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_interval() {
        let c = LinuxNetworkCollector::new();
        assert_eq!(c.interval, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn run_with_dropped_receiver_returns_ok() {
        let mut c = LinuxNetworkCollector::with_interval(Duration::from_millis(10));
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        drop(rx);
        let result = c.run(tx).await;
        assert!(result.is_ok());
    }
}
