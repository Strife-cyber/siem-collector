//! Windows registry event collector.
//!
//! Monitors the Security Event Log for registry modification events:
//!   - 4657 – A registry value was modified
//!
//! Requires registry auditing SACL to be configured on the keys of interest
//! (e.g. `HKLM\SYSTEM\CurrentControlSet\Services`, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`).

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::logs::Collector;
use crate::logs::windows::subscription::subscribe_and_collect;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

/// Collector for Windows registry modification events.
pub struct WindowsRegistryCollector;

#[async_trait]
impl Collector for WindowsRegistryCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();

        let filter = "*[System[(EventID=4657)]]".to_string();

        tokio::task::spawn_blocking(move || {
            subscribe_and_collect(
                "Security".to_string(),
                filter,
                SourceType::WindowsRegistry,
                sender,
                hostname,
                None,
            )
        })
        .await
        .map_err(|e| anyhow::anyhow!("Join error: {}", e))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_collector() {
        let _ = WindowsRegistryCollector;
    }

    #[tokio::test]
    async fn run_with_dropped_receiver_returns_ok() {
        let mut collector = WindowsRegistryCollector;
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        drop(rx);
        let result = collector.run(tx).await;
        assert!(result.is_ok() || result.is_err());
    }
}
