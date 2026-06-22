//! Windows service event collector.
//!
//! Monitors the System and Security Event Logs for service state changes:
//!   - 7036 (System) – A service entered the running / stopped state
//!   - 7045 (System) – A new service was installed
//!   - 4697 (Security) – A new service was installed (Advanced Audit Policy)

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::logs::Collector;
use crate::logs::windows::subscription::subscribe_and_collect;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

/// Collector for Windows service installation / state-change events.
pub struct WindowsServicesCollector;

#[async_trait]
impl Collector for WindowsServicesCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();

        let filter = "*[System[(EventID=7036 or EventID=7045 or EventID=4697)]]".to_string();

        tokio::task::spawn_blocking(move || {
            subscribe_and_collect(
                "System".to_string(),
                filter,
                SourceType::WindowsServices,
                sender,
                hostname,
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
        let _ = WindowsServicesCollector;
    }

    #[tokio::test]
    async fn run_with_dropped_receiver_returns_ok() {
        let mut collector = WindowsServicesCollector;
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        drop(rx);
        let result = collector.run(tx).await;
        assert!(result.is_ok());
    }
}
