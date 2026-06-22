//! Windows Scheduled Task collector.
//!
//! Monitors the Security Event Log for scheduled task events:
//!   - 4698 – A scheduled task was created
//!   - 4699 – A scheduled task was deleted
//!   - 4700 – A scheduled task was enabled
//!   - 4701 – A scheduled task was disabled
//!   - 4702 – A scheduled task was updated
//!
//! These events are generated when Audit Detailed Tracking > Audit Other
//! Object Access Events is enabled.

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::logs::Collector;
use crate::logs::windows::subscription::subscribe_and_collect;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

/// Collector for Windows scheduled task events.
pub struct WindowsTasksCollector;

#[async_trait]
impl Collector for WindowsTasksCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();

        let filter = "*[System[(".to_string()
            + "EventID=4698 or EventID=4699 or EventID=4700 or "
            + "EventID=4701 or EventID=4702"
            + ")]]";

        tokio::task::spawn_blocking(move || {
            subscribe_and_collect(
                "Security".to_string(),
                filter,
                SourceType::WindowsTasks,
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
        let _ = WindowsTasksCollector;
    }

    #[tokio::test]
    async fn run_with_dropped_receiver_returns_ok() {
        let mut collector = WindowsTasksCollector;
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        drop(rx);
        let result = collector.run(tx).await;
        assert!(result.is_ok());
    }
}
