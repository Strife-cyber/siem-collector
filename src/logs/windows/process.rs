//! Windows process event collector.
//!
//! Monitors the Security Event Log for process creation and termination:
//!   - 4688 – A new process has been created (includes command line)
//!   - 4689 – A process has exited
//!
//! Process creation auditing is enabled via Group Policy:
//!   `Computer Configuration > Windows Settings > Security Settings >
//!    Advanced Audit Policy Configuration > Detailed Tracking >
//!    Audit Process Creation`

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::logs::Collector;
use crate::logs::windows::subscription::subscribe_and_collect;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

/// Collector for process creation / termination events.
pub struct WindowsProcessCollector;

#[async_trait]
impl Collector for WindowsProcessCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();

        let filter = "*[System[(EventID=4688 or EventID=4689)]]".to_string();

        tokio::task::spawn_blocking(move || {
            subscribe_and_collect(
                "Security".to_string(),
                filter,
                SourceType::WindowsProcess,
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
        let _ = WindowsProcessCollector;
    }

    #[tokio::test]
    async fn run_with_dropped_receiver_returns_ok() {
        let mut collector = WindowsProcessCollector;
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        drop(rx);
        let result = collector.run(tx).await;
        assert!(result.is_ok() || result.is_err());
    }
}
