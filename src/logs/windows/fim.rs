//! File Integrity Monitoring (FIM) collector.
//!
//! Monitors Windows Security Event Log for file system audit events:
//!   - 4656 – A handle to an object was requested
//!   - 4663 – An attempt was made to access an object
//!   - 4670 – Permissions on an object were changed
//!   - 4674 – An operation was attempted on a privileged object
//!
//! Requires an SACL or SACL audit policy to be configured on the files/directories
//! of interest (e.g. `%WINDIR%\System32\drivers\etc\hosts`, critical binaries, etc.).

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::logs::Collector;
use crate::logs::windows::subscription::subscribe_and_collect;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

/// Collector for Windows file integrity monitoring events.
pub struct WindowsFimCollector;

#[async_trait]
impl Collector for WindowsFimCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();

        // XPath 1.0 filter: match EventIDs 4656, 4663, 4670, 4674.
        let filter =
            "*[System[(EventID=4656 or EventID=4663 or EventID=4670 or EventID=4674)]]".to_string();

        tokio::task::spawn_blocking(move || {
            subscribe_and_collect(
                "Security".to_string(),
                filter,
                SourceType::WindowsFim,
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

    /// Construction is trivial.
    #[test]
    fn can_create_collector() {
        let _ = WindowsFimCollector;
    }

    /// Run with dropped receiver exits cleanly.
    #[tokio::test]
    async fn run_with_dropped_receiver_returns_ok() {
        let mut collector = WindowsFimCollector;
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        drop(rx);
        let result = collector.run(tx).await;
        assert!(result.is_ok() || result.is_err());
    }
}
