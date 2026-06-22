//! Windows network event collector.
//!
//! Monitors the Security Event Log for firewall and network events:
//!   - 5152 – The Windows Filtering Platform blocked a packet
//!   - 5153 – A more restrictive Windows Filtering Platform filter has blocked a packet
//!   - 5154 – The Windows Filtering Platform has permitted a connection
//!   - 5155 – The Windows Filtering Platform has blocked a connection
//!   - 5156 – The Windows Filtering Platform has allowed a connection
//!   - 5157 – The Windows Filtering Platform has blocked a connection
//!   - 5158 – The Windows Filtering Platform has permitted a bind to a local port
//!   - 5159 – The Windows Filtering Platform has blocked a bind to a local port
//!
//! Also includes Windows Defender Firewall policy-change events:
//!   - 2004, 2005, 2006, 2009 – Firewall rule changes

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::logs::Collector;
use crate::logs::windows::subscription::subscribe_and_collect;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

/// Collector for Windows firewall / network events.
pub struct WindowsNetworkCollector;

#[async_trait]
impl Collector for WindowsNetworkCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();

        // WFP events (5152-5159) plus Windows Defender Firewall rule changes (2004-2006, 2009).
        let filter = "*[System[(".to_string()
            + "(EventID=5152 or EventID=5153 or EventID=5154 or EventID=5155 or "
            + "EventID=5156 or EventID=5157 or EventID=5158 or EventID=5159 or "
            + "EventID=2004 or EventID=2005 or EventID=2006 or EventID=2009)"
            + ")]]";

        tokio::task::spawn_blocking(move || {
            subscribe_and_collect(
                "Security".to_string(),
                filter,
                SourceType::WindowsNetwork,
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
        let _ = WindowsNetworkCollector;
    }

    #[tokio::test]
    async fn run_with_dropped_receiver_returns_ok() {
        let mut collector = WindowsNetworkCollector;
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        drop(rx);
        let result = collector.run(tx).await;
        assert!(result.is_ok());
    }
}
