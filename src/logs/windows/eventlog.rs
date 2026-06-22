//! Windows Event Log collector — generic subscription to any channel.
//!
//! This is the primary collector used for the well-known Windows channels
//! (`Security`, `System`, `Application`) and any custom channel.
//!
//! # Usage
//! ```ignore
//! let mut collector = WindowsEventLogCollector::new("Security");
//! collector.run(sender).await?;
//! ```

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::logs::Collector;
use crate::logs::windows::subscription::subscribe_and_collect;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

/// Collector for Windows Event Log channels using `EvtQuery` polling.
pub struct WindowsEventLogCollector {
    /// The Event Log channel name (e.g. "Security", "System", "Application").
    channel: String,
    /// An XPath 1.0 filter to select events (e.g. `*[System[EventID=4624]]`).
    /// Use `"*"` to collect all events.
    filter: String,
    /// The `SourceType` to tag each record with.
    source_type: SourceType,
}

impl WindowsEventLogCollector {
    /// Create a new collector for the given channel with no filter.
    ///
    /// Uses `SourceType::Custom(channel)` as the default source type.
    pub fn new(channel: impl Into<String>) -> Self {
        let channel = channel.into();
        let source_type = match channel.to_lowercase().as_str() {
            "security" => SourceType::WindowsSecurity,
            "system" => SourceType::WindowsSystem,
            "application" => SourceType::WindowsApplication,
            _ => SourceType::Custom(channel.clone()),
        };
        Self {
            channel,
            filter: "*".to_string(),
            source_type,
        }
    }

    /// Create a collector for the given channel with an explicit `SourceType`.
    pub fn with_source_type(
        channel: impl Into<String>,
        filter: impl Into<String>,
        source_type: SourceType,
    ) -> Self {
        Self {
            channel: channel.into(),
            filter: filter.into(),
            source_type,
        }
    }
}

#[async_trait]
impl Collector for WindowsEventLogCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let channel = self.channel.clone();
        let filter = self.filter.clone();
        let source_type = self.source_type.clone();
        let hostname = get_hostname();

        tokio::task::spawn_blocking(move || {
            subscribe_and_collect(channel, filter, source_type, sender, hostname)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Join error: {}", e))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test construction with well-known channels auto-detects the source type.
    #[test]
    fn known_channel_autodetects_source_type() {
        let sec = WindowsEventLogCollector::new("Security");
        assert_eq!(sec.source_type, SourceType::WindowsSecurity);
        assert_eq!(sec.channel, "Security");

        let sys = WindowsEventLogCollector::new("System");
        assert_eq!(sys.source_type, SourceType::WindowsSystem);
        assert_eq!(sys.channel, "System");

        let app = WindowsEventLogCollector::new("Application");
        assert_eq!(app.source_type, SourceType::WindowsApplication);
        assert_eq!(app.channel, "Application");
    }

    /// Test construction with an unknown channel falls back to Custom.
    #[test]
    fn unknown_channel_falls_back_to_custom() {
        let custom = WindowsEventLogCollector::new("MyApp");
        assert_eq!(custom.source_type, SourceType::Custom("MyApp".to_string()));
        assert_eq!(custom.channel, "MyApp");
    }

    /// Test with_source_type builder.
    #[test]
    fn with_source_type_builder() {
        let coll = WindowsEventLogCollector::with_source_type(
            "Security",
            "*[System[EventID=4624]]",
            SourceType::WindowsSecurity,
        );
        assert_eq!(coll.channel, "Security");
        assert_eq!(coll.filter, "*[System[EventID=4624]]");
        assert_eq!(coll.source_type, SourceType::WindowsSecurity);
    }

    /// The run method spawns a blocking task; if the sender is dropped quickly,
    /// it should return Ok(()).
    #[tokio::test]
    async fn run_with_dropped_receiver_returns_ok() {
        let mut collector = WindowsEventLogCollector::new("Security");
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        drop(rx); // Drop immediately so the loop exits

        let result = collector.run(tx).await;
        assert!(result.is_ok());
    }
}
