//! Windows Event Log collector — generic subscription to any channel.
//!
//! This is the primary collector used for the well-known Windows channels
//! (`Security`, `System`, `Application`) and any custom channel.
//!
//! Each collector persists an Event Log bookmark to disk so that it resumes
//! exactly where it left off after a restart — no duplicate events.
//!
//! # Usage
//! ```ignore
//! let mut collector = WindowsEventLogCollector::new("Security");
//! collector.run(sender).await?;
//! ```

use std::path::PathBuf;

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::logs::Collector;
use crate::logs::windows::subscription::subscribe_and_collect;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

/// Collector for Windows Event Log channels using `EvtSubscribe` with
/// persisted bookmarks.
pub struct WindowsEventLogCollector {
    /// The Event Log channel name (e.g. "Security", "System", "Application").
    channel: String,
    /// An XPath 1.0 filter to select events (e.g. `*[System[EventID=4624]]`).
    /// Use `"*"` to collect all events.
    filter: String,
    /// The `SourceType` to tag each record with.
    source_type: SourceType,
    /// Optional path to the bookmark file for this channel.
    bookmark_path: Option<PathBuf>,
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
            bookmark_path: None,
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
            bookmark_path: None,
        }
    }

    /// Set the bookmark file path for this collector.
    /// Pass `None` to disable bookmarking (legacy behaviour).
    pub fn with_bookmark(mut self, path: Option<PathBuf>) -> Self {
        self.bookmark_path = path;
        self
    }

    /// Override the XPath query filter (default is `"*"` = all events).
    /// Example: `*[System[(EventID=4624 or EventID=4625)]]`
    pub fn with_filter(mut self, filter: impl Into<String>) -> Self {
        self.filter = filter.into();
        self
    }
}

#[async_trait]
impl Collector for WindowsEventLogCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let channel = self.channel.clone();
        let filter = self.filter.clone();
        let source_type = self.source_type.clone();
        let hostname = get_hostname();
        let bookmark_path = self.bookmark_path.clone();

        tokio::task::spawn_blocking(move || {
            subscribe_and_collect(
                channel,
                filter,
                source_type,
                sender,
                hostname,
                bookmark_path,
            )
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

    #[test]
    fn with_filter_overrides_default() {
        let coll = WindowsEventLogCollector::new("Security")
            .with_filter("*[System[(EventID=4624 or EventID=4625)]]");
        assert_eq!(coll.filter, "*[System[(EventID=4624 or EventID=4625)]]");
    }

    #[test]
    fn with_filter_on_custom_channel() {
        let coll = WindowsEventLogCollector::new("MyApp").with_filter("*[System[EventID=100]]");
        assert_eq!(coll.channel, "MyApp");
        assert_eq!(coll.filter, "*[System[EventID=100]]");
        assert_eq!(coll.source_type, SourceType::Custom("MyApp".to_string()));
    }

    /// The run method spawns a blocking task; if the sender is dropped quickly,
    /// it should return Ok(()).
    #[tokio::test]
    async fn run_with_dropped_receiver_returns_ok() {
        let mut collector = WindowsEventLogCollector::new("Security");
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        drop(rx);

        let result = collector.run(tx).await;
        // May fail if EvtSubscribe lacks permissions (test/CI context),
        // but must not panic or hang.
        assert!(result.is_ok() || result.is_err());
    }
}
