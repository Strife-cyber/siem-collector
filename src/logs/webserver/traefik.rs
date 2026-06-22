//! Traefik reverse-proxy log collector.
//!
//! Traefik is most commonly deployed as a Docker container, so the primary
//! collection method is `docker logs -f traefik`.  If the container name
//! differs, configure it via [`TraefikCollector::with_container`].
//!
//! Falls back to file-based collection if Traefik is configured to write
//! logs to a file path.
//!
//! Usage:
//! ```ignore
//! // Docker-based (default)
//! let c = TraefikCollector::new();
//!
//! // Custom container name
//! let c = TraefikCollector::with_container("reverse-proxy");
//!
//! // File-based
//! let c = TraefikCollector::with_file("/var/log/traefik/access.json");
//! ```

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::logs::linux::streamer::stream_process_output;
use crate::logs::linux::tailer::tail_log;
use crate::logs::Collector;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

/// Default Docker container name for Traefik.
const DEFAULT_CONTAINER: &str = "traefik";

pub enum TraefikSource {
    Docker(String),
    File(String),
}

/// Traefik log collector.
pub struct TraefikCollector {
    source: TraefikSource,
}

impl TraefikCollector {
    /// Create a collector that reads from `docker logs -f traefik`.
    pub fn new() -> Self {
        Self {
            source: TraefikSource::Docker(DEFAULT_CONTAINER.to_string()),
        }
    }

    /// Use a custom Docker container name.
    pub fn with_container(container: impl Into<String>) -> Self {
        Self {
            source: TraefikSource::Docker(container.into()),
        }
    }

    /// Use a file-based log path instead of Docker.
    pub fn with_file(path: impl Into<String>) -> Self {
        Self {
            source: TraefikSource::File(path.into()),
        }
    }
}

impl Default for TraefikCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Collector for TraefikCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();

        match &self.source {
            TraefikSource::Docker(container) => {
                stream_process_output(
                    "docker",
                    &["logs", "-f", container],
                    &format!("traefik/{}", container),
                    SourceType::Traefik,
                    sender,
                    hostname,
                    true, // restart on container restart
                )
                .await
            }
            TraefikSource::File(path) => {
                tail_log(path, SourceType::Traefik, sender, hostname).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_docker() {
        let c = TraefikCollector::new();
        assert!(matches!(c.source, TraefikSource::Docker(_)));
    }

    #[test]
    fn with_container_name() {
        let c = TraefikCollector::with_container("reverse-proxy");
        assert!(matches!(c.source, TraefikSource::Docker(_)));
    }

    #[test]
    fn with_file_path() {
        let c = TraefikCollector::with_file("/custom/path.log");
        assert!(matches!(c.source, TraefikSource::File(_)));
    }
}
