//! Linux authentication log collector.
//!
//! Tails `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS)
//! and emits each new line as a `CollectorLogRecord` with `SourceType::LinuxAuth`.
//!
//! Detects brute-force attacks, successful logins, SSH activity,
//! privilege escalation (sudo), and user management events.

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tracing::warn;

use crate::logs::Collector;
use crate::logs::linux::tailer::tail_log;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

/// Common auth log paths checked at startup.
const AUTH_LOG_PATHS: &[&str] = &["/var/log/auth.log", "/var/log/secure"];

pub struct LinuxAuthCollector;

#[async_trait]
impl Collector for LinuxAuthCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();

        // Try each known path and use the first that exists.
        let path = AUTH_LOG_PATHS
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .copied()
            .unwrap_or_else(|| {
                warn!("No auth log found (tried: {:?})", AUTH_LOG_PATHS);
                AUTH_LOG_PATHS[0] // will fail on open, producing a clear error
            });

        tail_log(path, SourceType::LinuxAuth, sender, hostname).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create() {
        let _ = LinuxAuthCollector;
    }
}
