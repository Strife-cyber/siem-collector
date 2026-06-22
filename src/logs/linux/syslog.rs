//! Linux syslog collector.
//!
//! Tails `/var/log/syslog` (Debian/Ubuntu) or `/var/log/messages` (RHEL/CentOS)
//! for service restarts, daemon crashes, cron jobs, and general system events.

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tracing::warn;

use crate::logs::linux::tailer::tail_log;
use crate::logs::Collector;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

/// Common syslog paths.
const SYSLOG_PATHS: &[&str] = &["/var/log/syslog", "/var/log/messages"];

pub struct LinuxSyslogCollector;

#[async_trait]
impl Collector for LinuxSyslogCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();

        let path = SYSLOG_PATHS
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .copied()
            .unwrap_or_else(|| {
                warn!("No syslog found (tried: {:?})", SYSLOG_PATHS);
                SYSLOG_PATHS[0]
            });

        tail_log(path, SourceType::LinuxSyslog, sender, hostname).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create() {
        let _ = LinuxSyslogCollector;
    }
}
