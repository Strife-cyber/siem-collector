//! Linux Auditd collector.
//!
//! Tails `/var/log/audit/audit.log` — the closest equivalent to Windows
//! Security Auditing / Sysmon.  Contains process executions (`execve`),
//! file access, user changes, sudo usage, SELinux events, and more.
//!
//! Requires `auditd` to be installed and running.

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tracing::warn;

use crate::logs::Collector;
use crate::logs::linux::tailer::tail_log;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

const AUDIT_LOG_PATH: &str = "/var/log/audit/audit.log";

pub struct LinuxAuditdCollector;

#[async_trait]
impl Collector for LinuxAuditdCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();

        if !std::path::Path::new(AUDIT_LOG_PATH).exists() {
            warn!(
                "Audit log not found at '{}' — is auditd installed?",
                AUDIT_LOG_PATH
            );
        }

        tail_log(AUDIT_LOG_PATH, SourceType::LinuxAuditd, sender, hostname).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create() {
        let _ = LinuxAuditdCollector;
    }
}
