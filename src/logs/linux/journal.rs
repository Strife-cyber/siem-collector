//! Systemd journal collector.
//!
//! Spawns `journalctl -f --output=json` and streams new journal entries.
//! This is the Linux equivalent of subscribing to Windows Event Logs —
//! it captures service starts/stops, kernel messages, application logs,
//! and (optionally) authentication events.
//!
//! Requires `systemd` (journald) to be the init system.
//!
//! For a native C binding, `sd_journal_open` / `sd_journal_next` from
//! `libsystemd` can be used instead of shelling out to `journalctl`.

use async_trait::async_trait;
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;
use tokio::sync::mpsc::Sender;
use tracing::{error, trace};

use crate::logs::Collector;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

/// The journalctl command and arguments.
const JOURNALCTL: &str = "journalctl";
const JOURNALCTL_ARGS: &[&str] = &["-f", "--output=json", "--no-pager"];

pub struct LinuxJournalCollector;

#[async_trait]
impl Collector for LinuxJournalCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();

        trace!("Spawning '{} {:?}'", JOURNALCTL, JOURNALCTL_ARGS);

        let mut child = Command::new(JOURNALCTL)
            .args(JOURNALCTL_ARGS)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn journalctl: {}", e))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("No stdout from journalctl"))?;

        let reader = tokio::io::BufReader::new(stdout);
        let mut lines = reader.lines();

        loop {
            // Check for shutdown.
            if sender.is_closed() {
                let _ = child.kill().await;
                return Ok(());
            }

            tokio::select! {
                line = lines.next_line() => {
                    match line {
                        Ok(Some(text)) => {
                            let record = CollectorLogRecord::new(
                                SourceType::LinuxSystemdJournal,
                                hostname.clone(),
                                text.into_bytes(),
                            );
                            if sender.send(record).await.is_err() {
                                let _ = child.kill().await;
                                return Ok(());
                            }
                        }
                        Ok(None) => {
                            trace!("journalctl stream ended");
                            break;
                        }
                        Err(e) => {
                            error!("Error reading journalctl output: {}", e);
                            break;
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    let _ = child.kill().await;
                    return Ok(());
                }
            }
        }

        // Wait for the child to exit and capture any stderr.
        let status = child.wait().await?;
        if !status.success() {
            anyhow::bail!("journalctl exited with: {}", status);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create() {
        let _ = LinuxJournalCollector;
    }
}
