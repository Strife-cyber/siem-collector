//! Linux kernel log collector.
//!
//! Tails `/var/log/kern.log` for kernel events: module loading, driver errors,
//! USB device changes, filesystem events, and possible rootkit indicators.

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tracing::warn;

use crate::logs::Collector;
use crate::logs::linux::tailer::tail_log;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

const KERN_LOG_PATH: &str = "/var/log/kern.log";

pub struct LinuxKernelCollector;

#[async_trait]
impl Collector for LinuxKernelCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();

        if !std::path::Path::new(KERN_LOG_PATH).exists() {
            warn!("Kernel log not found at '{}'", KERN_LOG_PATH);
        }

        tail_log(KERN_LOG_PATH, SourceType::LinuxKernel, sender, hostname).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create() {
        let _ = LinuxKernelCollector;
    }
}
