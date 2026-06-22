//! Nginx web server log collector.
//!
//! Tails both access and error logs:
//!   - `/var/log/nginx/access.log`
//!   - `/var/log/nginx/error.log`
//!
//! Each stream gets its own `SourceType` (`NginxAccess` / `NginxError`)
//! so the downstream parser can route them appropriately.

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::logs::Collector;
use crate::logs::linux::tailer::tail_log;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

/// Common Nginx log paths.
const NGINX_ACCESS: &str = "/var/log/nginx/access.log";
const NGINX_ERROR: &str = "/var/log/nginx/error.log";

/// Nginx access log collector (file tail).
pub struct NginxAccessCollector;

#[async_trait]
impl Collector for NginxAccessCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();
        tail_log(NGINX_ACCESS, SourceType::NginxAccess, sender, hostname).await
    }
}

/// Nginx error log collector (file tail).
pub struct NginxErrorCollector;

#[async_trait]
impl Collector for NginxErrorCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();
        tail_log(NGINX_ERROR, SourceType::NginxError, sender, hostname).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_access() {
        let _ = NginxAccessCollector;
    }

    #[test]
    fn can_create_error() {
        let _ = NginxErrorCollector;
    }
}
