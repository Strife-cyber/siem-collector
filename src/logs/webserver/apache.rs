//! Apache HTTPD web server log collector.
//!
//! Tails both access and error logs:
//!   - `/var/log/apache2/access.log`
//!   - `/var/log/apache2/error.log`
//!
//! Each stream has its own `SourceType` for downstream routing.

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tracing::warn;

use crate::logs::linux::tailer::tail_log;
use crate::logs::Collector;
use crate::types::{CollectorLogRecord, SourceType};
use crate::utils::get_hostname;

/// Common Apache log paths.
const APACHE_ACCESS: &str = "/var/log/apache2/access.log";
const APACHE_ERROR: &str = "/var/log/apache2/error.log";

/// Fallback paths for RHEL/CentOS based systems.
const APACHE_ACCESS_RHEL: &str = "/var/log/httpd/access_log";
const APACHE_ERROR_RHEL: &str = "/var/log/httpd/error_log";

fn resolve_access_path() -> &'static str {
    if std::path::Path::new(APACHE_ACCESS).exists() {
        APACHE_ACCESS
    } else if std::path::Path::new(APACHE_ACCESS_RHEL).exists() {
        APACHE_ACCESS_RHEL
    } else {
        warn!("No Apache access log found (tried: {}, {})", APACHE_ACCESS, APACHE_ACCESS_RHEL);
        APACHE_ACCESS // will fail on open
    }
}

fn resolve_error_path() -> &'static str {
    if std::path::Path::new(APACHE_ERROR).exists() {
        APACHE_ERROR
    } else if std::path::Path::new(APACHE_ERROR_RHEL).exists() {
        APACHE_ERROR_RHEL
    } else {
        warn!("No Apache error log found (tried: {}, {})", APACHE_ERROR, APACHE_ERROR_RHEL);
        APACHE_ERROR
    }
}

/// Apache access log collector.
pub struct ApacheAccessCollector;

#[async_trait]
impl Collector for ApacheAccessCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();
        let path = resolve_access_path();
        tail_log(path, SourceType::ApacheAccess, sender, hostname).await
    }
}

/// Apache error log collector.
pub struct ApacheErrorCollector;

#[async_trait]
impl Collector for ApacheErrorCollector {
    async fn run(&mut self, sender: Sender<CollectorLogRecord>) -> anyhow::Result<()> {
        let hostname = get_hostname();
        let path = resolve_error_path();
        tail_log(path, SourceType::ApacheError, sender, hostname).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_access() {
        let _ = ApacheAccessCollector;
    }

    #[test]
    fn can_create_error() {
        let _ = ApacheErrorCollector;
    }
}
