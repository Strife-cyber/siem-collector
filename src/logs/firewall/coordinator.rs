//! Firewall log coordinator.
//!
//! Starts a UDP syslog listener that collects logs from network firewalls,
//! routers, and other network appliances that support RFC 3164 / RFC 5424
//! syslog.
//!
//! # Supported devices (via syslog)
//!
//! | Device       | Protocol | Default Port |
//! |-------------|----------|-------------|
//! | pfSense     | UDP      | 514         |
//! | Cisco ASA   | UDP/TCP  | 514         |
//! | Fortinet    | UDP      | 514         |
//! | Palo Alto   | UDP      | 514         |
//! | Sophos      | UDP      | 514         |
//! | iptables    | UDP      | 514         |
//! | UFW         | UDP      | 514         |
//! | Linux kernel| syslog   | 514         |
//!
//! All produce `CollectorLogRecord` with `SourceType::Firewall` and the
//! sender's IP as the hostname.

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::logs::firewall::syslog::SyslogListener;
use crate::types::CollectorLogRecord;

/// Descriptions for startup logging.
const ALL_LISTENERS: &[(&str, &str)] = &[(
    "SyslogUDP",
    "UDP syslog listener on port 514 (firewall logs)",
)];

pub struct FirewallCoordinator;

impl FirewallCoordinator {
    pub async fn run(sender: mpsc::Sender<CollectorLogRecord>) -> Result<()> {
        info!("Starting {} firewall listener(s)", ALL_LISTENERS.len());

        let mut handles = Vec::new();

        // UDP syslog listener on port 514.
        let tx = sender.clone();
        handles.push(tokio::spawn(async move {
            let listener = SyslogListener::new();
            if let Err(e) = listener.run(tx).await {
                error!("Syslog listener failed: {:#}", e);
            } else {
                info!("Syslog listener finished");
            }
        }));

        drop(sender);

        for handle in handles {
            let _ = handle.await;
        }

        info!("All firewall collectors shut down");
        Ok(())
    }
}
