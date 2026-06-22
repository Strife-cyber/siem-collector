//! RFC 5424 / RFC 3164 syslog receiver.
//!
//! Listens on a UDP port (default 514) for syslog messages from network
//! firewalls, routers, and other network appliances.  Each datagram is
//! wrapped into a `CollectorLogRecord` tagged with `SourceType::Firewall`
//! and the sender's IP address as the hostname.
//!
//! # Why UDP and not TCP
//!
//! Most network devices send syslog over UDP by default.  UDP is fire-and-forget
//! so the collector never blocks the sender.  If packet loss is a concern,
//! the central SIEM should use TCP or RELP for guaranteed delivery — but
//! for a local collector sitting on the same LAN as the firewalls, UDP is
//! the standard and works well.

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use tracing::{error, info};

use crate::types::{CollectorLogRecord, SourceType};

/// Default syslog UDP port.
const DEFAULT_SYSLOG_PORT: u16 = 514;

/// Maximum syslog datagram size (RFC 5426 recommends 2048; we use 8192
/// to handle extended messages from modern appliances).
const MAX_DATAGRAM: usize = 8192;

/// Syslog listener that collects firewall logs over UDP.
pub struct SyslogListener {
    /// UDP port to bind to (default 514 — requires admin/root).
    port: u16,
    /// Bind address.
    bind: String,
}

impl Default for SyslogListener {
    fn default() -> Self {
        Self {
            port: DEFAULT_SYSLOG_PORT,
            bind: "0.0.0.0".to_string(),
        }
    }
}

impl SyslogListener {
    /// Create a listener on the default syslog port (514).
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind to a specific port (use a high port like 1514 if 514 is unavailable).
    pub fn with_port(port: u16) -> Self {
        Self {
            port,
            bind: "0.0.0.0".to_string(),
        }
    }

    /// Bind to a specific address and port.
    pub fn with_addr(bind: impl Into<String>, port: u16) -> Self {
        Self {
            port,
            bind: bind.into(),
        }
    }

    /// Run the syslog listener, forwarding every datagram through `sender`.
    pub async fn run(&self, sender: Sender<CollectorLogRecord>) -> Result<()> {
        let addr = format!("{}:{}", self.bind, self.port);

        let socket = UdpSocket::bind(&addr).await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to bind UDP syslog listener on {}: {}\n\
                 Try a high port with `SyslogListener::with_port(1514)` \
                 or run as admin for port 514.",
                addr,
                e
            )
        })?;

        info!("Syslog listener started on UDP {} (firewall logs)", addr);

        let mut buf = vec![0u8; MAX_DATAGRAM];

        loop {
            if sender.is_closed() {
                info!("Syslog listener shutting down (receiver dropped)");
                return Ok(());
            }

            match socket.recv_from(&mut buf).await {
                Ok((n, src_addr)) => {
                    let raw = buf[..n].to_vec();

                    // Use the sender's IP as the hostname so the SIEM
                    // knows which firewall sent the message.
                    let source_host = src_addr.ip().to_string();

                    let record = CollectorLogRecord::new(SourceType::Firewall, source_host, raw);

                    if sender.send(record).await.is_err() {
                        info!("Syslog listener: receiver dropped, exiting");
                        return Ok(());
                    }
                }
                Err(e) => {
                    error!("Syslog listener recv error: {}", e);
                    // Brief backoff so we don't busy-loop on persistent errors.
                    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_port_514() {
        let l = SyslogListener::new();
        assert_eq!(l.port, 514);
    }

    #[test]
    fn custom_port() {
        let l = SyslogListener::with_port(1514);
        assert_eq!(l.port, 1514);
    }

    #[test]
    fn custom_addr() {
        let l = SyslogListener::with_addr("127.0.0.1", 1514);
        assert_eq!(l.port, 1514);
        assert_eq!(l.bind, "127.0.0.1");
    }
}
