//! Linux platform coordinator.
//!
//! Spawns all Linux log collectors and feeds their records into the
//! shared mpsc channel owned by the central [`Coordinator`].
//!
//! [`Coordinator`]: crate::coordinator::Coordinator

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::logs::Collector;
use crate::logs::linux::{
    auditd::LinuxAuditdCollector, auth::LinuxAuthCollector, journal::LinuxJournalCollector,
    kern::LinuxKernelCollector, network::LinuxNetworkCollector, process::LinuxProcessCollector,
    syslog::LinuxSyslogCollector,
};
use crate::types::CollectorLogRecord;

/// Descriptions of every Linux collector for startup logging.
const ALL_COLLECTORS: &[(&str, &str)] = &[
    (
        "Auth",
        "Authentication log (/var/log/auth.log or /var/log/secure)",
    ),
    ("Syslog", "Syslog (/var/log/syslog or /var/log/messages)"),
    ("Kernel", "Kernel log (/var/log/kern.log)"),
    ("Auditd", "Auditd log (/var/log/audit/audit.log)"),
    ("Journald", "Systemd journal via journalctl -f"),
    ("Process", "Process snapshot via /proc (every 60 s)"),
    ("Network", "Network connections via /proc/net (every 30 s)"),
];

/// Linux platform coordinator.
///
/// Receives a sender into the central channel, creates every Linux
/// collector, spawns them as tokio tasks, and waits for completion.
pub struct LinuxCoordinator;

impl LinuxCoordinator {
    /// Run all Linux collectors, feeding records into `sender`.
    pub async fn run(sender: mpsc::Sender<CollectorLogRecord>) -> Result<()> {
        info!("Starting {} Linux collectors", ALL_COLLECTORS.len());

        let collectors: Vec<Box<dyn Collector>> = vec![
            Box::new(LinuxAuthCollector),
            Box::new(LinuxSyslogCollector),
            Box::new(LinuxKernelCollector),
            Box::new(LinuxAuditdCollector),
            Box::new(LinuxJournalCollector),
            Box::new(LinuxProcessCollector::new()),
            Box::new(LinuxNetworkCollector::new()),
        ];

        let mut handles = Vec::new();
        for (collector, (name, _desc)) in collectors.into_iter().zip(ALL_COLLECTORS.iter()) {
            let tx = sender.clone();
            handles.push(tokio::spawn(async move {
                let mut c = collector;
                if let Err(e) = c.run(tx).await {
                    error!("Linux collector '{}' failed: {:#}", name, e);
                } else {
                    info!("Linux collector '{}' finished", name);
                }
            }));
        }

        drop(sender);

        for handle in handles {
            let _ = handle.await;
        }

        info!("All Linux collectors shut down");
        Ok(())
    }
}
