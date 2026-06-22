//! Windows platform coordinator.
//!
//! Spawns all Windows Event Log collectors and feeds their records
//! into the shared mpsc channel owned by the central [`Coordinator`].
//!
//! [`Coordinator`]: crate::coordinator::Coordinator

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::logs::Collector;
use crate::logs::windows::{
    eventlog::WindowsEventLogCollector, fim::WindowsFimCollector,
    inventory::WindowsInventoryCollector, network::WindowsNetworkCollector,
    process::WindowsProcessCollector, registry::WindowsRegistryCollector,
    services::WindowsServicesCollector, tasks::WindowsTasksCollector,
};
use crate::types::CollectorLogRecord;

/// Descriptions of every Windows collector for startup logging.
const ALL_COLLECTORS: &[(&str, &str)] = &[
    ("Security", "Windows Security log (4624/4625, etc.)"),
    ("System", "Windows System log (service state, etc.)"),
    ("Application", "Windows Application log"),
    ("FIM", "File Integrity Monitoring (4663, etc.)"),
    ("Network", "Firewall / WFP events (5152–5159)"),
    ("Process", "Process creation/termination (4688/4689)"),
    ("Registry", "Registry modification (4657)"),
    ("Services", "Service install/state (7036/7045/4697)"),
    ("Tasks", "Scheduled task changes (4698–4702)"),
    ("Inventory", "Periodic system inventory via wmic"),
];

/// Windows platform coordinator.
///
/// Receives a sender into the central channel, creates every Windows
/// collector, spawns them as tokio tasks, and waits for completion.
pub struct WindowsCoordinator;

impl WindowsCoordinator {
    /// Run all Windows collectors, feeding records into `sender`.
    pub async fn run(sender: mpsc::Sender<CollectorLogRecord>) -> Result<()> {
        info!("Starting {} Windows collectors", ALL_COLLECTORS.len());

        let collectors: Vec<Box<dyn Collector>> = vec![
            Box::new(WindowsEventLogCollector::new("Security")),
            Box::new(WindowsEventLogCollector::new("System")),
            Box::new(WindowsEventLogCollector::new("Application")),
            Box::new(WindowsFimCollector),
            Box::new(WindowsNetworkCollector),
            Box::new(WindowsProcessCollector),
            Box::new(WindowsRegistryCollector),
            Box::new(WindowsServicesCollector),
            Box::new(WindowsTasksCollector),
            Box::new(WindowsInventoryCollector::new()),
        ];

        let mut handles = Vec::new();
        for (collector, (name, _desc)) in collectors.into_iter().zip(ALL_COLLECTORS.iter()) {
            let tx = sender.clone();
            handles.push(tokio::spawn(async move {
                let mut c = collector;
                if let Err(e) = c.run(tx).await {
                    error!("Windows collector '{}' failed: {:#}", name, e);
                } else {
                    info!("Windows collector '{}' finished", name);
                }
            }));
        }

        // Drop our sender so the channel closes when all collectors finish.
        drop(sender);

        for handle in handles {
            let _ = handle.await;
        }

        info!("All Windows collectors shut down");
        Ok(())
    }
}
