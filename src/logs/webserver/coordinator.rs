//! Web server platform coordinator.
//!
//! Spawns Nginx, Apache, and Traefik log collectors.
//! Only collectors for services that are actually installed on the host
//! will run — the rest fail fast with a clear log message.

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::logs::Collector;
use crate::logs::webserver::{
    apache::{ApacheAccessCollector, ApacheErrorCollector},
    nginx::{NginxAccessCollector, NginxErrorCollector},
    traefik::TraefikCollector,
};
use crate::types::CollectorLogRecord;

/// Web server collectors.
const ALL_COLLECTORS: &[(&str, &str)] = &[
    (
        "NginxAccess",
        "Nginx access log (/var/log/nginx/access.log)",
    ),
    ("NginxError", "Nginx error log (/var/log/nginx/error.log)"),
    (
        "ApacheAccess",
        "Apache access log (/var/log/apache2/access.log)",
    ),
    (
        "ApacheError",
        "Apache error log (/var/log/apache2/error.log)",
    ),
    (
        "Traefik",
        "Traefik reverse-proxy logs (docker logs -f traefik)",
    ),
];

pub struct WebServerCoordinator;

impl WebServerCoordinator {
    pub async fn run(sender: mpsc::Sender<CollectorLogRecord>) -> Result<()> {
        info!("Starting {} web server collectors", ALL_COLLECTORS.len());

        let collectors: Vec<Box<dyn Collector>> = vec![
            Box::new(NginxAccessCollector),
            Box::new(NginxErrorCollector),
            Box::new(ApacheAccessCollector),
            Box::new(ApacheErrorCollector),
            Box::new(TraefikCollector::new()),
        ];

        let mut handles = Vec::new();
        for (collector, (name, _desc)) in collectors.into_iter().zip(ALL_COLLECTORS.iter()) {
            let tx = sender.clone();
            handles.push(tokio::spawn(async move {
                let mut c = collector;
                if let Err(e) = c.run(tx).await {
                    warn!("Web server collector '{}' failed: {:#}", name, e);
                } else {
                    info!("Web server collector '{}' finished", name);
                }
            }));
        }

        drop(sender);

        for handle in handles {
            let _ = handle.await;
        }

        info!("All web server collectors shut down");
        Ok(())
    }
}
