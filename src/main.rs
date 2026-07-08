use tracing::{error, info};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "siem_collector=info".into()),
        )
        .init();

    info!("Starting SIEM Collector");

    // Load config: drop a `siem-collector.toml` next to the .exe, or use env vars.
    let config = siem_collector::config::CollectorConfig::build();
    let shipper_config = config.shipper_config();

    if shipper_config.is_some() {
        info!("Shipper configured");
    } else {
        info!("Shipper disabled — set siem_endpoint in siem-collector.toml or SIEM_ENDPOINT env var");
    }

    let coordinator = match siem_collector::coordinator::Coordinator::new(
        shipper_config,
        config.wal_dir.clone(),
    ) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create coordinator: {:#}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = coordinator.run().await {
        error!("Coordinator exited with error: {:#}", e);
        std::process::exit(1);
    }

    info!("SIEM Collector shut down gracefully");
}
