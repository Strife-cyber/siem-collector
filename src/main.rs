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

    // Load shipper config from environment (optional — set SIEM_ENDPOINT).
    let shipper_config = siem_collector::shipper::ShipperConfig::from_env();
    if shipper_config.is_some() {
        info!("Shipper configured via environment variables");
    } else {
        info!("Shipper disabled — set SIEM_ENDPOINT to enable");
    }

    let coordinator = match siem_collector::coordinator::Coordinator::new(shipper_config) {
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
