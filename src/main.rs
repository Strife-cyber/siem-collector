use tracing::{error, info};

#[tokio::main]
async fn main() {
    // Initialize structured logging to stdout.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "siem_collector=info".into()),
        )
        .init();

    info!("Starting SIEM Collector");

    let coordinator = match siem_collector::coordinator::Coordinator::new() {
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
