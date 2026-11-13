//! Batched HTTP shipper with log normalization.
//!
//! Reads raw `CollectorLogRecord` values from a tokio channel, normalizes
//! them into structured `NormalizedLog` entries (matching the SIEM backend's
//! `CreateLogDto`), batches them by count or time, and POSTs the batch as
//! JSON to a configurable endpoint.
//!
//! # Configuration
//!
//! | Variable             | Default  | Description                         |
//! |----------------------|----------|-------------------------------------|
//! | `SIEM_ENDPOINT`      | *(none)* | Required — URL to POST batches to   |
//! | `SIEM_API_KEY`       | *(none)* | Bearer token                        |
//! | `SIEM_BATCH_SIZE`    | `100`    | Max records per batch               |
//! | `SIEM_BATCH_INTERVAL`| `5`      | Seconds before flushing partial     |

use std::time::Duration;

use anyhow::Result;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::flow::FlowAggregator;
use crate::normalize::normalize_record;
use crate::types::CollectorLogRecord;

#[derive(Debug, Clone)]
pub struct ShipperConfig {
    pub endpoint: String,
    pub api_key: Option<String>,
    pub batch_size: usize,
    pub batch_interval: Duration,
}

impl ShipperConfig {
    pub fn from_env() -> Option<Self> {
        let endpoint = std::env::var("SIEM_ENDPOINT").ok()?;
        if endpoint.is_empty() {
            return None;
        }

        let batch_size = std::env::var("SIEM_BATCH_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);

        let interval_secs = std::env::var("SIEM_BATCH_INTERVAL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);

        Some(Self {
            endpoint,
            api_key: std::env::var("SIEM_API_KEY").ok().filter(|k| !k.is_empty()),
            batch_size,
            batch_interval: Duration::from_secs(interval_secs),
        })
    }
}

/// Run the shipper loop — normalize, batch, and POST.
pub async fn run_shipper(
    mut rx: mpsc::Receiver<CollectorLogRecord>,
    config: ShipperConfig,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))?;

    info!(
        endpoint = %config.endpoint,
        batch_size = config.batch_size,
        interval = ?config.batch_interval,
        "Shipper started"
    );

    let mut batch: Vec<serde_json::Value> = Vec::with_capacity(config.batch_size);
    let mut flow_agg = FlowAggregator::from_env();

    loop {
        // ── Wait for at least one record ────────────────────────────
        match rx.recv().await {
            Some(record) => {
                for v in flow_agg.ingest(&record) {
                    batch.push(v);
                }
                let normalized = normalize_record(&record);
                batch.push(serde_json::to_value(&normalized)?);
            }
            None => {
                for v in flow_agg.flush_all() {
                    batch.push(v);
                }
                if !batch.is_empty() {
                    send_batch_with_retry(&client, &config, &batch).await?;
                }
                info!("Shipper channel closed, exiting");
                return Ok(());
            }
        }

        // ── Collect more until batch_size or timeout ────────────────
        let deadline = Instant::now() + config.batch_interval;

        loop {
            tokio::select! {
                biased;

                result = rx.recv() => {
                    match result {
                        Some(record) => {
                            for v in flow_agg.ingest(&record) {
                                batch.push(v);
                            }
                            let normalized = normalize_record(&record);
                            batch.push(serde_json::to_value(&normalized)?);
                            if batch.len() >= config.batch_size {
                                break;
                            }
                        }
                        None => {
                            for v in flow_agg.flush_all() {
                                batch.push(v);
                            }
                            if !batch.is_empty() {
                                send_batch_with_retry(&client, &config, &batch).await?;
                            }
                            return Ok(());
                        }
                    }
                }

                _ = tokio::time::sleep_until(deadline) => {
                    break;
                }
            }
        }

        send_batch_with_retry(&client, &config, &batch).await?;
        batch.clear();
    }
}

async fn send_batch_with_retry(
    client: &reqwest::Client,
    config: &ShipperConfig,
    batch: &[serde_json::Value],
) -> Result<()> {
    let backoff = Duration::from_secs(10);
    loop {
        match send_batch(client, config, batch).await {
            Ok(()) => {
                info!(count = batch.len(), "Batch sent successfully");
                return Ok(());
            }
            Err(e) => {
                warn!(
                    count = batch.len(),
                    error = %e,
                    "Failed to send batch — retrying in {:?}",
                    backoff
                );
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

async fn send_batch(
    client: &reqwest::Client,
    config: &ShipperConfig,
    batch: &[serde_json::Value],
) -> Result<()> {
    let body = serde_json::to_string(batch)?;

    let mut req = client
        .post(&config.endpoint)
        .header("Content-Type", "application/json");

    if let Some(key) = &config.api_key {
        req = req.header("X-API-Key", key);
    }

    let resp = req.body(body).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("HTTP {}: {}", status, text.trim());
    }

    Ok(())
}
