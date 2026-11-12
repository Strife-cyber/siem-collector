//! Replay a scenario file through the real normalization and ship pipeline.
//!
//! The replay subcommand reads a JSON scenario file, builds one
//! `CollectorLogRecord` per line with a controlled `collected_at` timestamp,
//! and feeds them into the same `run_shipper` path the live collector uses.
//! Nothing bypasses `normalize_record` — replayed logs are normalized by the
//! exact production code that runs on Windows/Linux event sources.
//!
//! Scenario file format (JSON):
//!
//! ```json
//! {
//!   "name": "r001-brute-force",
//!   "description": "15 failed SSH logins from 192.168.243.10",
//!   "base_time": "2026-11-12T09:00:00Z",
//!   "sources": [
//!     {
//!       "source_type": "LINUX_AUTH",
//!       "hostname": "KALI-01",
//!       "lines": [
//!         { "offset_seconds": 0, "raw": "Nov 12 09:00:01 kali sshd[1234]: Failed password for invalid user admin from 192.168.243.10 port 5555 ssh2" }
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! Usage:
//!   replay <scenario.json> [--endpoint URL] [--api-key KEY] [--batch-ms MS]
//!                            [--ship-timeout-secs N]
//!
//! `--endpoint` / `--api-key` fall back to SIEM_ENDPOINT / SIEM_API_KEY.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use siem_collector::shipper::{ShipperConfig, run_shipper};
use siem_collector::types::{CollectorLogRecord, SourceType};
use std::path::PathBuf;
use std::time::Duration as StdDuration;
use tokio::sync::mpsc;

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    #[serde(default)]
    description: String,
    base_time: String,
    #[serde(default)]
    sources: Vec<Source>,
}

#[derive(Debug, Deserialize)]
struct Source {
    source_type: String,
    hostname: String,
    lines: Vec<Line>,
}

#[derive(Debug, Deserialize)]
struct Line {
    #[serde(default)]
    offset_seconds: i64,
    raw: String,
}

/// Map a scenario `source_type` label back onto the collector enum.
/// Labels match the serde representation emitted by the normalizer.
fn source_type_from(label: &str) -> SourceType {
    match label {
        "LINUX_AUTH" => SourceType::LinuxAuth,
        "LINUX_SYSLOG" => SourceType::LinuxSyslog,
        "LINUX_KERNEL" => SourceType::LinuxKernel,
        "LINUX_AUDITD" => SourceType::LinuxAuditd,
        "LINUX_SYSTEMD_JOURNAL" => SourceType::LinuxSystemdJournal,
        "LINUX_PROCESS" => SourceType::LinuxProcess,
        "LINUX_NETWORK" => SourceType::LinuxNetwork,
        "WINDOWS_SECURITY" => SourceType::WindowsSecurity,
        "WINDOWS_SYSTEM" => SourceType::WindowsSystem,
        "WINDOWS_APPLICATION" => SourceType::WindowsApplication,
        "WINDOWS_FIM" => SourceType::WindowsFim,
        "WINDOWS_INVENTORY" => SourceType::WindowsInventory,
        "WINDOWS_NETWORK" => SourceType::WindowsNetwork,
        "WINDOWS_PROCESS" => SourceType::WindowsProcess,
        "WINDOWS_REGISTRY" => SourceType::WindowsRegistry,
        "WINDOWS_SERVICES" => SourceType::WindowsServices,
        "WINDOWS_TASKS" => SourceType::WindowsTasks,
        "FIREWALL" => SourceType::Firewall,
        "WEB_SERVER" => SourceType::WebServer,
        "NGINX_ACCESS" => SourceType::NginxAccess,
        "NGINX_ERROR" => SourceType::NginxError,
        "APACHE_ACCESS" => SourceType::ApacheAccess,
        "APACHE_ERROR" => SourceType::ApacheError,
        "TRAEFIK" => SourceType::Traefik,
        "DOCKER_CONTAINER" => SourceType::DockerContainer,
        other => SourceType::Custom(other.to_string()),
    }
}

struct Args {
    scenario: PathBuf,
    endpoint: Option<String>,
    api_key: Option<String>,
    batch_ms: u64,
    ship_timeout_secs: u64,
}

fn parse_args() -> Result<Args> {
    let mut positional: Vec<String> = Vec::new();
    let mut endpoint = None;
    let mut api_key = None;
    let mut batch_ms = 500u64;
    let mut ship_timeout_secs = 120u64;

    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--endpoint" => endpoint = Some(iter.next().context("--endpoint requires a value")?),
            "--api-key" => api_key = Some(iter.next().context("--api-key requires a value")?),
            "--batch-ms" => {
                let value = iter.next().context("--batch-ms requires a value")?;
                batch_ms = value
                    .parse::<u64>()
                    .context("--batch-ms must be an integer")?;
            }
            "--ship-timeout-secs" => {
                let value = iter
                    .next()
                    .context("--ship-timeout-secs requires a value")?;
                ship_timeout_secs = value
                    .parse::<u64>()
                    .context("--ship-timeout-secs must be an integer")?;
            }
            "--help" | "-h" => {
                println!(
                    "Usage: replay <scenario.json> [--endpoint URL] [--api-key KEY] [--batch-ms MS] [--ship-timeout-secs N]"
                );
                std::process::exit(0);
            }
            _ if arg.starts_with("--") => anyhow::bail!("unknown flag: {arg}"),
            _ => positional.push(arg),
        }
    }

    let scenario = positional
        .into_iter()
        .next()
        .map(PathBuf::from)
        .context("missing scenario file path")?;

    Ok(Args {
        scenario,
        endpoint,
        api_key,
        batch_ms,
        ship_timeout_secs,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;

    let raw = std::fs::read_to_string(&args.scenario)
        .with_context(|| format!("cannot read {}", args.scenario.display()))?;
    let scenario: Scenario = serde_json::from_str(&raw)
        .with_context(|| format!("invalid scenario JSON: {}", args.scenario.display()))?;

    let base = DateTime::parse_from_rfc3339(&scenario.base_time)
        .with_context(|| format!("invalid base_time: {}", scenario.base_time))?
        .with_timezone(&Utc);

    let endpoint = args
        .endpoint
        .or_else(|| std::env::var("SIEM_ENDPOINT").ok())
        .context("no endpoint: pass --endpoint or set SIEM_ENDPOINT")?;
    let api_key = args.api_key.or_else(|| std::env::var("SIEM_API_KEY").ok());

    let config = ShipperConfig {
        endpoint,
        api_key,
        batch_size: 100,
        batch_interval: StdDuration::from_millis(args.batch_ms.max(50)),
    };

    let (tx, rx) = mpsc::channel::<CollectorLogRecord>(1024);
    let ship_endpoint = config.endpoint.clone();
    let shipper = tokio::spawn(run_shipper(rx, config));

    let mut total = 0usize;
    for source in &scenario.sources {
        let source_type = source_type_from(&source.source_type);
        for line in &source.lines {
            let record = CollectorLogRecord {
                collected_at: base + Duration::seconds(line.offset_seconds),
                source_type: source_type.clone(),
                hostname: source.hostname.clone(),
                raw_bytes: line.raw.as_bytes().to_vec(),
            };
            tx.send(record)
                .await
                .context("shipper channel closed unexpectedly")?;
            total += 1;
        }
    }
    drop(tx);

    // The production shipper retries failed batches forever (by design, for
    // the WAL-backed live collector). Replay is a one-shot tool, so bound the
    // total ship time and fail loudly instead of hanging.
    let ship_result =
        tokio::time::timeout(StdDuration::from_secs(args.ship_timeout_secs), shipper).await;

    match ship_result {
        Ok(joined) => joined
            .context("shipper task panicked")?
            .context("shipper failed")?,
        Err(_) => {
            anyhow::bail!(
                "shipping did not complete within {}s — is the backend reachable at {}?",
                args.ship_timeout_secs,
                ship_endpoint
            );
        }
    }

    println!(
        "replayed {} line(s) from {} source(s) for scenario '{}' ({})",
        total,
        scenario.sources.len(),
        scenario.name,
        scenario.description
    );
    Ok(())
}
