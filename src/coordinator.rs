//! Central coordinator — orchestrates all platform-specific collectors,
//! persists every record to a WAL file, and optionally ships batches
//! to a remote SIEM endpoint.
//!
//! # Architecture
//!
//! ```text
//!                        ┌──────────────────────────┐
//!                        │    Central Coordinator    │
//!                        │  (owns WAL + channels)    │
//!                        └──┬──────┬──────┬──────┬───┘
//!                    clone  │      │      │      │
//!                      ┌────┘  ┌───┘  ┌──┘   ┌─┘
//!                      ▼       ▼      ▼       ▼
//!               ┌──────────┐ ┌────┐ ┌────┐ ┌──────────┐
//!               │ Windows  │ │Linux│ │Web  │ │  Firewall│
//!               │Coordinator│ │   † │ │Srvr │ │  Syslog │
//!               └──────────┘ └────┘ └────┘ └──────────┘
//!                      │       │      │        │
//!                      └───────┴──────┴────────┘
//!                              │
//!                     ┌────────┴────────┐
//!                     ▼                 ▼
//!              ┌────────────┐   ┌──────────────┐
//!              │ WAL writer │   │   Shipper    │
//!              │ (always on)│   │ (if endpoint)│
//!              └────────────┘   └──────────────┘
//! ```

use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use tokio::io::AsyncSeekExt;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::shipper::{ShipperConfig, run_shipper};
use crate::types::CollectorLogRecord;

/// How many events can be buffered in-memory before blocking collectors.
const CHANNEL_BUFFER: usize = 4096;

/// How many events can be buffered for the shipper before we start dropping
/// records (the WAL always captures everything regardless).
const SHIPPER_CHANNEL_BUFFER: usize = 16384;

/// Central coordinator that owns the WAL file and runs all platform coordinators.
pub struct Coordinator {
    wal_dir: PathBuf,
    shipper_config: Option<ShipperConfig>,
    wal_max_size: u64,
    security_event_ids: Option<Vec<u32>>,
}

impl Coordinator {
    /// Create a new coordinator with optional shipper config and optional
    /// WAL directory override (from `siem-collector.toml`).
    pub fn new(
        shipper_config: Option<ShipperConfig>,
        wal_dir_override: Option<PathBuf>,
        wal_max_size: u64,
        security_event_ids: Option<Vec<u32>>,
    ) -> Result<Self> {
        let wal_dir = match wal_dir_override {
            Some(d) => d,
            None => {
                let project_dirs = directories::ProjectDirs::from("", "", "siem-collector")
                    .ok_or_else(|| anyhow::anyhow!("failed to determine data directory"))?;
                project_dirs.data_local_dir().to_path_buf()
            }
        };
        Ok(Self {
            wal_dir,
            shipper_config,
            wal_max_size,
            security_event_ids,
        })
    }

    /// Run the full collection pipeline until shutdown.
    pub async fn run(&self) -> Result<()> {
        // ── 1. File setup ──────────────────────────────────────────────
        tokio::fs::create_dir_all(&self.wal_dir).await?;
        let wal_path = self.wal_dir.join("collector_log.bin");
        info!("WAL file: {}", wal_path.display());

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(&wal_path)
            .await?;
        // Seek to end for appending (not using append mode because set_len
        // fails on Windows when the file is opened with append=true).
        file.seek(std::io::SeekFrom::End(0)).await?;

        // ── 2. Shared channels ─────────────────────────────────────────
        // Main channel: platform coordinators → WAL writer + forwarder.
        let (tx, mut rx) = mpsc::channel::<CollectorLogRecord>(CHANNEL_BUFFER);
        // Shipper channel: forwarder → HTTP shipper (separate so the WAL
        // writer never blocks on a slow endpoint).
        let (shipper_tx, shipper_rx) = mpsc::channel::<CollectorLogRecord>(SHIPPER_CHANNEL_BUFFER);

        // ── 3. Spawn platform coordinators ────────────────────────────
        let mut platform_handles = Vec::new();

        // ── Windows ─────────────────────────────────────────────────────
        #[cfg(target_os = "windows")]
        {
            let win_tx = tx.clone();
            let bm_dir = self.wal_dir.join("bookmarks");
            let evt_ids = self.security_event_ids.clone();
            platform_handles.push(tokio::spawn(async move {
                if let Err(e) = crate::logs::windows::coordinator::WindowsCoordinator::run(
                    win_tx,
                    Some(bm_dir),
                    evt_ids,
                )
                .await
                {
                    error!("Windows coordinator failed: {:#}", e);
                } else {
                    info!("Windows coordinator finished");
                }
            }));
        }

        // ── Linux ───────────────────────────────────────────────────────
        #[cfg(target_os = "linux")]
        {
            let linux_tx = tx.clone();
            platform_handles.push(tokio::spawn(async move {
                if let Err(e) =
                    crate::logs::linux::coordinator::LinuxCoordinator::run(linux_tx).await
                {
                    error!("Linux coordinator failed: {:#}", e);
                } else {
                    info!("Linux coordinator finished");
                }
            }));
        }

        // ── Web servers ────────────────────────────────────────────────
        // Only run on platforms with Linux-style log paths.
        #[cfg(not(target_os = "windows"))]
        {
            let ws_tx = tx.clone();
            platform_handles.push(tokio::spawn(async move {
                if let Err(e) =
                    crate::logs::webserver::coordinator::WebServerCoordinator::run(ws_tx).await
                {
                    error!("Web server coordinator failed: {:#}", e);
                } else {
                    info!("Web server coordinator finished");
                }
            }));
        }

        // ── Firewall ───────────────────────────────────────────────────
        {
            let fw_tx = tx.clone();
            platform_handles.push(tokio::spawn(async move {
                if let Err(e) =
                    crate::logs::firewall::coordinator::FirewallCoordinator::run(fw_tx).await
                {
                    error!("Firewall coordinator failed: {:#}", e);
                } else {
                    info!("Firewall coordinator finished");
                }
            }));
        }

        // ── 4. Spawn shipper (if configured) ──────────────────────────
        let mut shipper_handle = None;
        if let Some(config) = &self.shipper_config {
            let cfg = config.clone();
            shipper_handle = Some(tokio::spawn(async move {
                if let Err(e) = run_shipper(shipper_rx, cfg).await {
                    error!("Shipper failed: {:#}", e);
                } else {
                    info!("Shipper finished");
                }
            }));
        } else {
            // No endpoint configured — drop the shipper receiver so the
            // channel doesn't stay open.
            drop(shipper_rx);
            info!("Shipper disabled (set SIEM_ENDPOINT to enable)");
        }

        // Drop the original sender so the channel closes once **every**
        // platform coordinator has dropped its own clone.
        drop(tx);

        // ── 5. Write loop (with forwarding to shipper) ─────────────────
        info!(
            "Pipeline running — {} platform task(s) active, writing records to WAL",
            platform_handles.len()
        );

        let mut last_wal_check = Instant::now();
        const WAL_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

        tokio::select! {
                biased;  // prefer draining events over handling Ctrl+C

                result = async {
                    while let Some(record) = rx.recv().await {
                        // Always persist to WAL (durable storage).
                        if let Err(e) = crate::storage::write_record(&mut file, &record).await {
                            error!("Failed to write record to WAL: {:#}", e);
                        }
                        // Check WAL size every 30 seconds (not after every write!).
                        if last_wal_check.elapsed() >= WAL_CHECK_INTERVAL {
                            last_wal_check = Instant::now();
                            if let Err(e) = crate::storage::check_truncate_wal(&mut file, self.wal_max_size).await {
                                warn!("Failed to truncate WAL: {:#}", e);
                            }
                        }
                        // Best-effort forward to shipper (drops if full).
                        if shipper_tx.try_send(record).is_err() {
                            // Shipper falling behind — records are safe in WAL.
                        }
                    }
                    Ok::<_, anyhow::Error>(())
                } => {
                result?;
            }

            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl+C, initiating graceful shutdown…");
            }
        }

        // ── 6. Wait for all tasks ──────────────────────────────────────
        info!("Waiting for collector tasks to finish…");
        for handle in platform_handles {
            if let Err(e) = handle.await {
                error!("Platform coordinator task failed to join: {}", e);
            }
        }

        if let Some(handle) = shipper_handle {
            info!("Waiting for shipper to flush…");
            // Drop the shipper sender to signal the shipper to stop.
            drop(shipper_tx);
            if let Err(e) = handle.await {
                error!("Shipper task failed to join: {}", e);
            }
        }

        info!("Coordinator shut down cleanly");
        Ok(())
    }
}
