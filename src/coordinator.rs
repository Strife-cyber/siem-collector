//! Central coordinator — orchestrates all platform-specific collectors
//! and writes every collected record into a single WAL file on disk.
//!
//! # Architecture
//!
//! ```text
//!                        ┌─────────────────────┐
//!                        │  Central Coordinator │
//!                        │  (owns WAL + channel)│
//!                        └──┬──────┬──────┬─────┘
//!                    clone  │      │      │  clone
//!                      ┌────┘  ┌───┘  ┌──┘
//!                      ▼       ▼      ▼
//!               ┌──────────┐ ┌────┐ ┌────┐
//!               │ Windows  │ │Linux│ │... │   ← platform coordinators
//!               │Coordinator│ │  †  │ │ †  │
//!               └──────────┘ └────┘ └────┘
//! ```
//!
//! † Not yet implemented — the central coordinator is ready to accept them.
//!
//! Each platform coordinator receives a `Sender<CollectorLogRecord>`, spawns
//! its own collectors, and pushes records into the shared channel.  The
//! central coordinator drains that channel and persists via `storage::write_record`.

use std::path::PathBuf;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::types::CollectorLogRecord;

/// How many events can be buffered in-memory before blocking collectors.
const CHANNEL_BUFFER: usize = 4096;

/// Central coordinator that owns the WAL file and runs all platform coordinators.
pub struct Coordinator {
    wal_dir: PathBuf,
}

impl Coordinator {
    /// Create a new coordinator.
    ///
    /// The WAL file will be placed inside the platform-specific local data
    /// directory provided by the `directories` crate.
    pub fn new() -> Result<Self> {
        let project_dirs = directories::ProjectDirs::from("", "", "siem-collector")
            .ok_or_else(|| anyhow::anyhow!("failed to determine data directory"))?;
        Ok(Self {
            wal_dir: project_dirs.data_local_dir().to_path_buf(),
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
            .append(true)
            .read(true)
            .open(&wal_path)
            .await?;

        // ── 2. Shared channel ─────────────────────────────────────────
        let (tx, mut rx) = mpsc::channel::<CollectorLogRecord>(CHANNEL_BUFFER);

        // ── 3. Spawn platform coordinators ────────────────────────────
        let mut platform_handles = Vec::new();

        // ── Windows ─────────────────────────────────────────────────────
        #[cfg(target_os = "windows")]
        {
            let win_tx = tx.clone();
            platform_handles.push(tokio::spawn(async move {
                if let Err(e) =
                    crate::logs::windows::coordinator::WindowsCoordinator::run(win_tx).await
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

        // Future platform coordinators go here:
        //   - Firewall coordinator → tx.clone()
        //   - Web server coordinator → tx.clone()
        //   - Cisco / network device coordinator → tx.clone()
        //   - etc.

        // Drop the original sender so the channel closes once **every**
        // platform coordinator has dropped its own clone.
        drop(tx);

        // ── 4. Write loop ─────────────────────────────────────────────
        info!(
            "Pipeline running — {} platform task(s) active, writing records to WAL",
            platform_handles.len()
        );

        tokio::select! {
            biased;  // prefer draining events over handling Ctrl+C

            result = async {
                while let Some(record) = rx.recv().await {
                    if let Err(e) = crate::storage::write_record(&mut file, &record).await {
                        error!("Failed to write record to WAL: {:#}", e);
                    }
                }
                Ok::<_, anyhow::Error>(())
            } => {
                result?;
            }

            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl+C, initiating graceful shutdown…");
                // The rx goes out of scope → dropped → all senders detect
                // is_closed() → collectors stop → platform coordinators return.
            }
        }

        // ── 5. Wait for platform coordinators ─────────────────────────
        info!("Waiting for platform coordinator tasks to finish…");
        for handle in platform_handles {
            if let Err(e) = handle.await {
                error!("Platform coordinator task failed to join: {}", e);
            }
        }

        info!("Coordinator shut down cleanly");
        Ok(())
    }
}
