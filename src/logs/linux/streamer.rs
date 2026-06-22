//! Shared process-streaming engine.
//!
//! Spawns a subprocess and streams its stdout line-by-line,
//! wrapping each line into a `CollectorLogRecord`.
//!
//! Used by the Traefik collector (`docker logs -f`), Docker collector,
//! and any other source that produces logs via a process pipe.
//!
//! If the process exits, the streamer restarts it with exponential backoff
//! (capped at 30 s) so transient failures are tolerated.

use std::time::Duration;

use anyhow::Result;
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;
use tracing::{error, info, trace, warn};

use crate::types::{CollectorLogRecord, SourceType};

/// Initial backoff after a process exits (2 seconds).
const BASE_BACKOFF: Duration = Duration::from_secs(2);
/// Maximum backoff between restart attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Stream lines from a spawned process, restarting on failure.
///
/// - `program` — the executable (e.g. `"docker"`, `"journalctl"`)
/// - `args` — arguments passed to the executable
/// - `source_type` — the `SourceType` to tag each record with
/// - `sender` — the channel to push records into
/// - `hostname` — hostname for each record
/// - `restart` — if `true`, automatically restart the process on exit
pub(crate) async fn stream_process_output(
    program: &str,
    args: &[&str],
    label: &str,
    source_type: SourceType,
    sender: Sender<CollectorLogRecord>,
    hostname: String,
    restart: bool,
) -> Result<()> {
    let mut backoff = BASE_BACKOFF;

    loop {
        if sender.is_closed() {
            return Ok(());
        }

        trace!(program, label, "Spawning process");

        let mut child = match Command::new(program)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(c) => {
                backoff = BASE_BACKOFF; // reset on successful spawn
                c
            }
            Err(e) => {
                warn!(program, label, error = %e, "Failed to spawn process");

                if !restart {
                    return Err(anyhow::anyhow!("Failed to spawn '{}': {}", program, e));
                }

                sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };

        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => {
                error!(program, label, "No stdout from process");
                return Err(anyhow::anyhow!("No stdout from '{}'", program));
            }
        };

        let reader = tokio::io::BufReader::new(stdout);
        let mut lines = reader.lines();

        loop {
            tokio::select! {
                line = lines.next_line() => {
                    match line {
                        Ok(Some(text)) => {
                            let record = CollectorLogRecord::new(
                                source_type.clone(),
                                hostname.clone(),
                                text.into_bytes(),
                            );
                            if sender.send(record).await.is_err() {
                                let _ = child.kill().await;
                                return Ok(());
                            }
                        }
                        Ok(None) => {
                            trace!(program, label, "Process stdout stream ended");
                            break;
                        }
                        Err(e) => {
                            error!(program, label, error = %e, "Error reading stdout");
                            break;
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    let _ = child.kill().await;
                    return Ok(());
                }
            }
        }

        // Process exited (or stream ended).  Wait for actual exit status.
        let status = child.wait().await?;

        if !restart {
            if status.success() {
                info!(program, label, "Process exited successfully");
            } else {
                warn!(program, label, exit_code = ?status.code(), "Process exited");
            }
            return Ok(());
        }

        // Restart with backoff.
        warn!(
            program,
            label,
            exit_code = ?status.code(),
            backoff_ms = backoff.as_millis(),
            "Process exited — restarting"
        );
        sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}
