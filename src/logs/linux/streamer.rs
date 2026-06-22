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

use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;
use tokio::sync::mpsc::Sender;
use tracing::{error, info, trace, warn};

use crate::types::{CollectorLogRecord, SourceType};

/// Initial backoff after a process exits (2 seconds).
const BASE_BACKOFF: Duration = Duration::from_secs(2);
/// Maximum backoff between restart attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Sleep for `duration` but return early if Ctrl+C is pressed.
/// Returns `true` if shutdown was requested.
async fn interruptible_sleep(duration: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl+C received during backoff");
            true
        }
    }
}

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
    let mut rapid_failures = 0u32;
    const MAX_RAPID_FAILURES: u32 = 5;

    loop {
        if sender.is_closed() {
            return Ok(());
        }

        trace!(program, label, "Spawning process");

        let (mut child, spawn_time) = match Command::new(program)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(c) => {
                backoff = BASE_BACKOFF; // reset on successful spawn
                (c, Instant::now())
            }
            Err(e) => {
                warn!(program, label, error = %e, "Failed to spawn process");

                if !restart {
                    return Err(anyhow::anyhow!("Failed to spawn '{}': {}", program, e));
                }

                if interruptible_sleep(backoff).await {
                    return Ok(()); // shutdown requested
                }
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

        // Detect rapid restart loops (e.g., docker not installed).
        // If the process exits within 2 seconds of spawning, count it as
        // a rapid failure.  After MAX_RAPID_FAILURES, give up.
        let uptime = spawn_time.elapsed();
        if uptime < Duration::from_secs(2) {
            rapid_failures += 1;
        } else {
            rapid_failures = 0; // ran long enough, reset counter
        }

        if rapid_failures >= MAX_RAPID_FAILURES {
            warn!(
                program,
                label,
                rapid_failures,
                "Process exits too quickly — giving up after {} rapid failures",
                MAX_RAPID_FAILURES
            );
            return Err(anyhow::anyhow!(
                "'{}' exited too quickly {} times — stopped retrying",
                program,
                MAX_RAPID_FAILURES
            ));
        }

        // Restart with backoff (interruptible by Ctrl+C).
        warn!(
            program,
            label,
            exit_code = ?status.code(),
            uptime_ms = uptime.as_millis(),
            backoff_ms = backoff.as_millis(),
            "Process exited — restarting"
        );
        if interruptible_sleep(backoff).await {
            return Ok(());
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}
