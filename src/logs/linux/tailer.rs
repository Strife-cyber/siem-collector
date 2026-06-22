//! Shared log-file tailing engine.
//!
//! Polls a log file for new lines using a simple seek-to-end + read loop.
//! This is the Linux equivalent of `subscription.rs` for Windows Event Logs.
//!
//! For production use, consider replacing this with `inotify`-based watching
//! to eliminate the polling overhead.

use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncSeekExt;
use tokio::sync::mpsc::Sender;
use tokio::time::{Duration, sleep};
use tracing::{error, trace};

use crate::types::{CollectorLogRecord, SourceType};

/// Polling interval when no new data is available.
const POLL_MS: u64 = 500;

/// Buffer size for reading new log data.
const READ_BUF_SIZE: usize = 65536;

/// Tail a log file and send new lines through `sender`.
///
/// Opens `path`, seeks to the end (to skip historical lines), then polls
/// for new content.  Each complete line is sent as a `CollectorLogRecord`.
///
/// Lines that straddle two reads are reassembled transparently.
pub(crate) async fn tail_log(
    path: &str,
    source_type: SourceType,
    sender: Sender<CollectorLogRecord>,
    hostname: String,
) -> Result<()> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to open '{}': {}", path, e))?;

    // Seek to end so we only capture new lines.
    file.seek(std::io::SeekFrom::End(0))
        .await
        .map_err(|e| anyhow::anyhow!("failed to seek '{}': {}", path, e))?;

    trace!("Tailing '{}' from position end", path);

    let mut buf = vec![0u8; READ_BUF_SIZE];
    let mut partial = Vec::new(); // holds an incomplete line from the previous read

    loop {
        // Check if the receiver has been dropped.
        if sender.is_closed() {
            trace!("Receiver closed, stopping tail of '{}'", path);
            return Ok(());
        }

        match file.read(&mut buf).await {
            Ok(0) => {
                // No new data – wait and retry.
                sleep(Duration::from_millis(POLL_MS)).await;
                continue;
            }
            Ok(n) => {
                let data = &buf[..n];

                // Process complete lines, preserving any trailing partial line.
                let mut start = 0usize;
                for (i, &b) in data.iter().enumerate() {
                    if b == b'\n' {
                        let line = &data[start..=i];
                        // Prepend any partial from the previous read.
                        if partial.is_empty() {
                            send_line(&sender, &source_type, &hostname, line).await?;
                        } else {
                            partial.extend_from_slice(line);
                            send_line(&sender, &source_type, &hostname, &partial).await?;
                            partial.clear();
                        }
                        start = i + 1;
                    }
                }

                // Any leftover bytes form a partial line for the next read.
                if start < n {
                    if partial.is_empty() {
                        partial.extend_from_slice(&data[start..]);
                    } else {
                        partial.extend_from_slice(&data[start..]);
                    }
                }
            }
            Err(e) => {
                error!("Error reading '{}': {}", path, e);
                sleep(Duration::from_millis(POLL_MS * 10)).await;
            }
        }
    }
}

/// Send a single line as a `CollectorLogRecord`.
async fn send_line(
    sender: &Sender<CollectorLogRecord>,
    source_type: &SourceType,
    hostname: &str,
    line: &[u8],
) -> Result<()> {
    // Skip empty lines (just a newline character).
    if line.is_empty() || (line.len() == 1 && line[0] == b'\n') {
        return Ok(());
    }

    let record = CollectorLogRecord::new(source_type.clone(), hostname.to_string(), line.to_vec());
    sender
        .send(record)
        .await
        .map_err(|_| anyhow::anyhow!("receiver dropped"))?;
    Ok(())
}

/// Collect a one-shot snapshot of a file and send each line.
///
/// Unlike `tail_log`, this reads the entire file from the beginning.
/// Used for `/proc`-based collectors that want a point-in-time snapshot.
pub(crate) async fn read_file_lines(
    path: &str,
    source_type: SourceType,
    sender: &Sender<CollectorLogRecord>,
    hostname: &str,
) -> Result<()> {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(c) => c,
        Err(e) => {
            trace!("Could not read '{}': {}", path, e);
            return Ok(());
        }
    };

    for line in content.lines() {
        let line_bytes = format!("{}\n", line).into_bytes();
        if sender
            .send(CollectorLogRecord::new(
                source_type.clone(),
                hostname.to_string(),
                line_bytes,
            ))
            .await
            .is_err()
        {
            return Ok(());
        }
    }
    Ok(())
}
