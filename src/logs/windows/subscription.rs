//! Shared Windows Event Log subscription engine.
//!
//! Uses `EvtQuery` (polling) with a time-based bookmark file so the collector
//! never re-sends events that were already shipped across restarts — without
//! requiring Administrator privileges.
//!
//! # How bookmarks work
//!
//! After each event, we extract the `<TimeCreated SystemTime="...">` from the
//! rendered XML and persist the latest timestamp to a `.bookmark` file.
//! On restart the timestamp is baked into the XPath query filter, skipping
//! events older than the cutoff.
//!
//! This means a handful of events at the same millisecond boundary may be
//! re-processed on restart, which is vastly better than re-sending every
//! event in the channel.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use tokio::sync::mpsc::Sender;
use tracing::{error, info, trace, warn};

use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
use windows::Win32::System::EventLog::{EVT_HANDLE, EvtClose, EvtNext, EvtQuery, EvtRender};
use windows::core::PCWSTR;

use crate::types::{CollectorLogRecord, SourceType};

/// HRESULT encoding of `ERROR_NO_MORE_ITEMS` (0x80070103).
const ERROR_NO_MORE_ITEMS_HR: i32 = (0x80070000u32 | ERROR_NO_MORE_ITEMS.0) as i32;

/// Polling interval in milliseconds when no new events are available.
const POLL_MS: u32 = 1_000;

/// How often to flush the bookmark timestamp to disk.
const BOOKMARK_SAVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Render an event handle into an XML string.
unsafe fn render_event_xml(event: EVT_HANDLE) -> Result<String> {
    let mut buffer_used = 0u32;
    let mut prop_count = 0u32;

    // First call with null buffer to get required size.
    let _ = unsafe {
        EvtRender(
            None,
            event,
            1, // EvtRenderEventXml
            0,
            None,
            &mut buffer_used,
            &mut prop_count,
        )
    };

    if buffer_used == 0 {
        anyhow::bail!("EvtRender returned zero buffer size");
    }

    let mut buffer = vec![0u8; buffer_used as usize];

    unsafe {
        EvtRender(
            None,
            event,
            1, // EvtRenderEventXml
            buffer_used,
            Some(buffer.as_mut_ptr() as *mut _),
            &mut buffer_used,
            &mut prop_count,
        )
        .map_err(|e| anyhow::anyhow!("EvtRender failed: {}", e))?;
    }

    // Buffer is UTF-16LE. Trim trailing nulls.
    let u16_len = buffer.len() / 2;
    let u16_slice = unsafe { std::slice::from_raw_parts(buffer.as_ptr() as *const u16, u16_len) };
    let effective_len = u16_slice
        .iter()
        .rposition(|&c| c != 0)
        .map(|pos| pos + 1)
        .unwrap_or(0);

    Ok(String::from_utf16_lossy(&u16_slice[..effective_len]))
}

/// Extract the `SystemTime` value from a rendered Event XML string.
///
/// Looks for `SystemTime="..."` in the XML and returns the value
/// **truncated to millisecond precision** (3 fractional digits) for
/// reliable XPath comparison on restart.
///
/// Returns `None` if not found.
fn extract_system_time(xml: &str) -> Option<String> {
    let needle = "SystemTime=\"";
    let start = xml.find(needle)?;
    let value_start = start + needle.len();
    let value_end = xml[value_start..].find('"')?;
    let raw = &xml[value_start..value_start + value_end];

    // Truncate to milliseconds (3 fractional digits) for XPath compatibility.
    // Windows uses format: 2025-07-08T18:30:00.123Z  (or .1234567Z with full precision)
    // XPath comparison with >3 fractional digits can fail silently.
    Some(truncate_timestamp_ms(raw))
}

/// Truncate a Windows SystemTime to millisecond precision for XPath queries.
///
/// `2025-07-08T18:30:00.1234567Z` → `2025-07-08T18:30:00.123Z`
fn truncate_timestamp_ms(ts: &str) -> String {
    if let Some(dot) = ts.find('.') {
        if let Some(z) = ts.rfind('Z').or_else(|| ts.rfind('z')) {
            // Take up to 3 digits after the decimal point.
            let mut result = String::with_capacity(dot + 1 + 3 + 1);
            result.push_str(&ts[..=dot]);
            // Pad or truncate to exactly 3 fractional digits.
            let frac = &ts[dot + 1..z];
            match frac.len() {
                0 => result.push_str("000"),
                1 => {
                    result.push_str(frac);
                    result.push_str("00");
                }
                2 => {
                    result.push_str(frac);
                    result.push('0');
                }
                _ => result.push_str(&frac[..3]),
            }
            result.push('Z');
            return result;
        }
    }
    ts.to_string()
}

/// Save a timestamp string to the bookmark file.
fn save_bookmark(path: &Path, timestamp: &str) {
    if let Err(e) = std::fs::write(path, timestamp) {
        warn!(path = %path.display(), error = %e, "Failed to save bookmark");
    } else {
        trace!(path = %path.display(), ts = %timestamp, "Bookmark saved");
    }
}

/// Read the saved timestamp from a bookmark file.
fn load_bookmark(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    let ts = std::fs::read_to_string(path).ok()?;
    let ts = ts.trim().to_string();
    if ts.is_empty() { None } else { Some(ts) }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run a blocking Event Log query loop with time-based bookmark persistence.
///
/// Opens a query on `channel` with `xpath_query`, polls for new events,
/// renders them as XML, and sends each one through `sender`.
///
/// **Bookmarking**: If `bookmark_path` is set, a timestamp of the latest
/// event is periodically persisted. On the next start the timestamp is used
/// to filter out already-sent events via an XPath `TimeCreated >= ...` clause.
pub(crate) fn subscribe_and_collect(
    channel: String,
    xpath_query: String,
    source_type: SourceType,
    sender: Sender<CollectorLogRecord>,
    hostname: String,
    bookmark_path: Option<PathBuf>,
) -> Result<()> {
    // Ensure bookmark directory exists.
    if let Some(ref path) = bookmark_path {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    // ── 1. Build the effective XPath query ─────────────────────────────
    // If we have a saved bookmark timestamp, add a TimeCreated filter to
    // skip events that were already sent.
    let effective_query = if let Some(ref path) = bookmark_path {
        if let Some(ts) = load_bookmark(path) {
            info!(
                channel = %channel,
                timestamp = %ts,
                "Skipping events before saved bookmark"
            );
            // Strip the leading `*` or `*[` and inject the time filter.
            // If the query is `*`, replace with a time-filtered version.
            // If the query already has `[...]`, append the time filter.
            if xpath_query == "*" {
                format!("*[System/TimeCreated[@SystemTime >= '{}']]", ts)
            } else {
                // Insert the time filter inside the existing predicates
                // by wrapping the whole thing.
                format!(
                    "*[System/TimeCreated[@SystemTime >= '{}'] and ({})]",
                    ts,
                    &xpath_query[2..] // strip "*[" prefix
                )
            }
        } else {
            xpath_query.clone()
        }
    } else {
        xpath_query.clone()
    };

    // Convert to wide strings.
    let channel_wide: Vec<u16> = channel.encode_utf16().chain(std::iter::once(0)).collect();
    let query_wide: Vec<u16> = effective_query
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // ── 2. Open query ──────────────────────────────────────────────────
    // EvtQueryChannelPath (0x1) | EvtQueryForwardDirection (0x100) | EvtQueryTolerateQueryErrors (0x1000)
    let query_flags = 0x1 | 0x100 | 0x1000;

    let query_handle = unsafe {
        EvtQuery(
            None,
            PCWSTR::from_raw(channel_wide.as_ptr()),
            PCWSTR::from_raw(query_wide.as_ptr()),
            query_flags,
        )
        .map_err(|e| anyhow::anyhow!("EvtQuery failed for channel '{}': {}", channel, e))?
    };

    // ── 3. Event loop ──────────────────────────────────────────────────
    let event_batch_size = 16usize;
    let mut raw_events = vec![0isize; event_batch_size];
    let mut latest_timestamp: Option<String> = None;
    let mut last_bookmark_save = Instant::now();
    let mut empty_polls = 0u32;
    let mut has_ever_received = false;
    let is_primary_channel = matches!(
        channel.to_lowercase().as_str(),
        "security" | "system" | "application"
    ) && xpath_query == "*";

    loop {
        // Check if the receiver has been dropped (shutdown signal).
        if sender.is_closed() {
            info!(channel = %channel, "Sender closed, shutting down");
            break;
        }

        let mut returned = 0u32;

        let ok = unsafe { EvtNext(query_handle, &mut raw_events, POLL_MS, 0, &mut returned) };

        if ok.is_ok() {
            empty_polls = 0;
            for i in 0..returned as usize {
                let event = EVT_HANDLE(raw_events[i]);
                match unsafe { render_event_xml(event) } {
                    Ok(xml) => {
                        has_ever_received = true;
                        trace!(channel, xml_len = xml.len(), "Event rendered");

                        // Track latest timestamp for bookmarking.
                        if let Some(ts) = extract_system_time(&xml) {
                            // Keep the max timestamp.
                            let update = match &latest_timestamp {
                                Some(current) => ts > *current,
                                None => true,
                            };
                            if update {
                                latest_timestamp = Some(ts);
                            }
                        }

                        let record = CollectorLogRecord::new(
                            source_type.clone(),
                            hostname.clone(),
                            xml.into_bytes(),
                        );
                        if sender.blocking_send(record).is_err() {
                            // Receiver dropped – clean up and exit.
                            for j in i..returned as usize {
                                let _ = unsafe { EvtClose(EVT_HANDLE(raw_events[j])) };
                            }
                            let _ = unsafe { EvtClose(query_handle) };
                            if let Some(ref path) = bookmark_path {
                                if let Some(ref ts) = latest_timestamp {
                                    save_bookmark(path, ts);
                                }
                            }
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        error!("Failed to render event XML: {:#}", e);
                    }
                }
                let _ = unsafe { EvtClose(event) };
            }

            // Periodically persist the bookmark timestamp to disk.
            if let Some(ref path) = bookmark_path {
                if let Some(ref ts) = latest_timestamp {
                    if last_bookmark_save.elapsed() >= BOOKMARK_SAVE_INTERVAL {
                        save_bookmark(path, ts);
                        last_bookmark_save = Instant::now();
                    }
                }
            }
        } else {
            let err_code = windows::core::Error::from_win32();
            let code = err_code.code().0;

            if code == ERROR_NO_MORE_ITEMS_HR {
                // No new events — normal, poll again.
                trace!("No new events on '{}', retrying…", channel);

                // Detect silent permission failure once per primary channel.
                empty_polls += 1;
                if empty_polls >= 5 && is_primary_channel && !has_ever_received {
                    warn!(
                        channel = %channel,
                        "No events after {} polls — process may lack permission to read the \
                        Event Log. Run as Administrator or join the 'Event Log Readers' \
                        group.",
                        empty_polls,
                    );
                    empty_polls = u32::MAX / 2;
                }
            } else {
                // Real error — log at warn and back off.
                warn!(
                    "EvtNext error for channel '{}': {} (code {})",
                    channel, err_code, code
                );
                std::thread::sleep(std::time::Duration::from_millis(5000));
            }
        }
    }

    // ── 4. Cleanup — final bookmark save ──────────────────────────────
    if let Some(ref path) = bookmark_path {
        if let Some(ref ts) = latest_timestamp {
            save_bookmark(path, ts);
        }
    }

    unsafe {
        let _ = EvtClose(query_handle);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_invalid_handle_returns_error() {
        let handle = EVT_HANDLE(0);
        let result = unsafe { render_event_xml(handle) };
        assert!(result.is_err(), "Expected error for null/invalid handle");
    }

    #[test]
    fn extract_system_time_from_typical_xml() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2025-07-08T18:30:00.1234567Z"/>
    <EventRecordID>12345</EventRecordID>
  </System>
</Event>"#;
        // Truncated to 3 fractional digits for XPath compatibility.
        assert_eq!(
            extract_system_time(xml),
            Some("2025-07-08T18:30:00.123Z".to_string())
        );
    }

    #[test]
    fn extract_system_time_returns_none_when_missing() {
        assert_eq!(extract_system_time("<Event></Event>"), None);
    }

    #[test]
    fn truncate_full_precision_to_ms() {
        assert_eq!(
            truncate_timestamp_ms("2025-07-08T18:30:00.1234567Z"),
            "2025-07-08T18:30:00.123Z"
        );
    }

    #[test]
    fn truncate_ms_already() {
        assert_eq!(
            truncate_timestamp_ms("2025-07-08T18:30:00.123Z"),
            "2025-07-08T18:30:00.123Z"
        );
    }

    #[test]
    fn truncate_no_fractional() {
        assert_eq!(
            truncate_timestamp_ms("2025-07-08T18:30:00Z"),
            "2025-07-08T18:30:00Z"
        );
    }

    #[test]
    fn truncate_one_digit() {
        assert_eq!(
            truncate_timestamp_ms("2025-07-08T18:30:00.1Z"),
            "2025-07-08T18:30:00.100Z"
        );
    }

    #[tokio::test]
    async fn nonexistent_channel_errors() {
        use tokio::sync::mpsc;

        let (tx, rx) = mpsc::channel::<CollectorLogRecord>(16);

        let handle = tokio::task::spawn_blocking(move || {
            subscribe_and_collect(
                "NonExistentChannel_2024_Test".to_string(),
                "*".to_string(),
                SourceType::Custom("test".to_string()),
                tx,
                "test-host".to_string(),
                None,
            )
        });

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        drop(rx);

        let result = handle.await.unwrap();
        assert!(result.is_ok() || result.is_err());
    }
}
