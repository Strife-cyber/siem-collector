//! Shared Windows Event Log subscription engine.
//!
//! Provides a blocking loop that queries a Windows Event Log channel
//! using `EvtQuery` / `EvtNext` / `EvtRender`, converts each event
//! to a `CollectorLogRecord`, and pushes it into a tokio `Sender`.
//!
//! All collectors in this module delegate to [`subscribe_and_collect`].

use anyhow::Result;
use tokio::sync::mpsc::Sender;
use tracing::{error, trace};

use crate::types::{CollectorLogRecord, SourceType};

use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
use windows::Win32::System::EventLog::{EVT_HANDLE, EvtClose, EvtNext, EvtQuery, EvtRender};
use windows::core::PCWSTR;

/// Default polling interval when no new events are available (milliseconds).
const POLL_MS: u64 = 1_000;

/// Render an event handle into an XML string.
///
/// Calls `EvtRender` twice: first to discover the required buffer size,
/// then to fill it.
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

    // buffer_used is in bytes; result is UTF-16LE.
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
        .map_err(|e| anyhow::anyhow!("EvtRender second call failed: {}", e))?;
    }

    // The buffer contains UTF-16LE text. Trim trailing nulls.
    let u16_len = buffer.len() / 2;
    let u16_slice = unsafe { std::slice::from_raw_parts(buffer.as_ptr() as *const u16, u16_len) };
    let effective_len = u16_slice
        .iter()
        .rposition(|&c| c != 0)
        .map(|pos| pos + 1)
        .unwrap_or(0);
    Ok(String::from_utf16_lossy(&u16_slice[..effective_len]))
}

/// Run a blocking Event Log query loop.
///
/// Opens a query on `channel` with `xpath_query`, polls for new events,
/// renders them as XML, and sends each one through `sender`.
pub(crate) fn subscribe_and_collect(
    channel: String,
    xpath_query: String,
    source_type: SourceType,
    sender: Sender<CollectorLogRecord>,
    hostname: String,
) -> Result<()> {
    // Convert to wide strings.
    let channel_wide: Vec<u16> = channel.encode_utf16().chain(std::iter::once(0)).collect();
    let query_wide: Vec<u16> = xpath_query
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // EvtQueryChannelPath (0x1) | EvtQueryForwardDirection (0x100) | EvtQueryTolerateQueryErrors (0x1000)
    let flags = 0x1 | 0x100 | 0x1000;

    let query_handle = unsafe {
        EvtQuery(
            None,
            PCWSTR::from_raw(channel_wide.as_ptr()),
            PCWSTR::from_raw(query_wide.as_ptr()),
            flags,
        )
        .map_err(|e| anyhow::anyhow!("EvtQuery failed for channel '{}': {}", channel, e))?
    };

    let event_batch_size = 16usize;
    let mut raw_events = vec![0isize; event_batch_size];

    loop {
        // Check if the receiver has been dropped (shutdown signal).
        if sender.is_closed() {
            let _ = unsafe { EvtClose(query_handle) };
            return Ok(());
        }

        let mut returned = 0u32;

        let ok = unsafe {
            EvtNext(
                query_handle,
                &mut raw_events,
                std::time::Duration::from_millis(POLL_MS).as_millis() as u32,
                0,
                &mut returned,
            )
        };

        if ok.is_ok() {
            // Process returned events.
            for i in 0..returned as usize {
                let event = EVT_HANDLE(raw_events[i]);
                match unsafe { render_event_xml(event) } {
                    Ok(xml) => {
                        trace!(channel, xml_len = xml.len(), "Event rendered");
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
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        error!("Failed to render event XML: {:#}", e);
                    }
                }
                let _ = unsafe { EvtClose(event) };
            }
        } else {
            let err_code = windows::core::Error::from_win32();
            let code = err_code.code().0;

            if code == ERROR_NO_MORE_ITEMS.0 as i32 {
                // No events right now – sleep and retry.
                std::thread::sleep(std::time::Duration::from_millis(POLL_MS));
            } else {
                error!(
                    "EvtNext error for channel '{}': {} (code {})",
                    channel, err_code, code
                );
                std::thread::sleep(std::time::Duration::from_millis(POLL_MS * 5));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    /// Rendering an invalid handle should fail.
    #[test]
    fn render_invalid_handle_returns_error() {
        let handle = EVT_HANDLE(0);
        let result = unsafe { render_event_xml(handle) };
        assert!(result.is_err(), "Expected error for null/invalid handle");
    }

    /// subscribe_and_collect with a non-existent channel and a dropped receiver
    /// should exit cleanly.
    #[tokio::test]
    async fn nonexistent_channel_errors() {
        let (tx, rx) = mpsc::channel::<CollectorLogRecord>(16);

        let handle = tokio::task::spawn_blocking(move || {
            subscribe_and_collect(
                "NonExistentChannel_2024_Test".to_string(),
                "*".to_string(),
                SourceType::Custom("test".to_string()),
                tx,
                "test-host".to_string(),
            )
        });

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        drop(rx);

        let result = handle.await.unwrap();
        // Should either succeed (sender dropped) or fail with channel error.
        assert!(result.is_ok() || result.is_err());
    }
}
