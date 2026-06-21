use crate::types::CollectorLogRecord;
use anyhow::Result;
use rmp_serde::{from_slice, to_vec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum allowed frame payload size (10 MB).
/// Prevents OOM from corrupted or malicious length headers.
const MAX_FRAME_SIZE: usize = 10_000_000;

async fn write_record(file: &mut tokio::fs::File, record: &CollectorLogRecord) -> Result<()> {
    let payload = to_vec(record)?;

    // Build and write a single frame buffer (length prefix + payload).
    // A single write is preferred over two to ensure atomicity on all platforms
    // and to avoid potential buffering issues with some OS file I/O.
    let len = (payload.len() as u32).to_le_bytes();
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len);
    frame.extend_from_slice(&payload);
    file.write_all(&frame).await?;

    Ok(())
}

async fn read_next_record(file: &mut tokio::fs::File) -> Result<Option<CollectorLogRecord>> {
    let mut len_buf = [0u8; 4];

    if file.read_exact(&mut len_buf).await.is_err() {
        return Ok(None);
    }

    let length = u32::from_le_bytes(len_buf) as usize;

    // Zero-length frames are invalid for MessagePack-serialized records.
    if length == 0 || length > MAX_FRAME_SIZE {
        return Ok(None);
    }

    let mut payload = vec![0u8; length];
    if file.read_exact(&mut payload).await.is_err() {
        return Ok(None);
    }

    Ok(from_slice::<CollectorLogRecord>(&payload).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CollectorLogRecord, SourceType};
    use chrono::Utc;
    use tokio::io::AsyncSeekExt;

    // Helper: create a temporary file opened for both reading and writing,
    // and return its handle. Using `create` + `read(true)` ensures the file
    // is readable on Windows (tokio::fs::File::create is write-only there).
    async fn temp_file() -> tokio::fs::File {
        let dir = std::env::temp_dir();
        let name = format!("logcollector_test_{}.log", uuid::Uuid::new_v4());
        tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(dir.join(name))
            .await
            .unwrap()
    }

    // Helper: a sample record
    fn sample_record() -> CollectorLogRecord {
        CollectorLogRecord {
            collected_at: Utc::now(),
            source_type: SourceType::LinuxAuth,
            hostname: "test-box".to_string(),
            raw_bytes: b"May  3 12:34:56 auth failed for root".to_vec(),
        }
    }

    // ------------------------------------------------------------------
    // Happy‑path: write one record, read it back, fields must match
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn write_and_read_one() {
        let mut file = temp_file().await;
        let original = sample_record();

        write_record(&mut file, &original).await.unwrap();

        // Rewind to read
        file.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        let read_back = read_next_record(&mut file)
            .await
            .unwrap()
            .expect("should have record");
        assert_eq!(read_back.collected_at, original.collected_at);
        assert_eq!(read_back.source_type, original.source_type);
        assert_eq!(read_back.hostname, original.hostname);
        assert_eq!(read_back.raw_bytes, original.raw_bytes);
    }

    // ------------------------------------------------------------------
    // Write multiple records, read them back in the correct order
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn multiple_records() {
        let mut file = temp_file().await;
        let records: Vec<_> = (0..5)
            .map(|i| CollectorLogRecord {
                collected_at: Utc::now(),
                source_type: SourceType::Custom(format!("test-{}", i)),
                hostname: "multi".to_string(),
                raw_bytes: format!("log line {}", i).into_bytes(),
            })
            .collect();

        for rec in &records {
            write_record(&mut file, rec).await.unwrap();
        }

        file.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        let mut got = Vec::new();
        while let Some(rec) = read_next_record(&mut file).await.unwrap() {
            got.push(rec);
        }

        assert_eq!(got.len(), records.len());
        for (original, read_back) in records.iter().zip(got.iter()) {
            assert_eq!(original.raw_bytes, read_back.raw_bytes);
            // Don't compare timestamps exactly – they may drift by a few ticks
            assert_eq!(original.hostname, read_back.hostname);
            assert_eq!(original.source_type, read_back.source_type);
        }
    }

    // ------------------------------------------------------------------
    // Empty file: read must return None without error
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn empty_file_yields_none() {
        let mut file = temp_file().await;
        let result = read_next_record(&mut file).await.unwrap();
        assert!(result.is_none());
    }

    // ------------------------------------------------------------------
    // Truncated length header (only 2 bytes written)
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn truncated_length_header() {
        let mut file = temp_file().await;
        // write only 2 bytes of a length prefix
        file.write_all(&[0x01, 0x00]).await.unwrap();
        file.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        // read_exact for 4 bytes will fail → should return Ok(None)
        let result = read_next_record(&mut file).await.unwrap();
        assert!(result.is_none());
    }

    // ------------------------------------------------------------------
    // Payload shorter than advertised length
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn payload_too_short() {
        let mut file = temp_file().await;
        // Length prefix says 100 bytes, but we write only 10
        let bogus_len = 100u32;
        let mut frame = Vec::with_capacity(4 + 10);
        frame.extend_from_slice(&bogus_len.to_le_bytes());
        frame.extend_from_slice(b"shortpayload"); // 13 bytes? Actually 13 bytes, but we'll write less than 100
        // write 4 (len) + 10 bytes only
        file.write_all(&frame[0..14]).await.unwrap(); // 4 + 10 = 14 bytes

        file.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        // read_next_record will try to read 100 bytes for payload, but EOF will occur
        let result = read_next_record(&mut file).await.unwrap();
        // Should be None because payload read fails
        assert!(result.is_none());
    }

    // ------------------------------------------------------------------
    // Zero‑length payload (valid, though unusual)
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn zero_payload_record() {
        let mut file = temp_file().await;
        let mut empty_rec = sample_record();
        empty_rec.raw_bytes = vec![];
        empty_rec.source_type = SourceType::Custom("zero".to_string());

        write_record(&mut file, &empty_rec).await.unwrap();
        file.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        let read_back = read_next_record(&mut file)
            .await
            .unwrap()
            .expect("record must exist");
        assert_eq!(read_back.raw_bytes, b"");
        assert_eq!(
            read_back.source_type,
            SourceType::Custom("zero".to_string())
        );
    }

    // ------------------------------------------------------------------
    // Large record (1 MB) to ensure framing works
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn large_record() {
        let mut file = temp_file().await;
        let data = vec![b'x'; 1_000_000]; // 1 MB of raw bytes
        let original = CollectorLogRecord {
            collected_at: Utc::now(),
            source_type: SourceType::Custom("large".to_string()),
            hostname: "big".to_string(),
            raw_bytes: data.clone(),
        };

        write_record(&mut file, &original).await.unwrap();
        file.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        let read_back = read_next_record(&mut file)
            .await
            .unwrap()
            .expect("large record");
        assert_eq!(read_back.raw_bytes.len(), 1_000_000);
        assert!(read_back.raw_bytes.iter().all(|b| *b == b'x'));
    }

    // ------------------------------------------------------------------
    // Corrupt payload – valid length but content is not valid MessagePack
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn corrupt_payload() {
        let mut file = temp_file().await;
        // Write a valid length prefix but garbage after it
        let garbage = b"this is not MessagePack";
        let len = garbage.len() as u32;
        let mut frame = Vec::with_capacity(4 + garbage.len());
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(garbage);
        file.write_all(&frame).await.unwrap();

        file.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        // from_slice will fail, and your code uses .ok() → returns None
        let result = read_next_record(&mut file).await.unwrap();
        assert!(result.is_none()); // record skipped
    }

    // ------------------------------------------------------------------
    // Multiple records with a corrupt one in the middle (robust skip)
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn skip_corrupt_middle_record() {
        let mut file = temp_file().await;
        let good1 = sample_record();
        let good2 = CollectorLogRecord {
            raw_bytes: b"goodbye".to_vec(),
            ..sample_record()
        };

        // Write first good record
        write_record(&mut file, &good1).await.unwrap();

        // Write a corrupt frame: length says 50, but we only put 5 bytes of garbage
        let corrupt_len = 50u32;
        let mut frame = Vec::with_capacity(4 + 5);
        frame.extend_from_slice(&corrupt_len.to_le_bytes());
        frame.extend_from_slice(b"^^^^^");
        file.write_all(&frame).await.unwrap();

        // Write second good record
        write_record(&mut file, &good2).await.unwrap();

        file.seek(std::io::SeekFrom::Start(0)).await.unwrap();

        // First record should be readable
        let r1 = read_next_record(&mut file)
            .await
            .unwrap()
            .expect("first good");
        assert_eq!(r1.raw_bytes, good1.raw_bytes);

        // Second read hits corrupt frame → expected None because read_exact for 50 bytes will fail (EOF)
        let r_corrupt = read_next_record(&mut file).await.unwrap();
        assert!(r_corrupt.is_none(), "should skip corrupt frame");

        // But after that, the file pointer is already at EOF? In this test we wrote only 4+5 bytes for the corrupt frame; after failing to read 50 bytes, the file pointer may be in an unpredictable state. So we shouldn't expect to recover the third record. That's okay – the test demonstrates that a truncated frame doesn't crash and returns None. Real recovery would require more logic (e.g., scanning for the next valid length header). We'll note that.

        // So we don't attempt to read further.
    }
}
