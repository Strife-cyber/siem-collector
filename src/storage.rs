use crate::types::CollectorLogRecord;
use anyhow::Result;
use rmp_serde::{from_slice, to_vec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum allowed frame payload size (10 MB).
const MAX_FRAME_SIZE: usize = 10_000_000;

pub async fn write_record(file: &mut tokio::fs::File, record: &CollectorLogRecord) -> Result<()> {
    let payload = to_vec(record)?;

    let len = (payload.len() as u32).to_le_bytes();
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len);
    frame.extend_from_slice(&payload);
    file.write_all(&frame).await?;

    Ok(())
}

/// Truncate WAL when it exceeds `max_size_bytes`. Keeps the **newest** half.
pub async fn check_truncate_wal(file: &mut tokio::fs::File, max_size_bytes: u64) -> Result<()> {
    use tokio::io::AsyncSeekExt;

    let len = file.metadata().await?.len();
    if len <= max_size_bytes {
        return Ok(());
    }
    let target = (max_size_bytes / 2).max(4096);
    file.set_len(target).await?;
    // After truncation, seek to end so subsequent writes append correctly.
    file.seek(std::io::SeekFrom::End(0)).await?;
    tracing::info!(
        "WAL truncated from {:.1} MB to {:.1} MB",
        len as f64 / 1_048_576.0,
        target as f64 / 1_048_576.0,
    );
    Ok(())
}

pub async fn read_next_record(file: &mut tokio::fs::File) -> Result<Option<CollectorLogRecord>> {
    let mut len_buf = [0u8; 4];

    if file.read_exact(&mut len_buf).await.is_err() {
        return Ok(None);
    }

    let length = u32::from_le_bytes(len_buf) as usize;

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

    fn sample_record() -> CollectorLogRecord {
        CollectorLogRecord {
            collected_at: Utc::now(),
            source_type: SourceType::LinuxAuth,
            hostname: "test-box".to_string(),
            raw_bytes: b"May  3 12:34:56 auth failed for root".to_vec(),
        }
    }

    #[tokio::test]
    async fn write_and_read_one() {
        let mut file = temp_file().await;
        let original = sample_record();
        write_record(&mut file, &original).await.unwrap();
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
            assert_eq!(original.hostname, read_back.hostname);
            assert_eq!(original.source_type, read_back.source_type);
        }
    }

    #[tokio::test]
    async fn empty_file_yields_none() {
        let mut file = temp_file().await;
        let result = read_next_record(&mut file).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn truncated_length_header() {
        let mut file = temp_file().await;
        file.write_all(&[0x01, 0x00]).await.unwrap();
        file.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        let result = read_next_record(&mut file).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn payload_too_short() {
        let mut file = temp_file().await;
        let bogus_len = 100u32;
        let mut frame = Vec::with_capacity(4 + 10);
        frame.extend_from_slice(&bogus_len.to_le_bytes());
        frame.extend_from_slice(b"shortpayload");
        file.write_all(&frame[0..14]).await.unwrap();
        file.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        let result = read_next_record(&mut file).await.unwrap();
        assert!(result.is_none());
    }

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

    #[tokio::test]
    async fn large_record() {
        let mut file = temp_file().await;
        let data = vec![b'x'; 1_000_000];
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

    #[tokio::test]
    async fn corrupt_payload() {
        let mut file = temp_file().await;
        let garbage = b"this is not MessagePack";
        let len = garbage.len() as u32;
        let mut frame = Vec::with_capacity(4 + garbage.len());
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(garbage);
        file.write_all(&frame).await.unwrap();
        file.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        let result = read_next_record(&mut file).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn skip_corrupt_middle_record() {
        let mut file = temp_file().await;
        let good1 = sample_record();
        let good2 = CollectorLogRecord {
            raw_bytes: b"goodbye".to_vec(),
            ..sample_record()
        };
        write_record(&mut file, &good1).await.unwrap();
        let corrupt_len = 50u32;
        let mut frame = Vec::with_capacity(4 + 5);
        frame.extend_from_slice(&corrupt_len.to_le_bytes());
        frame.extend_from_slice(b"^^^^^");
        file.write_all(&frame).await.unwrap();
        write_record(&mut file, &good2).await.unwrap();
        file.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        let r1 = read_next_record(&mut file)
            .await
            .unwrap()
            .expect("first good");
        assert_eq!(r1.raw_bytes, good1.raw_bytes);
        let r_corrupt = read_next_record(&mut file).await.unwrap();
        assert!(r_corrupt.is_none(), "should skip corrupt frame");
    }

    // ------------------------------------------------------------------
    // WAL truncation tests
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn truncate_does_nothing_when_under_limit() {
        let mut file = temp_file().await;
        write_record(&mut file, &sample_record()).await.unwrap();

        // max_size_bytes larger than the file → no truncation.
        let before = file.metadata().await.unwrap().len();
        check_truncate_wal(&mut file, 1_000_000).await.unwrap();
        let after = file.metadata().await.unwrap().len();
        assert_eq!(before, after, "file should not shrink when within limit");
    }

    #[tokio::test]
    async fn truncate_shrinks_wal_when_over_limit() {
        let mut file = temp_file().await;
        let rec = sample_record();

        // Write enough records to exceed 2 KB.
        for _ in 0..200 {
            write_record(&mut file, &rec).await.unwrap();
        }

        let before = file.metadata().await.unwrap().len();
        assert!(before > 2000, "need at least 2KB of data, got {}", before);

        // Truncate with a max of 1 KB → drops oldest, keeps newest ~512 bytes.
        check_truncate_wal(&mut file, 1024).await.unwrap();
        let after = file.metadata().await.unwrap().len();
        // Minimum is 4096 bytes (4 KB).
        assert_eq!(after, 4096, "truncation floor is 4KB");
    }

    #[tokio::test]
    async fn truncate_keeps_newest_records_readable() {
        // We need the file path separately because tokio::fs::File on Windows
        // doesn't expose path(). We'll remember it from temp creation.
        let dir = std::env::temp_dir();
        let name = format!("wal_trunc_test_{}.log", uuid::Uuid::new_v4());
        let path = dir.join(&name);

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .await
            .unwrap();

        // Write 100 records with distinct labels.
        let records: Vec<CollectorLogRecord> = (0..100)
            .map(|i| CollectorLogRecord {
                collected_at: Utc::now(),
                source_type: SourceType::Custom(format!("label-{}", i)),
                hostname: "test".to_string(),
                raw_bytes: format!("event number {}", i).into_bytes(),
            })
            .collect();

        for rec in &records {
            write_record(&mut file, rec).await.unwrap();
        }

        // Sync and get size.
        let before = file.metadata().await.unwrap().len();

        // Truncate to keep roughly 20 % of the file.
        let max_size = (before / 5).max(4096);
        check_truncate_wal(&mut file, max_size).await.unwrap();

        // Re-open fresh for reading (append-mode file can't seek properly).
        drop(file);
        let mut rf = tokio::fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .await
            .unwrap();

        let mut count = 0usize;
        while let Some(rec) = read_next_record(&mut rf).await.unwrap() {
            count += 1;
            assert!(!rec.raw_bytes.is_empty(), "record should have content");
        }

        assert!(count >= 1, "at least one record should survive");
        assert!(count < 100, "fewer records than originally written");

        // Cleanup.
        let _ = tokio::fs::remove_file(&path).await;
    }
}
