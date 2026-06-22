//! Read and display records from the WAL file.
//!
//! Usage:
//!   cargo run --bin wal_dump                        # default path
//!   cargo run --bin wal_dump -- <PATH>              # custom path
//!   cargo run --bin wal_dump -- <PATH> <COUNT>      # first N records
//!
//! The default WAL path matches what `coordinator::Coordinator` uses.

use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let (path, max_count) = match args.len() {
        1 => {
            let dirs = directories::ProjectDirs::from("", "", "siem-collector")
                .ok_or_else(|| anyhow::anyhow!("failed to determine data directory"))?;
            (dirs.data_local_dir().join("collector_log.bin"), usize::MAX)
        }
        2 => (PathBuf::from(&args[1]), usize::MAX),
        3 => {
            let count: usize = args[2]
                .parse()
                .map_err(|_| anyhow::anyhow!("COUNT must be a number"))?;
            (PathBuf::from(&args[1]), count)
        }
        _ => {
            eprintln!("Usage: wal_dump [PATH] [COUNT]");
            std::process::exit(1);
        }
    };

    if !path.exists() {
        anyhow::bail!(
            "WAL file not found: {}\n\
             Run the collector first with:  cargo run\n\
             Then dump with:               cargo run --bin wal_dump\n\
             Or specify a custom path:     cargo run --bin wal_dump -- <PATH>",
            path.display()
        );
    }

    let file_size = std::fs::metadata(&path)?.len();
    println!("WAL file: {}  ({} bytes)", path.display(), file_size);

    if file_size == 0 {
        println!("(empty — no records collected yet)");
        return Ok(());
    }

    let mut file = tokio::fs::File::open(&path).await?;
    let mut count = 0u64;

    loop {
        match siem_collector::storage::read_next_record(&mut file).await {
            Ok(Some(record)) => {
                count += 1;
                if count > max_count as u64 {
                    break;
                }

                println!("─── Record {} ───────────────────────", count);
                println!("  collected_at: {}", record.collected_at);
                println!("  source_type:  {}", record.source_type);
                println!("  hostname:     {}", record.hostname);
                let preview = if record.raw_bytes.len() <= 200 {
                    String::from_utf8_lossy(&record.raw_bytes).to_string()
                } else {
                    format!(
                        "{}… ({} bytes total)",
                        String::from_utf8_lossy(&record.raw_bytes[..197]),
                        record.raw_bytes.len()
                    )
                };
                println!("  raw_bytes:    {}", preview);
                println!();
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("Error reading record {}: {:#}", count + 1, e);
                break;
            }
        }
    }

    println!("─── Total: {} records ────────────────", count);
    Ok(())
}
