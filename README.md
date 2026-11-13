# siem-collector

Rust edge collector for the SMART SIEM platform. It tails security-relevant
logs on Linux and Windows endpoints, normalizes them into a single schema,
and ships them in batches to the SIEM backend (`POST /api/v1/logs`).

If the backend is unreachable, records are buffered in a local write-ahead
log (WAL) and replayed on reconnect, so no telemetry is lost during network
outages.

## What it collects

| Platform | Sources |
|---|---|
| Linux | `auth.log` (SSH/sudo), syslog, kernel ring buffer, **auditd** (incl. `EXECVE` → `process_name`/`command_line`), systemd journal, process & network streams |
| Windows | Security/System/Application event logs, process creation (4688), file access (4663), registry, scheduled tasks, services, FIM, inventory |
| Web servers | nginx, Apache, Traefik access/error logs |
| Firewalls | syslog from pfSense / generic firewalls |

Normalization extracts structured fields — `source_ip`, `destination_ip`,
ports, `user_principal`, `action`, `outcome`, `process_name`,
`command_line`, `file_path`, `file_operation`, `event_taxonomy`,
`severity` — from each raw format, so the backend rules engine never has
to parse raw text.

## Repository layout

```
src/
  main.rs            entry point (tokio runtime, tracing)
  config.rs          CollectorConfig: TOML file + SIEM_* env vars
  coordinator.rs     wires collectors → normalizer → shipper, WAL lifecycle
  normalize.rs       per-source-type normalizers (the heart of the collector)
  shipper.rs         batch HTTP shipper with retry
  storage.rs         WAL (write-ahead log) buffer
  types.rs           SourceType enum, CollectorLogRecord, NormalizedLog
  logs/              per-source collectors (linux/, windows/, webserver/, firewall/)
  bin/
    replay.rs        scenario replay subcommand (see Testing)
    wal_dump.rs      inspect the WAL buffer
```

## Build

```bash
cargo build --release        # produces target/release/siem-collector
cargo build --bin replay     # also builds the replay tool
```

Requires Rust stable (see `rust-toolchain` if present). No runtime
dependencies beyond a writable `WAL_DIR` and network access to the backend.

## Configuration

Config is loaded from `siem-collector.toml` next to the binary (or
`./siem-collector.toml`), with `SIEM_*` environment variables overriding
the file values.

| Setting | Env var | Default | Purpose |
|---|---|---|---|
| `siem_endpoint` | `SIEM_ENDPOINT` | — (shipper disabled if unset) | Backend base URL, e.g. `http://siem-app:3000/api/v1` |
| `siem_api_key` | `SIEM_API_KEY` | — | Ingestion API key (`X-API-Key` header) |
| `siem_batch_size` | `SIEM_BATCH_SIZE` | 100 | Max logs per POST |
| `siem_batch_interval` | `SIEM_BATCH_INTERVAL` | 5 (seconds) | Max time between flushes |
| `wal_dir` | `WAL_DIR` | `./wal` | Offline buffer directory |
| `wal_max_size_mb` | `WAL_MAX_SIZE_MB` | 500 | WAL rotation cap |
| `security_event_ids` | `SECURITY_EVENT_IDS` | — | Optional comma-separated Windows Event IDs to subscribe |

Minimal `siem-collector.toml`:

```toml
siem_endpoint = "http://siem-app:3000/api/v1"
siem_api_key  = "siem_..."
wal_dir       = "/var/lib/siem-collector/wal"
```

Example systemd unit for a Linux endpoint:

```ini
[Unit]
Description=SMART SIEM Collector
After=network-online.target

[Service]
ExecStart=/usr/local/bin/siem-collector
Environment=SIEM_ENDPOINT=http://siem-app:3000/api/v1
Environment=SIEM_API_KEY=siem_...
Environment=WAL_DIR=/var/lib/siem-collector/wal
Restart=always
User=siem

[Install]
WantedBy=multi-user.target
```

On Windows, run the collector as a service under an account with read
access to the Security event log; enable the audit policies listed in the
[deployment guide](https://github.com/Strife-cyber/smart-siem_docs) (notably
4688 process creation with command line, and 4663 object access SACLs).

## Testing

### Unit tests

```bash
cargo test                 # all tests (normalizers, shipper, WAL)
cargo fmt --check
cargo clippy
```

The normalizer tests in `src/normalize.rs` cover every source type with
real-format raw log lines — extend them when adding a parser.

### Replay mode (end-to-end through the real pipeline)

`replay` feeds raw log lines from a JSON scenario file through the exact
production `normalize_record` + shipper path — nothing bypasses the code
that runs live. It is the same harness the backend simulation scenarios
use (`npm run simulate` in **siem-backend**).

```bash
cargo build --bin replay

./target/debug/replay scenario.json \
  --endpoint http://localhost:3000/api/v1 \
  --api-key siem_...
```

Scenario format:

```json
{
  "name": "r001-brute-force",
  "description": "15 failed SSH logins from 192.168.243.10",
  "base_time": "2026-11-12T09:00:00Z",
  "sources": [
    {
      "source_type": "LINUX_AUTH",
      "hostname": "SRV-WEB-01",
      "lines": [
        { "offset_seconds": 0, "raw": "Nov 12 09:00:01 srv sshd[1234]: Failed password for invalid user admin from 192.168.243.10 port 5555 ssh2" }
      ]
    }
  ]
}
```

Useful flags: `--batch-ms` (flush interval), `--ship-timeout-secs`
(fail loudly instead of hanging when the backend is down),
`--endpoint` / `--api-key` override config/env.

`source_type` values map to `SourceType` in `src/types.rs`
(`LINUX_AUTH`, `LINUX_AUDITD`, `WINDOWS_SECURITY`, `WINDOWS_PROCESS`,
`NGINX`, `APACHE`, `TRAEFIK`, `FIREWALL_SYSLOG`, …). auditd scenarios use
raw `type=EXECVE …` lines; the parser emits `action=PROCESS_EXEC` with
`process_name`/`command_line`.

### Inspecting the WAL

```bash
./target/debug/wal_dump --dir /var/lib/siem-collector/wal
```

## Deployment docs

For multi-machine topologies (edge collectors, app/DB nodes), collector
fleet setup, and firewall integration (pfSense syslog + REST SOAR,
Fortinet), see the deployment guide in
[smart-siem_docs](https://github.com/Strife-cyber/smart-siem_docs)
(`conception/deploiement-topologie.md`).
