//! pfSense filterlog flow-byte aggregation.
//!
//! pfSense `filterlog` CSV lines carry a per-packet `Data Length` field.
//! This module aggregates those payload bytes per flow tuple
//! (src/dst/proto/ports) over a sliding window and emits synthetic
//! `FLOW_BYTES` summary documents. The backend uses them for exfiltration
//! corroboration (R003 / C004 / C005 / C009).
//!
//! Scope (v1): IPv4 TCP/UDP `pass` entries only. Bytes are IP-payload bytes
//! on logged rules — an estimate, not exact wire counters. Exact per-flow
//! counters (pfctl/conntrack, option B) are documented as the upgrade path.
//!
//! Configuration:
//! | Variable                  | Default | Description                        |
//! |---------------------------|---------|------------------------------------|
//! | `FLOW_AGGREGATION_ENABLED`| `true`  | Set `false` to disable              |
//! | `FLOW_WINDOW_SECS`        | `60`    | Aggregation window                  |
//! | `FLOW_MIN_BYTES`          | `65536` | Min bytes before a summary is kept  |

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::types::{CollectorLogRecord, SourceType};

const FLOW_ACTION: &str = "FLOW_BYTES";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    host: String,
    src: String,
    dst: String,
    sport: u16,
    dport: u16,
    proto: String,
}

struct FlowState {
    hostname: String,
    source_type: String,
    direction: String,
    iface: String,
    rule: String,
    bytes: u64,
    packets: u64,
    started: DateTime<Utc>,
    collected_at: String,
}

pub struct FlowAggregator {
    enabled: bool,
    window: Duration,
    min_bytes: u64,
    flows: HashMap<FlowKey, FlowState>,
    last_sweep: DateTime<Utc>,
}

impl FlowAggregator {
    pub fn from_env() -> Self {
        let enabled = std::env::var("FLOW_AGGREGATION_ENABLED")
            .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "false" | "0" | "off"))
            .unwrap_or(true);
        let window_secs = std::env::var("FLOW_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60u64);
        let min_bytes = std::env::var("FLOW_MIN_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(65536u64);
        Self {
            enabled,
            window: Duration::from_secs(window_secs.max(1)),
            min_bytes,
            flows: HashMap::new(),
            last_sweep: Utc::now(),
        }
    }

    /// Feed one collector record; returns any expired flow summaries.
    pub fn ingest(&mut self, record: &CollectorLogRecord) -> Vec<serde_json::Value> {
        let now = Utc::now();
        let mut out = Vec::new();
        if self.enabled {
            self.sweep(now, &mut out);
        }
        if !self.enabled || record.source_type != SourceType::Firewall {
            return out;
        }
        let raw = String::from_utf8_lossy(&record.raw_bytes);
        let Some(pkt) = parse_filterlog_flow(&raw) else {
            return out;
        };

        let key = FlowKey {
            host: record.hostname.clone(),
            src: pkt.src,
            dst: pkt.dst,
            sport: pkt.sport,
            dport: pkt.dport,
            proto: pkt.proto,
        };
        let collected_at = record.collected_at.to_rfc3339();
        let entry = self.flows.entry(key.clone()).or_insert_with(|| FlowState {
            hostname: record.hostname.clone(),
            source_type: record.source_type.as_str().to_string(),
            direction: pkt.direction.clone(),
            iface: pkt.iface.clone(),
            rule: pkt.rule.clone(),
            bytes: 0,
            packets: 0,
            started: now,
            collected_at: collected_at.clone(),
        });
        entry.bytes += pkt.data_len;
        entry.packets += 1;
        entry.collected_at = collected_at;

        // Flush this flow early if it crosses the byte threshold and its
        // window has elapsed since the first packet of the window.
        if entry.bytes >= self.min_bytes
            && now
                .signed_duration_since(entry.started)
                .to_std()
                .unwrap_or_default()
                >= self.window
        {
            out.push(self.take(&key, now));
        }
        out
    }

    /// Flush every accumulated flow (channel close / shutdown).
    pub fn flush_all(&mut self) -> Vec<serde_json::Value> {
        let now = Utc::now();
        let keys: Vec<FlowKey> = self
            .flows
            .keys()
            .filter(|k| {
                self.flows
                    .get(*k)
                    .map(|s| s.bytes >= self.min_bytes)
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        let mut out = Vec::new();
        for k in keys {
            out.push(self.take(&k, now));
        }
        out
    }

    fn sweep(&mut self, now: DateTime<Utc>, out: &mut Vec<serde_json::Value>) {
        if now
            .signed_duration_since(self.last_sweep)
            .to_std()
            .unwrap_or_default()
            < Duration::from_secs(1)
        {
            return;
        }
        self.last_sweep = now;
        let window = self.window;
        let min_bytes = self.min_bytes;
        let expired: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, s)| {
                now.signed_duration_since(s.started)
                    .to_std()
                    .unwrap_or_default()
                    >= window
            })
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            // Drop expired windows below the byte threshold instead of
            // retaining them (memory bound) — bytes never carry across windows.
            if self
                .flows
                .get(&k)
                .map(|s| s.bytes >= min_bytes)
                .unwrap_or(false)
            {
                out.push(self.take(&k, now));
            } else {
                self.flows.remove(&k);
            }
        }
    }

    fn take(&mut self, key: &FlowKey, now: DateTime<Utc>) -> serde_json::Value {
        let state = self.flows.remove(key).expect("flow state");
        let seconds = now
            .signed_duration_since(state.started)
            .to_std()
            .unwrap_or_default()
            .as_secs_f64();
        serde_json::json!({
            "collected_at": state.collected_at,
            "source_type": state.source_type,
            "hostname": state.hostname,
            "source_ip": key.src,
            "destination_ip": key.dst,
            "source_port": key.sport,
            "destination_port": key.dport,
            "event_taxonomy": "NETWORK_CONNECTION",
            "action": FLOW_ACTION,
            "outcome": "ALLOWED",
            "severity": 6,
            "raw_message": format!(
                "{{\"flow\":\"{}\",\"interface\":\"{}\",\"rule\":\"{}\",\"protocol\":\"{}\",\"direction\":\"{}\",\"bytes\":{},\"packets\":{},\"window_seconds\":{:.0}}}",
                format!("{}:{}->{}:{}", key.src, key.sport, key.dst, key.dport),
                state.iface,
                state.rule,
                key.proto,
                state.direction,
                state.bytes,
                state.packets,
                seconds
            ),
            "bytes_sent": state.bytes,
            "direction": state.direction,
            "tags": ["flow_summary"],
        })
    }
}

struct ParsedFlow {
    rule: String,
    iface: String,
    direction: String,
    src: String,
    dst: String,
    sport: u16,
    dport: u16,
    proto: String,
    data_len: u64,
}

/// Parse one pfSense filterlog CSV packet (IPv4 TCP/UDP, action `pass`).
///
/// Netgate raw filter format field order (after `filterlog: `):
/// rule, subrule, anchor, tracker, interface, reason, action, direction,
/// ip-version, tos, ecn, ttl, id, offset, flags, proto-id, proto-text,
/// length, src-ip, dst-ip, [sport, dport, data-length, ...].
fn parse_filterlog_flow(raw: &str) -> Option<ParsedFlow> {
    let pos = raw.find("filterlog:")?;
    let csv = raw[pos + "filterlog:".len()..].trim();
    let f: Vec<&str> = csv.split(',').map(|s| s.trim()).collect();
    if f.len() < 23 {
        return None;
    }
    if !f[8].eq_ignore_ascii_case("4") {
        return None; // IPv6 layout differs — not handled yet
    }
    if !f[6].eq_ignore_ascii_case("pass") {
        return None; // blocked packets transferred nothing
    }
    let proto_id = f[15];
    if !matches!(proto_id, "6" | "17") {
        return None;
    }
    let direction = match f[7] {
        "out" => "outbound",
        "in" => "inbound",
        _ => return None,
    };
    let sport: u16 = f[20].parse().ok()?;
    let dport: u16 = f[21].parse().ok()?;
    let data_len: u64 = f[22].parse().ok()?;
    if !f[18].parse::<std::net::Ipv4Addr>().is_ok() || !f[19].parse::<std::net::Ipv4Addr>().is_ok()
    {
        return None;
    }
    Some(ParsedFlow {
        rule: f[0].to_string(),
        iface: f[4].to_string(),
        direction: direction.to_string(),
        src: f[18].to_string(),
        dst: f[19].to_string(),
        sport,
        dport,
        proto: if proto_id == "6" { "tcp" } else { "udp" }.to_string(),
        data_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SourceType;

    fn record(line: &str) -> CollectorLogRecord {
        CollectorLogRecord {
            collected_at: Utc::now(),
            source_type: SourceType::Firewall,
            hostname: "pfsense".to_string(),
            raw_bytes: line.as_bytes().to_vec(),
        }
    }

    // Real-format pfSense filterlog CSV (IPv4 TCP, rule 100, interface em0).
    const PASS_TCP: &str = "<134>Nov 13 12:00:01 pfsense filterlog: 100,0,anchor1,12345,em0,match,pass,out,4,0x0,0,64,0,0,0,6,tcp,1500,10.0.0.5,203.0.113.9,51234,443,1400,S,1000,2000,65535,0,0,,,,,,,,,,,";

    #[test]
    fn parses_pass_tcp_packet() {
        let p = parse_filterlog_flow(PASS_TCP).expect("should parse");
        assert_eq!(p.src, "10.0.0.5");
        assert_eq!(p.dst, "203.0.113.9");
        assert_eq!(p.sport, 51234);
        assert_eq!(p.dport, 443);
        assert_eq!(p.proto, "tcp");
        assert_eq!(p.direction, "outbound");
        assert_eq!(p.data_len, 1400);
        assert_eq!(p.iface, "em0");
    }

    #[test]
    fn rejects_block_action() {
        let line = PASS_TCP.replace(",pass,", ",block,");
        assert!(parse_filterlog_flow(&line).is_none());
    }

    #[test]
    fn rejects_ipv6() {
        let mut f: Vec<&str> = PASS_TCP
            .split("filterlog:")
            .nth(1)
            .unwrap()
            .split(',')
            .collect();
        f[8] = "6";
        let line = format!("x filterlog: {}", f.join(","));
        assert!(parse_filterlog_flow(&line).is_none());
    }

    #[test]
    fn rejects_non_tcp_udp() {
        let mut f: Vec<&str> = PASS_TCP
            .split("filterlog:")
            .nth(1)
            .unwrap()
            .split(',')
            .collect();
        f[15] = "1"; // ICMP
        let line = format!("x filterlog: {}", f.join(","));
        assert!(parse_filterlog_flow(&line).is_none());
    }

    #[test]
    fn aggregates_flow_and_flushes() {
        let mut agg = FlowAggregator {
            enabled: true,
            window: Duration::from_secs(60),
            min_bytes: 2000,
            flows: HashMap::new(),
            last_sweep: Utc::now(),
        };
        let r = record(PASS_TCP);
        assert!(agg.ingest(&r).is_empty()); // 1400 < 2000
        assert!(agg.ingest(&r).is_empty()); // 2800 >= 2000 but window not elapsed
        let out = agg.flush_all();
        assert_eq!(out.len(), 1);
        let doc = &out[0];
        assert_eq!(doc["action"], FLOW_ACTION);
        assert_eq!(doc["bytes_sent"], 2800);
        assert_eq!(doc["direction"], "outbound");
        assert_eq!(doc["source_ip"], "10.0.0.5");
        assert_eq!(doc["destination_ip"], "203.0.113.9");
    }

    #[test]
    fn separate_flows_do_not_mix() {
        let mut agg = FlowAggregator {
            enabled: true,
            window: Duration::from_secs(60),
            min_bytes: 1000,
            flows: HashMap::new(),
            last_sweep: Utc::now(),
        };
        let a = record(PASS_TCP);
        let b = record(&PASS_TCP.replace("51234,443", "51235,444"));
        agg.ingest(&a);
        agg.ingest(&b);
        let out = agg.flush_all();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn below_min_bytes_not_flushed() {
        let mut agg = FlowAggregator {
            enabled: true,
            window: Duration::from_secs(60),
            min_bytes: 999999,
            flows: HashMap::new(),
            last_sweep: Utc::now(),
        };
        agg.ingest(&record(PASS_TCP));
        assert!(agg.flush_all().is_empty());
    }
}
