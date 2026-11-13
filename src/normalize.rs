//! Log normalization engine.
//!
//! Converts raw `CollectorLogRecord` values into structured `NormalizedLog`
//! records that match the downstream SIEM's `CreateLogDto` schema.
//!
//! Each source type has a dedicated parser that extracts fields like
//! source/destination IP, port, username, event taxonomy, action, and severity.

use crate::types::{CollectorLogRecord, SourceType};
use serde::Serialize;

// ── Normalized log (matches CreateLogDto) ────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct NormalizedLog {
    pub collected_at: String,
    pub source_type: String,
    pub hostname: String,
    pub source_ip: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_principal: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_security_id: Option<String>,

    pub event_taxonomy: String,
    pub action: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,

    pub severity: u8,
    pub raw_message: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_operation: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

// ── Severity constants ───────────────────────────────────────────────

#[allow(dead_code)]
const SEV_EMERGENCY: u8 = 0;
#[allow(dead_code)]
const SEV_ALERT: u8 = 1;
const SEV_CRITICAL: u8 = 2;
const SEV_ERROR: u8 = 3;
const SEV_WARNING: u8 = 4;
const SEV_NOTICE: u8 = 5;
const SEV_INFO: u8 = 6;
const SEV_DEBUG: u8 = 7;

// ── Taxonomy constants ───────────────────────────────────────────────

const TAX_AUTHENTICATION: &str = "AUTHENTICATION";
const TAX_PROCESS_ACTIVITY: &str = "PROCESS_ACTIVITY";
const TAX_NETWORK_CONNECTION: &str = "NETWORK_CONNECTION";
const TAX_FILE_ACCESS: &str = "FILE_ACCESS";
const TAX_REGISTRY_CHANGE: &str = "REGISTRY_CHANGE";
const TAX_SERVICE_STATE: &str = "SERVICE_STATE";
const TAX_SYSTEM_EVENT: &str = "SYSTEM_EVENT";
const TAX_WEB_REQUEST: &str = "WEB_REQUEST";
const TAX_FIREWALL_RULE: &str = "FIREWALL_RULE";

// ── Normalize entry point ────────────────────────────────────────────

/// Convert a raw collector record into a normalized log entry.
pub fn normalize_record(record: &CollectorLogRecord) -> NormalizedLog {
    let raw = String::from_utf8_lossy(&record.raw_bytes).into_owned();
    let source_type = record.source_type.as_str().to_string();
    let hostname = record.hostname.clone();
    let collected_at = record.collected_at.to_rfc3339();

    match &record.source_type {
        // Linux auth events
        SourceType::LinuxAuth => normalize_auth(&raw, source_type, hostname, collected_at),

        // Web server accesses
        SourceType::NginxAccess | SourceType::ApacheAccess | SourceType::WebServer => {
            normalize_web_access(&raw, source_type, hostname, collected_at)
        }
        SourceType::NginxError | SourceType::ApacheError => {
            normalize_web_error(&raw, source_type, hostname, collected_at)
        }

        // Firewall — pfSense syslog also carries resolver (unbound) lines,
        // so try DNS extraction before the firewall normalizer.
        SourceType::Firewall => normalize_dns(&raw, &source_type, &hostname, &collected_at)
            .unwrap_or_else(|| normalize_firewall(&raw, source_type, hostname, collected_at)),

        // Windows events
        SourceType::WindowsSecurity
        | SourceType::WindowsSystem
        | SourceType::WindowsApplication
        | SourceType::WindowsFim
        | SourceType::WindowsNetwork
        | SourceType::WindowsProcess
        | SourceType::WindowsRegistry
        | SourceType::WindowsServices
        | SourceType::WindowsTasks => {
            normalize_windows(&raw, &record.source_type, hostname, collected_at)
        }

        // Linux auditd (execve, syscall, file access)
        SourceType::LinuxAuditd => normalize_auditd(&raw, source_type, hostname, collected_at),

        // Everything else — DNS resolver lines get domain extraction,
        // everything else passes through with defaults.
        _ => normalize_dns(&raw, &source_type, &hostname, &collected_at)
            .unwrap_or_else(|| default_normalized(source_type, hostname, collected_at, raw)),
    }
}

// ── Linux auditd parser ─────────────────────────────────────────────

fn normalize_auditd(
    raw: &str,
    source_type: String,
    hostname: String,
    collected_at: String,
) -> NormalizedLog {
    let mut log = default_normalized(source_type, hostname, collected_at, raw.to_string());

    if raw.contains("type=EXECVE") {
        // argc=N a0="/usr/bin/foo" a1="arg1" a2="arg two" ...
        // auditd splits long argument lists across records; only records
        // carrying a0= start a new execution — fragments are ignored.
        let mut args = auditd_args(raw);
        args.sort_by_key(|(idx, _)| *idx);
        if let Some((_, program)) = args.iter().find(|(idx, _)| *idx == 0) {
            let command_line = args
                .iter()
                .map(|(_, v)| v.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            log.process_name = Some(program.clone());
            log.command_line = Some(command_line);
            log.event_taxonomy = TAX_PROCESS_ACTIVITY.to_string();
            log.action = "PROCESS_EXEC".to_string();
            log.severity = SEV_INFO;
        }
    } else if raw.contains("type=SYSCALL") {
        log.event_taxonomy = TAX_SYSTEM_EVENT.to_string();
        log.action = "SYSCALL".to_string();
    } else if raw.contains("type=PATH") {
        // PATH records accompany syscalls on watched paths:
        //   item=0 name="/home/u/.ssh/authorized_keys" nametype=CREATE mode=0100644 ...
        if let Some(name) = auditd_name_field(raw) {
            log.event_taxonomy = TAX_FILE_ACCESS.to_string();
            log.action = "FILE_ACCESS".to_string();
            log.file_path = Some(name);
            log.file_operation = Some(auditd_path_operation(raw));
            log.severity = SEV_INFO;
        }
    }
    log
}

/// Extract a quoted auditd field value, e.g. `name="/etc/passwd"`.
fn auditd_quoted_field(raw: &str, key: &str) -> Option<String> {
    let pat = format!("{}=\"", key);
    let start = raw.find(&pat)? + pat.len();
    let end = raw[start..].find('"')? + start;
    Some(raw[start..end].to_string())
}

/// Extract the PATH `name=` field: quoted plain text, or hex-encoded when
/// the filename contains spaces/quotes/non-ASCII bytes.
fn auditd_name_field(raw: &str) -> Option<String> {
    if let Some(quoted) = auditd_quoted_field(raw, "name") {
        return Some(quoted);
    }
    let pat = "name=";
    let start = raw.find(pat)? + pat.len();
    let rest = &raw[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let hex = &rest[..end];
    if hex.len() >= 2 && hex.len() % 2 == 0 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect();
        return Some(String::from_utf8_lossy(&bytes).into_owned());
    }
    None
}

/// Byte offset just past the first PATH `name=` value (quoted or hex).
fn auditd_name_field_end(raw: &str) -> Option<usize> {
    let pat = "name=";
    let start = raw.find(pat)? + pat.len();
    let rest = &raw[start..];
    if rest.starts_with('"') {
        let end = rest[1..].find('"')? + 1;
        return Some(start + end + 1);
    }
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    Some(start + end)
}

/// Extract an unquoted auditd token, e.g. `nametype=CREATE`.
fn auditd_token(raw: &str, key: &str) -> Option<String> {
    let pat = format!("{}=", key);
    let start = raw.find(&pat)? + pat.len();
    let rest = &raw[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// Map auditd PATH `nametype` to a coarse file operation.
fn auditd_path_operation(raw: &str) -> String {
    // The first name= field's closing quote bounds where its item ends;
    // search for nametype after it so filenames containing "nametype="
    // (e.g. /tmp/nametype=example) are not mistaken for the field.
    let search_from = auditd_name_field_end(raw).unwrap_or(0);
    let haystack = &raw[search_from..];
    match auditd_token(haystack, "nametype").as_deref() {
        Some("DELETE") => "delete",
        Some("CREATE") => "create",
        Some("RENAME") | Some("RENAME_UPDATE") => "rename",
        _ => "modify",
    }
    .to_string()
}

/// Extract auditd arguments as (index, value) pairs.
///
/// Values are either quoted (`a0="/bin/sh"`) or hex-encoded without quotes
/// (`a1=68656c6c6f`) when they contain non-printable characters.
fn auditd_args(raw: &str) -> Vec<(u32, String)> {
    let mut args = Vec::new();
    let mut rest = raw;
    loop {
        let Some(pos) = rest.find(" a") else { break };
        let tail = &rest[pos + 1..];
        let after_a = &tail[1..];
        let digit_len = after_a.chars().take_while(|c| c.is_ascii_digit()).count();
        if digit_len == 0 {
            rest = &tail[1..];
            continue;
        }
        let Ok(idx) = after_a[..digit_len].parse::<u32>() else {
            rest = &tail[1..];
            continue;
        };
        let after_digits = &after_a[digit_len..];
        if let Some(stripped) = after_digits.strip_prefix("=\"") {
            let Some(end) = stripped.find('"') else { break };
            args.push((idx, stripped[..end].to_string()));
            rest = &stripped[end + 1..];
        } else if after_digits.starts_with('=') {
            let hex_start = &after_digits[1..];
            let end = hex_start
                .find(char::is_whitespace)
                .unwrap_or(hex_start.len());
            let hex = &hex_start[..end];
            if hex.len() >= 2 && hex.len() % 2 == 0 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                let bytes: Vec<u8> = (0..hex.len())
                    .step_by(2)
                    .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                    .collect();
                args.push((idx, String::from_utf8_lossy(&bytes).into_owned()));
                rest = &hex_start[end..];
            } else {
                rest = &tail[1..];
            }
        } else {
            rest = &tail[1..];
        }
    }
    args
}

// ── DNS resolver parser (dnsmasq, unbound/pfSense) ──────────────────

/// Recognize DNS query/reply lines from common resolvers and extract the
/// queried domain. Returns None for anything else.
fn normalize_dns(
    raw: &str,
    source_type: &str,
    hostname: &str,
    collected_at: &str,
) -> Option<NormalizedLog> {
    let (domain, source_ip, is_response) = parse_dns_line(raw)?;
    let mut log = default_normalized(
        source_type.to_string(),
        hostname.to_string(),
        collected_at.to_string(),
        raw.to_string(),
    );
    log.domain = Some(domain);
    if !source_ip.is_empty() {
        log.source_ip = source_ip;
    }
    log.event_taxonomy = TAX_NETWORK_CONNECTION.to_string();
    log.action = if is_response {
        "DNS_RESPONSE"
    } else {
        "DNS_QUERY"
    }
    .to_string();
    log.severity = SEV_INFO;
    Some(log)
}

fn parse_dns_line(raw: &str) -> Option<(String, String, bool)> {
    // dnsmasq: "dnsmasq[1234]: query[A] www.example.com from 192.168.1.10"
    //          "dnsmasq[1234]: reply www.example.com is 93.184.216.34"
    //          "dnsmasq[1234]: cached www.example.com is ..."
    // matches both "dnsmasq[pid]: ..." syslog lines and systemd-journal
    // JSON envelopes with SYSLOG_IDENTIFIER=dnsmasq
    if raw.contains("dnsmasq") {
        if let Some(rest) = raw.split("query[").nth(1) {
            let after = rest.split(']').nth(1)?.trim_start();
            let (domain, ip) = after.split_once(" from ")?;
            // syslog lines end the IP at whitespace; journal JSON envelopes
            // end it at a quote/comma/brace
            let ip = ip
                .split(|c: char| c.is_whitespace() || c == '"' || c == ',' || c == '}')
                .next()
                .unwrap_or("")
                .to_string();
            return valid_domain(domain).map(|d| (d, ip, false));
        }
        for prefix in ["reply ", "cached "] {
            if let Some(idx) = raw.find(prefix) {
                let rest = &raw[idx + prefix.len()..];
                let domain = rest.split(" is ").next()?;
                return valid_domain(domain).map(|d| (d, String::new(), true));
            }
        }
        return None;
    }
    // unbound (pfSense): "unbound: [1234:0] info: 192.168.1.5 www.example.com. A IN"
    if raw.contains("unbound") && raw.contains(" info: ") {
        let rest = raw.split(" info: ").nth(1)?;
        let mut tokens = rest.split_whitespace();
        let ip = tokens.next()?.to_string();
        let domain = tokens.next()?.trim_end_matches('.');
        let qtype = tokens.next().unwrap_or("");
        if !matches!(
            qtype,
            "A" | "AAAA" | "PTR" | "TXT" | "MX" | "NS" | "SOA" | "ANY" | "CNAME" | "HTTPS" | "SVCB"
        ) {
            return None;
        }
        // unbound log-replies appends a response code after the query prefix
        let is_response = tokens.any(|t| {
            matches!(
                t,
                "NOERROR"
                    | "NXDOMAIN"
                    | "SERVFAIL"
                    | "REFUSED"
                    | "NOTIMP"
                    | "YXDOMAIN"
                    | "NXRRSET"
                    | "NOTAUTH"
                    | "BADVERS"
            )
        });
        return valid_domain(domain).map(|d| (d, ip, is_response));
    }
    None
}

/// Accept only plausible DNS names (labels of [a-z0-9._-], one dot minimum).
fn valid_domain(d: &str) -> Option<String> {
    let d = d.trim().trim_end_matches('.');
    if d.len() < 4 || d.len() > 253 || !d.contains('.') {
        return None;
    }
    if !d
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return None;
    }
    Some(d.to_lowercase())
}

// ── Default (catch-all) ──────────────────────────────────────────────

fn default_normalized(
    source_type: String,
    hostname: String,
    collected_at: String,
    raw_message: String,
) -> NormalizedLog {
    NormalizedLog {
        collected_at,
        source_type,
        hostname,
        source_ip: "0.0.0.0".to_string(),
        destination_ip: None,
        source_port: None,
        destination_port: None,
        user_principal: None,
        user_security_id: None,
        event_taxonomy: TAX_SYSTEM_EVENT.to_string(),
        action: "UNKNOWN".to_string(),
        outcome: None,
        severity: SEV_INFO,
        raw_message,
        process_name: None,
        command_line: None,
        file_path: None,
        file_operation: None,
        domain: None,
        tags: None,
    }
}

// ── Linux auth parser ────────────────────────────────────────────────

fn normalize_auth(
    raw: &str,
    source_type: String,
    hostname: String,
    collected_at: String,
) -> NormalizedLog {
    let (taxonomy, action, outcome, severity) = if raw.contains("Failed password") {
        (
            TAX_AUTHENTICATION,
            "FAILED_LOGIN",
            Some("FAILURE"),
            SEV_WARNING,
        )
    } else if raw.contains("Accepted password") || raw.contains("Accepted publickey") {
        (
            TAX_AUTHENTICATION,
            "SUCCESSFUL_LOGIN",
            Some("SUCCESS"),
            SEV_INFO,
        )
    } else if raw.contains("sudo:") {
        (
            TAX_AUTHENTICATION,
            "PRIVILEGE_ESCALATION",
            Some("SUCCESS"),
            SEV_NOTICE,
        )
    } else if raw.contains("useradd") || raw.contains("userdel") {
        (
            TAX_AUTHENTICATION,
            "USER_MANAGEMENT",
            Some("SUCCESS"),
            SEV_NOTICE,
        )
    } else if raw.contains("authentication failure") {
        (
            TAX_AUTHENTICATION,
            "AUTH_FAILURE",
            Some("FAILURE"),
            SEV_WARNING,
        )
    } else {
        (TAX_AUTHENTICATION, "AUTH_EVENT", None, SEV_INFO)
    };

    let source_ip = extract_ip(raw).unwrap_or_else(|| "0.0.0.0".to_string());
    let source_port = extract_port(raw);
    let user_principal = extract_auth_user(raw);

    NormalizedLog {
        collected_at,
        source_type,
        hostname,
        source_ip,
        destination_ip: None,
        source_port,
        destination_port: None,
        user_principal,
        user_security_id: None,
        event_taxonomy: taxonomy.to_string(),
        action: action.to_string(),
        outcome: outcome.map(|s| s.to_string()),
        severity,
        raw_message: raw.to_string(),
        process_name: None,
        command_line: None,
        file_path: None,
        file_operation: None,
        domain: None,
        tags: None,
    }
}

// ── Web access log parser (Nginx / Apache combined format) ──────────

fn normalize_web_access(
    raw: &str,
    source_type: String,
    hostname: String,
    collected_at: String,
) -> NormalizedLog {
    // Combined log format: IP - - [date] "METHOD URL PROTO" STATUS SIZE "REF" "UA"
    let source_ip = raw
        .split_whitespace()
        .next()
        .filter(|token| token.parse::<std::net::IpAddr>().is_ok())
        .unwrap_or("0.0.0.0")
        .to_string();

    let status = extract_status_code(raw);
    let code = status.unwrap_or(0);
    let (action, outcome, severity) = match code {
        200..=299 => ("HTTP_OK", Some("SUCCESS"), SEV_INFO),
        300..=399 => ("HTTP_REDIRECT", None, SEV_DEBUG),
        400..=499 => ("HTTP_CLIENT_ERROR", Some("FAILURE"), SEV_WARNING),
        500..=599 => ("HTTP_SERVER_ERROR", Some("FAILURE"), SEV_ERROR),
        _ => ("HTTP_REQUEST", None, SEV_INFO),
    };

    // Extract HTTP method.
    let method = extract_http_method(raw);
    let tags = if let Some(m) = method {
        Some(vec![m, format!("HTTP {}", code)])
    } else {
        Some(vec![format!("HTTP {}", code)])
    };

    NormalizedLog {
        collected_at,
        source_type,
        hostname,
        source_ip,
        destination_ip: None,
        source_port: None,
        destination_port: None,
        user_principal: None,
        user_security_id: None,
        event_taxonomy: TAX_WEB_REQUEST.to_string(),
        action: action.to_string(),
        outcome: outcome.map(|s| s.to_string()),
        severity,
        raw_message: raw.to_string(),
        process_name: None,
        command_line: None,
        file_path: None,
        file_operation: None,
        domain: None,
        tags,
    }
}

fn normalize_web_error(
    raw: &str,
    source_type: String,
    hostname: String,
    collected_at: String,
) -> NormalizedLog {
    let severity = raw
        .to_lowercase()
        .split_whitespace()
        .find_map(|w| match w {
            "emerg" | "alert" | "crit" => Some(SEV_CRITICAL),
            "error" => Some(SEV_ERROR),
            "warn" => Some(SEV_WARNING),
            "notice" => Some(SEV_NOTICE),
            "info" => Some(SEV_INFO),
            "debug" => Some(SEV_DEBUG),
            _ => None,
        })
        .unwrap_or(SEV_ERROR);

    NormalizedLog {
        collected_at,
        source_type,
        hostname,
        source_ip: "0.0.0.0".to_string(),
        destination_ip: None,
        source_port: None,
        destination_port: None,
        user_principal: None,
        user_security_id: None,
        event_taxonomy: TAX_WEB_REQUEST.to_string(),
        action: "HTTP_ERROR".to_string(),
        outcome: Some("FAILURE".to_string()),
        severity,
        raw_message: raw.to_string(),
        process_name: None,
        command_line: None,
        file_path: None,
        file_operation: None,
        domain: None,
        tags: None,
    }
}

// ── Firewall syslog parser ───────────────────────────────────────────

fn normalize_firewall(
    raw: &str,
    source_type: String,
    hostname: String,
    collected_at: String,
) -> NormalizedLog {
    let upper = raw.to_uppercase();

    let (action, outcome, severity) =
        if upper.contains("DENY") || upper.contains("DROP") || upper.contains("BLOCK") {
            ("FIREWALL_DENY", Some("BLOCKED"), SEV_WARNING)
        } else if upper.contains("ALLOW") || upper.contains("ACCEPT") || upper.contains("PERMIT") {
            ("FIREWALL_ALLOW", Some("ALLOWED"), SEV_INFO)
        } else if upper.contains("BUILT") || upper.contains("TEARDOWN") {
            ("CONNECTION_STATE", None, SEV_INFO)
        } else {
            ("FIREWALL_EVENT", None, SEV_INFO)
        };

    let source_ip = extract_first_ip(raw).unwrap_or_else(|| "0.0.0.0".to_string());
    let dst_ip = extract_second_ip(raw);

    let (src_port, dst_port) = extract_port_pair(raw);

    let tags = extract_cisco_asa_type(raw);

    NormalizedLog {
        collected_at,
        source_type,
        hostname,
        source_ip,
        destination_ip: dst_ip,
        source_port: src_port,
        destination_port: dst_port,
        user_principal: None,
        user_security_id: None,
        event_taxonomy: TAX_FIREWALL_RULE.to_string(),
        action: action.to_string(),
        outcome: outcome.map(|s| s.to_string()),
        severity,
        raw_message: raw.to_string(),
        process_name: None,
        command_line: None,
        file_path: None,
        file_operation: None,
        domain: None,
        tags,
    }
}

// ── Windows Event parser ─────────────────────────────────────────────

fn normalize_windows(
    raw: &str,
    source_type: &SourceType,
    hostname: String,
    collected_at: String,
) -> NormalizedLog {
    let event_id = extract_xml_event_id(raw);
    let (taxonomy, action, default_severity) = classify_windows_event(&source_type, event_id);

    let (process_name, command_line, file_path, file_operation) =
        extract_windows_process_file(raw, event_id);

    NormalizedLog {
        collected_at,
        source_type: source_type.as_str().to_string(),
        hostname,
        source_ip: "0.0.0.0".to_string(),
        destination_ip: None,
        source_port: None,
        destination_port: None,
        user_principal: extract_xml_user(raw),
        user_security_id: extract_xml_sid(raw),
        event_taxonomy: taxonomy.to_string(),
        action: action.to_string(),
        outcome: None,
        severity: default_severity,
        raw_message: raw.to_string(),
        process_name,
        command_line,
        file_path,
        file_operation,
        domain: None,
        tags: event_id.map(|id| vec![format!("EventID={}", id)]),
    }
}

/// Extract structured process / file fields from Windows Security XML events.
///
/// - 4688 (process creation): `NewProcessName` + `CommandLine`
/// - 4663 (object access): `ProcessName` + `ObjectName` + access-mask operation
fn extract_windows_process_file(
    raw: &str,
    event_id: Option<u32>,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    match event_id {
        Some(4688) => (
            extract_xml_data(raw, "NewProcessName"),
            extract_xml_data(raw, "CommandLine"),
            None,
            None,
        ),
        Some(4663) => (
            extract_xml_data(raw, "ProcessName"),
            None,
            extract_xml_data(raw, "ObjectName"),
            extract_xml_data(raw, "AccessMask").and_then(|mask| access_mask_operation(&mask)),
        ),
        _ => (None, None, None, None),
    }
}

/// Map a 4663 AccessMask hex value to a coarse file operation.
fn access_mask_operation(mask: &str) -> Option<String> {
    let hex = mask
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    let value = u64::from_str_radix(hex, 16).ok()?;
    // FILE_DELETE 0x10000, FILE_WRITE_DATA 0x2, FILE_APPEND_DATA 0x4,
    // FILE_READ_DATA 0x1 / FILE_LIST_DIRECTORY 0x1
    if value & 0x10000 != 0 {
        Some("delete".to_string())
    } else if value & 0x6 != 0 {
        Some("write".to_string())
    } else if value & 0x1 != 0 {
        Some("read".to_string())
    } else {
        Some("access".to_string())
    }
}

// ── IP/port helpers ────────────────────────────────────────────────

/// Check if a token is a bare IP or an IP:port.
fn is_ip_or_ip_port(w: &str) -> bool {
    if w.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if let Some(last_colon) = w.rfind(':') {
        w[..last_colon].parse::<std::net::IpAddr>().is_ok()
    } else {
        false
    }
}

/// Strip :port suffix from an IP token.
fn ip_without_port(w: &str) -> String {
    if w.parse::<std::net::IpAddr>().is_ok() {
        w.to_string()
    } else if let Some(last_colon) = w.rfind(':') {
        w[..last_colon].to_string()
    } else {
        w.to_string()
    }
}

// ── Extraction helpers ───────────────────────────────────────────────

fn extract_ip(raw: &str) -> Option<String> {
    for word in raw.split_whitespace() {
        if word.parse::<std::net::IpAddr>().is_ok() {
            return Some(word.to_string());
        }
    }
    None
}

fn extract_first_ip(raw: &str) -> Option<String> {
    raw.split_whitespace()
        .find(|w| is_ip_or_ip_port(w))
        .map(|w| ip_without_port(w))
}

fn extract_second_ip(raw: &str) -> Option<String> {
    let mut found = false;
    for word in raw.split_whitespace() {
        if is_ip_or_ip_port(word) {
            if found {
                return Some(ip_without_port(word));
            }
            found = true;
        }
    }
    None
}

fn extract_port(raw: &str) -> Option<u16> {
    for word in raw.split_whitespace() {
        // Try the whole word, then try after the last colon (IP:PORT format).
        if let Ok(p) = word.trim_end_matches(':').parse::<u16>() {
            if p > 0 {
                return Some(p);
            }
        }
        if let Some(last_colon) = word.rfind(':') {
            if let Ok(p) = word[last_colon + 1..].parse::<u16>() {
                if p > 0 {
                    return Some(p);
                }
            }
        }
    }
    None
}

fn extract_port_pair(raw: &str) -> (Option<u16>, Option<u16>) {
    let ports: Vec<u16> = raw
        .split_whitespace()
        .filter_map(|w| {
            // Try after last colon (IP:PORT), then whole word.
            w.rfind(':')
                .and_then(|c| w[c + 1..].parse::<u16>().ok())
                .or_else(|| w.trim_end_matches(':').parse::<u16>().ok())
        })
        .filter(|&p| p > 0)
        .collect();

    if ports.len() >= 2 {
        (Some(ports[0]), Some(ports[1]))
    } else if ports.len() == 1 {
        (Some(ports[0]), None)
    } else {
        (None, None)
    }
}

fn extract_auth_user(raw: &str) -> Option<String> {
    // SSH: "Failed password for root from 10.0.0.5"
    // Sudo: "sudo: dunamis : TTY=..."
    for phrase in &["for ", "sudo: ", "user=", "user "] {
        if let Some(pos) = raw.find(phrase) {
            let after = &raw[pos + phrase.len()..];
            if let Some(user) = after.split_whitespace().next() {
                let clean = user
                    .trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
                    .trim();
                if !clean.is_empty() && clean.len() < 64 {
                    return Some(clean.to_string());
                }
            }
        }
    }
    None
}

fn extract_status_code(raw: &str) -> Option<u16> {
    // Find HTTP/1.x" or HTTP/2" then take the next token as status code.
    for proto in &["HTTP/1.1", "HTTP/1.0", "HTTP/2", "HTTP/2.0"] {
        if let Some(pos) = raw.find(proto) {
            let rest = &raw[pos + proto.len()..];
            if let Some(quote_end) = rest.find('"') {
                let after = rest[quote_end + 1..].trim();
                if let Some(code) = after
                    .split_whitespace()
                    .next()
                    .and_then(|w| w.parse::<u16>().ok())
                {
                    if (100..=599).contains(&code) {
                        return Some(code);
                    }
                }
            }
        }
    }
    None
}

fn extract_http_method(raw: &str) -> Option<String> {
    for method in &[
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE",
    ] {
        if raw.contains(&format!("\"{} ", method)) || raw.contains(&format!("{} /", method)) {
            return Some(method.to_string());
        }
    }
    None
}

fn extract_cisco_asa_type(raw: &str) -> Option<Vec<String>> {
    // %ASA-6-302013: Built outbound TCP connection
    // The token after splitting includes the trailing colon: "%ASA-6-302013:"
    if let Some(tag) = raw.split_whitespace().find(|w| w.starts_with("%ASA-")) {
        return Some(vec![tag.trim_end_matches(':').to_string()]);
    }
    None
}

fn extract_xml_event_id(xml: &str) -> Option<u32> {
    // <EventID>4624</EventID> or <EventID Qualifiers="...">4624</EventID>
    let start = xml.find("<EventID")?;
    let end = xml[start..].find('>')?;
    let after = &xml[start + end + 1..];
    let value_end = after.find('<')?;
    after[..value_end].trim().parse().ok()
}

fn extract_xml_user(xml: &str) -> Option<String> {
    // <Data Name="TargetUserName">john</Data> or <Data Name="SubjectUserName">SYSTEM</Data>
    for name in &["TargetUserName", "SubjectUserName", "AccountName"] {
        if let Some(user) = extract_xml_data(xml, name) {
            if !user.is_empty() && user != "-" {
                return Some(user);
            }
        }
    }
    None
}

fn extract_xml_sid(xml: &str) -> Option<String> {
    extract_xml_data(xml, "SubjectUserSid")
}

fn extract_xml_data(xml: &str, name: &str) -> Option<String> {
    let pattern = format!("Name=\"{}\"", name);
    let start = xml.find(&pattern)?;
    let after = &xml[start + pattern.len()..];
    let value_start = after.find('>')? + 1;
    let value_end = after[value_start..].find('<')?;
    Some(
        after[value_start..value_start + value_end]
            .trim()
            .to_string(),
    )
}

fn classify_windows_event(source_type: &SourceType, event_id: Option<u32>) -> (&str, &str, u8) {
    match event_id {
        Some(4624) => (TAX_AUTHENTICATION, "SUCCESSFUL_LOGIN", SEV_INFO),
        Some(4625) => (TAX_AUTHENTICATION, "FAILED_LOGIN", SEV_WARNING),
        Some(4688) => (TAX_PROCESS_ACTIVITY, "PROCESS_START", SEV_INFO),
        Some(4689) => (TAX_PROCESS_ACTIVITY, "PROCESS_END", SEV_INFO),
        Some(4656) | Some(4663) | Some(4670) => (TAX_FILE_ACCESS, "FILE_ACCESS", SEV_INFO),
        Some(4657) => (TAX_REGISTRY_CHANGE, "REGISTRY_MODIFY", SEV_NOTICE),
        Some(4698) | Some(4702) => (TAX_PROCESS_ACTIVITY, "SCHEDULED_TASK", SEV_INFO),
        Some(7036) | Some(7045) => (TAX_SERVICE_STATE, "SERVICE_EVENT", SEV_INFO),
        Some(5152) | Some(5157) => (TAX_NETWORK_CONNECTION, "FIREWALL_DENY", SEV_WARNING),
        Some(5154) | Some(5156) => (TAX_NETWORK_CONNECTION, "FIREWALL_ALLOW", SEV_INFO),
        _ => {
            // Use the source_type to determine taxonomy
            let taxonomy = match source_type {
                SourceType::WindowsProcess => TAX_PROCESS_ACTIVITY,
                SourceType::WindowsFim => TAX_FILE_ACCESS,
                SourceType::WindowsRegistry => TAX_REGISTRY_CHANGE,
                SourceType::WindowsServices => TAX_SERVICE_STATE,
                SourceType::WindowsNetwork => TAX_NETWORK_CONNECTION,
                SourceType::WindowsSecurity => TAX_AUTHENTICATION,
                _ => TAX_SYSTEM_EVENT,
            };
            (taxonomy, "WINDOWS_EVENT", SEV_INFO)
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_record(source_type: SourceType, raw: &str) -> CollectorLogRecord {
        CollectorLogRecord {
            collected_at: Utc::now(),
            source_type,
            hostname: "test-host".into(),
            raw_bytes: raw.as_bytes().to_vec(),
        }
    }

    #[test]
    fn parse_auth_failed_login() {
        let rec = make_record(
            SourceType::LinuxAuth,
            "Jun 22 12:00:01 server sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2",
        );
        let log = normalize_record(&rec);
        assert_eq!(log.source_ip, "10.0.0.5");
        assert_eq!(log.source_port, Some(22));
        assert_eq!(log.user_principal.as_deref(), Some("root"));
        assert_eq!(log.action, "FAILED_LOGIN");
        assert_eq!(log.severity, SEV_WARNING);
    }

    #[test]
    fn parse_auth_successful_login() {
        let rec = make_record(
            SourceType::LinuxAuth,
            "Jun 22 12:00:02 server sshd[1235]: Accepted publickey for dunamis from 192.168.1.1 port 50001",
        );
        let log = normalize_record(&rec);
        assert_eq!(log.source_ip, "192.168.1.1");
        assert_eq!(log.user_principal.as_deref(), Some("dunamis"));
        assert_eq!(log.action, "SUCCESSFUL_LOGIN");
    }

    #[test]
    fn parse_nginx_access() {
        let rec = make_record(
            SourceType::NginxAccess,
            "192.168.1.5 - - [22/Jun/2026:12:00:01] \"GET /admin HTTP/1.1\" 404 123 \"-\" \"curl/7.81\"",
        );
        let log = normalize_record(&rec);
        assert_eq!(log.source_ip, "192.168.1.5");
        assert_eq!(log.action, "HTTP_CLIENT_ERROR");
        assert_eq!(log.severity, SEV_WARNING);
        assert!(
            log.tags
                .as_ref()
                .map(|t| t.contains(&"GET".to_string()))
                .unwrap_or(false)
        );
    }

    #[test]
    fn parse_web_error() {
        let rec = make_record(
            SourceType::NginxError,
            "2026/06/22 12:00:01 [error] 1234#1234: *1 connect() failed (111: Connection refused)",
        );
        let log = normalize_record(&rec);
        assert_eq!(log.action, "HTTP_ERROR");
        assert_eq!(log.severity, SEV_ERROR);
    }

    #[test]
    fn parse_firewall_deny() {
        let rec = make_record(
            SourceType::Firewall,
            "DENY TCP 10.0.0.5:53212 -> 8.8.8.8:443",
        );
        let log = normalize_record(&rec);
        assert_eq!(log.source_ip, "10.0.0.5");
        assert_eq!(log.destination_ip.as_deref(), Some("8.8.8.8"));
        assert_eq!(log.source_port, Some(53212));
        assert_eq!(log.destination_port, Some(443));
        assert_eq!(log.action, "FIREWALL_DENY");
    }

    #[test]
    fn parse_firewall_cisco() {
        let rec = make_record(
            SourceType::Firewall,
            "%ASA-6-302013: Built outbound TCP connection 192.168.1.1:443 -> 52.20.10.1:443",
        );
        let log = normalize_record(&rec);
        assert_eq!(log.action, "CONNECTION_STATE");
        assert!(
            log.tags
                .as_ref()
                .map(|t| t.contains(&"%ASA-6-302013".to_string()))
                .unwrap_or(false)
        );
    }

    #[test]
    fn parse_sudo() {
        let rec = make_record(
            SourceType::LinuxAuth,
            "Jun 22 12:05:00 server sudo: dunamis : TTY=pts/0 ; PWD=/home/dunamis ; USER=root ; COMMAND=/usr/bin/apt update",
        );
        let log = normalize_record(&rec);
        assert_eq!(log.action, "PRIVILEGE_ESCALATION");
        assert_eq!(log.user_principal.as_deref(), Some("dunamis"));
    }

    #[test]
    fn default_normalized_still_fills_fields() {
        let rec = make_record(SourceType::Custom("test".into()), "some random log line");
        let log = normalize_record(&rec);
        assert_eq!(log.source_ip, "0.0.0.0");
        assert_eq!(log.action, "UNKNOWN");
        assert!(log.raw_message.contains("some random log line"));
    }

    #[test]
    fn windows_4688_extracts_process_and_command_line() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4688</EventID></System><EventData><Data Name="SubjectUserName">SYSTEM</Data><Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data><Data Name="CommandLine">cmd.exe /c whoami</Data></EventData></Event>"#;
        let rec = make_record(SourceType::WindowsProcess, xml);
        let log = normalize_record(&rec);
        assert_eq!(
            log.process_name.as_deref(),
            Some("C:\\Windows\\System32\\cmd.exe")
        );
        assert_eq!(log.command_line.as_deref(), Some("cmd.exe /c whoami"));
        assert_eq!(log.file_path, None);
    }

    #[test]
    fn windows_4663_extracts_file_path_and_operation() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4663</EventID></System><EventData><Data Name="ProcessName">C:\Windows\System32\notepad.exe</Data><Data Name="ObjectName">C:\Users\admin\secret.txt</Data><Data Name="AccessMask">0x10000</Data></EventData></Event>"#;
        let rec = make_record(SourceType::WindowsFim, xml);
        let log = normalize_record(&rec);
        assert_eq!(
            log.process_name.as_deref(),
            Some("C:\\Windows\\System32\\notepad.exe")
        );
        assert_eq!(
            log.file_path.as_deref(),
            Some("C:\\Users\\admin\\secret.txt")
        );
        assert_eq!(log.file_operation.as_deref(), Some("delete"));
    }

    #[test]
    fn access_mask_write_and_read() {
        assert_eq!(access_mask_operation("0x2"), Some("write".into()));
        assert_eq!(access_mask_operation("0x1"), Some("read".into()));
        assert_eq!(access_mask_operation("0x10000"), Some("delete".into()));
        assert_eq!(access_mask_operation("garbage"), None);
    }

    #[test]
    fn auditd_execve_hex_arg_decoded() {
        let raw = r#"type=EXECVE msg=audit(1699999999.123:457): argc=2 a0="/usr/bin/printf" a1=68656c6c6f20776f726c64"#;
        let rec = make_record(SourceType::LinuxAuditd, raw);
        let log = normalize_record(&rec);
        assert_eq!(log.process_name.as_deref(), Some("/usr/bin/printf"));
        assert_eq!(
            log.command_line.as_deref(),
            Some("/usr/bin/printf hello world")
        );
    }

    #[test]
    fn auditd_execve_trailing_newline_hex_arg_decoded() {
        // Live tailer preserves the trailing newline; the hex scan must stop at it.
        let raw = "type=EXECVE msg=audit(1699999999.123:459): argc=2 a0=2f62696e2f7368 a1=2d69\n";
        let rec = make_record(SourceType::LinuxAuditd, raw);
        let log = normalize_record(&rec);
        assert_eq!(log.process_name.as_deref(), Some("/bin/sh"));
        assert_eq!(log.command_line.as_deref(), Some("/bin/sh -i"));
        assert_eq!(log.action, "PROCESS_EXEC");
    }

    #[test]
    fn auditd_execve_fragment_without_a0_is_not_a_process() {
        let raw = r#"type=EXECVE msg=audit(1699999999.123:458): a5="continued-arg""#;
        let rec = make_record(SourceType::LinuxAuditd, raw);
        let log = normalize_record(&rec);
        assert_eq!(log.process_name, None);
        assert_eq!(log.command_line, None);
    }

    #[test]
    fn auditd_path_record_extracts_file_access() {
        let raw = r#"type=PATH msg=audit(1699999999.123:460): item=0 name="/home/admin/.ssh/authorized_keys" nametype=CREATE mode=0100600 ouid=1000 ogid=1000 rdev=00:00"#;
        let rec = make_record(SourceType::LinuxAuditd, raw);
        let log = normalize_record(&rec);
        assert_eq!(log.action, "FILE_ACCESS");
        assert_eq!(
            log.file_path.as_deref(),
            Some("/home/admin/.ssh/authorized_keys")
        );
        assert_eq!(log.file_operation.as_deref(), Some("create"));
        assert_eq!(log.event_taxonomy, TAX_FILE_ACCESS);
    }

    #[test]
    fn auditd_path_record_hex_name_decoded() {
        // auditd hex-encodes names with spaces/quotes/non-ASCII bytes
        let raw = "type=PATH msg=audit(1699999999.125:462): item=0 name=2f686f6d652f757365722f6d792066696c65 nametype=CREATE";
        let rec = make_record(SourceType::LinuxAuditd, raw);
        let log = normalize_record(&rec);
        assert_eq!(log.file_path.as_deref(), Some("/home/user/my file"));
        assert_eq!(log.file_operation.as_deref(), Some("create"));
    }

    #[test]
    fn auditd_path_record_nametype_inside_filename_ignored() {
        let raw = r#"type=PATH msg=audit(1699999999.126:463): item=0 name="/tmp/nametype=example" nametype=DELETE"#;
        let rec = make_record(SourceType::LinuxAuditd, raw);
        let log = normalize_record(&rec);
        assert_eq!(log.file_path.as_deref(), Some("/tmp/nametype=example"));
        assert_eq!(log.file_operation.as_deref(), Some("delete"));
    }

    #[test]
    fn auditd_path_record_delete_maps_operation() {
        let raw = r#"type=PATH msg=audit(1699999999.124:461): item=1 name="/var/log/auth.log" nametype=DELETE"#;
        let rec = make_record(SourceType::LinuxAuditd, raw);
        let log = normalize_record(&rec);
        assert_eq!(log.file_operation.as_deref(), Some("delete"));
        assert_eq!(log.file_path.as_deref(), Some("/var/log/auth.log"));
    }

    #[test]
    fn dnsmasq_query_extracts_domain_and_client() {
        let raw =
            r#"Nov 12 09:00:01 srv dnsmasq[1234]: query[A] www.example.com from 192.168.1.10"#;
        let rec = make_record(SourceType::LinuxSyslog, raw);
        let log = normalize_record(&rec);
        assert_eq!(log.action, "DNS_QUERY");
        assert_eq!(log.domain.as_deref(), Some("www.example.com"));
        assert_eq!(log.source_ip, "192.168.1.10");
    }

    #[test]
    fn unbound_info_line_extracts_domain() {
        let raw = r#"unbound: [12345:0] info: 192.168.1.5 Exfil.Evil-Corp.com. A IN"#;
        let rec = make_record(SourceType::LinuxSyslog, raw);
        let log = normalize_record(&rec);
        assert_eq!(log.action, "DNS_QUERY");
        assert_eq!(log.domain.as_deref(), Some("exfil.evil-corp.com"));
        assert_eq!(log.source_ip, "192.168.1.5");
    }

    #[test]
    fn dnsmasq_reply_is_response() {
        let raw = r#"Nov 12 09:00:02 srv dnsmasq[1234]: reply www.example.com is 93.184.216.34"#;
        let rec = make_record(SourceType::LinuxSyslog, raw);
        let log = normalize_record(&rec);
        assert_eq!(log.action, "DNS_RESPONSE");
        assert_eq!(log.domain.as_deref(), Some("www.example.com"));
    }

    #[test]
    fn pfsense_firewall_source_unbound_query_extracts_domain() {
        let raw = r#"unbound: [12345:0] info: 192.168.1.5 tunnel.evil-corp.com. A IN"#;
        let rec = make_record(SourceType::Firewall, raw);
        let log = normalize_record(&rec);
        assert_eq!(log.action, "DNS_QUERY");
        assert_eq!(log.domain.as_deref(), Some("tunnel.evil-corp.com"));
        assert_eq!(log.source_ip, "192.168.1.5");
    }

    #[test]
    fn unbound_reply_with_rcode_is_response() {
        let raw = r#"unbound: [12345:0] info: 192.168.1.5 www.example.com. A IN NOERROR"#;
        let rec = make_record(SourceType::LinuxSyslog, raw);
        let log = normalize_record(&rec);
        assert_eq!(log.action, "DNS_RESPONSE");
        assert_eq!(log.domain.as_deref(), Some("www.example.com"));
    }

    #[test]
    fn dnsmasq_journal_envelope_extracts_domain() {
        let raw = r#"{"MESSAGE":"dnsmasq[1234]: query[A] cdn.example.com from 10.0.0.8","SYSLOG_IDENTIFIER":"dnsmasq"}"#;
        let rec = make_record(SourceType::LinuxSyslog, raw);
        let log = normalize_record(&rec);
        assert_eq!(log.action, "DNS_QUERY");
        assert_eq!(log.domain.as_deref(), Some("cdn.example.com"));
        assert_eq!(log.source_ip, "10.0.0.8");
    }

    #[test]
    fn non_dns_syslog_line_has_no_domain() {
        let raw = r#"Nov 12 09:00:03 srv cron[99]: (root) CMD (run-parts /etc/cron.hourly)"#;
        let rec = make_record(SourceType::LinuxSyslog, raw);
        let log = normalize_record(&rec);
        assert_eq!(log.domain, None);
    }

    #[test]
    fn auditd_execve_extracts_process_and_command_line() {
        let raw = r#"type=EXECVE msg=audit(1699999999.123:456): argc=3 a0="/bin/sh" a1="-c" a2="rm -rf /tmp/x""#;
        let rec = make_record(SourceType::LinuxAuditd, raw);
        let log = normalize_record(&rec);
        assert_eq!(log.process_name.as_deref(), Some("/bin/sh"));
        assert_eq!(
            log.command_line.as_deref(),
            Some("/bin/sh -c rm -rf /tmp/x")
        );
        assert_eq!(log.action, "PROCESS_EXEC");
    }
}
