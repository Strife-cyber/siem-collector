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

        // Firewall
        SourceType::Firewall => normalize_firewall(&raw, source_type, hostname, collected_at),

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

        // Everything else — pass through with defaults.
        _ => default_normalized(source_type, hostname, collected_at, raw),
    }
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
        tags: event_id.map(|id| vec![format!("EventID={}", id)]),
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
}
