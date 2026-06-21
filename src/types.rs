use std::fmt;
use std::fmt::Formatter;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceType {
    LinuxAuth,          // /var/log/auth.log
    WindowsSecurity,    // Windows Event Logs 4624/4625
    Firewall,           // iptables / pfSense / Cisco ASA logs
    WebServer,          // Nginx / Apache access logs
    Custom(String)      // For the "fallback" or rare cases
}

// Default for unknow
impl Default for SourceType {
    fn default() -> Self {
        SourceType::Custom("unknown".to_string())
    }
}

impl fmt::Display for SourceType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SourceType::LinuxAuth => write!(f, "LINUX_AUTH"),
            SourceType::WindowsSecurity => write!(f, "WINDOWS_SECURITY"),
            SourceType::Firewall => write!(f, "FIREWALL"),
            SourceType::WebServer => write!(f, "WEB_SERVER"),
            SourceType::Custom(str) => write!(f, "CUSTOM({})", str),
        }
    }
}

impl SourceType {
    pub fn as_str(&self) -> &str {
        match self {
            SourceType::LinuxAuth => "LINUX_AUTH",
            SourceType::WindowsSecurity => "WINDOWS_SECURITY",
            SourceType::Firewall => "FIREWALL",
            SourceType::WebServer => "WEB_SERVER",
            SourceType::Custom(str) => str.as_str(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorLogRecord {
    /// When the collector read this line from the file.
    pub collected_at: DateTime<Utc>,

    /// The source platform tag (ENUM).
    pub source_type: SourceType,

    /// The hostname of the machine (for CTU context).
    pub hostname: String,

    /// The raw, unmodified bytes of the log line.
    /// The central server will decode this to UTF-8 and parse it.
    pub raw_bytes: Vec<u8>,
}

impl CollectorLogRecord {
    /// Quick constructor to make the collector code cleaner.
    pub fn new(source_type: SourceType, hostname: String, raw_line: Vec<u8>) -> Self {
        Self {
            collected_at: Utc::now(),
            source_type,
            hostname,
            raw_bytes: raw_line,
        }
    }
}
