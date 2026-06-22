use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Formatter;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceType {
    LinuxAuth, // /var/log/auth.log
    LinuxSyslog,
    LinuxKernel,
    LinuxAuditd,
    LinuxSystemdJournal,
    LinuxProcess,
    LinuxNetwork,
    WindowsSecurity, // Windows Event Logs 4624/4625
    WindowsSystem,
    WindowsApplication,
    WindowsFim,
    WindowsInventory,
    WindowsNetwork,
    WindowsProcess,
    WindowsRegistry,
    WindowsServices,
    WindowsTasks,
    Firewall,  // iptables / pfSense / Cisco ASA logs
    WebServer, // Nginx / Apache access logs
    NginxAccess,
    NginxError,
    ApacheAccess,
    ApacheError,
    Traefik,
    DockerContainer,
    Custom(String), // For the "fallback" or rare cases
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
            SourceType::LinuxSyslog => write!(f, "LINUX_SYSLOG"),
            SourceType::LinuxKernel => write!(f, "LINUX_KERNEL"),
            SourceType::LinuxAuditd => write!(f, "LINUX_AUDITD"),
            SourceType::LinuxSystemdJournal => write!(f, "LINUX_SYSTEMD_JOURNAL"),
            SourceType::LinuxProcess => write!(f, "LINUX_PROCESS"),
            SourceType::LinuxNetwork => write!(f, "LINUX_NETWORK"),
            SourceType::WindowsSecurity => write!(f, "WINDOWS_SECURITY"),
            SourceType::WindowsSystem => write!(f, "WINDOWS_SYSTEM"),
            SourceType::WindowsApplication => write!(f, "WINDOWS_APPLICATION"),
            SourceType::WindowsFim => write!(f, "WINDOWS_FIM"),
            SourceType::WindowsInventory => write!(f, "WINDOWS_INVENTORY"),
            SourceType::WindowsNetwork => write!(f, "WINDOWS_NETWORK"),
            SourceType::WindowsProcess => write!(f, "WINDOWS_PROCESS"),
            SourceType::WindowsRegistry => write!(f, "WINDOWS_REGISTRY"),
            SourceType::WindowsServices => write!(f, "WINDOWS_SERVICES"),
            SourceType::WindowsTasks => write!(f, "WINDOWS_TASKS"),
            SourceType::Firewall => write!(f, "FIREWALL"),
            SourceType::WebServer => write!(f, "WEB_SERVER"),
            SourceType::NginxAccess => write!(f, "NGINX_ACCESS"),
            SourceType::NginxError => write!(f, "NGINX_ERROR"),
            SourceType::ApacheAccess => write!(f, "APACHE_ACCESS"),
            SourceType::ApacheError => write!(f, "APACHE_ERROR"),
            SourceType::Traefik => write!(f, "TRAEFIK"),
            SourceType::DockerContainer => write!(f, "DOCKER_CONTAINER"),
            SourceType::Custom(str) => write!(f, "CUSTOM({})", str),
        }
    }
}

impl SourceType {
    pub fn as_str(&self) -> &str {
        match self {
            SourceType::LinuxAuth => "LINUX_AUTH",
            SourceType::LinuxSyslog => "LINUX_SYSLOG",
            SourceType::LinuxKernel => "LINUX_KERNEL",
            SourceType::LinuxAuditd => "LINUX_AUDITD",
            SourceType::LinuxSystemdJournal => "LINUX_SYSTEMD_JOURNAL",
            SourceType::LinuxProcess => "LINUX_PROCESS",
            SourceType::LinuxNetwork => "LINUX_NETWORK",
            SourceType::WindowsSecurity => "WINDOWS_SECURITY",
            SourceType::WindowsSystem => "WINDOWS_SYSTEM",
            SourceType::WindowsApplication => "WINDOWS_APPLICATION",
            SourceType::WindowsFim => "WINDOWS_FIM",
            SourceType::WindowsInventory => "WINDOWS_INVENTORY",
            SourceType::WindowsNetwork => "WINDOWS_NETWORK",
            SourceType::WindowsProcess => "WINDOWS_PROCESS",
            SourceType::WindowsRegistry => "WINDOWS_REGISTRY",
            SourceType::WindowsServices => "WINDOWS_SERVICES",
            SourceType::WindowsTasks => "WINDOWS_TASKS",
            SourceType::Firewall => "FIREWALL",
            SourceType::WebServer => "WEB_SERVER",
            SourceType::NginxAccess => "NGINX_ACCESS",
            SourceType::NginxError => "NGINX_ERROR",
            SourceType::ApacheAccess => "APACHE_ACCESS",
            SourceType::ApacheError => "APACHE_ERROR",
            SourceType::Traefik => "TRAEFIK",
            SourceType::DockerContainer => "DOCKER_CONTAINER",
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
