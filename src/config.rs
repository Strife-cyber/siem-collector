//! Configuration for the SIEM Collector.
//!
//! Loaded from two sources (in order of precedence):
//!
//! 1. **`siem-collector.toml`** — placed next to the `.exe` (lowest priority)
//! 2. **Environment variables** — `SIEM_ENDPOINT`, `SIEM_API_KEY`, etc. override
//!    the file, so you can still use CI/CD or system-level config.
//!
//! # One-command launch
//!
//! 1. Drop `siem-collector.exe` and `siem-collector.toml` in the same folder.
//! 2. Double-click the `.exe`.
//! 3. That's it.
//!
//! # Example `siem-collector.toml`
//!
//! ```toml
//! siem_endpoint = "https://siem.example.com/api/logs"
//! # siem_api_key = "your-key"
//! # siem_batch_size = 100
//! # siem_batch_interval = 5
//! # wal_dir = "C:\data\siem-collector"
//! ```

use std::path::PathBuf;

use serde::Deserialize;

/// All configurable parameters for the collector.
///
/// Every field is `Option` so that a partial config file is valid and
/// missing fields fall through to their respective defaults.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct CollectorConfig {
    /// Remote SIEM endpoint URL.
    pub siem_endpoint: Option<String>,
    /// Optional API key sent as `X-API-Key` header.
    pub siem_api_key: Option<String>,
    /// Maximum records per POST batch (default: 100).
    pub siem_batch_size: Option<usize>,
    /// Seconds to wait before flushing a partial batch (default: 5).
    pub siem_batch_interval: Option<u64>,
    /// Directory for the WAL file. Defaults to the system data directory
    /// (`%APPDATA%/siem-collector` on Windows).
    pub wal_dir: Option<PathBuf>,
}

impl CollectorConfig {
    /// Load config from `siem-collector.toml` next to the executable, if it exists.
    ///
    /// Returns `None` silently when the file is absent or unreadable so that
    /// the app works identically to before when no config file is present.
    pub fn from_exe_dir() -> Option<Self> {
        let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
        let config_path = exe_dir.join("siem-collector.toml");

        if !config_path.exists() {
            return None;
        }

        let contents = std::fs::read_to_string(&config_path).ok()?;
        toml::from_str(&contents).ok().inspect(|_| {
            tracing::info!(path = %config_path.display(), "Loaded config file");
        })
    }

    /// Build the effective config by loading from the file (if any) and then
    /// overlaying environment variables.
    pub fn build() -> Self {
        let mut config = Self::from_exe_dir().unwrap_or_default();
        config.merge_env();
        config
    }

    /// Override any config fields with non-empty environment variables.
    fn merge_env(&mut self) {
        if let Ok(v) = std::env::var("SIEM_ENDPOINT") {
            if !v.is_empty() {
                self.siem_endpoint = Some(v);
            }
        }
        if let Ok(v) = std::env::var("SIEM_API_KEY") {
            if !v.is_empty() {
                self.siem_api_key = Some(v);
            }
        }
        if let Ok(v) = std::env::var("SIEM_BATCH_SIZE") {
            if let Ok(n) = v.parse() {
                self.siem_batch_size = Some(n);
            }
        }
        if let Ok(v) = std::env::var("SIEM_BATCH_INTERVAL") {
            if let Ok(n) = v.parse() {
                self.siem_batch_interval = Some(n);
            }
        }
    }

    /// Build a [`ShipperConfig`] from this config, or `None` if no endpoint is set.
    pub fn shipper_config(&self) -> Option<crate::shipper::ShipperConfig> {
        let endpoint = self.siem_endpoint.as_ref()?;
        Some(crate::shipper::ShipperConfig {
            endpoint: endpoint.clone(),
            api_key: self.siem_api_key.clone().filter(|k| !k.is_empty()),
            batch_size: self.siem_batch_size.unwrap_or(100),
            batch_interval: std::time::Duration::from_secs(
                self.siem_batch_interval.unwrap_or(5),
            ),
        })
    }
}
