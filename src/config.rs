//! Configuration for maskforai.

use std::env;
use std::fs;
use std::path::PathBuf;

/// Filter logging verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterLogLevel {
    /// No filter logging.
    #[default]
    Off,
    /// Log summary per request: "filter: api_key=2, email=1".
    Summary,
    /// Log each mask type with context (path/field).
    Detailed,
}

impl FilterLogLevel {
    pub fn from_env() -> Self {
        let v = env::var("MASKFORAI_LOG_FILTER")
            .unwrap_or_default()
            .to_lowercase();
        match v.as_str() {
            "1" | "true" | "yes" | "summary" => Self::Summary,
            "2" | "detailed" | "debug" => Self::Detailed,
            _ => Self::Off,
        }
    }

    pub fn is_enabled(self) -> bool {
        self != Self::Off
    }
}

/// Custom pattern definition loaded from config file.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CustomPatternDef {
    pub pattern: String,
    pub replacement: String,
    pub mask_type: String,
    #[serde(default = "default_score")]
    pub score: f32,
    #[serde(default)]
    pub action: CustomAction,
}

fn default_score() -> f32 {
    0.8
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CustomAction {
    #[default]
    Mask,
    Block,
    Observe,
}

/// Custom patterns config file structure.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct PatternsConfig {
    #[serde(default)]
    pub pattern: Vec<CustomPatternDef>,
    #[serde(default)]
    pub allowlist: Vec<String>,
}

impl PatternsConfig {
    /// Load custom patterns from config file if it exists.
    pub fn load() -> Self {
        let path = Self::config_path();
        if !path.exists() {
            return Self::default();
        }
        match fs::read_to_string(&path) {
            Ok(content) => match toml::from_str(&content) {
                Ok(config) => {
                    tracing::info!(path = %path.display(), "Loaded custom patterns config");
                    config
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "Failed to parse custom patterns config");
                    Self::default()
                }
            },
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "Failed to read custom patterns config");
                Self::default()
            }
        }
    }

    fn config_path() -> PathBuf {
        if let Ok(p) = env::var("MASKFORAI_PATTERNS_FILE") {
            return PathBuf::from(p);
        }
        let config_dir = dirs_config_dir().join("maskforai");
        config_dir.join("patterns.toml")
    }

    /// Config path as String (for web UI).
    pub fn config_path_string() -> String {
        Self::config_path().to_string_lossy().to_string()
    }
}

/// Get the user config directory.
fn dirs_config_dir() -> PathBuf {
    env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".config")
        })
}

/// Proxy configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Port to listen on.
    pub port: u16,
    /// Upstream Anthropic API base URL (e.g. relay or api.anthropic.com).
    pub upstream_url: String,
    /// Bind address.
    pub bind: String,
    /// Filter logging level.
    pub filter_log: FilterLogLevel,
    /// Minimum confidence score for masking (0.0–1.0).
    pub min_score: f32,
    /// Allow-list of values that should never be masked.
    pub allowlist: Vec<String>,
    /// Enable audit logging with SHA256 hashes.
    pub audit_log: bool,
    /// Custom patterns loaded from config file.
    pub custom_patterns: PatternsConfig,
    /// Enable whistledown reversible masking mode.
    pub whistledown: bool,
    /// Sensitivity level (low, medium, high, paranoid).
    pub sensitivity: String,
    /// Dry-run mode: log detections but don't modify traffic.
    pub dry_run: bool,
    /// Web UI port (0 = disabled).
    pub web_port: u16,
}

impl Config {
    pub fn from_env() -> Self {
        let port = env::var("MASKFORAI_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8432);

        let upstream_url = env::var("MASKFORAI_UPSTREAM")
            .or_else(|_| env::var("ANTHROPIC_BASE_URL"))
            .unwrap_or_else(|_| "https://api.anthropic.com".to_string());

        let bind = env::var("MASKFORAI_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());

        let filter_log = FilterLogLevel::from_env();

        let min_score: f32 = env::var("MASKFORAI_MIN_SCORE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);

        let allowlist: Vec<String> = env::var("MASKFORAI_ALLOWLIST")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let audit_log = env::var("MASKFORAI_AUDIT_LOG")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

        let whistledown = env::var("MASKFORAI_WHISTLEDOWN")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(true);

        let sensitivity = env::var("MASKFORAI_SENSITIVITY")
            .unwrap_or_else(|_| "medium".to_string());

        let dry_run = env::var("MASKFORAI_DRY_RUN")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

        let web_port: u16 = env::var("MASKFORAI_WEB_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8433);

        let custom_patterns = PatternsConfig::load();

        // Merge custom allowlist with env allowlist
        let mut all_allowlist = allowlist;
        all_allowlist.extend(custom_patterns.allowlist.clone());

        Self {
            port,
            upstream_url: upstream_url.trim_end_matches('/').to_string(),
            bind,
            filter_log,
            min_score,
            allowlist: all_allowlist,
            audit_log,
            custom_patterns,
            whistledown,
            sensitivity,
            dry_run,
            web_port,
        }
    }
}
