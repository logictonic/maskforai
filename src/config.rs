//! Configuration for maskforai.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Filter logging verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterLogLevel {
    #[default]
    Off,
    Summary,
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

/// Extra Whistledown regex rules loaded from `patterns.toml` (`[[whistledown_pattern]]`).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct WhistledownPatternDef {
    pub regex: String,
    pub entity_type: String,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct PatternsConfig {
    #[serde(default)]
    pub pattern: Vec<CustomPatternDef>,
    #[serde(default)]
    pub allowlist: Vec<String>,
    #[serde(default)]
    pub whistledown_pattern: Vec<WhistledownPatternDef>,
}

impl PatternsConfig {
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
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "Failed to parse custom patterns config"
                    );
                    Self::default()
                }
            },
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "Failed to read custom patterns config"
                );
                Self::default()
            }
        }
    }

    fn config_path() -> PathBuf {
        if let Ok(p) = env::var("MASKFORAI_PATTERNS_FILE") {
            return PathBuf::from(p);
        }
        dirs_config_dir().join("maskforai").join("patterns.toml")
    }

    pub fn config_path_string() -> String {
        Self::config_path().to_string_lossy().to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    Claude,
    Openai,
    Compatible,
}

impl ProviderType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Openai => "openai",
            Self::Compatible => "compatible",
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProviderDefinition {
    #[serde(rename = "type")]
    pub provider_type: ProviderType,
    #[serde(default)]
    pub bind: Option<String>,
    pub port: u16,
    pub upstream_url: String,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct ProvidersFile {
    #[serde(default)]
    providers: BTreeMap<String, ProviderDefinition>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub provider_name: String,
    pub provider_type: ProviderType,
    pub port: u16,
    pub upstream_url: String,
    pub bind: String,
    pub filter_log: FilterLogLevel,
    pub min_score: f32,
    pub allowlist: Vec<String>,
    pub audit_log: bool,
    pub custom_patterns: PatternsConfig,
    pub whistledown: bool,
    pub sensitivity: String,
    pub dry_run: bool,
    pub web_port: u16,
    /// When true, use HTTP/1.1 only to upstream (often more stable for SSE through nginx relays).
    pub http1_only: bool,
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub providers: Vec<Config>,
    pub filter_log: FilterLogLevel,
    pub min_score: f32,
    pub allowlist: Vec<String>,
    pub audit_log: bool,
    pub custom_patterns: PatternsConfig,
    pub whistledown: bool,
    pub sensitivity: String,
    pub dry_run: bool,
    pub web_port: u16,
    pub providers_path: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderInfo {
    pub name: String,
    pub provider_type: String,
    pub bind: String,
    pub port: u16,
    pub upstream_url: String,
    pub legacy: bool,
}

impl RuntimeConfig {
    pub fn from_env() -> Result<Self, String> {
        let defaults = GlobalConfig::from_env();
        let providers_path = providers_config_path();
        let definitions = load_provider_definitions(&providers_path)?;
        let providers = if definitions.is_empty() {
            vec![defaults.to_legacy_provider()]
        } else {
            let mut configs = Vec::with_capacity(definitions.len());
            for (name, def) in definitions {
                configs.push(defaults.to_provider_config(&name, def));
            }
            configs
        };
        validate_providers(&providers, defaults.web_port)?;

        Ok(Self {
            providers,
            filter_log: defaults.filter_log,
            min_score: defaults.min_score,
            allowlist: defaults.allowlist,
            audit_log: defaults.audit_log,
            custom_patterns: defaults.custom_patterns,
            whistledown: defaults.whistledown,
            sensitivity: defaults.sensitivity,
            dry_run: defaults.dry_run,
            web_port: defaults.web_port,
            providers_path: providers_path.to_string_lossy().to_string(),
        })
    }

    pub fn provider_infos(&self) -> Vec<ProviderInfo> {
        self.providers
            .iter()
            .map(|cfg| ProviderInfo {
                name: cfg.provider_name.clone(),
                provider_type: cfg.provider_type.as_str().to_string(),
                bind: cfg.bind.clone(),
                port: cfg.port,
                upstream_url: cfg.upstream_url.clone(),
                legacy: cfg.provider_type == ProviderType::Compatible,
            })
            .collect()
    }
}

impl Config {
    pub fn from_env() -> Self {
        RuntimeConfig::from_env()
            .expect("Invalid runtime configuration")
            .providers
            .into_iter()
            .next()
            .expect("At least one provider must be configured")
    }
}

#[derive(Debug, Clone)]
struct GlobalConfig {
    port: u16,
    upstream_url: String,
    bind: String,
    filter_log: FilterLogLevel,
    min_score: f32,
    allowlist: Vec<String>,
    audit_log: bool,
    custom_patterns: PatternsConfig,
    whistledown: bool,
    sensitivity: String,
    dry_run: bool,
    web_port: u16,
    http1_only: bool,
}

impl GlobalConfig {
    fn from_env() -> Self {
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
        let sensitivity =
            env::var("MASKFORAI_SENSITIVITY").unwrap_or_else(|_| "medium".to_string());
        let dry_run = env::var("MASKFORAI_DRY_RUN")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        let web_port: u16 = env::var("MASKFORAI_WEB_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8433);
        let http1_only = env::var("MASKFORAI_HTTP1_ONLY")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        let custom_patterns = PatternsConfig::load();
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
            http1_only,
        }
    }

    fn to_legacy_provider(&self) -> Config {
        self.build_provider_config(
            "default",
            ProviderType::Compatible,
            self.bind.clone(),
            self.port,
            self.upstream_url.clone(),
        )
    }

    fn to_provider_config(&self, name: &str, def: ProviderDefinition) -> Config {
        self.build_provider_config(
            name,
            def.provider_type,
            def.bind.unwrap_or_else(|| self.bind.clone()),
            def.port,
            def.upstream_url.trim_end_matches('/').to_string(),
        )
    }

    fn build_provider_config(
        &self,
        name: &str,
        provider_type: ProviderType,
        bind: String,
        port: u16,
        upstream_url: String,
    ) -> Config {
        Config {
            provider_name: name.to_string(),
            provider_type,
            port,
            upstream_url,
            bind,
            filter_log: self.filter_log,
            min_score: self.min_score,
            allowlist: self.allowlist.clone(),
            audit_log: self.audit_log,
            custom_patterns: self.custom_patterns.clone(),
            whistledown: self.whistledown,
            sensitivity: self.sensitivity.clone(),
            dry_run: self.dry_run,
            web_port: self.web_port,
            http1_only: self.http1_only,
        }
    }
}

fn load_provider_definitions(path: &Path) -> Result<BTreeMap<String, ProviderDefinition>, String> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let providers: ProvidersFile = toml::from_str(&content).map_err(|e| e.to_string())?;
    Ok(providers.providers)
}

fn validate_providers(providers: &[Config], web_port: u16) -> Result<(), String> {
    let mut used = BTreeMap::new();
    for cfg in providers {
        let addr = format!("{}:{}", cfg.bind, cfg.port);
        if let Some(existing) = used.insert(addr.clone(), cfg.provider_name.clone()) {
            return Err(format!(
                "Provider port conflict: {} and {} both use {}",
                existing, cfg.provider_name, addr
            ));
        }
        if web_port > 0 && cfg.port == web_port {
            return Err(format!(
                "Provider {} uses the same port as Web UI: {}",
                cfg.provider_name, web_port
            ));
        }
    }
    Ok(())
}

pub fn providers_config_path() -> PathBuf {
    if let Ok(p) = env::var("MASKFORAI_PROVIDERS_FILE") {
        return PathBuf::from(p);
    }
    dirs_config_dir().join("maskforai").join("providers.toml")
}

pub fn providers_config_path_string() -> String {
    providers_config_path().to_string_lossy().to_string()
}

fn dirs_config_dir() -> PathBuf {
    if let Ok(p) = env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(p);
    }
    if let Ok(userprofile) = env::var("USERPROFILE") {
        return PathBuf::from(userprofile).join(".config");
    }
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home).join(".config");
    }
    PathBuf::from("/tmp").join(".config")
}

/// Path to `env.conf` next to `providers.toml` (same as systemd `EnvironmentFile` on Linux).
pub fn env_config_path() -> PathBuf {
    if let Ok(p) = env::var("MASKFORAI_ENV_FILE") {
        return PathBuf::from(p);
    }
    dirs_config_dir().join("maskforai").join("env.conf")
}

/// Load `KEY=VALUE` lines from `env.conf` into the process environment (does not override
/// already-set variables). Enables `HTTP(S)_PROXY` / `ALL_PROXY` for the upstream `reqwest`
/// client without a shell or systemd, including on Windows.
pub fn load_optional_env_file() -> bool {
    let path = env_config_path();
    if !path.exists() {
        return false;
    }
    let content = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "maskforai: could not read {}: {}",
                path.display(),
                e
            );
            return false;
        }
    };
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_prefix("export ")
            .map(str::trim)
            .unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = value.trim();
        if std::env::var_os(key).is_none() {
            std::env::set_var(key, value);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multi_provider_toml() {
        let content = r#"
[providers.claude]
type = "claude"
port = 8432
upstream_url = "https://api.anthropic.com"

[providers.openai]
type = "openai"
port = 8434
upstream_url = "https://api.openai.com/v1"
"#;

        let parsed: ProvidersFile = toml::from_str(content).unwrap();
        assert_eq!(parsed.providers.len(), 2);
        assert_eq!(
            parsed.providers.get("claude").unwrap().provider_type,
            ProviderType::Claude
        );
        assert_eq!(parsed.providers.get("openai").unwrap().port, 8434);
    }

    #[test]
    fn detects_port_conflicts() {
        let providers = vec![
            Config {
                provider_name: "claude".into(),
                provider_type: ProviderType::Claude,
                port: 8432,
                upstream_url: "https://api.anthropic.com".into(),
                bind: "127.0.0.1".into(),
                filter_log: FilterLogLevel::Off,
                min_score: 0.0,
                allowlist: Vec::new(),
                audit_log: false,
                custom_patterns: PatternsConfig::default(),
                whistledown: true,
                sensitivity: "medium".into(),
                dry_run: false,
                web_port: 8433,
                http1_only: false,
            },
            Config {
                provider_name: "openai".into(),
                provider_type: ProviderType::Openai,
                port: 8432,
                upstream_url: "https://api.openai.com/v1".into(),
                bind: "127.0.0.1".into(),
                filter_log: FilterLogLevel::Off,
                min_score: 0.0,
                allowlist: Vec::new(),
                audit_log: false,
                custom_patterns: PatternsConfig::default(),
                whistledown: true,
                sensitivity: "medium".into(),
                dry_run: false,
                web_port: 8433,
                http1_only: false,
            },
        ];

        assert!(validate_providers(&providers, 8433).is_err());
    }
}
