//! Web UI API routes for MaskForAI configuration management.
//!
//! Provides REST API on a separate port for:
//! - Viewing/editing configuration
//! - Viewing masking statistics
//! - Managing custom patterns
//! - Viewing filter logs
//! - Live log streaming via WebSocket

use axum::extract::{ws, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Default, Serialize)]
pub struct ProviderStats {
    pub requests_total: u64,
    pub requests_masked: u64,
    pub requests_blocked: u64,
    pub masks_by_type: HashMap<String, u64>,
}

/// Stats tracked by the proxy.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProxyStats {
    pub requests_total: u64,
    pub requests_masked: u64,
    pub requests_blocked: u64,
    pub masks_by_type: HashMap<String, u64>,
    pub by_provider: HashMap<String, ProviderStats>,
    pub uptime_secs: u64,
}

/// Shared state for the web UI.
#[derive(Clone)]
pub struct WebState {
    pub stats: Arc<Mutex<ProxyStats>>,
    pub config_path: String,
    pub providers_path: String,
    pub providers: Arc<Vec<crate::config::ProviderInfo>>,
    pub log_tx: broadcast::Sender<String>,
    pub start_time: std::time::Instant,
}

impl WebState {
    pub fn new(runtime: &crate::config::RuntimeConfig) -> Self {
        let (log_tx, _) = broadcast::channel(256);
        Self {
            stats: Arc::new(Mutex::new(ProxyStats::default())),
            config_path: crate::config::PatternsConfig::config_path_string(),
            providers_path: runtime.providers_path.clone(),
            providers: Arc::new(runtime.provider_infos()),
            log_tx,
            start_time: std::time::Instant::now(),
        }
    }

    /// Record a proxy request.
    pub fn record_request(
        &self,
        provider_name: &str,
        masked: bool,
        blocked: bool,
        mask_types: &[String],
    ) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.requests_total += 1;
            if masked {
                stats.requests_masked += 1;
            }
            if blocked {
                stats.requests_blocked += 1;
            }
            for t in mask_types {
                *stats.masks_by_type.entry(t.clone()).or_insert(0) += 1;
            }

            let provider_stats = stats
                .by_provider
                .entry(provider_name.to_string())
                .or_default();
            provider_stats.requests_total += 1;
            if masked {
                provider_stats.requests_masked += 1;
            }
            if blocked {
                provider_stats.requests_blocked += 1;
            }
            for t in mask_types {
                *provider_stats.masks_by_type.entry(t.clone()).or_insert(0) += 1;
            }
        }
    }

    /// Send a log event to all WebSocket subscribers.
    pub fn send_log(&self, msg: &str) {
        let _ = self.log_tx.send(msg.to_string());
    }
}

/// Build the web UI router.
pub fn web_router(state: WebState) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/api/status", get(status_handler))
        .route("/api/stats", get(stats_handler))
        .route("/api/providers", get(get_providers_handler))
        .route("/api/config", get(get_config_handler))
        .route("/api/config", post(update_config_handler))
        .route("/api/patterns", get(get_patterns_handler))
        .route("/api/patterns", post(add_pattern_handler))
        .route("/api/patterns/{index}", delete(delete_pattern_handler))
        .route("/api/allowlist", get(get_allowlist_handler))
        .route("/api/allowlist", post(add_allowlist_handler))
        .route("/api/allowlist/{value}", delete(delete_allowlist_handler))
        .route("/api/test", post(test_mask_handler))
        .route("/ws/logs", get(ws_logs_handler))
        .with_state(state)
}

async fn index_handler() -> Html<&'static str> {
    Html(include_str!("web_ui.html"))
}

#[derive(Serialize)]
struct StatusResponse {
    status: &'static str,
    version: &'static str,
    uptime_secs: u64,
    providers_count: usize,
}

async fn status_handler(State(state): State<WebState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        status: "running",
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.start_time.elapsed().as_secs(),
        providers_count: state.providers.len(),
    })
}

async fn stats_handler(State(state): State<WebState>) -> Json<ProxyStats> {
    let mut stats = state.stats.lock().unwrap().clone();
    stats.uptime_secs = state.start_time.elapsed().as_secs();
    Json(stats)
}

#[derive(Serialize)]
struct ProvidersResponse {
    providers: Vec<crate::config::ProviderInfo>,
    config_path: String,
}

async fn get_providers_handler(State(state): State<WebState>) -> Json<ProvidersResponse> {
    Json(ProvidersResponse {
        providers: state.providers.as_ref().clone(),
        config_path: state.providers_path.clone(),
    })
}

#[derive(Serialize)]
struct ConfigResponse {
    sensitivity: String,
    min_score: f32,
    whistledown: bool,
    dry_run: bool,
    audit_log: bool,
    filter_log: String,
    providers_count: usize,
    providers_path: String,
}

async fn get_config_handler(State(state): State<WebState>) -> Json<ConfigResponse> {
    let config = crate::config::RuntimeConfig::from_env().expect("Invalid runtime configuration");
    Json(ConfigResponse {
        sensitivity: config.sensitivity,
        min_score: config.min_score,
        whistledown: config.whistledown,
        dry_run: config.dry_run,
        audit_log: config.audit_log,
        filter_log: format!("{:?}", config.filter_log),
        providers_count: state.providers.len(),
        providers_path: state.providers_path.clone(),
    })
}

#[derive(Deserialize)]
struct ConfigUpdate {
    #[serde(default)]
    sensitivity: Option<String>,
    #[serde(default)]
    min_score: Option<f32>,
    #[serde(default)]
    whistledown: Option<bool>,
    #[serde(default)]
    dry_run: Option<bool>,
    #[serde(default)]
    audit_log: Option<bool>,
    #[serde(default)]
    filter_log: Option<String>,
}

async fn update_config_handler(Json(update): Json<ConfigUpdate>) -> Response {
    let env_conf_path = find_env_conf();
    let mut lines: Vec<String> = if let Ok(content) = std::fs::read_to_string(&env_conf_path) {
        content.lines().map(|l| l.to_string()).collect()
    } else {
        Vec::new()
    };

    if let Some(v) = update.sensitivity {
        set_env_line(&mut lines, "MASKFORAI_SENSITIVITY", &v);
    }
    if let Some(v) = update.min_score {
        set_env_line(&mut lines, "MASKFORAI_MIN_SCORE", &v.to_string());
    }
    if let Some(v) = update.whistledown {
        set_env_line(&mut lines, "MASKFORAI_WHISTLEDOWN", &v.to_string());
    }
    if let Some(v) = update.dry_run {
        set_env_line(&mut lines, "MASKFORAI_DRY_RUN", &v.to_string());
    }
    if let Some(v) = update.audit_log {
        set_env_line(&mut lines, "MASKFORAI_AUDIT_LOG", &v.to_string());
    }
    if let Some(v) = update.filter_log {
        set_env_line(&mut lines, "MASKFORAI_LOG_FILTER", &v);
    }

    match std::fs::write(&env_conf_path, lines.join("\n") + "\n") {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "saved",
                "note": "Restart proxy to apply changes"
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to write config: {}", e),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
struct PatternResponse {
    patterns: Vec<PatternInfo>,
}

#[derive(Serialize, Deserialize, Clone)]
struct PatternInfo {
    pattern: String,
    replacement: String,
    mask_type: String,
    score: f32,
    action: String,
}

async fn get_patterns_handler(State(state): State<WebState>) -> Json<PatternResponse> {
    let config = load_patterns_toml(&state.config_path);
    let patterns: Vec<PatternInfo> = config
        .pattern
        .iter()
        .map(|p| PatternInfo {
            pattern: p.pattern.clone(),
            replacement: p.replacement.clone(),
            mask_type: p.mask_type.clone(),
            score: p.score,
            action: format!("{:?}", p.action),
        })
        .collect();
    Json(PatternResponse { patterns })
}

async fn add_pattern_handler(
    State(state): State<WebState>,
    Json(new_pattern): Json<PatternInfo>,
) -> Response {
    if regex::Regex::new(&new_pattern.pattern).is_err() {
        return (StatusCode::BAD_REQUEST, "Invalid regex pattern").into_response();
    }

    let mut config = load_patterns_toml(&state.config_path);
    config.pattern.push(crate::config::CustomPatternDef {
        pattern: new_pattern.pattern,
        replacement: new_pattern.replacement,
        mask_type: new_pattern.mask_type,
        score: new_pattern.score,
        action: match new_pattern.action.to_lowercase().as_str() {
            "block" => crate::config::CustomAction::Block,
            "observe" => crate::config::CustomAction::Observe,
            _ => crate::config::CustomAction::Mask,
        },
    });

    match save_patterns_toml(&state.config_path, &config) {
        Ok(_) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"status": "added"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save: {}", e),
        )
            .into_response(),
    }
}

async fn delete_pattern_handler(
    State(state): State<WebState>,
    axum::extract::Path(index): axum::extract::Path<usize>,
) -> Response {
    let mut config = load_patterns_toml(&state.config_path);
    if index >= config.pattern.len() {
        return (StatusCode::NOT_FOUND, "Pattern index out of range").into_response();
    }
    config.pattern.remove(index);
    match save_patterns_toml(&state.config_path, &config) {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "deleted"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save: {}", e),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
struct AllowlistResponse {
    items: Vec<String>,
}

async fn get_allowlist_handler(State(state): State<WebState>) -> Json<AllowlistResponse> {
    let config = load_patterns_toml(&state.config_path);
    Json(AllowlistResponse {
        items: config.allowlist,
    })
}

#[derive(Deserialize)]
struct AllowlistAdd {
    value: String,
}

async fn add_allowlist_handler(
    State(state): State<WebState>,
    Json(item): Json<AllowlistAdd>,
) -> Response {
    let mut config = load_patterns_toml(&state.config_path);
    if !config.allowlist.contains(&item.value) {
        config.allowlist.push(item.value);
    }
    match save_patterns_toml(&state.config_path, &config) {
        Ok(_) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"status": "added"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save: {}", e),
        )
            .into_response(),
    }
}

async fn delete_allowlist_handler(
    State(state): State<WebState>,
    axum::extract::Path(value): axum::extract::Path<String>,
) -> Response {
    let mut config = load_patterns_toml(&state.config_path);
    config.allowlist.retain(|v| v != &value);
    match save_patterns_toml(&state.config_path, &config) {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "deleted"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save: {}", e),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct TestMaskRequest {
    text: String,
}

#[derive(Serialize)]
struct TestMaskResponse {
    original: String,
    masked: String,
    detections: Vec<String>,
}

async fn test_mask_handler(Json(req): Json<TestMaskRequest>) -> Json<TestMaskResponse> {
    use crate::filter_log::FilterLogger;
    let mut logger = FilterLogger::new(true);
    let mut log = Some(&mut logger);
    let result = crate::patterns::mask_text_full(&req.text, 0.0, &[], &mut log, None);
    let masked = match result {
        crate::patterns::MaskResult::Ok(s) => s,
        crate::patterns::MaskResult::Blocked { mask_type, .. } => {
            format!("[BLOCKED: {}]", mask_type)
        }
    };
    let detections = logger.events().iter().map(|e| e.to_string()).collect();
    Json(TestMaskResponse {
        original: req.text,
        masked,
        detections,
    })
}

async fn ws_logs_handler(State(state): State<WebState>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| handle_ws_logs(socket, state))
}

async fn handle_ws_logs(mut socket: ws::WebSocket, state: WebState) {
    let mut rx = state.log_tx.subscribe();
    while let Ok(msg) = rx.recv().await {
        if socket.send(ws::Message::Text(msg.into())).await.is_err() {
            break;
        }
    }
}

fn find_env_conf() -> String {
    let candidates = [
        std::env::var("MASKFORAI_ENV_CONF").unwrap_or_default(),
        format!(
            "{}/.config/maskforai/env.conf",
            std::env::var("HOME").unwrap_or_default()
        ),
        "env.conf".to_string(),
    ];
    for c in &candidates {
        if !c.is_empty() && std::path::Path::new(c).exists() {
            return c.clone();
        }
    }
    candidates[1].clone()
}

fn set_env_line(lines: &mut Vec<String>, key: &str, value: &str) {
    let prefix = format!("{}=", key);
    if let Some(pos) = lines.iter().position(|l| l.starts_with(&prefix)) {
        lines[pos] = format!("{}={}", key, value);
    } else {
        lines.push(format!("{}={}", key, value));
    }
}

fn load_patterns_toml(config_path: &str) -> crate::config::PatternsConfig {
    let path = if config_path.is_empty() {
        crate::config::PatternsConfig::config_path_string()
    } else {
        config_path.to_string()
    };
    if let Ok(content) = std::fs::read_to_string(&path) {
        toml::from_str(&content).unwrap_or_default()
    } else {
        crate::config::PatternsConfig::default()
    }
}

fn save_patterns_toml(
    config_path: &str,
    config: &crate::config::PatternsConfig,
) -> Result<(), String> {
    let path = if config_path.is_empty() {
        crate::config::PatternsConfig::config_path_string()
    } else {
        config_path.to_string()
    };
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let mut output = String::new();
    if !config.allowlist.is_empty() {
        output.push_str("allowlist = [\n");
        for item in &config.allowlist {
            output.push_str(&format!("    \"{}\",\n", item.replace('"', "\\\"")));
        }
        output.push_str("]\n\n");
    }
    for p in &config.pattern {
        output.push_str("[[pattern]]\n");
        output.push_str(&format!(
            "pattern = \"{}\"\n",
            p.pattern.replace('\\', "\\\\").replace('"', "\\\"")
        ));
        output.push_str(&format!(
            "replacement = \"{}\"\n",
            p.replacement.replace('"', "\\\"")
        ));
        output.push_str(&format!("mask_type = \"{}\"\n", p.mask_type));
        output.push_str(&format!("score = {:.1}\n", p.score));
        output.push_str(&format!("action = \"{:?}\"\n\n", p.action).to_lowercase());
    }
    std::fs::write(&path, output).map_err(|e| e.to_string())
}
