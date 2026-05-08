//! HTTP proxy logic: mask request body and forward to upstream.
//! Supports whistledown (reversible masking), dry-run, and SSE streaming modes.
//! Part of MaskForAI.

use crate::config::{Config, FilterLogLevel, ProviderType};
use crate::filter_log::FilterLogger;
use crate::mask;
use crate::patterns::MaskResult;
use crate::web::WebState;
use crate::whistledown::{WhistledownMap, WhistledownPatternSet};
use axum::body::Bytes;
use axum::extract::FromRequestParts;
use axum::extract::ws::{Message as AxumWsMsg, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::stream::StreamExt;
use futures::SinkExt;
use reqwest::{Client, NoProxy, Proxy};
use serde_json::Value;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tracing::info;

/// Shared proxy state.
#[derive(Clone)]
pub struct ProxyState {
    pub config: Arc<Config>,
    pub client: Client,
    pub web_state: Option<WebState>,
    pub whistledown_patterns: Arc<WhistledownPatternSet>,
}

fn first_env(names: &[&'static str]) -> Option<String> {
    for name in names {
        if let Ok(v) = std::env::var(name) {
            let t = v.trim();
            if !t.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

fn no_proxy_value() -> Option<NoProxy> {
    first_env(&["NO_PROXY", "no_proxy"])
        .as_ref()
        .and_then(|s| NoProxy::from_string(s))
}

/// Build reqwest with explicit `HTTP(S)_PROXY` / `ALL_PROXY` from the environment.
/// `reqwest` only applies the default system/env proxy matcher if you never call
/// [`ClientBuilder::proxy`]; that path is easy to get wrong, so we configure proxies
/// explicitly when any of the usual env vars is set.
fn build_reqwest_from_env(config: &Config) -> reqwest::Client {
    let mut base = Client::builder();
    if config.http1_only {
        base = base.http1_only();
    }
    let no = no_proxy_value();

    if let Some(url) = first_env(&["ALL_PROXY", "all_proxy"]) {
        match Proxy::all(&url) {
            Ok(p) => {
                if let Ok(c) = base.proxy(p.no_proxy(no.clone())).build() {
                    return c;
                }
                tracing::warn!("Failed to build client with ALL_PROXY; trying HTTP/HTTPS or default");
            }
            Err(e) => tracing::warn!(error = %e, "Invalid ALL_PROXY"),
        }
    }

    let mut b = {
        let mut b = Client::builder();
        if config.http1_only {
            b = b.http1_only();
        }
        b
    };
    let mut n = 0;
    if let Some(url) = first_env(&["HTTP_PROXY", "http_proxy"]) {
        match Proxy::http(&url) {
            Ok(p) => {
                b = b.proxy(p.no_proxy(no.clone()));
                n += 1;
            }
            Err(e) => tracing::warn!(error = %e, "Invalid HTTP_PROXY"),
        }
    }
    if let Some(url) = first_env(&["HTTPS_PROXY", "https_proxy"]) {
        match Proxy::https(&url) {
            Ok(p) => {
                b = b.proxy(p.no_proxy(no));
                n += 1;
            }
            Err(e) => tracing::warn!(error = %e, "Invalid HTTPS_PROXY"),
        }
    }
    if n == 0 {
        return {
            let mut b = Client::builder();
            if config.http1_only {
                b = b.http1_only();
            }
            b.build()
        }
        .expect("Failed to create HTTP client");
    }
    b.build().expect("Failed to create HTTP client with explicit env proxies")
}

impl ProxyState {
    pub fn new(config: Config) -> Self {
        let has_proxy_env = first_env(&["ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"])
            .is_some();
        if has_proxy_env {
            tracing::info!(
                provider = %config.provider_name,
                "Upstream HTTP client: using HTTP_PROXY / HTTPS_PROXY / ALL_PROXY from process environment (URLs not logged)"
            );
        }
        let client = build_reqwest_from_env(&config);
        if config.http1_only {
            tracing::info!(
                provider = %config.provider_name,
                "Upstream HTTP client: HTTP/1.1 only (MASKFORAI_HTTP1_ONLY)"
            );
        }
        let whistledown_patterns = Arc::new(WhistledownPatternSet::compile_from_patterns_config(
            &config.custom_patterns,
        ));
        Self {
            config: Arc::new(config),
            client,
            web_state: None,
            whistledown_patterns,
        }
    }

    pub fn with_web_state(mut self, web_state: WebState) -> Self {
        self.web_state = Some(web_state);
        self
    }
}

/// SSE rehydrator: restores fake values in streaming SSE responses.
struct SseRehydrator {
    map: WhistledownMap,
    buffer: String,
    overlap_size: usize,
}

impl SseRehydrator {
    fn new(map: WhistledownMap) -> Self {
        Self {
            map,
            buffer: String::new(),
            overlap_size: 128,
        }
    }

    fn process_chunk(&mut self, chunk: &str) -> String {
        let combined = format!("{}{}", self.buffer, chunk);
        let restored = self.map.restore(&combined);

        if restored.len() <= self.overlap_size {
            // Chunk too small, buffer entirely
            self.buffer = restored;
            return String::new();
        }

        let raw_emit_end = restored.len() - self.overlap_size;
        // `str` slice endpoints must be UTF-8 char boundaries; overlap is in bytes and can
        // land inside a multibyte codepoint (e.g. Cyrillic in model output).
        let mut emit_end = restored.floor_char_boundary(raw_emit_end);
        if emit_end == 0 && raw_emit_end > 0 {
            emit_end = restored.ceil_char_boundary(raw_emit_end);
        }
        // Find a safe split point (don't split in the middle of a line)
        let split_at = restored[..emit_end]
            .rfind('\n')
            .map(|p| p + 1)
            .unwrap_or(emit_end);

        self.buffer = restored[split_at..].to_string();
        restored[..split_at].to_string()
    }

    fn flush(&mut self) -> String {
        let restored = self.map.restore(&self.buffer);
        self.buffer.clear();
        restored
    }
}

/// Drop hop-by-hop / framing headers before attaching a new streamed body.
/// Hyper sets `Transfer-Encoding` for the client; forwarding upstream
/// `Connection`, `Transfer-Encoding`, or `Content-Length` breaks some clients (e.g. SSE consumers).
fn sanitize_streaming_response_headers(headers: &mut HeaderMap) {
    headers.remove(axum::http::header::CONNECTION);
    headers.remove(axum::http::header::TRANSFER_ENCODING);
    headers.remove(axum::http::header::CONTENT_LENGTH);
    headers.remove(HeaderName::from_static("keep-alive"));
    headers.remove(axum::http::header::TE);
    headers.remove(axum::http::header::TRAILER);
    headers.remove(axum::http::header::UPGRADE);
}

/// Compose upstream URL from configured base and the client request URI.
///
/// Maps bare `/responses` (used by some Codex transports) to `/v1/responses`.  
/// If `upstream_url` ends with `/v1` and the path already starts with `/v1/`, strips the
/// duplicate segment so we never request `/v1/v1/...`.
fn build_upstream_url(config: &Config, uri: &axum::http::Uri) -> String {
    let base = config.upstream_url.trim_end_matches('/');
    let mut path = uri.path().to_string();
    let query = uri
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    if config.provider_type == ProviderType::Openai && path == "/responses"
    {
        path = "/v1/responses".to_string();
    }

    let path_for_join = if base.ends_with("/v1") && path.starts_with("/v1/") {
        path.strip_prefix("/v1")
            .map(|p| format!("/{}", p.trim_start_matches('/')))
            .unwrap_or(path)
    } else {
        path
    };

    format!("{}{}{}", base, path_for_join, query)
}

fn https_to_ws_url(https_url: &str) -> Option<String> {
    if let Some(rest) = https_url.strip_prefix("https://") {
        Some(format!("wss://{}", rest))
    } else if let Some(rest) = https_url.strip_prefix("http://") {
        Some(format!("ws://{}", rest))
    } else {
        None
    }
}

fn is_openai_responses_path(path: &str) -> bool {
    path == "/responses"
        || path.ends_with("/responses")
        || path == "/v1/responses"
        || path.ends_with("/v1/responses")
}

async fn tunnel_openai_responses_ws(
    state: ProxyState,
    client: WebSocket,
    client_uri: axum::http::Uri,
    client_headers: HeaderMap,
) {
    let upstream_https = build_upstream_url(state.config.as_ref(), &client_uri);
    let Some(upstream_ws) = https_to_ws_url(&upstream_https) else {
        tracing::error!(%upstream_https, "WebSocket tunnel requires upstream URL starting with http:// or https://");
        return;
    };

    let uri: http::Uri = match upstream_ws.parse() {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, %upstream_ws, "invalid WebSocket URI");
            return;
        }
    };

    let mut builder =
        tokio_tungstenite::tungstenite::ClientRequestBuilder::new(uri);

    for name in [
        axum::http::header::AUTHORIZATION.as_str(),
        "x-api-key",
        "openai-organization",
        "openai-beta",
        axum::http::header::USER_AGENT.as_str(),
        axum::http::header::SEC_WEBSOCKET_PROTOCOL.as_str(),
    ] {
        if let Some(val) = client_headers.get(name) {
            if let Ok(s) = val.to_str() {
                builder = builder.with_header(name, s);
            }
        }
    }

    let ws_req = match builder.into_client_request() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "failed to build upstream WebSocket request");
            return;
        }
    };

    let (upstream, _resp) = match tokio_tungstenite::connect_async(ws_req).await {
        Ok(x) => x,
        Err(e) => {
            tracing::error!(error = %e, url = %upstream_ws, "upstream WebSocket connect failed");
            return;
        }
    };

    tracing::info!(url = %upstream_ws, "OpenAI Responses WebSocket tunnel established");

    use tokio_tungstenite::tungstenite::Message as TungMsg;

    let (mut up_write, mut up_read) = upstream.split();
    let (mut cx_write, mut cx_read) = client.split();

    let client_to_upstream = async move {
        while let Some(msg) = cx_read.next().await {
            let Ok(msg) = msg else { break };
            let tung = match msg {
                AxumWsMsg::Text(t) => TungMsg::Text(t),
                AxumWsMsg::Binary(b) => TungMsg::Binary(b),
                AxumWsMsg::Ping(p) => TungMsg::Ping(p),
                AxumWsMsg::Pong(p) => TungMsg::Pong(p),
                AxumWsMsg::Close(f) => TungMsg::Close(f.map(|c| {
                    tokio_tungstenite::tungstenite::protocol::CloseFrame {
                        code: c.code.into(),
                        reason: std::borrow::Cow::Owned(c.reason.into_owned()),
                    }
                })),
            };
            if up_write.send(tung).await.is_err() {
                break;
            }
        }
        let _ = up_write.close().await;
    };

    let upstream_to_client = async move {
        while let Some(msg) = up_read.next().await {
            let Ok(msg) = msg else { break };
            let axum_msg = match msg {
                TungMsg::Text(t) => AxumWsMsg::Text(t),
                TungMsg::Binary(b) => AxumWsMsg::Binary(b),
                TungMsg::Ping(p) => AxumWsMsg::Ping(p),
                TungMsg::Pong(p) => AxumWsMsg::Pong(p),
                TungMsg::Close(f) => AxumWsMsg::Close(f.map(|c| axum::extract::ws::CloseFrame {
                    code: c.code.into(),
                    reason: std::borrow::Cow::Owned(c.reason.into_owned()),
                })),
                TungMsg::Frame(_) => continue,
            };
            if cx_write.send(axum_msg).await.is_err() {
                break;
            }
        }
        let _ = cx_write.close().await;
    };

    tokio::join!(client_to_upstream, upstream_to_client);
}

/// HTTP entry for every provider listener. When `provider_type` is Openai and the request is a
/// valid GET WebSocket upgrade on the Responses API paths, tunnels to upstream `wss://`; otherwise
/// delegates to [`proxy_handler`].
pub async fn openai_smart_proxy(
    State(state): State<ProxyState>,
    req: Request<axum::body::Body>,
) -> Response {
    if state.config.provider_type != ProviderType::Openai {
        return proxy_handler(State(state), req).await;
    }

    let (mut parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    if parts.method == axum::http::Method::GET && is_openai_responses_path(&path) {
        let uri = parts.uri.clone();
        let client_headers = parts.headers.clone();
        match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
            Ok(ws_up) => {
                return ws_up
                    .on_upgrade(move |socket| {
                        let st = state.clone();
                        async move {
                            tunnel_openai_responses_ws(st, socket, uri, client_headers).await
                        }
                    })
                    .into_response();
            }
            Err(_) => {}
        }
    }

    let req = Request::from_parts(parts, body);
    proxy_handler(State(state), req).await
}

/// Proxy handler: intercept, mask, and forward.
pub async fn proxy_handler(
    State(state): State<ProxyState>,
    req: Request<axum::body::Body>,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str();
    let provider_tag = format!("[{}]", state.config.provider_name);
    let request_label = format!("{} {} {}", provider_tag, method, path);
    let content_type = req
        .headers()
        .get("content-type")
        .cloned()
        .unwrap_or_else(|| axum::http::HeaderValue::from_static("application/json"));

    info!(
        provider = %state.config.provider_name,
        provider_type = %state.config.provider_type.as_str(),
        %method,
        %path,
        "Proxying request"
    );

    if let Some(web_state) = &state.web_state {
        web_state.send_log(&format!("[request] {}", request_label));
    }

    let upstream = build_upstream_url(&state.config, req.uri());

    // Forward headers but remove hop-by-hop headers that reqwest should set itself
    let mut forwarded_headers = req.headers().clone();
    forwarded_headers.remove("host");
    forwarded_headers.remove("content-length");
    forwarded_headers.remove("transfer-encoding");
    forwarded_headers.remove("connection");

    let upstream_req = state
        .client
        .request(req.method().clone(), &upstream)
        .headers(forwarded_headers);

    let body = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "Failed to read request body");
            return (StatusCode::BAD_REQUEST, "Failed to read body").into_response();
        }
    };

    let is_claude_messages = path == "/v1/messages"
        || path.ends_with("/v1/messages")
        || path == "/v1/messages/count_tokens"
        || path.ends_with("/v1/messages/count_tokens");
    let is_openai_chat = path == "/v1/chat/completions" || path.ends_with("/v1/chat/completions");
    let is_responses = path == "/responses"
        || path.ends_with("/responses")
        || path == "/v1/responses"
        || path.ends_with("/v1/responses");

    let is_messages = match state.config.provider_type {
        ProviderType::Claude => is_claude_messages,
        ProviderType::Openai => is_openai_chat,
        ProviderType::Compatible => is_claude_messages || is_openai_chat,
    };

    let is_masked_path = is_messages || is_responses;

    let dry_run = state.config.dry_run;
    let should_collect_events = state.web_state.is_some() || state.config.filter_log.is_enabled();
    let should_emit_filter_logs = state.config.filter_log.is_enabled();
    let logger_detailed = state.config.filter_log == FilterLogLevel::Detailed;
    let mut logger = if should_collect_events {
        Some(if should_emit_filter_logs && state.config.audit_log {
            FilterLogger::with_audit(logger_detailed)
        } else {
            FilterLogger::new(logger_detailed)
        })
    } else {
        None
    };
    let mut request_masked = false;
    let mut mask_types: Vec<String> = Vec::new();

    let (body_to_send, whistledown_map) = if is_masked_path {
        if let Ok(mut json) = serde_json::from_slice::<Value>(&body) {
            let min_score = state.config.min_score;
            let allowlist = &state.config.allowlist;
            let whistledown_enabled = state.config.whistledown;

            // Whistledown: reversible tokens on Messages, chat completions, or Responses API shapes.
            let wmap = if whistledown_enabled && !dry_run && (is_messages || is_responses) {
                let mut map = WhistledownMap::new(
                    state.whistledown_patterns.clone(),
                    state.config.allowlist.clone(),
                );
                if is_messages {
                    map.apply(&mut json);
                } else {
                    map.apply_responses(&mut json);
                }
                if map.has_mappings() {
                    tracing::info!(
                        path = %path,
                        count = map.mappings_count(),
                        tokens = %map.summary(),
                        "Whistledown applied"
                    );
                }
                Some(map)
            } else {
                None
            };

            // Standard masking: Messages API vs Responses API structure
            let block_result = if let Some(logger) = logger.as_mut() {
                let mut log = Some(&mut *logger);
                let block_result = if is_responses {
                    mask::mask_responses_request_body_full(
                        &mut json, min_score, allowlist, &mut log,
                    )
                } else {
                    mask::mask_request_body_full(&mut json, min_score, allowlist, &mut log)
                };
                let summary = logger.summary();
                request_masked = !summary.is_empty();
                mask_types = summary.keys().cloned().collect();

                if logger.has_events() {
                    if dry_run && should_emit_filter_logs {
                        tracing::info!(path = %path, "[DRY-RUN] would have masked");
                    }
                    if should_emit_filter_logs {
                        logger.emit(&path);
                    }
                    if let Some(web_state) = &state.web_state {
                        for event in logger.events() {
                            web_state.send_log(&format!("[mask] {} :: {}", request_label, event));
                        }
                    }
                }

                block_result
            } else if is_responses {
                mask::mask_responses_request_body_full(&mut json, min_score, allowlist, &mut None)
            } else {
                mask::mask_request_body_full(&mut json, min_score, allowlist, &mut None)
            };

            if !dry_run {
                if let Some(MaskResult::Blocked {
                    mask_type,
                    matched_preview,
                }) = block_result
                {
                    tracing::warn!(
                        mask_type = %mask_type,
                        preview = %matched_preview,
                        path = %path,
                        "Request BLOCKED: sensitive content detected"
                    );
                    if let Some(web_state) = &state.web_state {
                        web_state.record_request(
                            &state.config.provider_name,
                            request_masked,
                            true,
                            &mask_types,
                        );
                        web_state.send_log(&format!(
                            "[blocked] {} :: {} detected",
                            request_label, mask_type
                        ));
                    }
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("Request blocked: {} detected", mask_type),
                    )
                        .into_response();
                }
            }

            if let Some(web_state) = &state.web_state {
                web_state.record_request(
                    &state.config.provider_name,
                    request_masked,
                    false,
                    &mask_types,
                );
            }

            if dry_run {
                // In dry-run, send original body unmodified
                (body, None)
            } else {
                match serde_json::to_vec(&json) {
                    Ok(v) => (Bytes::from(v), wmap),
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to serialize masked body");
                        return (StatusCode::INTERNAL_SERVER_ERROR, "Serialization error")
                            .into_response();
                    }
                }
            }
        } else {
            if let Some(web_state) = &state.web_state {
                web_state.record_request(&state.config.provider_name, false, false, &[]);
            }
            (body, None)
        }
    } else {
        if let Some(web_state) = &state.web_state {
            web_state.record_request(&state.config.provider_name, false, false, &[]);
        }
        (body, None)
    };

    let upstream_req = upstream_req
        .header("content-type", content_type)
        .body(body_to_send);

    let upstream_request = upstream_req
        .build()
        .expect("Failed to build upstream request");
    match state.client.execute(upstream_request).await {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                tracing::warn!(
                    provider = %state.config.provider_name,
                    path = %path,
                    status = %status,
                    "Upstream returned non-success status (Codex may retry and show 'high demand')"
                );
            }
            if let Some(web_state) = &state.web_state {
                let masked_suffix = if request_masked {
                    format!(" masked={}", mask_types.join(","))
                } else {
                    String::new()
                };
                web_state.send_log(&format!(
                    "[response] {} -> {}{}",
                    request_label, status, masked_suffix
                ));
            }
            let headers = resp.headers().clone();
            let is_sse = headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|ct| ct.contains("text/event-stream"))
                .unwrap_or(false);

            if let Some(wmap) = whistledown_map {
                if is_sse && wmap.has_mappings() {
                    // SSE streaming rehydration with overlap buffer
                    let mut rehydrator = SseRehydrator::new(wmap);
                    let byte_stream = resp.bytes_stream();

                    let mapped_stream = byte_stream
                        .map(|r| r.map(Some))
                        .chain(futures::stream::once(async {
                            Ok::<_, reqwest::Error>(None)
                        }))
                        .map(move |chunk_result| {
                            match chunk_result {
                                Ok(Some(bytes)) => {
                                    let chunk_str = String::from_utf8_lossy(&bytes);
                                    let output = rehydrator.process_chunk(&chunk_str);
                                    Ok::<_, reqwest::Error>(Bytes::from(output))
                                }
                                Ok(None) => {
                                    // Stream ended — flush remaining buffer
                                    let output = rehydrator.flush();
                                    Ok(Bytes::from(output))
                                }
                                Err(e) => Err(e),
                            }
                        });

                    // We need to flush the buffer at the end
                    // Use a wrapper that flushes on stream end
                    let body = axum::body::Body::from_stream(mapped_stream);
                    let mut response = Response::new(body);
                    *response.status_mut() = status;
                    let mut resp_headers = headers;
                    sanitize_streaming_response_headers(&mut resp_headers);
                    *response.headers_mut() = resp_headers;
                    response
                } else if is_responses && !wmap.has_mappings() {
                    // Streaming JSON/chunked Responses API: buffering the full body stalls Codex (RST).
                    let body = axum::body::Body::from_stream(resp.bytes_stream());
                    let mut response = Response::new(body);
                    *response.status_mut() = status;
                    let mut resp_headers = headers;
                    sanitize_streaming_response_headers(&mut resp_headers);
                    *response.headers_mut() = resp_headers;
                    response
                } else {
                    // Non-SSE whistledown with mappings: must buffer to restore tokens.
                    match resp.bytes().await {
                        Ok(body_bytes) => {
                            let body_str = String::from_utf8_lossy(&body_bytes);
                            let unmasked = wmap.restore(&body_str);
                            if wmap.has_mappings() {
                                tracing::info!(
                                    count = wmap.mappings_count(),
                                    "Whistledown restored tokens in response"
                                );
                            }
                            let mut response =
                                Response::new(axum::body::Body::from(unmasked.clone()));
                            *response.status_mut() = status;
                            *response.headers_mut() = headers;
                            response.headers_mut().remove("content-length");
                            response.headers_mut().insert(
                                "content-length",
                                axum::http::HeaderValue::from_str(&unmasked.len().to_string())
                                    .unwrap(),
                            );
                            response
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Failed to read upstream response for whistledown");
                            (StatusCode::BAD_GATEWAY, format!("Response error: {}", e))
                                .into_response()
                        }
                    }
                }
            } else {
                // Stream all non-whistledown replies, including `/responses` (Codex expects chunks).
                let body = axum::body::Body::from_stream(resp.bytes_stream());
                let mut response = Response::new(body);
                *response.status_mut() = status;
                let mut resp_headers = headers;
                sanitize_streaming_response_headers(&mut resp_headers);
                *response.headers_mut() = resp_headers;
                response
            }
        }
        Err(e) => {
            tracing::error!(error = ?e, "Upstream request failed");
            if let Some(web_state) = &state.web_state {
                web_state.send_log(&format!("[error] {} :: upstream {}", request_label, e));
            }
            (StatusCode::BAD_GATEWAY, format!("Upstream error: {}", e)).into_response()
        }
    }
}

#[cfg(test)]
mod build_upstream_url_tests {
    use super::build_upstream_url;
    use crate::config::{Config, FilterLogLevel, PatternsConfig, ProviderType};

    fn cfg(upstream: &str, ptype: ProviderType) -> Config {
        Config {
            provider_name: "t".into(),
            provider_type: ptype,
            port: 1,
            upstream_url: upstream.into(),
            bind: "127.0.0.1".into(),
            filter_log: FilterLogLevel::Off,
            min_score: 0.0,
            allowlist: vec![],
            audit_log: false,
            custom_patterns: PatternsConfig::default(),
            whistledown: false,
            sensitivity: "medium".into(),
            dry_run: false,
            web_port: 0,
            http1_only: false,
        }
    }

    #[test]
    fn openai_no_double_v1_when_base_has_v1() {
        let c = cfg("https://example/v1", ProviderType::Openai);
        let u: axum::http::Uri = "/v1/responses".parse().unwrap();
        assert_eq!(
            build_upstream_url(&c, &u),
            "https://example/v1/responses"
        );
    }

    #[test]
    fn openai_bare_responses_becomes_v1() {
        let c = cfg("https://example", ProviderType::Openai);
        let u: axum::http::Uri = "/responses".parse().unwrap();
        assert_eq!(
            build_upstream_url(&c, &u),
            "https://example/v1/responses"
        );
    }

    #[test]
    fn openai_bare_responses_with_base_suffix_v1() {
        let c = cfg("https://example/v1", ProviderType::Openai);
        let u: axum::http::Uri = "/responses".parse().unwrap();
        assert_eq!(
            build_upstream_url(&c, &u),
            "https://example/v1/responses"
        );
    }

    #[test]
    fn compatible_keeps_bare_responses_path() {
        let c = cfg("https://example", ProviderType::Compatible);
        let u: axum::http::Uri = "/responses".parse().unwrap();
        assert_eq!(build_upstream_url(&c, &u), "https://example/responses");
    }
}
