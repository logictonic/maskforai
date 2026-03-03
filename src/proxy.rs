//! HTTP proxy logic: mask request body and forward to upstream.
//! Supports whistledown (reversible masking), dry-run, and SSE streaming modes.
//! Part of MaskForAI.

use crate::config::{Config, FilterLogLevel};
use crate::filter_log::FilterLogger;
use crate::mask;
use crate::patterns::MaskResult;
use crate::whistledown::WhistledownMap;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::stream::StreamExt;
use reqwest::Client;
use serde_json::Value;
use std::sync::Arc;
use tracing::info;

/// Shared proxy state.
#[derive(Clone)]
pub struct ProxyState {
    pub config: Arc<Config>,
    pub client: Client,
}

impl ProxyState {
    pub fn new(config: Config) -> Self {
        let client = Client::builder()
            .build()
            .expect("Failed to create HTTP client");
        Self {
            config: Arc::new(config),
            client,
        }
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

        let emit_end = restored.len() - self.overlap_size;
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

/// Proxy handler: intercept, mask, and forward.
pub async fn proxy_handler(
    State(state): State<ProxyState>,
    req: Request<axum::body::Body>,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str();
    let content_type = req
        .headers()
        .get("content-type")
        .cloned()
        .unwrap_or_else(|| axum::http::HeaderValue::from_static("application/json"));

    info!(%method, %path, "Proxying request");

    let upstream = format!("{}{}", state.config.upstream_url, req.uri());

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

    let is_messages = path == "/v1/messages" || path.ends_with("/v1/messages")
        || path == "/v1/messages/count_tokens"
        || path.ends_with("/v1/messages/count_tokens")
        // OpenAI-compatible endpoints
        || path == "/v1/chat/completions"
        || path.ends_with("/v1/chat/completions");

    let dry_run = state.config.dry_run;

    let (body_to_send, whistledown_map) = if is_messages {
        if let Ok(mut json) = serde_json::from_slice::<Value>(&body) {
            let min_score = state.config.min_score;
            let allowlist = &state.config.allowlist;
            let whistledown_enabled = state.config.whistledown;

            // Whistledown mode: reversible masking
            let wmap = if whistledown_enabled && !dry_run {
                let mut map = WhistledownMap::new();
                map.apply(&mut json);
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

            // Standard masking (on top of whistledown if both enabled)
            if state.config.filter_log.is_enabled() {
                let detailed = state.config.filter_log == FilterLogLevel::Detailed;
                let mut logger = if state.config.audit_log {
                    FilterLogger::with_audit(detailed)
                } else {
                    FilterLogger::new(detailed)
                };
                let mut log = Some(&mut logger);
                let block_result = mask::mask_request_body_full(&mut json, min_score, allowlist, &mut log);
                if !dry_run {
                    if let Some(MaskResult::Blocked { mask_type, matched_preview }) = block_result {
                        tracing::warn!(
                            mask_type = %mask_type,
                            preview = %matched_preview,
                            path = %path,
                            "Request BLOCKED: sensitive content detected"
                        );
                        return (
                            StatusCode::BAD_REQUEST,
                            format!("Request blocked: {} detected", mask_type),
                        ).into_response();
                    }
                }
                if logger.has_events() {
                    if dry_run {
                        tracing::info!(path = %path, "[DRY-RUN] would have masked");
                    }
                    logger.emit(&path);
                }
            } else if !dry_run {
                let block_result = mask::mask_request_body_full(&mut json, min_score, allowlist, &mut None);
                if let Some(MaskResult::Blocked { mask_type, matched_preview }) = block_result {
                    tracing::warn!(
                        mask_type = %mask_type,
                        preview = %matched_preview,
                        path = %path,
                        "Request BLOCKED: sensitive content detected"
                    );
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("Request blocked: {} detected", mask_type),
                    ).into_response();
                }
            }

            if dry_run {
                // In dry-run, send original body unmodified
                (body, None)
            } else {
                match serde_json::to_vec(&json) {
                    Ok(v) => (Bytes::from(v), wmap),
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to serialize masked body");
                        return (StatusCode::INTERNAL_SERVER_ERROR, "Serialization error").into_response();
                    }
                }
            }
        } else {
            (body, None)
        }
    } else {
        (body, None)
    };

    let upstream_req = upstream_req.header("content-type", content_type).body(body_to_send);

    let upstream_request = upstream_req.build().expect("Failed to build upstream request");
    match state.client.execute(upstream_request).await {
        Ok(resp) => {
            let status = resp.status();
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
                        .chain(futures::stream::once(async { Ok::<_, reqwest::Error>(None) }))
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
                    resp_headers.remove("content-length"); // SSE has no fixed length
                    *response.headers_mut() = resp_headers;
                    response
                } else {
                    // Non-SSE whistledown: buffer full response
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
                            let mut response = Response::new(axum::body::Body::from(unmasked.clone()));
                            *response.status_mut() = status;
                            *response.headers_mut() = headers;
                            response.headers_mut().remove("content-length");
                            response.headers_mut().insert(
                                "content-length",
                                axum::http::HeaderValue::from_str(&unmasked.len().to_string()).unwrap(),
                            );
                            response
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Failed to read upstream response for whistledown");
                            (StatusCode::BAD_GATEWAY, format!("Response error: {}", e)).into_response()
                        }
                    }
                }
            } else {
                // Standard streaming passthrough
                let body = axum::body::Body::from_stream(resp.bytes_stream());
                let mut response = Response::new(body);
                *response.status_mut() = status;
                *response.headers_mut() = headers;
                response
            }
        }
        Err(e) => {
            tracing::error!(error = ?e, "Upstream request failed");
            (
                StatusCode::BAD_GATEWAY,
                format!("Upstream error: {}", e),
            )
                .into_response()
        }
    }
}
