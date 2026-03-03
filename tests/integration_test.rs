//! Integration test: proxy masks request body before forwarding to upstream.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use httpmock::prelude::*;
use maskforai::config::{Config, FilterLogLevel, PatternsConfig};
use maskforai::proxy::{proxy_handler, ProxyState};
use tower::ServiceExt;

fn test_config(upstream_url: String) -> Config {
    Config {
        port: 8432,
        upstream_url,
        bind: "127.0.0.1".to_string(),
        filter_log: FilterLogLevel::Off,
        min_score: 0.0,
        allowlist: Vec::new(),
        audit_log: false,
        custom_patterns: PatternsConfig::default(),
        whistledown: false,
        sensitivity: "medium".to_string(),
        dry_run: false,
        web_port: 0,
    }
}

#[tokio::test]
async fn proxy_masks_sensitive_data_before_forwarding() {
    let mock_server = MockServer::start_async().await;

    let capture = mock_server.mock_async(|when, then| {
        when.method(POST)
            .path("/v1/messages")
            .header("content-type", "application/json")
            .body_contains("[masked:email]");
        then.status(200)
            .body(r#"{"id":"msg_123","type":"message"}"#);
    })
    .await;

    let config = test_config(mock_server.base_url());
    let state = ProxyState::new(config);

    let app = Router::new()
        .fallback(proxy_handler)
        .with_state(state);

    let body = r#"{"model":"claude-3-5-sonnet","max_tokens":1024,"messages":[{"role":"user","content":"Contact me at user@secret.com"}]}"#;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .header("x-api-key", "test-key")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    capture.assert_async().await;
}

#[tokio::test]
async fn proxy_masks_count_tokens_request() {
    let mock_server = MockServer::start_async().await;

    let capture = mock_server.mock_async(|when, then| {
        when.method(POST)
            .path("/v1/messages/count_tokens")
            .body_contains("[masked:email]");
        then.status(200)
            .body(r#"{"input_tokens":10}"#);
    })
    .await;

    let config = test_config(mock_server.base_url());
    let state = ProxyState::new(config);

    let app = Router::new()
        .fallback(proxy_handler)
        .with_state(state);

    let body = r#"{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"Hi from a@b.co"}]}"#;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages/count_tokens")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    capture.assert_async().await;
}

#[tokio::test]
async fn proxy_logs_filter_events_when_enabled() {
    let mock_server = MockServer::start_async().await;

    let _capture = mock_server.mock_async(|when, then| {
        when.method(POST)
            .path("/v1/messages")
            .body_contains("[masked:email]");
        then.status(200)
            .body(r#"{"id":"msg_123","type":"message"}"#);
    })
    .await;

    let mut config = test_config(mock_server.base_url());
    config.filter_log = FilterLogLevel::Summary;
    let state = ProxyState::new(config);

    let app = Router::new()
        .fallback(proxy_handler)
        .with_state(state);

    let body = r#"{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"Email: test@example.com"}]}"#;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn proxy_passthrough_non_messages_path() {
    let mock_server = MockServer::start_async().await;

    let capture = mock_server.mock_async(|when, then| {
        when.method(GET).path("/v1/models");
        then.status(200).body(r#"{"data":[]}"#);
    })
    .await;

    let config = test_config(mock_server.base_url());
    let state = ProxyState::new(config);

    let app = Router::new()
        .fallback(proxy_handler)
        .with_state(state);

    let req = Request::builder()
        .method("GET")
        .uri("/v1/models")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    capture.assert_async().await;
}

#[tokio::test]
async fn proxy_masks_private_key() {
    let mock_server = MockServer::start_async().await;

    // Private key should be masked (not blocked)
    let capture = mock_server.mock_async(|when, then| {
        when.method(POST)
            .path("/v1/messages")
            .body_contains("[masked:private_key]");
        then.status(200)
            .body(r#"{"id":"msg_123","type":"message"}"#);
    })
    .await;

    let config = test_config(mock_server.base_url());
    let state = ProxyState::new(config);

    let app = Router::new()
        .fallback(proxy_handler)
        .with_state(state);

    let body = r#"{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALR\n-----END RSA PRIVATE KEY-----"}]}"#;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    capture.assert_async().await;
}

#[tokio::test]
async fn proxy_respects_min_score() {
    let mock_server = MockServer::start_async().await;

    // Phone (score=0.55) should pass through when min_score=0.8
    let capture = mock_server.mock_async(|when, then| {
        when.method(POST)
            .path("/v1/messages")
            .body_contains("+79991234567"); // Phone should NOT be masked
        then.status(200)
            .body(r#"{"id":"msg_123","type":"message"}"#);
    })
    .await;

    let mut config = test_config(mock_server.base_url());
    config.min_score = 0.8;
    let state = ProxyState::new(config);

    let app = Router::new()
        .fallback(proxy_handler)
        .with_state(state);

    let body = r#"{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"Number +79991234567"}]}"#;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    capture.assert_async().await;
}

#[tokio::test]
async fn proxy_whistledown_mode() {
    let mock_server = MockServer::start_async().await;

    // When whistledown is enabled, the upstream should receive [[EMAIL_1]] token
    let capture = mock_server.mock_async(|when, then| {
        when.method(POST)
            .path("/v1/messages")
            .body_contains("[[EMAIL_1]]");
        then.status(200)
            .body(r#"{"id":"msg_123","type":"message","content":[{"type":"text","text":"I sent email to [[EMAIL_1]]"}]}"#);
    })
    .await;

    let mut config = test_config(mock_server.base_url());
    config.whistledown = true;
    let state = ProxyState::new(config);

    let app = Router::new()
        .fallback(proxy_handler)
        .with_state(state);

    let body = r#"{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"Email me at user@secret.com"}]}"#;

    let req = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    capture.assert_async().await;

    // The response should have the original email restored
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_body);
    assert!(resp_str.contains("user@secret.com"), "Whistledown should restore email in response: {}", resp_str);
    assert!(!resp_str.contains("[[EMAIL_1]]"), "Token should be replaced: {}", resp_str);
}
