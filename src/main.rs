//! MaskForAI: Local HTTP proxy that masks sensitive data in Claude Code
//! requests before forwarding to Anthropic API relay.

use axum::Router;
use maskforai::proxy::ProxyState;
use maskforai::web::{self, WebState};
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "maskforai=info,tower_http=info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = maskforai::config::Config::from_env();
    let state = ProxyState::new(config.clone());

    let app = Router::new()
        .fallback(maskforai::proxy::proxy_handler)
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", config.bind, config.port)
        .parse()
        .expect("Invalid bind address");

    tracing::info!(
        "MaskForAI listening on http://{} (upstream: {})",
        addr,
        config.upstream_url
    );

    // Start Web UI on separate port
    let web_port = config.web_port;
    if web_port > 0 {
        let web_state = WebState::new();
        let web_app = web::web_router(web_state);
        let web_addr: SocketAddr = format!("{}:{}", config.bind, web_port)
            .parse()
            .expect("Invalid web UI bind address");

        tracing::info!("Web UI available at http://{}", web_addr);

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(web_addr).await.expect("Web UI bind failed");
            axum::serve(listener, web_app).await.expect("Web UI server failed");
        });
    }

    let listener = tokio::net::TcpListener::bind(addr).await.expect("Bind failed");
    axum::serve(listener, app).await.expect("Server failed");
}
