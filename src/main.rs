//! MaskForAI: Local HTTP proxy that masks sensitive data in Claude Code
//! requests before forwarding to Anthropic API relay.

use axum::Router;
use maskforai::config::RuntimeConfig;
use maskforai::proxy::ProxyState;
use maskforai::web::{self, WebState};
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() {
    let loaded_env = maskforai::config::load_optional_env_file();
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "maskforai=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    if loaded_env {
        tracing::info!(
            path = %maskforai::config::env_config_path().display(),
            "Loaded env.conf (HTTP_PROXY and related vars apply to upstream if set)"
        );
    }

    let runtime = RuntimeConfig::from_env().expect("Invalid runtime configuration");
    let web_state = (runtime.web_port > 0).then(|| WebState::new(&runtime));

    // Start Web UI on separate port
    let web_port = runtime.web_port;
    if web_port > 0 {
        let web_state = web_state
            .clone()
            .expect("web state must exist when web UI is enabled");
        let web_app = web::web_router(web_state);
        let web_bind = runtime
            .providers
            .first()
            .map(|cfg| cfg.bind.clone())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let web_addr: SocketAddr = format!("{}:{}", web_bind, web_port)
            .parse()
            .expect("Invalid web UI bind address");

        tracing::info!("Web UI available at http://{}", web_addr);

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(web_addr)
                .await
                .expect("Web UI bind failed");
            axum::serve(listener, web_app)
                .await
                .expect("Web UI server failed");
        });
    }

    let mut tasks = Vec::new();
    for config in runtime.providers.clone() {
        let state = if let Some(web_state) = &web_state {
            ProxyState::new(config.clone()).with_web_state(web_state.clone())
        } else {
            ProxyState::new(config.clone())
        };
        let app = Router::new()
            .fallback(maskforai::proxy::proxy_handler)
            .with_state(state);
        let addr: SocketAddr = format!("{}:{}", config.bind, config.port)
            .parse()
            .expect("Invalid bind address");

        tracing::info!(
            provider = %config.provider_name,
            provider_type = %config.provider_type.as_str(),
            "MaskForAI listening on http://{} (upstream: {})",
            addr,
            config.upstream_url
        );

        tasks.push(tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .expect("Bind failed");
            axum::serve(listener, app).await.expect("Server failed");
        }));
    }

    futures::future::join_all(tasks).await;
}
