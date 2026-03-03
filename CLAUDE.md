# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo build --release    # Production build → target/release/maskforai
cargo build              # Debug build
cargo test               # All unit + integration tests (143 total)
cargo test <test_name>   # Run a single test by name
cargo fmt                # Format code (default rustfmt)
cargo clippy             # Lint
```

Install script: `./install.sh [--install-dir PATH] [--no-start] [--no-systemd]` — builds release binary, copies to `~/.local/bin/maskforai`, creates and enables a systemd user service.

## Architecture

MaskForAI is a transparent HTTP reverse proxy that intercepts Anthropic Messages API requests, masks PII and secrets in JSON payloads before forwarding them upstream. Works with Claude Code, openclaw, and any Anthropic-compatible client.

**Request flow:**
```
Claude Code / openclaw → MaskForAI (127.0.0.1:8432) → upstream relay → api.anthropic.com
```

**Key modules:**

- **`src/main.rs`** — Binary entry point. Sets up tracing, loads config, creates axum router with a single fallback handler. Starts Web UI on separate port.
- **`src/proxy.rs`** — The `proxy_handler`: reads body bytes, masks JSON for `/v1/messages`, `/v1/messages/count_tokens`, and `/v1/chat/completions` paths. Supports SSE streaming rehydration, dry-run mode, and whistledown.
- **`src/mask.rs`** — Parses Anthropic API JSON structure. Only masks `system` field and `messages[].content` (both string and content-block formats). Non-messages paths pass through unmodified.
- **`src/patterns.rs`** — 75+ regex patterns with sensitivity levels, confidence scoring, context boosting, validators (Luhn, SSN), RegexSet pre-filtering. Patterns compile once via `OnceLock`.
- **`src/whistledown.rs`** — Reversible masking: replaces PII with `[[TYPE_N]]` tokens and restores them in responses.
- **`src/entropy.rs`** — Shannon entropy-based high-entropy secret detection.
- **`src/fakes.rs`** — Format-matching fake value generation (deterministic, Luhn-valid cards, etc.).
- **`src/vault.rs`** — Encrypted vault for whistledown mappings (AES-256-GCM + Argon2id).
- **`src/web.rs`** — Web UI REST API + WebSocket live logs on separate port (default 8433).
- **`src/filter_log.rs`** — Audit logging of masking events with optional SHA256 hashes.
- **`src/config.rs`** — `Config::from_env()` reads all `MASKFORAI_*` environment variables.

**Runtime config:** `env.conf` is loaded by the systemd service as `EnvironmentFile`.

## Testing

Unit tests are inline (`#[cfg(test)]` modules) across all modules:
- `src/patterns.rs` — 100+ pattern and validation tests
- `src/mask.rs` — 8 JSON masking tests
- `src/whistledown.rs` — 9 reversible masking tests
- `src/entropy.rs` — 7 entropy detection tests
- `src/fakes.rs` — 11 fake generation tests
- `src/vault.rs` — 6 encrypted vault tests

Integration tests in `tests/integration_test.rs` use `httpmock` for a mock upstream and `tower::ServiceExt::oneshot` to exercise the full axum router in-process.

## Key Design Decisions

- Uses `reqwest` with `native-tls` and `socks` proxy support.
- Regex patterns use `std::sync::OnceLock` for lazy one-time compilation — no `lazy_static` or `once_cell` crate.
- `RegexSet` for O(1) pre-filtering before individual pattern matching.
- Masking is applied sequentially in a fixed order defined in `patterns::apply()`.
- The proxy is a single axum fallback route — all HTTP methods and paths are captured.
- SSE streaming uses 128-byte overlap buffer for safe token boundary handling.
- Vault uses AES-256-GCM encryption with Argon2id key derivation.
- Web UI is embedded as a single HTML file via `include_str!()`.
