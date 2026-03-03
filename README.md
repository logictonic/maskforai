# MaskForAI

Local HTTP proxy that masks sensitive data (API keys, passwords, PII) in Claude Code / openclaw requests before forwarding to Anthropic API relay.

## Install

**Supported:** Ubuntu, Debian, Fedora, Rocky Linux

```bash
# From the maskforai directory
./install.sh

# Or with options
./install.sh --install-dir /path/to/maskforai [--no-start] [--no-systemd]
```

The installer will:
1. Detect distro and install build dependencies (gcc, curl) if needed
2. Install Rust via rustup if `cargo` is not present
3. Build from source and install to `~/.local/bin/maskforai`
4. Create `~/.config/maskforai/env.conf` (template) and systemd user service
5. Enable and start the service

**Post-install:** Edit `~/.config/maskforai/env.conf` and set `MASKFORAI_UPSTREAM` to your relay URL.

## Architecture

```
[Claude Code / openclaw] --HTTP--> [MaskForAI localhost:8432] --HTTPS--> [Relay] --HTTPS--> [api.anthropic.com]
```

The proxy intercepts Anthropic Messages API requests, applies regex-based masking to `system` and `messages[].content`, then forwards the sanitized payload to the upstream relay.

## Usage with Claude Code

Point Claude Code to the proxy:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8432
export ANTHROPIC_AUTH_TOKEN=<your-token>
```

## Usage with openclaw

Configure openclaw to use MaskForAI:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8432
openclaw chat "your prompt here"
```

Or set in openclaw config file (`~/.config/openclaw/config.toml`):

```toml
base_url = "http://127.0.0.1:8432"
```

## Build

```bash
cd maskforai
cargo build --release
```

## Configure upstream

Set the relay URL (the real Anthropic API endpoint):

```bash
export MASKFORAI_UPSTREAM=https://api.anthropic.com
```

Or use `ANTHROPIC_BASE_URL` if it points to your relay.

## Run the proxy

```bash
./target/release/maskforai
```

Defaults: listen on `127.0.0.1:8432`, upstream from `MASKFORAI_UPSTREAM` or `ANTHROPIC_BASE_URL`.

## Web UI

MaskForAI includes a built-in web interface for configuration management, available at `http://127.0.0.1:8433` by default.

Features:
- View real-time statistics (requests, masks, blocks)
- Edit configuration (sensitivity, whistledown, dry-run, etc.)
- Manage custom regex patterns
- Manage allowlist
- Test masking in real-time
- Live log streaming via WebSocket

Set `MASKFORAI_WEB_PORT=0` to disable the web UI.

## Environment variables

| Variable | Default | Description |
|---------|---------|-------------|
| `MASKFORAI_PORT` | 8432 | Listen port |
| `MASKFORAI_BIND` | 127.0.0.1 | Bind address |
| `MASKFORAI_UPSTREAM` | (from ANTHROPIC_BASE_URL) | Upstream API URL |
| `MASKFORAI_LOG_FILTER` | off | Filter logging: `off`, `summary`, `detailed` |
| `MASKFORAI_SENSITIVITY` | medium | Sensitivity: `low`, `medium`, `high`, `paranoid` |
| `MASKFORAI_WHISTLEDOWN` | false | Reversible masking with numbered tokens |
| `MASKFORAI_DRY_RUN` | false | Log detections but don't modify traffic |
| `MASKFORAI_WEB_PORT` | 8433 | Web UI port (0 = disabled) |
| `MASKFORAI_MIN_SCORE` | 0.0 | Minimum confidence score (0.0–1.0) |
| `MASKFORAI_ALLOWLIST` | | Comma-separated values to never mask |
| `MASKFORAI_AUDIT_LOG` | false | Log SHA256 hashes of masked values |

### Filter logging

When `MASKFORAI_LOG_FILTER` is set, the proxy logs what was masked:

- **off** (default): no filter logging
- **summary** / **1** / **true**: one line per request, e.g. `filter applied path=/v1/messages filters=email=1, api_key=2`
- **detailed** / **2** / **debug**: one debug line per mask type and context

Use `RUST_LOG=maskforai=info` (or `debug` for detailed) to see filter logs.

## Features

- **75+ regex patterns**: API keys (Anthropic, OpenAI, GitHub, AWS, Stripe, etc.), PEM keys, DB connections, JWT/Bearer tokens, PII (email, phone, SSN, credit card, IP, MAC)
- **Sensitivity levels**: Low (secrets only), Medium (+ PII), High (+ context-dependent), Paranoid (+ entropy detection)
- **Whistledown**: Reversible masking — PII replaced with `[[TYPE_N]]` tokens, restored in responses
- **SSE streaming**: Real-time demasking for Server-Sent Events with overlap buffer
- **Encrypted vault**: AES-256-GCM + Argon2id for secure mapping storage
- **Fake generation**: Format-matching fakes (Luhn-valid cards, valid SSN format, etc.)
- **Entropy detection**: Shannon entropy-based high-entropy secret detection
- **Dry-run mode**: Log detections without modifying traffic
- **Web UI**: Built-in dashboard for configuration and monitoring
- **Custom patterns**: Add your own regex patterns via TOML config

Format: `[masked:type]****` so the AI knows data was redacted.

## TLS / HTTPS

The proxy runs over HTTP by default. For HTTPS:

- Run the proxy behind nginx or Caddy with TLS termination
- Or use a tunnel (e.g. cloudflared) to expose it over HTTPS

## Testing

```bash
cargo test
```

143 tests (136 unit + 7 integration).

## License

MIT
