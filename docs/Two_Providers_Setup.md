# MaskForAI: two-provider setup (after upgrade on a new server)

This guide configures **one** `maskforai` process with **two listeners**: Anthropic-style (Claude / Cursor) and OpenAI-compatible (Codex / `responses` API). Use it after you have updated the `maskforai` git tree on the target host.

## 1. Update the binary

On the server, from the maskforai repository:

```bash
cd /path/to/maskforai
git pull
./install.sh
```

Or build manually:

```bash
cd /path/to/maskforai
cargo build --release
mkdir -p ~/.local/bin
cp target/release/maskforai ~/.local/bin/maskforai
chmod +x ~/.local/bin/maskforai
```

If you use the installer, it recreates or refresers `~/.config/maskforai/` templates and the **systemd user** unit unless you pass `--no-systemd`.

## 2. Retire old split services (if any)

If you previously ran **separate** user units (e.g. `maskforai-anthropic.service`, `maskforai-drlj.service`) on the same ports, **disable and stop** them so they do not conflict with the unified service:

```bash
systemctl --user disable --now maskforai-anthropic.service 2>/dev/null || true
systemctl --user disable --now maskforai-drlj.service 2>/dev/null || true
systemctl --user daemon-reload
```

Use a **single** unit: `maskforai.service`.

## 3. Configure `providers.toml` (required for two providers)

Path: `~/.config/maskforai/providers.toml`

When this file exists, MaskForAI runs **multi-provider mode**: each `[providers.*]` block is one local listener with its own upstream.

Example for a relay that exposes Anthropic at the host root and OpenAI under `/openai`:

```toml
[providers.claude]
type = "claude"
bind = "127.0.0.1"
port = 8432
upstream_url = "https://api.example-relay.example"

[providers.openai]
type = "openai"
bind = "127.0.0.1"
port = 8434
upstream_url = "https://api.example-relay.example/openai"
```

Rules:

- **`type`**: `claude` or `openai` (controls which request paths are masked and how).
- **`upstream_url`**: no trailing slash (MaskForAI appends the incoming path, e.g. `/v1/messages`, `/responses`).
- **Ports must differ** from each other and from the Web UI port (`MASKFORAI_WEB_PORT`, default `8433`).

If `providers.toml` is **missing**, MaskForAI falls back to **legacy** single-provider mode using only `MASKFORAI_PORT` / `MASKFORAI_UPSTREAM` in `env.conf`.

## 4. Configure `env.conf` (global options + legacy fallback)

Path: `~/.config/maskforai/env.conf`

This file is loaded by **systemd** via `EnvironmentFile=`. Use it for **global** masking and runtime flags, not per-provider upstreams (those live in `providers.toml`).

Typical entries:

```bash
# Optional: legacy fallback if providers.toml is absent (OpenAI-style base)
# MASKFORAI_UPSTREAM=https://api.example-relay.example/openai

MASKFORAI_LOG_FILTER=detailed
MASKFORAI_WHISTLEDOWN=true
MASKFORAI_SENSITIVITY=high
MASKFORAI_WEB_PORT=8433

# Optional: force HTTP/1.1 to upstream (often helps long SSE via some nginx/HTTP2 relays)
MASKFORAI_HTTP1_ONLY=true
```

Optional override for the providers file path:

```bash
# MASKFORAI_PROVIDERS_FILE=/path/to/custom-providers.toml
```

## 5. Enable and start the user service

```bash
systemctl --user daemon-reload
systemctl --user enable maskforai.service
systemctl --user restart maskforai.service
systemctl --user status maskforai.service --no-pager
```

Verify listeners:

```bash
ss -tlnp | grep -E '8432|8433|8434'
```

You should see **127.0.0.1:8432**, **8433** (Web UI), **8434**.

Logs:

```bash
journalctl --user -u maskforai.service -n 40 --no-pager
```

Expect one process logging **two** “MaskForAI listening” lines (claude + openai).

**Note:** `systemctl --user` requires a **lingering** login session for your user on servers without a desktop, or enable lingering:

```bash
loginctl enable-linger "$USER"
```

## 6. Point clients at the proxy (HTTP, not HTTPS)

The local listeners speak **plain HTTP** only.

**Claude / Anthropic-compatible:**

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8432
export ANTHROPIC_AUTH_TOKEN=<your-relay-or-provider-token>
```

**OpenAI-compatible (e.g. Codex with `responses`):**

In `~/.codex/config.toml` (example):

```toml
[model_providers.crs]
name = "crs"
base_url = "http://127.0.0.1:8434"
wire_api = "responses"
requires_openai_auth = true
env_key = "CRS_OAI_KEY"
```

Use **`http://`**, not `https://`, for `127.0.0.1`.

Ensure the API key variable (`CRS_OAI_KEY` here) is set in the **same environment** as the Codex/Cursor process (login shell, `environment.d`, or IDE remote env), not only in an interactive `.bashrc` if that file is never sourced by the IDE.

## 7. Quick health checks

```bash
# Web UI
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8433/

# Claude path (relay may return 401/404 without a valid token; connection proves listen)
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8432/v1/messages -X POST \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer test' -d '{}'

# OpenAI path (same idea)
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8434/responses -X POST \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer test' -d '{}'
```

## 8. Troubleshooting

| Symptom | Check |
|--------|--------|
| `Reconnecting…` / stream drops (Codex) | `MASKFORAI_HTTP1_ONLY=true`; confirm `base_url` is **http**; inspect `journalctl` for `Upstream returned non-success status`. |
| Port already in use | Old extra `maskforai-*.service` or another app on 8432/8434. |
| Wrong upstream path | `upstream_url` must match relay docs; no trailing `/`; OpenAI-style relay often needs `.../openai` for port 8434. |
| No env vars in IDE | Put exports in `~/.profile` / systemd `environment.d`, or Cursor SSH remote env. |

## 9. Files reference

| File | Role |
|------|------|
| `~/.config/maskforai/providers.toml` | Per-provider `bind`, `port`, `upstream_url`, `type` |
| `~/.config/maskforai/env.conf` | Globals + legacy fallback |
| `~/.config/maskforai/patterns.toml` | Custom masking patterns (optional) |
| `~/.config/systemd/user/maskforai.service` | User service unit |
| `~/.local/bin/maskforai` | Installed binary |
