#!/usr/bin/env bash
# MaskForAI installer for Ubuntu, Debian, Fedora, Rocky Linux
# Builds from source, installs to ~/.local/bin and sets up systemd user service.

set -euo pipefail

INSTALL_DIR=""
NO_START=false
NO_SYSTEMD=false
NO_ADAPTIVE_PROXY=false
AUTO_STRIP_PROXY_ENV=false

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --no-start)
            NO_START=true
            shift
            ;;
        --no-systemd)
            NO_SYSTEMD=true
            shift
            ;;
        --no-adaptive-proxy)
            NO_ADAPTIVE_PROXY=true
            shift
            ;;
        --auto-strip-proxy-env)
            AUTO_STRIP_PROXY_ENV=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--install-dir PATH] [--no-start] [--no-systemd] [--no-adaptive-proxy] [--auto-strip-proxy-env]"
            echo "  --install-dir   Source directory (default: script dir or ~/.local/share/maskforai)"
            echo "  --no-start      Do not start systemd service after install"
            echo "  --no-systemd    Install binary only, skip systemd setup"
            echo "  --no-adaptive-proxy  Do not install adaptive proxy detector drop-in"
            echo "  --auto-strip-proxy-env  Comment out legacy *_PROXY lines in env.conf"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_HOME="${XDG_BIN_HOME:-${HOME}/.local/bin}"
CONFIG_HOME="${XDG_CONFIG_HOME:-${HOME}/.config}"
BIN_DIR="${BIN_HOME}"
CONFIG_DIR="${CONFIG_HOME}/maskforai"
SERVICE_DIR="${CONFIG_HOME}/systemd/user"

# Detect source dir
if [[ -z "$INSTALL_DIR" ]]; then
    if [[ -f "${SCRIPT_DIR}/Cargo.toml" ]]; then
        INSTALL_DIR="$SCRIPT_DIR"
    else
        INSTALL_DIR="${HOME}/.local/share/maskforai"
    fi
fi

mkdir -p "$BIN_DIR"

echo "==> MaskForAI installer (Ubuntu, Debian, Fedora, Rocky)"
echo "    Source: $INSTALL_DIR"
echo "    Binary: $BIN_DIR/maskforai"
echo "    Adaptive proxy: $([[ \"$NO_ADAPTIVE_PROXY\" == true ]] && echo disabled || echo enabled)"
echo ""

# Detect distro and install build deps
detect_and_install_deps() {
    local id=""
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        id="${ID:-}"
        id_like="${ID_LIKE:-}"
    fi

    case "$id" in
        ubuntu|debian|raspbian)
            echo "==> Detected Ubuntu/Debian"
            if ! command -v gcc &>/dev/null || ! command -v curl &>/dev/null; then
                echo "==> Installing build-essential, curl (requires sudo)"
                sudo apt-get update -qq
                sudo apt-get install -y build-essential curl
            fi
            ;;
        fedora)
            echo "==> Detected Fedora"
            if ! command -v gcc &>/dev/null || ! command -v curl &>/dev/null; then
                echo "==> Installing gcc, curl (requires sudo)"
                sudo dnf install -y gcc curl
            fi
            ;;
        rocky|rhel|centos|almalinux)
            echo "==> Detected Rocky/RHEL/CentOS"
            if ! command -v gcc &>/dev/null || ! command -v curl &>/dev/null; then
                echo "==> Installing gcc, curl (requires sudo)"
                if command -v dnf &>/dev/null; then
                    sudo dnf install -y gcc curl
                else
                    sudo yum install -y gcc curl
                fi
            fi
            ;;
        *)
            if [[ "$id_like" == *"debian"* ]]; then
                echo "==> Detected Debian-based (ID_LIKE=$id_like)"
                if ! command -v gcc &>/dev/null || ! command -v curl &>/dev/null; then
                    sudo apt-get update -qq
                    sudo apt-get install -y build-essential curl
                fi
            elif [[ "$id_like" == *"rhel"* ]] || [[ "$id_like" == *"fedora"* ]]; then
                echo "==> Detected RHEL/Fedora-based (ID_LIKE=$id_like)"
                if ! command -v gcc &>/dev/null || ! command -v curl &>/dev/null; then
                    (command -v dnf &>/dev/null && sudo dnf install -y gcc curl) || sudo yum install -y gcc curl
                fi
            else
                echo "==> Unknown distro (ID=$id). Assuming gcc and curl are available."
            fi
            ;;
    esac
}

# Install Rust if missing
ensure_rust() {
    if command -v cargo &>/dev/null; then
        echo "==> Cargo found: $(cargo --version)"
        return
    fi
    echo "==> Installing Rust via rustup"
    curl -sSf https://sh.rustup.rs | sh -s -- -y -q --default-toolchain stable --profile minimal
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
    echo "==> Rust installed: $(cargo --version)"
}

# Clone if needed
ensure_source() {
    if [[ -f "${INSTALL_DIR}/Cargo.toml" ]]; then
        echo "==> Source found at $INSTALL_DIR"
        return
    fi
    echo "==> No source at $INSTALL_DIR"
    echo "    Run this script from the maskforai repo, or:"
    echo "    git clone <repo-url> $INSTALL_DIR && $0 --install-dir $INSTALL_DIR"
    exit 1
}

# Build
build() {
    echo "==> Building maskforai (release)"
    # Ensure cargo in path for subshell
    export PATH="${HOME}/.cargo/bin:${PATH:-}"
    (cd "$INSTALL_DIR" && cargo build --release -q)
    echo "==> Build complete"
}

# Install binary (stop service first if running, to avoid "Text file busy")
install_binary() {
    if systemctl --user is-active maskforai.service &>/dev/null; then
        echo "==> Stopping maskforai service for update"
        systemctl --user stop maskforai.service || true
    fi
    mkdir -p "$BIN_DIR"
    cp "${INSTALL_DIR}/target/release/maskforai" "$BIN_DIR/maskforai"
    chmod +x "$BIN_DIR/maskforai"
    echo "==> Installed to $BIN_DIR/maskforai"
}

replace_upstream_line() {
    local file="$1"
    local upstream="$2"
    python3 - "$file" "$upstream" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
upstream = sys.argv[2]
lines = path.read_text(encoding="utf-8").splitlines()
updated = []
replaced = False
for line in lines:
    if line.startswith("MASKFORAI_UPSTREAM="):
        updated.append(f"MASKFORAI_UPSTREAM={upstream}")
        replaced = True
    else:
        updated.append(line)
if not replaced:
    updated.append(f"MASKFORAI_UPSTREAM={upstream}")
path.write_text("\n".join(updated) + "\n", encoding="utf-8")
PY
}

# Create config templates
install_config() {
    mkdir -p "$CONFIG_DIR"
    local conf="$CONFIG_DIR/env.conf"
    if [[ ! -f "$conf" ]]; then
        local upstream="https://api.anthropic.com"
        if [[ -f "${HOME}/.config/environment.d/anthropic.conf" ]]; then
            local val
            val=$(grep -E '^MASKFORAI_UPSTREAM=' "${HOME}/.config/environment.d/anthropic.conf" 2>/dev/null | cut -d= -f2-)
            if [[ -n "$val" ]]; then
                upstream="$val"
            fi
        fi
        cp "${INSTALL_DIR}/env.conf" "$conf"
        replace_upstream_line "$conf" "$upstream"
        echo "==> Created config template: $conf"
        echo "    Edit it to change global defaults if needed"
    else
        echo "==> Config exists: $conf"
    fi

    local providers="$CONFIG_DIR/providers.toml"
    if [[ ! -f "$providers" ]]; then
        cat > "$providers" << EOF
# Multi-provider listener configuration for maskforai
# One process can expose multiple local ports, one per provider.

[providers.claude]
type = "claude"
bind = "127.0.0.1"
port = 8432
upstream_url = "$upstream"

[providers.openai]
type = "openai"
bind = "127.0.0.1"
port = 8434
upstream_url = "https://api.openai.com"
EOF
        echo "==> Created providers template: $providers"
        echo "    Edit each provider upstream_url to match your relay/provider base URL"
    else
        echo "==> Providers config exists: $providers"
    fi

    # Create patterns.toml template if missing
    local patterns="$CONFIG_DIR/patterns.toml"
    if [[ ! -f "$patterns" ]]; then
        cat > "$patterns" << 'EOF'
# Custom patterns for maskforai
# Add your own regex patterns here.
# They will be merged with built-in patterns at startup.

# Allow-list: values that should never be masked
# allowlist = ["test@example.com", "10.0.0.1"]

# Custom pattern example (uncomment to use):
# [[pattern]]
# pattern = "CUSTOM_SECRET_[A-Za-z0-9]{32}"
# replacement = "[masked:custom]****"
# mask_type = "custom_secret"
# score = 0.9
# action = "mask"  # mask, block, or observe
EOF
        echo "==> Created patterns template: $patterns"
    else
        echo "==> Patterns config exists: $patterns"
    fi
}

# Install systemd user service
install_systemd() {
    mkdir -p "$SERVICE_DIR"
    local svc="$SERVICE_DIR/maskforai.service"
    cat > "$svc" << 'EOF'
[Unit]
Description=MaskForAI: masks PII/secrets in Claude Code requests before relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=%h/.config/maskforai/env.conf
ExecStart=%h/.local/bin/maskforai
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
    echo "==> Installed systemd user service: $svc"
}

install_adaptive_proxy() {
    mkdir -p "$BIN_DIR"
    cp "${INSTALL_DIR}/bin/maskforai-detect-proxy.sh" "$BIN_DIR/maskforai-detect-proxy.sh"
    chmod +x "$BIN_DIR/maskforai-detect-proxy.sh"

    mkdir -p "${SERVICE_DIR}/maskforai.service.d"
    cp "${INSTALL_DIR}/systemd/maskforai.service.d/10-adaptive-proxy.conf" \
        "${SERVICE_DIR}/maskforai.service.d/10-adaptive-proxy.conf"

    echo "==> Installed adaptive proxy detector: $BIN_DIR/maskforai-detect-proxy.sh"
    echo "==> Installed systemd drop-in: ${SERVICE_DIR}/maskforai.service.d/10-adaptive-proxy.conf"
}

warn_or_strip_proxy_env() {
    local conf="${CONFIG_DIR}/env.conf"

    [[ -f "$conf" ]] || return 0

    if ! grep -Eq '^(HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|http_proxy|https_proxy|all_proxy)=' "$conf"; then
        return 0
    fi

    if [[ "$AUTO_STRIP_PROXY_ENV" == true ]]; then
        python3 - "$conf" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
pattern = re.compile(r'^(HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|http_proxy|https_proxy|all_proxy)=')
lines = path.read_text(encoding="utf-8").splitlines()
updated = []
for line in lines:
    if pattern.match(line):
        updated.append(f"# stripped by install.sh adaptive-proxy migration: {line}")
    else:
        updated.append(line)
path.write_text("\n".join(updated) + "\n", encoding="utf-8")
PY
        echo "==> Commented out legacy proxy env lines in $conf"
    else
        echo "==> WARNING: $conf still defines *_PROXY variables."
        echo "    Adaptive proxy detection will override them at runtime."
        echo "    Re-run with --auto-strip-proxy-env to comment them out automatically."
    fi
}

# Enable and start service
start_service() {
    systemctl --user daemon-reload
    systemctl --user enable maskforai.service
    if ! systemctl --user is-active maskforai.service &>/dev/null; then
        systemctl --user start maskforai.service
        echo "==> Started maskforai service"
    else
        systemctl --user restart maskforai.service
        echo "==> Restarted maskforai service"
    fi

    if [[ "$NO_ADAPTIVE_PROXY" != true ]]; then
        echo "==> Recent adaptive proxy logs"
        journalctl --user -u maskforai -n 5 --no-pager 2>/dev/null || true
    fi
}

# Main
detect_and_install_deps
ensure_rust
ensure_source
build
install_binary
install_config

if [[ "$NO_SYSTEMD" != true ]]; then
    install_systemd
    if [[ "$NO_ADAPTIVE_PROXY" != true ]]; then
        install_adaptive_proxy
    else
        echo "==> Skipping adaptive proxy setup (--no-adaptive-proxy)"
    fi
    warn_or_strip_proxy_env
    if [[ "$NO_START" != true ]]; then
        start_service
    else
        echo "==> Skipping service start (--no-start)"
    fi
else
    echo "==> Skipping systemd setup (--no-systemd)"
fi

echo ""
echo "==> Done!"
echo ""
echo "Next steps:"
echo "  1. Edit $CONFIG_DIR/providers.toml and set each provider upstream_url"
echo "  2. Adjust $CONFIG_DIR/env.conf for global masking defaults if needed"
echo "  3. For Claude Code, set ANTHROPIC_BASE_URL=http://127.0.0.1:8432"
echo "  4. For OpenAI-compatible clients, point them to http://127.0.0.1:8434"
if [[ "$NO_ADAPTIVE_PROXY" != true ]]; then
    echo "  5. Check journalctl --user -u maskforai -n 20 for maskforai-detect-proxy mode logs"
fi
echo ""
echo "Commands:"
echo "  systemctl --user status maskforai   # Check status"
echo "  journalctl --user -u maskforai -f   # View logs"
echo ""
