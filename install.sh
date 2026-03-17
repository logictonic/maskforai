#!/usr/bin/env bash
# MaskForAI installer for Ubuntu, Debian, Fedora, Rocky Linux
# Builds from source, installs to ~/.local/bin and sets up systemd user service.

set -euo pipefail

INSTALL_DIR=""
NO_START=false
NO_SYSTEMD=false

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
        -h|--help)
            echo "Usage: $0 [--install-dir PATH] [--no-start] [--no-systemd]"
            echo "  --install-dir   Source directory (default: script dir or ~/.local/share/maskforai)"
            echo "  --no-start      Do not start systemd service after install"
            echo "  --no-systemd    Install binary only, skip systemd setup"
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
BIN_DIR="${HOME}/.local/bin"
CONFIG_DIR="${HOME}/.config/maskforai"
SERVICE_DIR="${HOME}/.config/systemd/user"

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

# Create config template
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
        cat > "$conf" << EOF
# MaskForAI configuration
# Upstream relay URL (required)
MASKFORAI_UPSTREAM=$upstream

# Port (default: 8432)
# MASKFORAI_PORT=8432

# Bind address (default: 127.0.0.1)
# MASKFORAI_BIND=127.0.0.1

# Filter logging: off, summary, detailed (default: off)
# MASKFORAI_LOG_FILTER=summary

# Minimum confidence score (0.0–1.0, default: 0.0 = mask everything)
# Higher values reduce false positives but may miss some PII
# MASKFORAI_MIN_SCORE=0.0

# Allow-list: comma-separated values that should never be masked
# MASKFORAI_ALLOWLIST=test@internal.corp,192.168.1.1

# Audit log: log SHA256 hashes of masked values (default: off)
# MASKFORAI_AUDIT_LOG=false

# Whistledown: reversible masking with numbered tokens (default: on)
# When enabled, PII is replaced with [[TYPE_N]] tokens and restored in responses
MASKFORAI_WHISTLEDOWN=true
EOF
        echo "==> Created config template: $conf"
        echo "    Edit it to change MASKFORAI_UPSTREAM if needed"
    else
        echo "==> Config exists: $conf"
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
}

# Main
detect_and_install_deps
ensure_rust
ensure_source
build
install_binary

if [[ "$NO_SYSTEMD" != true ]]; then
    install_config
    install_systemd
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
echo "  1. Edit $CONFIG_DIR/env.conf and set MASKFORAI_UPSTREAM to your relay URL"
echo "  2. For Claude Code, set ANTHROPIC_BASE_URL=http://127.0.0.1:8432"
echo "  3. Restart session or log out/in for env vars to apply"
echo ""
echo "Commands:"
echo "  systemctl --user status maskforai   # Check status"
echo "  journalctl --user -u maskforai -f   # View logs"
echo ""
