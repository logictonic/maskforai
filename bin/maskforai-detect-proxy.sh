#!/usr/bin/env bash

set -euo pipefail

OUT="${1:-${RUNTIME_DIRECTORY:-/tmp}/proxy.env}"
DEFAULT_PROXY_HOST="${MASKFORAI_PROXY_HOST:-127.0.0.1}"
if [[ ${MASKFORAI_PROXY_HTTP_PORTS+x} ]]; then
    DEFAULT_HTTP_PORTS="${MASKFORAI_PROXY_HTTP_PORTS}"
else
    DEFAULT_HTTP_PORTS="10809 7890 2081"
fi
if [[ ${MASKFORAI_PROXY_SOCKS_PORTS+x} ]]; then
    DEFAULT_SOCKS_PORTS="${MASKFORAI_PROXY_SOCKS_PORTS}"
else
    DEFAULT_SOCKS_PORTS="10808 1080 1081 7891 2080"
fi
if [[ ${MASKFORAI_TUN_IFACES+x} ]]; then
    DEFAULT_TUN_IFACES="${MASKFORAI_TUN_IFACES}"
else
    DEFAULT_TUN_IFACES="singbox_tun tun0 utun0 wg0"
fi
NO_PROXY_LIST="${NO_PROXY:-localhost,127.0.0.1,::1}"

log() {
    printf '[maskforai-detect-proxy] %s\n' "$*" >&2
}

normalize_host() {
    local host="${1:-}"
    case "${host}" in
        ""|"0.0.0.0"|"::"|"*"|"[::]")
            printf '%s\n' "${DEFAULT_PROXY_HOST}"
            ;;
        *)
            printf '%s\n' "${host}"
            ;;
    esac
}

append_candidate() {
    local type="$1"
    local host="$2"
    local port="$3"
    local normalized_host entry

    [[ -n "${port}" ]] || return 0
    normalized_host="$(normalize_host "${host}")"
    entry="${type}|${normalized_host}|${port}"

    if [[ -z "${CANDIDATES:-}" ]]; then
        CANDIDATES="${entry}"
        return 0
    fi

    case "
${CANDIDATES}
" in
        *"
${entry}
"*) ;;
        *)
            CANDIDATES="${CANDIDATES}
${entry}"
            ;;
    esac
}

append_ports_as_candidates() {
    local type="$1"
    local ports="$2"
    local port

    for port in ${ports}; do
        [[ -n "${port}" ]] || continue
        append_candidate "${type}" "${DEFAULT_PROXY_HOST}" "${port}"
    done
}

parse_probe_override() {
    local spec entry host port type
    spec="${MASKFORAI_PROXY_PROBE_PORTS:-}"
    [[ -n "${spec}" ]] || return 0

    IFS=',' read -r -a entries <<<"${spec}"
    for entry in "${entries[@]}"; do
        [[ -n "${entry}" ]] || continue
        IFS=':' read -r host port type <<<"${entry}"
        if [[ -z "${type:-}" ]]; then
            type="${port:-}"
            port="${host:-}"
            host="${DEFAULT_PROXY_HOST}"
        fi
        case "${type}" in
            http|https|mixed)
                append_candidate "http" "${host}" "${port}"
                ;;
            socks|socks5)
                append_candidate "socks5" "${host}" "${port}"
                ;;
        esac
    done
}

probe_http_proxy() {
    local host="$1"
    local port="$2"

    python3 - "${host}" "${port}" <<'PY' >/dev/null 2>&1
import re
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

try:
    with socket.create_connection((host, port), timeout=1.0) as sock:
        sock.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        response = sock.recv(128).decode("iso-8859-1", "ignore")
except OSError:
    sys.exit(1)

first_line = response.splitlines()[0] if response else ""
sys.exit(0 if re.match(r"^HTTP/1\.[01] (200|407|502|503|504)\b", first_line) else 1)
PY
}

probe_socks5_proxy() {
    local host="$1"
    local port="$2"

    python3 - "${host}" "${port}" <<'PY' >/dev/null 2>&1
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

try:
    with socket.create_connection((host, port), timeout=1.0) as sock:
        sock.sendall(b"\x05\x01\x00")
        response = sock.recv(2)
except OSError:
    sys.exit(1)

sys.exit(0 if len(response) >= 1 and response[0] == 0x05 else 1)
PY
}

parse_json_config() {
    local file="$1"

    if command -v jq >/dev/null 2>&1; then
        while IFS=$'\t' read -r type host port; do
            append_candidate "${type}" "${host}" "${port}"
        done < <(jq -r '
            def norm_type(v):
                if v == "mixed" or v == "http" or v == "https" then "http"
                elif v == "socks" or v == "socks5" then "socks5"
                else empty
                end;

            (.inbounds // [])
            | .[]
            | [norm_type((.type // .protocol // "") | ascii_downcase),
               (.listen // .["bind-address"] // .bind // ""),
               ((.listen_port // .port // "") | tostring)]
            | select(.[0] != "" and .[2] != "")
            | @tsv
        ' "${file}" 2>/dev/null)
        return 0
    fi

    while IFS='|' read -r type host port; do
        append_candidate "${type}" "${host}" "${port}"
    done < <(python3 - "${file}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

for inbound in data.get("inbounds", []):
    raw_type = str(inbound.get("type") or inbound.get("protocol") or "").lower()
    if raw_type in {"mixed", "http", "https"}:
        kind = "http"
    elif raw_type in {"socks", "socks5"}:
        kind = "socks5"
    else:
        continue

    port = inbound.get("listen_port", inbound.get("port"))
    if port in (None, ""):
        continue

    host = inbound.get("listen") or inbound.get("bind") or inbound.get("bind-address") or ""
    print(f"{kind}|{host}|{port}")
PY
    )
}

parse_yaml_config() {
    local file="$1"
    local host

    host="$(awk -F': *' '/^[[:space:]]*bind-address:[[:space:]]*/ {print $2; exit}' "${file}" 2>/dev/null || true)"
    host="${host%\"}"
    host="${host#\"}"
    host="${host%\'}"
    host="${host#\'}"
    host="$(normalize_host "${host}")"

    while IFS='|' read -r type port; do
        port="${port%%[[:space:]]*}"
        [[ -n "${port}" ]] || continue
        append_candidate "${type}" "${host}" "${port}"
    done < <(awk -F': *' '
        /^[[:space:]]*mixed-port:[[:space:]]*/ {print "http|" $2}
        /^[[:space:]]*port:[[:space:]]*/ {print "http|" $2}
        /^[[:space:]]*socks-port:[[:space:]]*/ {print "socks5|" $2}
    ' "${file}" 2>/dev/null)
}

discover_from_configs() {
    local paths file

    if [[ -n "${MASKFORAI_PROXY_CONFIG_PATHS:-}" ]]; then
        paths="${MASKFORAI_PROXY_CONFIG_PATHS}"
    else
        paths="
${HOME}/.local/share/v2rayN/binConfigs/config.json
${HOME}/.config/sing-box/config.json
/etc/sing-box/config.json
${HOME}/.config/xray/config.json
/etc/xray/config.json
${HOME}/.config/v2ray/config.json
/etc/v2ray/config.json
${HOME}/.config/clash/config.yaml
${HOME}/.config/mihomo/config.yaml
${HOME}/.config/clash/config.yml
${HOME}/.config/mihomo/config.yml
"
    fi

    while IFS= read -r file; do
        [[ -n "${file}" ]] || continue
        [[ -f "${file}" ]] || continue

        case "${file}" in
            *.yaml|*.yml)
                parse_yaml_config "${file}"
                ;;
            *)
                parse_json_config "${file}"
                ;;
        esac

        if [[ -n "${CANDIDATES:-}" ]]; then
            PROXY_SOURCE="config:${file}"
            return 0
        fi
    done <<<"${paths}"

    return 0
}

select_proxy_candidate() {
    local type host port

    while IFS='|' read -r type host port; do
        [[ -n "${type}" ]] || continue
        case "${type}" in
            http)
                if probe_http_proxy "${host}" "${port}"; then
                    SELECTED_TYPE="${type}"
                    SELECTED_HOST="${host}"
                    SELECTED_PORT="${port}"
                    return 0
                fi
                ;;
            socks5)
                if probe_socks5_proxy "${host}" "${port}"; then
                    SELECTED_TYPE="${type}"
                    SELECTED_HOST="${host}"
                    SELECTED_PORT="${port}"
                    return 0
                fi
                ;;
        esac
    done <<<"${CANDIDATES:-}"

    return 1
}

tun_up() {
    local iface candidate

    for iface in ${DEFAULT_TUN_IFACES}; do
        [[ "${iface}" == "__none__" ]] && continue
        if [[ -d "/sys/class/net/${iface}" ]]; then
            printf '%s\n' "${iface}"
            return 0
        fi
    done

    [[ "${MASKFORAI_PROXY_DISABLE_GLOB_TUN:-0}" == "1" ]] && return 1

    for candidate in /sys/class/net/tun* /sys/class/net/utun* /sys/class/net/wg*; do
        [[ -e "${candidate}" ]] || continue
        basename "${candidate}"
        return 0
    done

    return 1
}

write_common_env() {
    echo "# Generated by maskforai-detect-proxy.sh at $(date -Iseconds)"
    echo "NO_PROXY=${NO_PROXY_LIST}"
    echo "no_proxy=${NO_PROXY_LIST}"
}

write_cleared_proxy_env() {
    echo "HTTP_PROXY="
    echo "HTTPS_PROXY="
    echo "http_proxy="
    echo "https_proxy="
    echo "ALL_PROXY="
    echo "all_proxy="
}

mkdir -p "$(dirname "${OUT}")"
TMP_FILE="$(mktemp "${OUT}.XXXXXX")"
CANDIDATES=""
PROXY_SOURCE=""
SELECTED_TYPE=""
SELECTED_HOST=""
SELECTED_PORT=""

parse_probe_override
discover_from_configs

if [[ -z "${CANDIDATES}" ]]; then
    append_ports_as_candidates "http" "${DEFAULT_HTTP_PORTS}"
    append_ports_as_candidates "socks5" "${DEFAULT_SOCKS_PORTS}"
    [[ -n "${CANDIDATES}" ]] && PROXY_SOURCE="fallback-ports"
fi

{
    write_common_env

    if select_proxy_candidate; then
        echo "MASKFORAI_PROXY_SOURCE=${PROXY_SOURCE:-probe}"
        case "${SELECTED_TYPE}" in
            http)
                log "mode=http upstream proxy on ${SELECTED_HOST}:${SELECTED_PORT} (${PROXY_SOURCE:-probe})"
                echo "MASKFORAI_PROXY_MODE=http"
                echo "HTTP_PROXY=http://${SELECTED_HOST}:${SELECTED_PORT}"
                echo "HTTPS_PROXY=http://${SELECTED_HOST}:${SELECTED_PORT}"
                echo "http_proxy=http://${SELECTED_HOST}:${SELECTED_PORT}"
                echo "https_proxy=http://${SELECTED_HOST}:${SELECTED_PORT}"
                echo "ALL_PROXY="
                echo "all_proxy="
                ;;
            socks5)
                log "mode=socks5 upstream proxy on ${SELECTED_HOST}:${SELECTED_PORT} (${PROXY_SOURCE:-probe})"
                echo "MASKFORAI_PROXY_MODE=socks5"
                echo "HTTP_PROXY="
                echo "HTTPS_PROXY="
                echo "http_proxy="
                echo "https_proxy="
                echo "ALL_PROXY=socks5h://${SELECTED_HOST}:${SELECTED_PORT}"
                echo "all_proxy=socks5h://${SELECTED_HOST}:${SELECTED_PORT}"
                ;;
        esac
    elif TUN_IFACE="$(tun_up)"; then
        log "mode=tun routing via interface=${TUN_IFACE} (clearing proxy env)"
        echo "MASKFORAI_PROXY_MODE=tun"
        echo "MASKFORAI_TUN_IFACE=${TUN_IFACE}"
        echo "MASKFORAI_PROXY_SOURCE=tun"
        write_cleared_proxy_env
    else
        log "WARNING: no proxy ports and no TUN interface detected — direct egress"
        echo "MASKFORAI_PROXY_MODE=direct"
        echo "MASKFORAI_PROXY_SOURCE=direct"
        write_cleared_proxy_env
    fi
} >"${TMP_FILE}"

mv -f "${TMP_FILE}" "${OUT}"
log "wrote ${OUT}"
