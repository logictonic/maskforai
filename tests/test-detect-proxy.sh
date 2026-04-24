#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_PATH="${ROOT_DIR}/bin/maskforai-detect-proxy.sh"
TMP_DIR="$(mktemp -d)"

cleanup() {
    if [[ -n "${HTTP_PID:-}" ]]; then
        kill "${HTTP_PID}" 2>/dev/null || true
    fi
    if [[ -n "${SOCKS_PID:-}" ]]; then
        kill "${SOCKS_PID}" 2>/dev/null || true
    fi
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_contains() {
    local file="$1"
    local needle="$2"
    if ! rg -q --fixed-strings "${needle}" "${file}"; then
        printf 'Expected to find %s in %s\n' "${needle}" "${file}" >&2
        printf -- '--- %s ---\n' "${file}" >&2
        sed -n '1,160p' "${file}" >&2
        fail "assert_contains failed"
    fi
}

assert_not_contains() {
    local file="$1"
    local needle="$2"
    if rg -q --fixed-strings "${needle}" "${file}"; then
        printf 'Did not expect to find %s in %s\n' "${needle}" "${file}" >&2
        printf -- '--- %s ---\n' "${file}" >&2
        sed -n '1,160p' "${file}" >&2
        fail "assert_not_contains failed"
    fi
}

free_port() {
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

start_http_proxy_stub() {
    local port="$1"
    python3 - <<PY >/dev/null 2>&1 &
import socket
import time

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", ${port}))
server.listen(5)
conn, _ = server.accept()
conn.recv(4096)
conn.sendall(b"HTTP/1.1 200 Connection established\\r\\nProxy-Agent: test\\r\\n\\r\\n")
time.sleep(1)
conn.close()
server.close()
PY
    HTTP_PID=$!
    sleep 0.2
}

start_socks_proxy_stub() {
    local port="$1"
    python3 - <<PY >/dev/null 2>&1 &
import socket
import time

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", ${port}))
server.listen(5)
conn, _ = server.accept()
conn.recv(3)
conn.sendall(b"\\x05\\x00")
time.sleep(1)
conn.close()
server.close()
PY
    SOCKS_PID=$!
    sleep 0.2
}

run_detector() {
    local output_file="$1"
    local log_file="$2"
    shift 2
    (
        export HTTP_PROXY="http://127.0.0.1:9"
        export HTTPS_PROXY="http://127.0.0.1:9"
        export ALL_PROXY="socks5h://127.0.0.1:9"
        "$@" "${SCRIPT_PATH}" "${output_file}"
    ) >"${log_file}" 2>&1
}

test_http_override() {
    local port output log
    port="$(free_port)"
    output="${TMP_DIR}/http.env"
    log="${TMP_DIR}/http.log"

    start_http_proxy_stub "${port}"

    run_detector "${output}" "${log}" env \
        MASKFORAI_PROXY_CONFIG_PATHS="/nonexistent" \
        MASKFORAI_PROXY_HTTP_PORTS="${port}" \
        MASKFORAI_PROXY_SOCKS_PORTS="" \
        MASKFORAI_TUN_IFACES="__none__"

    kill "${HTTP_PID}" 2>/dev/null || true
    unset HTTP_PID

    assert_contains "${output}" "MASKFORAI_PROXY_MODE=http"
    assert_contains "${output}" "HTTP_PROXY=http://127.0.0.1:${port}"
    assert_contains "${output}" "ALL_PROXY="
}

test_socks_override() {
    local port output log
    port="$(free_port)"
    output="${TMP_DIR}/socks.env"
    log="${TMP_DIR}/socks.log"

    start_socks_proxy_stub "${port}"

    run_detector "${output}" "${log}" env \
        MASKFORAI_PROXY_CONFIG_PATHS="/nonexistent" \
        MASKFORAI_PROXY_HTTP_PORTS="" \
        MASKFORAI_PROXY_SOCKS_PORTS="${port}" \
        MASKFORAI_TUN_IFACES="__none__"

    kill "${SOCKS_PID}" 2>/dev/null || true
    unset SOCKS_PID

    assert_contains "${output}" "MASKFORAI_PROXY_MODE=socks5"
    assert_contains "${output}" "ALL_PROXY=socks5h://127.0.0.1:${port}"
    assert_contains "${output}" "HTTP_PROXY="
}

test_tun_fallback() {
    local output log
    output="${TMP_DIR}/tun.env"
    log="${TMP_DIR}/tun.log"

    run_detector "${output}" "${log}" env \
        MASKFORAI_PROXY_CONFIG_PATHS="/nonexistent" \
        MASKFORAI_PROXY_HTTP_PORTS="" \
        MASKFORAI_PROXY_SOCKS_PORTS="" \
        MASKFORAI_TUN_IFACES="lo"

    assert_contains "${output}" "MASKFORAI_PROXY_MODE=tun"
    assert_contains "${output}" "MASKFORAI_TUN_IFACE=lo"
    assert_contains "${output}" "HTTP_PROXY="
    assert_contains "${output}" "ALL_PROXY="
}

test_direct_fallback() {
    local output log
    output="${TMP_DIR}/direct.env"
    log="${TMP_DIR}/direct.log"

    run_detector "${output}" "${log}" env \
        MASKFORAI_PROXY_CONFIG_PATHS="/nonexistent" \
        MASKFORAI_PROXY_HTTP_PORTS="" \
        MASKFORAI_PROXY_SOCKS_PORTS="" \
        MASKFORAI_TUN_IFACES="__none__" \
        MASKFORAI_PROXY_DISABLE_GLOB_TUN=1

    assert_contains "${output}" "MASKFORAI_PROXY_MODE=direct"
    assert_contains "${output}" "HTTP_PROXY="
    assert_contains "${output}" "ALL_PROXY="
    assert_contains "${log}" "WARNING: no proxy ports and no TUN interface detected"
}

test_config_parsing_preferred() {
    local port config_dir output log
    port="$(free_port)"
    config_dir="${TMP_DIR}/config"
    mkdir -p "${config_dir}"
    output="${TMP_DIR}/config.env"
    log="${TMP_DIR}/config.log"

    start_http_proxy_stub "${port}"

    cat >"${config_dir}/sing-box.json" <<EOF
{
  "inbounds": [
    {
      "type": "mixed",
      "listen": "127.0.0.1",
      "listen_port": ${port},
      "tag": "mixed-in"
    }
  ]
}
EOF

    run_detector "${output}" "${log}" env \
        MASKFORAI_PROXY_CONFIG_PATHS="${config_dir}/sing-box.json" \
        MASKFORAI_PROXY_HTTP_PORTS="" \
        MASKFORAI_PROXY_SOCKS_PORTS="" \
        MASKFORAI_TUN_IFACES="__none__"

    kill "${HTTP_PID}" 2>/dev/null || true
    unset HTTP_PID

    assert_contains "${output}" "MASKFORAI_PROXY_MODE=http"
    assert_contains "${output}" "HTTP_PROXY=http://127.0.0.1:${port}"
}

test_non_proxy_http_port_is_ignored() {
    local port output log
    port="$(free_port)"
    output="${TMP_DIR}/not-proxy.env"
    log="${TMP_DIR}/not-proxy.log"

    python3 -m http.server "${port}" --bind 127.0.0.1 >/dev/null 2>&1 &
    HTTP_PID=$!
    sleep 0.5

    run_detector "${output}" "${log}" env \
        MASKFORAI_PROXY_CONFIG_PATHS="/nonexistent" \
        MASKFORAI_PROXY_HTTP_PORTS="${port}" \
        MASKFORAI_PROXY_SOCKS_PORTS="" \
        MASKFORAI_TUN_IFACES="__none__" \
        MASKFORAI_PROXY_DISABLE_GLOB_TUN=1

    kill "${HTTP_PID}" 2>/dev/null || true
    unset HTTP_PID

    assert_contains "${output}" "MASKFORAI_PROXY_MODE=direct"
}

main() {
    [[ -x "${SCRIPT_PATH}" ]] || fail "detector script missing: ${SCRIPT_PATH}"

    test_http_override
    test_socks_override
    test_tun_fallback
    test_direct_fallback
    test_config_parsing_preferred
    test_non_proxy_http_port_is_ignored

    printf 'ok\n'
}

main "$@"
