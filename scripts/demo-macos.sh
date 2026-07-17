#!/bin/sh
# macOS end-to-end demo. The same MCP server (a curl reaching example.com) is
# run three ways to show hatch enforces the manifest's network allowlist:
#
#   1. no isolation (stub backend)        -> reaches the host (baseline)
#   2. hatch, host ON the allowlist       -> reaches it *through* the proxy
#   3. hatch, host NOT on the allowlist   -> blocked at the proxy
#
# Usage: scripts/demo-macos.sh
set -eu

cd "$(dirname "$0")/.."
DEMO="$(mktemp -d)"
trap 'rm -rf "$DEMO"' EXIT

echo "==> building daemon + cli"
cargo build -q -p hatch-daemon -p hatch-cli -p hatch-shim
BIN="$(cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["target_directory"])')/debug"

# Writes a manifest whose curl targets example.com; $1 = name, $2 = allowlist
# entry ("" for an empty allowlist).
write_manifest() {
  name="$1"; allow="$2"
  allow_line="allow_https = []"
  dns_line="allow_dns = []"
  if [ -n "$allow" ]; then
    allow_line="allow_https = [\"$allow\"]"
    dns_line="allow_dns = [\"$allow\"]"
  fi
  cat > "$DEMO/$name.toml" <<TOML
schema_version = "1.0"
name = "$name"
version = "0.1.0"
description = "curl example.com under policy"
[command]
program = "/usr/bin/curl"
args = ["-sS", "--max-time", "8", "-o", "/dev/null", "-w", "HTTP %{http_code}\\n", "https://example.com"]
[network]
$allow_line
$dns_line
[filesystem]
read = []
write = []
tmpfs = ["/tmp"]
[env]
passthrough = []
[exec]
allow_subprocess = false
allow_binaries = []
[resources]
memory_mb = 128
cpu_percent = 25
pids_max = 20
nofile = 64
tool_call_timeout_seconds = 30
[tool_policy]
require_approval = []
deny = []
[platform.linux]
seccomp_preset = "strict"
landlock = true
[platform.macos]
endpoint_security = false
TOML
}

# $1 label, $2 manifest name, $3 socket tag, then daemon flags
run_scenario() {
  label="$1"; name="$2"; tag="$3"; shift 3
  sock="$DEMO/$tag.sock"; state="$DEMO/state-$tag"
  rm -f "$sock"; rm -rf "$state"
  "$BIN/hatch-daemon" --foreground --state-dir "$state" --socket "$sock" "$@" \
    > "$DEMO/daemon-$tag.log" 2>&1 &
  dpid=$!
  i=0; while [ ! -S "$sock" ] && [ "$i" -lt 40 ]; do sleep 0.25; i=$((i+1)); done
  "$BIN/hatch" --socket "$sock" --state-dir "$state" \
    install --file "$DEMO/$name.toml" --allow-unsigned >/dev/null 2>&1
  echo ""
  echo "=== $label ==="
  "$BIN/hatch" --socket "$sock" --state-dir "$state" run "$name" --seconds 12 2>&1 || true
  kill "$dpid" 2>/dev/null || true
  wait "$dpid" 2>/dev/null || true
}

write_manifest exfil ""
write_manifest allowed "example.com"

run_scenario "WITHOUT hatch (stub) — reaches example.com: HTTP 200" exfil stub
run_scenario "WITH hatch — example.com ALLOWLISTED — flows through proxy: HTTP 200" \
  allowed allow --real-sandbox --enable-proxy
run_scenario "WITH hatch — example.com NOT allowlisted — blocked at proxy" \
  exfil deny --real-sandbox --enable-proxy

echo ""
echo "==> hatch let the allowlisted host through and blocked the one that wasn't."
