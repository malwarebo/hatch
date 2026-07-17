#!/bin/sh
# hatch installer: detect platform/arch, download the matching release
# artifact, verify it, and install the binaries.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/malwarebo/hatch/main/install.sh | sh
#
# Environment overrides:
#   HATCH_VERSION       Install a specific version (e.g. 0.1.1) instead of latest.
#   HATCH_INSTALL_DIR   Install location (default: /usr/local/bin as root,
#                       otherwise ~/.local/bin).
set -eu

REPO="malwarebo/hatch"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/main"

log()  { printf 'hatch-install: %s\n' "$*" >&2; }
err()  { printf 'hatch-install: error: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# --- download helper (curl or wget) ------------------------------------------
fetch() {
  # fetch <url> <dest>; returns nonzero on HTTP error
  url="$1"; dest="$2"
  if have curl; then
    curl -fsSL "$url" -o "$dest"
  elif have wget; then
    wget -q -O "$dest" "$url"
  else
    err "need curl or wget to download"
  fi
}

fetch_stdout() {
  url="$1"
  if have curl; then
    curl -fsSL "$url"
  elif have wget; then
    wget -q -O - "$url"
  else
    err "need curl or wget to download"
  fi
}

# --- platform detection ------------------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Linux)  platform="linux" ;;
  Darwin) platform="darwin" ;;
  *) err "unsupported OS: $os (hatch supports Linux and macOS)" ;;
esac

case "$arch" in
  x86_64|amd64) cpu="x86_64" ;;
  aarch64|arm64) cpu="aarch64" ;;
  *) err "unsupported architecture: $arch" ;;
esac

# --- resolve version ---------------------------------------------------------
version="${HATCH_VERSION:-}"
if [ -z "$version" ]; then
  log "resolving latest release..."
  tag="$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -m1 '"tag_name"' \
    | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
  [ -n "$tag" ] || err "could not resolve latest release tag"
  version="${tag#v}"
fi
log "installing hatch v${version} for ${platform}/${cpu}"

# --- asset name --------------------------------------------------------------
if [ "$platform" = "darwin" ]; then
  asset="hatch-${version}-universal-apple-darwin.tar.gz"
else
  asset="hatch-${version}-${cpu}-unknown-linux-gnu.tar.gz"
fi
base_url="https://github.com/${REPO}/releases/download/v${version}"

# --- workspace ---------------------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

log "downloading ${asset}"
fetch "${base_url}/${asset}" "$asset" || err "download failed: ${base_url}/${asset}"
fetch "${base_url}/SHA256SUMS" "SHA256SUMS" || err "download failed: SHA256SUMS"

# --- verify: minisign signature preferred, checksum always ------------------
verified_sig=0
if have minisign; then
  if fetch "${base_url}/SHA256SUMS.minisig" "SHA256SUMS.minisig" 2>/dev/null \
    && fetch "${RAW_BASE}/hatch.pub" "hatch.pub" 2>/dev/null; then
    if minisign -Vm SHA256SUMS -p hatch.pub >/dev/null 2>&1; then
      log "minisign signature verified"
      verified_sig=1
    else
      err "minisign signature verification FAILED for SHA256SUMS"
    fi
  fi
fi
[ "$verified_sig" -eq 1 ] || log "no signature verified (minisign or key unavailable); using checksum only"

# checksum check for the downloaded asset
expected="$(grep " ${asset}$" SHA256SUMS | awk '{print $1}' | head -n1)"
[ -n "$expected" ] || err "no checksum for ${asset} in SHA256SUMS"
if have sha256sum; then
  actual="$(sha256sum "$asset" | awk '{print $1}')"
elif have shasum; then
  actual="$(shasum -a 256 "$asset" | awk '{print $1}')"
else
  err "need sha256sum or shasum to verify download"
fi
[ "$expected" = "$actual" ] || err "checksum mismatch for ${asset}"
log "checksum verified"

# --- extract & install -------------------------------------------------------
tar -xzf "$asset"

if [ -n "${HATCH_INSTALL_DIR:-}" ]; then
  install_dir="$HATCH_INSTALL_DIR"
elif [ "$(id -u)" = "0" ]; then
  install_dir="/usr/local/bin"
else
  install_dir="$HOME/.local/bin"
fi
mkdir -p "$install_dir"

bins="hatch hatch-daemon hatch-shim"
[ "$platform" = "linux" ] && bins="$bins hatch-linux-helper"

for b in $bins; do
  [ -f "$b" ] || err "expected binary '$b' missing from archive"
  install -m 0755 "$b" "$install_dir/$b" 2>/dev/null \
    || { cp "$b" "$install_dir/$b" && chmod 0755 "$install_dir/$b"; }
  log "installed $install_dir/$b"
done

# --- post-install guidance ---------------------------------------------------
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) log "note: $install_dir is not on your PATH; add it to use 'hatch' directly" ;;
esac

cat >&2 <<EOF

hatch v${version} installed. Next steps:

  hatch doctor            # check the environment
  hatch --help            # command overview

Start the daemon:
EOF
if [ "$platform" = "linux" ]; then
  cat >&2 <<EOF
  # foreground (quick try):
  hatch-daemon --foreground --state-dir ~/.hatch
  # or, if the systemd user unit is installed (deb/rpm):
  systemctl --user enable --now hatch-daemon
EOF
else
  cat >&2 <<EOF
  # foreground (quick try):
  hatch-daemon --foreground --state-dir ~/.hatch
  # or load the launchd agent if installed via the .pkg:
  launchctl load ~/Library/LaunchAgents/sh.hatch.daemon.plist
EOF
fi
