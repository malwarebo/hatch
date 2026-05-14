#!/usr/bin/env bash
set -euo pipefail

echo "hatch dev setup"

if ! command -v rustup >/dev/null 2>&1; then
    echo "rustup required: https://rustup.rs" >&2
    exit 1
fi

rustup show >/dev/null
rustup component add rustfmt clippy

if ! command -v cargo-deny >/dev/null 2>&1; then
    cargo install cargo-deny --locked
fi
if ! command -v cargo-nextest >/dev/null 2>&1; then
    cargo install cargo-nextest --locked || true
fi

case "$(uname -s)" in
    Linux)
        echo "linux: confirm user namespaces are enabled with:"
        echo "  sysctl kernel.unprivileged_userns_clone"
        echo "linux: install seccomp + landlock headers via your package manager"
        ;;
    Darwin)
        echo "macos: \`hatch install --system\` (after building) provisions the UID pool"
        ;;
esac

cargo build --workspace
echo "ok"
