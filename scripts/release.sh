#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <version>" >&2
    exit 2
fi
VERSION="$1"

if ! git diff --quiet HEAD 2>/dev/null; then
    echo "working tree is dirty; commit or stash first" >&2
    exit 3
fi

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked

case "$(uname -s)" in
    Linux)
        cargo build --release --target x86_64-unknown-linux-gnu
        cargo build --release --target aarch64-unknown-linux-gnu
        ;;
    Darwin)
        cargo build --release --target x86_64-apple-darwin
        cargo build --release --target aarch64-apple-darwin
        ./scripts/notarize-macos.sh "$VERSION"
        ;;
    *)
        echo "unsupported OS: $(uname -s)" >&2
        exit 4
        ;;
esac

echo "ok: built $VERSION"
