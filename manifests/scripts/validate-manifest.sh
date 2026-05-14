#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 1 ]; then
    echo "usage: $0 <path-to-manifest.toml>" >&2
    exit 2
fi
exec hatch manifest validate "$1"
