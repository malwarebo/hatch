#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <bundle.tar.zst> <ed25519-private-key.pem>" >&2
    exit 2
fi

bundle="$1"
key="$2"

if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl required" >&2
    exit 3
fi

openssl pkeyutl -sign -rawin -inkey "$key" -in "$bundle" -out "${bundle}.sig"
echo "signed: ${bundle}.sig"
