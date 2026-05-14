#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
    echo "macos only" >&2
    exit 2
fi

if [ "$EUID" -ne 0 ]; then
    echo "must run as root (sudo $0)" >&2
    exit 3
fi

if ! dscl . -read /Groups/_hatch >/dev/null 2>&1; then
    dscl . -create /Groups/_hatch
    dscl . -create /Groups/_hatch PrimaryGroupID 300
    dscl . -create /Groups/_hatch RealName "Hatch Sandbox"
    dscl . -create /Groups/_hatch Password "*"
fi

for i in $(seq -f "%03g" 1 64); do
    user="_hatch_${i}"
    uid=$((300 + 10#${i}))
    if dscl . -read "/Users/${user}" >/dev/null 2>&1; then
        continue
    fi
    dscl . -create "/Users/${user}"
    dscl . -create "/Users/${user}" UserShell /usr/bin/false
    dscl . -create "/Users/${user}" NFSHomeDirectory /var/empty
    dscl . -create "/Users/${user}" UniqueID "${uid}"
    dscl . -create "/Users/${user}" PrimaryGroupID 300
    dscl . -create "/Users/${user}" RealName "Hatch Sandbox ${i}"
    dscl . -create "/Users/${user}" Password "*"
    dscl . -append "/Groups/_hatch" GroupMembership "${user}"
done

echo "ok: provisioned 64 _hatch_NNN service accounts"
