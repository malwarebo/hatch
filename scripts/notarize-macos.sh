#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <version>" >&2
    exit 2
fi
VERSION="$1"

: "${APPLE_DEVELOPER_ID_APPLICATION:?set APPLE_DEVELOPER_ID_APPLICATION (e.g. 'Developer ID Application: <name> (<TEAMID>)')}"
: "${APPLE_DEVELOPER_ID_INSTALLER:?set APPLE_DEVELOPER_ID_INSTALLER}"
: "${APPLE_NOTARY_PROFILE:?set APPLE_NOTARY_PROFILE (xcrun notarytool keychain profile)}"

OUT="dist/macos"
mkdir -p "$OUT"

ENTITLEMENTS="packaging/macos/entitlements.plist"
if [ ! -f "$ENTITLEMENTS" ]; then
    mkdir -p packaging/macos
    cat > "$ENTITLEMENTS" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-jit</key><false/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key><false/>
    <key>com.apple.security.cs.disable-library-validation</key><false/>
</dict>
</plist>
PLIST
fi

for bin in hatch hatch-daemon hatch-shim; do
    lipo -create -output "$OUT/$bin" \
        "target/x86_64-apple-darwin/release/$bin" \
        "target/aarch64-apple-darwin/release/$bin"
    codesign --force --options runtime --timestamp \
        --sign "$APPLE_DEVELOPER_ID_APPLICATION" \
        --entitlements "$ENTITLEMENTS" \
        "$OUT/$bin"
done

ROOT="$OUT/pkg-root"
mkdir -p "$ROOT/usr/local/bin"
mkdir -p "$ROOT/Library/LaunchAgents"
cp "$OUT/hatch" "$OUT/hatch-daemon" "$OUT/hatch-shim" "$ROOT/usr/local/bin/"
cp packaging/macos/sh.hatch.daemon.plist "$ROOT/Library/LaunchAgents/"

UNSIGNED_PKG="$OUT/hatch-${VERSION}-unsigned.pkg"
pkgbuild --root "$ROOT" \
    --identifier sh.hatch.pkg \
    --version "$VERSION" \
    --install-location / \
    "$UNSIGNED_PKG"

SIGNED_PKG="$OUT/hatch-${VERSION}.pkg"
productsign --sign "$APPLE_DEVELOPER_ID_INSTALLER" "$UNSIGNED_PKG" "$SIGNED_PKG"

xcrun notarytool submit "$SIGNED_PKG" --wait --keychain-profile "$APPLE_NOTARY_PROFILE"
xcrun stapler staple "$SIGNED_PKG"

shasum -a 256 "$SIGNED_PKG" > "${SIGNED_PKG}.sha256"
echo "ok: $SIGNED_PKG"
