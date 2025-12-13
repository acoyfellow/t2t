#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SRC="$ROOT/target/release/bundle/macos/t2t.app"
DST="/Applications/t2t.app"

bun tauri build --bundles app

rm -rf "$DST"
cp -R "$SRC" "$DST"

if [[ -n "${T2T_SIGN_IDENTITY:-}" ]]; then
  /usr/bin/codesign --force --deep --options runtime \
    --entitlements "$ROOT/entitlements.plist" \
    --sign "$T2T_SIGN_IDENTITY" \
    "$DST"

  /usr/bin/codesign -dv --verbose=4 "$DST" 2>/dev/null | sed -n '1,120p'
else
  echo "NOTE: not signing (set T2T_SIGN_IDENTITY to a valid codesigning identity to persist macOS permissions across builds)"
fi


