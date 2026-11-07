#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
OUT="$ROOT/.tmp/bundle/t2t-v2"
rm -rf "$ROOT/.tmp/bundle"
mkdir -p "$OUT"

./scripts/build-shell.sh
(cd ui && npx vite build >/dev/null)

cp -R "$ROOT/dist/T2T.app" "$OUT/T2T.app"
cp -R "$ROOT/dist/ui" "$OUT/ui"
mkdir -p "$OUT/bridge" "$OUT/scripts"
cp bridge/mcp-host.mjs "$OUT/bridge/"
cp scripts/serve-ui.mjs scripts/install-bundle.sh "$OUT/scripts/"
printf '{"dependencies":{"@modelcontextprotocol/sdk":"^1.32.2"}}' > "$OUT/bridge/package.json"
(cd "$OUT/bridge" && npm install --ignore-scripts --no-audit --no-fund >/dev/null)
rm -f "$OUT/bridge/package.json"
cat > "$OUT/README.txt" <<'TXT'
t2t v2 bundle — macOS Apple silicon.

Run ./scripts/install-bundle.sh, grant the four permissions, hold Fn to dictate.
Dictation is local. Agent mode needs a Worker deploy from source or a maintainer key; see the repo README.
TXT
chmod +x "$OUT/scripts/install-bundle.sh"
(cd "$OUT/.." && zip -qr t2t-v2.zip t2t-v2)
ls -lh "$ROOT/.tmp/bundle/t2t-v2.zip"
