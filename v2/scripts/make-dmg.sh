#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
DMG="$ROOT/.tmp/bundle/t2t-v2.dmg"
STAGE="$ROOT/.tmp/bundle/dmg-stage"
rm -rf "$STAGE"
mkdir -p "$STAGE"
./scripts/build-shell.sh
cp -R "$ROOT/dist/T2T.app" "$STAGE/T2T.app"
ln -s /Applications "$STAGE/Applications"
cat > "$STAGE/README.txt" <<'TXT'
t2t v2 — drag T2T.app to Applications, then run ./scripts/install-bundle.sh from the unzipped bundle (or clone the repo and run ./scripts/install.sh).
First launch may need right-click Open because this build is ad-hoc signed, not notarized.
TXT
hdiutil create -volname t2t-v2 -fs HFS+ -ov -srcfolder "$STAGE" "$DMG"
ls -lh "$DMG"
