#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
APP="$ROOT/dist/T2T.app"
( cd shell && swift build -c release >/dev/null )
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp shell/.build/release/T2T "$APP/Contents/MacOS/T2T"
cp shell/Resources/AppIcon.icns shell/Resources/mark.svg "$APP/Contents/Resources/"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.coey.t2t</string>
<key>CFBundleName</key><string>t2t</string>
<key>CFBundleExecutable</key><string>T2T</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>2.0.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>LSUIElement</key><true/>
<key>NSMicrophoneUsageDescription</key><string>t2t records your voice while you hold Fn.</string>
<key>NSAppTransportSecurity</key><dict><key>NSAllowsLocalNetworking</key><true/></dict>
</dict></plist>
PLIST
cat > "$ROOT/.tmp/entitlements.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.device.audio-input</key><true/>
</dict></plist>
PLIST
KC="$ROOT/.secrets/t2t.keychain-db"
security unlock-keychain -p "$(cat "$ROOT/.secrets/keychain.pass")" "$KC"
security list-keychains -d user -s "$HOME/Library/Keychains/login.keychain-db" "$KC"
codesign --force --options runtime --entitlements "$ROOT/.tmp/entitlements.plist" -s "t2t local signing" "$APP"
codesign -d -r- "$APP" 2>&1 | tail -1
