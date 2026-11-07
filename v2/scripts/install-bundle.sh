#!/bin/bash
set -euo pipefail
BUNDLE="$(cd "$(dirname "$0")/.." && pwd)"
MODEL="$HOME/.cache/whisper/ggml-base.en.bin"
MODEL_URL="https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-base.en.bin"

say() { printf '%s\n' "$*"; }
[ "$(uname -m)" = "arm64" ] || { say "Apple-silicon Mac required."; exit 1; }
command -v node >/dev/null || { say "Node 22+ required: brew install node@22"; exit 1; }
command -v whisper-cli >/dev/null || command -v /opt/homebrew/bin/whisper-cli >/dev/null || say "Tip: brew install whisper-cpp for dictation."

mkdir -p "$HOME/.cache/whisper" "$BUNDLE/.tmp/logs"
[ -f "$MODEL" ] || { say "Downloading Whisper model..."; curl -L -o "$MODEL" "$MODEL_URL"; }

defaults write dev.coey.t2t mcpHostScript "$BUNDLE/bridge/mcp-host.mjs"
say "MCP host pointed at $BUNDLE/bridge/mcp-host.mjs"

NODE_BIN=$(command -v node)
cat > "$HOME/Library/LaunchAgents/dev.coey.t2t-ui.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>dev.coey.t2t-ui</string>
<key>ProgramArguments</key><array><string>$NODE_BIN</string><string>$BUNDLE/scripts/serve-ui.mjs</string><string>$BUNDLE/ui</string></array>
<key>WorkingDirectory</key><string>$BUNDLE</string>
<key>EnvironmentVariables</key><dict><key>PATH</key><string>$(dirname "$NODE_BIN"):/opt/homebrew/bin:/usr/bin:/bin</string></dict>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>$BUNDLE/.tmp/logs/ui.log</string>
<key>StandardErrorPath</key><string>$BUNDLE/.tmp/logs/ui.log</string>
</dict></plist>
PLIST
launchctl bootout "gui/$(id -u)/dev.coey.t2t-ui" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/dev.coey.t2t-ui.plist" 2>/dev/null || true
sleep 1
curl -s -o /dev/null -w "UI %{http_code}\n" localhost:5197/ || say "UI not up yet; check $BUNDLE/.tmp/logs/ui.log"

xattr -dr com.apple.quarantine "$BUNDLE/T2T.app" 2>/dev/null || true
open -g "$BUNDLE/T2T.app"
say "Done. Grant Input Monitoring, Accessibility, Screen Recording, and Microphone when macOS asks."
say "Dictation works out of the box. Agent mode needs your own Worker deploy from source (see README) or a maintainer key."
