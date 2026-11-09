#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
SECRETS="$ROOT/.secrets"
MODEL="$HOME/.cache/whisper/ggml-base.en.bin"
MODEL_URL="https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-base.en.bin"

check_only=0
[ "${1:-}" = "--check" ] && check_only=1

say() { printf '%s\n' "$*"; }
missing=()

say "== t2t v2 install =="

if [ "$(uname -m)" != "arm64" ]; then missing+=("Apple-silicon Mac required (uname -m = $(uname -m))"); fi
command -v swift >/dev/null || missing+=("Swift toolchain missing: xcode-select --install")
command -v node >/dev/null || missing+=("Node 22+ missing: brew install node@22")
command -v brew >/dev/null || missing+=("Homebrew missing: https://brew.sh")
command -v whisper-cli >/dev/null || command -v /opt/homebrew/bin/whisper-cli >/dev/null || missing+=("whisper-cpp missing: brew install whisper-cpp")
[ -f "$MODEL" ] || missing+=("Whisper model missing: $MODEL (install.sh can download it)")
for f in key gateway.url opencode.token; do [ -s "$SECRETS/$f" ] || missing+=(".secrets/$f missing — see README 'One-time setup'"); done
[ -f "$SECRETS/t2t.keychain-db" ] || missing+=("local signing keychain missing: $SECRETS/t2t.keychain-db (install.sh can create it)")

if [ "${#missing[@]}" -gt 0 ]; then
  say "Missing:"
  printf ' - %s\n' "${missing[@]}"
else
  say "All prerequisites present."
fi

if [ "$check_only" = 1 ]; then
  say "check-only: no changes made."
  exit 0
fi

mkdir -p "$SECRETS" "$ROOT/.tmp/logs" "$HOME/.cache/whisper"

if [ ! -f "$SECRETS/key" ]; then
  openssl rand -hex 32 > "$SECRETS/key"; chmod 600 "$SECRETS/key"
  say "Created .secrets/key (shared secret for shell, UI, and Worker)."
fi
if [ ! -f "$SECRETS/gateway.url" ]; then
  say "Create .secrets/gateway.url with your AI Gateway URL, e.g. https://gateway.ai.cloudflare.com/v1/<account>/<gateway>/anthropic"
fi
if [ ! -f "$SECRETS/opencode.token" ]; then
  say "Create .secrets/opencode.token with your gateway API token."
fi

if [ ! -f "$SECRETS/t2t.keychain-db" ]; then
  say "Creating local signing certificate and keychain..."
  PASS=$(openssl rand -hex 16)
  printf '%s' "$PASS" > "$SECRETS/keychain.pass"; chmod 600 "$SECRETS/keychain.pass"
  cat > "$SECRETS/cert.cnf" <<'CNF'
[req]
distinguished_name=dn
x509_extensions=ext
prompt=no
[dn]
CN=t2t local signing
[ext]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,codeSigning
CNF
  openssl req -x509 -newkey rsa:2048 -keyout "$SECRETS/signing.key" -out "$SECRETS/signing.crt" -days 3650 -nodes -config "$SECRETS/cert.cnf" >/dev/null 2>&1
  openssl pkcs12 -export -inkey "$SECRETS/signing.key" -in "$SECRETS/signing.crt" -out "$SECRETS/signing.p12" -passout "pass:$PASS" -name "t2t local signing" >/dev/null 2>&1
  security create-keychain -p "$PASS" "$SECRETS/t2t.keychain-db" >/dev/null
  security import "$SECRETS/signing.p12" -k "$SECRETS/t2t.keychain-db" -P "$PASS" -T /usr/bin/codesign >/dev/null
  say "Signing certificate ready. macOS will keep permissions across rebuilds."
fi

if [ ! -f "$MODEL" ]; then
  say "Downloading Whisper model (ggml-base.en.bin)..."
  curl -L -o "$MODEL" "$MODEL_URL"
fi

say "Installing Node dependencies..."
npm install --no-audit --no-fund

NODE_BIN=$(command -v node)
cat > "$HOME/Library/LaunchAgents/dev.coey.t2t-ui.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>dev.coey.t2t-ui</string>
<key>ProgramArguments</key><array><string>$NODE_BIN</string><string>$ROOT/node_modules/vite/bin/vite.js</string><string>--config</string><string>ui/vite.config.ts</string></array>
<key>WorkingDirectory</key><string>$ROOT</string>
<key>EnvironmentVariables</key><dict><key>PATH</key><string>$(dirname "$NODE_BIN"):/opt/homebrew/bin:/usr/bin:/bin</string></dict>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>$ROOT/.tmp/logs/ui.log</string>
<key>StandardErrorPath</key><string>$ROOT/.tmp/logs/ui.log</string>
</dict></plist>
PLIST
launchctl bootout "gui/$(id -u)/dev.coey.t2t-ui" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/dev.coey.t2t-ui.plist" 2>/dev/null || true
say "UI LaunchAgent installed (dev.coey.t2t-ui) — starts at login, logs to .tmp/logs/ui.log."

if [ -s "$SECRETS/gateway.url" ] && [ -s "$SECRETS/opencode.token" ]; then
  say "Deploying agent Worker..."
  ./scripts/deploy.sh
else
  say "Skipping Worker deploy until .secrets/gateway.url and .secrets/opencode.token exist. Run ./scripts/deploy.sh after creating them."
fi

say "Building app..."
./scripts/build-shell.sh
open -g "$ROOT/dist/T2T.app"
say "Done. Grant Input Monitoring, Accessibility, Screen Recording, and Microphone when macOS asks. Settings > General shows what is missing."
say "First dictation downloads nothing — the Whisper model is already at ~/.cache/whisper/ggml-base.en.bin"
