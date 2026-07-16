# t2t

![t2t logo](web/static/logo.svg)

**Local push-to-talk dictation for macOS. Hold Fn to type. Hold Fn+Ctrl to talk to a local Pi agent.**

## Download

**[Download for macOS →](https://t2t.now)**

[View all releases on GitHub →](https://github.com/acoyfellow/t2t/releases)

> t2t is currently ad-hoc signed for local development. Always run the installed app at `/Applications/t2t.app`; do not launch the copy inside `desktop/target`. After rebuilding, macOS may require you to re-enable **Accessibility**, **Microphone**, and **Input Monitoring** for `/Applications/t2t.app`.

## What it does

- **Fn** → record speech, transcribe locally with Whisper, paste into the focused text field.
- **Fn+Ctrl** → record speech, transcribe locally, send the prompt to the local `pi` CLI agent, then speak Pi's reply with macOS text-to-speech.
- **Agent tools stay enabled.** t2t delegates the agent loop to Pi rather than embedding a hosted chat client.
- **Cloudflare AI Gateway is the recommended public model path.** Users choose their Pi provider and model.

## Requirements

- macOS
- Accessibility permission
- Microphone permission
- [`pi`](https://github.com/badlogic/pi-mono) or a compatible `pi` CLI on `PATH` for Fn+Ctrl agent mode
- A Pi provider/model configuration

## AI setup

`t2t` delegates agent requests to the locally installed `pi` CLI, using the same local Pi authentication and provider configuration as a normal Pi session. The default configuration mirrors the local setup:

- Provider: `cloudflare-ai-gateway`
- Model: `gpt-5.6-luna`
- Thinking: `medium`
- Session mode: `--no-session`

Credentials are never stored in the t2t repository. They remain in Pi's local configuration. The settings screen allows overriding the binary, provider, model, thinking level, and optional CA bundle.

## Settings

The Settings tab includes:

- Theme
- Pi voice agent config
  - Pi binary
  - Provider
  - Model
- Speak agent responses aloud
- MCP server management / discovery surface
- History and analytics

## History & logging

- Transcriptions are stored locally.
- Pi agent prompt/response summaries are stored locally.
- Logs: `~/Library/Logs/t2t.log`
- Whisper model: `~/.cache/whisper/ggml-base.en.bin`

## Developer setup

Use this workflow from the repository root. It keeps one canonical app location and avoids macOS granting permissions to a temporary build copy.

### 1. Install dependencies and validate

```bash
cd /Users/jcoeyman/cloudflare/t2t/desktop
bun install
bun run check
cargo check
```

### 2. Run local development

Use this only for development work:

```bash
cd /Users/jcoeyman/cloudflare/t2t/desktop
bunx tauri dev
```

The development process is not the same identity/path as the installed app, so macOS permissions granted to `/Applications/t2t.app` may not apply to it.

### 3. Build, install, and launch the canonical app

For normal local use, build and install through the repository script, then launch the installed app:

```bash
cd /Users/jcoeyman/cloudflare/t2t/desktop
bun run macos:install
open -a /Applications/t2t.app
```

`macos:install` builds the release app, replaces `/Applications/t2t.app`, and leaves the source checkout unchanged. Do not open `desktop/target/release/.../t2t.app` directly.

### 4. Repair macOS permissions after a rebuild

If Fn capture, dictation, paste, or microphone access stops working:

```bash
# Stop only T2T, if it is running.
pkill -f '/Applications/t2t.app/Contents/MacOS/t2t' 2>/dev/null || true
pkill -f '/Users/jcoeyman/cloudflare/t2t/desktop/target/release/bundle/macos/t2t.app/Contents/MacOS/t2t' 2>/dev/null || true

# Reset only T2T's privacy grants. You will need to approve them again.
tccutil reset Accessibility com.t2t.desktop
tccutil reset Microphone com.t2t.desktop
tccutil reset ListenEvent com.t2t.desktop

# Open Privacy & Security and re-enable /Applications/t2t.app.
open 'x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility'
open 'x-apple.systempreferences:com.apple.preference.security?Privacy_Microphone'
open 'x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent'

open -a /Applications/t2t.app
```

In **System Settings → Privacy & Security**, approve `/Applications/t2t.app` under Accessibility and Microphone, and under Input Monitoring if it appears there. If permissions continue to reset between builds, install a stable Apple Developer signing identity; local builds are currently ad-hoc signed.

### 5. Verify the canonical installation

```bash
ps -axo pid,args | grep '[t]2t.app/Contents/MacOS/t2t'
ls -ld /Applications/t2t.app
cd /Users/jcoeyman/cloudflare/t2t
git diff --check
```

Build directly, without installing, when you only need an artifact:

```bash
cd /Users/jcoeyman/cloudflare/t2t/desktop
bun run build
```

## Tech stack

- Tauri + Rust
- Svelte 5 / SvelteKit
- whisper-rs local transcription
- local `pi` CLI agent bridge
- Cloudflare AI Gateway recommended for model routing
- macOS `say` for spoken agent replies

## License

MIT
