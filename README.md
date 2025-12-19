# t2t

![t2t logo](static/logo.svg)

**Voice-to-text with intelligence. Hold fn to talk, hold fn+ctrl to command.**

## Download

**[Download for macOS →](https://t2t.now)**

[View all releases on GitHub →](https://github.com/acoyfellow/t2t/releases)

> **Note:** The app is not code-signed yet. On first launch, macOS may show a security warning. To open it:
> - Right-click the app → **Open**, then click **Open** in the dialog
> - Or run: `xattr -cr /Applications/t2t.app` in Terminal

## How It Works

- **Hold Fn key** → records microphone audio
- **Release Fn key** → transcribes using local Whisper model
- **Typing mode** (red bar): Hold Fn alone → pastes transcription into focused text field, preserves clipboard
- **Agent mode** (cyan bar): Hold Fn+Ctrl → speaks commands to AI agent that generates and executes AppleScript
- Visual feedback: red/cyan bar while recording (based on mode), amber while processing

## Requirements

- **macOS** (currently macOS only; tested on Apple Silicon)
- **Accessibility permission** - Required for Fn key detection and focusing the correct field before paste
- **Microphone permission** - Required for audio recording

The app will prompt you if permissions are missing.

## First Run

On first launch, the app automatically downloads the Whisper model (~150MB) to `~/.cache/whisper/ggml-base.en.bin`. This happens in the background.

## For Developers

### Setup

```bash
# Install dependencies
bun install

# Development
bun tauri dev

# Build
bun tauri build
```

### Requirements

- **Rust** (install via rustup)
- **Bun** (recommended) or Node.js 18+

### Tech Stack

- **Frontend**: Svelte 5 + SvelteKit
- **Backend**: Rust + Tauri
- **STT**: whisper-rs (local Whisper.cpp model)
- **Agent API**: Cloudflare Workers AI (hosted at t2t.now)
- **Hotkey**: macOS event monitoring (Fn key) + fallbacks
- **Audio capture**: native (Rust via cpal)

### Debugging

- **Logs**: `~/Library/Logs/t2t.log`
- **Model location**: `~/.cache/whisper/ggml-base.en.bin`

## License

MIT
