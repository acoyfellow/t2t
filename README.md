# t2t

Hold **Fn key** to record audio, release to transcribe and auto-paste.

## How It Works

- Press and hold Fn key → records microphone audio
- Release Fn key → transcribes using a local Whisper model, copies to clipboard, and pastes automatically
- Visual feedback: red orb while recording, orange while processing

## Setup

```bash
# Install dependencies
npm install

# Development
bun tauri dev

# Build
bun tauri build
```

## Requirements

- **Rust** (install via rustup)
- **Bun** (recommended) or Node.js 18+
- **macOS** (currently macOS only; tested on Apple Silicon)

## First Run

On first launch, the app automatically downloads the Whisper model (~150MB) to `~/.cache/whisper/ggml-base.en.bin`. This happens in the background.

## Permissions (macOS)

Grant these in **System Settings > Privacy & Security**:

- **Accessibility** - Required for Fn key detection and focusing the correct field before paste
- **Microphone** - Required for audio recording

The app will prompt you if permissions are missing.

## Tech Stack

- **Frontend**: Svelte 5 + SvelteKit
- **Backend**: Rust + Tauri
- **STT**: whisper-rs (local Whisper.cpp model)
- **Hotkey**: macOS event monitoring (Fn key) + fallbacks
- **Audio capture**: native (Rust via cpal)

## Notes / Debugging

- **Logs**: `~/Library/Logs/t2t.log`
- **Model location**: `~/.cache/whisper/ggml-base.en.bin`

## License

MIT
