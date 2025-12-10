# t2t

Hold **Fn key** to record audio, release to transcribe and auto-paste.

## How It Works

- Press and hold Fn key → records microphone audio
- Release Fn key → transcribes using local Whisper model, copies to clipboard, and pastes automatically
- Visual feedback: red orb while recording, orange while processing

## Setup

```bash
# Install dependencies
npm install

# Development
npm run tauri dev

# Build
npm run tauri build
```

## Requirements

- **Rust** (install via rustup)
- **Node.js 18+** (or Bun)
- **macOS** (currently macOS only)

## First Run

On first launch, the app automatically downloads the Whisper model (~150MB) to `~/.cache/whisper/ggml-base.en.bin`. This happens in the background.

## Permissions (macOS)

Grant these in **System Settings > Privacy & Security**:

- **Accessibility** - Required for global Fn key detection and auto-paste
- **Microphone** - Required for audio recording

The app will prompt you if permissions are missing.

## Tech Stack

- **Frontend**: Svelte 5 + SvelteKit
- **Backend**: Rust + Tauri
- **STT**: whisper-rs (local Whisper.cpp model)
- **Hotkey**: rdev (global key listener)

## License

MIT
