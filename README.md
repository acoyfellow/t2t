# t2t

![t2t logo](web/static/logo.svg)

**Local push-to-talk dictation for macOS. Hold Fn to type. Hold Fn+Ctrl to talk to a local Pi agent.**

## Download

**[Download for macOS →](https://t2t.now)**

[View all releases on GitHub →](https://github.com/acoyfellow/t2t/releases)

> t2t is currently unsigned. After replacing the app, macOS may require you to re-enable **Accessibility** permission for `/Applications/t2t.app`.

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

```bash
cd desktop
bun install
bun run check
bunx tauri dev
```

Build:

```bash
cd desktop
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
