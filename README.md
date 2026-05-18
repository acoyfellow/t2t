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

## Recommended AI setup: Cloudflare AI Gateway

Pi already supports Cloudflare AI Gateway. Configure the provider outside t2t, then select it in t2t Settings:

```bash
export CLOUDFLARE_API_KEY=...
export CLOUDFLARE_ACCOUNT_ID=...
export CLOUDFLARE_GATEWAY_ID=...

pi --provider cloudflare-ai-gateway --model gpt-5.4-mini -p "hello"
```

In **t2t → Settings**, use:

- Pi binary: `pi`
- Provider: `cloudflare-ai-gateway`
- Model: any model available through your gateway

### Cloudflare employee local mode

Jordan's local setup uses the existing Pi/OpenCode provider:

- Provider: `opencode.cloudflare.dev`
- Model: `ember-alpha`

That setup is local/private configuration, not required by the public repo.

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
