# t2t

![t2t logo](web/static/logo.svg)

**Voice-to-text with intelligence. Hold fn to talk, hold fn+ctrl to command.**

## Download

**[Download for macOS →](https://t2t.now)**

[View all releases on GitHub →](https://github.com/acoyfellow/t2t/releases)

> **Note:** The app is not code-signed yet. On first launch:
> - Right-click the app → **Open**, then click **Open** in the dialog
> - Or run: `xattr -cr /Applications/t2t.app` in Terminal
>
> Each update may require re-adding t2t in System Settings → Privacy & Security → Accessibility.

## Get started

1. Download and install from [t2t.now](https://t2t.now)
2. Grant Accessibility and Microphone permissions when prompted
3. **Hold fn** → speak → release → text appears in your focused field

That's it. You're dictating.

## Usage

### fn — Dictate

Hold fn, speak, release. Your words are transcribed locally (Whisper) and pasted into whatever text field is focused. Clipboard is preserved.

- Green status bar while recording
- Amber bar while transcribing

### fn+ctrl — Command Shelley

Hold fn, then hold ctrl, speak a command, release. Your voice is sent to Shelley, a coding agent that runs locally inside t2t.

- Purple status bar while recording
- Orange bar with sweep animation while Shelley is working
- **Click the orange bar** to open the Chat tab and see what Shelley is doing
- Press Escape to dismiss

Shelley requires an API key (it calls the model over the internet). Set it in Settings.

**Fallback chain:** If Shelley isn't available, agent mode falls back to MCP servers (if configured), then to AppleScript generation.

### Vision

Agent mode automatically captures a screenshot with each command. Vision-capable models see your screen context; text-only models ignore it. No setup required.

## Settings

Menu bar icon → **View Settings**. Four tabs:

| Tab | What it shows |
|---|---|
| **Analytics** | Total words, WPM averages, session count, 48-hour activity chart |
| **Settings** | API key, model selection, theme, MCP server management |
| **History** | Searchable log of all transcriptions and agent calls |
| **Chat** | Shelley's web UI — full coding agent interface |

### Configure agent mode

1. Get an API key at [openrouter.ai](https://openrouter.ai)
2. Open Settings tab → paste your OpenRouter API key → Save
3. Optionally select a model (defaults to `openai/gpt-5-nano`)
4. Optionally add MCP servers for extended tool access

### MCP servers

When MCP servers are configured, agent mode can use their tools (databases, APIs, file systems). Supports stdio, HTTP, and SSE transports. Add servers in the Settings tab.

## Reference

### Status bar colors

| Color | Meaning |
|---|---|
| Green | Recording (typing mode) |
| Purple | Recording (agent mode) |
| Amber | Transcribing |
| Orange + sweep | Shelley working (click to open Chat) |

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `OPENROUTER_API_KEY` | — | Fallback API key (settings UI takes priority) |
| `OPENROUTER_MODEL` | `openai/gpt-5-nano` | Fallback model |
| `ANTHROPIC_API_KEY` | — | Passed to Shelley for direct Anthropic access |
| `T2T_HISTORY_LIMIT` | `1000` | Max history entries before pruning |

### File locations

| File | Path |
|---|---|
| Logs | `~/Library/Logs/t2t.log` |
| Whisper model | `~/.cache/whisper/ggml-base.en.bin` (~150MB, auto-downloaded) |
| History | `history.json` (Tauri store) |
| Shelley DB | App data dir / `shelley.db` |
| MCP config | `mcp-servers.json` (Tauri store) |

### Permissions required

- **Accessibility** — Fn key detection, paste targeting
- **Microphone** — Audio capture
- **Screen Recording** — Agent mode screenshots (prompted on first use)

## For developers

### Setup

```bash
cd desktop && bun install

# Fetch Shelley binary
bash scripts/fetch-shelley.sh

# Development
bun dev

# Build
bun build
```

**Requires:** Rust (via rustup), Bun or Node.js 18+

### Tech stack

| Layer | Technology |
|---|---|
| Frontend | Svelte 5 + SvelteKit |
| Desktop | Rust + Tauri 2 |
| Speech-to-text | whisper-rs (local) |
| AI | OpenRouter API |
| Coding agent | Shelley (Go, bundled sidecar) |
| MCP | stdio / HTTP / SSE client |
| Audio | cpal (native) |
| Hotkey | macOS IOKit (Fn key) |

Fully local. Only API calls leave your machine.

## License

MIT
