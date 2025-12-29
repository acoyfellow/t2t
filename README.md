# t2t

![t2t logo](web/static/logo.svg)

**Voice-to-text with intelligence. Hold fn to talk, hold fn+ctrl to command.**

## Download

**[Download for macOS →](https://t2t.now)**

[View all releases on GitHub →](https://github.com/acoyfellow/t2t/releases)

> **Note:** The app is not code-signed yet. On first launch, macOS may show a security warning. To open it:
> - Right-click the app → **Open**, then click **Open** in the dialog
> - Or run: `xattr -cr /Applications/t2t.app` in Terminal
>
> **Heads up:** This is an unsigned build while we polish things up. Each time you update to a new version, you'll need to remove t2t from System Settings → Privacy & Security → Accessibility (and Microphone if needed), then re-add it. We'll get it properly signed soon!

## How It Works

- **Hold Fn key** → records microphone audio
- **Release Fn key** → transcribes using local Whisper model
- **Typing mode** (red bar): Hold Fn alone → pastes transcription into focused text field, preserves clipboard
- **Agent mode** (cyan bar): Hold Fn+Ctrl → speaks commands to AI agent
  - **MCP mode** (if configured): Connects to MCP servers, uses their tools via OpenRouter AI
  - **AppleScript mode** (fallback): Generates and executes AppleScript for macOS automation
- Visual feedback: red/cyan bar while recording (based on mode), amber while processing

## Requirements

- **macOS** (currently macOS only; tested on Apple Silicon)
- **Accessibility permission** - Required for Fn key detection and focusing the correct field before paste
- **Microphone permission** - Required for audio recording
- **OpenRouter API key** (for agent mode) - Get one at [openrouter.ai](https://openrouter.ai)

The app will prompt you if permissions are missing.

## Getting Started

1. **Download and install** the app from [t2t.now](https://t2t.now)
2. **Grant permissions** when prompted (Accessibility and Microphone)
3. **Get an OpenRouter API key** at [openrouter.ai](https://openrouter.ai) (required for agent mode)
4. **Open settings**: Click the menu bar icon → **View Settings**
5. **Configure agent mode** (optional):
   - Add your OpenRouter API key in settings
   - Optionally configure MCP servers for extended automation

## Settings & Analytics

The settings window (Menu bar icon → **View Settings**) includes three tabs:

### Analytics Tab

View your transcription usage statistics:
- **Total Words**: Lifetime count of all transcribed words
- **Lifetime Average**: Average words per minute across all sessions
- **Session Average**: Average words per minute for current session
- **Sessions**: Total number of transcription sessions
- **Hours Active**: Total time spent transcribing
- **Recent Activity**: 48-hour hourly activity chart

### Settings Tab

Configure your t2t installation:
- **Theme**: Toggle between light and dark mode
- **OpenRouter API Key**: Set your API key for agent mode
- **AI Model Selection**: Choose which model to use for agent mode
  - Supports all OpenRouter models
  - Image generation models show a 🖼️ badge
  - Auto-refresh available to fetch latest models
- **MCP Servers**: Add, configure, and manage MCP servers
  - Test connections and view available tools
  - Enable/disable servers individually
  - Supports stdio, HTTP, and SSE transports

### History Tab

See [History & Logging](#history--logging) section below.

## MCP (Model Context Protocol) Support

When MCP servers are configured in settings, agent mode uses MCP instead of AppleScript. This enables:

- **Extensible automation**: Connect to any MCP-compatible service (databases, APIs, file systems, etc.)
- **Tool-based execution**: AI agent uses tools provided by your MCP servers
- **Multiple servers**: Connect to multiple MCP servers simultaneously
- **Transport options**: Supports stdio, HTTP, and SSE transports

**To configure**: Menu bar icon → **View Settings** → Settings tab → MCP Servers section. Requires an OpenRouter API key.

## Image Generation Models & Automatic Screenshots

When you select an **image generation model** (e.g., DALL-E, Stable Diffusion, Flux, Midjourney, Ideogram), t2t automatically captures and includes a screenshot with every agent input. This enables the "agent can see" feature - the AI can see your screen context when generating images.

### How It Works

- **Automatic detection**: Models are automatically detected as image generation capable based on their ID patterns
- **Screenshot capture**: When you use agent mode (Fn+Ctrl) with an image generation model, a screenshot is captured before sending your prompt
- **Seamless integration**: Screenshots are included in the API request without any additional UI or user action
- **Privacy**: Screenshots are only captured when using image generation models, and only sent to the API (not stored locally)

### Supported Model Patterns

The following model ID patterns trigger automatic screenshot capture:
- `dall-e`, `dalle` (OpenAI DALL-E)
- `stable-diffusion`, `stablediffusion` (Stability AI)
- `flux` (Black Forest Labs)
- `midjourney`
- `ideogram`
- `imagen` (Google)
- `sdxl`, `realistic-vision`, `dreamshaper` (Stable Diffusion variants)
- Models from `black-forest-labs` or `stability-ai` providers

### UI Indicators

In Settings → Model Selection:
- Image generation models show a 🖼️ badge
- A purple info box appears when an image generation model is selected, explaining the automatic screenshot behavior

### Privacy & Permissions

- **Screen Recording permission**: macOS may prompt for screen recording permission the first time you use an image generation model
- **No local storage**: Screenshots are not saved to disk - they're only sent to the API
- **Error handling**: If screenshot capture fails (e.g., permission denied), the agent falls back to text-only mode

### Technical Details

- Screenshots are captured using macOS `screencapture` command
- Images are encoded as base64 PNG and included in the OpenAI-compatible message format
- The screenshot is included in both initial requests and follow-up requests after tool execution

## History & Logging

t2t automatically logs all transcriptions and agent calls for review and debugging.

### Features

- **Transcription history**: All voice transcriptions are saved with timestamps
- **Agent call logging**: Complete request/response logs for all OpenRouter API calls
- **Screenshot thumbnails**: Tiny thumbnails (150x150px) of screenshots sent with agent calls
- **Search**: Fast local search across all history entries
- **Expandable details**: Click any entry to view full request/response JSON and tool calls

### Accessing History

Menu bar icon → **View Settings** → **History** tab

### Configuration

- **History limit**: Set `T2T_HISTORY_LIMIT` environment variable (default: 1000 entries)
- **Storage**: History is stored locally in `history.json` via Tauri's store plugin
- **Privacy**: All data stays on your machine - nothing is sent to external services

### What's Logged

**Transcriptions:**
- Timestamp
- Transcribed text

**Agent Calls:**
- Timestamp
- Transcript (your voice input)
- Model used
- Full request JSON (messages, parameters)
- Full response JSON (AI output, tool calls)
- Tool calls executed (if any)
- Screenshot thumbnail (if screenshot was included)
- Success/error status

## First Run

On first launch, the app automatically downloads the Whisper model (~150MB) to `~/.cache/whisper/ggml-base.en.bin`. This happens in the background.

## For Developers

### Setup

```bash
# Install dependencies (in desktop/)
cd desktop && bun install

# Development
bun dev              # From root, or:
cd desktop && bun tauri dev

# Build
bun build            # From root, or:
cd desktop && bun tauri build
```

### Requirements

- **Rust** (install via rustup)
- **Bun** (recommended) or Node.js 18+

### Tech Stack

- **Frontend**: Svelte 5 + SvelteKit
- **Backend**: Rust + Tauri
- **STT**: whisper-rs (local Whisper.cpp model)
- **AI**: OpenRouter API (direct calls, no infrastructure needed)
- **MCP**: Model Context Protocol client (local stdio/HTTP/SSE)
- **Hotkey**: macOS event monitoring (Fn key) + fallbacks
- **Audio capture**: native (Rust via cpal)

**Architecture**: Fully local. Only OpenRouter API calls go out. No servers, workers, or infrastructure required.

### Debugging

- **Logs**: `~/Library/Logs/t2t.log`
- **Model location**: `~/.cache/whisper/ggml-base.en.bin`
- **History storage**: `history.json` (via Tauri store, location depends on Tauri config)

## License

MIT
