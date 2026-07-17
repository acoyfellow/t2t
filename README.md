# t2t

![t2t logo](web/static/logo.svg)

**Push-to-talk dictation for macOS. Hold `Fn` to type. Hold `Fn` + `Ctrl` to talk to a local Pi agent.**

`t2t` is a small menu-bar app that turns a keyboard hold into a complete voice workflow. Dictation runs through Whisper on your Mac. Agent mode hands the transcript to the `pi` CLI you already use, with your configured model and MCP tools.

## Features at a glance

| Feature | What happens | Available by default |
| --- | --- | --- |
| Local dictation | Hold `Fn`, speak, and release. Whisper transcribes the recording locally. | Yes |
| Paste into the focused field | The transcription is inserted into the text field that was focused when the turn started. | Yes |
| Agent mode | Hold `Fn` + `Ctrl` to send the transcript to the local `pi` CLI. | Requires `pi` on `PATH` |
| Spoken agent replies | T2T can read the agent response aloud with macOS text-to-speech. | Configurable in Settings |
| MCP tools | Add, edit, remove, enable, disable, and inspect MCP servers from Settings. Agent turns can use the enabled servers. | Configurable in Settings |
| MCP directory | Browse example MCP servers for files, databases, GitHub, browsers, and documentation. | Included on [t2t.now](https://t2t.now) |
| Local history | Keep transcription and agent-turn history on the Mac for later inspection. | Yes |
| Live agent history | Settings → History shows agent activity and streamed response text while a turn is running. | Yes |
| Two-mode indicator | Transparent, click-through indicator bars show recording, processing, and speaking state. | Yes |
| Multiple displays | Indicator surfaces are placed on connected displays and stale display surfaces are removed after disconnects. | Yes |
| Cancellation | Press `Escape` to cancel an active processing turn. | Yes |
| Screen context | Agent turns can include a temporary screenshot as visual context; the temporary file is deleted after the turn. | Configurable by the agent flow |
| Privacy controls | Audio transcription is local. Credentials stay in your local Pi configuration; T2T does not store them in the repository. | Yes |

## Download

**[Download for macOS](https://t2t.now)**

[View releases on GitHub](https://github.com/acoyfellow/t2t/releases)

T2T is currently ad-hoc signed for local development. A rebuilt app can receive a new macOS identity, so macOS may ask you to approve Accessibility, Microphone, and Input Monitoring again.

## Requirements

- macOS
- Accessibility permission, for the global `Fn` shortcut and focused-field insertion
- Microphone permission, for recording
- [`pi`](https://github.com/badlogic/pi-mono) or a compatible `pi` CLI on `PATH` for agent mode
- A Pi provider and model configured locally

## First run

1. Download or build the app.
2. Open T2T and grant Accessibility and Microphone access when macOS asks.
3. Hold `Fn` in any editable field and speak.
4. For agent mode, install `pi`, configure a provider and model, then hold `Fn` + `Ctrl`.
5. Open Settings to configure voice output, Pi options, MCP servers, and history.

The first local transcription run uses the Whisper model at `~/.cache/whisper/ggml-base.en.bin`. T2T downloads or initializes that model through its local Whisper path.

## Pi and model configuration

T2T delegates agent turns to the locally installed `pi` CLI. It does not embed a hosted chat client or copy Pi credentials into the app. The current public defaults are:

- Provider: `cloudflare-ai-gateway`
- Model: `gpt-5.6-luna`
- Thinking: `medium`
- Session mode: `--no-session`

Override these values in Settings or with environment variables:

```bash
export T2T_PI_BINARY=pi
export T2T_PI_PROVIDER=cloudflare-ai-gateway
export T2T_PI_MODEL=gpt-5.6-luna
export T2T_PI_THINKING=medium
```

The provider, model, thinking level, and optional CA bundle can also be stored in T2T's local Pi-agent settings.

## MCP servers

MCP is optional. In Settings, you can manage the servers that the Pi agent is allowed to discover and use for a turn. T2T preserves unrelated MCP configuration fields when it updates the server list and treats a server as available only when its runtime configuration explicitly enables it.

Examples include:

- Filesystem access
- Git and GitHub
- PostgreSQL and other databases
- Browser and developer-tools automation
- Documentation and search services

MCP tools are not blanket authorization. A server can expose a capability, but the current voice request still needs to authorize an external or state-changing action.

## Local data and history

- Transcriptions and agent-turn summaries are stored locally.
- Pi credentials remain in Pi's local configuration.
- Logs: `~/Library/Logs/t2t.log`
- Whisper model: `~/.cache/whisper/ggml-base.en.bin`
- Temporary screenshots used for an agent turn are deleted after use.

## Developer setup

### Validate the desktop app

```bash
cd /Users/jcoeyman/cloudflare/t2t/desktop
bun install
bun run check
cargo test
```

### Run desktop development mode

```bash
cd /Users/jcoeyman/cloudflare/t2t/desktop
bunx tauri dev
```

Development builds have a different macOS identity from `/Applications/t2t.app`, so permissions granted to one copy may not apply to the other. Run only one T2T instance at a time.

### Build and install the canonical app

```bash
cd /Users/jcoeyman/cloudflare/t2t/desktop
bun run macos:install
open -a /Applications/t2t.app
```

Do not launch the copy inside `desktop/target` for normal use. The install script builds the release app and replaces `/Applications/t2t.app`.

### Repair macOS permissions after a rebuild

```bash
# Stop only T2T, if it is running.
pkill -f '/Applications/t2t.app/Contents/MacOS/t2t' 2>/dev/null || true

# Reset only T2T's grants. macOS will ask for approval again.
tccutil reset Accessibility com.t2t.desktop
tccutil reset Microphone com.t2t.desktop
tccutil reset ListenEvent com.t2t.desktop

open 'x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility'
open 'x-apple.systempreferences:com.apple.preference.security?Privacy_Microphone'
open 'x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent'
open -a /Applications/t2t.app
```

### Verify the installed app

```bash
ps -axo pid,args | grep '[t]2t.app/Contents/MacOS/t2t'
ls -ld /Applications/t2t.app
cd /Users/jcoeyman/cloudflare/t2t
git diff --check
```

Build without installing when you only need an artifact:

```bash
cd /Users/jcoeyman/cloudflare/t2t/desktop
bun run build
```

## Website development and deployment

The public site lives in `web/` and is deployed to [t2t.now](https://t2t.now) with Alchemy and Cloudflare.

```bash
cd /Users/jcoeyman/cloudflare/t2t/web
bun install
bun run check
bun run build
bun run deploy
```

`bun run deploy` uses the configured Cloudflare credentials and Alchemy state. It may ask for the deployment password or other environment variables when they are not present locally.

## Tech stack

- Tauri 2 and Rust
- Svelte 5 and SvelteKit
- `whisper-rs` for local transcription
- Local `pi` CLI bridge for agent mode
- MCP server management and discovery
- Cloudflare Workers, D1, Durable Objects, and Workers AI for the website
- macOS `say` for spoken agent replies

## License

MIT
