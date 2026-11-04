# t2t

![t2t logo](web/static/logo.svg)

**Hold `fn` to dictate. Hold `fn` + `ctrl` to ask an agent that sees your screen, uses your tools, and draws its answers.**

[![An animated diagram the t2t agent made from one spoken request: browser, edge, worker, durable object and storage, lit up step by step.](docs/media/genui-demo.gif)](web/static/demos/durable-object-request.mp4)

> “Show me how a request to a Worker with a Durable Object works, and record it.”
> The agent built this diagram and saved the video in 19 seconds, for $0.20. Unedited.

## What it does

| | |
| --- | --- |
| **Dictate** | Hold `fn` in any text field and speak. Whisper transcribes on your Mac and the text lands at your cursor. A slider sets how long a pause must be before each phrase is pasted. |
| **Ask** | Hold `fn` + `ctrl`. Your words and a screenshot go to an agent (Claude Opus 5.5 in a Cloudflare Durable Object). Replies stream in and are spoken aloud. |
| **Explain with scenes** | Ask how something works. The agent writes a short scene — boxes, wires, steps — and t2t's scene kit turns it into an animated diagram in a window on your Mac. |
| **Any UI** | For charts, tables, forms or 3D, the agent writes HTML into a window. Windows are normal Mac windows and come back after a restart. |
| **Record it** | Say "record it". t2t renders one loop offscreen, frame by frame, to a 30 fps mp4 in `~/Movies/t2t`. Your screen, mouse and focus are never touched. |
| **Point and draw** | The agent draws boxes, arrows and labels over your apps to show you where things are. |
| **Use your tools** | t2t uses the MCP servers in `~/.pi/agent/mcp.json`. Tools run on your Mac. Optional Allow / Deny before each call. |
| **Use your apps** | With the [hand](https://github.com/acoyfellow/hand) MCP server, the agent reads and changes Mac apps through Accessibility, without stealing focus. |
| **Mute while talking** | Your Mac's sound mutes while you hold the key, and comes back when you let go. |

## How it works

[![How t2t works: fn dictation on the Mac, fn+ctrl to the agent on Cloudflare, MCP tools on the Mac, and spoken answers.](docs/media/how-t2t-works.gif)](web/static/demos/how-t2t-works.mp4)

| On your Mac | On Cloudflare |
| --- | --- |
| Swift shell: hotkeys, microphone, paste, overlay, windows, recorder | The agent (pi-durable in a Durable Object) and its conversation |
| Whisper (`whisper-cli`) for dictation | Model calls |
| MCP host for your tools, including hand | Screenshots you send with a question |

Dictation never leaves your Mac. Agent questions do.

## Install

There is no signed download for v2 yet. Build it on a Mac with Apple silicon.

Requirements: macOS 15+, Swift 6, Node 22, `brew install whisper-cpp`, the model at `~/.cache/whisper/ggml-base.en.bin`, and a Cloudflare account.

```sh
git clone https://github.com/acoyfellow/t2t
cd t2t && git checkout v2 && cd v2
npm install
npm run deploy          # the agent Worker
npm run ui &            # overlay and settings UI on :5197
./scripts/build-shell.sh
open dist/T2T.app
```

`build-shell.sh` signs the app with a local certificate in `.secrets/`, so macOS keeps your permissions across rebuilds. Grant Input Monitoring, Accessibility, Screen Recording and Microphone; Settings → General shows which are missing.

## Scene kit

`v2/kit/scene.js` is one small runtime. A scene is JSON:

```json
{
  "title": "a request to a worker with a durable object",
  "regions": [{ "label": "cloudflare", "x": 220, "y": 10, "w": 700, "h": 330 }],
  "boxes": [{ "id": "worker", "kicker": "fetch handler", "label": "worker", "x": 480, "y": 60, "w": 180, "h": 76 }],
  "wires": [{ "from": "edge", "to": "worker", "label": "route" }],
  "steps": [{ "label": "worker runs", "caption": "the edge runs your worker.", "lit": ["edge", "worker"], "flow": ["edge>worker"] }]
}
```

Render one yourself: `node v2/kit/build.mjs v2/kit/scenes/t2t.json out.html`.

## t2t v1

v1 (the Tauri app, v0.3.x) is deprecated. To remove it:

```sh
launchctl bootout gui/$(id -u)/com.t2t.desktop
rm ~/Library/LaunchAgents/com.t2t.desktop.plist
rm -rf /Applications/t2t.app
```

## License

MIT
