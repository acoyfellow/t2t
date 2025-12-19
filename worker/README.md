# t2t Agent Worker

Cloudflare Worker that converts voice transcripts to AppleScript using Cloudflare AI.

## Stack

- **Runtime**: Cloudflare Workers
- **Framework**: Hono
- **AI**: Cloudflare Workers AI (Llama 3.1 8B)
- **Effects**: Effect-TS
- **Deploy**: Alchemy

## Setup

```bash
cd worker
bun install
bun wrangler login  # one-time auth
```

## Development

```bash
bun dev
```

## Deploy

```bash
bun deploy
```

## API

### POST /agent

Convert a voice transcript to AppleScript.

**Request:**
```json
{
  "transcript": "open slack"
}
```

**Response (success):**
```json
{
  "success": true,
  "script": "tell application \"Slack\" to activate",
  "blocked": false
}
```

**Response (blocked by denylist):**
```json
{
  "success": false,
  "error": "Script blocked by safety filter",
  "blocked": true,
  "script": "..."
}
```

## Safety

Scripts are checked against a denylist before being returned. Blocked patterns include:
- Destructive shell commands (rm -rf, sudo, etc.)
- Mass file deletion
- Credential/keychain access
- Network exfiltration patterns
- Privilege escalation
