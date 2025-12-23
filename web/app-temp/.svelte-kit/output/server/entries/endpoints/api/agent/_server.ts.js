import { json } from "@sveltejs/kit";
import { Effect, Data } from "effect";
import "@sveltejs/kit/internal/server";
import "../../../../chunks/utils.js";
import "@sveltejs/kit/internal";
import "../../../../chunks/query.js";
const SYSTEM_PROMPT = `You are an AppleScript generator for macOS automation.

Given a voice command from a user, generate a valid AppleScript that accomplishes their request.

Rules:
1. Output ONLY the AppleScript code, nothing else
2. No markdown, no explanation, no backticks
3. Use "tell application" blocks for app control
4. Use "System Events" for keyboard/mouse simulation
5. Keep scripts simple and focused on the single task
6. If the request is unclear, generate a script that does nothing harmful

Common patterns:
- Open app: tell application "AppName" to activate
- Open URL: open location "https://..."
- Type text: tell application "System Events" to keystroke "text"
- Notification: display notification "message" with title "title"
- Click menu: tell application "System Events" to click menu item "X" of menu "Y" of menu bar 1 of process "App"

Examples:
User: "open slack"
Output: tell application "Slack" to activate

User: "open google"
Output: open location "https://google.com"

User: "send a notification saying hello"
Output: display notification "hello" with title "t2t"`;
const generateAppleScript = (ai, transcript) => Effect.tryPromise({
  try: async () => {
    const response = await ai.run("@cf/meta/llama-3.1-8b-instruct", {
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: transcript }
      ],
      max_tokens: 500
    });
    const result = response;
    const script = result.response?.trim() ?? "";
    return script.replace(/^```applescript\n?/i, "").replace(/^```\n?/, "").replace(/\n?```$/, "").trim();
  },
  catch: (error) => new Error(`AI generation failed: ${error}`)
});
const DENY_PATTERNS = [
  // Destructive shell commands
  /do shell script.*rm\s+(-rf?|--recursive)/i,
  /do shell script.*sudo/i,
  /do shell script.*mkfs/i,
  /do shell script.*dd\s+if=/i,
  /do shell script.*:\(\)\{.*\}.*:/i,
  // fork bomb
  /do shell script.*>\s*\/dev\//i,
  // Mass file operations
  /delete\s+(every|all)\s+(file|folder|item)/i,
  /remove\s+(every|all)\s+(file|folder|item)/i,
  // Credential/secret access
  /security\s+find-(generic|internet)-password/i,
  /keychain/i,
  // Network exfiltration patterns
  /do shell script.*curl.*-d.*\$\(/i,
  /do shell script.*wget.*--post/i,
  // Privilege escalation
  /with\s+administrator\s+privileges/i,
  // Dangerous System Events
  /keystroke.*password/i,
  /keystroke.*secret/i,
  /keystroke.*api.?key/i
];
class DenylistViolation extends Data.TaggedError("DenylistViolation") {
}
const checkDenylist = (script) => Effect.sync(() => {
  for (const pattern of DENY_PATTERNS) {
    if (pattern.test(script)) {
      return Effect.fail(
        new DenylistViolation({
          script,
          pattern: pattern.source
        })
      );
    }
  }
  return Effect.succeed(script);
}).pipe(Effect.flatten);
const POST = async ({ request, platform }) => {
  try {
    const { transcript } = await request.json();
    if (!transcript || typeof transcript !== "string") {
      return json({ error: "Missing transcript" }, { status: 400 });
    }
    const ai = platform?.env?.AI;
    if (!ai) {
      return json({ error: "AI service not available" }, { status: 503 });
    }
    const program = generateAppleScript(ai, transcript).pipe(
      Effect.flatMap(
        (script) => checkDenylist(script).pipe(
          Effect.mapError(() => new DenylistViolation({ script })),
          Effect.as(script)
        )
      ),
      Effect.match({
        onSuccess: (script) => ({
          success: true,
          script,
          blocked: false
        }),
        onFailure: (error) => {
          if (error instanceof DenylistViolation) {
            return {
              success: false,
              error: "Script blocked by safety filter",
              blocked: true,
              script: error.script
            };
          }
          return {
            success: false,
            error: error.message,
            blocked: false
          };
        }
      })
    );
    const result = await Effect.runPromise(program);
    return json(result);
  } catch (error) {
    console.error("Agent API error:", error);
    return json(
      { error: "Internal server error", success: false, blocked: false },
      { status: 500 }
    );
  }
};
export {
  POST
};
