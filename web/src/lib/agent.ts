import { Effect } from "effect";

// Minimal type for Cloudflare AI binding
export type CloudflareAI = {
  run(
    model: string,
    options: {
      messages: Array<{ role: string; content: string }>;
      max_tokens?: number;
    }
  ): Promise<{ response?: string }>;
};

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

export const generateAppleScript = (ai: CloudflareAI, transcript: string) =>
  Effect.tryPromise({
    try: async () => {
      const response = await ai.run("@cf/meta/llama-3.1-8b-instruct", {
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: transcript },
        ],
        max_tokens: 500,
      });

      // Handle the response - Cloudflare AI returns { response: string } for text models
      const result = response as { response?: string };
      const script = result.response?.trim() ?? "";

      // Strip any markdown code blocks if the model added them
      return script
        .replace(/^```applescript\n?/i, "")
        .replace(/^```\n?/, "")
        .replace(/\n?```$/, "")
        .trim();
    },
    catch: (error) => new Error(`AI generation failed: ${error}`),
  });

