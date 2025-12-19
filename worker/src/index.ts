import { Hono } from "hono";
import { cors } from "hono/cors";
import { Effect } from "effect";
import { generateAppleScript, type CloudflareAI } from "./agent";
import { checkDenylist, DenylistViolation } from "./denylist";

type Bindings = {
  AI: CloudflareAI;
};

const app = new Hono<{ Bindings: Bindings }>();

app.use("*", cors());

// Health check
app.get("/", (c) => c.json({ status: "ok", service: "t2t-agent" }));

// Main agent endpoint - accepts voice transcript, returns AppleScript
app.post("/agent", async (c) => {
  const { transcript } = await c.req.json<{ transcript: string }>();


  if (!transcript || typeof transcript !== "string") {
    return c.json({ error: "Missing transcript" }, 400);
  }

  const program = generateAppleScript(c.env.AI, transcript).pipe(
    Effect.flatMap((script) =>
      checkDenylist(script).pipe(
        Effect.mapError(() => new DenylistViolation({ script })),
        Effect.as(script)
      )
    ),
    Effect.match({
      onSuccess: (script) => ({
        success: true as const,
        script,
        blocked: false,
      }),
      onFailure: (error: Error | DenylistViolation) => {
        if (error instanceof DenylistViolation) {
          return {
            success: false as const,
            error: "Script blocked by safety filter",
            blocked: true,
            script: error.script,
          };
        }
        return {
          success: false as const,
          error: error.message,
          blocked: false,
        };
      },
    })
  );

  const result = await Effect.runPromise(program);
  return c.json(result);
});

export default app;
