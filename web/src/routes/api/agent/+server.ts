import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { generateAppleScript } from '$lib/agent';
import { checkDenylist, DenylistViolation } from '$lib/denylist';
import { Effect } from 'effect';
import { getRequestEvent } from '$app/server';

export const POST: RequestHandler = async ({ request, platform }) => {
  try {
    const { transcript } = await request.json<{ transcript: string }>();

    if (!transcript || typeof transcript !== "string") {
      return json({ error: "Missing transcript" }, { status: 400 });
    }

    // Access AI binding from platform.env
    const ai = platform?.env?.AI;
    if (!ai) {
      return json({ error: "AI service not available" }, { status: 503 });
    }

    const program = generateAppleScript(ai, transcript).pipe(
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
    return json(result);
  } catch (error) {
    console.error('Agent API error:', error);
    return json(
      { error: "Internal server error", success: false, blocked: false },
      { status: 500 }
    );
  }
};

