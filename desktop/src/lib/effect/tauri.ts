import { Effect } from "effect";
import { invoke } from "@tauri-apps/api/core";

export const logEvent = (message: string) =>
  Effect.tryPromise({
    try: () => invoke("log_event", { message }),
    catch: (e) => e as Error,
  });


