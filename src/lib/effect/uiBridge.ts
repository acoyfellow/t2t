import { Effect, Fiber, Runtime } from "effect";
import { logEvent } from "./tauri";
import { runtime } from "./runtime";

export type UiBridge = {
  setRecording: (v: boolean) => void;
  setProcessing: (v: boolean) => void;
  setLevel: (v: number) => void;
};

const runVoid = (eff: Effect.Effect<unknown, unknown, never>) => {
  Runtime.runFork(runtime, Effect.asVoid(eff));
};

export const installUiBridge = ({ setRecording, setProcessing, setLevel }: UiBridge) =>
  Effect.acquireRelease(
    Effect.gen(function* () {
      // Install global callbacks used by Rust (webview eval).
      window.__startRecording = () => {
        setRecording(true);
        runVoid(logEvent("UI: startRecording"));
      };

      window.__stopRecording = () => {
        setRecording(false);
        setLevel(0); // Reset level when recording stops
        runVoid(logEvent("UI: stopRecording"));
      };

      window.__setProcessing = (v: boolean) => setProcessing(v);

      window.__setLevel = (v: number) => setLevel(v);

      yield* logEvent(
        "Frontend initialized (__startRecording/__stopRecording/__setProcessing/__setLevel set).",
      );

      // Keep handlers installed for the lifetime of the scope / fiber.
      yield* Effect.never;
    }),
    () =>
      Effect.sync(() => {
        delete window.__startRecording;
        delete window.__stopRecording;
        delete window.__setProcessing;
        delete window.__setLevel;
      }),
  );

export const interruptFiber = (fiber: Fiber.RuntimeFiber<unknown, unknown>) =>
  Runtime.runFork(runtime, Fiber.interrupt(fiber));


