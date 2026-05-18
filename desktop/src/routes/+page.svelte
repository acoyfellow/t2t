<script lang="ts">
  import { onMount } from "svelte";
  import { Effect, Runtime } from "effect";
  import { runtime } from "../lib/effect/runtime";
  import { installUiBridge, interruptFiber } from "../lib/effect/uiBridge";
  import { invoke } from "@tauri-apps/api/core";

  let recording = $state(false);
  let processing = $state(false);
  let speaking = $state(false);
  let level = $state(0);
  let mode = $state<"typing" | "agent">("typing");

  const clamp01 = (v: number) => Math.max(0, Math.min(1, v));

  // Bar is visible during recording, processing (thinking), or speaking.
  const indicatorClass = $derived.by(() => {
    const visible = recording || processing || speaking;
    const state = recording
      ? "opacity-100 h-[var(--h)]"
      : visible
        ? "opacity-100 h-[6px]"
        : "opacity-0 h-[3px]";

    return [
      "fixed bottom-0 left-0 w-screen pointer-events-none z-[9999]",
      "transition-[opacity,height] duration-300 ease-out",
      "[--h:6px] [--glow:16px] [--alpha:0.55]",
      "border-0 outline-none",
      state,
    ].join(" ");
  });

  // Colors:
  //   recording + typing  -> bright green
  //   recording + agent   -> bright purple (#c27aff)
  //   processing + typing -> amber (typing mode is paste-only; no audible output)
  //   processing + agent  -> thinking: bright purple pulsing
  //   speaking            -> deep purple (#a855f7) steady
  const borderClass = $derived.by(() => {
    const recordColor =
      mode === "agent"
        ? "bg-[#c27aff]/80"
        : "bg-[#00ffa3]/80";

    let state: string;
    if (recording) {
      state = recordColor;
    } else if (speaking) {
      state = "bg-[#a855f7]/90";
    } else if (processing && mode === "agent") {
      state = "bg-[#c27aff]/80 animate-pulse";
    } else if (processing) {
      state = "bg-amber-500/80";
    } else {
      state = "bg-transparent";
    }

    return [
      "absolute bottom-0 left-0 w-full h-full",
      "transition-[background-color,height] duration-300 ease-out",
      "border-0 outline-none",
      state,
    ].join(" ");
  });

  onMount(() => {
    // Initialize mode to typing (red bar)
    mode = "typing";

    // Expose hooks to Rust - set up synchronously so they're available immediately
    (window as any).__setMode = (m: "typing" | "agent") => {
      mode = m;
    };
    (window as any).__agentInput = (text: string) => {
      console.log("Agent mode:", text);
      // Future: show UI, trigger agent workflow
    };

    // Set up UI bridge callbacks synchronously first (fallback)
    (window as any).__startRecording = () => {
      recording = true;
      console.log("[UI] startRecording");
    };
    (window as any).__stopRecording = () => {
      recording = false;
      level = 0;
      console.log("[UI] stopRecording");
    };
    (window as any).__setProcessing = (v: boolean) => {
      processing = v;
      console.log("[UI] setProcessing", v);
    };
    (window as any).__setSpeaking = (v: boolean) => {
      speaking = v;
      console.log("[UI] setSpeaking", v);
    };

    // Handle escape key during processing to cancel
    // Use $effect to reactively add/remove escape key listener based on processing state
    $effect(() => {
      if (!processing) {
        return; // No listener needed when not processing
      }

      // Add escape key listener when processing starts
      const escapeHandler = (e: KeyboardEvent) => {
        if (e.key === "Escape") {
          e.preventDefault();
          e.stopPropagation();
          console.log("[UI] Escape pressed during processing - cancelling");
          invoke("cancel_processing").catch((err) => {
            console.error("Failed to cancel processing:", err);
          });
        }
      };

      window.addEventListener("keydown", escapeHandler, true); // Use capture phase
      
      // Cleanup: remove listener when processing stops or component unmounts
      return () => {
        window.removeEventListener("keydown", escapeHandler, true);
      };
    });
    (window as any).__setLevel = (v: number) => {
      level = v;
    };

    // Then install the Effect-based UI bridge (which will replace the above)
    const fiber = Runtime.runFork(
      runtime,
      Effect.scoped(
        installUiBridge({
          setRecording: (v) => {
            recording = v;
            console.log("[UI Bridge] setRecording", v);
          },
          setProcessing: (v) => {
            processing = v;
            console.log("[UI Bridge] setProcessing", v);
          },
          setLevel: (v) => {
            level = v;
          },
        })
      )
    );

    return () => {
      interruptFiber(fiber);
      delete (window as any).__startRecording;
      delete (window as any).__stopRecording;
      delete (window as any).__setProcessing;
      delete (window as any).__setSpeaking;
      delete (window as any).__setLevel;
      delete (window as any).__setMode;
      delete (window as any).__agentInput;
    };
  });
</script>

<div
  class={indicatorClass}
  style={(() => {
    const l = clamp01(level);
    const h = 6 + l * 30; // px (more)
    const glow = 18 + l * 90; // px (more)
    const a = 0.35 + l * 0.45; // 0..1
    return `--h:${h}px;--glow:${glow}px;--alpha:${a};`;
  })()}
>
  <div class={borderClass}></div>
</div>
