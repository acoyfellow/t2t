<script lang="ts">
  import { onMount } from "svelte";
  import { Effect, Runtime } from "effect";
  import { runtime } from "../lib/effect/runtime";
  import { installUiBridge, interruptFiber } from "../lib/effect/uiBridge";
  import { invoke } from "@tauri-apps/api/core";

  let recording = $state(false);
  let processing = $state(false);
  let level = $state(0);
  let mode = $state<"typing" | "agent">("typing");

  const clamp01 = (v: number) => Math.max(0, Math.min(1, v));

  const indicatorClass = $derived.by(() => {
    const state = recording
      ? "opacity-100 h-[var(--h)]"
      : processing
        ? "opacity-100 h-[6px]"
        : "opacity-0 h-[3px]";

    return [
      "fixed bottom-0 left-0 w-screen pointer-events-none z-[9999]",
      "transition-[opacity,height] duration-300 ease-out",
      "[--h:6px] [--glow:16px] [--alpha:0.55]",
      state,
    ].join(" ");
  });

  const borderClass = $derived.by(() => {
    const color =
      mode === "agent"
        ? "bg-[#c27aff]/80 shadow-[0_0_var(--glow)_rgba(194,122,255,var(--alpha))]"
        : "bg-[#00ffa3]/80 shadow-[0_0_var(--glow)_rgba(0,255,163,var(--alpha))]";

    const state = recording
      ? color
      : processing
        ? "bg-amber-500/80 shadow-[0_0_15px_rgba(245,158,11,0.8)]"
        : "bg-transparent";

    return [
      "absolute bottom-0 left-0 w-full h-full",
      "transition-[background-color,box-shadow,height] duration-300 ease-out",
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
