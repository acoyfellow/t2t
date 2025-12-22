<script lang="ts">
  import { onMount } from "svelte";
  import { Effect, Runtime } from "effect";
  import { runtime } from "../lib/effect/runtime";
  import { installUiBridge, interruptFiber } from "../lib/effect/uiBridge";

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
      "fixed bottom-0 left-0 w-screen pointer-events-none",
      "transition-[opacity,height] duration-300 ease-out",
      "[--h:6px] [--glow:16px] [--alpha:0.55]",
      state,
    ].join(" ");
  });

  const borderClass = $derived.by(() => {
    const color =
      mode === "agent"
        ? "bg-cyan-500/80 shadow-[0_0_var(--glow)_rgba(6,182,212,var(--alpha))]"
        : "bg-red-500/80 shadow-[0_0_var(--glow)_rgba(239,68,68,var(--alpha))]";

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
    // Expose hooks to Rust
    (window as any).__setMode = (m: "typing" | "agent") => {
      mode = m;
    };
    (window as any).__agentInput = (text: string) => {
      console.log("Agent mode:", text);
      // Future: show UI, trigger agent workflow
    };

    // Initialize mode to typing (red bar)
    mode = "typing";

    const fiber = Runtime.runFork(
      runtime,
      Effect.scoped(
        installUiBridge({
          setRecording: (v) => (recording = v),
          setProcessing: (v) => (processing = v),
          setLevel: (v) => (level = v),
        })
      )
    );

    return () => interruptFiber(fiber);
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
