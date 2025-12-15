<script lang="ts">
  import { onMount } from "svelte";
  import { Effect, Runtime } from "effect";
  import { runtime } from "../lib/effect/runtime";
  import { installUiBridge, interruptFiber } from "../lib/effect/uiBridge";

  let recording = $state(false);
  let processing = $state(false);
  let level = $state(0);

  const clamp01 = (v: number) => Math.max(0, Math.min(1, v));

  onMount(() => {
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
  class="indicator"
  class:recording
  class:processing
  style={(() => {
    const l = clamp01(level);
    const h = 6 + l * 30; // px (more)
    const glow = 18 + l * 90; // px (more)
    const a = 0.35 + l * 0.45; // 0..1
    return `--h:${h}px;--glow:${glow}px;--alpha:${a};`;
  })()}
>
  <div class="border"></div>
</div>

<style>
  :global(html, body) {
    margin: 0;
    padding: 0;
    background: transparent;
    overflow: hidden;
    pointer-events: none;
  }

  :global(*) {
    pointer-events: none;
  }

  .indicator {
    position: fixed;
    bottom: 0;
    left: 0;
    width: 100vw;
    height: 3px;
    opacity: 0;
    transition:
      opacity 0.3s ease,
      height 0.15s ease;
    pointer-events: none;
    --h: 6px;
    --glow: 16px;
    --alpha: 0.55;
  }

  .border {
    position: absolute;
    bottom: 0;
    left: 0;
    width: 100%;
    height: 3px;
    background: transparent;
    transition:
      background 0.3s ease,
      box-shadow 0.15s ease,
      height 0.15s ease;
  }

  /* Recording state */
  .indicator.recording {
    opacity: 1;
    height: var(--h);
  }

  .indicator.recording .border {
    background: #ef4444;
    height: 100%;
    box-shadow: 0 0 var(--glow) rgba(239, 68, 68, var(--alpha));
  }

  /* Processing state */
  .indicator.processing {
    height: 6px;
    opacity: 1;
  }

  .indicator.processing .border {
    background: #f59e0b;
    box-shadow: 0 0 15px rgba(245, 158, 11, 0.8);
  }
</style>
