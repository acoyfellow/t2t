<script lang="ts">
  import { onMount } from "svelte";
  import { Effect, Runtime } from "effect";
  import { runtime } from "../lib/effect/runtime";
  import { installUiBridge, interruptFiber } from "../lib/effect/uiBridge";

  let recording = $state(false);
  let processing = $state(false);

  onMount(() => {
    const fiber = Runtime.runFork(
      runtime,
      Effect.scoped(
        installUiBridge({
          setRecording: (v) => (recording = v),
          setProcessing: (v) => (processing = v),
        })
      )
    );

    return () => interruptFiber(fiber);
  });
</script>

<div class="indicator" class:recording class:processing>
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
      height 0.3s ease;
    pointer-events: none;
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
      box-shadow 0.3s ease;
  }

  /* Recording state */
  .indicator.recording {
    height: 6px;
    opacity: 1;
  }

  .indicator.recording .border {
    background: #ef4444;
    box-shadow: 0 0 20px rgba(239, 68, 68, 0.8);
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
