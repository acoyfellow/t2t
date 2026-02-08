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

  // Persists after processing ends - Shelley is working in the background.
  // Cleared when the user clicks the bar to open Chat.
  let shelleyActive = $state(false);

  const clamp01 = (v: number) => Math.max(0, Math.min(1, v));

  // Visible when recording, processing, OR Shelley is active in background
  const barVisible = $derived(recording || processing || shelleyActive);

  // Clickable when Shelley is active (processing or background)
  const isClickable = $derived(shelleyActive || (processing && mode === "agent"));

  const indicatorClass = $derived.by(() => {
    const state = recording
      ? "opacity-100 h-[var(--h)]"
      : processing || shelleyActive
        ? "opacity-100 h-[6px]"
        : "opacity-0 h-[3px]";

    return [
      "fixed bottom-0 left-0 w-screen z-[9999]",
      isClickable ? "cursor-pointer" : "pointer-events-none",
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

    const shelleyColor =
      "bg-[#f97316]/80 shadow-[0_0_15px_rgba(249,115,22,0.8)]";

    const state = recording
      ? color
      : shelleyActive
        ? shelleyColor
        : processing
          ? "bg-amber-500/80 shadow-[0_0_15px_rgba(245,158,11,0.8)]"
          : "bg-transparent";

    return [
      "absolute bottom-0 left-0 w-full h-full",
      "transition-[background-color,box-shadow,height] duration-300 ease-out",
      state,
    ].join(" ");
  });

  function openChat() {
    if (!isClickable) return;
    // Dismiss the indicator — user is going to look at Shelley's output
    shelleyActive = false;
    invoke("open_chat_window").catch((err) => {
      console.error("Failed to open chat:", err);
    });
  }

  onMount(() => {
    mode = "typing";

    (window as any).__setMode = (m: "typing" | "agent") => {
      mode = m;
    };
    (window as any).__agentInput = (text: string) => {
      console.log("Agent mode:", text);
    };

    // Rust calls this when a voice command is dispatched to Shelley
    (window as any).__setShelleyActive = (v: boolean) => {
      shelleyActive = v;
      console.log("[UI] setShelleyActive", v);
    };

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

    $effect(() => {
      if (!processing && !shelleyActive) {
        return;
      }

      const escapeHandler = (e: KeyboardEvent) => {
        if (e.key === "Escape") {
          e.preventDefault();
          e.stopPropagation();
          if (shelleyActive) {
            shelleyActive = false;
            console.log("[UI] Escape dismissed Shelley indicator");
          }
          console.log("[UI] Escape pressed during processing - cancelling");
          invoke("cancel_processing").catch((err) => {
            console.error("Failed to cancel processing:", err);
          });
        }
      };

      window.addEventListener("keydown", escapeHandler, true);
      return () => {
        window.removeEventListener("keydown", escapeHandler, true);
      };
    });

    (window as any).__setLevel = (v: number) => {
      level = v;
    };

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
      delete (window as any).__setShelleyActive;
    };
  });
</script>

<!-- svelte-ignore a11y_click_events_have_key_events -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  class={indicatorClass}
  onclick={openChat}
  style={(() => {
    const l = clamp01(level);
    const h = 6 + l * 30;
    const glow = 18 + l * 90;
    const a = 0.35 + l * 0.45;
    return `--h:${h}px;--glow:${glow}px;--alpha:${a};`;
  })()}
>
  <div class={borderClass}></div>

  <!-- Sweeping light — visible while Shelley is active -->
  {#if shelleyActive && !recording}
    <div class="absolute bottom-0 left-0 w-full h-[6px] overflow-hidden">
      <div class="shelley-pulse"></div>
    </div>
  {/if}
</div>

<style>
  .shelley-pulse {
    position: absolute;
    bottom: 0;
    width: 80px;
    height: 100%;
    border-radius: 2px;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.9), transparent);
    animation: shelley-sweep 2s ease-in-out infinite;
    box-shadow: 0 0 12px rgba(249, 115, 22, 0.6);
  }

  @keyframes shelley-sweep {
    0% {
      left: -80px;
    }
    100% {
      left: 100%;
    }
  }
</style>
