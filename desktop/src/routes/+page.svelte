<script lang="ts">
  import { onMount } from "svelte";
  import { Effect, Runtime } from "effect";
  import { runtime } from "../lib/effect/runtime";
  import { installUiBridge, interruptFiber } from "../lib/effect/uiBridge";
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { getCurrentWindow } from "@tauri-apps/api/window";
  import { load } from "@tauri-apps/plugin-store";

  let recording = $state(false);
  let processing = $state(false);
  let speaking = $state(false);
  let level = $state(0);
  let mode = $state<"typing" | "agent">("typing");
  let streamedResponse = $state("");
  let streamVisible = $state(false);
  let panelMinimized = $state(false);
  let captionsEnabled = $state(true);
  const isMainWindow = getCurrentWindow().label === "main";
  let panelX = $state(0);
  let panelY = $state(0);
  let panelWidth = $state(760);
  let panelHeight = $state(320);
  let draggingPanel = $state(false);
  let panelElement = $state<HTMLElement | null>(null);
  let dragOffset = { x: 0, y: 0 };

  function savePanelLayout() {
    if (!isMainWindow) return;
    localStorage.setItem("t2t-response-panel", JSON.stringify({
      x: panelX,
      y: panelY,
      width: panelWidth,
      height: panelHeight,
    }));
  }

  function loadPanelLayout() {
    if (!isMainWindow) return;
    try {
      const saved = JSON.parse(localStorage.getItem("t2t-response-panel") || "null");
      if (saved && typeof saved === "object") {
        panelX = Number(saved.x) || 0;
        panelY = Number(saved.y) || 0;
        panelWidth = Math.max(360, Number(saved.width) || 760);
        panelHeight = Math.max(180, Number(saved.height) || 320);
      } else {
        panelX = Math.max(16, window.innerWidth - panelWidth - 24);
        panelY = Math.max(16, window.innerHeight - panelHeight - 48);
      }
    } catch {
      panelX = Math.max(16, window.innerWidth - panelWidth - 24);
      panelY = Math.max(16, window.innerHeight - panelHeight - 48);
    }
  }

  function startPanelDrag(event: PointerEvent) {
    if (!isMainWindow || event.button !== 0) return;
    draggingPanel = true;
    dragOffset = { x: event.clientX - panelX, y: event.clientY - panelY };
    (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
  }

  function movePanel(event: PointerEvent) {
    if (!draggingPanel) return;
    panelX = Math.max(8, Math.min(window.innerWidth - 120, event.clientX - dragOffset.x));
    panelY = Math.max(8, Math.min(window.innerHeight - 100, event.clientY - dragOffset.y));
  }

  function stopPanelDrag() {
    if (!draggingPanel) return;
    draggingPanel = false;
    savePanelSizeFromElement();
    savePanelLayout();
  }

  function savePanelSizeFromElement() {
    if (!panelElement) return;
    const rect = panelElement.getBoundingClientRect();
    panelWidth = Math.max(360, Math.round(rect.width));
    panelHeight = Math.max(180, Math.round(rect.height));
    savePanelLayout();
  }


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
      state = "bg-[#a855f7]/90 t2t-agent-speaking";
    } else if (processing && mode === "agent") {
      state = "bg-[#c27aff]/80 t2t-agent-thinking";
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
    let unlistenStream: (() => void) | undefined;
    let unlistenPanelToggle: (() => void) | undefined;
    load("tts", { autoSave: true, defaults: {} }).then(async (store) => {
      captionsEnabled = ((await store.get("captions")) ?? true) as boolean;
    }).catch(() => {});
    listen<{ kind: string; text?: string }>("pi-stream", (event) => {
      const payload = event.payload;
      if (!captionsEnabled) {
        invoke("set_caption_interactivity", { interactive: false }).catch(() => {});
        return;
      }
      if (payload.kind === "start") {
        streamedResponse = "";
        streamVisible = true;
        panelMinimized = false;
        invoke("set_caption_interactivity", { interactive: true }).catch((err) => {
          console.error("Failed to enable caption scrolling:", err);
        });
      } else if (payload.kind === "delta" && payload.text) {
        streamedResponse += payload.text;
        streamVisible = true;
      } else if (payload.kind === "end") {
        // Keep the completed response available until the user hides or minimizes
        // it. A new turn replaces it and automatically restores the panel.
        if (payload.text) streamedResponse = payload.text;
        streamVisible = true;
        invoke("set_caption_interactivity", { interactive: !panelMinimized }).catch(() => {});
      }
    }).then((cleanup) => {
      unlistenStream = cleanup;
    });
    listen("toggle-response-panel", () => {
      if (!streamedResponse) return;
      panelMinimized = !panelMinimized;
      streamVisible = !panelMinimized;
      invoke("set_caption_interactivity", { interactive: !panelMinimized }).catch(() => {});
    }).then((cleanup) => {
      unlistenPanelToggle = cleanup;
    });

    // Initialize mode to typing (red bar)
    mode = "typing";
    loadPanelLayout();
    window.addEventListener("pointermove", movePanel);
    window.addEventListener("pointerup", stopPanelDrag);
    window.addEventListener("pointerup", savePanelSizeFromElement);

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
      unlistenStream?.();
      unlistenPanelToggle?.();
      window.removeEventListener("pointermove", movePanel);
      window.removeEventListener("pointerup", stopPanelDrag);
      window.removeEventListener("pointerup", savePanelSizeFromElement);
      invoke("set_caption_interactivity", { interactive: false }).catch(() => {});
    };
  });
</script>

{#if isMainWindow && streamVisible && streamedResponse}
  <aside
    aria-label="Agent response"
    role="region"
    bind:this={panelElement}
    class="fixed z-[10000] min-w-[360px] min-h-[180px] max-w-[calc(100vw-16px)] max-h-[calc(100vh-16px)] resize overflow-hidden rounded-xl border border-purple-300/30 bg-black/90 text-left text-base leading-relaxed text-white shadow-2xl backdrop-blur-md pointer-events-auto"
    style={`left:${panelX}px; top:${panelY}px; width:${panelWidth}px; height:${panelHeight}px`}
  >
    <div
      role="button"
      tabindex="0"
      onkeydown={(event) => event.preventDefault()}
      class="flex cursor-move touch-none items-center justify-between gap-4 border-b border-white/10 px-5 py-3 text-xs uppercase tracking-[0.18em] text-purple-200/80"
      onpointerdown={startPanelDrag}
      title="Drag to move response panel"
    >
      <span>Agent response · drag to move · resize from corner</span>
      <button
        type="button"
        aria-label="Minimize agent response"
        class="rounded px-2 py-1 text-purple-200 hover:bg-white/10 hover:text-white"
        onclick={() => {
          panelMinimized = true;
          streamVisible = false;
          invoke("set_caption_interactivity", { interactive: false }).catch(() => {});
        }}
      >
        Minimize
      </button>
    </div>
    <div class="max-h-[calc(70vh-48px)] overflow-y-auto overscroll-contain px-5 py-4 select-text whitespace-pre-wrap">
      {streamedResponse}
    </div>
  </aside>
{/if}

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
