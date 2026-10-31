<script lang="ts">
  import { dismiss, overlay, shell } from './connection.svelte';
  import Mark from './lib/Mark.svelte';

  let bubble: HTMLElement | undefined = $state();

  $effect(() => {
    void overlay.reply;
    void overlay.lastError;
    void overlay.phase;
    const rect = bubble?.getBoundingClientRect();
    const rects = rect ? [{ x: rect.x, y: rect.y, w: rect.width, h: rect.height }] : [];
    shell({ command: 'hitRegions', rects });
  });

  const bar = $derived.by(() => {
    if (overlay.phase === 'listening') return overlay.mode === 'agent' ? 'bg-[#c27aff]/80' : 'bg-[#00ffa3]/80';
    if (overlay.phase === 'speaking') return 'bg-[#a855f7]/90 t2t-agent-speaking';
    if (overlay.phase === 'thinking') return overlay.mode === 'agent' ? 'bg-[#c27aff]/80 t2t-agent-thinking' : 'bg-amber-500/80';
    return 'bg-transparent';
  });

  const glowColor = $derived(overlay.phase === 'listening' && overlay.mode === 'dictate' ? '0,255,163' : '194,122,255');
  const barHeight = $derived(overlay.phase === 'listening' ? 6 + overlay.level * 30 : 6);
  const glowSize = $derived(overlay.phase === 'listening' ? 18 + overlay.level * 90 : 0);
  const glowAlpha = $derived(0.35 + overlay.level * 0.45);

  const palette: Record<string, string> = { red: '#ef4444', blue: '#3b82f6', green: '#22c55e', yellow: '#eab308' };
  const colorOf = (name: string | undefined) => (name && palette[name]) || name || '#f97316';
</script>

<div class="pointer-events-none fixed inset-0">
  {#each overlay.shapes as shape (shape.id)}
    {#if shape.kind === 'box' || shape.kind === 'highlight'}
      <div
        data-shape={shape.kind}
        class="absolute rounded-lg border-4"
        style="left:{shape.x}px;top:{shape.y}px;width:{shape.w}px;height:{shape.h}px;border-color:{colorOf(shape.color)};background:{shape.kind === 'highlight' ? colorOf(shape.color) + '33' : 'transparent'}"
      >
        {#if shape.label}
          <span class="absolute -top-7 left-0 rounded bg-black/80 px-2 py-0.5 text-sm text-white">{shape.label}</span>
        {/if}
      </div>
    {:else if shape.kind === 'text'}
      <div data-shape="text" class="absolute rounded bg-black/80 px-3 py-1 text-lg text-white" style="left:{shape.x}px;top:{shape.y}px">
        {shape.label ?? ''}
      </div>
    {:else if shape.kind === 'arrow'}
      <svg data-shape="arrow" class="absolute inset-0 h-full w-full overflow-visible">
        <defs>
          <marker id="head-{shape.id}" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto">
            <path d="M0,0 L10,5 L0,10 z" fill={colorOf(shape.color)} />
          </marker>
        </defs>
        <line x1={shape.x} y1={shape.y} x2={shape.x + shape.w} y2={shape.y + shape.h} stroke={colorOf(shape.color)} stroke-width="4" marker-end="url(#head-{shape.id})" />
      </svg>
    {/if}
  {/each}

  <div
    data-indicator
    class="absolute bottom-0 left-0 w-full transition-[background-color] duration-300 ease-out {bar}"
    style="height:{barHeight}px;box-shadow:0 0 {glowSize}px rgba({glowColor},{overlay.phase === 'idle' ? 0 : glowAlpha});transition-property:background-color,height,box-shadow;transition-duration:300ms,60ms,60ms"
  ></div>

  {#if overlay.reply || overlay.lastError || overlay.phase === 'thinking'}
    <div
      bind:this={bubble}
      data-bubble
      class="pointer-events-auto absolute bottom-8 left-1/2 flex max-w-xl -translate-x-1/2 items-start gap-3 rounded-2xl bg-black/85 py-2.5 pl-4 pr-2 text-white shadow-2xl ring-1 ring-white/10 backdrop-blur"
    >
      <Mark spinning={overlay.phase === 'thinking'} class="mt-0.5 h-5 w-5 shrink-0 text-[#c27aff]" />
      <span class="max-h-48 overflow-y-auto pt-0.5 text-sm leading-relaxed" class:text-red-300={overlay.lastError}>
        {#if overlay.lastError}{overlay.lastError}
        {:else if overlay.phase === 'thinking' && !overlay.reply}{overlay.activity ? `Using ${overlay.activity}…` : 'Thinking…'}
        {:else}{overlay.reply}{/if}
      </span>
      {#if overlay.talking}
        <button
          type="button"
          aria-label="Stop speaking"
          title="Stop speaking"
          class="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[#c27aff] hover:bg-white/10"
          onclick={() => shell({ command: 'stopSpeaking' })}
        >
          <svg viewBox="0 0 24 24" class="h-4 w-4" fill="currentColor" aria-hidden="true"><path d="M3 9v6h4l5 4V5L7 9H3zm13.5 3a4.5 4.5 0 0 0-2.5-4v8a4.5 4.5 0 0 0 2.5-4z" /></svg>
        </button>
      {/if}
      <button
        type="button"
        aria-label="Dismiss"
        title="Dismiss (Esc)"
        data-dismiss
        class="flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-white/60 hover:bg-white/10 hover:text-white"
        onclick={dismiss}
      >
        <svg viewBox="0 0 24 24" class="h-3.5 w-3.5" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" /></svg>
      </button>
    </div>
  {/if}

  {#if !overlay.connected}
    <div class="absolute right-4 top-10 rounded bg-black/70 px-2 py-1 text-xs text-white/70">agent offline</div>
  {/if}
</div>
