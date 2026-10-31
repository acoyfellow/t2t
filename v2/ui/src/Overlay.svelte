<script lang="ts">
  import { overlay } from './connection.svelte';
  import mark from './mark.svg?raw';

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
    <div class="absolute bottom-8 left-1/2 flex max-w-xl -translate-x-1/2 items-center gap-3 rounded-2xl bg-black/85 px-4 py-2.5 text-white shadow-2xl">
      <span class="h-5 w-5 shrink-0 text-[#c27aff]" class:t2t-agent-thinking={overlay.phase === 'thinking'}>{@html mark}</span>
      <span class="text-sm">
        {#if overlay.lastError}{overlay.lastError}
        {:else if overlay.phase === 'thinking' && !overlay.reply}Thinking…
        {:else}{overlay.reply}{/if}
      </span>
    </div>
  {/if}

  {#if !overlay.connected}
    <div class="absolute right-4 top-10 rounded bg-black/70 px-2 py-1 text-xs text-white/70">agent offline</div>
  {/if}
</div>
