<script lang="ts">
  import { overlay } from './connection.svelte';

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

  {#if overlay.phase !== 'idle' || overlay.reply || overlay.lastError}
    <div class="absolute bottom-10 left-1/2 flex max-w-xl -translate-x-1/2 items-center gap-3 rounded-2xl bg-black/85 px-5 py-3 text-white shadow-2xl">
      <span
        class="h-3 w-3 shrink-0 rounded-full"
        class:bg-red-500={overlay.phase === 'listening'}
        class:animate-pulse={overlay.phase !== 'idle'}
        class:bg-amber-400={overlay.phase === 'thinking'}
        class:bg-emerald-400={overlay.phase === 'speaking' || overlay.phase === 'idle'}
      ></span>
      <span class="text-sm">
        {#if overlay.lastError}{overlay.lastError}
        {:else if overlay.phase === 'listening'}{overlay.mode === 'agent' ? 'Listening for the agent…' : 'Listening…'}
        {:else if overlay.phase === 'thinking'}Thinking…
        {:else}{overlay.reply}{/if}
      </span>
    </div>
  {/if}

  {#if !overlay.connected}
    <div class="absolute right-4 top-10 rounded bg-black/70 px-2 py-1 text-xs text-white/70">agent offline</div>
  {/if}
</div>
