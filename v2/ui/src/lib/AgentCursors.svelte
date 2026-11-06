<script lang="ts">
  import { cursors } from '../cursors.svelte';
</script>

{#each Object.values(cursors.byAgent) as cursor (cursor.agent)}
  <div
    data-agent-cursor={cursor.agent}
    data-phase={cursor.phase}
    class="pointer-events-none absolute left-0 top-0 z-50"
    style="transform:translate({cursor.x}px,{cursor.y}px);transition:transform {cursor.travelMs}ms cubic-bezier(0.22,1,0.36,1);opacity:{cursor.visible ? 1 : 0}"
  >
    <svg viewBox="0 0 24 24" class="h-7 w-7 -translate-x-[3px] -translate-y-[2px] drop-shadow-[0_2px_6px_rgba(0,0,0,0.55)]" aria-hidden="true">
      <path d="M3 2 L3 19 L8 14.5 L11.5 22 L14.5 20.6 L11 13.2 L18 13.2 Z" fill={cursor.color} stroke="#0b0b10" stroke-width="1.4" stroke-linejoin="round" />
    </svg>
    {#if cursor.phase === 'after'}
      <span
        class="absolute left-0 top-0 h-10 w-10 -translate-x-1/2 -translate-y-1/2 animate-ping rounded-full"
        style="background:{cursor.ok ? cursor.color : '#ef4444'}55"
      ></span>
    {/if}
    <span
      class="absolute left-6 top-5 whitespace-nowrap rounded-full px-2.5 py-1 text-xs font-medium text-black shadow-lg"
      style="background:{cursor.ok ? cursor.color : '#fca5a5'}">{cursor.label}</span
    >
  </div>
  {#if cursor.target && cursor.visible}
    <div
      data-agent-target={cursor.agent}
      class="pointer-events-none absolute rounded-md border-2 transition-all duration-200"
      style="left:{cursor.target.x - 3}px;top:{cursor.target.y - 3}px;width:{cursor.target.w + 6}px;height:{cursor.target.h + 6}px;border-color:{cursor.color};background:{cursor.color}1a"
    ></div>
  {/if}
{/each}
