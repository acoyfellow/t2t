<script lang="ts">
  import { shell, stats } from './connection.svelte';

  $effect(() => {
    shell({ command: 'stats' });
    const timer = setInterval(() => shell({ command: 'stats' }), 5000);
    return () => clearInterval(timer);
  });

  const value = $derived(stats.value);
  const peak = $derived(Math.max(1, ...(value?.recent ?? [])));
  const cards = $derived(
    value
      ? [
          { label: 'Total words', text: Math.round(value.totalWords).toLocaleString() },
          { label: 'Lifetime avg', text: `${Math.round(value.lifetimeWpm)} wpm` },
          { label: 'Session avg', text: `${Math.round(value.sessionAvgWpm)} wpm` },
          { label: 'Sessions', text: Math.round(value.sessions).toLocaleString() },
          { label: 'Hours talking', text: value.hoursActive.toFixed(1) },
        ]
      : [],
  );
</script>

<h1 class="mb-2 text-xl font-semibold">Stats</h1>
<p class="mb-6 text-sm text-white/50">Words you have spoken through t2t, counted on this Mac only.</p>

{#if !value}
  <p class="text-sm text-white/50">Loading…</p>
{:else}
  <div class="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-3">
    {#each cards as card (card.label)}
      <div class="rounded-xl border border-white/5 bg-white/[0.03] p-4">
        <p class="mb-1 text-[11px] uppercase tracking-wider text-white/40">{card.label}</p>
        <p class="text-3xl font-semibold tabular-nums">{card.text}</p>
      </div>
    {/each}
  </div>

  <section class="mb-6 rounded-xl border border-white/5 bg-white/[0.03] p-4">
    <p class="mb-3 text-[11px] uppercase tracking-wider text-white/40">Words per hour, last 48 hours</p>
    <div class="flex h-24 items-end gap-[2px]">
      {#each value.recent as words, index (index)}
        <div class="flex-1 rounded-sm bg-[#c27aff]/60" style="height: {Math.max(2, (words / peak) * 100)}%" title="{Math.round(words)} words"></div>
      {/each}
    </div>
  </section>

  {#if value.importedFrom}
    <p class="font-mono text-[11px] text-white/30">Includes t2t v1 history from {value.importedFrom} · imported {new Date(value.importedAt ?? '').toLocaleString()}</p>
  {:else if value.legacyAvailable}
    <button type="button" class="rounded-md bg-[#c27aff]/20 px-3 py-1.5 text-xs text-[#e2c2ff] hover:bg-[#c27aff]/30" onclick={() => shell({ command: 'statsImport' })}>Bring in t2t v1 stats</button>
  {/if}
{/if}
