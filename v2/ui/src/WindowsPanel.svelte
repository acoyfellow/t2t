<script lang="ts">
  import { forgetWindow, loadLibrary, reopenWindow, type SavedWindow } from './connection.svelte';

  let windows: SavedWindow[] = $state([]);
  let query = $state('');
  let status = $state('Loading…');
  let busy = $state('');

  const refresh = () =>
    loadLibrary()
      .then((next) => {
        windows = next;
        status = '';
      })
      .catch((error) => (status = `Could not load windows: ${error}`));

  $effect(() => {
    refresh();
    const timer = setInterval(refresh, 5000);
    return () => clearInterval(timer);
  });

  const visible = $derived(
    windows.filter((window) => {
      const needle = query.trim().toLowerCase();
      return needle === '' || `${window.title} ${window.summary} ${window.ask} ${window.id}`.toLowerCase().includes(needle);
    }),
  );

  const when = (at: number) => new Date(at).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

  const act = async (id: string, run: (id: string) => Promise<unknown>) => {
    busy = id;
    await run(id).catch((error) => (status = String(error)));
    busy = '';
    await refresh();
  };

  const remove = (window: SavedWindow) => {
    if (confirm(`Delete "${window.title}" from saved windows?`)) act(window.id, forgetWindow);
  };
</script>

<h1 class="mb-2 text-xl font-semibold">Windows</h1>
<p class="mb-6 text-sm text-white/50">Every window the agent makes is saved here. Open one again, or ask the agent for “the one about …”; it checks this list before it builds anything new.</p>

<input
  class="mb-5 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm"
  placeholder="Search titles, contents and the requests that made them"
  bind:value={query}
/>

{#if status}<p class="mb-4 text-sm text-white/50">{status}</p>{/if}
{#if !status && windows.length === 0}<p class="text-sm text-white/50">No windows yet. Hold Fn + Ctrl and ask the agent to show you how something works.</p>{/if}

<div class="grid gap-3">
  {#each visible as window (window.id)}
    <article class="rounded-xl border border-white/5 bg-white/[0.03] p-4">
      <div class="flex items-start justify-between gap-4">
        <div class="min-w-0">
          <div class="flex items-center gap-2">
            <span class="rounded bg-white/10 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider {window.kind === 'scene' ? 'text-[#00FFA3]' : 'text-[#c27aff]'}">{window.kind}</span>
            <h2 class="truncate text-sm font-medium">{window.title}</h2>
            {#if window.open}<span class="text-xs text-[#00FFA3]">● open</span>{/if}
          </div>
          {#if window.summary}<p class="mt-1 line-clamp-2 text-xs text-white/50">{window.summary}</p>{/if}
          {#if window.ask}<p class="mt-1 truncate text-xs italic text-white/40">“{window.ask}”</p>{/if}
          <p class="mt-2 font-mono text-[11px] text-white/30">{window.id} · {when(window.updatedAt)} · opened {window.opens}× · {Math.round(window.bytes / 1024)} KB</p>
        </div>
        <div class="flex shrink-0 gap-2">
          <button
            type="button"
            class="rounded-md bg-[#c27aff]/20 px-3 py-1.5 text-xs text-[#e2c2ff] hover:bg-[#c27aff]/30 disabled:opacity-40"
            disabled={busy === window.id}
            onclick={() => act(window.id, reopenWindow)}>{window.open ? 'Reload' : 'Open'}</button
          >
          <button type="button" class="rounded-md px-2 py-1.5 text-xs text-white/40 hover:bg-white/5 hover:text-white/80" onclick={() => remove(window)}>Delete</button>
        </div>
      </div>
    </article>
  {/each}
</div>
