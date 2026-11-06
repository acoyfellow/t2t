<script lang="ts">
  import { jobs, shell, type Job } from './connection.svelte';

  let open = $state('');

  const refresh = () => {
    shell({ command: 'jobs' });
    if (open) shell({ command: 'jobLog', name: open, lines: 80 });
  };

  $effect(() => {
    refresh();
    const timer = setInterval(refresh, 4000);
    return () => clearInterval(timer);
  });

  const toggle = (name: string) => {
    open = open === name ? '' : name;
    if (open) shell({ command: 'jobLog', name, lines: 80 });
  };

  const run = (name: string) => {
    jobs.error = '';
    shell({ command: 'jobRun', name });
  };

  const ago = (iso?: string) => {
    if (!iso) return 'never';
    const seconds = Math.round((Date.now() - Date.parse(iso)) / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
    return `${Math.round(seconds / 86400)}d ago`;
  };

  const status = (job: Job) =>
    job.running
      ? { label: 'running', tone: 'text-[#c27aff]' }
      : job.abandoned
        ? { label: 'did not finish', tone: 'text-[#ffb86b]' }
        : job.exitCode === undefined
        ? { label: 'not run', tone: 'text-white/40' }
        : job.exitCode === 0
          ? { label: 'ok', tone: 'text-[#00FFA3]' }
          : { label: `exit ${job.exitCode}`, tone: 'text-[#ff6b6b]' };
</script>

<h1 class="mb-2 text-xl font-semibold">Jobs</h1>
<p class="mb-4 text-sm text-white/50">Local loops: a schedule plus a command, run by the <code class="font-mono">loops</code> watcher. Run one now or read its last log.</p>

{#if !jobs.state}
  <p class="text-sm text-white/50">Loading…</p>
{:else}
  <p class="mb-5 font-mono text-[11px] text-white/40">
    {jobs.state.file || 'no loops.yaml found'} ·
    <span class={jobs.state.watcher ? 'text-[#00FFA3]' : 'text-[#ff6b6b]'}>watcher {jobs.state.watcher ? 'running' : 'stopped'}</span>
  </p>
  {#if jobs.error}<p class="mb-4 text-sm text-[#ff6b6b]">{jobs.error}</p>{/if}
  {#if jobs.state.jobs.length === 0}<p class="text-sm text-white/50">No jobs yet. Add one to loops.yaml.</p>{/if}

  <div class="grid gap-3">
    {#each jobs.state.jobs as job (job.name)}
      {@const state = status(job)}
      <article class="rounded-xl border border-white/5 bg-white/[0.03] p-4 {job.defined ? '' : 'opacity-60'}">
        <div class="flex items-start justify-between gap-4">
          <button type="button" class="min-w-0 text-left" onclick={() => toggle(job.name)}>
            <div class="flex items-center gap-2">
              <h2 class="text-sm font-medium">{job.name}</h2>
              <span class="text-xs {state.tone}">● {state.label}</span>
              {#if !job.defined}<span class="text-xs text-white/40">removed from loops.yaml</span>{/if}
            </div>
            <p class="mt-1 truncate font-mono text-[11px] text-white/40">{job.schedule || 'on demand'} · {job.run || '—'}</p>
            <p class="mt-1 flex items-center gap-1 text-[11px] text-white/30">
              last {ago(job.startedAt)}
              <span class="ml-2 flex gap-0.5">
                {#each job.recent as exit, index (index)}<span class="h-2 w-2 rounded-sm {exit === 0 ? 'bg-[#00FFA3]/70' : 'bg-[#ff6b6b]/70'}" title="exit {exit}"></span>{/each}
              </span>
            </p>
          </button>
          {#if job.defined}
            <button
              type="button"
              class="shrink-0 rounded-md bg-[#c27aff]/20 px-3 py-1.5 text-xs text-[#e2c2ff] hover:bg-[#c27aff]/30 disabled:opacity-40"
              disabled={state.label === 'running'}
              onclick={() => run(job.name)}>Run now</button
            >
          {/if}
        </div>
        {#if open === job.name}
          <pre class="mt-3 max-h-80 overflow-auto rounded-lg bg-black/50 p-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap text-white/70">{jobs.logs[job.name] ?? 'Loading…'}</pre>
        {/if}
      </article>
    {/each}
  </div>
{/if}
