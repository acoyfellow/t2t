<script lang="ts">
  import { loadTranscript, overlay, setSetting, type TranscriptLine } from './connection.svelte';
  import Mark from './lib/Mark.svelte';

  type Section = 'general' | 'tools' | 'transcript';
  let section: Section = $state('general');
  let transcript: TranscriptLine[] = $state(loadTranscript());

  const refreshTranscript = () => (transcript = loadTranscript());
  $effect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key === 't2t.transcript') refreshTranscript();
    };
    window.addEventListener('storage', onStorage);
    const timer = setInterval(refreshTranscript, 1500);
    return () => {
      window.removeEventListener('storage', onStorage);
      clearInterval(timer);
    };
  });

  const settings = $derived(overlay.settings);
  const enabledTools = $derived(settings?.mcp.filter((server) => server.enabledInT2T).length ?? 0);
  const time = (at: number) => new Date(at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  const nav: { id: Section; label: string }[] = [
    { id: 'general', label: 'General' },
    { id: 'tools', label: 'Agent tools' },
    { id: 'transcript', label: 'Transcript' },
  ];

  const permissionRows = $derived(
    settings
      ? [
          { label: 'Input Monitoring', ok: settings.permissions.inputMonitoring, why: 'Hear Fn and Fn+Ctrl' },
          { label: 'Accessibility', ok: settings.permissions.accessibility, why: 'Paste into other apps' },
          { label: 'Screen Recording', ok: settings.permissions.screenRecording, why: 'Let the agent see your screen' },
        ]
      : [],
  );
</script>

<div class="flex min-h-screen">
  <aside class="flex w-52 shrink-0 flex-col gap-1 border-r border-white/5 bg-black/30 p-4">
    <div class="mb-5 flex items-center gap-2 px-2">
      <Mark class="h-6 w-6 text-[#c27aff]" />
      <span class="text-sm font-semibold tracking-wide">t2t</span>
    </div>
    {#each nav as item (item.id)}
      <button
        type="button"
        class="rounded-lg px-3 py-2 text-left text-sm transition-colors {section === item.id ? 'bg-white/10 text-white' : 'text-white/60 hover:bg-white/5 hover:text-white'}"
        onclick={() => (section = item.id)}
      >
        {item.label}
        {#if item.id === 'tools' && settings}<span class="float-right text-xs text-white/40">{enabledTools}</span>{/if}
      </button>
    {/each}
  </aside>

  <main class="flex-1 overflow-y-auto p-8">
    {#if !settings}
      <div class="flex items-center gap-3 text-sm text-white/60"><Mark spinning class="h-5 w-5 text-[#c27aff]" /> Loading…</div>
    {:else if section === 'general'}
      <h1 class="mb-6 text-xl font-semibold">General</h1>

      <section class="mb-6 rounded-xl border border-white/5 bg-white/[0.03] p-5">
        <h2 class="mb-4 text-sm font-medium text-white/80">Shortcuts</h2>
        <div class="grid gap-3 text-sm">
          <div class="flex items-center justify-between"><span>Dictate and paste</span><kbd class="rounded bg-white/10 px-2 py-0.5 text-xs">hold Fn</kbd></div>
          <div class="flex items-center justify-between"><span>Ask the agent</span><kbd class="rounded bg-white/10 px-2 py-0.5 text-xs">hold Fn + Ctrl</kbd></div>
          <div class="flex items-center justify-between"><span>Dismiss and stop speaking</span><kbd class="rounded bg-white/10 px-2 py-0.5 text-xs">Esc</kbd></div>
        </div>
      </section>

      <section class="mb-6 rounded-xl border border-white/5 bg-white/[0.03] p-5">
        <h2 class="mb-4 text-sm font-medium text-white/80">Dictation</h2>
        <label class="flex items-center justify-between text-sm">
          <span>Type as I talk <span class="text-white/40">(paste each phrase at a pause, not only at the end)</span></span>
          <input type="checkbox" class="h-4 w-4 accent-[#c27aff]" checked={settings.streamDictation} onchange={(event) => setSetting('streamDictation', event.currentTarget.checked)} />
        </label>
      </section>

      <section class="mb-6 rounded-xl border border-white/5 bg-white/[0.03] p-5">
        <h2 class="mb-4 text-sm font-medium text-white/80">Voice reply</h2>
        <label class="mb-4 flex items-center justify-between text-sm">
          <span>Speak agent replies aloud</span>
          <input type="checkbox" class="h-4 w-4 accent-[#c27aff]" checked={settings.speak} onchange={(event) => setSetting('speak', event.currentTarget.checked)} />
        </label>
        <label class="flex items-center justify-between gap-4 text-sm">
          <span>Voice <span class="text-white/40">(macOS <code>say -v</code> name, empty for system voice)</span></span>
          <input
            class="w-48 rounded-md border border-white/10 bg-black/40 px-2 py-1 text-sm"
            value={settings.voice}
            placeholder="System default"
            onchange={(event) => setSetting('voice', event.currentTarget.value.trim())}
          />
        </label>
      </section>

      <section class="mb-6 rounded-xl border border-white/5 bg-white/[0.03] p-5">
        <h2 class="mb-4 text-sm font-medium text-white/80">Model</h2>
        <div class="flex items-center justify-between gap-4 text-sm">
          <span>Claude Opus 5.5 <span class="text-white/40">· the opencode gateway</span></span>
          <div class="flex items-center gap-3">
            {#if settings.gateway.state === 'ok'}
              <span class="rounded-full bg-[#00ffa3]/15 px-2 py-0.5 text-xs text-[#00ffa3]">Signed in · {settings.gateway.hoursLeft}h left</span>
            {:else if settings.gateway.state === 'refreshing'}
              <span class="flex items-center gap-2 text-xs text-white/60"><Mark spinning class="h-3.5 w-3.5 text-[#c27aff]" /> Refreshing…</span>
            {:else if settings.gateway.state === 'login-needed'}
              <span class="rounded-full bg-amber-500/15 px-2 py-0.5 text-xs text-amber-300">Sign-in needed</span>
            {:else if settings.gateway.state === 'push-failed'}
              <span class="rounded-full bg-red-500/15 px-2 py-0.5 text-xs text-red-300" title={settings.gateway.error}>Could not reach agent</span>
            {:else}
              <span class="text-xs text-white/40">Checking…</span>
            {/if}
            <button
              type="button"
              class="rounded-md border border-white/10 px-2.5 py-1 text-xs hover:bg-white/10"
              onclick={() => setSetting('refreshGateway', settings.gateway.state === 'login-needed')}
            >{settings.gateway.state === 'login-needed' ? 'Sign in' : 'Refresh'}</button>
          </div>
        </div>
        {#if settings.gateway.error && settings.gateway.state !== 'ok'}
          <p class="mt-2 truncate font-mono text-xs text-white/40">{settings.gateway.error}</p>
        {/if}
      </section>

      <section class="rounded-xl border border-white/5 bg-white/[0.03] p-5">
        <h2 class="mb-4 text-sm font-medium text-white/80">Permissions</h2>
        <div class="grid gap-3">
          {#each permissionRows as row (row.label)}
            <div class="flex items-center justify-between text-sm">
              <span>{row.label} <span class="text-white/40">· {row.why}</span></span>
              <span class="rounded-full px-2 py-0.5 text-xs {row.ok ? 'bg-[#00ffa3]/15 text-[#00ffa3]' : 'bg-amber-500/15 text-amber-300'}">{row.ok ? 'Granted' : 'Needed'}</span>
            </div>
          {/each}
        </div>
      </section>
    {:else if section === 'tools'}
      <h1 class="mb-2 text-xl font-semibold">Agent tools</h1>
      <p class="mb-6 text-sm text-white/50">MCP servers from <code class="text-white/70">{settings.mcpPath}</code>. Turn a server on to offer it to the agent.</p>
      <div class="overflow-hidden rounded-xl border border-white/5">
        {#each settings.mcp as server (server.name)}
          <label class="flex items-center gap-4 border-b border-white/5 bg-white/[0.03] px-5 py-3 last:border-b-0 hover:bg-white/[0.05]">
            <input
              type="checkbox"
              class="h-4 w-4 accent-[#c27aff]"
              checked={server.enabledInT2T}
              onchange={(event) => setSetting('mcp', { name: server.name, enabled: event.currentTarget.checked })}
            />
            <div class="min-w-0 flex-1">
              <div class="flex items-center gap-2 text-sm font-medium">
                {server.name}
                <span class="rounded bg-white/10 px-1.5 py-px text-[10px] uppercase tracking-wider text-white/50">{server.transport}</span>
                {#if !server.enabledInPi}<span class="text-[10px] uppercase tracking-wider text-amber-300/80">off in pi</span>{/if}
              </div>
              <div class="truncate font-mono text-xs text-white/40">{server.target}</div>
            </div>
          </label>
        {:else}
          <div class="p-5 text-sm text-white/50">No MCP servers found.</div>
        {/each}
      </div>
    {:else}
      <div class="mb-6 flex items-center justify-between">
        <h1 class="text-xl font-semibold">Transcript</h1>
        <button
          type="button"
          class="rounded-md px-3 py-1 text-xs text-white/50 hover:bg-white/5 hover:text-white"
          onclick={() => {
            localStorage.setItem('t2t.transcript', '[]');
            refreshTranscript();
          }}>Clear</button
        >
      </div>
      <div class="space-y-1 font-mono text-xs">
        {#each transcript as line (line.at + line.role)}
          <div class="flex gap-3 rounded px-2 py-1 hover:bg-white/[0.03]">
            <span class="shrink-0 text-white/30">{time(line.at)}</span>
            <span class="w-12 shrink-0 {line.role === 'agent' ? 'text-[#c27aff]' : line.role === 'error' ? 'text-red-400' : line.mode === 'dictate' ? 'text-[#00ffa3]' : 'text-white/70'}">{line.role === 'you' ? (line.mode === 'dictate' ? 'dictate' : 'you') : line.role}</span>
            <span class="whitespace-pre-wrap text-white/85">{line.text}</span>
          </div>
        {:else}
          <div class="text-white/40">Nothing yet. Hold Fn to dictate, or Fn + Ctrl to ask the agent.</div>
        {/each}
      </div>
    {/if}
  </main>
</div>
