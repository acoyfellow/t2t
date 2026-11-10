<script lang="ts">
  import { loadTranscript, overlay, setSetting, shell, type TranscriptLine } from './connection.svelte';
  import Indicator, { indicatorStyles, type IndicatorPhase } from './lib/Indicator.svelte';
  import models from './lib/models.json';
  import Mark from './lib/Mark.svelte';
  import McpPanel from './McpPanel.svelte';
  import WindowsPanel from './WindowsPanel.svelte';
  import JobsPanel from './JobsPanel.svelte';
  import StatsPanel from './StatsPanel.svelte';

  type Section = 'general' | 'tools' | 'stats' | 'windows' | 'jobs' | 'transcript';
  const sections: readonly string[] = ['general', 'stats', 'tools', 'windows', 'jobs', 'transcript'];
  const isSection = (value: unknown): value is Section => typeof value === 'string' && sections.includes(value);
  const initialSection = new URLSearchParams(location.search).get('section');
  let section: Section = $state(isSection(initialSection) ? initialSection : 'general');
  $effect(() => {
    if (isSection(overlay.section)) section = overlay.section;
  });
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
  const previewPhases: { phase: IndicatorPhase; mode: 'dictate' | 'agent'; label: string }[] = [
    { phase: 'listening', mode: 'dictate', label: 'Dictating' },
    { phase: 'listening', mode: 'agent', label: 'Asking the agent' },
    { phase: 'thinking', mode: 'agent', label: 'Thinking' },
    { phase: 'speaking', mode: 'agent', label: 'Speaking' },
  ];
  let previewIndex = $state(0);
  let previewLevel = $state(0);
  $effect(() => {
    const step = setInterval(() => (previewIndex = (previewIndex + 1) % previewPhases.length), 2600);
    const voice = setInterval(() => {
      const t = performance.now() / 1000;
      previewLevel = Math.max(0, 0.35 + 0.35 * Math.sin(t * 6.1) * Math.sin(t * 1.7) + 0.2 * Math.sin(t * 13));
    }, 50);
    return () => {
      clearInterval(step);
      clearInterval(voice);
    };
  });
  const preview = $derived(previewPhases[previewIndex]);
  const enabledTools = $derived(settings?.mcp.filter((server) => server.enabledInT2T).length ?? 0);
  const time = (at: number) => new Date(at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  const nav: { id: Section; label: string }[] = [
    { id: 'general', label: 'General' },
    { id: 'stats', label: 'Stats' },
    { id: 'tools', label: 'Agent tools' },
    { id: 'windows', label: 'Windows' },
    { id: 'jobs', label: 'Jobs' },
    { id: 'transcript', label: 'Transcript' },
  ];

  const permissionRows = $derived(
    settings
      ? [
          { label: 'Microphone', ok: settings.permissions.microphone, why: 'Lets t2t hear you while you hold Fn, so your words become text.', pane: 'Microphone' },
          { label: 'Input Monitoring', ok: settings.permissions.inputMonitoring, why: 'Lets t2t hear the Fn key you hold to start and stop talking.', pane: 'InputMonitoring' },
          { label: 'Accessibility', ok: settings.permissions.accessibility, why: 'Lets t2t type your words into the app you are in, at your cursor.', pane: 'Accessibility' },
          { label: 'Screen Recording', ok: settings.permissions.screenRecording, why: 'Lets your agent see your screen when you ask it a question.', pane: 'ScreenRecording' },
        ]
      : [],
  );
  $effect(() => {
    if (section !== 'general') return;
    const timer = setInterval(() => shell({ command: 'settings' }), 1500);
    return () => clearInterval(timer);
  });
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
    {#if section === 'windows'}
      <WindowsPanel />
    {:else if section === 'stats'}
      <StatsPanel />
    {:else if section === 'jobs'}
      <JobsPanel />
    {:else if !settings}
      <div class="flex items-center gap-3 text-sm text-white/60"><Mark spinning class="h-5 w-5 text-[#c27aff]" /> Loading…</div>
    {:else if section === 'general'}
      <h1 class="mb-6 text-xl font-semibold">General</h1>

      <section class="mb-6 rounded-xl border border-white/5 bg-white/[0.03] p-5">
        <h2 class="mb-4 text-sm font-medium text-white/80">Look</h2>
        <label class="mb-4 flex items-center justify-between gap-4 text-sm">
          <span>Voice indicator <span class="text-white/40">(the strip at the bottom of the screen)</span></span>
          <select
            class="w-48 rounded-md border border-white/10 bg-black/40 px-2 py-1 text-sm"
            value={settings.indicatorStyle}
            onchange={(event) => setSetting('indicatorStyle', event.currentTarget.value)}
          >
            {#each indicatorStyles as option (option.id)}<option value={option.id}>{option.label}</option>{/each}
          </select>
        </label>
        <div data-indicator-preview class="relative overflow-hidden rounded-lg border border-white/5 bg-black/60" style="height:140px">
          <span class="absolute left-3 top-2 font-mono text-[11px] text-white/40">{preview.label}</span>
          <div class="absolute inset-x-0 bottom-0">
            {#if settings.indicatorStyle === 'classic'}
              <div
                class="w-full transition-all duration-300 {preview.phase === 'thinking' ? 't2t-agent-thinking' : preview.phase === 'speaking' ? 't2t-agent-speaking' : ''}"
                style="height:{preview.phase === 'listening' ? 6 + previewLevel * 30 : 6}px;background:{preview.phase === 'listening' && preview.mode === 'dictate' ? '#00ffa3cc' : preview.phase === 'speaking' ? '#a855f7e6' : '#c27affcc'}"
              ></div>
            {:else}
              {#key settings.indicatorStyle}<Indicator style={settings.indicatorStyle} phase={preview.phase} mode={preview.mode} level={previewLevel} height={130} />{/key}
            {/if}
          </div>
        </div>
      </section>


      <section class="mb-6 rounded-xl border border-white/5 bg-white/[0.03] p-5">
        <h2 class="mb-4 text-sm font-medium text-white/80">Agent model</h2>
        <label class="flex items-center justify-between gap-4 text-sm">
          <span>Model <span class="text-white/40">(the agent that answers Fn+Ctrl turns)</span></span>
          <select
            class="w-64 rounded-md border border-white/10 bg-black/40 px-2 py-1 text-sm"
            value={settings.model}
            onchange={(event) => setSetting('model', event.currentTarget.value)}
            data-testid="model-select"
          >
            {#each [...new Set(models.map((m) => m.family))].sort() as family (family)}
              <optgroup label={family}>
                {#each models.filter((m) => m.family === family) as model (model.id)}
                  <option value={model.id}>{model.name} · ${model.cost?.input ?? '?'} / ${model.cost?.output ?? '?'} per M</option>
                {/each}
              </optgroup>
            {/each}
          </select>
        </label>
      </section>

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
        {#if settings.streamDictation}
          <div class="text-sm">
            <div class="flex items-center justify-between">
              <span>Paste after a pause of <span class="font-mono text-[#c27aff]">{settings.pastePauseSeconds.toFixed(2)}s</span></span>
              <input
                type="range"
                min="0.2"
                max="2.5"
                step="0.05"
                class="w-48 accent-[#c27aff]"
                value={settings.pastePauseSeconds}
                oninput={(event) => setSetting('pastePauseSeconds', Number(event.currentTarget.value))}
              />
            </div>
            <div class="mt-1 flex justify-between text-xs text-white/40">
              <span>quicker, shorter pieces</span>
              <span>fewer, more accurate pieces</span>
            </div>
          </div>
        {/if}
        <label class="flex items-center justify-between text-sm">
          <span>Mute while talking <span class="text-white/40">(silence your Mac's sound while you hold fn)</span></span>
          <input type="checkbox" class="h-4 w-4 accent-[#c27aff]" checked={settings.muteWhileTalking} onchange={(event) => setSetting('muteWhileTalking', event.currentTarget.checked)} />
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
          <span>Claude Opus 5.5 {#if settings.gateway.host}<span class="text-white/40">· {settings.gateway.host}</span>{/if}</span>
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
            <div class="flex items-center justify-between gap-4 text-sm">
              <span><span class="text-white/85">{row.label}</span> <span class="text-white/45">{row.why}</span></span>
              {#if row.ok}
                <span class="shrink-0 rounded-full bg-[#00ffa3]/15 px-2 py-0.5 text-xs text-[#00ffa3]" data-testid="permission-granted">Granted</span>
              {:else}
                <button type="button" class="shrink-0 rounded-md border border-white/15 px-2.5 py-1 text-xs hover:bg-white/10" onclick={() => shell({ command: 'openPane', pane: row.pane })} data-testid="permission-grant">Grant…</button>
              {/if}
            </div>
          {/each}
        </div>
      </section>
    {:else if section === 'tools'}
      <McpPanel servers={settings.mcp} path={settings.mcpPath} confirmMcp={settings.confirmMcp} />
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
