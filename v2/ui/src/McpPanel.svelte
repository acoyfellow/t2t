<script lang="ts">
  import { mcpAction, mcpStatus, type McpServer, type McpStatus, setSetting, shell } from './connection.svelte';
  import Mark from './lib/Mark.svelte';

  let { servers, path, confirmMcp }: { servers: McpServer[]; path: string; confirmMcp: boolean } = $props();

  let statuses: Record<string, McpStatus> = $state({});
  let open: Record<string, boolean> = $state({});
  let busy: Record<string, boolean> = $state({});
  let hostError = $state('');
  let lastShown = '';

  const enabled = $derived(servers.filter((server) => server.enabledInT2T).map((server) => server.name));

  const poll = async (warm: boolean) => {
    if (enabled.length === 0) return;
    try {
      const { servers: next } = await mcpStatus(enabled, warm);
      for (const entry of next) statuses[entry.server] = entry;
      hostError = '';
      const shown = next.map((entry) => `${entry.server}=${entry.state}:${entry.tools.length}`).join(' ');
      if (shown !== lastShown) shell({ command: 'log', line: `mcp panel ${shown}` });
      lastShown = shown;
    } catch (error) {
      hostError = `The t2t MCP host on this Mac is not reachable (${error}).`;
    }
  };

  $effect(() => {
    void enabled.join(',');
    void poll(true);
    const timer = setInterval(() => void poll(false), 1500);
    return () => clearInterval(timer);
  });

  const act = async (action: 'refresh' | 'disconnect' | 'connect', server: string) => {
    busy[server] = true;
    statuses[server] = { ...(statuses[server] ?? { server, tools: [] }), state: action === 'disconnect' ? 'disconnected' : 'connecting', error: undefined };
    try {
      statuses[server] = await mcpAction(action, server);
    } catch (error) {
      hostError = String(error);
    }
    busy[server] = false;
  };

  const badge: Record<string, string> = {
    connected: 'bg-[#00ffa3]/15 text-[#00ffa3]',
    connecting: 'bg-[#c27aff]/15 text-[#c27aff]',
    error: 'bg-red-500/15 text-red-300',
    disconnected: 'bg-white/10 text-white/50',
    idle: 'bg-white/10 text-white/50',
  };
</script>

<h1 class="mb-2 text-xl font-semibold">Agent tools</h1>
<p class="mb-6 text-sm text-white/50">MCP servers from <code class="text-white/70">{path}</code>. Turn a server on to offer it to the agent.</p>
{#if hostError}
  <div class="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2 text-sm text-red-200" data-testid="mcp-host-error">{hostError}</div>
{/if}
<label class="mb-4 flex items-center justify-between rounded-xl border border-white/5 bg-white/[0.03] px-5 py-3 text-sm">
  <span>Ask before each tool call <span class="text-white/40">(show Allow / Deny before the agent runs an MCP tool)</span></span>
  <input type="checkbox" data-testid="confirm-mcp" class="h-4 w-4 accent-[#c27aff]" checked={confirmMcp} onchange={(event) => setSetting('confirmMcp', event.currentTarget.checked)} />
</label>
<div class="overflow-hidden rounded-xl border border-white/5">
  {#each servers as server (server.name)}
    {@const status = statuses[server.name]}
    {@const state = server.enabledInT2T ? (status?.state ?? 'connecting') : 'off'}
    <div class="border-b border-white/5 bg-white/[0.03] last:border-b-0" data-testid="mcp-row" data-server={server.name} data-state={state}>
      <div class="flex items-center gap-4 px-5 py-3">
        <input
          type="checkbox"
          aria-label="Offer {server.name} to the agent"
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
        {#if server.enabledInT2T}
          <span class="flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs {badge[state]}" data-testid="mcp-state">
            {#if state === 'connecting'}<Mark spinning class="h-3 w-3" />{/if}
            {state === 'connected' ? `${status?.tools.length ?? 0} tools` : state}
          </span>
          {#if state === 'connected'}
            <button type="button" class="text-xs text-white/60 hover:text-white" onclick={() => (open[server.name] = !open[server.name])}>{open[server.name] ? 'Hide tools' : 'Tools'}</button>
          {/if}
          {#if state === 'disconnected'}
            <button type="button" disabled={busy[server.name]} class="rounded-md border border-white/10 px-2.5 py-1 text-xs hover:bg-white/10" onclick={() => act('connect', server.name)}>Reconnect</button>
          {:else}
            <button type="button" disabled={busy[server.name]} class="rounded-md border border-white/10 px-2.5 py-1 text-xs hover:bg-white/10" onclick={() => act('refresh', server.name)}>Refresh</button>
            <button type="button" disabled={busy[server.name]} class="rounded-md px-2.5 py-1 text-xs text-white/50 hover:bg-white/10 hover:text-white" onclick={() => act('disconnect', server.name)}>Disconnect</button>
          {/if}
        {/if}
      </div>
      {#if server.enabledInT2T && state === 'error' && status?.error}
        <p class="px-5 pb-3 pl-13 font-mono text-xs text-red-300/80" data-testid="mcp-error">{status.error}</p>
      {/if}
      {#if open[server.name] && status}
        <ul class="space-y-1 px-5 pb-3 pl-13" data-testid="mcp-tools">
          {#each status.tools as tool (tool.name)}
            <li class="text-xs"><span class="font-mono text-white/80">{tool.name}</span> <span class="text-white/40">{tool.description.slice(0, 140)}</span></li>
          {/each}
        </ul>
      {/if}
    </div>
  {:else}
    <div class="p-5 text-sm text-white/50">No MCP servers found.</div>
  {/each}
</div>
