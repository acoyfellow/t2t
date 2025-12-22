<script lang="ts">
  import { onMount } from "svelte";
  import {
    Plus,
    X,
    BarChart3,
    Server,
    Activity,
    Zap,
    Mic,
    RefreshCw,
    ChevronDown,
    ChevronUp,
  } from "@lucide/svelte";

  type MCPServer = {
    id: string;
    name: string;
    transport: "stdio" | "http" | "sse";
    command?: string;
    args?: string[];
    url?: string;
    enabled?: boolean;
    status?: "active" | "loading" | "error";
    statusMessage?: string;
    toolsCount?: number;
    promptsCount?: number;
    resourcesCount?: number;
    expanded?: boolean;
    tools?: Array<{ name: string; description?: string }>;
  };

  type ActiveTab = "analytics" | "servers";

  let activeTab = $state<ActiveTab>("analytics");
  let loading = $state(true);
  let servers = $state<MCPServer[]>([]);
  let showAddDialog = $state(false);
  let editingId: string | null = $state(null);
  let deleteConfirmId: string | null = $state(null);

  // Analytics state
  let totalWords = $state(0);
  let lifetimeWpm = $state(0);
  let sessionAvgWpm = $state(0);
  let sessions = $state(0);
  let hoursActive = $state(0);
  let recent = $state<number[]>([]);

  // Form state
  let formName = $state("");
  let formTransport = $state<"stdio" | "http" | "sse">("stdio");
  let formCommand = $state("");
  let formArgs = $state("");
  let formUrl = $state("");

  const HOUR_MS = 3600 * 1000;

  function buildLast48Hours(hourly: Array<[number, number]>): number[] {
    const nowHour = Math.floor(Date.now() / HOUR_MS);
    const out = Array.from({ length: 48 }, () => 0);
    for (const [h, w] of hourly) {
      const offset = h - nowHour;
      if (offset < -47 || offset > 0) continue;
      out[47 + offset] = w;
    }
    return out;
  }

  async function loadAnalytics() {
    try {
      if (!window.__TAURI__?.store) return;

      const { load } = window.__TAURI__.store;
      const store = await load("stats.json", { autoSave: true });

      const totalWordsVal = ((await store.get("total_words")) ?? 0) as number;
      const totalSeconds = ((await store.get("total_seconds")) ?? 0) as number;
      const sessionCount = ((await store.get("session_count")) ?? 0) as number;
      const sessionWpmSum = ((await store.get("session_wpm_sum")) ??
        0) as number;
      const activityHourly = ((await store.get("activity_hourly")) ??
        []) as Array<[number, number]>;

      totalWords = totalWordsVal;
      sessions = sessionCount;
      hoursActive = totalSeconds / 3600;
      recent = buildLast48Hours(activityHourly);

      if (totalSeconds > 0) {
        lifetimeWpm = totalWordsVal / (totalSeconds / 60);
      }

      if (sessionCount > 0) {
        sessionAvgWpm = sessionWpmSum / sessionCount;
      }
    } catch (e) {
      console.error("Failed to load analytics:", e);
    }
  }

  async function loadServers() {
    try {
      if (!window.__TAURI__?.store) {
        console.error("Tauri store API not available");
        return;
      }

      const { load } = window.__TAURI__.store;
      const serversStore = await load("mcp-servers.json", { autoSave: true });

      const serversData = ((await serversStore.get("servers")) ??
        []) as MCPServer[];

      servers = serversData.map((s) => ({
        ...s,
        enabled: s.enabled ?? true,
        status: s.status ?? "active",
        tools: s.tools,
        toolsCount: s.toolsCount ?? s.tools?.length,
        promptsCount: s.promptsCount,
        resourcesCount: s.resourcesCount,
      }));
    } catch (e) {
      console.error("Failed to load MCP data:", e);
    }
  }

  async function loadData() {
    loading = true;
    await Promise.all([loadAnalytics(), loadServers()]);
    loading = false;
  }

  async function saveServers() {
    if (!window.__TAURI__?.store) return;
    const { load } = window.__TAURI__.store;
    const store = await load("mcp-servers.json", { autoSave: true });
    await store.set("servers", servers);
    await store.save();
  }

  function resetForm() {
    formName = "";
    formTransport = "stdio";
    formCommand = "";
    formArgs = "";
    formUrl = "";
    editingId = null;
    showAddDialog = false;
  }

  function startAdd() {
    resetForm();
    showAddDialog = true;
  }

  function startEdit(server: MCPServer) {
    editingId = server.id;
    formName = server.name;
    formTransport = server.transport;
    formCommand = server.command ?? "";
    formArgs = server.args?.join(" ") ?? "";
    formUrl = server.url ?? "";
    showAddDialog = true;
  }

  async function handleSave() {
    if (!formName.trim()) return;

    const server: MCPServer = {
      id: editingId ?? crypto.randomUUID(),
      name: formName.trim(),
      transport: formTransport,
      enabled: true,
      status: "loading",
      statusMessage: "Testing connection...",
    };

    if (formTransport === "stdio") {
      if (!formCommand.trim()) return;
      server.command = formCommand.trim();
      server.args = formArgs.trim() ? formArgs.trim().split(/\s+/) : [];
    } else {
      if (!formUrl.trim()) return;
      server.url = formUrl.trim();
    }

    if (editingId) {
      const idx = servers.findIndex((s) => s.id === editingId);
      if (idx >= 0) servers[idx] = server;
    } else {
      servers = [...servers, server];
    }

    saveServers();
    resetForm();

    // Automatically test connection and fetch tools for new servers
    if (server.enabled) {
      await fetchTools(server);
      saveServers(); // Save again after fetching tools
    }
  }

  function handleDelete(id: string) {
    deleteConfirmId = id;
  }

  function confirmDelete() {
    if (deleteConfirmId) {
      servers = servers.filter((s) => s.id !== deleteConfirmId);
      saveServers();
      deleteConfirmId = null;
    }
  }

  function cancelDelete() {
    deleteConfirmId = null;
  }

  function handleToggle(id: string) {
    const idx = servers.findIndex((s) => s.id === id);
    if (idx >= 0) {
      servers[idx].enabled = !servers[idx].enabled;
      saveServers();
    }
  }

  function getInitials(name: string) {
    return name.charAt(0).toUpperCase();
  }

  async function fetchTools(server: MCPServer) {
    const idx = servers.findIndex((s) => s.id === server.id);
    if (idx < 0) return;

    servers[idx].status = "loading";
    servers[idx].statusMessage = "Connecting...";

    try {
      const response = await fetch(
        import.meta.env.DEV
          ? "http://localhost:5173/api/mcp-tools"
          : "https://t2t.now/api/mcp-tools",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            server: {
              name: server.name,
              transport: server.transport,
              command: server.command,
              args: server.args,
              url: server.url,
            },
          }),
        }
      );

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();
      if (data.error) {
        throw new Error(data.error);
      }

      servers[idx].tools = data.tools || [];
      servers[idx].toolsCount = data.tools?.length || 0;
      servers[idx].promptsCount = data.promptsCount || 0;
      servers[idx].resourcesCount = data.resourcesCount || 0;
      servers[idx].status = "active";
      servers[idx].statusMessage = undefined;
    } catch (error) {
      servers[idx].status = "error";
      servers[idx].statusMessage =
        error instanceof Error ? error.message : "Connection failed";
      servers[idx].tools = [];
      servers[idx].toolsCount = 0;
    }
  }

  function handleExpand(id: string) {
    const idx = servers.findIndex((s) => s.id === id);
    if (idx >= 0) {
      const server = servers[idx];
      servers[idx].expanded = !servers[idx].expanded;

      // Fetch tools when expanding if not already loaded
      if (servers[idx].expanded && !server.tools && server.enabled) {
        fetchTools(server);
      }
    }
  }

  function getStatusColor(status?: string) {
    switch (status) {
      case "active":
        return "bg-[oklch(0.62_0.21_146.43)]";
      case "loading":
        return "bg-[oklch(0.75_0.15_85.87)]";
      case "error":
        return "bg-[oklch(0.58_0.22_29.23)]";
      default:
        return "bg-[oklch(0.24_0.012_258.34)]";
    }
  }

  onMount(() => {
    loadData();
  });
</script>

<div
  class="h-screen flex flex-col bg-[oklch(0.11_0.012_258.34)] text-[oklch(0.88_0.01_258.34)] overflow-hidden"
>
  <!-- Header with Tabs -->
  <header
    class="border-b border-[oklch(0.28_0.012_258.34)] bg-[oklch(0.15_0.01_258.34)]/50 backdrop-blur-sm sticky top-0 z-10"
  >
    <div class="container mx-auto max-w-6xl px-6">
      <div class="flex items-center justify-between py-4">
        <div class="flex items-center gap-6">
          <div class="flex items-center gap-3">
            <img src="/logo.svg" alt="t2t" class="h-8 w-8 invert" />
            <h1 class="sr-only">t2t</h1>
          </div>

          <!-- Tab Navigation -->
          <nav class="flex gap-1">
            <button
              onclick={() => (activeTab = "analytics")}
              class="flex items-center gap-2 px-4 py-2 rounded-md transition-colors {activeTab ===
              'analytics'
                ? 'bg-[oklch(0.58_0.21_262.29)]/10 text-[oklch(0.58_0.21_262.29)] font-medium'
                : 'text-[oklch(0.58_0.008_258.34)] hover:text-[oklch(0.88_0.01_258.34)] hover:bg-[oklch(0.22_0.015_258.34)]/50'}"
            >
              <BarChart3 class="w-4 h-4" />
              Analytics
            </button>
            <button
              onclick={() => (activeTab = "servers")}
              class="flex items-center gap-2 px-4 py-2 rounded-md transition-colors {activeTab ===
              'servers'
                ? 'bg-[oklch(0.58_0.21_262.29)]/10 text-[oklch(0.58_0.21_262.29)] font-medium'
                : 'text-[oklch(0.58_0.008_258.34)] hover:text-[oklch(0.88_0.01_258.34)] hover:bg-[oklch(0.22_0.015_258.34)]/50'}"
            >
              <Server class="w-4 h-4" />
              MCP Servers
            </button>
          </nav>
        </div>

        <!-- Ready Status -->
        {#if activeTab === "analytics"}
          <div
            class="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[oklch(0.58_0.21_262.29)]/10 border border-[oklch(0.58_0.21_262.29)]/20"
          >
            <div
              class="w-2 h-2 rounded-full bg-[oklch(0.58_0.21_262.29)] animate-pulse"
            ></div>
            <span class="text-sm font-medium text-[oklch(0.58_0.21_262.29)]"
              >Ready</span
            >
          </div>
        {/if}
      </div>
    </div>
  </header>

  <!-- Main Content -->
  <div class="container mx-auto max-w-6xl flex-1 overflow-y-auto">
    {#if activeTab === "analytics"}
      <!-- Analytics Dashboard -->
      <div class="p-6 space-y-6">
        <p class="text-sm text-[oklch(0.58_0.008_258.34)]">
          Voice transcription analytics
        </p>

        {#if loading}
          <div class="flex items-center justify-center py-12">
            <div
              class="flex items-center gap-3 text-[oklch(0.58_0.008_258.34)]"
            >
              <div
                class="w-5 h-5 border-2 border-[oklch(0.58_0.21_262.29)] border-t-transparent rounded-full animate-spin"
              ></div>
              <span class="text-sm">Loading...</span>
            </div>
          </div>
        {:else}
          <!-- Main Stats Grid -->
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <!-- Total Words -->
            <div
              class="p-6 space-y-4 bg-[oklch(0.15_0.01_258.34)]/50 border border-[oklch(0.28_0.012_258.34)] rounded-lg"
            >
              <div
                class="w-12 h-12 rounded-xl bg-[oklch(0.58_0.21_262.29)]/10 flex items-center justify-center"
              >
                <Activity class="w-6 h-6 text-[oklch(0.58_0.21_262.29)]" />
              </div>
              <div>
                <p
                  class="text-xs font-medium text-[oklch(0.58_0.008_258.34)] uppercase tracking-wider mb-2"
                >
                  Total Words
                </p>
                <p
                  class="text-5xl font-bold text-[oklch(0.88_0.01_258.34)] tabular-nums"
                >
                  {totalWords.toLocaleString()}
                </p>
              </div>
            </div>

            <!-- Lifetime Average -->
            <div
              class="p-6 space-y-4 bg-[oklch(0.15_0.01_258.34)]/50 border border-[oklch(0.28_0.012_258.34)] rounded-lg"
            >
              <div
                class="w-12 h-12 rounded-xl bg-[oklch(0.58_0.21_262.29)]/10 flex items-center justify-center"
              >
                <Zap class="w-6 h-6 text-[oklch(0.58_0.21_262.29)]" />
              </div>
              <div>
                <p
                  class="text-xs font-medium text-[oklch(0.58_0.008_258.34)] uppercase tracking-wider mb-2"
                >
                  Lifetime Avg
                </p>
                <div class="flex items-baseline gap-2">
                  <p
                    class="text-5xl font-bold text-[oklch(0.88_0.01_258.34)] tabular-nums"
                  >
                    {lifetimeWpm.toFixed(1)}
                  </p>
                  <p class="text-lg text-[oklch(0.58_0.008_258.34)]">WPM</p>
                </div>
              </div>
            </div>

            <!-- Session Average -->
            <div
              class="p-6 space-y-4 bg-[oklch(0.15_0.01_258.34)]/50 border border-[oklch(0.28_0.012_258.34)] rounded-lg relative"
            >
              <div
                class="absolute top-4 right-4 px-2.5 py-1 rounded-md bg-[oklch(0.58_0.21_262.29)]/10 border border-[oklch(0.58_0.21_262.29)]/20"
              >
                <span class="text-xs font-medium text-[oklch(0.58_0.21_262.29)]"
                  >Active</span
                >
              </div>
              <div
                class="w-12 h-12 rounded-xl bg-[oklch(0.58_0.21_262.29)]/10 flex items-center justify-center"
              >
                <Mic class="w-6 h-6 text-[oklch(0.58_0.21_262.29)]" />
              </div>
              <div>
                <p
                  class="text-xs font-medium text-[oklch(0.58_0.008_258.34)] uppercase tracking-wider mb-2"
                >
                  Session Avg
                </p>
                <div class="flex items-baseline gap-2">
                  <p
                    class="text-5xl font-bold text-[oklch(0.88_0.01_258.34)] tabular-nums"
                  >
                    {sessionAvgWpm.toFixed(1)}
                  </p>
                  <p class="text-lg text-[oklch(0.58_0.008_258.34)]">WPM</p>
                </div>
              </div>
            </div>
          </div>

          <!-- Secondary Stats -->
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div
              class="p-6 bg-[oklch(0.15_0.01_258.34)]/50 border border-[oklch(0.28_0.012_258.34)] rounded-lg"
            >
              <p
                class="text-xs font-medium text-[oklch(0.58_0.008_258.34)] uppercase tracking-wider mb-2"
              >
                Sessions
              </p>
              <p
                class="text-4xl font-bold text-[oklch(0.88_0.01_258.34)] tabular-nums"
              >
                {sessions}
              </p>
            </div>

            <div
              class="p-6 bg-[oklch(0.15_0.01_258.34)]/50 border border-[oklch(0.28_0.012_258.34)] rounded-lg"
            >
              <p
                class="text-xs font-medium text-[oklch(0.58_0.008_258.34)] uppercase tracking-wider mb-2"
              >
                Hours Active
              </p>
              <p
                class="text-4xl font-bold text-[oklch(0.88_0.01_258.34)] tabular-nums"
              >
                {hoursActive.toFixed(1)}h
              </p>
            </div>
          </div>

          <!-- Recent Activity Chart -->
          <div
            class="p-6 bg-[oklch(0.15_0.01_258.34)]/50 border border-[oklch(0.28_0.012_258.34)] rounded-lg"
          >
            <p
              class="text-xs font-medium text-[oklch(0.58_0.008_258.34)] uppercase tracking-wider mb-6"
            >
              Recent Activity
            </p>
            <div class="flex items-end justify-between gap-1 h-48">
              {#each recent as value, index}
                {@const maxValue = Math.max(...recent)}
                {@const height = maxValue > 0 ? (value / maxValue) * 100 : 0}
                <div
                  class="flex-1 bg-[oklch(0.58_0.21_262.29)]/30 rounded-t hover:bg-[oklch(0.58_0.21_262.29)]/50 transition-colors cursor-pointer"
                  style="height: {height}%"
                  title="{value} words"
                ></div>
              {/each}
            </div>
            <div
              class="mt-2 border-t-2 border-dashed border-[oklch(0.58_0.21_262.29)]/20"
            ></div>
          </div>
        {/if}
      </div>
    {:else}
      <!-- MCP Servers -->
      <div class="p-6 space-y-6">
        <p class="text-sm text-[oklch(0.58_0.008_258.34)]">
          Manage your MCP servers
        </p>

        <div
          class="bg-[oklch(0.15_0.01_258.34)]/50 border border-[oklch(0.28_0.012_258.34)] rounded-lg overflow-hidden"
        >
          <div class="px-6 py-4 border-b border-[oklch(0.28_0.012_258.34)]">
            <h2 class="text-lg font-medium text-[oklch(0.85_0.01_258.34)]">
              Installed MCP Servers
            </h2>
          </div>

          {#if loading}
            <div class="px-6 py-8 flex items-center justify-center">
              <div
                class="flex items-center gap-3 text-[oklch(0.58_0.008_258.34)]"
              >
                <div
                  class="w-5 h-5 border-2 border-[oklch(0.58_0.21_262.29)] border-t-transparent rounded-full animate-spin"
                ></div>
                <span class="text-sm">Loading servers...</span>
              </div>
            </div>
          {:else if servers.length === 0}
            <div class="px-6 py-12 text-center">
              <p class="text-[oklch(0.58_0.008_258.34)] text-sm">
                No servers installed yet
              </p>
            </div>
          {:else}
            <div class="divide-y divide-[oklch(0.28_0.012_258.34)]">
              {#each servers as server (server.id)}
                <div class="group">
                  <div class="px-6 py-4 flex items-center gap-4">
                    <!-- Avatar with status indicator -->
                    <div class="relative">
                      <div
                        class="w-12 h-12 rounded-full bg-[oklch(0.22_0.015_258.34)] flex items-center justify-center text-[oklch(0.88_0.01_258.34)] font-medium"
                      >
                        {getInitials(server.name)}
                      </div>
                      <div
                        class="absolute bottom-0 right-0 w-3 h-3 rounded-full border-2 border-[oklch(0.15_0.01_258.34)] {getStatusColor(
                          server.status
                        )}"
                      ></div>
                    </div>

                    <!-- Server info -->
                    <div class="flex-1 min-w-0">
                      <div class="flex items-center gap-2 mb-1">
                        <h3
                          class="text-base font-medium text-[oklch(0.85_0.01_258.34)]"
                        >
                          {server.name}
                        </h3>
                      </div>

                      <div
                        onclick={() => handleExpand(server.id)}
                        class="flex items-center gap-2 text-sm text-[oklch(0.58_0.008_258.34)] cursor-pointer hover:text-[oklch(0.88_0.01_258.34)]"
                      >
                        {#if server.status === "loading"}
                          <div class="flex items-center gap-2">
                            <div
                              class="w-3 h-3 border-2 border-[oklch(0.75_0.15_85.87)] border-t-transparent rounded-full animate-spin"
                            ></div>
                            <span>Loading tools</span>
                          </div>
                        {:else if server.status === "error"}
                          <div class="flex items-center gap-2">
                            <span class="text-[oklch(0.98_0.002_282.32)]"
                              >{server.statusMessage || "Error"}</span
                            >
                          </div>
                        {:else if server.toolsCount !== undefined || server.promptsCount !== undefined || server.resourcesCount !== undefined}
                          <div class="flex items-center gap-1.5">
                            {#if server.expanded}
                              <ChevronUp class="w-4 h-4" />
                            {:else}
                              <ChevronDown class="w-4 h-4" />
                            {/if}
                            {#if server.toolsCount !== undefined}
                              <span>{server.toolsCount} tools</span>
                            {/if}
                            {#if server.promptsCount !== undefined && server.promptsCount > 0}
                              {#if server.toolsCount !== undefined}
                                <span>,</span>
                              {/if}
                              <span>{server.promptsCount} prompts</span>
                            {/if}
                            {#if server.resourcesCount !== undefined && server.resourcesCount > 0}
                              {#if server.toolsCount !== undefined || server.promptsCount !== undefined}
                                <span>,</span>
                              {/if}
                              <span>{server.resourcesCount} resources</span>
                            {/if}
                          </div>
                        {:else}
                          <span>{server.transport}</span>
                        {/if}
                      </div>

                      <!-- Expanded tools list -->
                      {#if server.expanded && server.tools}
                        <div
                          class="mt-3 pt-3 border-t border-[oklch(0.28_0.012_258.34)]"
                        >
                          <div class="space-y-2">
                            {#each server.tools as tool}
                              <div
                                class="px-3 py-2 bg-[oklch(0.22_0.015_258.34)]/50 rounded text-sm"
                              >
                                <div
                                  class="font-medium text-[oklch(0.85_0.01_258.34)]"
                                >
                                  {tool.name}
                                </div>
                                {#if tool.description}
                                  <div
                                    class="text-xs text-[oklch(0.58_0.008_258.34)] mt-1"
                                  >
                                    {tool.description}
                                  </div>
                                {/if}
                              </div>
                            {/each}
                          </div>
                        </div>
                      {/if}
                    </div>

                    <!-- Toggle switch -->
                    <label
                      class="relative inline-flex h-[1.15rem] w-8 shrink-0 items-center rounded-full border border-transparent transition-all cursor-pointer {server.enabled
                        ? 'bg-[oklch(0.58_0.21_262.29)]'
                        : 'bg-[oklch(0.28_0.012_258.34)]'}"
                    >
                      <input
                        type="checkbox"
                        checked={server.enabled}
                        onchange={() => handleToggle(server.id)}
                        class="sr-only"
                      />
                      <span
                        class="pointer-events-none block size-4 rounded-full ring-0 transition-transform bg-[oklch(0.11_0.012_258.34)] {server.enabled
                          ? 'translate-x-[calc(100%-2px)]'
                          : 'translate-x-0'}"
                      ></span>
                    </label>

                    <!-- Refresh/Test button -->
                    {#if server.enabled && server.status !== "loading"}
                      <button
                        onclick={() => fetchTools(server)}
                        class="opacity-0 group-hover:opacity-100 transition-opacity h-8 w-8 flex items-center justify-center text-[oklch(0.58_0.008_258.34)] hover:text-[oklch(0.88_0.01_258.34)] rounded"
                        title="Refresh tools"
                      >
                        <RefreshCw class="w-4 h-4" />
                      </button>
                    {/if}

                    <!-- Delete button (shown on hover) -->
                    <button
                      onclick={() => handleDelete(server.id)}
                      class="opacity-0 group-hover:opacity-100 transition-opacity h-8 w-8 flex items-center justify-center text-[oklch(0.58_0.008_258.34)] hover:text-[oklch(0.58_0.22_29.23)] rounded"
                    >
                      <X class="w-4 h-4" />
                    </button>
                  </div>
                </div>
              {/each}
            </div>
          {/if}

          <!-- Add New Server Button -->
          <button
            onclick={startAdd}
            class="w-full px-6 py-4 flex items-center gap-4 hover:bg-[oklch(0.22_0.015_258.34)]/50 transition-colors border-t border-[oklch(0.28_0.012_258.34)]"
          >
            <div
              class="w-12 h-12 rounded-full bg-[oklch(0.22_0.015_258.34)] flex items-center justify-center"
            >
              <Plus class="w-5 h-5 text-[oklch(0.88_0.01_258.34)]" />
            </div>
            <div class="flex-1 text-left">
              <div class="text-base font-medium text-[oklch(0.85_0.01_258.34)]">
                New MCP Server
              </div>
              <div class="text-sm text-[oklch(0.58_0.008_258.34)]">
                Add a Custom MCP Server
              </div>
            </div>
          </button>
        </div>
      </div>
    {/if}
  </div>

  <!-- Add/Edit Dialog -->
  {#if showAddDialog}
    <div
      class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
      onclick={(e) => {
        if (e.target === e.currentTarget) resetForm();
      }}
    >
      <div
        class="bg-[oklch(0.15_0.01_258.34)] border border-[oklch(0.28_0.012_258.34)] rounded-lg shadow-lg w-full max-w-md mx-4"
        onclick={(e) => e.stopPropagation()}
      >
        <div class="px-6 py-4 border-b border-[oklch(0.28_0.012_258.34)]">
          <h3 class="text-lg font-semibold text-[oklch(0.85_0.01_258.34)]">
            {editingId ? "Edit" : "Add"} MCP Server
          </h3>
          <p class="text-sm text-[oklch(0.58_0.008_258.34)] mt-1">
            Configure your MCP server connection
          </p>
        </div>

        <form
          onsubmit={(e) => {
            e.preventDefault();
            handleSave();
          }}
          class="p-6 space-y-4"
        >
          <div>
            <label
              for="form-name"
              class="block text-sm font-medium text-[oklch(0.85_0.01_258.34)] mb-2"
            >
              Server Name
            </label>
            <input
              id="form-name"
              type="text"
              bind:value={formName}
              placeholder="e.g., my-custom-server"
              required
              class="w-full px-3 py-2 rounded-md bg-[oklch(0.11_0.012_258.34)] border border-[oklch(0.28_0.012_258.34)] text-[oklch(0.88_0.01_258.34)] placeholder:text-[oklch(0.58_0.008_258.34)] focus:outline-none focus:ring-2 focus:ring-[oklch(0.52_0.19_262.29)]"
            />
          </div>

          <div>
            <label
              for="form-transport"
              class="block text-sm font-medium text-[oklch(0.85_0.01_258.34)] mb-2"
            >
              Transport
            </label>
            <select
              id="form-transport"
              bind:value={formTransport}
              class="w-full px-3 py-2 rounded-md bg-[oklch(0.11_0.012_258.34)] border border-[oklch(0.28_0.012_258.34)] text-[oklch(0.88_0.01_258.34)] focus:outline-none focus:ring-2 focus:ring-[oklch(0.52_0.19_262.29)]"
            >
              <option value="stdio">stdio</option>
              <option value="http">http</option>
              <option value="sse">sse</option>
            </select>
          </div>

          {#if formTransport === "stdio"}
            <div>
              <label
                for="form-command"
                class="block text-sm font-medium text-[oklch(0.85_0.01_258.34)] mb-2"
              >
                Command
              </label>
              <input
                id="form-command"
                type="text"
                bind:value={formCommand}
                placeholder="/usr/local/bin/mcp-server"
                required
                class="w-full px-3 py-2 rounded-md bg-[oklch(0.11_0.012_258.34)] border border-[oklch(0.28_0.012_258.34)] text-[oklch(0.88_0.01_258.34)] placeholder:text-[oklch(0.58_0.008_258.34)] focus:outline-none focus:ring-2 focus:ring-[oklch(0.52_0.19_262.29)] font-mono text-sm"
              />
            </div>
            <div>
              <label
                for="form-args"
                class="block text-sm font-medium text-[oklch(0.85_0.01_258.34)] mb-2"
              >
                Args (space-separated)
              </label>
              <input
                id="form-args"
                type="text"
                bind:value={formArgs}
                placeholder="--port 8080"
                class="w-full px-3 py-2 rounded-md bg-[oklch(0.11_0.012_258.34)] border border-[oklch(0.28_0.012_258.34)] text-[oklch(0.88_0.01_258.34)] placeholder:text-[oklch(0.58_0.008_258.34)] focus:outline-none focus:ring-2 focus:ring-[oklch(0.52_0.19_262.29)] font-mono text-sm"
              />
            </div>
          {:else}
            <div>
              <label
                for="form-url"
                class="block text-sm font-medium text-[oklch(0.85_0.01_258.34)] mb-2"
              >
                URL
              </label>
              <input
                id="form-url"
                type="text"
                bind:value={formUrl}
                placeholder="https://mcp.example.com"
                required
                class="w-full px-3 py-2 rounded-md bg-[oklch(0.11_0.012_258.34)] border border-[oklch(0.28_0.012_258.34)] text-[oklch(0.88_0.01_258.34)] placeholder:text-[oklch(0.58_0.008_258.34)] focus:outline-none focus:ring-2 focus:ring-[oklch(0.52_0.19_262.29)] font-mono text-sm"
              />
            </div>
          {/if}

          <div class="flex gap-3 pt-4">
            <button
              type="button"
              onclick={resetForm}
              class="flex-1 px-4 py-2 rounded-md border border-[oklch(0.28_0.012_258.34)] bg-[oklch(0.11_0.012_258.34)] text-[oklch(0.88_0.01_258.34)] hover:bg-[oklch(0.22_0.015_258.34)] transition-colors font-medium"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!formName.trim()}
              class="flex-1 px-4 py-2 rounded-md bg-[oklch(0.58_0.21_262.29)] text-[oklch(0.98_0.002_282.32)] hover:bg-[oklch(0.52_0.19_262.29)] transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {editingId ? "Save" : "Add"} Server
            </button>
          </div>
        </form>
      </div>
    </div>
  {/if}

  <!-- Delete Confirmation Dialog -->
  {#if deleteConfirmId}
    {@const serverToDelete = servers.find((s) => s.id === deleteConfirmId)}
    <div
      class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
      onclick={cancelDelete}
    >
      <div
        class="bg-[oklch(0.15_0.01_258.34)] border border-[oklch(0.28_0.012_258.34)] rounded-lg shadow-lg w-full max-w-md mx-4"
        onclick={(e) => e.stopPropagation()}
      >
        <div class="px-6 py-4 border-b border-[oklch(0.28_0.012_258.34)]">
          <h3 class="text-lg font-semibold text-[oklch(0.85_0.01_258.34)]">
            Delete Server
          </h3>
          <p class="text-sm text-[oklch(0.58_0.008_258.34)] mt-1">
            Are you sure you want to delete "{serverToDelete?.name}"? This
            action cannot be undone.
          </p>
        </div>

        <div class="flex gap-3 p-6">
          <button
            type="button"
            onclick={cancelDelete}
            class="flex-1 px-4 py-2 rounded-md border border-[oklch(0.28_0.012_258.34)] bg-[oklch(0.11_0.012_258.34)] text-[oklch(0.88_0.01_258.34)] hover:bg-[oklch(0.22_0.015_258.34)] transition-colors font-medium"
          >
            Cancel
          </button>
          <button
            type="button"
            onclick={confirmDelete}
            class="flex-1 px-4 py-2 rounded-md bg-[oklch(0.58_0.22_29.23)] text-[oklch(0.98_0.002_282.32)] hover:bg-[oklch(0.52_0.19_262.29)] transition-colors font-medium"
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  @keyframes pulse {
    0%,
    100% {
      opacity: 1;
    }
    50% {
      opacity: 0.5;
    }
  }
  .animate-spin {
    animation: spin 1s linear infinite;
  }
  .animate-pulse {
    animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
  }
</style>
