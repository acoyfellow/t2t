<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
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
    ChevronsUpDown,
    Check,
  } from "@lucide/svelte";
  import { tick } from "svelte";
  import * as Command from "$lib/components/ui/command/index.js";
  import * as Popover from "$lib/components/ui/popover/index.js";
  import { Button } from "$lib/components/ui/button/index.js";
  import { cn } from "$lib/utils.js";
  import { resolvedTheme, saveTheme as saveThemeStore } from "../../lib/theme";

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
    prompts?: Array<{ name: string; description?: string; arguments?: any[] }>;
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

  // Model selection state
  let models = $state<Array<{ id: string; name?: string }>>([]);
  let selectedModel = $state("openai/gpt-5-nano");
  let modelsLoading = $state(false);
  let modelComboboxOpen = $state(false);
  let modelTriggerRef = $state<HTMLButtonElement>(null!);

  const selectedModelLabel = $derived(
    models.find((m) => m.id === selectedModel)?.name || selectedModel
  );

  function closeAndFocusTrigger() {
    modelComboboxOpen = false;
    tick().then(() => {
      modelTriggerRef?.focus();
    });
  }

  // OpenRouter key state
  let openrouterKey = $state("");
  let keyLoading = $state(false);

  // Theme state
  let isDark = $state(false);

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
        // Reset any "loading" status on load - user must manually refresh
        status: s.status === "loading" ? "active" : (s.status ?? "active"),
        // Load cached tools/prompts/resources from store
        tools: s.tools || [],
        prompts: s.prompts || [],
        toolsCount: s.toolsCount ?? s.tools?.length ?? 0,
        promptsCount: s.promptsCount ?? s.prompts?.length ?? 0,
        resourcesCount: s.resourcesCount ?? 0,
        // Start collapsed on page load
        expanded: false,
      }));
    } catch (e) {
      console.error("Failed to load MCP data:", e);
    }
  }

  async function loadModel() {
    try {
      if (!window.__TAURI__?.store) return;
      const { load } = window.__TAURI__.store;
      const store = await load("model", { autoSave: true });
      const saved = (await store.get("model")) as string | undefined;
      if (saved && saved.length > 0) {
        selectedModel = saved;
      }
    } catch (e) {
      console.error("Failed to load model:", e);
    }
  }

  async function loadOpenRouterKey() {
    try {
      keyLoading = true;
      const key = (await invoke("get_openrouter_key")) as string | null;
      if (key) {
        openrouterKey = key;
      }
    } catch (e) {
      console.error("Failed to load OpenRouter key:", e);
    } finally {
      keyLoading = false;
    }
  }

  async function saveOpenRouterKey() {
    try {
      if (!openrouterKey || openrouterKey.length === 0) {
        console.error("OpenRouter key cannot be empty");
        return;
      }
      await invoke("set_openrouter_key", { key: openrouterKey });
      // Refresh models after saving key
      await fetchModels();
    } catch (e) {
      console.error("Failed to save OpenRouter key:", e);
    }
  }

  async function saveModel() {
    try {
      if (!window.__TAURI__?.store) return;
      const { load } = window.__TAURI__.store;
      const store = await load("model", { autoSave: true });
      await store.set("model", selectedModel);
      await store.save();
    } catch (e) {
      console.error("Failed to save model:", e);
    }
  }

  async function fetchModels() {
    try {
      modelsLoading = true;
      // Get OpenRouter key (from store or env var)
      const key = (await invoke("get_openrouter_key")) as string | null;

      if (!key || key.length === 0) {
        console.error("No OpenRouter key found. Please set it in Settings.");
        modelsLoading = false;
        return;
      }

      const result = (await invoke("fetch_openrouter_models", {
        openrouterKey: key,
      })) as { data?: Array<{ id: string; name?: string }> };

      console.log("OpenRouter models response:", result);

      if (result && result.data && Array.isArray(result.data)) {
        // Sort models by name/id for better UX
        models = result.data.sort((a, b) => {
          const aName = a.name || a.id;
          const bName = b.name || b.id;
          return aName.localeCompare(bName);
        });
        console.log(`Loaded ${models.length} models`);
      } else {
        console.warn("Unexpected response structure:", result);
        models = [];
      }
    } catch (e) {
      console.error("Failed to fetch models:", e);
      models = [];
    } finally {
      modelsLoading = false;
    }
  }

  async function loadData() {
    loading = true;
    await Promise.all([
      loadAnalytics(),
      loadServers(),
      loadModel(),
      loadOpenRouterKey(),
    ]);
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

    // Don't auto-fetch on save - user must manually click refresh
    // Reset status to active so it doesn't show as loading
    if (editingId) {
      const idx = servers.findIndex((s) => s.id === editingId);
      if (idx >= 0) {
        servers[idx].status = "active";
        servers[idx].statusMessage = undefined;
      }
    } else {
      const idx = servers.findIndex((s) => s.id === server.id);
      if (idx >= 0) {
        servers[idx].status = "active";
        servers[idx].statusMessage = undefined;
      }
    }
    saveServers();
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
      const data = (await invoke("fetch_mcp_tools", {
        server: {
          id: server.id,
          name: server.name,
          transport: server.transport,
          command: server.command,
          args: server.args,
          url: server.url,
          enabled: server.enabled,
        },
      })) as {
        success: boolean;
        tools?: Array<{
          name: string;
          description: string;
          input_schema?: any;
        }>;
        prompts?: Array<{
          name: string;
          description: string;
          arguments?: any[];
        }>;
        tools_count?: number;
        prompts_count?: number;
        resources_count?: number;
        error?: string;
      };

      if (!data.success || data.error) {
        throw new Error(data.error || "Connection failed");
      }

      servers[idx].tools = data.tools || [];
      servers[idx].prompts = data.prompts || [];
      servers[idx].toolsCount = data.tools_count || 0;
      servers[idx].promptsCount = data.prompts_count || 0;
      servers[idx].resourcesCount = data.resources_count || 0;
      servers[idx].status = "active";
      servers[idx].statusMessage = undefined;

      // Update cache in store
      await saveServers();
    } catch (error) {
      servers[idx].status = "error";
      servers[idx].statusMessage =
        error instanceof Error ? error.message : "Connection failed";
      servers[idx].tools = [];
      servers[idx].toolsCount = 0;
      servers[idx].promptsCount = 0;
      servers[idx].resourcesCount = 0;

      // Still save to cache (with error state)
      await saveServers();
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
        return "bg-green-500";
      case "loading":
        return "bg-yellow-500";
      case "error":
        return "bg-destructive";
      default:
        return "bg-muted";
    }
  }

  onMount(() => {
    // Subscribe to resolved theme
    const unsubscribe = resolvedTheme.subscribe((t) => {
      isDark = t === "dark";
    });

    // Load data and models asynchronously
    loadData().then(() => {
      // Auto-fetch models if we have an OpenRouter key
      invoke("get_openrouter_key")
        .then((key) => {
          if (key && typeof key === "string" && key.length > 0) {
            openrouterKey = key;
            fetchModels();
          }
        })
        .catch(() => {
          // Ignore - models can be fetched manually
        });
    });

    return unsubscribe;
  });
</script>

<div
  class="h-screen flex flex-col bg-background text-foreground overflow-hidden"
>
  <!-- Header with Tabs -->
  <header
    class="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-10"
  >
    <div class="container mx-auto max-w-6xl px-6">
      <div class="flex items-center justify-between py-4">
        <div class="flex items-center gap-6">
          <div class="flex items-center gap-3">
            <img src="/logo.svg" alt="t2t" class="h-8 w-8 dark:invert" />
            <h1 class="sr-only">t2t</h1>
          </div>

          <!-- Tab Navigation -->
          <nav class="flex gap-1">
            <button
              onclick={() => (activeTab = "analytics")}
              class="flex items-center gap-2 px-4 py-2 rounded-md transition-colors {activeTab ===
              'analytics'
                ? 'bg-primary/10 text-primary font-medium'
                : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'}"
            >
              <BarChart3 class="w-4 h-4" />
              Analytics
            </button>
            <button
              onclick={() => (activeTab = "servers")}
              class="flex items-center gap-2 px-4 py-2 rounded-md transition-colors {activeTab ===
              'servers'
                ? 'bg-primary/10 text-primary font-medium'
                : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'}"
            >
              <Server class="w-4 h-4" />
              Settings
            </button>
          </nav>
        </div>

        <!-- Ready Status -->
        {#if activeTab === "analytics"}
          <div
            class="flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20"
          >
            <div class="w-2 h-2 rounded-full bg-primary animate-pulse"></div>
            <span class="text-sm font-medium text-primary">Ready</span>
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
        <p class="text-sm text-muted-foreground">
          Voice transcription analytics
        </p>

        {#if loading}
          <div class="flex items-center justify-center py-12">
            <div class="flex items-center gap-3 text-muted-foreground">
              <div
                class="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin"
              ></div>
              <span class="text-sm">Loading...</span>
            </div>
          </div>
        {:else}
          <!-- Main Stats Grid -->
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <!-- Total Words -->
            <div
              class="p-6 space-y-4 bg-card/50 border border-border rounded-lg"
            >
              <div
                class="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center"
              >
                <Activity class="w-6 h-6 text-primary" />
              </div>
              <div>
                <p
                  class="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2"
                >
                  Total Words
                </p>
                <p class="text-5xl font-bold text-foreground tabular-nums">
                  {totalWords.toLocaleString()}
                </p>
              </div>
            </div>

            <!-- Lifetime Average -->
            <div
              class="p-6 space-y-4 bg-card/50 border border-border rounded-lg"
            >
              <div
                class="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center"
              >
                <Zap class="w-6 h-6 text-primary" />
              </div>
              <div>
                <p
                  class="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2"
                >
                  Lifetime Avg
                </p>
                <div class="flex items-baseline gap-2">
                  <p class="text-5xl font-bold text-foreground tabular-nums">
                    {lifetimeWpm.toFixed(1)}
                  </p>
                  <p class="text-lg text-muted-foreground">WPM</p>
                </div>
              </div>
            </div>

            <!-- Session Average -->
            <div
              class="p-6 space-y-4 bg-card/50 border border-border rounded-lg relative"
            >
              <div
                class="absolute top-4 right-4 px-2.5 py-1 rounded-md bg-primary/10 border border-primary/20"
              >
                <span class="text-xs font-medium text-primary">Active</span>
              </div>
              <div
                class="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center"
              >
                <Mic class="w-6 h-6 text-primary" />
              </div>
              <div>
                <p
                  class="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2"
                >
                  Session Avg
                </p>
                <div class="flex items-baseline gap-2">
                  <p class="text-5xl font-bold text-foreground tabular-nums">
                    {sessionAvgWpm.toFixed(1)}
                  </p>
                  <p class="text-lg text-muted-foreground">WPM</p>
                </div>
              </div>
            </div>
          </div>

          <!-- Secondary Stats -->
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="p-6 bg-card/50 border border-border rounded-lg">
              <p
                class="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2"
              >
                Sessions
              </p>
              <p class="text-4xl font-bold text-foreground tabular-nums">
                {sessions}
              </p>
            </div>

            <div class="p-6 bg-card/50 border border-border rounded-lg">
              <p
                class="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2"
              >
                Hours Active
              </p>
              <p class="text-4xl font-bold text-foreground tabular-nums">
                {hoursActive.toFixed(1)}h
              </p>
            </div>
          </div>

          <!-- Recent Activity Chart -->
          <div class="p-6 bg-card/50 border border-border rounded-lg">
            <p
              class="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-6"
            >
              Recent Activity
            </p>
            <div class="flex items-end justify-between gap-1 h-48">
              {#each recent as value, index}
                {@const maxValue = Math.max(...recent)}
                {@const height = maxValue > 0 ? (value / maxValue) * 100 : 0}
                <div
                  class="flex-1 bg-primary/30 rounded-t hover:bg-primary/50 transition-colors cursor-pointer"
                  style="height: {height}%"
                  title="{value} words"
                ></div>
              {/each}
            </div>
            <div class="mt-2 border-t-2 border-dashed border-primary/20"></div>
          </div>
        {/if}
      </div>
    {:else}
      <!-- Settings -->
      <div class="p-6 space-y-6">
        <!-- Theme Selection -->
        <div class="flex items-center justify-between py-2">
          <label class="text-sm font-medium text-foreground">Theme</label>
          <label
            class="relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border border-transparent transition-all cursor-pointer {isDark
              ? 'bg-primary'
              : 'bg-muted'}"
          >
            <input
              type="checkbox"
              checked={isDark}
              onchange={(e) => {
                const newTheme = (e.currentTarget as HTMLInputElement).checked
                  ? "dark"
                  : "light";
                saveThemeStore(newTheme);
              }}
              class="sr-only"
            />
            <span
              class="pointer-events-none block h-4 w-4 rounded-full ring-0 transition-transform bg-background {isDark
                ? 'translate-x-[calc(100%+2px)]'
                : 'translate-x-0.5'}"
            ></span>
          </label>
        </div>

        <!-- OpenRouter API Key -->
        <div class="p-4 bg-card/50 border border-border rounded-lg">
          <label
            for="openrouter-key"
            class="block text-sm font-medium text-foreground mb-2"
            >OpenRouter API Key</label
          >
          <div class="flex gap-2">
            <input
              id="openrouter-key"
              type="password"
              bind:value={openrouterKey}
              placeholder={keyLoading ? "Loading..." : "sk-or-v1-..."}
              class="flex-1 px-3 py-2 rounded-md bg-background border border-border/50 text-foreground placeholder:text-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary font-mono text-sm"
            />
            <button
              onclick={saveOpenRouterKey}
              disabled={!openrouterKey || openrouterKey.length === 0}
              class="px-4 py-2 rounded-md bg-primary text-white hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              Save
            </button>
          </div>
          <p class="text-xs text-muted-foreground mt-2">
            Your API key is stored locally. Falls back to <code
              class="px-1 py-0.5 bg-muted rounded">OPENROUTER_API_KEY</code
            > env var if not set.
          </p>
        </div>

        <!-- Model Selection -->
        <div class="p-4 bg-card/50 border border-border rounded-lg">
          <div class="flex items-center justify-between mb-3">
            <label class="text-sm font-medium text-foreground">AI Model</label>
            <button
              onclick={fetchModels}
              disabled={modelsLoading || !openrouterKey}
              class="text-xs text-primary hover:text-primary disabled:opacity-50"
            >
              {modelsLoading ? "Loading..." : "Refresh Models"}
            </button>
          </div>

          <Popover.Root bind:open={modelComboboxOpen}>
            <Popover.Trigger bind:ref={modelTriggerRef}>
              {#snippet child({ props })}
                <Button
                  {...props}
                  variant="outline"
                  class="w-full justify-between bg-muted border-border/50 text-foreground hover:bg-muted/80"
                  role="combobox"
                  aria-expanded={modelComboboxOpen}
                >
                  {selectedModelLabel || "Select a model..."}
                  <ChevronsUpDown class="ms-2 size-4 shrink-0 opacity-50" />
                </Button>
              {/snippet}
            </Popover.Trigger>
            <Popover.Content class="w-full p-0" align="start">
              <Command.Root>
                <Command.Input placeholder="Search models..." class="h-9" />
                <Command.List>
                  <Command.Empty>No model found.</Command.Empty>
                  <Command.Group>
                    {#if models.length === 0}
                      <Command.Item
                        value={selectedModel}
                        onSelect={() => {
                          saveModel();
                          closeAndFocusTrigger();
                        }}
                      >
                        <Check class="me-2 size-4 opacity-100" />
                        {selectedModel}
                      </Command.Item>
                    {:else}
                      {#each models as model}
                        <Command.Item
                          value={model.name || model.id}
                          onSelect={() => {
                            selectedModel = model.id;
                            saveModel();
                            closeAndFocusTrigger();
                          }}
                        >
                          <Check
                            class={cn(
                              "me-2 size-4",
                              model.id === selectedModel
                                ? "opacity-100"
                                : "opacity-0"
                            )}
                          />
                          {model.name || model.id}
                        </Command.Item>
                      {/each}
                      <!-- Ensure selected model is always available even if not in fetched list -->
                      {#if models.findIndex((m) => m.id === selectedModel) === -1}
                        <Command.Item
                          value={selectedModel}
                          onSelect={() => {
                            saveModel();
                            closeAndFocusTrigger();
                          }}
                        >
                          <Check class="me-2 size-4 opacity-100" />
                          {selectedModel}
                        </Command.Item>
                      {/if}
                    {/if}
                  </Command.Group>
                </Command.List>
              </Command.Root>
            </Popover.Content>
          </Popover.Root>
          <p class="text-xs text-muted-foreground mt-2">
            Model used for agent mode. Defaults to <code
              class="px-1 py-0.5 bg-muted rounded">openai/gpt-5-nano</code
            >
            or
            <code class="px-1 py-0.5 bg-muted rounded">OPENROUTER_MODEL</code> env
            var.
          </p>
        </div>

        <p class="text-sm text-muted-foreground">Manage your MCP servers</p>

        <div class="bg-card/50 border border-border rounded-lg overflow-hidden">
          <div class="px-6 py-4 border-b border-border/30">
            <h2 class="text-lg font-medium text-foreground">
              Installed MCP Servers
            </h2>
          </div>

          {#if loading}
            <div class="px-6 py-8 flex items-center justify-center">
              <div class="flex items-center gap-3 text-muted-foreground">
                <div
                  class="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin"
                ></div>
                <span class="text-sm">Loading servers...</span>
              </div>
            </div>
          {:else if servers.length === 0}
            <div class="px-6 py-12 text-center">
              <p class="text-muted-foreground text-sm">
                No servers installed yet
              </p>
            </div>
          {:else}
            <div class="divide-y divide-border/30">
              {#each servers as server (server.id)}
                <div class="group">
                  <div class="px-6 py-4 flex items-center gap-4">
                    <!-- Avatar with status indicator -->
                    <div class="relative">
                      <div
                        class="w-12 h-12 rounded-full bg-muted flex items-center justify-center text-foreground font-medium"
                      >
                        {getInitials(server.name)}
                      </div>
                      <div
                        class="absolute bottom-0 right-0 w-3 h-3 rounded-full border-2 border-card {getStatusColor(
                          server.status
                        )}"
                      ></div>
                    </div>

                    <!-- Server info -->
                    <div class="flex-1 min-w-0">
                      <div class="flex items-center gap-2 mb-1">
                        <h3 class="text-base font-medium text-foreground">
                          {server.name}
                        </h3>
                      </div>

                      <div
                        onclick={() => handleExpand(server.id)}
                        class="flex items-center gap-2 text-sm text-muted-foreground cursor-pointer hover:text-foreground"
                      >
                        {#if server.status === "loading"}
                          <div class="flex items-center gap-2">
                            <div
                              class="w-3 h-3 border-2 border-yellow-500 border-t-transparent rounded-full animate-spin"
                            ></div>
                            <span>Loading tools</span>
                          </div>
                        {:else if server.status === "error"}
                          <div class="flex items-center gap-2">
                            <span class="text-primary-foreground"
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
                        <div class="mt-3 pt-3 border-t border-border/50">
                          <div class="space-y-2">
                            {#each server.tools as tool}
                              <div
                                class="px-3 py-2 bg-muted/50 rounded text-sm"
                              >
                                <div class="font-medium text-foreground">
                                  {tool.name}
                                </div>
                                {#if tool.description}
                                  <div
                                    class="text-xs text-muted-foreground mt-1"
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
                        ? 'bg-primary'
                        : 'bg-border'}"
                    >
                      <input
                        type="checkbox"
                        checked={server.enabled}
                        onchange={() => handleToggle(server.id)}
                        class="sr-only"
                      />
                      <span
                        class="pointer-events-none block size-4 rounded-full ring-0 transition-transform bg-background {server.enabled
                          ? 'translate-x-[calc(100%-2px)]'
                          : 'translate-x-0'}"
                      ></span>
                    </label>

                    <!-- Refresh/Test button -->
                    {#if server.enabled && server.status !== "loading"}
                      <button
                        onclick={() => fetchTools(server)}
                        class="h-8 w-8 flex items-center justify-center text-muted-foreground hover:text-foreground rounded transition-colors"
                        title="Refresh tools"
                      >
                        <RefreshCw class="w-4 h-4" />
                      </button>
                    {/if}

                    <!-- Delete button -->
                    <button
                      onclick={() => handleDelete(server.id)}
                      class="h-8 w-8 flex items-center justify-center text-muted-foreground hover:text-destructive rounded transition-colors"
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
            class="w-full px-6 py-4 flex items-center gap-4 hover:bg-muted/50 transition-colors border-t border-border/50"
          >
            <div
              class="w-12 h-12 rounded-full bg-muted flex items-center justify-center"
            >
              <Plus class="w-5 h-5 text-foreground" />
            </div>
            <div class="flex-1 text-left">
              <div class="text-base font-medium text-foreground">
                New MCP Server
              </div>
              <div class="text-sm text-muted-foreground">
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
        class="bg-card border border-border/50 rounded-lg shadow-lg w-full max-w-md mx-4"
        onclick={(e) => e.stopPropagation()}
      >
        <div class="px-6 py-4 border-b border-border/30">
          <h3 class="text-lg font-semibold text-foreground">
            {editingId ? "Edit" : "Add"} MCP Server
          </h3>
          <p class="text-sm text-muted-foreground mt-1">
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
              class="block text-sm font-medium text-foreground mb-2"
            >
              Server Name
            </label>
            <input
              id="form-name"
              type="text"
              bind:value={formName}
              placeholder="e.g., my-custom-server"
              required
              class="w-full px-3 py-2 rounded-md bg-background border border-border/50 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>

          <div>
            <label
              for="form-transport"
              class="block text-sm font-medium text-foreground mb-2"
            >
              Transport
            </label>
            <select
              id="form-transport"
              bind:value={formTransport}
              class="w-full px-3 py-2 rounded-md bg-background border border-border/50 text-foreground focus:outline-none focus:ring-2 focus:ring-primary"
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
                class="block text-sm font-medium text-foreground mb-2"
              >
                Command
              </label>
              <input
                id="form-command"
                type="text"
                bind:value={formCommand}
                placeholder="/usr/local/bin/mcp-server"
                required
                class="w-full px-3 py-2 rounded-md bg-background border border-border/50 text-foreground placeholder:text-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary font-mono text-sm"
              />
            </div>
            <div>
              <label
                for="form-args"
                class="block text-sm font-medium text-foreground mb-2"
              >
                Args (space-separated)
              </label>
              <input
                id="form-args"
                type="text"
                bind:value={formArgs}
                placeholder="--port 8080"
                class="w-full px-3 py-2 rounded-md bg-background border border-border/50 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary font-mono text-sm"
              />
            </div>
          {:else}
            <div>
              <label
                for="form-url"
                class="block text-sm font-medium text-foreground mb-2"
              >
                URL
              </label>
              <input
                id="form-url"
                type="text"
                bind:value={formUrl}
                placeholder="https://mcp.example.com"
                required
                class="w-full px-3 py-2 rounded-md bg-background border border-border/50 text-foreground placeholder:text-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary font-mono text-sm"
              />
            </div>
          {/if}

          <div class="flex gap-3 pt-4">
            <button
              type="button"
              onclick={resetForm}
              class="flex-1 px-4 py-2 rounded-md border border-border/50 bg-background text-foreground hover:bg-muted transition-colors font-medium"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!formName.trim()}
              class="flex-1 px-4 py-2 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed"
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
        class="bg-[oklch(0.15_0.01_258.34)] border border-border/50 rounded-lg shadow-lg w-full max-w-md mx-4"
        onclick={(e) => e.stopPropagation()}
      >
        <div class="px-6 py-4 border-b border-border/50">
          <h3 class="text-lg font-semibold text-foreground">Delete Server</h3>
          <p class="text-sm text-muted-foreground mt-1">
            Are you sure you want to delete "{serverToDelete?.name}"? This
            action cannot be undone.
          </p>
        </div>

        <div class="flex gap-3 p-6">
          <button
            type="button"
            onclick={cancelDelete}
            class="flex-1 px-4 py-2 rounded-md border border-border/50 bg-background text-foreground hover:bg-muted transition-colors font-medium"
          >
            Cancel
          </button>
          <button
            type="button"
            onclick={confirmDelete}
            class="flex-1 px-4 py-2 rounded-md bg-destructive text-primary-foreground hover:bg-destructive/90 transition-colors font-medium"
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
