<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { getCurrentWindow } from "@tauri-apps/api/window";

  let appWindow = $state<Awaited<ReturnType<typeof getCurrentWindow>> | null>(
    null
  );

  onMount(async () => {
    appWindow = await getCurrentWindow();
  });

  async function closeWindow() {
    if (appWindow) {
      await appWindow.close();
    }
  }

  async function minimizeWindow() {
    if (appWindow) {
      await appWindow.minimize();
    }
  }

  async function toggleMaximize() {
    if (appWindow) {
      const isMaximized = await appWindow.isMaximized();
      if (isMaximized) {
        await appWindow.unmaximize();
      } else {
        await appWindow.maximize();
      }
    }
  }
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
    Moon,
    Sun,
    Pencil,
  } from "@lucide/svelte";
  import { tick } from "svelte";
  import * as Command from "$lib/components/ui/command/index.js";
  import * as Popover from "$lib/components/ui/popover/index.js";
  import { Button } from "$lib/components/ui/button/index.js";
  import { Toggle } from "$lib/components/ui/toggle/index.js";
  import { cn } from "$lib/utils.js";
  import { resolvedTheme, saveTheme as saveThemeStore } from "../../lib/theme";
  import { Schema } from "effect";
  import Nav from "$lib/components/Nav.svelte";

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

  type ActiveTab = "analytics" | "servers" | "history";

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

  // Paste JSON state
  let pasteMode = $state(false);
  let pasteJson = $state("");
  let pasteError = $state<string | null>(null);

  // Model selection state
  let models = $state<Array<{ id: string; name?: string }>>([]);
  let selectedModel = $state("openai/gpt-5-nano");
  let modelsLoading = $state(false);
  let modelComboboxOpen = $state(false);
  let modelTriggerRef = $state<HTMLButtonElement>(null!);

  const selectedModelLabel = $derived(
    models.find((m) => m.id === selectedModel)?.name || selectedModel
  );

  // MCP Server Config Schema for validation
  const MCPServerConfigSchema = Schema.Struct({
    name: Schema.String,
    transport: Schema.Union(
      Schema.Literal("stdio"),
      Schema.Literal("http"),
      Schema.Literal("sse")
    ),
    command: Schema.optional(Schema.String),
    args: Schema.optional(Schema.Array(Schema.String)),
    url: Schema.optional(Schema.String),
    enabled: Schema.optional(Schema.Boolean),
  });

  // Check if a model is an image generation model
  function isImageGenerationModel(modelId: string): boolean {
    const modelLower = modelId.toLowerCase();
    return (
      modelLower.includes("dall-e") ||
      modelLower.includes("dalle") ||
      modelLower.includes("stable-diffusion") ||
      modelLower.includes("stablediffusion") ||
      modelLower.includes("flux") ||
      modelLower.includes("midjourney") ||
      modelLower.includes("ideogram") ||
      modelLower.includes("imagen") ||
      modelLower.includes("cogview") ||
      modelLower.includes("wuerstchen") ||
      modelLower.includes("playground") ||
      modelLower.includes("kandinsky") ||
      modelLower.includes("realistic-vision") ||
      modelLower.includes("dreamshaper") ||
      modelLower.includes("sdxl") ||
      modelLower.includes("black-forest-labs") ||
      modelLower.includes("stability-ai")
    );
  }

  // Get model capability label
  function getModelCapability(modelId: string): string {
    if (isImageGenerationModel(modelId)) {
      return "Image Generation";
    }
    // Could add vision model detection here in the future
    return "Text";
  }

  function closeAndFocusTrigger() {
    modelComboboxOpen = false;
    tick().then(() => {
      modelTriggerRef?.focus();
    });
  }

  // Transport selection state
  let transportComboboxOpen = $state(false);
  let transportTriggerRef = $state<HTMLButtonElement>(null!);
  const transportOptions = ["stdio", "http", "sse"] as const;

  function closeAndFocusTransportTrigger() {
    transportComboboxOpen = false;
    tick().then(() => {
      transportTriggerRef?.focus();
    });
  }

  // OpenRouter key state
  let openrouterKey = $state("");
  let keyLoading = $state(false);

  // Theme state
  let isDark = $state(false);

  // History state
  type HistoryEntry = {
    id: string;
    timestamp: string;
    type: string;
    data: any;
  };

  let historyEntries = $state<HistoryEntry[]>([]);
  let historyLoading = $state(false);
  let historySearch = $state("");
  let expandedEntryId = $state<string | null>(null);
  let mainContentRef = $state<HTMLDivElement>(null!);

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
    pasteMode = false;
    pasteJson = "";
    pasteError = null;
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
    pasteMode = false;
    pasteJson = "";
    pasteError = null;
    showAddDialog = true;

    // Auto-fix known servers with incorrect configs
    if (server.name === "Svelte MCP" && server.transport === "http") {
      // Suggest correct stdio config
      formTransport = "stdio";
      formCommand = "npx";
      formArgs = "-y @sveltejs/mcp";
      formUrl = "";
    }
  }

  function validateAndParseJson(jsonString: string): boolean {
    pasteError = null;

    if (!jsonString.trim()) {
      pasteError = "Please paste JSON configuration";
      return false;
    }

    try {
      const parsed = JSON.parse(jsonString);
      const result = Schema.decodeUnknownSync(MCPServerConfigSchema)(parsed);

      // Additional validation: stdio needs command, http/sse needs url
      if (result.transport === "stdio" && !result.command) {
        pasteError = "stdio transport requires 'command' field";
        return false;
      }
      if (
        (result.transport === "http" || result.transport === "sse") &&
        !result.url
      ) {
        pasteError = `${result.transport} transport requires 'url' field`;
        return false;
      }

      // Auto-fill form
      formName = result.name;
      formTransport = result.transport;
      formCommand = result.command ?? "";
      formArgs = result.args?.join(" ") ?? "";
      formUrl = result.url ?? "";

      // Switch to form mode
      pasteMode = false;
      pasteJson = "";
      pasteError = null;
      return true;
    } catch (error) {
      if (error instanceof SyntaxError) {
        pasteError = `Invalid JSON: ${error.message}`;
      } else if (error instanceof Error) {
        pasteError = `Validation failed: ${error.message}`;
      } else {
        pasteError = "Invalid configuration";
      }
      return false;
    }
  }

  function handlePasteModeSwitch() {
    pasteMode = !pasteMode;
    if (pasteMode) {
      // Clear form when switching to paste mode
      pasteError = null;
    } else {
      // Clear paste when switching to form mode
      pasteJson = "";
      pasteError = null;
    }
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
        return "bg-red-500 dark:bg-red-400";
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

    // Setup history realtime if history tab is active
    if (activeTab === "history") {
      loadHistory();
      setupHistoryRealtime();
    }

    return () => {
      unsubscribe();
      cleanupHistoryRealtime();
    };
  });

  async function loadHistory() {
    if (historyLoading) return; // Prevent duplicate calls
    historyLoading = true;

    // Add timeout to prevent infinite loading
    const timeoutId = setTimeout(() => {
      if (historyLoading) {
        console.error("History load timeout");
        historyLoading = false;
        historyEntries = [];
      }
    }, 5000);

    try {
      console.log("Loading history...");
      const result = (await invoke("get_history")) as {
        entries?: HistoryEntry[];
        total?: number;
      };
      console.log("History loaded:", result);
      historyEntries = result?.entries || [];
    } catch (e) {
      console.error("Failed to load history:", e);
      historyEntries = [];
    } finally {
      clearTimeout(timeoutId);
      // Always clear loading state
      historyLoading = false;
      console.log("History loading complete, entries:", historyEntries.length);
    }
  }

  async function searchHistory() {
    if (!historySearch.trim()) {
      await loadHistory();
      return;
    }
    historyLoading = true;
    try {
      const result = (await invoke("search_history", {
        query: historySearch,
      })) as {
        entries: HistoryEntry[];
        total: number;
      };
      historyEntries = result.entries;
    } catch (e) {
      console.error("Failed to search history:", e);
      historyEntries = [];
    } finally {
      historyLoading = false;
    }
  }

  let historyPollInterval: ReturnType<typeof setInterval> | null = null;
  let historyUnlisten: (() => void) | null = null;

  function setupHistoryRealtime() {
    // Cleanup existing
    if (historyPollInterval) {
      clearInterval(historyPollInterval);
      historyPollInterval = null;
    }
    if (historyUnlisten) {
      historyUnlisten();
      historyUnlisten = null;
    }

    if (activeTab !== "history") return;

    // Listen for events
    listen("history-updated", () => {
      if (activeTab === "history" && !historyLoading && !historySearch.trim()) {
        loadHistory();
      }
    })
      .then((unlistenFn) => {
        historyUnlisten = unlistenFn;
      })
      .catch((e) => {
        console.error("Failed to listen to history-updated:", e);
      });

    // Poll fallback
    historyPollInterval = setInterval(() => {
      if (activeTab === "history" && !historyLoading && !historySearch.trim()) {
        loadHistory();
      }
    }, 5000);
  }

  function cleanupHistoryRealtime() {
    if (historyPollInterval) {
      clearInterval(historyPollInterval);
      historyPollInterval = null;
    }
    if (historyUnlisten) {
      historyUnlisten();
      historyUnlisten = null;
    }
  }

  // Reset scroll to top when tab changes (manual, no $effect)
  function handleTabChangeWithScroll(tab: ActiveTab) {
    cleanupHistoryRealtime();
    activeTab = tab;
    if (tab === "history") {
      loadHistory();
      setupHistoryRealtime();
    }
    tick().then(() => {
      if (mainContentRef) {
        mainContentRef.scrollTop = 0;
      }
    });
  }

  const tabs = [
    {
      id: "analytics" as const,
      label: "Analytics",
      icon: BarChart3,
    },
    {
      id: "servers" as const,
      label: "Settings",
      icon: Server,
    },
    {
      id: "history" as const,
      label: "History",
      icon: Activity,
      onClick: () => {
        loadHistory();
      },
    },
  ];
</script>

<div
  class="h-screen flex flex-col bg-background text-foreground overflow-hidden"
>
  <!-- Header with Tabs -->
  <header
    class="border-b border-border bg-card/50 backdrop-blur-sm shrink-0 z-10"
    data-tauri-drag-region
  >
    <div class="w-full px-4 sm:px-6 lg:px-8 xl:px-12">
      <!-- macOS Window Controls -->
      <div class="flex items-center gap-2 mb-2" data-tauri-drag-region>
        <button
          onclick={closeWindow}
          class="w-3 h-3 rounded-full bg-red-500 hover:bg-red-600 transition-colors flex items-center justify-center group"
          title="Close"
        >
          <span
            class="opacity-0 group-hover:opacity-100 text-[8px] text-red-900"
            >×</span
          >
        </button>
        <button
          onclick={minimizeWindow}
          class="w-3 h-3 rounded-full bg-yellow-500 hover:bg-yellow-600 transition-colors flex items-center justify-center group"
          title="Minimize"
        >
          <span
            class="opacity-0 group-hover:opacity-100 text-[8px] text-yellow-900"
            >−</span
          >
        </button>
        <button
          onclick={toggleMaximize}
          class="w-3 h-3 rounded-full bg-green-500 hover:bg-green-600 transition-colors flex items-center justify-center group"
          title="Maximize"
        >
          <span
            class="opacity-0 group-hover:opacity-100 text-[8px] text-green-900"
            >+</span
          >
        </button>
      </div>
      <div
        class="flex items-center justify-between py-3 sm:py-4 gap-2 sm:gap-4"
      >
        <div class="flex items-center gap-3 sm:gap-6 min-w-0">
          <div class="flex items-center gap-2 sm:gap-3 shrink-0">
            <img
              src="/logo.svg"
              alt="t2t"
              class="h-6 w-6 sm:h-8 sm:w-8 dark:invert"
            />
            <h1 class="sr-only">t2t</h1>
          </div>

          <!-- Tab Navigation -->
          <Nav {activeTab} {tabs} onTabChange={handleTabChangeWithScroll} />
        </div>

        <!-- Ready Status -->
        {#if activeTab === "analytics"}
          <div
            class="flex items-center gap-1.5 sm:gap-2 px-2 sm:px-3 py-1 sm:py-1.5 rounded-full bg-primary/10 border border-primary/20 shrink-0"
          >
            <div
              class="w-1.5 h-1.5 sm:w-2 sm:h-2 rounded-full bg-primary animate-pulse"
            ></div>
            <span
              class="text-xs sm:text-sm font-medium text-primary hidden sm:inline"
              >Ready</span
            >
          </div>
        {/if}
      </div>
    </div>
  </header>

  <!-- Main Content -->
  <div bind:this={mainContentRef} class="w-full flex-1 overflow-y-auto min-h-0">
    {#if activeTab === "analytics"}
      <!-- Analytics Dashboard -->
      <div class="p-4 sm:p-6 lg:p-8 xl:p-12 space-y-4 sm:space-y-6 min-h-full">
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
          <div
            class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4"
          >
            <!-- Total Words -->
            <div
              class="p-4 sm:p-6 space-y-3 sm:space-y-4 bg-card/50 border border-border rounded-lg"
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
                <p
                  class="text-3xl sm:text-4xl lg:text-5xl font-bold text-foreground tabular-nums"
                >
                  {totalWords.toLocaleString()}
                </p>
              </div>
            </div>

            <!-- Lifetime Average -->
            <div
              class="p-4 sm:p-6 space-y-3 sm:space-y-4 bg-card/50 border border-border rounded-lg"
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
                  <p
                    class="text-3xl sm:text-4xl lg:text-5xl font-bold text-foreground tabular-nums"
                  >
                    {lifetimeWpm.toFixed(1)}
                  </p>
                  <p class="text-base sm:text-lg text-muted-foreground">WPM</p>
                </div>
              </div>
            </div>

            <!-- Session Average -->
            <div
              class="p-4 sm:p-6 space-y-3 sm:space-y-4 bg-card/50 border border-border rounded-lg relative"
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
                  <p
                    class="text-3xl sm:text-4xl lg:text-5xl font-bold text-foreground tabular-nums"
                  >
                    {sessionAvgWpm.toFixed(1)}
                  </p>
                  <p class="text-base sm:text-lg text-muted-foreground">WPM</p>
                </div>
              </div>
            </div>
          </div>

          <!-- Secondary Stats -->
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">
            <div class="p-4 sm:p-6 bg-card/50 border border-border rounded-lg">
              <p
                class="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2"
              >
                Sessions
              </p>
              <p
                class="text-2xl sm:text-3xl lg:text-4xl font-bold text-foreground tabular-nums"
              >
                {sessions}
              </p>
            </div>

            <div class="p-4 sm:p-6 bg-card/50 border border-border rounded-lg">
              <p
                class="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2"
              >
                Hours Active
              </p>
              <p
                class="text-2xl sm:text-3xl lg:text-4xl font-bold text-foreground tabular-nums"
              >
                {hoursActive.toFixed(1)}h
              </p>
            </div>
          </div>

          <!-- Recent Activity Chart -->
          <div class="p-4 sm:p-6 bg-card/50 border border-border rounded-lg">
            <p
              class="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-4 sm:mb-6"
            >
              Recent Activity
            </p>
            <div
              class="flex items-end justify-between gap-1 h-32 sm:h-40 lg:h-48 min-h-[120px]"
            >
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
    {:else if activeTab === "servers"}
      <!-- Settings -->
      <div class="p-4 sm:p-6 lg:p-8 xl:p-12 space-y-4 sm:space-y-6 min-h-full">
        <!-- Theme Selection -->
        <div class="flex items-center gap-3 sm:gap-4 py-2">
          <span class="text-sm font-medium text-foreground dark:text-white"
            >Theme</span
          >
          <Toggle
            aria-label="Toggle theme"
            pressed={isDark}
            onPressedChange={(pressed) => {
              const newTheme = pressed ? "dark" : "light";
              saveThemeStore(newTheme);
            }}
            variant="outline"
            size="sm"
          >
            {#if isDark}
              <Moon class="size-4" />
            {:else}
              <Sun class="size-4" />
            {/if}
          </Toggle>
        </div>

        <!-- OpenRouter API Key -->
        <div class="p-4 sm:p-6 bg-card/50 border border-border rounded-lg">
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
            <Button
              onclick={saveOpenRouterKey}
              disabled={!openrouterKey || openrouterKey.length === 0}
            >
              Save
            </Button>
          </div>
          <p class="text-xs text-muted-foreground mt-2">
            Your API key is stored locally. Falls back to <code
              class="px-1 py-0.5 bg-muted rounded">OPENROUTER_API_KEY</code
            > env var if not set.
          </p>
        </div>

        <!-- Model Selection -->
        <div class="p-4 sm:p-6 bg-card/50 border border-border rounded-lg">
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
                  <div class="flex items-center justify-between w-full min-w-0">
                    <span class="truncate"
                      >{selectedModelLabel || "Select a model..."}</span
                    >
                    {#if isImageGenerationModel(selectedModel)}
                      <span
                        class="ms-2 px-2 py-0.5 text-xs rounded bg-purple-500/20 text-purple-400 border border-purple-500/30 shrink-0"
                        title="Screenshots will be automatically included with prompts"
                      >
                        🖼️
                      </span>
                    {/if}
                    <ChevronsUpDown class="ms-2 size-4 shrink-0 opacity-50" />
                  </div>
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
                          <div class="flex items-center justify-between w-full">
                            <div class="flex items-center flex-1 min-w-0">
                              <Check
                                class={cn(
                                  "me-2 size-4 shrink-0",
                                  model.id === selectedModel
                                    ? "opacity-100"
                                    : "opacity-0"
                                )}
                              />
                              <span class="truncate"
                                >{model.name || model.id}</span
                              >
                            </div>
                            {#if isImageGenerationModel(model.id)}
                              <span
                                class="ms-2 px-2 py-0.5 text-xs rounded bg-purple-500/20 text-purple-400 border border-purple-500/30 shrink-0"
                                title="Screenshots will be automatically included with prompts"
                              >
                                🖼️ Image Gen
                              </span>
                            {/if}
                          </div>
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
          {#if isImageGenerationModel(selectedModel)}
            <div
              class="mt-2 p-2 bg-purple-500/10 border border-purple-500/20 rounded text-xs text-purple-300"
            >
              <strong>🖼️ Image Generation Mode:</strong> Screenshots are automatically
              captured and included with every agent input. The agent can "see" your
              screen.
            </div>
          {/if}
        </div>

        <p class="text-sm text-muted-foreground">Manage your MCP servers</p>

        <div class="bg-card/50 border border-border rounded-lg overflow-hidden">
          <div class="px-4 sm:px-6 py-3 sm:py-4 border-b border-border/30">
            <h2 class="text-lg font-medium text-foreground">
              Installed MCP Servers
            </h2>
          </div>

          {#if loading}
            <div
              class="px-4 sm:px-6 py-6 sm:py-8 flex items-center justify-center min-h-[200px]"
            >
              <div class="flex items-center gap-3 text-muted-foreground">
                <div
                  class="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin"
                ></div>
                <span class="text-sm">Loading servers...</span>
              </div>
            </div>
          {:else if servers.length === 0}
            <div
              class="px-4 sm:px-6 py-8 sm:py-12 text-center min-h-[200px] flex items-center justify-center"
            >
              <p class="text-muted-foreground text-sm">
                No servers installed yet
              </p>
            </div>
          {:else}
            <div class="divide-y divide-border/30">
              {#each servers as server (server.id)}
                <div class="group">
                  <div
                    class="px-4 sm:px-6 py-3 sm:py-4 flex items-center gap-3 sm:gap-4 flex-wrap sm:flex-nowrap"
                  >
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
                    <div class="flex-1 min-w-0 w-full sm:w-auto">
                      <div class="flex items-center gap-2 mb-1">
                        <h3
                          class="text-sm sm:text-base font-medium text-foreground truncate"
                        >
                          {server.name}
                        </h3>
                      </div>

                      <div
                        onclick={() => handleExpand(server.id)}
                        class="flex items-center gap-2 text-xs sm:text-sm text-muted-foreground cursor-pointer hover:text-foreground flex-wrap"
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
                            <span
                              class="text-red-500 dark:text-red-400 font-medium"
                              >{server.statusMessage ||
                                "Connection failed"}</span
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

                    <!-- Edit button -->
                    <button
                      onclick={() => startEdit(server)}
                      class="h-8 w-8 flex items-center justify-center text-muted-foreground hover:text-primary rounded transition-colors"
                      title="Edit server"
                    >
                      <Pencil class="w-4 h-4" />
                    </button>

                    <!-- Delete button -->
                    <button
                      onclick={() => handleDelete(server.id)}
                      class="h-8 w-8 flex items-center justify-center text-muted-foreground hover:text-destructive rounded transition-colors"
                      title="Delete server"
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
            class="w-full px-4 sm:px-6 py-3 sm:py-4 flex items-center gap-3 sm:gap-4 hover:bg-muted/50 transition-colors border-t border-border/50"
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
    {:else if activeTab === "history"}
      <!-- History Tab -->
      <div class="p-4 sm:p-6 lg:p-8 xl:p-12 space-y-4 sm:space-y-6 min-h-full">
        <div>
          <h2 class="text-xl sm:text-2xl font-bold text-foreground">History</h2>
          <p class="text-sm text-muted-foreground mt-1">
            View all transcriptions and agent calls
          </p>
        </div>

        <!-- Search -->
        <div class="relative">
          <input
            type="text"
            bind:value={historySearch}
            oninput={() => searchHistory()}
            placeholder="Search history..."
            class="w-full px-4 py-2 rounded-md bg-background border border-border/50 text-foreground placeholder:text-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary"
          />
        </div>

        <!-- History List -->
        {#if historyLoading}
          <div class="flex items-center justify-center py-12">
            <div class="flex items-center gap-3 text-muted-foreground">
              <div
                class="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin"
              ></div>
              <span class="text-sm">Loading...</span>
            </div>
          </div>
        {:else if historyEntries.length === 0}
          <div class="flex items-center justify-center py-12">
            <p class="text-muted-foreground">
              {historySearch ? "No results found" : "No history yet"}
            </p>
          </div>
        {:else}
          <div class="space-y-2">
            {#each historyEntries as entry (entry.id)}
              <button
                type="button"
                class="w-full bg-card/50 border border-border rounded-lg p-4 text-left hover:bg-card transition-colors"
                onclick={() => {
                  expandedEntryId =
                    expandedEntryId === entry.id ? null : entry.id;
                }}
              >
                <div class="flex items-start justify-between gap-4">
                  <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-2 mb-1">
                      <span
                        class="px-2 py-0.5 text-xs rounded {entry.type ===
                        'transcription'
                          ? 'bg-blue-500/20 text-blue-400'
                          : 'bg-purple-500/20 text-purple-400'}"
                      >
                        {entry.type === "transcription"
                          ? "Transcription"
                          : "Agent"}
                      </span>
                      <span class="text-xs text-muted-foreground">
                        {new Date(entry.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <p class="text-sm text-foreground truncate">
                      {entry.type === "transcription"
                        ? entry.data.text || ""
                        : entry.data.transcript || ""}
                    </p>
                    {#if entry.type === "agent" && entry.data.model}
                      <p class="text-xs text-muted-foreground mt-1">
                        Model: {entry.data.model}
                      </p>
                    {/if}
                  </div>
                  {#if entry.data.screenshotThumbnail}
                    <img
                      src={entry.data.screenshotThumbnail}
                      alt="Screenshot thumbnail"
                      class="w-16 h-16 rounded object-cover shrink-0"
                    />
                  {/if}
                </div>

                {#if expandedEntryId === entry.id}
                  <div class="mt-4 pt-4 border-t border-border/50 space-y-3">
                    {#if entry.type === "agent"}
                      <div>
                        <h4 class="text-sm font-medium mb-2">Request</h4>
                        <pre
                          class="text-xs bg-muted/50 p-3 rounded overflow-x-auto">{JSON.stringify(
                            entry.data.request,
                            null,
                            2
                          )}</pre>
                      </div>
                      <div>
                        <h4 class="text-sm font-medium mb-2">Response</h4>
                        <pre
                          class="text-xs bg-muted/50 p-3 rounded overflow-x-auto">{JSON.stringify(
                            entry.data.response,
                            null,
                            2
                          )}</pre>
                      </div>
                      {#if entry.data.toolCalls && entry.data.toolCalls.length > 0}
                        <div>
                          <h4 class="text-sm font-medium mb-2">Tool Calls</h4>
                          <pre
                            class="text-xs bg-muted/50 p-3 rounded overflow-x-auto">{JSON.stringify(
                              entry.data.toolCalls,
                              null,
                              2
                            )}</pre>
                        </div>
                      {/if}
                      {#if entry.data.error}
                        <div>
                          <h4 class="text-sm font-medium mb-2 text-destructive">
                            Error
                          </h4>
                          <p class="text-sm text-destructive">
                            {entry.data.error}
                          </p>
                        </div>
                      {/if}
                    {:else}
                      <div>
                        <p class="text-sm text-foreground">
                          {entry.data.text || ""}
                        </p>
                      </div>
                    {/if}
                  </div>
                {/if}
              </button>
            {/each}
          </div>
        {/if}
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

          {#if !editingId}
            <div class="flex gap-2 mt-4">
              <button
                type="button"
                onclick={() => {
                  pasteMode = false;
                  pasteJson = "";
                  pasteError = null;
                }}
                class="px-3 py-1.5 text-sm rounded-md transition-colors {pasteMode
                  ? 'bg-muted/50 text-muted-foreground hover:bg-muted'
                  : 'bg-primary/20 text-primary border border-primary/30'}"
              >
                Form
              </button>
              <button
                type="button"
                onclick={() => {
                  pasteMode = true;
                  pasteError = null;
                }}
                class="px-3 py-1.5 text-sm rounded-md transition-colors {pasteMode
                  ? 'bg-primary/20 text-primary border border-primary/30'
                  : 'bg-muted/50 text-muted-foreground hover:bg-muted'}"
              >
                Paste JSON
              </button>
            </div>
          {/if}
        </div>

        {#if pasteMode && !editingId}
          <div class="p-6 space-y-4">
            <div>
              <label
                for="paste-json"
                class="block text-sm font-medium text-foreground mb-2"
              >
                Paste MCP Server JSON Config
              </label>
              <textarea
                id="paste-json"
                bind:value={pasteJson}
                placeholder={`{"name": "Svelte MCP", "transport": "http", "url": "https://mcp.svelte.dev/mcp", "enabled": true}`}
                class="w-full px-3 py-2 rounded-md bg-background border border-border/50 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary font-mono text-sm min-h-[200px] resize-y"
              ></textarea>
              {#if pasteError}
                <p class="text-sm text-destructive mt-2">{pasteError}</p>
              {/if}
            </div>

            <div class="flex gap-3 pt-4">
              <button
                type="button"
                onclick={resetForm}
                class="flex-1 px-4 py-2 rounded-md border border-border/50 bg-background text-foreground hover:bg-muted transition-colors font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onclick={() => validateAndParseJson(pasteJson)}
                disabled={!pasteJson.trim()}
                class="flex-1 px-4 py-2 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Parse & Fill Form
              </button>
            </div>
          </div>
        {:else}
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
              <label class="block text-sm font-medium text-foreground mb-2">
                Transport
              </label>
              <Popover.Root bind:open={transportComboboxOpen}>
                <Popover.Trigger bind:ref={transportTriggerRef}>
                  {#snippet child({ props })}
                    <Button
                      {...props}
                      variant="outline"
                      class="w-full justify-between bg-muted border-border/50 text-foreground hover:bg-muted/80"
                      role="combobox"
                      aria-expanded={transportComboboxOpen}
                    >
                      {formTransport}
                      <ChevronsUpDown class="ms-2 size-4 shrink-0 opacity-50" />
                    </Button>
                  {/snippet}
                </Popover.Trigger>
                <Popover.Content class="w-full p-0" align="start">
                  <Command.Root>
                    <Command.List>
                      <Command.Group>
                        {#each transportOptions as transport}
                          <Command.Item
                            value={transport}
                            onSelect={() => {
                              formTransport = transport;
                              closeAndFocusTransportTrigger();
                            }}
                          >
                            <Check
                              class={cn(
                                "me-2 size-4",
                                formTransport === transport
                                  ? "opacity-100"
                                  : "opacity-0"
                              )}
                            />
                            {transport}
                          </Command.Item>
                        {/each}
                      </Command.Group>
                    </Command.List>
                  </Command.Root>
                </Popover.Content>
              </Popover.Root>
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
                  placeholder="npx"
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
                  placeholder="-y @sveltejs/mcp"
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
        {/if}
      </div>
    </div>
  {/if}

  <!-- Delete Confirmation Dialog -->
  {#if deleteConfirmId}
    {@const serverToDelete = servers.find((s) => s.id === deleteConfirmId)}
    <div
      class="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
      onclick={cancelDelete}
      role="dialog"
      aria-modal="true"
      aria-labelledby="delete-server-dialog-title"
      aria-describedby="delete-server-dialog-description"
      tabindex="-1"
      aria-hidden="true"
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
