<script lang="ts">
  import { ArrowLeft, Server, Search, Copy, Check } from "@lucide/svelte";
  import SEO from "$lib/components/SEO.svelte";
  import ThemeToggle from "$lib/components/ThemeToggle.svelte";
  import { Button } from "$lib/components/ui/button/index.js";
  import {
    mcpDirectory,
    categories,
    getCategoryLabel,
    getCategoryColor,
    type MCPEntry,
    type MCPCategory,
  } from "$lib/mcp-directory";

  let searchQuery = $state("");
  let selectedCategory = $state<MCPCategory | "all">("all");
  let copiedId = $state<string | null>(null);

  const filteredMCPs = $derived.by(() => {
    let filtered = mcpDirectory;

    if (selectedCategory !== "all") {
      filtered = filtered.filter((mcp) => mcp.category === selectedCategory);
    }

    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (mcp) =>
          mcp.name.toLowerCase().includes(query) ||
          mcp.description.toLowerCase().includes(query)
      );
    }

    return filtered;
  });

  function copyConfig(mcp: MCPEntry) {
    const config = {
      name: mcp.config.name,
      transport: mcp.config.transport,
      ...(mcp.config.command && { command: mcp.config.command }),
      ...(mcp.config.args && { args: mcp.config.args }),
      ...(mcp.config.url && { url: mcp.config.url }),
      enabled: mcp.config.enabled ?? true,
    };

    const json = JSON.stringify(config, null, 2);

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(json).then(() => {
        copiedId = mcp.id;
        setTimeout(() => {
          copiedId = null;
        }, 2000);
      });
    } else {
      // Fallback for older browsers
      const textarea = document.createElement("textarea");
      textarea.value = json;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      try {
        document.execCommand("copy");
        copiedId = mcp.id;
        setTimeout(() => {
          copiedId = null;
        }, 2000);
      } catch (err) {
        console.error("Failed to copy:", err);
      }
      document.body.removeChild(textarea);
    }
  }
</script>

<SEO
  title="MCP Directory - t2t"
  description="Browse popular MCP servers compatible with t2t. Copy configurations and extend your voice-to-text automation."
  keywords="t2t, mcp, model context protocol, servers, automation, integration"
  path="/mcp"
  section="mcp-directory"
  tags="t2t, mcp, directory, servers"
/>

<div class="min-h-screen bg-background text-foreground">
  <!-- Header -->
  <header
    class="border-b border-border sticky top-0 bg-background/80 backdrop-blur-sm z-20"
  >
    <div class="max-w-7xl mx-auto px-6 py-4">
      <a
        href="/"
        class="inline-flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors"
      >
        <ArrowLeft class="w-4 h-4" />
        <img src="/logo.svg" alt="t2t" class="dark:invert h-8" />
      </a>
    </div>
  </header>

  <!-- Content -->
  <div class="max-w-7xl mx-auto px-6 py-12">
    <!-- Hero Section -->
    <div class="mb-12">
      <div class="flex items-center gap-3 mb-4">
        <div
          class="w-12 h-12 rounded-xl bg-primary/20 flex items-center justify-center"
        >
          <Server class="w-6 h-6 text-primary" />
        </div>
        <h1 class="text-6xl md:text-7xl font-black">MCP Directory</h1>
      </div>
      <p class="text-xl text-muted-foreground max-w-3xl">
        Browse popular MCP servers that work seamlessly with t2t. Copy
        configurations and paste them into your t2t settings to extend your
        automation capabilities.
      </p>
    </div>

    <!-- Search and Filter -->
    <div class="mb-8 flex flex-col sm:flex-row gap-4">
      <!-- Search Input -->
      <div class="relative flex-1">
        <Search
          class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground"
        />
        <input
          type="text"
          placeholder="Search MCP servers..."
          bind:value={searchQuery}
          class="w-full pl-10 pr-4 py-2 bg-muted/50 border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50 text-foreground"
        />
      </div>

      <!-- Category Filter -->
      <div class="flex flex-wrap gap-2">
        <button
          onclick={() => (selectedCategory = "all")}
          class="px-4 py-2 rounded-lg border border-border transition-colors {selectedCategory ===
          'all'
            ? 'bg-primary/20 text-primary border-primary/30'
            : 'bg-muted/50 text-muted-foreground hover:bg-muted'}"
        >
          All
        </button>
        {#each categories as category}
          <button
            onclick={() => (selectedCategory = category)}
            class="px-4 py-2 rounded-lg border transition-colors {selectedCategory ===
            category
              ? getCategoryColor(category) + ' border-current'
              : 'bg-muted/50 text-muted-foreground hover:bg-muted border-border'}"
          >
            {getCategoryLabel(category)}
          </button>
        {/each}
      </div>
    </div>

    <!-- Results Count -->
    <div class="mb-6 text-sm text-muted-foreground">
      {filteredMCPs.length === 1
        ? "1 MCP server"
        : `${filteredMCPs.length} MCP servers`}
    </div>

    <!-- MCP Grid -->
    {#if filteredMCPs.length === 0}
      <div class="text-center py-16">
        <p class="text-muted-foreground text-lg">
          No MCP servers found matching your search.
        </p>
      </div>
    {:else}
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-12">
        {#each filteredMCPs as mcp}
          <div
            class="bg-muted/30 border border-border rounded-lg p-6 hover:border-primary/30 transition-all hover:shadow-lg flex flex-col items-center justify-between w-full min-h-60 gap-4"
          >
            <div class="w-full space-y-4 grow">
              <!-- Header -->
              <div class="flex items-start justify-between">
                <div class="flex-1">
                  <h3 class="text-xl font-bold mb-1">{mcp.name}</h3>
                </div>
              </div>

              <!-- Description -->
              <p class="text-sm text-muted-foreground line-clamp-3">
                {mcp.description}
              </p>

              <!-- Badges -->
              <div class="flex flex-wrap gap-2">
                <span
                  class="px-2 py-1 rounded text-xs font-medium border {getCategoryColor(
                    mcp.category
                  )}"
                >
                  {getCategoryLabel(mcp.category)}
                </span>
                <span
                  class="px-2 py-1 rounded text-xs font-medium bg-gray-500/20 text-gray-400 border border-gray-500/30"
                >
                  {mcp.transport.toUpperCase()}
                </span>
              </div>
            </div>

            <div class="shrink-0 w-full">
              <!-- Copy Button -->
              <Button
                onclick={() => copyConfig(mcp)}
                variant="outline"
                class="w-full"
              >
                {#if copiedId === mcp.id}
                  <Check class="w-4 h-4" />
                  Copied!
                {:else}
                  <Copy class="w-4 h-4" />
                  Copy Config
                {/if}
              </Button>
            </div>
          </div>
        {/each}
      </div>
    {/if}

    <!-- Footer -->
    <div class="border-t border-border pt-8 mt-16">
      <div class="flex flex-col items-center gap-4">
        <p class="text-center text-muted-foreground text-sm">
          Need help setting up MCP servers?
        </p>
        <a
          href="/docs#mcp-servers"
          class="text-primary hover:underline font-medium"
        >
          View Documentation →
        </a>
      </div>
    </div>
  </div>
  <ThemeToggle />
</div>
