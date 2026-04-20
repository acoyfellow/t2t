<script lang="ts">
  import type { Component } from "svelte";

  type ActiveTab = "analytics" | "servers" | "history";

  type Tab = {
    id: ActiveTab;
    label: string;
    icon: Component;
    onClick?: () => void;
  };

  let {
    activeTab,
    tabs,
    onTabChange,
  }: {
    activeTab: ActiveTab;
    tabs: Tab[];
    onTabChange?: (tab: ActiveTab) => void;
  } = $props();

  function handleClick(tab: Tab) {
    if (tab.onClick) {
      tab.onClick();
    }
    if (onTabChange) {
      onTabChange(tab.id);
    }
  }
</script>

<nav class="flex gap-1">
  {#each tabs as tab (tab.id)}
    {@const Icon = tab.icon}
    <button
      onclick={() => handleClick(tab)}
      class="flex items-center gap-1.5 sm:gap-2 px-2 sm:px-4 py-1.5 sm:py-2 rounded-md transition-colors text-xs sm:text-sm font-medium {activeTab ===
      tab.id
        ? 'bg-primary/10 text-primary '
        : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'}"
    >
      <Icon class="w-3.5 h-3.5 sm:w-4 sm:h-4" />
      <span class="hidden sm:inline">{tab.label}</span>
    </button>
  {/each}
</nav>
