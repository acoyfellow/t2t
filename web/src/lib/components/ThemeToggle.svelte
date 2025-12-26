<script lang="ts">
  import { Sun, Moon } from "@lucide/svelte/icons";
  import { getTheme, setTheme } from "$lib/theme";
  import { onMount } from "svelte";

  let currentTheme = $state<'light' | 'dark'>('light');

  onMount(() => {
    currentTheme = getTheme();
  });

  function toggle() {
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
    currentTheme = newTheme;
  }
</script>

<button
  onclick={toggle}
  class="fixed bottom-6 right-6 z-50 size-12 rounded-full bg-background border border-border shadow-lg hover:bg-accent hover:text-accent-foreground transition-colors flex items-center justify-center"
  aria-label="Toggle theme"
>
  {#if currentTheme === 'light'}
    <Sun class="size-5" />
  {:else}
    <Moon class="size-5" />
  {/if}
</button>




