<script lang="ts">
  import { onMount } from "svelte";
  let { children } = $props();
  import "../app.css";
  import { page } from "$app/state";
  import { resolvedTheme, loadTheme } from "../lib/theme";

  // Load theme on mount
  onMount(async () => {
    await loadTheme();
  });

  // Apply .dark class to document root
  let resolvedThemeValue = $state<"light" | "dark">("light");

  onMount(() => {
    const unsubscribe = resolvedTheme.subscribe((theme) => {
      resolvedThemeValue = theme;
      if (typeof document !== "undefined") {
        document.documentElement.classList.toggle("dark", theme === "dark");
      }
    });
    return unsubscribe;
  });

  $effect(() => {
    if (typeof document !== "undefined") {
      document.documentElement.classList.toggle(
        "dark",
        resolvedThemeValue === "dark"
      );
    }
  });

  const bodyClass = $derived(
    page.url.pathname === "/stats"
      ? "bg-background text-foreground font-sans antialiased"
      : page.url.pathname === "/settings"
        ? "bg-background text-foreground font-sans antialiased"
        : "bg-transparent overflow-hidden"
  );

  $effect(() => {
    document.body.className = bodyClass;
  });
</script>

{@render children()}
