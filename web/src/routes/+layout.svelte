<script lang="ts">
  import "../app.css";
  import { authStore } from "$lib/auth-store.svelte";
  import { initializeTheme } from "$lib/theme";
  import { onMount } from "svelte";

  let { data, children } = $props();

  // Initialize auth store with server data
  authStore.initialize(data.user, data.session);

  onMount(() => {
    initializeTheme(data.theme);
  });
</script>

{@render children()}
