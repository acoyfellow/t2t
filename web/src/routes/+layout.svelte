<script lang="ts">
  import "../app.css";
  import { authStore } from "$lib/auth-store.svelte";
  import { initializeTheme } from "$lib/theme";
  import { onMount } from "svelte";

  let { data, children } = $props();

  onMount(() => {
    authStore.initialize(data.user, data.session);
    initializeTheme(data.theme);
  });
</script>

{@render children()}
