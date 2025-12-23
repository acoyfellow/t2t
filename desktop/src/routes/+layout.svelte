<script>
  let { children } = $props();
  import "../app.css";
  import { page } from "$app/state";

  const bodyClass = $derived(
    page.url.pathname === "/stats"
      ? "bg-[#07070b] text-[#e9e9ee] font-sans antialiased"
      : page.url.pathname === "/settings"
        ? "bg-[oklch(0.11_0.012_258.34)] text-[oklch(0.88_0.01_258.34)] font-sans antialiased"
        : "bg-transparent overflow-hidden"
  );

  $effect(() => {
    document.body.className = bodyClass;
  });
</script>

{@render children()}
