<script>
  let { children } = $props();
  import "../app.css";
  import { page } from "$app/state";

  const bodyClass = $derived(
    page.url.pathname === "/stats"
      ? "bg-[#07070b] text-[#e9e9ee] font-sans antialiased"
      : "bg-transparent overflow-hidden"
  );

  $effect(() => {
    document.body.className = bodyClass;
  });
</script>

{@render children()}
