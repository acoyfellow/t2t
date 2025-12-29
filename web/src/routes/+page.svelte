<script lang="ts">
  import { onMount } from "svelte";
  import Github from "@lucide/svelte/icons/github";
  import Download from "@lucide/svelte/icons/download";
  import Mail from "@lucide/svelte/icons/mail";
  import Twitter from "@lucide/svelte/icons/twitter";
  import SignalThread from "$lib/components/Signal.svelte";
  const GITHUB_RELEASES_URL = "https://github.com/acoyfellow/t2t/releases";

  let mousePosition = $state({ x: 0, y: 0 });
  let heroRef: HTMLDivElement;

  onMount(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (heroRef) {
        const rect = heroRef.getBoundingClientRect();
        mousePosition = {
          x: ((e.clientX - rect.left) / rect.width) * 100,
          y: ((e.clientY - rect.top) / rect.height) * 100,
        };
      }
    };

    window.addEventListener("mousemove", handleMouseMove);
    return () => window.removeEventListener("mousemove", handleMouseMove);
  });
</script>

<svelte:head>
  <title>t2t - Talk to Type</title>
  <meta
    name="description"
    content="Voice-to-text with intelligence. Hold fn to talk, hold fn+ctrl to command."
  />
</svelte:head>

<nav class="absolute w-full top-0 z-10">
  <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
    <a
      href="/"
      class="inline-flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors bg-foreground px-4 py-2 rounded-md dark:invert"
    >
      <img src="/logo.svg" alt="t2t" class=" h-10 invert dark:invert-0" />
    </a>
    <div class="flex items-center gap-4">
      <a
        href="/mcp"
        class="text-background hover:text-muted-foreground transition-colors bg-foreground px-4 py-2 rounded-md dark:invert"
      >
        MCP Directory
      </a>
      <a
        href="/docs"
        class="text-background hover:text-muted-foreground transition-colors bg-foreground px-4 py-2 rounded-md dark:invert"
      >
        Docs
      </a>
      <a
        href="https://github.com/acoyfellow/t2t"
        class="text-background hover:text-muted-foreground transition-colors bg-foreground px-4 py-2 rounded-md dark:invert"
      >
        <Github class="w-6 h-6" />
      </a>
    </div>
  </div>
</nav>

<img
  src="/cluster-2.jpg"
  alt="cluster illustration"
  class="w-full z-0 -mb-20 pointer-events-none"
/>
<div class=" bg-black text-white overflow-hidden w-full">
  <!-- Hero Section -->
  <div
    bind:this={heroRef}
    class="relative flex flex-col items-center justify-center py-20 w-full"
  >
    <div
      class="absolute inset-0 opacity-30 blur-[100px] pointer-events-none transition-all duration-500"
      style={`background: radial-gradient(600px circle at ${mousePosition.x}% ${mousePosition.y}%, rgba(0, 255, 163, 0.4), transparent 40%);`}
    ></div>

    <div class="relative z-10 text-center space-y-16 w-full">
      <!-- Main headline -->
      <div class="relative">
        <h1
          class="text-[clamp(3rem,15vw,12rem)] font-black leading-[0.85] tracking-tighter text-balance"
        >
          <span
            class="block bg-linear-to-br from-white via-white to-zinc-400 bg-clip-text text-transparent z-10 relative"
          >
            HOLD
          </span>
          <div class="relative">
            <span class="block text-[#00FFA3] animate-pulse-slow z-10 relative"
              >fn</span
            >
            <div class="absolute top-4 left-0 right-0 opacity-50 z-0">
              <SignalThread
                color="#00FFA3"
                backgroundColor="transparent"
                speed={2}
                frequency={0.04}
                amplitude={20}
                baseAmplitude={20}
                breathSpeed={5}
                pulseSpeed={0.2}
                lineWidth={1}
              />
            </div>
          </div>
          <span
            class="block bg-linear-to-br from-white via-zinc-300 to-zinc-600 bg-clip-text text-transparent z-10 relative"
          >
            TO SPEAK
          </span>
        </h1>
      </div>
      <!-- Tagline -->
      <p
        class="text-xl md:text-3xl text-zinc-400 max-w-3xl mx-auto font-light tracking-wide text-balance"
      >
        Voice becomes text. Talk to any MCP server. Cross-platform.
      </p>

      <!-- CTA -->
      <div
        class="flex flex-col lg:flex-row gap-4 items-center justify-center pt-8 px-6 max-w-7xl mx-auto"
      >
        <a
          href={GITHUB_RELEASES_URL}
          class="group relative px-10 py-5 bg-[#00FFA3] text-black text-lg font-bold rounded-none hover:bg-[#00FF8F] transition-all duration-200 hover:scale-105 hover:shadow-[0_0_40px_rgba(0,255,163,0.4)] w-full"
        >
          <Download class="inline-block mr-2 h-5 w-5" />
          Download for macOS
        </a>
        <a
          href="https://github.com/acoyfellow/t2t"
          class="px-10 py-5 border-2 border-zinc-700 text-white text-lg font-bold rounded-none hover:border-[#00FFA3] hover:text-[#00FFA3] transition-all duration-200 bg-black w-full"
        >
          <Github class="inline-block mr-2 h-5 w-5" />
          View Source
        </a>
        <a
          href="/docs"
          class="px-10 py-5 border-2 border-zinc-700 text-white text-lg font-bold rounded-none hover:border-[#00FFA3] hover:text-[#00FFA3] transition-all duration-200 bg-black w-full"
        >
          Documentation
        </a>
      </div>
    </div>
  </div>

  <div class="relative py px-4 text-balance space-y-54">
    <!-- Background grid -->
    <div
      class="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.2)_1px,transparent_1px)] bg-size-[100px_100px] mask-[radial-gradient(ellipse_at_center,black,transparent_80%)]"
    ></div>

    <!-- fn key feature -->
    <div class="relative max-w-7xl mx-auto">
      <div class="grid lg:grid-cols-2 gap-16 items-center">
        <div class="order-2 lg:order-1">
          <h2 class="text-6xl md:text-8xl font-black mb-8 leading-none">
            Talk
            <br />
            <span class="text-[#00FFA3]">to type</span>
          </h2>
          <p class="text-2xl text-zinc-400 leading-relaxed">
            Hold{" "}
            <kbd
              class="px-3 py-1 bg-zinc-900 border-2 border-[#00FFA3] text-[#00FFA3] font-mono rounded"
            >
              fn
            </kbd>{" "}
            anywhere. Your voice becomes text. Nearly 4x faster than typing. No apps.
            No setup. No friction.
          </p>
        </div>
        <div class="order-1 lg:order-2 flex justify-center">
          <img
            src="/fn.png"
            alt="fn key illustration"
            class="w-full max-w-md"
          />
        </div>
      </div>
    </div>

    <!-- fn+ctrl feature -->
    <div class="relative max-w-7xl mx-auto">
      <div class="grid lg:grid-cols-2 gap-16 items-center">
        <div class="flex justify-center">
          <img
            src="/fn+control.png"
            alt="fn+ctrl keys illustration"
            class="w-full max-w-md"
          />
        </div>
        <div>
          <h2 class="text-6xl md:text-8xl font-black mb-8 leading-none">
            Command
            <br />
            <span class="text-purple-400">an agent</span>
          </h2>
          <p class="text-2xl text-zinc-400 leading-relaxed">
            Hold{" "}
            <kbd
              class="px-3 py-1 bg-zinc-900 border-2 border-purple-500 text-purple-400 font-mono rounded"
            >
              fn+ctrl
            </kbd>{" "}
            to speak commands. Your OpenRouter key. Any model. Local agent, zero
            servers.
          </p>
        </div>
      </div>
    </div>

    <div class="relative max-w-7xl mx-auto">
      <div
        class="absolute inset-0 bg-linear-to-br from-pink-500/10 via-transparent to-purple-500/10 blur-3xl"
      ></div>
      <div class="relative">
        <div class="mb-12">
          <div
            class="inline-block px-6 py-3 bg-pink-100/10 border-2 border-pink-400 rounded-lg mb-8"
          >
            <span class="text-3xl font-mono font-black text-pink-400">MCP</span>
          </div>
          <h2 class="text-6xl md:text-8xl font-black mb-8 leading-none">
            <span class="text-pink-400">Any MCP Server</span>
            <br />
            At Your Fingertips
          </h2>
        </div>

        <div class="grid md:grid-cols-2 gap-12 items-center relative z-10">
          <p class="text-2xl text-zinc-400 leading-relaxed">
            Connect to databases, APIs, filesystems. The agent uses tools from
            your MCP servers. Unlimited extensibility.
          </p>
          <div class="flex justify-center">
            <img
              src="/mcp.png"
              alt="mcp illustration"
              class="w-full max-w-md"
            />
          </div>
        </div>
      </div>
    </div>
  </div>

  <footer class="border-t border-zinc-900 py-20">
    <div
      class="max-w-7xl mx-auto px-4 flex flex-col md:flex-row items-center justify-between gap-8"
    >
      <div class="flex items-center gap-4">
        <img src="/logo.svg" alt="t2t" class="h-8 opacity-70 invert" />
        <span class="text-zinc-600 text-sm font-mono"
          >Open Source. MIT License.</span
        >
      </div>
      <div class="flex flex-col md:flex-row items-center gap-6">
        <div class="flex items-center gap-6">
          <a
            href="/docs"
            class="text-zinc-400 hover:text-[#00FFA3] transition-colors font-mono font-bold"
          >
            DOCS
          </a>
          <a
            href="https://github.com/acoyfellow/t2t"
            class="flex items-center gap-3 text-zinc-400 hover:text-[#00FFA3] transition-colors group"
          >
            <Github class="h-6 w-6" />
            <span class="font-mono font-bold">VIEW ON GITHUB</span>
          </a>
        </div>
        <div class="flex items-center gap-4">
          <a
            href="mailto:support@t2t.now"
            class="flex items-center gap-2 text-zinc-400 hover:text-[#00FFA3] transition-colors"
            title="Support Email"
          >
            <Mail class="h-5 w-5" />
            <span class="font-mono text-sm">support@t2t.now</span>
          </a>
          <a
            href="https://x.com/acoyfellow"
            target="_blank"
            rel="noopener noreferrer"
            class="flex items-center gap-2 text-zinc-400 hover:text-[#00FFA3] transition-colors"
            title="Follow on X"
          >
            <Twitter class="h-5 w-5" />
            <span class="font-mono text-sm">@acoyfellow</span>
          </a>
        </div>
      </div>
    </div>
  </footer>
</div>

<style>
  @keyframes pulse-slow {
    0%,
    100% {
      opacity: 1;
    }
    50% {
      opacity: 0.7;
    }
  }

  .animate-pulse-slow {
    animation: pulse-slow 3s cubic-bezier(0.4, 0, 0.6, 1) infinite;
  }
</style>
