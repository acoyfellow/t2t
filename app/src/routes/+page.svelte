<script lang="ts">
  const GITHUB_RELEASES_URL = "https://github.com/acoyfellow/t2t/releases";
  import Github from "@lucide/svelte/icons/github";
  import Download from "@lucide/svelte/icons/download";
</script>

<svelte:head>
  <title>t2t - Talk to Type</title>
  <meta
    name="description"
    content="Voice-to-text with intelligence. Hold fn to talk, hold fn+ctrl to command."
  />
</svelte:head>

<div class="min-h-screen bg-white">
  <!-- Hero Section -->
  <div class="flex flex-col items-center justify-center py-20 px-4">
    <!-- Logo -->
    <img src="/logo.svg" alt="t2t" class="h-16 mb-8" />

    <!-- Main Heading -->
    <h1 class="text-5xl md:text-6xl font-bold text-black mb-4 text-center">
      Talk to type
    </h1>

    <!-- Tagline -->
    <p
      class="text-lg md:text-xl text-black mb-8 text-center max-w-xl text-balance"
    >
      Voice-to-text with intelligence. Hold fn to talk, hold fn+ctrl to command.
    </p>

    <!-- Download Button -->
    <a
      href={GITHUB_RELEASES_URL}
      class="inline-flex items-center gap-2 bg-black text-white px-8 py-4 rounded-lg font-semibold hover:bg-gray-800 transition-colors"
    >
      <Download />
      Download for macOS
    </a>
  </div>

  <!-- Divider -->
  <div class="border-t border-gray-200"></div>

  <!-- Features Section -->
  <div class="max-w-xl mx-auto px-4 py-16 prose-xl">
    <div class="grid md:grid-cols-2 gap-8">
      <!-- fn - Talk to Type -->
      <div class="space-y-6">
        <div
          class="inline-flex px-4 py-6 bg-gray-100 rounded text-3xl font-bold text-black font-mono leading-1 border-[0.5px] border-gray-300"
        >
          <span>fn</span>
        </div>
        <h2 class="text-2xl font-bold text-black">Talk to type</h2>
        <p class="text-black">
          Hold the fn key anywhere in macOS to instantly convert your voice to
          text. No setup, no complexity.
        </p>
      </div>

      <!-- fn+ctrl - Talk to an Agent -->
      <div class="space-y-6">
        <div
          class="inline-flex px-4 py-6 bg-gray-100 rounded text-3xl font-bold text-black font-mono leading-1 border-[0.5px] border-gray-300"
        >
          <span>fn+ctrl</span>
        </div>
        <h2 class="text-2xl font-bold text-black">Talk to an agent</h2>
        <p class="text-black">
          Hold fn+ctrl to speak commands to an AI agent that generates and
          executes AppleScript. Automate anything.
        </p>
      </div>
    </div>
  </div>

  <div class="text-center py-20">
    <a
      href="https://github.com/acoyfellow/t2t"
      class="mt-6 inline-flex items-center gap-2 text-black hover:text-gray-700 transition-colors border border-gray-200 px-4 py-2 rounded-lg font-medium shadow"
      aria-label="View on GitHub"
    >
      <Github />
      View on GitHub
    </a>
  </div>
</div>
