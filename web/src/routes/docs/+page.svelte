<script lang="ts">
  import {
    ArrowLeft,
    Mic,
    Zap,
    Server,
    Settings,
    HelpCircle,
    Mail,
    Twitter,
  } from "@lucide/svelte/icons";
  import SEO from "$lib/components/SEO.svelte";

  const sections = [
    { id: "getting-started", label: "Getting Started", icon: Settings },
    { id: "typing-mode", label: "Typing Mode", icon: Mic },
    { id: "agent-mode", label: "Agent Mode", icon: Zap },
    { id: "mcp-servers", label: "MCP Servers", icon: Server },
    { id: "use-cases", label: "Use Cases", icon: HelpCircle },
    { id: "troubleshooting", label: "Troubleshooting", icon: HelpCircle },
  ];

  let activeSection = $state<string>("getting-started");

  // Section refs
  let gettingStartedRef: HTMLElement;
  let typingModeRef: HTMLElement;
  let agentModeRef: HTMLElement;
  let mcpServersRef: HTMLElement;
  let useCasesRef: HTMLElement;
  let troubleshootingRef: HTMLElement;

  // Set up intersection observers using native API
  $effect(() => {
    const refs = [
      { ref: gettingStartedRef, id: "getting-started" },
      { ref: typingModeRef, id: "typing-mode" },
      { ref: agentModeRef, id: "agent-mode" },
      { ref: mcpServersRef, id: "mcp-servers" },
      { ref: useCasesRef, id: "use-cases" },
      { ref: troubleshootingRef, id: "troubleshooting" },
    ];

    // Track which section is most visible
    const sectionVisibility = new Map<string, number>();

    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          const id = entry.target.id;
          if (id) {
            // Store intersection ratio for each section
            sectionVisibility.set(id, entry.intersectionRatio);
          }
        }

        // Find the section with the highest visibility
        let maxRatio = 0;
        let mostVisible = activeSection;

        for (const [id, ratio] of sectionVisibility.entries()) {
          if (ratio > maxRatio) {
            maxRatio = ratio;
            mostVisible = id;
          }
        }

        // Also check which section's top is closest to viewport top
        const viewportTop = window.scrollY + 100; // Account for header
        let closestSection = activeSection;
        let closestDistance = Infinity;

        for (const { ref, id } of refs) {
          if (ref) {
            const rect = ref.getBoundingClientRect();
            const sectionTop = window.scrollY + rect.top;
            const distance = Math.abs(sectionTop - viewportTop);

            // If section is above viewport top and closer, prefer it
            if (sectionTop <= viewportTop && distance < closestDistance) {
              closestDistance = distance;
              closestSection = id;
            }
          }
        }

        // Use the section that's most visible, or closest to top if none are very visible
        if (maxRatio > 0.1) {
          activeSection = mostVisible;
        } else if (closestDistance < 200) {
          activeSection = closestSection;
        }
      },
      {
        threshold: [0, 0.1, 0.2, 0.3, 0.5, 0.7, 1.0],
        rootMargin: "-100px 0px -50% 0px",
      }
    );

    for (const { ref } of refs) {
      if (ref) {
        observer.observe(ref);
      }
    }

    return () => {
      observer.disconnect();
    };
  });
</script>

<SEO
  title="Documentation - t2t"
  description="Learn how to use t2t: voice-to-text dictation and MCP-powered automation."
  keywords="t2t, documentation, voice-to-text, dictation, mcp, automation"
  path="/docs"
  section="documentation"
  tags="t2t, documentation, voice-to-text, dictation, mcp, automation"
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
        <img src="/logo.svg" alt="t2t" class="h-8" />
      </a>
    </div>
  </header>

  <div class="max-w-7xl mx-auto flex">
    <!-- Sidebar Navigation -->
    <aside
      class="hidden lg:block w-64 shrink-0 sticky top-[73px] h-[calc(100vh-73px)] overflow-y-auto border-r border-border p-6"
    >
      <nav class="space-y-1">
        {#each sections as section}
          {@const Icon = section.icon}
          <a
            href="#{section.id}"
            class="flex items-center gap-3 px-3 py-2 rounded-lg transition-colors {activeSection ===
            section.id
              ? 'bg-primary/10 text-primary outline-2'
              : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'}"
            onclick={(e) => {
              e.preventDefault();
              document.getElementById(section.id)?.scrollIntoView({
                behavior: "smooth",
                block: "start",
              });
            }}
          >
            <Icon class="w-4 h-4 shrink-0" />
            <span class="text-sm font-medium">{section.label}</span>
          </a>
        {/each}
      </nav>
    </aside>

    <!-- Content -->
    <div class="flex-1 max-w-4xl mx-auto px-6 py-12 text-balance">
      <div class="mb-12">
        <h1 class="text-6xl md:text-7xl font-black mb-4">Documentation</h1>
        <p class="text-xl text-muted-foreground">
          Learn how to get the most out of t2t
        </p>
      </div>

      <!-- Getting Started -->
      <section
        id="getting-started"
        class="mb-16 scroll-mt-20"
        bind:this={gettingStartedRef}
      >
        <div class="flex items-center gap-3 mb-6">
          <div
            class="w-12 h-12 rounded-xl bg-primary/20 flex items-center justify-center"
          >
            <Settings class="w-6 h-6 text-primary" />
          </div>
          <h2 class="text-4xl font-bold">Getting Started</h2>
        </div>

        <div class="space-y-6 text-foreground/90 prose-lg prose-invert">
          <div>
            <h3 class="font-semibold text-foreground mb-2">
              1. Download & Install
            </h3>
            <p>
              Download t2t from <a
                href="https://github.com/acoyfellow/t2t/releases"
                class="text-primary hover:underline">GitHub Releases</a
              >. On first launch, you may need to right-click and select "Open"
              if macOS shows a security warning.
            </p>
          </div>

          <div class="">
            <h3 class="text-foreground font-semibold">2. Grant Permissions</h3>
            <p class="mb-2">t2t needs two permissions:</p>
            <ul class="list-disc list-inside space-y-1 ml-4">
              <li>
                <strong>Accessibility</strong> - Required to detect the Fn key and
                paste into the correct field
              </li>
              <li>
                <strong>Microphone</strong> - Required for voice recording
              </li>
            </ul>
            <p class="mt-2 text-muted-foreground">
              The app will prompt you if permissions are missing. You can also
              grant them in System Settings.
            </p>
          </div>

          <div>
            <h3 class="text-foreground font-semibold">3. First Run</h3>
            <p>
              On first launch, t2t automatically downloads the Whisper model
              (~150MB) to your cache directory. This happens in the
              background—you'll see a notification when it's ready.
            </p>
          </div>
        </div>
      </section>

      <!-- Basic Usage: Typing Mode -->
      <section
        id="typing-mode"
        class="mb-16 scroll-mt-20"
        bind:this={typingModeRef}
      >
        <div class="flex items-center gap-3 mb-6">
          <div
            class="w-12 h-12 rounded-xl bg-primary/20 flex items-center justify-center"
          >
            <Mic class="w-6 h-6 text-primary" />
          </div>
          <h2 class="text-4xl font-bold">Typing Mode</h2>
        </div>

        <div class="space-y-6 text-foreground/90 prose-lg prose-invert">
          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              How to Use
            </h3>
            <ol class="list-decimal list-inside space-y-2 ml-4">
              <li>Focus any text field (email, notes, code editor, etc.)</li>
              <li>
                Hold the <kbd
                  class="px-2 py-1 bg-muted border border-border text-primary font-mono rounded text-sm"
                  >fn</kbd
                > key
              </li>
              <li>Speak your text</li>
              <li>
                Release <kbd
                  class="px-2 py-1 bg-muted border border-border text-primary font-mono rounded text-sm"
                  >fn</kbd
                > to transcribe and paste
              </li>
            </ol>
          </div>

          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              Visual Feedback
            </h3>
            <p class="mb-2">
              A red bar appears at the top of your screen while recording:
            </p>
            <ul class="list-disc list-inside space-y-1 ml-4">
              <li><strong>Red bar</strong> = Recording (typing mode)</li>
              <li><strong>Amber bar</strong> = Processing transcription</li>
              <li>Bar disappears when text is pasted</li>
            </ul>
          </div>

          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">Tips</h3>
            <ul class="list-disc list-inside space-y-1 ml-4">
              <li>Works in any app—no special integration needed</li>
              <li>Your clipboard is preserved (t2t saves and restores it)</li>
              <li>Speak clearly and at a normal pace for best results</li>
              <li>
                The model runs locally—your voice never leaves your computer
              </li>
            </ul>
          </div>
        </div>
      </section>

      <!-- Agent Mode -->
      <section
        id="agent-mode"
        class="mb-16 scroll-mt-20"
        bind:this={agentModeRef}
      >
        <div class="flex items-center gap-3 mb-6">
          <div
            class="w-12 h-12 rounded-xl bg-primary/20 flex items-center justify-center"
          >
            <Zap class="w-6 h-6 text-primary" />
          </div>
          <h2 class="text-4xl font-bold">Agent Mode</h2>
        </div>

        <div class="space-y-6 text-foreground/90 prose-lg prose-invert">
          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              How to Activate
            </h3>
            <p class="mb-2">
              Hold <kbd
                class="px-2 py-1 bg-muted border border-border text-primary font-mono rounded text-sm"
                >fn</kbd
              >
              +
              <kbd
                class="px-2 py-1 bg-muted border border-border text-primary font-mono rounded text-sm"
                >ctrl</kbd
              >
              (or
              <kbd
                class="px-2 py-1 bg-muted border border-border text-primary font-mono rounded text-sm"
                >fn</kbd
              >
              +
              <kbd
                class="px-2 py-1 bg-muted border border-border text-primary font-mono rounded text-sm"
                >cmd</kbd
              > on macOS) to enter agent mode.
            </p>
            <p class="text-sm text-muted-foreground">
              A cyan bar appears while recording in agent mode.
            </p>
          </div>

          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              What It Does
            </h3>
            <p class="mb-2">
              Agent mode uses AI to understand your voice command and execute
              actions:
            </p>
            <ul class="list-disc list-inside space-y-1 ml-4">
              <li>
                <strong>With MCP servers</strong>: Connects to your configured
                MCP servers and uses their tools
              </li>
              <li>
                <strong>Without MCP servers</strong>: Generates and executes
                AppleScript for macOS automation
              </li>
            </ul>
          </div>

          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              Setup Required
            </h3>
            <p class="mb-2">Agent mode requires an OpenRouter API key:</p>
            <ol class="list-decimal list-inside space-y-1 ml-4">
              <li>
                Get a free API key from <a
                  href="https://openrouter.ai"
                  class="text-primary hover:underline">openrouter.ai</a
                >
              </li>
              <li>Open t2t settings (menu bar icon → View Settings)</li>
              <li>Add your OpenRouter API key in the Settings tab</li>
              <li>Optionally select your preferred AI model</li>
            </ol>
          </div>

          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              Example Commands
            </h3>
            <ul class="list-disc list-inside space-y-1 ml-4">
              <li>"Open Slack"</li>
              <li>"Create a new note in Obsidian"</li>
              <li>"Search my database for users created this week"</li>
              <li>"Send a notification saying meeting in 5 minutes"</li>
            </ul>
          </div>
        </div>
      </section>

      <!-- MCP Servers -->
      <section
        id="mcp-servers"
        class="mb-16 scroll-mt-20"
        bind:this={mcpServersRef}
      >
        <div class="flex items-center gap-3 mb-6">
          <div
            class="w-12 h-12 rounded-xl bg-primary/20 flex items-center justify-center"
          >
            <Server class="w-6 h-6 text-primary" />
          </div>
          <h2 class="text-4xl font-bold">MCP Servers</h2>
        </div>

        <div class="space-y-6 text-foreground/90 prose-lg prose-invert">
          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              What Are MCP Servers?
            </h3>
            <p>
              MCP (Model Context Protocol) servers provide tools and
              capabilities that extend what the AI agent can do. Instead of
              hardcoding integrations, you connect to MCP servers that expose
              their own tools.
            </p>
          </div>

          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              Why Use MCP?
            </h3>
            <ul class="list-disc list-inside space-y-1 ml-4">
              <li>
                <strong>Extensible</strong> - Connect to databases, APIs, file systems,
                or any MCP-compatible service
              </li>
              <li>
                <strong>Unlimited possibilities</strong> - Each server adds new tools
                the agent can use
              </li>
              <li>
                <strong>Multiple servers</strong> - Connect to as many as you want
                simultaneously
              </li>
              <li>
                <strong>Local execution</strong> - All tool execution happens on
                your computer
              </li>
            </ul>
          </div>

          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              How to Configure
            </h3>
            <ol class="list-decimal list-inside space-y-2 ml-4">
              <li>Open t2t settings (menu bar icon → View Settings)</li>
              <li>Go to the "Settings" tab</li>
              <li>Click "New MCP Server"</li>
              <li>
                Fill in the details:
                <ul class="list-disc list-inside ml-6 mt-2 space-y-1 text-sm">
                  <li>
                    <strong>Name</strong> - A friendly name for the server
                  </li>
                  <li>
                    <strong>Transport</strong> - stdio (for local commands) or HTTP/HTTPS
                    (for remote servers)
                  </li>
                  <li>
                    <strong>Command/URL</strong> - The command to run (stdio) or
                    URL to connect to (HTTP)
                  </li>
                  <li>
                    <strong>Args</strong> - Command-line arguments (for stdio transport)
                  </li>
                </ul>
              </li>
              <li>Toggle the server on to enable it</li>
            </ol>
          </div>

          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              Common Examples
            </h3>
            <div
              class="bg-muted/50 border border-border rounded-lg p-4 space-y-3"
            >
              <div>
                <p class="font-semibold text-foreground mb-1">
                  Database Server (stdio)
                </p>
                <p class="text-sm">
                  <code class="text-primary"
                    >npx @modelcontextprotocol/server-postgres</code
                  >
                </p>
              </div>
              <div>
                <p class="font-semibold text-foreground mb-1">
                  File System Server (stdio)
                </p>
                <p class="text-sm">
                  <code class="text-primary"
                    >npx @modelcontextprotocol/server-filesystem</code
                  >
                </p>
              </div>
              <div>
                <p class="font-semibold text-foreground mb-1">
                  Remote API Server (HTTP)
                </p>
                <p class="text-sm">
                  <code class="text-primary"
                    >https://your-mcp-server.com/api</code
                  >
                </p>
              </div>
            </div>
          </div>

          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              Transport Types
            </h3>
            <ul class="list-disc list-inside space-y-2 ml-4">
              <li>
                <strong>stdio</strong> - Spawns a local process (e.g., `npx` commands).
                Best for local tools.
              </li>
              <li>
                <strong>HTTP/HTTPS</strong> - Connects to a remote server via HTTP.
                Best for remote APIs.
              </li>
            </ul>
          </div>
        </div>
      </section>

      <!-- Use Cases -->
      <section
        id="use-cases"
        class="mb-16 scroll-mt-20"
        bind:this={useCasesRef}
      >
        <div class="flex items-center gap-3 mb-6">
          <div
            class="w-12 h-12 rounded-xl bg-primary/20 flex items-center justify-center"
          >
            <HelpCircle class="w-6 h-6 text-primary" />
          </div>
          <h2 class="text-4xl font-bold">Use Cases</h2>
        </div>

        <div class="space-y-6 text-foreground/90 prose-lg prose-invert">
          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              Voice Dictation
            </h3>
            <p>Use typing mode to quickly input text anywhere:</p>
            <ul class="list-disc list-inside space-y-1 ml-4 mt-2">
              <li>Writing emails, messages, or documents</li>
              <li>Coding comments and documentation</li>
              <li>Taking notes during meetings</li>
              <li>Filling out forms</li>
            </ul>
          </div>

          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              Automation with MCP
            </h3>
            <p>Connect MCP servers to automate complex workflows:</p>
            <ul class="list-disc list-inside space-y-1 ml-4 mt-2">
              <li>Query databases: "Show me all users created this week"</li>
              <li>
                File operations: "Create a new file in my project with this
                content"
              </li>
              <li>API interactions: "Fetch the latest data from my API"</li>
              <li>Custom tools: Connect to any service that supports MCP</li>
            </ul>
          </div>

          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              macOS Automation
            </h3>
            <p>
              Without MCP servers, agent mode uses AppleScript for macOS
              automation:
            </p>
            <ul class="list-disc list-inside space-y-1 ml-4 mt-2">
              <li>Opening applications</li>
              <li>System notifications</li>
              <li>Basic app control</li>
            </ul>
          </div>
        </div>
      </section>

      <!-- Troubleshooting -->
      <section
        id="troubleshooting"
        class="mb-16 scroll-mt-20"
        bind:this={troubleshootingRef}
      >
        <div class="flex items-center gap-3 mb-6">
          <div
            class="w-12 h-12 rounded-xl bg-primary/20 flex items-center justify-center"
          >
            <HelpCircle class="w-6 h-6 text-primary" />
          </div>
          <h2 class="text-4xl font-bold">Troubleshooting</h2>
        </div>

        <div class="space-y-6 text-foreground/90 prose-lg prose-invert">
          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              Permissions Not Working
            </h3>
            <p class="mb-2">
              If t2t isn't detecting the Fn key or can't paste:
            </p>
            <ol class="list-decimal list-inside space-y-1 ml-4">
              <li>
                Check System Settings → Privacy & Security → Accessibility
              </li>
              <li>Ensure t2t is enabled</li>
              <li>Restart t2t after granting permissions</li>
            </ol>
          </div>

          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              Model Not Downloading
            </h3>
            <p class="mb-2">If the Whisper model isn't downloading:</p>
            <ul class="list-disc list-inside space-y-1 ml-4">
              <li>Check your internet connection</li>
              <li>Verify disk space (model is ~150MB)</li>
              <li>
                Check logs at <code class="text-primary text-sm"
                  >~/Library/Logs/t2t.log</code
                >
              </li>
            </ul>
          </div>

          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              MCP Server Connection Failed
            </h3>
            <p class="mb-2">If an MCP server won't connect:</p>
            <ul class="list-disc list-inside space-y-1 ml-4">
              <li>Verify the command/URL is correct</li>
              <li>
                For stdio: Ensure the command is available in your PATH (e.g.,
                `npx` is installed)
              </li>
              <li>For HTTP: Check the URL is accessible</li>
              <li>
                Check the server status in settings (red = error, yellow =
                loading, green = active)
              </li>
              <li>Review error messages in the settings UI</li>
            </ul>
          </div>

          <div>
            <h3 class="text-xl font-semibold text-foreground mb-2">
              Agent Mode Not Working
            </h3>
            <p class="mb-2">If agent mode doesn't respond:</p>
            <ul class="list-disc list-inside space-y-1 ml-4">
              <li>Verify your OpenRouter API key is set in settings</li>
              <li>Check that you're holding fn+ctrl (or fn+cmd on macOS)</li>
              <li>Look for error notifications</li>
              <li>
                Check logs at <code class="text-primary text-sm"
                  >~/Library/Logs/t2t.log</code
                >
              </li>
            </ul>
          </div>
        </div>
      </section>

      <!-- Footer -->
      <div class="border-t border-border pt-8 mt-16">
        <div class="flex flex-col items-center gap-4">
          <p class="text-center text-muted-foreground text-sm">
            Need more help?
          </p>
          <div class="flex items-center gap-6">
            <a
              href="mailto:support@t2t.now"
              class="flex items-center gap-2 text-muted-foreground hover:text-primary transition-colors"
            >
              <Mail class="h-5 w-5" />
              <span class="font-mono text-sm">support@t2t.now</span>
            </a>
            <a
              href="https://x.com/acoyfellow"
              target="_blank"
              rel="noopener noreferrer"
              class="flex items-center gap-2 text-muted-foreground hover:text-primary transition-colors"
            >
              <Twitter class="h-5 w-5" />
              <span class="font-mono text-sm">@acoyfellow</span>
            </a>
            <a
              href="https://github.com/acoyfellow/t2t"
              target="_blank"
              rel="noopener noreferrer"
              class="text-muted-foreground hover:text-primary transition-colors text-sm"
            >
              GitHub Issues
            </a>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
