import "../../chunks/async.js";
import { w as attributes, x as clsx, y as ensure_array_like, z as element, F as spread_props, G as head, J as attr_style, K as attr } from "../../chunks/index.js";
import { k as escape_html } from "../../chunks/context.js";
const defaultAttributes = {
  xmlns: "http://www.w3.org/2000/svg",
  width: 24,
  height: 24,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  "stroke-width": 2,
  "stroke-linecap": "round",
  "stroke-linejoin": "round"
};
function Icon($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    const {
      name,
      color = "currentColor",
      size = 24,
      strokeWidth = 2,
      absoluteStrokeWidth = false,
      iconNode = [],
      children,
      $$slots,
      $$events,
      ...props
    } = $$props;
    $$renderer2.push(`<svg${attributes(
      {
        ...defaultAttributes,
        ...props,
        width: size,
        height: size,
        stroke: color,
        "stroke-width": absoluteStrokeWidth ? Number(strokeWidth) * 24 / Number(size) : strokeWidth,
        class: clsx(["lucide-icon lucide", name && `lucide-${name}`, props.class])
      },
      void 0,
      void 0,
      void 0,
      3
    )}><!--[-->`);
    const each_array = ensure_array_like(iconNode);
    for (let $$index = 0, $$length = each_array.length; $$index < $$length; $$index++) {
      let [tag, attrs] = each_array[$$index];
      element($$renderer2, tag, () => {
        $$renderer2.push(`${attributes({ ...attrs }, void 0, void 0, void 0, 3)}`);
      });
    }
    $$renderer2.push(`<!--]-->`);
    children?.($$renderer2);
    $$renderer2.push(`<!----></svg>`);
  });
}
function Github($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let { $$slots, $$events, ...props } = $$props;
    const iconNode = [
      [
        "path",
        {
          "d": "M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"
        }
      ],
      ["path", { "d": "M9 18c-4.51 2-5-2-7-2" }]
    ];
    Icon($$renderer2, spread_props([
      { name: "github" },
      /**
       * @component @name Github
       * @description Lucide SVG icon component, renders SVG Element with children.
       *
       * @preview ![img](data:image/svg+xml;base64,PHN2ZyAgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIgogIHdpZHRoPSIyNCIKICBoZWlnaHQ9IjI0IgogIHZpZXdCb3g9IjAgMCAyNCAyNCIKICBmaWxsPSJub25lIgogIHN0cm9rZT0iIzAwMCIgc3R5bGU9ImJhY2tncm91bmQtY29sb3I6ICNmZmY7IGJvcmRlci1yYWRpdXM6IDJweCIKICBzdHJva2Utd2lkdGg9IjIiCiAgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIgogIHN0cm9rZS1saW5lam9pbj0icm91bmQiCj4KICA8cGF0aCBkPSJNMTUgMjJ2LTRhNC44IDQuOCAwIDAgMC0xLTMuNWMzIDAgNi0yIDYtNS41LjA4LTEuMjUtLjI3LTIuNDgtMS0zLjUuMjgtMS4xNS4yOC0yLjM1IDAtMy41IDAgMC0xIDAtMyAxLjUtMi42NC0uNS01LjM2LS41LTggMEM2IDIgNSAyIDUgMmMtLjMgMS4xNS0uMyAyLjM1IDAgMy41QTUuNDAzIDUuNDAzIDAgMCAwIDQgOWMwIDMuNSAzIDUuNSA2IDUuNS0uMzkuNDktLjY4IDEuMDUtLjg1IDEuNjUtLjE3LjYtLjIyIDEuMjMtLjE1IDEuODV2NCIgLz4KICA8cGF0aCBkPSJNOSAxOGMtNC41MSAyLTUtMi03LTIiIC8+Cjwvc3ZnPgo=) - https://lucide.dev/icons/github
       * @see https://lucide.dev/guide/packages/lucide-svelte - Documentation
       *
       * @param {Object} props - Lucide icons props and any valid SVG attribute
       * @returns {FunctionalComponent} Svelte component
       * @deprecated Brand icons have been deprecated and are due to be removed, please refer to https://github.com/lucide-icons/lucide/issues/670. We recommend using https://simpleicons.org/?q=github instead. This icon will be removed in v1.0
       */
      props,
      {
        iconNode,
        children: ($$renderer3) => {
          props.children?.($$renderer3);
          $$renderer3.push(`<!---->`);
        },
        $$slots: { default: true }
      }
    ]));
  });
}
function Download($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let { $$slots, $$events, ...props } = $$props;
    const iconNode = [
      ["path", { "d": "M12 15V3" }],
      ["path", { "d": "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" }],
      ["path", { "d": "m7 10 5 5 5-5" }]
    ];
    Icon($$renderer2, spread_props([
      { name: "download" },
      /**
       * @component @name Download
       * @description Lucide SVG icon component, renders SVG Element with children.
       *
       * @preview ![img](data:image/svg+xml;base64,PHN2ZyAgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIgogIHdpZHRoPSIyNCIKICBoZWlnaHQ9IjI0IgogIHZpZXdCb3g9IjAgMCAyNCAyNCIKICBmaWxsPSJub25lIgogIHN0cm9rZT0iIzAwMCIgc3R5bGU9ImJhY2tncm91bmQtY29sb3I6ICNmZmY7IGJvcmRlci1yYWRpdXM6IDJweCIKICBzdHJva2Utd2lkdGg9IjIiCiAgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIgogIHN0cm9rZS1saW5lam9pbj0icm91bmQiCj4KICA8cGF0aCBkPSJNMTIgMTVWMyIgLz4KICA8cGF0aCBkPSJNMjEgMTV2NGEyIDIgMCAwIDEtMiAySDVhMiAyIDAgMCAxLTItMnYtNCIgLz4KICA8cGF0aCBkPSJtNyAxMCA1IDUgNS01IiAvPgo8L3N2Zz4K) - https://lucide.dev/icons/download
       * @see https://lucide.dev/guide/packages/lucide-svelte - Documentation
       *
       * @param {Object} props - Lucide icons props and any valid SVG attribute
       * @returns {FunctionalComponent} Svelte component
       *
       */
      props,
      {
        iconNode,
        children: ($$renderer3) => {
          props.children?.($$renderer3);
          $$renderer3.push(`<!---->`);
        },
        $$slots: { default: true }
      }
    ]));
  });
}
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    const GITHUB_RELEASES_URL = "https://github.com/acoyfellow/t2t/releases";
    let mousePosition = { x: 0, y: 0 };
    const mcpTags = [
      "Databases",
      "APIs",
      "File Systems",
      "Custom Tools",
      "Any Server",
      "Infinite Power"
    ];
    head("1uha8ag", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>t2t - Talk to Type</title>`);
      });
      $$renderer3.push(`<meta name="description" content="Voice-to-text with intelligence. Hold fn to talk, hold fn+ctrl to command." class="svelte-1uha8ag"/>`);
    });
    $$renderer2.push(`<img src="/cluster.jpg" alt="cluster illustration" class="w-full -mt-10 z-0 -mb-40 svelte-1uha8ag"/> <div class="min-h-screen bg-black text-white overflow-hidden svelte-1uha8ag"><div class="relative min-h-screen flex flex-col items-center justify-center px-4 py-20 svelte-1uha8ag"><div class="absolute inset-0 opacity-30 blur-[100px] pointer-events-none transition-all duration-500 svelte-1uha8ag"${attr_style(`background: radial-gradient(600px circle at ${mousePosition.x}% ${mousePosition.y}%, rgba(0, 255, 163, 0.4), transparent 40%);`)}></div> <div class="relative z-10 max-w-7xl mx-auto text-center space-y-16 svelte-1uha8ag"><div class="bg-gray/10 p-4 rounded-lg svelte-1uha8ag"><img src="/logo.svg" alt="t2t" class="h-16 md:h-20 mx-auto opacity-30 invert svelte-1uha8ag"/></div> <div class="relative svelte-1uha8ag"><h1 class="text-[clamp(3rem,15vw,12rem)] font-black leading-[0.85] tracking-tighter text-balance svelte-1uha8ag"><span class="block bg-linear-to-br from-white via-white to-zinc-400 bg-clip-text text-transparent svelte-1uha8ag">HOLD</span> <span class="block text-[#00FFA3] animate-pulse-slow svelte-1uha8ag">fn</span> <span class="block bg-linear-to-br from-white via-zinc-300 to-zinc-600 bg-clip-text text-transparent svelte-1uha8ag">TO SPEAK</span></h1></div> <p class="text-xl md:text-3xl text-zinc-400 max-w-3xl mx-auto font-light tracking-wide text-balance svelte-1uha8ag">Voice becomes text. Instantly. Anywhere on macOS.</p> <div class="flex flex-col sm:flex-row gap-4 items-center justify-center pt-8 svelte-1uha8ag"><a${attr("href", GITHUB_RELEASES_URL)} class="group relative px-10 py-5 bg-[#00FFA3] text-black text-lg font-bold rounded-none hover:bg-[#00FF8F] transition-all duration-200 hover:scale-105 hover:shadow-[0_0_40px_rgba(0,255,163,0.4)] svelte-1uha8ag">`);
    Download($$renderer2, { class: "inline-block mr-2 h-5 w-5" });
    $$renderer2.push(`<!----> Download for macOS</a> <a href="https://github.com/acoyfellow/t2t" class="px-10 py-5 border-2 border-zinc-700 text-white text-lg font-bold rounded-none hover:border-[#00FFA3] hover:text-[#00FFA3] transition-all duration-200 bg-black svelte-1uha8ag">`);
    Github($$renderer2, { class: "inline-block mr-2 h-5 w-5" });
    $$renderer2.push(`<!----> View Source</a></div></div> <div class="absolute bottom-12 left-1/2 -translate-x-1/2 svelte-1uha8ag"><div class="w-px h-20 bg-linear-to-b from-zinc-700 to-transparent bg-clip-padding svelte-1uha8ag"></div></div></div> <div class="relative py px-4 svelte-1uha8ag"><div class="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-size-[100px_100px] mask-[radial-gradient(ellipse_at_center,black,transparent_80%)] svelte-1uha8ag"></div> <div class="relative max-w-5xl mx-auto svelte-1uha8ag"><div class="mb-48 svelte-1uha8ag"><div class="grid lg:grid-cols-2 gap-16 items-center svelte-1uha8ag"><div class="order-2 lg:order-1 svelte-1uha8ag"><h2 class="text-6xl md:text-8xl font-black mb-8 leading-none svelte-1uha8ag">Talk <br class="svelte-1uha8ag"/> <span class="text-[#00FFA3] svelte-1uha8ag">to type</span></h2> <p class="text-2xl text-zinc-400 leading-relaxed svelte-1uha8ag">Hold  <kbd class="px-3 py-1 bg-zinc-900 border-2 border-[#00FFA3] text-[#00FFA3] font-mono rounded svelte-1uha8ag">fn</kbd> 
              anywhere. Your voice becomes text. No apps. No setup. No friction.</p></div> <div class="order-1 lg:order-2 flex justify-center svelte-1uha8ag"><img src="/fn.jpg" alt="fn key illustration" class="w-full max-w-md svelte-1uha8ag"/></div></div></div> <div class="mb-48 svelte-1uha8ag"><div class="grid lg:grid-cols-2 gap-16 items-center svelte-1uha8ag"><div class="flex justify-center svelte-1uha8ag"><img src="/fn+control.jpg" alt="fn+ctrl keys illustration" class="w-full max-w-md svelte-1uha8ag"/></div> <div class="svelte-1uha8ag"><h2 class="text-6xl md:text-8xl font-black mb-8 leading-none svelte-1uha8ag">Command <br class="svelte-1uha8ag"/> <span class="text-purple-400 svelte-1uha8ag">an agent</span></h2> <p class="text-2xl text-zinc-400 leading-relaxed svelte-1uha8ag">Hold  <kbd class="px-3 py-1 bg-zinc-900 border-2 border-purple-500 text-purple-400 font-mono rounded svelte-1uha8ag">fn+ctrl</kbd> 
              to speak commands. With MCP servers configured, the agent uses their
              tools. Otherwise, it generates AppleScript. Your choice, same two keys.</p></div></div></div> <div class="relative svelte-1uha8ag"><div class="absolute inset-0 bg-linear-to-br from-pink-500/10 via-transparent to-purple-500/10 blur-3xl svelte-1uha8ag"></div> <div class="relative svelte-1uha8ag"><div class="mb-12 svelte-1uha8ag"><div class="inline-block px-6 py-3 bg-pink-100/10 border-2 border-pink-400 rounded-lg mb-8 svelte-1uha8ag"><span class="text-3xl font-mono font-black text-pink-400 svelte-1uha8ag">MCP</span></div> <h2 class="text-6xl md:text-8xl font-black mb-8 leading-none svelte-1uha8ag"><span class="text-pink-400 svelte-1uha8ag">Talk to any</span> <br class="svelte-1uha8ag"/> MCP Server</h2> <p class="text-3xl md:text-4xl text-zinc-400 mb-12 max-w-4xl leading-relaxed svelte-1uha8ag">Press  <kbd class="px-4 py-2 bg-zinc-900 border-2 border-pink-400 text-pink-400 font-mono rounded text-2xl svelte-1uha8ag">fn+ctrl</kbd> 
              and speak. The agent connects to your MCP servers and executes tools.
              No code. No complexity. Just works.</p></div> <div class="grid md:grid-cols-2 gap-12 items-center relative z-10 svelte-1uha8ag"><div class="space-y-6 svelte-1uha8ag"><p class="text-2xl text-zinc-400 leading-relaxed svelte-1uha8ag">Connect databases, APIs, filesystems, or any MCP-compatible
                service. Configure once in settings, then control everything
                with your voice.</p> <div class="flex flex-wrap gap-3 pt-4 svelte-1uha8ag"><!--[-->`);
    const each_array = ensure_array_like(mcpTags);
    for (let $$index = 0, $$length = each_array.length; $$index < $$length; $$index++) {
      let tag = each_array[$$index];
      $$renderer2.push(`<span class="px-5 py-3 bg-zinc-900 border border-zinc-700 hover:border-pink-400 hover:text-pink-400 rounded text-sm font-bold uppercase tracking-wider transition-all cursor-default svelte-1uha8ag">${escape_html(tag)}</span>`);
    }
    $$renderer2.push(`<!--]--></div></div> <div class="flex justify-center svelte-1uha8ag"><img src="/mcp.jpg" alt="mcp illustration" class="w-full max-w-md svelte-1uha8ag"/></div></div></div></div></div></div> <footer class="border-t border-zinc-900 py-20 svelte-1uha8ag"><div class="max-w-7xl mx-auto px-4 flex flex-col md:flex-row items-center justify-between gap-8 svelte-1uha8ag"><div class="flex items-center gap-4 svelte-1uha8ag"><img src="/logo.svg" alt="t2t" class="h-8 opacity-70 invert svelte-1uha8ag"/> <span class="text-zinc-600 text-sm font-mono svelte-1uha8ag">Open Source. MIT License.</span></div> <a href="https://github.com/acoyfellow/t2t" class="flex items-center gap-3 text-zinc-400 hover:text-[#00FFA3] transition-colors group svelte-1uha8ag">`);
    Github($$renderer2, { class: "h-6 w-6" });
    $$renderer2.push(`<!----> <span class="font-mono font-bold svelte-1uha8ag">VIEW ON GITHUB</span></a></div></footer></div>`);
  });
}
export {
  _page as default
};
