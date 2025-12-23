<script lang="ts">
  import { onMount } from "svelte";

  let loading = $state(true);
  let totalWords = $state(0);
  let lifetimeWpm = $state(0);
  let sessionAvgWpm = $state(0);
  let sessions = $state(0);
  let hoursActive = $state(0);
  let recent = $state<number[]>([]);

  const HOUR_MS = 3600 * 1000;

  const cardBase =
    "rounded-[18px] p-[clamp(16px,2.2vw,22px)] border border-[rgba(255,255,255,0.06)] shadow-[0_10px_30px_rgba(0,0,0,0.45)] bg-[radial-gradient(1200px_600px_at_20%_0%,rgba(140,120,255,0.08),transparent_50%),rgba(10,10,14,0.7)]";
  const cardSmall = `${cardBase} p-[18px_20px]`;
  const cardChart = `${cardBase} p-[18px_20px_22px] flex flex-col gap-[14px]`;

  const gridGap = "gap-[clamp(10px,1.5vw,18px)]";

  const iconWrap =
    "w-11 h-11 rounded-xl grid place-items-center bg-[rgba(140,120,255,0.12)] border border-[rgba(140,120,255,0.18)] text-[rgba(180,160,255,0.95)]";
  const tagClass =
    "px-3 py-1.5 rounded-[10px] bg-[rgba(140,120,255,0.14)] border border-[rgba(140,120,255,0.18)] text-[rgba(210,200,255,0.9)] font-bold text-xs";

  const labelBase =
    "text-[13px] font-semibold tracking-[0.08em] uppercase text-[rgba(233,233,238,0.62)]";

  function buildLast48Hours(hourly: Array<[number, number]>): number[] {
    const nowHour = Math.floor(Date.now() / HOUR_MS);
    const out = Array.from({ length: 48 }, () => 0);
    for (const [h, w] of hourly) {
      const offset = h - nowHour;
      if (offset < -47 || offset > 0) continue;
      out[47 + offset] = w;
    }
    return out;
  }

  onMount(async () => {
    try {
      // Use global Tauri API since withGlobalTauri: true
      if (!window.__TAURI__?.store) {
        console.error("Tauri store API not available");
        loading = false;
        return;
      }

      const { load } = window.__TAURI__.store;
      const store = await load("stats.json", { autoSave: true });

      // get() returns a Promise - must await
      const totalWordsVal = ((await store.get("total_words")) ?? 0) as number;
      const totalSeconds = ((await store.get("total_seconds")) ?? 0) as number;
      const sessionCount = ((await store.get("session_count")) ?? 0) as number;
      const sessionWpmSum = ((await store.get("session_wpm_sum")) ??
        0) as number;
      const activityHourly = ((await store.get("activity_hourly")) ??
        []) as Array<[number, number]>;

      totalWords = totalWordsVal;
      sessions = sessionCount;
      hoursActive = totalSeconds / 3600;
      recent = buildLast48Hours(activityHourly);

      // Lifetime avg WPM = total_words / (total_seconds / 60)
      if (totalSeconds > 0) {
        lifetimeWpm = totalWordsVal / (totalSeconds / 60);
      }

      // Session avg WPM = session_wpm_sum / session_count
      if (sessionCount > 0) {
        sessionAvgWpm = sessionWpmSum / sessionCount;
      }
    } catch (e) {
      console.error("Failed to load stats:", e);
    } finally {
      loading = false;
    }
  });
</script>

<div
  class="min-h-screen w-full box-border p-[clamp(14px,2.5vw,28px)] flex flex-col gap-[clamp(12px,2vw,18px)]"
>
  <header class="flex items-start justify-between gap-4">
    <div>
      <div class="text-[clamp(36px,6vw,56px)] font-extrabold tracking-[-0.02em] leading-none">
        t2t
      </div>
      <div class="mt-1.5 text-[clamp(14px,2.2vw,18px)] text-[rgba(233,233,238,0.68)]">
        Voice transcription analytics
      </div>
    </div>
    <div
      class="inline-flex items-center gap-2.5 px-3.5 py-2.5 rounded-full border border-[rgba(140,120,255,0.25)] bg-[rgba(30,26,55,0.35)] text-[rgba(210,210,255,0.9)] font-semibold whitespace-nowrap"
    >
      <span
        class="w-2.5 h-2.5 rounded-full bg-[rgba(140,120,255,0.95)] shadow-[0_0_18px_rgba(140,120,255,0.65)]"
      ></span>
      <span>Ready</span>
    </div>
  </header>

  {#if loading}
    <div class="flex-1 grid place-items-center text-[rgba(233,233,238,0.7)]">
      Loading…
    </div>
  {:else}
    <section class={`grid ${gridGap} grid-cols-3 [@media(max-width:900px)]:grid-cols-1`}>
      <div class={cardBase}>
        <div class="flex items-center justify-between mb-[18px]">
          <div class={iconWrap}>
            <svg class="w-[22px] h-[22px]" viewBox="0 0 24 24" fill="none">
              <path
                d="M3 12h4l2-6 4 12 2-6h6"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
            </svg>
          </div>
        </div>
        <div class={labelBase}>Total Words</div>
        <div class="mt-2.5 text-[clamp(44px,5vw,64px)] font-extrabold tracking-[-0.02em] leading-none">
          {totalWords.toLocaleString()}
        </div>
      </div>

      <div class={cardBase}>
        <div class="flex items-center justify-between mb-[18px]">
          <div class={iconWrap}>
            <svg class="w-[22px] h-[22px]" viewBox="0 0 24 24" fill="none">
              <path
                d="M13 2 3 14h8l-1 8 10-12h-8l1-8Z"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
            </svg>
          </div>
        </div>
        <div class={labelBase}>Lifetime Avg</div>
        <div class="mt-2.5 text-[clamp(44px,5vw,64px)] font-extrabold tracking-[-0.02em] leading-none">
          {lifetimeWpm.toFixed(1)}
          <span class="text-[18px] font-bold text-[rgba(233,233,238,0.55)] ml-2">WPM</span>
        </div>
      </div>

      <div class={cardBase}>
        <div class="flex items-center justify-between mb-[18px]">
          <div class={iconWrap}>
            <svg class="w-[22px] h-[22px]" viewBox="0 0 24 24" fill="none">
              <path
                d="M12 14a3 3 0 0 0 3-3V6a3 3 0 0 0-6 0v5a3 3 0 0 0 3 3Z"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
              <path
                d="M19 11a7 7 0 0 1-14 0"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
            </svg>
          </div>
          <div class={tagClass}>Active</div>
        </div>
        <div class={labelBase}>Session Avg</div>
        <div class="mt-2.5 text-[clamp(44px,5vw,64px)] font-extrabold tracking-[-0.02em] leading-none">
          {sessionAvgWpm.toFixed(1)}
          <span class="text-[18px] font-bold text-[rgba(233,233,238,0.55)] ml-2">WPM</span>
        </div>
      </div>
    </section>

    <section class={`grid ${gridGap} grid-cols-2 [@media(max-width:900px)]:grid-cols-1`}>
      <div class={cardSmall}>
        <div class={`${labelBase} tracking-[0.12em]`}>Sessions</div>
        <div class="mt-2.5 text-[clamp(24px,3vw,34px)] font-extrabold">
          {sessions.toLocaleString()}
        </div>
      </div>
      <div class={cardSmall}>
        <div class={`${labelBase} tracking-[0.12em]`}>Hours Active</div>
        <div class="mt-2.5 text-[clamp(24px,3vw,34px)] font-extrabold">
          {hoursActive.toFixed(1)}h
        </div>
      </div>
    </section>

    <section class={cardChart}>
      <div class={labelBase}>Recent Activity</div>
      <div
        class="grid grid-cols-48 gap-1.5 items-end h-[clamp(120px,22vh,200px)]"
        aria-label="Recent activity"
      >
        {#each recent as v, i (i)}
          <div class="h-full flex items-end">
            <div
              class="w-full rounded-[10px_10px_6px_6px] bg-linear-to-t from-[rgba(120,100,255,0.55)] to-[rgba(170,140,255,0.85)] shadow-[0_0_18px_rgba(140,120,255,0.22)] opacity-95"
              style={`height:${Math.max(
                2,
                Math.round((v / Math.max(1, Math.max(...recent))) * 100)
              )}%`}
            ></div>
          </div>
        {/each}
      </div>
    </section>
  {/if}
</div>
