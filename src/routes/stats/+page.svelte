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

<div class="wrap">
  <header class="header">
    <div>
      <div class="title">t2t</div>
      <div class="subtitle">Voice transcription analytics</div>
    </div>
    <div class="pill">
      <span class="dot"></span>
      <span>Ready</span>
    </div>
  </header>

  {#if loading}
    <div class="loading">Loading…</div>
  {:else}
    <section class="grid top">
      <div class="card">
        <div class="cardTop">
          <div class="icon">
            <svg viewBox="0 0 24 24" fill="none">
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
        <div class="label">Total Words</div>
        <div class="big">{totalWords.toLocaleString()}</div>
      </div>

      <div class="card">
        <div class="cardTop">
          <div class="icon">
            <svg viewBox="0 0 24 24" fill="none">
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
        <div class="label">Lifetime Avg</div>
        <div class="big">
          {lifetimeWpm.toFixed(1)} <span class="unit">WPM</span>
        </div>
      </div>

      <div class="card">
        <div class="cardTop">
          <div class="icon">
            <svg viewBox="0 0 24 24" fill="none">
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
          <div class="tag">Active</div>
        </div>
        <div class="label">Session Avg</div>
        <div class="big">
          {sessionAvgWpm.toFixed(1)} <span class="unit">WPM</span>
        </div>
      </div>
    </section>

    <section class="grid mid">
      <div class="card small">
        <div class="label sm">Sessions</div>
        <div class="midVal">{sessions.toLocaleString()}</div>
      </div>
      <div class="card small">
        <div class="label sm">Hours Active</div>
        <div class="midVal">{hoursActive.toFixed(1)}h</div>
      </div>
    </section>

    <section class="card chart">
      <div class="label">Recent Activity</div>
      <div class="bars" aria-label="Recent activity">
        {#each recent as v, i (i)}
          <div class="bar">
            <div
              class="barFill"
              style={`height:${Math.max(
                2,
                Math.round(
                  (v / Math.max(1, Math.max(...recent))) * 100
                )
              )}%`}
            ></div>
          </div>
        {/each}
      </div>
    </section>
  {/if}
</div>

<style>
  :global(html, body) {
    margin: 0;
    padding: 0;
    background: #07070b;
    color: #e9e9ee;
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto,
      Helvetica, Arial;
    width: 100%;
    height: 100%;
  }

  .wrap {
    min-height: 100vh;
    width: 100%;
    box-sizing: border-box;
    padding: clamp(14px, 2.5vw, 28px);
    display: flex;
    flex-direction: column;
    gap: clamp(12px, 2vw, 18px);
  }

  .header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
  }

  .title {
    font-size: clamp(36px, 6vw, 56px);
    font-weight: 800;
    letter-spacing: -0.02em;
    line-height: 1;
  }

  .subtitle {
    margin-top: 6px;
    color: rgba(233, 233, 238, 0.68);
    font-size: clamp(14px, 2.2vw, 18px);
  }

  .pill {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    border-radius: 999px;
    border: 1px solid rgba(140, 120, 255, 0.25);
    background: rgba(30, 26, 55, 0.35);
    color: rgba(210, 210, 255, 0.9);
    font-weight: 600;
    white-space: nowrap;
  }

  .dot {
    width: 10px;
    height: 10px;
    border-radius: 999px;
    background: rgba(140, 120, 255, 0.95);
    box-shadow: 0 0 18px rgba(140, 120, 255, 0.65);
  }

  .loading {
    flex: 1;
    display: grid;
    place-items: center;
    color: rgba(233, 233, 238, 0.7);
  }

  .grid {
    display: grid;
    gap: clamp(10px, 1.5vw, 18px);
  }

  .grid.top {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }

  .grid.mid {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }

  @media (max-width: 900px) {
    .grid.top {
      grid-template-columns: 1fr;
    }
    .grid.mid {
      grid-template-columns: 1fr;
    }
  }

  .card {
    border-radius: 18px;
    padding: clamp(16px, 2.2vw, 22px);
    background: radial-gradient(
        1200px 600px at 20% 0%,
        rgba(140, 120, 255, 0.08),
        transparent 50%
      ),
      rgba(10, 10, 14, 0.7);
    border: 1px solid rgba(255, 255, 255, 0.06);
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.45);
  }

  .cardTop {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 18px;
  }

  .icon {
    width: 44px;
    height: 44px;
    border-radius: 12px;
    display: grid;
    place-items: center;
    background: rgba(140, 120, 255, 0.12);
    border: 1px solid rgba(140, 120, 255, 0.18);
    color: rgba(180, 160, 255, 0.95);
  }

  .icon svg {
    width: 22px;
    height: 22px;
  }

  .tag {
    padding: 6px 12px;
    border-radius: 10px;
    background: rgba(140, 120, 255, 0.14);
    border: 1px solid rgba(140, 120, 255, 0.18);
    color: rgba(210, 200, 255, 0.9);
    font-weight: 700;
    font-size: 12px;
  }

  .label {
    color: rgba(233, 233, 238, 0.62);
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  .label.sm {
    letter-spacing: 0.12em;
  }

  .big {
    margin-top: 10px;
    font-size: clamp(44px, 5vw, 64px);
    font-weight: 800;
    letter-spacing: -0.02em;
    line-height: 1;
  }

  .unit {
    font-size: 18px;
    font-weight: 700;
    color: rgba(233, 233, 238, 0.55);
    margin-left: 8px;
  }

  .card.small {
    padding: 18px 20px;
  }

  .midVal {
    margin-top: 10px;
    font-size: clamp(24px, 3vw, 34px);
    font-weight: 800;
  }

  .card.chart {
    padding: 18px 20px 22px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .bars {
    display: grid;
    grid-template-columns: repeat(48, minmax(0, 1fr));
    gap: 6px;
    align-items: end;
    height: clamp(120px, 22vh, 200px);
  }

  .bar {
    height: 100%;
    display: flex;
    align-items: end;
  }

  .barFill {
    width: 100%;
    border-radius: 10px 10px 6px 6px;
    background: linear-gradient(
      to top,
      rgba(120, 100, 255, 0.55),
      rgba(170, 140, 255, 0.85)
    );
    box-shadow: 0 0 18px rgba(140, 120, 255, 0.22);
    opacity: 0.95;
  }
</style>
