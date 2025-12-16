<script lang="ts">
  import { onMount } from "svelte";

  let totalWords = $state(0);
  let lifetimeWpm = $state(0);
  let sessionAvgWpm = $state(0);
  let loading = $state(true);

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

      totalWords = totalWordsVal;

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

<div class="container">
  <h1>t2t Stats</h1>

  {#if loading}
    <p class="loading">Loading...</p>
  {:else}
    <div class="stats">
      <div class="stat">
        <div class="label">Total Words</div>
        <div class="value">{totalWords.toLocaleString()}</div>
      </div>

      <div class="stat">
        <div class="label">Lifetime Avg WPM</div>
        <div class="value">{lifetimeWpm.toFixed(1)}</div>
      </div>

      <div class="stat">
        <div class="label">Session Avg WPM</div>
        <div class="value">{sessionAvgWpm.toFixed(1)}</div>
      </div>
    </div>
  {/if}
</div>

<style>
  :global(html, body) {
    margin: 0;
    padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
      sans-serif;
    background: #f5f5f5;
    overflow: hidden;
    width: 100vw;
    height: 100vh;
  }

  .container {
    padding: clamp(12px, 3vh, 24px) clamp(12px, 3vw, 24px);
    width: 100%;
    height: 100vh;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  h1 {
    margin: 0 0 clamp(8px, 2vh, 16px) 0;
    font-size: clamp(18px, 4vw, 28px);
    font-weight: 600;
    color: #1a1a1a;
    flex-shrink: 0;
  }

  .loading {
    color: #666;
    text-align: center;
    font-size: clamp(14px, 2vw, 18px);
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: clamp(8px, 1.5vw, 16px);
    flex: 1;
    min-height: 0;
    align-content: start;
  }

  @media (max-width: 500px) {
    .stats {
      grid-template-columns: 1fr;
    }
  }

  .stat {
    background: white;
    padding: clamp(12px, 2vh, 20px);
    border-radius: clamp(4px, 0.5vw, 8px);
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    display: flex;
    flex-direction: column;
    justify-content: center;
    min-height: 0;
  }

  .label {
    font-size: clamp(11px, 1.8vw, 14px);
    color: #666;
    margin-bottom: clamp(4px, 1vh, 8px);
    font-weight: 500;
    flex-shrink: 0;
  }

  .value {
    font-size: clamp(20px, 5vw, 36px);
    font-weight: 600;
    color: #1a1a1a;
    line-height: 1.2;
    flex: 1;
    display: flex;
    align-items: center;
  }
</style>
