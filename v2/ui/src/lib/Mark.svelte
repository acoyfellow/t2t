<script lang="ts">
  let { spinning = false, class: className = '' }: { spinning?: boolean; class?: string } = $props();
</script>

<svg viewBox="0 0 790 790" class={className} aria-hidden="true">
  {#if spinning}
    <circle cx="440.883" cy="263.333" r="202" fill="none" stroke="currentColor" stroke-opacity="0.22" stroke-width="121" />
    <g class="t2t-spin" style="transform-origin: 440.883px 263.333px">
      <circle cx="440.883" cy="263.333" r="202" fill="none" stroke="currentColor" stroke-width="121" stroke-linecap="butt" stroke-dasharray="380 890" />
    </g>
    <path d="M206.439 384.872V668.462H611.234V790H85L85 506.41L206.439 384.872Z" fill="currentColor" />
  {:else}
    <path d="M440.883 0C586.198 9.88762e-07 704 117.898 704 263.333C704 408.768 586.198 526.667 440.883 526.667C415.725 526.667 391.393 523.13 368.353 516.532V385.16C389.57 397.84 414.375 405.128 440.883 405.128C519.13 405.128 582.561 341.644 582.561 263.333C582.561 185.022 519.13 121.538 440.883 121.538C362.636 121.539 299.204 185.022 299.204 263.333C299.204 314.914 326.725 360.06 367.871 384.872H207.41C188.474 348.511 177.765 307.174 177.765 263.333C177.765 117.898 295.567 0.000122783 440.883 0Z" fill="currentColor" />
    <path d="M206.439 384.872V668.462H611.234V790H85L85 506.41L206.439 384.872Z" fill="currentColor" />
  {/if}
</svg>
