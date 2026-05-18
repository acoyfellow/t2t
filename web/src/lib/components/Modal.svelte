<script lang="ts">
  import type { Snippet } from "svelte";

  type ModalProps = {
    open?: boolean;
    title?: string;
    size?: string;
    outsideclose?: boolean;
    children?: Snippet;
  };

  let {
    open = $bindable(false),
    title,
    size = "md",
    outsideclose = false,
    children,
  }: ModalProps = $props();

  const widthClass = $derived(
    size === "sm"
      ? "max-w-sm"
      : size === "lg"
        ? "max-w-3xl"
        : "max-w-xl"
  );

  function handleBackdropClick(event: MouseEvent) {
    if (outsideclose && event.target === event.currentTarget) open = false;
  }
</script>

{#if open}
  <div
    class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
    role="presentation"
    onclick={handleBackdropClick}
  >
    <div
      class={`w-full ${widthClass} overflow-hidden rounded-xl bg-white shadow-2xl`}
      role="dialog"
      aria-modal="true"
      aria-label={title || "Dialog"}
    >
      {#if title}
        <header class="border-b border-gray-200 px-6 py-4">
          <h2 class="text-lg font-semibold text-gray-900">{title}</h2>
        </header>
      {/if}
      {@render children?.()}
    </div>
  </div>
{/if}
