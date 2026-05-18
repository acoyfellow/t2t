<script lang="ts">
  import type { HTMLInputAttributes } from "svelte/elements";

  let {
    value = $bindable(""),
    class: className = "",
    ...restProps
  }: HTMLInputAttributes & { value?: string } = $props();
</script>

<input bind:value class={className} {...restProps} />
