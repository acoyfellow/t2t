<script lang="ts">
  import type { HTMLTextareaAttributes } from "svelte/elements";

  let {
    value = $bindable(""),
    class: className = "",
    ...restProps
  }: HTMLTextareaAttributes & { value?: string } = $props();
</script>

<textarea bind:value class={className} {...restProps}></textarea>
