<script lang="ts" module>
	import { cn, type WithElementRef } from "$lib/utils.js";
	import type { HTMLButtonAttributes } from "svelte/elements";
	import { type VariantProps, tv } from "tailwind-variants";
	import { Toggle as TogglePrimitive } from "bits-ui";

	export const toggleVariants = tv({
		base: "inline-flex items-center justify-center gap-2 rounded-md text-sm font-medium transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 data-[state=on]:bg-accent data-[state=on]:text-accent-foreground aria-disabled:pointer-events-none aria-disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
		variants: {
			variant: {
				default: "bg-transparent",
				outline:
					"border border-input bg-transparent shadow-xs hover:bg-accent hover:text-accent-foreground",
			},
			size: {
				default: "h-9 px-3",
				sm: "h-8 rounded-md px-2",
				lg: "h-10 rounded-md px-3.5",
			},
		},
		defaultVariants: {
			variant: "default",
			size: "default",
		},
	});

	export type ToggleVariant = VariantProps<typeof toggleVariants>["variant"];
	export type ToggleSize = VariantProps<typeof toggleVariants>["size"];
	export type ToggleVariants = VariantProps<typeof toggleVariants>;

	export type ToggleProps = WithElementRef<HTMLButtonAttributes> & {
		variant?: ToggleVariant;
		size?: ToggleSize;
		pressed?: boolean;
		onPressedChange?: (pressed: boolean) => void;
	};
</script>

<script lang="ts">
	let {
		class: className,
		variant = "default",
		size = "default",
		pressed = $bindable(false),
		onPressedChange,
		ref = $bindable(null),
		children,
		...restProps
	}: ToggleProps = $props();

	function handlePressedChange(newPressed: boolean) {
		pressed = newPressed;
		onPressedChange?.(newPressed);
	}
</script>

<TogglePrimitive.Root
	bind:this={ref}
	class={cn(toggleVariants({ variant, size }), className)}
	bind:pressed
	onPressedChange={handlePressedChange}
	{...restProps}
>
	{@render children?.()}
</TogglePrimitive.Root>

