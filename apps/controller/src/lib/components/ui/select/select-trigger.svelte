<script lang="ts">
  import { Select as SelectPrimitive } from "bits-ui";
  import ChevronDownIcon from "@lucide/svelte/icons/chevron-down";
  import { cn, type WithoutChild } from "#lib/utils.ts";

  let {
    ref = $bindable(null),
    class: className,
    children,
    size = "default",
    ...restProps
  }: WithoutChild<SelectPrimitive.TriggerProps> & {
    size?: "sm" | "default";
  } = $props();
</script>

<SelectPrimitive.Trigger
  bind:ref
  data-slot="select-trigger"
  data-size={size}
  class={cn(
    "border-input data-placeholder:text-muted-foreground bg-card hover:bg-hover focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive gap-1.5 rounded-lg border py-1 pr-2 pl-2.5 text-sm transition-colors duration-100 select-none focus-visible:outline-2 focus-visible:outline-ring focus-visible:outline-offset-2 aria-invalid:ring-3 data-[size=default]:h-(--control-height) data-[size=sm]:h-(--control-height-small) data-[size=sm]:rounded-[min(var(--radius-md),10px)] *:data-[slot=select-value]:flex *:data-[slot=select-value]:gap-1.5 [&_svg:not([class*='size-'])]:size-4 flex w-fit items-center justify-between whitespace-nowrap outline-none disabled:cursor-not-allowed disabled:opacity-50 *:data-[slot=select-value]:line-clamp-1 *:data-[slot=select-value]:flex *:data-[slot=select-value]:items-center [&_svg]:pointer-events-none [&_svg]:shrink-0",
    className,
  )}
  {...restProps}
>
  {@render children?.()}
  <ChevronDownIcon class="text-muted-foreground size-4 pointer-events-none" />
</SelectPrimitive.Trigger>
