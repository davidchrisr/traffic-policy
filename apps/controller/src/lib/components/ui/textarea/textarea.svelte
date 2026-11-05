<script lang="ts">
  import { cn, type WithElementRef, type WithoutChildren } from "#lib/utils.ts";
  import type { HTMLTextareaAttributes } from "svelte/elements";

  let {
    ref = $bindable(null),
    value = $bindable(),
    class: className,
    "data-slot": dataSlot = "textarea",
    ...restProps
  }: WithoutChildren<WithElementRef<HTMLTextareaAttributes>> = $props();
</script>

<textarea
  bind:this={ref}
  data-slot={dataSlot}
  class={cn(
    "border-input bg-card focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive disabled:bg-input/50 dark:disabled:bg-input/80 rounded-lg border bg-card px-2.5 py-2 text-sm transition-colors duration-100 focus-visible:outline-2 focus-visible:outline-ring focus-visible:outline-offset-2 aria-invalid:ring-3 md:text-sm flex field-sizing-content min-h-16 w-full outline-none placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-50",
    className,
  )}
  bind:value
  {...restProps}></textarea>
