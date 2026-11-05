<script lang="ts">
  import { currentTime } from "#lib/clock.ts";
  import { formatFullInstant, formatInstant } from "#lib/format-time.ts";

  let {
    value,
    class: className,
    title,
  }: {
    value: string;
    class?: string;
    // Replaces the full timestamp tooltip when the time needs more context.
    title?: string;
  } = $props();
</script>

<time
  class={className}
  datetime={value}
  title={title ?? formatFullInstant(value)}
  >{formatInstant(value, currentTime())}</time
>
