<script lang="ts">
  import { ArrowDown, ArrowUp } from "@lucide/svelte";
  import { displayTrafficBytes } from "#lib/client.ts";
  import { trafficBar } from "#lib/monitor-groups.ts";

  let {
    received,
    sent,
    scale,
  }: {
    received: string;
    sent: string;
    // The total the bar's length is measured against; without it, no bar is drawn.
    scale?: bigint;
  } = $props();

  const bar = $derived(
    scale === undefined
      ? null
      : trafficBar({ receivedBytes: received, sentBytes: sent }, scale),
  );
</script>

<span
  class="traffic-measure"
  title={`Received: ${received} bytes; sent: ${sent} bytes`}
>
  <span class="traffic-pair">
    <span
      class="traffic-pill traffic-received"
      aria-label={`Received ${displayTrafficBytes(received)}`}
    >
      <ArrowDown size={12} aria-hidden="true" />{displayTrafficBytes(received)}
    </span>
    <span
      class="traffic-pill traffic-sent"
      aria-label={`Sent ${displayTrafficBytes(sent)}`}
    >
      <ArrowUp size={12} aria-hidden="true" />{displayTrafficBytes(sent)}
    </span>
  </span>
  {#if bar}
    <span class="traffic-bar" aria-hidden="true">
      {#if !bar.empty}
        <span class="traffic-bar-fill" style:width={`${bar.fill}%`}>
          {#if bar.received > 0}<span
              class="traffic-bar-received"
              style:flex-grow={bar.received}
            ></span>{/if}
          {#if bar.received < 100}<span
              class="traffic-bar-sent"
              style:flex-grow={100 - bar.received}
            ></span>{/if}
        </span>
      {/if}
    </span>
  {/if}
</span>
