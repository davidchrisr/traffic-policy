<script lang="ts">
  import { ArrowDown, ArrowUp } from "@lucide/svelte";
  import { displayTrafficBytes } from "#lib/client.ts";

  let {
    received,
    sent,
    meter = false,
  }: {
    received: string;
    sent: string;
    meter?: boolean;
  } = $props();

  const total = $derived(BigInt(received) + BigInt(sent));

  const receivedShare = $derived(
    total > 0n ? Number((BigInt(received) * 10000n) / total) / 100 : 0,
  );

  const sentShare = $derived(
    total > 0n ? Number((BigInt(sent) * 10000n) / total) / 100 : 0,
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
  {#if meter}
    <span class="traffic-share" aria-hidden="true">
      <span class="traffic-share-sent" style:width={`${sentShare}%`}></span>
      <span class="traffic-share-baseline"></span>
      <span class="traffic-share-received" style:width={`${receivedShare}%`}
      ></span>
    </span>
  {/if}
</span>
