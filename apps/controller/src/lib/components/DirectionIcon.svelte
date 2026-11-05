<script lang="ts">
  import { ArrowLeft, ArrowLeftRight, ArrowRight } from "@lucide/svelte";
  import { directionLabels } from "@traffic-policy/core";

  let {
    direction,
  }: {
    direction: "outgoing" | "incoming" | "both";
  } = $props();

  const Icon = $derived(
    direction === "outgoing"
      ? ArrowRight
      : direction === "incoming"
        ? ArrowLeft
        : ArrowLeftRight,
  );
</script>

<span class="rule-label-icon" title={directionLabels[direction]}
  ><Icon size={14} aria-hidden="true" /><span class="sr-only"
    >{directionLabels[direction]}</span
  ></span
>
