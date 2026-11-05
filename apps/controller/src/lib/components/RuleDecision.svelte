<script lang="ts">
  import { Ban, Check } from "@lucide/svelte";
  import { Button } from "#lib/components/ui/button/index.ts";
  import type { DecisionState } from "#lib/rule-state.ts";

  let {
    state,
    scope,
    description,
    onallow,
    onblock,
    locked = null,
  }: {
    state: DecisionState | null;
    scope: string;
    description: string;
    onallow: () => void;
    onblock: () => void;
    // Says where the decision is changed instead; the pair then only shows the state.
    locked?: string | null;
  } = $props();

  const blockColor = $derived(
    state === "block"
      ? "text-destructive"
      : state === "waiting"
        ? "text-pending"
        : "text-muted-foreground",
  );

  const allowColor = $derived(
    state === "allow" ? "text-allow" : "text-muted-foreground",
  );
</script>

{#if locked}<span
    class="rule-decision"
    data-state={state}
    data-locked="true"
    title={`${description}. ${locked}`}
    ><span class="rule-decision-icon"
      ><Ban size={16} class={blockColor} aria-hidden="true" /></span
    ><span class="rule-decision-icon"
      ><Check size={16} class={allowColor} aria-hidden="true" /></span
    ><span class="sr-only">{`${description}. ${locked}`}</span></span
  >{:else}<span class="rule-decision" data-state={state} title={description}>
    <Button
      variant="ghost"
      size="icon-pair"
      class="hover:bg-[color-mix(in_oklch,var(--accent),var(--foreground)_20%)]"
      aria-label={`Block ${scope}. Current: ${description}`}
      onclick={onblock}><Ban size={16} class={blockColor} /></Button
    ><Button
      variant="ghost"
      size="icon-pair"
      class="hover:bg-[color-mix(in_oklch,var(--accent),var(--foreground)_20%)]"
      aria-label={`Allow ${scope}. Current: ${description}`}
      onclick={onallow}><Check size={16} class={allowColor} /></Button
    >
  </span>{/if}
