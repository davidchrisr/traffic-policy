<script lang="ts">
  import { ChevronsUp, Clock, Globe } from "@lucide/svelte";
  import type { Instance, Rule } from "@traffic-policy/contracts";
  import {
    isCatchAll,
    ruleScopeLabel,
    subjectLabel,
  } from "@traffic-policy/core";
  import DirectionIcon from "#lib/components/DirectionIcon.svelte";
  import { currentTime } from "#lib/clock.ts";
  import { formatInstantInSentence } from "#lib/format-time.ts";

  let {
    rule,
    dns = null,
    instances = null,
    path = null,
  }: {
    rule: Rule;
    dns?: string | null;
    // Shows the rule's instance where no heading already names it.
    instances?: Instance[] | null;
    // Where that instance or address sits among the scopes, shown on hover.
    path?: string | null;
  } = $props();

  const instance = $derived(
    instances === null ? null : subjectLabel(rule.subject, instances),
  );

  const until = $derived(
    rule.expiresAt
      ? `Temporary, ends ${formatInstantInSentence(rule.expiresAt, currentTime())}`
      : null,
  );
</script>

<span class="rule-label">
  {#if instance}<span class="shrink-0" title={path ?? undefined}
      >{instance}{#if path}<span class="sr-only"
          >{` (${path.replaceAll("\n", "; ")})`}</span
        >{/if}</span
    >{/if}
  <DirectionIcon direction={rule.direction} />
  <span class="min-w-0 break-words"
    >{isCatchAll(rule) ? "Catch-all" : ruleScopeLabel(rule)}</span
  >
  {#if until}<span class="rule-label-icon" title={until}
      ><Clock size={14} aria-hidden="true" /><span class="sr-only">{until}</span
      ></span
    >{/if}
  {#if rule.priority === "high"}<span
      class="rule-label-icon"
      title="High priority"
      ><ChevronsUp size={14} aria-hidden="true" /><span class="sr-only"
        >High priority</span
      ></span
    >{/if}
  {#if dns}<span class="rule-label-icon" title={dns}
      ><Globe size={14} aria-hidden="true" /><span class="sr-only">{dns}</span
      ></span
    >{/if}
</span>
