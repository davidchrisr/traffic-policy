<script lang="ts">
  import { ChevronsUp, Clock, Globe } from "@lucide/svelte";
  import type { Instance, Rule, RuleSet } from "@traffic-policy/contracts";
  import {
    isCatchAll,
    ruleServiceLabel,
    subjectLabel,
  } from "@traffic-policy/core";
  import BuiltInValue from "#lib/components/BuiltInValue.svelte";
  import DirectionIcon from "#lib/components/DirectionIcon.svelte";
  import DottedName from "#lib/components/DottedName.svelte";
  import { currentTime } from "#lib/clock.ts";
  import { formatInstantInSentence } from "#lib/format-time.ts";

  let {
    rule,
    dns = null,
    instances = null,
    ruleSets = [],
    path = null,
    direction,
  }: {
    rule: Rule;
    dns?: string | null;
    // Shows the rule's instance where no heading already names it.
    instances?: Instance[] | null;
    // Names a rule set subject; shown with `instances`.
    ruleSets?: RuleSet[];
    // Where that instance or address sits among the scopes, shown on hover.
    path?: string | null;
    // A packet's direction in place of the rule's; null shows none.
    direction?: Rule["direction"] | null;
  } = $props();

  const shownDirection = $derived(
    direction === undefined ? rule.direction : direction,
  );

  // Keeps a protocol with its first port when the label wraps.
  const service = $derived(ruleServiceLabel(rule)?.replace(" ", "\u00a0"));

  const until = $derived(
    rule.expiresAt
      ? `Temporary, ends ${formatInstantInSentence(rule.expiresAt, currentTime())}`
      : null,
  );
</script>

<span class="rule-label">
  {#if instances !== null}{#if rule.subject.kind === "global"}<BuiltInValue
        kind="any"
      />{:else}<span class="shrink-0" title={path ?? undefined}
        >{subjectLabel(rule.subject, instances, ruleSets)}{#if path}<span
            class="sr-only">{` (${path.replaceAll("\n", "; ")})`}</span
          >{/if}</span
      >{/if}{/if}
  {#if shownDirection}<DirectionIcon direction={shownDirection} />{/if}
  <span class="min-w-0 break-words"
    >{#if isCatchAll(rule)}Catch-all{:else}{#if rule.peer.kind === "any" || rule.peer.kind === "gateway"}<BuiltInValue
          kind={rule.peer.kind}
        />{:else}<DottedName
          value={rule.peer.value}
        />{/if}{#if service}{` · ${service}`}{/if}{/if}</span
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
