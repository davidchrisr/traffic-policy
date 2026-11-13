<script lang="ts">
  import { onMount, untrack } from "svelte";
  import {
    ArrowUpDown,
    Ban,
    CircleCheck,
    FileText,
    Globe,
    RefreshCw,
    TriangleAlert,
  } from "@lucide/svelte";
  import type { PageProps } from "./$types";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import {
    historySnapshotSchema,
    type HistorySnapshot,
  } from "@traffic-policy/contracts/dashboard";
  import { latestStatus, liveStatus } from "#lib/live-status.ts";
  import { RefreshRunner } from "#lib/refresh-runner.ts";
  import { api } from "#lib/client.ts";
  import BuiltInValue from "#lib/components/BuiltInValue.svelte";
  import RuleLabel from "#lib/components/RuleLabel.svelte";
  import Time from "#lib/components/Time.svelte";
  import StatusLine from "#lib/components/StatusLine.svelte";
  import {
    anyValue,
    gatewayValue,
    describeChanges,
    type ChangeValue,
  } from "#lib/audit-changes.ts";

  let { data }: PageProps = $props();

  let model = $state.raw<HistorySnapshot>(untrack(() => data)),
    view = $state("audit"),
    search = $state(""),
    error = $state("");

  const audit = $derived(
    model.audit.filter((item) =>
      `${item.actor} ${item.client?.address ?? ""} ${item.client?.browser ?? ""} ${item.action} ${item.subjectLabel ?? ""} ${item.subject}`
        .toLowerCase()
        .includes(search.toLowerCase()),
    ),
  );

  // Kept in a mustache so formatting cannot move or drop the spaces around it.
  const separator = " · ";

  // Audit actions are slugs such as "rule-created".
  const sentence = (slug: string) => {
    const words = slug.replaceAll("-", " ");

    return words.charAt(0).toUpperCase() + words.slice(1);
  };

  const eventTypes: Record<HistorySnapshot["events"][number]["type"], string> =
    {
      traffic: "Traffic",
      dns: "DNS",
      blocked: "Blocked",
      blocked_count: "Blocked count",
      condition: "Condition",
      metadata: "Metadata",
    };

  let refreshing = $state(false);

  const runner = new RefreshRunner<HistorySnapshot>({
    onValue: (next) => {
      model = next;
      error = "";
    },
    onError: () => {
      error = "History could not be refreshed. Try again.";
    },
    onBusy: (busy) => {
      refreshing = busy;
    },
  });

  function refresh(supersede = true) {
    return runner.run(
      async (signal) =>
        historySnapshotSchema.parse(
          await api("history?limit=500", "GET", undefined, signal),
        ),
      supersede,
    );
  }

  onMount(() => () => runner.dispose());

  // History is loaded once; the layout keeps its status current.
  const live = liveStatus();

  const status = $derived(latestStatus(live.current, model.status));
</script>

{#snippet changeValue(
  value: ChangeValue | null,
)}{#if value === anyValue}<BuiltInValue
      kind="any"
    />{:else if value === gatewayValue}<BuiltInValue
      kind="gateway"
    />{:else}{value}{/if}{/snippet}

<svelte:head><title>History · Traffic Policy</title></svelte:head>
<header class="page-header">
  <h1 class="page-title">History</h1>
  <div class="header-actions">
    <StatusLine
      pending={status.pending}
      lastError={status.lastError as string | null}
      lastSeen={status.lastSeen as string | null}
    />
    <Button
      variant="ghost"
      size="icon"
      aria-label="Refresh history"
      disabled={refreshing}
      onclick={() => refresh()}
      ><RefreshCw
        size={16}
        class={refreshing ? "animate-spin" : undefined}
      /></Button
    >
  </div>
</header>
<section class="page-content">
  <div class="control-row mb-5">
    <Button
      variant={view === "audit" ? "selected" : "ghost"}
      aria-pressed={view === "audit"}
      onclick={() => (view = "audit")}>Changes</Button
    ><Button
      variant={view === "observations" ? "selected" : "ghost"}
      aria-pressed={view === "observations"}
      onclick={() => (view = "observations")}>Traffic events</Button
    ><Button
      variant={view === "coverage" ? "selected" : "ghost"}
      aria-pressed={view === "coverage"}
      onclick={() => (view = "coverage")}>System status</Button
    >{#if view === "audit"}<Input
        class="ml-auto max-w-xs"
        aria-label="Search changes"
        placeholder="Search changes"
        bind:value={search}
      />{/if}
  </div>
  {#if error}<p role="alert" class="field-error">{error}</p>{/if}
  {#if view === "audit"}{#each audit as item (item.id)}<div class="list-row">
        <Time class="muted numeric w-40 shrink-0 text-xs" value={item.at} />
        <div class="min-w-0">
          <p>{sentence(item.action)}</p>
          {#if item.subjectRule}{@const current = model.rules.find(
              (rule) => rule.id === item.subjectRule?.id,
            )}
            <p class="break-words text-xs">
              {#if current}<a
                  class="link-subtle"
                  href={`/${current.subject.kind === "ruleSet" ? "rule-sets" : "rules"}?rule=${current.id}`}
                  ><RuleLabel
                    rule={item.subjectRule}
                    instances={model.instances}
                    ruleSets={model.ruleSets}
                  /></a
                >{:else}<RuleLabel
                  rule={item.subjectRule}
                  instances={model.instances}
                  ruleSets={model.ruleSets}
                />{/if}
            </p>{:else if (item.subjectLabel ?? item.subject) !== item.actor}<p
              class="break-words text-xs"
            >
              {item.subjectLabel ?? item.subject}
            </p>{/if}
          <p class="muted break-words text-xs">
            {item.actor}{#if item.client}{` (${[item.client.browser, item.client.address].filter(Boolean).join(", ")})`}{/if}
          </p>
          {#if item.changes.length || item.revisions || item.subjectLabel}<details
              class="muted mt-1 text-xs"
            >
              <summary
                >{item.changes.length ? "What changed" : "Details"}</summary
              >
              {#each describeChanges(item.changes, model.instances, model.ruleSets, item.subjectRule ? [item.subjectRule, ...model.rules] : model.rules) as change, index (index)}<div
                  class="audit-change"
                >
                  <p class="text-foreground">
                    {change.title}{#if change.rule && change.rule.id !== item.subjectRule?.id}:
                      <RuleLabel
                        rule={change.rule}
                        instances={model.instances}
                        ruleSets={model.ruleSets}
                      />{/if}
                  </p>
                  {#if change.lines.length}<dl>
                      {#each change.lines as line (line.label)}<dt>
                          {line.label}
                        </dt>
                        <dd>
                          {#if line.before !== null && line.after !== null}{@render changeValue(
                              line.before,
                            )} → {@render changeValue(
                              line.after,
                            )}{:else}{@render changeValue(
                              line.after ?? line.before,
                            )}{/if}
                        </dd>{/each}
                    </dl>{/if}
                </div>{/each}
              {#if item.revisions}<p class="mt-1">
                  Revision {item.revisions.after}
                </p>{/if}
              {#if item.subjectLabel}<p class="mt-1 break-all">
                  Identifier <span class="font-mono">{item.subject}</span>
                </p>{/if}
            </details>{/if}
        </div>
      </div>{/each}{#if !audit.length}<div class="empty-state">
        No recorded changes match this view.
      </div>{/if}
    <p class="muted mt-5 text-xs">
      Oldest recorded change: {#if model.earliestAuditAt}<Time
          value={model.earliestAuditAt}
        />{:else}No events retained{/if}.
    </p>
  {:else if view === "observations"}{#each model.events as event (event.id)}{@const recovered =
        event.details.recovered === true}
      {@const text =
        event.type === "condition" && typeof event.details.message === "string"
          ? event.details.message
          : [event.question, event.peerIp].filter(Boolean).join(" · ")}
      {@const kind =
        event.type === "condition"
          ? recovered
            ? "Condition recovered"
            : "Condition"
          : eventTypes[event.type]}
      <div class="list-row">
        <Time
          class="muted numeric w-40 shrink-0 text-xs"
          value={event.observedAt}
        />
        <div class="min-w-0 flex-1">
          <p class="flex min-w-0 items-center gap-1.5">
            <span class="shrink-0" title={kind}
              >{#if event.type === "traffic"}<ArrowUpDown
                  size={15}
                  aria-hidden="true"
                />{:else if event.type === "dns"}<Globe
                  size={15}
                  aria-hidden="true"
                />{:else if event.type === "metadata"}<FileText
                  size={15}
                  aria-hidden="true"
                />{:else if event.type === "condition"}{#if recovered}<CircleCheck
                    size={15}
                    class="text-allow"
                    aria-hidden="true"
                  />{:else}<TriangleAlert
                    size={15}
                    class="text-pending"
                    aria-hidden="true"
                  />{/if}{:else}<Ban
                  size={15}
                  class="text-destructive"
                  aria-hidden="true"
                />{/if}<span class="sr-only">{kind}</span></span
            ><span class="min-w-0 truncate" title={text || undefined}
              >{text || eventTypes[event.type]}</span
            >
          </p>
          <p class="muted text-xs">
            {event.source}{event.details.outcome
              ? ` · ${event.details.outcome}`
              : ""}
          </p>
        </div>
      </div>{/each}{#if !model.events.length}<div class="empty-state">
        No traffic events recorded.
      </div>{/if}
  {:else}{#each model.conditions as condition (condition.code)}<div
        class="list-row"
      >
        <div class="min-w-0 flex-1">
          <p>{condition.message}</p>
          <p class="muted text-xs">
            First observed <Time value={condition.firstAt} /> · {condition.occurrences}
            {condition.occurrences === "1"
              ? "occurrence"
              : "occurrences"}{#if condition.recoveredAt}{separator}Recovered <Time
                value={condition.recoveredAt}
              />{/if}
          </p>
        </div>
        <span
          class:text-allow={condition.recoveredAt !== null}
          class:text-pending={condition.recoveredAt === null}
          >{condition.recoveredAt ? "Recovered" : "Active"}</span
        >
      </div>{/each}{#if !model.conditions.length}<div class="empty-state">
        No gateway issues recorded.
      </div>{/if}{/if}
</section>
