<script lang="ts">
  import { onMount, tick, untrack } from "svelte";
  import { page } from "$app/state";
  import { Plus, Check, Ban, Pencil, RefreshCw, Trash2 } from "@lucide/svelte";
  import type { PageProps } from "./$types";
  import {
    ScopeTree,
    subjectScope,
    type Rule,
  } from "@traffic-policy/contracts";
  import { policyTree } from "#lib/rule-state.ts";
  import { rulesSnapshotSchema } from "@traffic-policy/contracts/dashboard";
  import { RefreshRunner } from "#lib/refresh-runner.ts";
  import {
    describeRule,
    isSettingsCatchAll,
    overriddenBy,
    subjectPath,
  } from "@traffic-policy/core";
  import { api, failureMessage } from "#lib/client.ts";
  import { currentTime } from "#lib/clock.ts";
  import { formatInstantInSentence } from "#lib/format-time.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import Choice from "#lib/components/Choice.svelte";
  import DateTimeField from "#lib/components/DateTimeField.svelte";
  import { nextDay, nextQuarterHour } from "#lib/date-picking.ts";
  import RuleEditor from "#lib/components/RuleEditor.svelte";
  import InspectorPanel from "#lib/components/InspectorPanel.svelte";
  import StatusLine from "#lib/components/StatusLine.svelte";
  import Time from "#lib/components/Time.svelte";
  import BuiltInValue from "#lib/components/BuiltInValue.svelte";
  import RuleLabel from "#lib/components/RuleLabel.svelte";
  import * as Dialog from "#lib/components/ui/dialog/index.ts";

  let { data }: PageProps = $props();

  let model = $state.raw(untrack(() => data)),
    search = $state(""),
    filter = $state("all"),
    sort = $state("instance");

  let selected = $state<string | null>(null),
    inspectorOpen = $state(false),
    editorOpen = $state(false),
    editing = $state<Rule | null>(null),
    refreshError = $state(""),
    actionError = $state("");

  // Renewal reuses the editor's lifetimes; a custom end is sent as seconds from now.
  const renewOptions = [
    { value: "900", label: "15 minutes" },
    { value: "3600", label: "1 hour" },
    { value: "28800", label: "8 hours" },
    { value: "86400", label: "24 hours" },
    { value: "custom", label: "Custom" },
  ];

  let renewFor = $state("3600"),
    renewUntil = $state("");

  // Custom renewal ends a day from the next quarter hour unless an end is already set.
  function chooseRenewal(value: string) {
    renewFor = value;

    if (value === "custom") renewUntil ||= nextDay(nextQuarterHour());
  }

  let deleting = $state<Rule | null>(null),
    deleteBusy = $state(false),
    deleteError = $state("");

  const shown = $derived(
    model.rules
      .filter(
        (rule) =>
          (!search ||
            `${rule.description} ${rule.reason}`
              .toLowerCase()
              .includes(search.toLowerCase())) &&
          (filter === "all" ||
            (filter === "high" && rule.priority === "high") ||
            (filter === "temporary" && rule.expiresAt !== null) ||
            rule.state === filter),
      )
      .sort((left, right) =>
        sort === "modified"
          ? right.modifiedAt.localeCompare(left.modifiedAt)
          : 0,
      ),
  );

  // Global rules, each instance's, and each address rule's range with the instance holding it.
  const groups = $derived.by(() => {
    const tree = policyTree(model.instances, model.rules);

    // The tree holds one entry per address-rule range.
    const addresses = tree.entries.filter((entry) => !entry.instanceId);

    return [
      { id: null, name: "Any", path: null },
      ...model.instances.map((instance) => ({
        id: instance.id,
        name: instance.name,
        path: subjectPath(
          { kind: "instance", instanceId: instance.id },
          tree,
          model.instances,
        ),
      })),
      ...addresses.map((entry) => {
        const holder = model.instances.find(
          (instance) => instance.id === ScopeTree.instanceOf(entry),
        );

        return {
          id: entry.network,
          name: holder ? `${entry.network} in ${holder.name}` : entry.network,
          path: subjectPath(
            { kind: "address", value: entry.network },
            tree,
            model.instances,
          ),
        };
      }),
    ].flatMap((group) => {
      const rules = shown.filter(
        (rule) => subjectScope(rule.subject) === group.id,
      );

      return rules.length ? [{ ...group, rules }] : [];
    });
  });

  const catchAllNote = "Applies when no rule matches. Set in Settings.";

  // Rules that another rule overrides completely, with the text that says so.
  const overrides = $derived(
    new Map(
      model.rules.flatMap((rule) => {
        const found = overriddenBy(
          rule,
          model.rules,
          model.instances,
          currentTime().getTime(),
        );

        if (!found) return [];

        return [
          [
            rule.id,
            {
              state: found.until
                ? `No effect, takes effect ${formatInstantInSentence(found.until, currentTime())}`
                : "No effect",
              reason: `${found.rule.action === "allow" ? "Allow" : "Block"} ${describeRule(found.rule, model.instances)} matches the same traffic and wins.`,
              winner: found.rule,
            },
          ],
        ];
      }),
    ),
  );

  const packetCount = new Intl.NumberFormat();

  const focused = $derived(model.rules.find((rule) => rule.id === selected));

  const focusedOverride = $derived(focused && overrides.get(focused.id));

  let refreshing = $state(false);

  const runner = new RefreshRunner<typeof data>({
    onValue: (next) => {
      model = next;
      refreshError = "";
    },
    onError: () => {
      refreshError = "Rules could not be refreshed. Try again.";
    },
    onBusy: (busy) => {
      refreshing = busy;
    },
  });

  function refresh(supersede = true) {
    return runner.run(
      async (signal) =>
        rulesSnapshotSchema.parse(await api("rules", "GET", undefined, signal)),
      supersede,
    );
  }

  onMount(() => {
    // A History entry links here with its rule: open it.
    const linked = model.rules.find(
      (rule) => rule.id === page.url.searchParams.get("rule"),
    );

    if (linked) {
      select(linked);
      inspectorOpen = true;
      void tick().then(() =>
        document
          .getElementById(`rule-${linked.id}`)
          ?.scrollIntoView({ block: "center" }),
      );
    }

    const timer = setInterval(() => {
      void refresh(false);
    }, 5000);

    return () => {
      clearInterval(timer);
      runner.dispose();
    };
  });

  function edit(rule: Rule | null) {
    editing = rule;
    editorOpen = true;
  }

  function select(rule: Rule) {
    selected = rule.id;
    actionError = "";
  }

  async function toggle(rule: (typeof data.rules)[number]) {
    actionError = "";

    const {
      id,
      createdAt: _createdAt,
      modifiedAt: _modifiedAt,
      ...fields
    } = rule;

    const {
      state: _state,
      description: _description,
      blocked: _blocked,
      ...input
    } = fields;

    try {
      await api(`rules/${id}`, "PUT", {
        expectedRevision: model.revision,
        rule: { ...input, enabled: !rule.enabled },
      });
      await refresh();
    } catch (failure) {
      actionError = failureMessage(failure, "Rule could not be changed");
    }
  }

  function confirmDelete(rule: Rule) {
    deleting = rule;
    deleteError = "";
  }

  async function remove() {
    if (!deleting || deleteBusy) return;
    deleteBusy = true;
    deleteError = "";

    try {
      await api(`rules/${deleting.id}`, "DELETE", {
        expectedRevision: model.revision,
      });
      deleting = null;
      selected = null;
      inspectorOpen = false;
      await refresh();
    } catch (failure) {
      deleteError = failureMessage(failure, "Rule could not be deleted");
    } finally {
      deleteBusy = false;
    }
  }

  async function renew(rule: Rule) {
    actionError = "";

    const durationSeconds =
      renewFor === "custom"
        ? Math.ceil((new Date(renewUntil).getTime() - Date.now()) / 1000)
        : Number(renewFor);

    if (!(durationSeconds > 0)) {
      actionError = "Select an end in the future";

      return;
    }

    try {
      await api(`rules/${rule.id}/renew`, "POST", {
        expectedRevision: model.revision,
        durationSeconds,
      });
      await refresh();
    } catch (failure) {
      actionError = failureMessage(failure, "Rule could not be renewed");
    }
  }
</script>

<svelte:head><title>Rules · Traffic Policy</title></svelte:head>
<header class="page-header">
  <h1 class="page-title">Rules</h1>
  <div class="header-actions">
    <StatusLine
      pending={model.status.pending}
      lastError={model.status.lastError as string | null}
      lastSeen={model.status.lastSeen as string | null}
    />
    <Button
      variant="ghost"
      size="icon"
      aria-label="Refresh rules"
      disabled={refreshing}
      onclick={() => refresh()}
      ><RefreshCw
        size={16}
        class={refreshing ? "animate-spin" : undefined}
      /></Button
    >
    <Button onclick={() => edit(null)}><Plus size={16} />Create rule</Button>
  </div>
</header>
<div class="split-view">
  <section class="page-content min-w-0">
    <div class="control-row mb-4">
      <Input
        aria-label="Search rules"
        placeholder="Search rules"
        bind:value={search}
        class="min-w-40 flex-1"
      /><Choice
        label="Sort rules"
        bind:value={sort}
        options={[
          { value: "instance", label: "By instance" },
          { value: "modified", label: "Last modified" },
        ]}
      />
    </div>
    <div class="control-row mb-4" role="group" aria-label="Rule filters">
      {#each [{ value: "all", label: "All rules" }, { value: "high", label: "High priority" }, { value: "temporary", label: "Temporary" }, { value: "disabled", label: "Disabled" }, { value: "expired", label: "Expired" }] as item (item.value)}<Button
          variant={filter === item.value ? "selected" : "ghost"}
          size="sm"
          aria-pressed={filter === item.value}
          onclick={() => (filter = item.value)}>{item.label}</Button
        >{/each}
    </div>
    {#if refreshError}<p class="field-error mb-4" role="alert">
        {refreshError}
      </p>{/if}
    {#each groups as group (group.id)}<section class="mb-5">
        <h2 class="section-title mb-2">
          {#if group.id === null}<BuiltInValue kind="any" />{:else}<span
              title={group.path ?? undefined}>{group.name}</span
            >{/if}{#if group.path}<span class="sr-only"
              >{` (${group.path.replaceAll("\n", "; ")})`}</span
            >{/if}<span
            class="muted ml-2 text-xs font-normal"
            aria-hidden="true">{group.rules.length}</span
          ><span class="sr-only"
            >{`, ${group.rules.length} ${group.rules.length === 1 ? "rule" : "rules"}`}</span
          >
        </h2>
        {#each group.rules as rule (rule.id)}{@const fromSettings =
            isSettingsCatchAll(rule)}{@const override = overrides.get(rule.id)}
          <div
            id={`rule-${rule.id}`}
            class="list-row"
            data-selected={selected === rule.id}
            data-inactive={rule.state !== "active" || override !== undefined}
            data-settings={fromSettings}
          >
            <button
              class="flex min-w-0 flex-1 items-center gap-3 text-left"
              title={fromSettings ? catchAllNote : override?.reason}
              onclick={() => {
                select(rule);
                inspectorOpen = true;
              }}
            >
              {#if rule.action === "allow"}<Check
                  size={18}
                  class="text-allow rule-row-dim shrink-0"
                  aria-hidden="true"
                />{:else}<Ban
                  size={18}
                  class="text-destructive rule-row-dim shrink-0"
                  aria-hidden="true"
                />{/if}
              <span class="min-w-0"
                ><span class="sr-only"
                  >{rule.action === "allow" ? "Allow" : "Block"}
                </span><span class="rule-row-dim"><RuleLabel {rule} /></span
                >{#if rule.state !== "active"}<span
                    class="rule-row-state block text-xs capitalize"
                    >{rule.state}</span
                  >{:else if override}<span class="rule-row-state block text-xs"
                    >{override.state}</span
                  ><span class="sr-only">{` ${override.reason}`}</span
                  >{/if}{#if fromSettings}<span class="sr-only"
                    >{` ${catchAllNote}`}</span
                  >{/if}</span
              >
            </button>
            {#if !fromSettings}<Button
                variant="ghost"
                size="icon"
                aria-label={`Edit ${rule.description}`}
                onclick={() => edit(rule)}><Pencil size={15} /></Button
              >{/if}
          </div>{/each}
      </section>{/each}
    {#if !groups.length}<div class="empty-state">
        No rules match these filters.
      </div>{/if}
  </section>
  <InspectorPanel label="Rule inspector" bind:open={inspectorOpen}>
    {#if focused}<h2 class="section-title mb-4">Selected rule</h2>
      <p class="break-words">
        <RuleLabel rule={focused} instances={model.instances} />
      </p>
      <dl class="mt-4 space-y-3">
        <div>
          <dt class="muted text-xs">Action</dt>
          <dd
            class:text-allow={focused.action === "allow"}
            class:text-destructive={focused.action === "block"}
          >
            {focused.action === "allow" ? "Allow" : "Block"}
          </dd>
        </div>
        <div>
          <dt class="muted text-xs">High priority</dt>
          <dd>{focused.priority === "high" ? "Yes" : "No"}</dd>
        </div>
        <div>
          <dt class="muted text-xs">State</dt>
          {#if focused.state === "active" && focusedOverride}<dd>
              {focusedOverride.state}
            </dd>
            <dd class="muted mt-1 text-xs">
              {focusedOverride.winner.action === "allow" ? "Allow" : "Block"}
              <RuleLabel
                rule={focusedOverride.winner}
                instances={model.instances}
              /> matches the same traffic and wins.
            </dd>{:else}<dd class="capitalize">{focused.state}</dd>{/if}
        </div>
        {#if focused.blocked}<div>
            <dt class="muted text-xs">Blocked in the last 24 hours</dt>
            <dd class="numeric">
              {packetCount.format(BigInt(focused.blocked.packets))}
              {focused.blocked.packets === "1" ? "packet" : "packets"}
            </dd>
            {#if focused.blocked.samplesSince}<dd class="muted mt-1 text-xs">
                Samples kept since <Time value={focused.blocked.samplesSince} />
              </dd>{/if}
          </div>{/if}
        <div>
          <dt class="muted text-xs">Last modified</dt>
          <dd><Time value={focused.modifiedAt} /></dd>
        </div>
        {#if focused.reason}<div>
            <dt class="muted text-xs">Reason</dt>
            <dd>{focused.reason}</dd>
          </div>{/if}
      </dl>
      {#if isSettingsCatchAll(focused)}<p class="muted mt-6 text-sm">
          Applies when no rule matches. <a
            class="link-subtle"
            href="/settings#settings-catch-all">Change it in Settings</a
          >
        </p>{:else}<div class="control-row mt-6">
          <Button variant="secondary" onclick={() => edit(focused)}
            ><Pencil size={15} />Edit</Button
          ><Button variant="outline" onclick={() => toggle(focused)}
            >{focused.enabled ? "Disable rule" : "Enable rule"}</Button
          ><Button
            variant="ghost"
            aria-label="Delete selected rule"
            onclick={() => confirmDelete(focused)}><Trash2 size={15} /></Button
          >
        </div>
        {#if focused.expiresAt}<div
            class="control-row mt-3"
            role="group"
            aria-label="Renew rule"
          >
            <Choice
              label="Renew for"
              bind:value={() => renewFor, chooseRenewal}
              options={renewOptions}
            />{#if renewFor === "custom"}<div class="w-64">
                <DateTimeField
                  id="renew-until"
                  label="Renew until"
                  bind:value={renewUntil}
                />
              </div>{/if}<Button
              variant="outline"
              onclick={() => renew(focused)}>Renew</Button
            >
          </div>{/if}{/if}
      {#if actionError}<p class="field-error mt-4" role="alert">
          {actionError}
        </p>{/if}
    {:else}<p class="muted">Select a rule.</p>{/if}
  </InspectorPanel>
</div>
<RuleEditor
  bind:open={editorOpen}
  rule={editing}
  instances={model.instances}
  rules={model.rules}
  revision={model.revision}
  onSaved={() => refresh()}
/>
<Dialog.Root
  open={deleting !== null}
  onOpenChange={(open) => {
    if (!open && !deleteBusy) deleting = null;
  }}
>
  <Dialog.Content
    showCloseButton={!deleteBusy}
    onEscapeKeydown={(event) => {
      if (deleteBusy) event.preventDefault();
    }}
    onInteractOutside={(event) => {
      if (deleteBusy) event.preventDefault();
    }}
  >
    <Dialog.Header
      ><Dialog.Title>Delete this rule?</Dialog.Title><Dialog.Description
        >The remaining rules will decide this traffic.</Dialog.Description
      ></Dialog.Header
    >
    {#if deleting}<p class="flex items-center gap-2 text-sm">
        {#if deleting.action === "allow"}<Check
            size={16}
            class="text-allow shrink-0"
            aria-hidden="true"
          />{:else}<Ban
            size={16}
            class="text-destructive shrink-0"
            aria-hidden="true"
          />{/if}<span class="sr-only"
          >{deleting.action === "allow" ? "Allow" : "Block"}
        </span><RuleLabel rule={deleting} instances={model.instances} />
      </p>{/if}
    {#if deleteError}<p class="field-error" role="alert">
        {deleteError}
      </p>{/if}
    <Dialog.Footer
      ><Button
        variant="outline"
        disabled={deleteBusy}
        onclick={() => (deleting = null)}>Cancel</Button
      ><Button variant="destructive" disabled={deleteBusy} onclick={remove}
        >{deleteBusy ? "Deleting…" : "Delete rule"}</Button
      ></Dialog.Footer
    >
  </Dialog.Content>
</Dialog.Root>
