<script lang="ts">
  import { onMount, tick, untrack } from "svelte";
  import { page } from "$app/state";
  import {
    Ban,
    Check,
    Download,
    Pencil,
    Plus,
    RefreshCw,
    Trash2,
    Upload,
    X,
  } from "@lucide/svelte";
  import type { PageProps } from "./$types";
  import type {
    Rule,
    RuleSet,
    RuleSetFile,
    RuleSetMembers,
  } from "@traffic-policy/contracts";
  import {
    ruleSetCreatedSchema,
    rulesSnapshotSchema,
  } from "@traffic-policy/contracts/dashboard";
  import { api, failureMessage } from "#lib/client.ts";
  import {
    attach,
    detach,
    isAttached,
    ruleSetFile,
    ruleSetFileName,
    ruleSetRules,
  } from "#lib/rule-sets.ts";
  import { RefreshRunner } from "#lib/refresh-runner.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import * as Dialog from "#lib/components/ui/dialog/index.ts";
  import Choice from "#lib/components/Choice.svelte";
  import InspectorPanel from "#lib/components/InspectorPanel.svelte";
  import RuleSetImportDialog from "#lib/components/RuleSetImportDialog.svelte";
  import RuleSetNameDialog from "#lib/components/RuleSetNameDialog.svelte";
  import BuiltInValue from "#lib/components/BuiltInValue.svelte";
  import RuleEditor from "#lib/components/RuleEditor.svelte";
  import RuleLabel from "#lib/components/RuleLabel.svelte";
  import StatusLine from "#lib/components/StatusLine.svelte";

  let { data }: PageProps = $props();

  let model = $state.raw(untrack(() => data)),
    selected = $state<string | null>(null),
    inspectorOpen = $state(false),
    refreshing = $state(false),
    refreshError = $state(""),
    actionError = $state(""),
    attachTo = $state("");

  let editorOpen = $state(false),
    editingSet = $state<string | null>(null),
    editing = $state<Rule | null>(null);

  let naming = $state<"create" | "rename">("create"),
    // The set being renamed and the revision the name dialog opened at.
    namingSet = $state.raw<RuleSet | null>(null),
    namingRevision = $state(""),
    namingOpen = $state(false),
    importOpen = $state(false);

  // A pending deletion, confirmed in a dialog.
  let confirming = $state<{
      title: string;
      description: string;
      action: string;
      // The revision the confirmation describes.
      revision: string;
      run: (revision: string) => Promise<void>;
    } | null>(null),
    confirmBusy = $state(false),
    confirmError = $state("");

  const sets = $derived(
    model.ruleSets.map((ruleSet) => ({
      ...ruleSet,
      rules: ruleSetRules(model.rules, ruleSet.id),
    })),
  );

  const focused = $derived(sets.find((ruleSet) => ruleSet.id === selected));

  const instanceName = (id: string) =>
    model.instances.find((instance) => instance.id === id)?.name ?? "Instance";

  // Where the focused rule set is not attached yet: instances, then every instance.
  const unattached = $derived(
    !focused || focused.members.kind === "global"
      ? []
      : [
          ...model.instances
            .filter((instance) => !isAttached(focused.members, instance.id))
            .map((instance) => ({ value: instance.id, label: instance.name })),
          { value: "any", label: "Any", builtIn: true },
        ],
  );

  const names = new Intl.ListFormat("en", { type: "conjunction" });

  // The instances a rule set applies to, for the sentence that confirms its deletion.
  function attachedNames(members: RuleSetMembers) {
    if (members.kind === "global") return "every instance";
    const listed = members.instanceIds.slice(0, 10).map(instanceName);
    const more = members.instanceIds.length - listed.length;

    return names.format(more ? [...listed, `${more} more`] : listed);
  }

  function attachment(members: RuleSetMembers) {
    if (members.kind === "global") return "Every instance";
    const count = members.instanceIds.length;

    return count
      ? `${count} ${count === 1 ? "instance" : "instances"}`
      : "Not attached";
  }

  const runner = new RefreshRunner<typeof data>({
    onValue: (next) => {
      model = next;
      refreshError = "";
    },
    onError: () => {
      refreshError = "Rule sets could not be refreshed. Try again.";
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

  function select(id: string) {
    selected = id;
    inspectorOpen = true;
    actionError = "";
    attachTo = "";
  }

  onMount(() => {
    // Rules and History link here with a rule set or one of its rules: open it.
    const rule = model.rules.find(
      (value) => value.id === page.url.searchParams.get("rule"),
    );

    const linked =
      rule?.subject.kind === "ruleSet"
        ? rule.subject.ruleSetId
        : page.url.searchParams.get("set");

    if (linked && model.ruleSets.some((ruleSet) => ruleSet.id === linked)) {
      select(linked);
      void tick().then(() =>
        document
          .getElementById(rule ? `rule-${rule.id}` : `rule-set-${linked}`)
          ?.scrollIntoView({ block: rule ? "center" : "start" }),
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

  function edit(ruleSetId: string, rule: Rule | null) {
    editingSet = ruleSetId;
    editing = rule;
    editorOpen = true;
  }

  function name(kind: "create" | "rename") {
    naming = kind;
    namingSet = kind === "rename" ? (focused ?? null) : null;
    namingRevision = model.revision;
    namingOpen = true;
  }

  async function create(file: Pick<RuleSetFile, "name" | "rules">) {
    const { id } = ruleSetCreatedSchema.parse(
      await api("rule-sets", "POST", {
        expectedRevision: model.revision,
        ruleSet: {
          name: file.name,
          members: { kind: "instances", instanceIds: [] },
        },
        rules: file.rules,
        move: [],
      }),
    );

    await refresh();
    select(id);
  }

  function save(
    ruleSet: RuleSet,
    fields: Partial<Omit<RuleSet, "id">>,
    expectedRevision = model.revision,
  ) {
    return api(`rule-sets/${ruleSet.id}`, "PUT", {
      expectedRevision,
      ruleSet: { name: ruleSet.name, members: ruleSet.members, ...fields },
    });
  }

  async function saveName(value: string) {
    if (naming === "create") return create({ name: value, rules: [] });

    if (namingSet) {
      await save(namingSet, { name: value }, namingRevision);
      await refresh();
    }
  }

  async function setMembers(ruleSet: RuleSet, members: RuleSetMembers) {
    actionError = "";

    try {
      await save(ruleSet, { members });
      attachTo = "";
    } catch (failure) {
      actionError = failureMessage(failure, "Rule set could not be changed");
    }

    await refresh();
  }

  function confirm(action: Omit<NonNullable<typeof confirming>, "revision">) {
    confirming = { ...action, revision: model.revision };
    confirmError = "";
  }

  async function runConfirmed() {
    if (!confirming || confirmBusy) return;
    confirmBusy = true;
    confirmError = "";

    try {
      await confirming.run(confirming.revision);
      confirming = null;
      await refresh();
    } catch (failure) {
      confirmError = failureMessage(failure, "Change could not be saved");
      await refresh();
    } finally {
      confirmBusy = false;
    }
  }

  function confirmDelete(ruleSet: NonNullable<typeof focused>) {
    const count = `${ruleSet.rules.length} ${ruleSet.rules.length === 1 ? "rule" : "rules"}`;

    const used =
      ruleSet.members.kind === "global" || ruleSet.members.instanceIds.length;

    confirm({
      title: `Delete ${ruleSet.name}?`,
      description: used
        ? `Its ${count} will stop applying to ${attachedNames(ruleSet.members)}.`
        : `Its ${count} will be deleted with it.`,
      action: "Delete rule set",
      run: async (expectedRevision) => {
        await api(`rule-sets/${ruleSet.id}`, "DELETE", { expectedRevision });
        selected = null;
        inspectorOpen = false;
      },
    });
  }

  // Saves the rule set as a file another controller can import.
  function exportSet(ruleSet: NonNullable<typeof focused>) {
    const file = ruleSetFile(ruleSet.name, ruleSet.rules);

    const url = URL.createObjectURL(
      new Blob([`${JSON.stringify(file, null, 2)}\n`], {
        type: "application/json",
      }),
    );

    const link = document.createElement("a");

    link.href = url;
    link.download = ruleSetFileName(ruleSet.name);
    link.click();
    URL.revokeObjectURL(url);
  }
</script>

<svelte:head><title>Rule sets · Traffic Policy</title></svelte:head>
<header class="page-header">
  <h1 class="page-title">Rule sets</h1>
  <div class="header-actions">
    <StatusLine
      pending={model.status.pending}
      lastError={model.status.lastError as string | null}
      lastSeen={model.status.lastSeen as string | null}
    />
    <Button
      variant="ghost"
      size="icon"
      aria-label="Refresh rule sets"
      disabled={refreshing}
      onclick={() => refresh()}
      ><RefreshCw
        size={16}
        class={refreshing ? "animate-spin" : undefined}
      /></Button
    >
    <Button variant="outline" onclick={() => (importOpen = true)}
      ><Upload size={16} />Import</Button
    >
    <Button onclick={() => name("create")}
      ><Plus size={16} />Create rule set</Button
    >
  </div>
</header>
<div class="split-view">
  <section class="page-content min-w-0">
    {#if refreshError}<p class="field-error mb-4" role="alert">
        {refreshError}
      </p>{/if}
    {#each sets as ruleSet (ruleSet.id)}
      <section class="mb-5" id={`rule-set-${ruleSet.id}`}>
        <h2 class="section-title mb-2">
          <button
            class="link-subtle text-left"
            aria-current={selected === ruleSet.id ? "true" : undefined}
            onclick={() => select(ruleSet.id)}>{ruleSet.name}</button
          ><span class="muted ml-2 text-xs font-normal" aria-hidden="true"
            >{ruleSet.rules.length}</span
          ><span class="sr-only"
            >{`, ${ruleSet.rules.length} ${ruleSet.rules.length === 1 ? "rule" : "rules"}`}</span
          ><span class="muted ml-2 text-xs font-normal"
            >{attachment(ruleSet.members)}</span
          >
        </h2>
        {#each ruleSet.rules as rule (rule.id)}<div
            id={`rule-${rule.id}`}
            class="list-row"
            data-selected={selected === ruleSet.id}
            data-inactive={rule.state !== "active"}
          >
            <button
              class="flex min-w-0 flex-1 items-center gap-3 text-left"
              onclick={() => select(ruleSet.id)}
            >
              {#if rule.action === "allow"}<Check
                  size={18}
                  class="text-allow rule-row-dim shrink-0"
                  aria-hidden="true"
                />{:else}<Ban
                  size={18}
                  class="text-destructive rule-row-dim shrink-0"
                  aria-hidden="true"
                />{/if}<span class="min-w-0"
                ><span class="sr-only"
                  >{rule.action === "allow" ? "Allow" : "Block"}
                </span><span class="rule-row-dim"><RuleLabel {rule} /></span
                >{#if rule.state !== "active"}<span
                    class="rule-row-state block text-xs capitalize"
                    >{rule.state}</span
                  >{/if}</span
              >
            </button>
            <Button
              variant="ghost"
              size="icon"
              aria-label={`Edit ${rule.description}`}
              onclick={() => edit(ruleSet.id, rule)}
              ><Pencil size={15} /></Button
            ><Button
              variant="ghost"
              size="icon"
              aria-label={`Delete ${rule.description}`}
              onclick={() =>
                confirm({
                  title: "Delete this rule?",
                  description: "The remaining rules will decide this traffic.",
                  action: "Delete rule",
                  run: async (expectedRevision) => {
                    await api(`rules/${rule.id}`, "DELETE", {
                      expectedRevision,
                    });
                  },
                })}><Trash2 size={15} /></Button
            >
          </div>{/each}
        <Button
          variant="ghost"
          size="sm"
          class="mt-1"
          onclick={() => edit(ruleSet.id, null)}
          ><Plus size={14} />Add rule</Button
        >
      </section>{/each}
    {#if !sets.length}<div class="empty-state">No rule sets.</div>{/if}
  </section>
  <InspectorPanel label="Rule set inspector" bind:open={inspectorOpen}>
    {#if focused}<h2 class="section-title mb-4">Selected rule set</h2>
      <p class="break-words">{focused.name}</p>
      <dl class="mt-4 space-y-3">
        <div>
          <dt class="muted text-xs">Rules</dt>
          <dd class="numeric">{focused.rules.length}</dd>
        </div>
        <div>
          <dt class="muted text-xs">Attached to</dt>
          {#if focused.members.kind === "global"}<dd
              class="flex items-center gap-2"
            >
              <span class="min-w-0 flex-1"><BuiltInValue kind="any" /></span
              ><Button
                variant="ghost"
                size="icon-sm"
                aria-label="Detach from every instance"
                onclick={() =>
                  setMembers(focused, detach(focused.members, null))}
                ><X size={14} /></Button
              >
            </dd>{:else}{#each focused.members.instanceIds as id (id)}<dd
                class="flex items-center gap-2"
              >
                <span class="min-w-0 flex-1 break-words"
                  >{instanceName(id)}</span
                ><Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label={`Detach from ${instanceName(id)}`}
                  onclick={() =>
                    setMembers(focused, detach(focused.members, id))}
                  ><X size={14} /></Button
                >
              </dd>{:else}<dd class="muted">No instance</dd>{/each}{/if}
        </div>
      </dl>
      {#if unattached.length}<div
          class="control-row mt-4"
          role="group"
          aria-label="Attach rule set"
        >
          <Choice
            label="Attach to"
            bind:value={attachTo}
            options={unattached}
          /><Button
            variant="outline"
            disabled={!attachTo}
            onclick={() =>
              setMembers(
                focused,
                attach(focused.members, attachTo === "any" ? null : attachTo),
              )}>Attach</Button
          >
        </div>{/if}
      <div class="control-row mt-4">
        <Button variant="outline" onclick={() => exportSet(focused)}
          ><Download size={15} />Export</Button
        ><Button variant="outline" onclick={() => name("rename")}>Rename</Button
        ><Button
          variant="ghost"
          aria-label="Delete selected rule set"
          onclick={() => confirmDelete(focused)}><Trash2 size={15} /></Button
        >
      </div>
      {#if actionError}<p class="field-error mt-4" role="alert">
          {actionError}
        </p>{/if}
    {:else}<p class="muted">Select a rule set.</p>{/if}
  </InspectorPanel>
</div>
<RuleEditor
  bind:open={editorOpen}
  rule={editing}
  scope={editingSet
    ? { subject: { kind: "ruleSet", ruleSetId: editingSet } }
    : null}
  instances={model.instances}
  ruleSets={model.ruleSets}
  rules={model.rules}
  revision={model.revision}
  onSaved={() => refresh()}
/>
<RuleSetNameDialog
  bind:open={namingOpen}
  title={naming === "rename" ? "Rename rule set" : "Create rule set"}
  initial={namingSet?.name ?? ""}
  action={naming === "rename" ? "Rename" : "Create rule set"}
  onSubmit={saveName}
/>
<RuleSetImportDialog
  bind:open={importOpen}
  submit={(file, value) => create({ name: value, rules: file.rules })}
/>
<Dialog.Root
  open={confirming !== null}
  onOpenChange={(open) => {
    if (!open && !confirmBusy) confirming = null;
  }}
>
  <Dialog.Content
    showCloseButton={!confirmBusy}
    onEscapeKeydown={(event) => {
      if (confirmBusy) event.preventDefault();
    }}
    onInteractOutside={(event) => {
      if (confirmBusy) event.preventDefault();
    }}
  >
    {#if confirming}<Dialog.Header
        ><Dialog.Title>{confirming.title}</Dialog.Title><Dialog.Description
          >{confirming.description}</Dialog.Description
        ></Dialog.Header
      >{/if}
    {#if confirmError}<p class="field-error" role="alert">
        {confirmError}
      </p>{/if}
    <Dialog.Footer
      ><Button
        variant="outline"
        disabled={confirmBusy}
        onclick={() => (confirming = null)}>Cancel</Button
      ><Button
        variant="destructive"
        disabled={confirmBusy}
        onclick={runConfirmed}
        >{confirmBusy ? "Deleting…" : (confirming?.action ?? "Delete")}</Button
      ></Dialog.Footer
    >
  </Dialog.Content>
</Dialog.Root>
