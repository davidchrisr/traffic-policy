<script lang="ts">
  import { onMount, untrack } from "svelte";
  import { beforeNavigate, goto } from "$app/navigation";
  import { Pencil, RefreshCw, Search, Trash2 } from "@lucide/svelte";
  import type { PageProps } from "./$types";
  import {
    settingsSnapshotSchema,
    instancesSnapshotSchema,
  } from "@traffic-policy/contracts/dashboard";
  import { RefreshRunner } from "#lib/refresh-runner.ts";
  import { latestStatus, liveStatus } from "#lib/live-status.ts";
  import { api, ApiError, displayBytes } from "#lib/client.ts";
  import { formatByteSize, parseByteSize } from "#lib/byte-size.ts";
  import { instanceSchema, type Instance } from "@traffic-policy/contracts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import Choice from "#lib/components/Choice.svelte";
  import * as Dialog from "#lib/components/ui/dialog/index.ts";
  import StatusLine from "#lib/components/StatusLine.svelte";
  import Time from "#lib/components/Time.svelte";
  import SignOutButton from "#lib/components/SignOutButton.svelte";

  let { data }: PageProps = $props();

  // History limits name the usage they bound and say what they hold.
  const sizeFields = [
    { key: "gatewayDiskBytes", label: "Gateway runtime disk" },
    { key: "controllerDiskBytes", label: "Controller runtime disk" },
    {
      key: "trafficHistoryBytes",
      label: "Traffic history",
      usage: "traffic",
      help: "Traffic charts and connection records.",
    },
    {
      key: "dnsHistoryBytes",
      label: "DNS history",
      usage: "dns",
      help: "DNS lookups.",
    },
    {
      key: "blockedHistoryBytes",
      label: "Blocked packets",
      usage: "blocked",
      help: "Blocked packet samples and counts. Samples of the rule and instance with the most are removed first.",
    },
    {
      key: "otherHistoryBytes",
      label: "Other history",
      usage: "other",
      help: "Suricata records and condition events.",
    },
    { key: "auditBytes", label: "Change history" },
    { key: "collectorBytes", label: "Gateway delivery buffer" },
  ] as const;

  type SizeKey = (typeof sizeFields)[number]["key"];

  const catchAllFields = [
    { key: "outgoing", label: "Outgoing" },
    { key: "incoming", label: "Incoming" },
  ] as const;

  // An empty action means no permanent catch-all covers that direction yet.
  const catchAllDraft = (current: typeof data.catchAll) => ({
    outgoing: current.outgoing ?? "",
    incoming: current.incoming ?? "",
  });

  // Field text in sizeFields order.
  const sizeText = (values: Record<SizeKey, string>) =>
    sizeFields.map(({ key }) => formatByteSize(values[key]));

  let model = $state.raw(untrack(() => data)),
    settings = $state(untrack(() => structuredClone(data.settings))),
    sizes = $state(untrack(() => sizeText(data.settings))),
    catchAll = $state(untrack(() => catchAllDraft(data.catchAll))),
    sizesLeft = $state(sizeFields.map(() => false)),
    error = $state(""),
    saving = $state(false);

  let name = $state(""),
    addresses = $state(""),
    instanceOpen = $state(false);

  let editing = $state(false),
    instanceId = $state(""),
    instanceRevision = $state(""),
    initialInstance = $state(""),
    instanceError = $state(""),
    instanceFields = $state<{ path: string; message: string }[]>([]);

  const instanceDirty = $derived(
    initialInstance !== JSON.stringify({ name, addresses }),
  );

  const nameError = $derived(
    instanceFields.find((field) => field.path === "name")?.message,
  );

  const addressError = $derived(
    instanceFields.find((field) => field.path.startsWith("addresses"))?.message,
  );

  let now = $state(Date.now());

  let removing = $state<Instance | null>(null),
    removalRevision = $state(""),
    removalRules = $state(0),
    removalError = $state("");

  function confirmRemoval(instance: Instance) {
    removing = instance;
    removalRevision = model.revision;
    removalRules = model.rules.filter(
      (rule) =>
        rule.subject.kind === "instance" &&
        rule.subject.instanceId === instance.id,
    ).length;
    removalError = "";
  }

  async function signOut() {
    await api("auth/logout", "POST");
    discarding = true;
    location.assign("/login");
  }

  // Unsaved changes ask before leaving: an app dialog inside the app, the browser's prompt when the
  // page would unload.
  let leavingTo = $state<URL | null>(null),
    discarding = false;

  beforeNavigate((navigation) => {
    if (!dirty || discarding) return;
    navigation.cancel();

    if (!navigation.willUnload && navigation.to) leavingTo = navigation.to.url;
  });

  function discardAndLeave() {
    if (!leavingTo) return;
    const target = leavingTo;
    discarding = true;
    leavingTo = null;
    void goto(target);
  }

  async function removeInstance() {
    if (!removing || saving) return;
    saving = true;
    removalError = "";
    let accepted = false;

    try {
      await api(`instances/${removing.id}`, "DELETE", {
        expectedRevision: removalRevision,
      });
      accepted = true;
      removing = null;
      await refresh();
    } catch (failure) {
      const message =
        failure instanceof Error
          ? failure.message
          : "Instance could not be removed";

      if (accepted)
        error = `Instance removed. Settings could not be refreshed. ${message}`;
      else removalError = message;
    } finally {
      saving = false;
    }
  }

  let refreshingResources = $state(false);

  // The layout keeps status current between Settings refreshes.
  const live = liveStatus();

  const status = $derived(latestStatus(live.current, model.status));

  const resourcesRunner = new RefreshRunner<typeof data>({
    onValue: (next) => {
      model = next;
    },
    onError: (failure) => {
      throw failure;
    },
    onBusy: (busy) => {
      refreshingResources = busy;
    },
  });

  onMount(() => {
    const timer = setInterval(() => {
      now = Date.now();
    }, 1000);

    return () => {
      clearInterval(timer);
      resourcesRunner.dispose();
    };
  });

  // Each size field holds its text; a valid size updates the byte value the API takes.
  const sizeErrors = $derived(
    sizes.map((text) => {
      const parsed = parseByteSize(text);

      return "error" in parsed ? parsed.error : null;
    }),
  );

  const sizesInvalid = $derived(sizeErrors.some((message) => message !== null));

  const catchAllMissing = $derived(!catchAll.outgoing || !catchAll.incoming);

  const dirty = $derived(
    sizesInvalid ||
      catchAllMissing ||
      JSON.stringify(settings) !== JSON.stringify(model.settings) ||
      JSON.stringify(catchAll) !==
        JSON.stringify(catchAllDraft(model.catchAll)),
  );

  function editSize(index: number, key: SizeKey, text: string) {
    sizes[index] = text;
    const parsed = parseByteSize(text);

    if ("bytes" in parsed) settings[key] = parsed.bytes;
  }

  function resetSettings() {
    settings = structuredClone(model.settings);
    sizes = sizeText(model.settings);
    catchAll = catchAllDraft(model.catchAll);
    sizesLeft = sizeFields.map(() => false);
  }

  let settingFields = $state<{ path: string; message: string }[]>([]);

  const settingError = (key: string) =>
    settingFields.find((field) => field.path === `settings.${key}`)?.message;

  async function refreshSettings() {
    const keepDraft = dirty;
    error = "";

    try {
      await refresh();

      if (!keepDraft) resetSettings();
    } catch (failure) {
      error =
        failure instanceof Error
          ? failure.message
          : "Settings could not be refreshed";
    }
  }

  function refresh() {
    refreshingResources = true;

    return resourcesRunner.run(async (signal) => {
      const [rawResources, rawInstances] = await Promise.all([
        api("settings", "GET", undefined, signal),
        api("instances", "GET", undefined, signal),
      ]);

      const resources = settingsSnapshotSchema.parse(rawResources);
      const instances = instancesSnapshotSchema.parse(rawInstances);

      if (resources.revision !== instances.revision)
        throw new Error("Settings changed while refreshing. Try again.");

      return { ...resources, ...instances };
    });
  }

  async function save() {
    saving = true;
    error = "";
    settingFields = [];
    let accepted = false;

    try {
      await api("settings", "PUT", {
        expectedRevision: model.revision,
        settings,
        catchAll,
      });
      accepted = true;
      await refresh();
      resetSettings();
    } catch (failure) {
      if (failure instanceof ApiError)
        settingFields = failure.failure.fields ?? [];

      const message =
        failure instanceof Error
          ? failure.message
          : "Settings could not be saved";

      error = accepted
        ? `Settings saved. The displayed values could not be refreshed. ${message}`
        : message;
    } finally {
      saving = false;
    }
  }

  function editInstance(instance: Instance | null) {
    editing = instance !== null;
    instanceId = instance?.id ?? newInstanceId();
    instanceRevision = model.revision;
    name = instance?.name ?? "";
    addresses = instance?.addresses.join(", ") ?? "";
    initialInstance = JSON.stringify({ name, addresses });
    instanceError = "";
    instanceFields = [];
    instanceOpen = true;
  }

  function newInstanceId() {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6]! & 0x0f) | 0x40;
    bytes[8] = (bytes[8]! & 0x3f) | 0x80;

    const hex = Array.from(bytes, (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");

    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  async function saveInstance() {
    if (saving) return;
    instanceError = "";
    instanceFields = [];

    const parsed = instanceSchema.safeParse({
      id: instanceId,
      name,
      addresses: addresses.split(/[\s,]+/).filter(Boolean),
    });

    if (!parsed.success) {
      instanceFields = parsed.error.issues.map((issue) => ({
        path: issue.path.join("."),
        message: issue.message,
      }));
      instanceError = "Review the highlighted values.";

      return;
    }

    saving = true;
    let accepted = false;

    try {
      await api("instances", "PUT", {
        expectedRevision: instanceRevision,
        instance: parsed.data,
      });
      accepted = true;
      instanceOpen = false;
      name = "";
      addresses = "";
      await refresh();
    } catch (failure) {
      if (accepted) {
        error =
          "Instance saved. Settings could not be refreshed. Refresh to see the saved changes.";

        return;
      }

      instanceError =
        failure instanceof Error
          ? failure.message
          : "Instance could not be saved";

      if (failure instanceof ApiError) {
        instanceFields = (failure.failure.fields ?? []).map((field) => ({
          ...field,
          path: field.path.replace(/^instance\./, ""),
        }));

        const generalErrors = instanceFields.filter(
          (field) =>
            field.path !== "name" && !field.path.startsWith("addresses"),
        );

        if (generalErrors.length)
          instanceError = generalErrors
            .map((field) => field.message)
            .join("; ");
      }
    } finally {
      saving = false;
    }
  }

  async function lookup(instanceId: string, address: string) {
    saving = true;
    error = "";

    try {
      await api("names/lookup", "POST", { instanceId, address });
      await refresh();
    } catch (failure) {
      error =
        failure instanceof Error ? failure.message : "Reverse lookup failed";
    } finally {
      saving = false;
    }
  }
</script>

<svelte:head><title>Settings · Traffic Policy</title></svelte:head>
<header class="page-header">
  <h1 class="page-title">Settings</h1>
  <div class="header-actions">
    <StatusLine
      pending={status.pending}
      lastError={status.lastError as string | null}
      lastSeen={status.lastSeen as string | null}
    />
    <Button
      variant="ghost"
      size="icon"
      aria-label="Refresh settings"
      disabled={saving || refreshingResources}
      onclick={refreshSettings}
      ><RefreshCw
        size={16}
        class={refreshingResources ? "animate-spin" : undefined}
      /></Button
    >
    <Button
      disabled={!dirty || saving || sizesInvalid || catchAllMissing}
      onclick={save}>{saving ? "Saving…" : "Save changes"}</Button
    >
  </div>
</header>
<section class="page-content mx-auto max-w-4xl">
  {#if dirty}<p class="text-pending mb-4 text-xs">
      Unsaved changes
    </p>{/if}{#if error}<p class="field-error mb-4" role="alert">
      {error}
    </p>{/if}
  <div class="settings-sections">
    <section class="settings-section" aria-labelledby="settings-instances">
      <header class="settings-section-header">
        <h2 id="settings-instances" class="section-title">Instances</h2>
        <p>
          Manage instance names and the addresses controlled by traffic rules.
        </p>
      </header>
      {#each model.instances as instance (instance.id)}<div class="list-row">
          <div class="min-w-0 flex-1">
            <p class="break-words font-bold">{instance.name}</p>
            <p class="muted break-all font-mono text-xs">
              {instance.addresses.join(", ")}
            </p>
          </div>
          <Button
            variant="ghost"
            size="icon"
            disabled={saving}
            title="Edit instance"
            aria-label={`Edit ${instance.name}`}
            onclick={() => editInstance(instance)}><Pencil size={15} /></Button
          >
          <Button
            variant="ghost"
            size="icon"
            disabled={saving}
            title="Remove instance"
            aria-label={`Remove ${instance.name}`}
            onclick={() => confirmRemoval(instance)}
            ><Trash2 size={15} /></Button
          >
        </div>
        {#if model.settings.reverseDnsResolver}{#each instance.addresses.filter((address) => !address.includes("/")) as address (address)}{@const name =
              model.names.find(
                (value) =>
                  value.instanceId === instance.id && value.address === address,
              )}
            <div class="list-row ml-4">
              <span class="muted min-w-0 flex-1 break-all text-xs"
                >{address} · {name?.expiresAt &&
                Date.parse(name.expiresAt) <= now
                  ? "Expired"
                  : (name?.hostname ?? name?.status ?? "Not looked up")}</span
              ><Button
                variant="ghost"
                size="icon"
                disabled={saving}
                title="Look up name"
                aria-label={`Look up the name of ${address}`}
                onclick={() => lookup(instance.id, address)}
                ><Search size={15} /></Button
              >
            </div>{/each}{/if}
      {/each}<Button
        variant="outline"
        class="my-4"
        disabled={saving}
        onclick={() => editInstance(null)}>Add instance</Button
      >
    </section>
    <section class="settings-section" aria-labelledby="settings-catch-all">
      <header class="settings-section-header">
        <h2 id="settings-catch-all" class="section-title">Catch-all</h2>
        <p>
          Decides traffic that no rule matches. Rules allow or block specific
          traffic on top of it.
        </p>
      </header>
      {#each catchAllFields as item (item.key)}<div class="setting-row">
          <Label for={`catch-all-${item.key}`}>{item.label}</Label>
          <div class="field-group">
            <Choice
              id={`catch-all-${item.key}`}
              label={`${item.label} catch-all`}
              bind:value={catchAll[item.key]}
              options={[
                { value: "allow", label: "Allow" },
                { value: "block", label: "Block" },
              ]}
            />
            {#if !catchAll[item.key]}<p class="field-error">
                Choose Allow or Block.
              </p>{/if}
          </div>
        </div>{/each}
    </section>
    <section class="settings-section" aria-labelledby="settings-dns">
      <header class="settings-section-header">
        <h2 id="settings-dns" class="section-title">DNS permissions</h2>
      </header>
      <div class="setting-row">
        <div>
          <Label for="grace">DNS grace period in seconds</Label>
          <p class="field-help muted">
            Keeps a DNS permission this long after its record expires.
          </p>
        </div>
        <div class="field-group">
          <Input
            id="grace"
            type="number"
            min={0}
            max={604800}
            bind:value={settings.dnsGraceSeconds}
            aria-invalid={!!settingError("dnsGraceSeconds")}
          />
          {#if settingError("dnsGraceSeconds")}<p class="field-error">
              {settingError("dnsGraceSeconds")}
            </p>{/if}
        </div>
      </div>
      <div class="setting-row">
        <div>
          <Label for="permission-limit">Active permission limit</Label>
        </div>
        <div class="field-group">
          <Input
            id="permission-limit"
            type="number"
            min={1}
            max={100000}
            bind:value={settings.permissionLimit}
            aria-invalid={!!settingError("permissionLimit")}
          />
          {#if settingError("permissionLimit")}<p class="field-error">
              {settingError("permissionLimit")}
            </p>{/if}
        </div>
      </div>
    </section>
    <section class="settings-section" aria-labelledby="settings-storage">
      <header class="settings-section-header">
        <h2 id="settings-storage" class="section-title">Storage limits</h2>
        <p>
          Database size: {displayBytes(model.databaseBytes)}. Change history: {displayBytes(
            model.auditUsedBytes,
          )}.
        </p>
      </header>
      <div class="settings-section-body">
        <p class="field-help muted">
          Pending requests: {displayBytes(model.requestsUsedBytes)} of {displayBytes(
            model.requestsLimitBytes,
          )}
        </p>
        <p class="field-help muted">
          Controller runtime files: {displayBytes(model.storage.allocatedBytes)} of
          {displayBytes(model.storage.limitBytes)}. Recovery reserve: {displayBytes(
            model.storage.reserveBytes,
          )}.
        </p>
        {#if model.gatewayStorage}<p class="field-help muted">
            Gateway runtime files: {displayBytes(
              model.gatewayStorage.allocatedBytes,
            )} of {displayBytes(model.gatewayStorage.limitBytes)}. Last reported <Time
              value={model.gatewayStorage.at}
            />.
          </p>{:else}<p class="field-help muted">
            Gateway storage has not been reported.
          </p>{/if}
      </div>
      {#each sizeFields as item, index (item.key)}{@const fieldError =
          (sizesLeft[index] && sizeErrors[index]) || settingError(item.key)}
        <div class="setting-row">
          {#if "usage" in item}<div>
              <Label for={item.key}>{item.label} limit</Label>
              <p class="field-help muted">
                {item.help} Using {displayBytes(
                  model.historyUsedBytes[item.usage],
                )}.
              </p>
            </div>{:else}<Label for={item.key}>{item.label} limit</Label>{/if}
          <div class="field-group">
            <Input
              id={item.key}
              autocomplete="off"
              spellcheck="false"
              aria-invalid={!!fieldError}
              aria-describedby={fieldError ? `${item.key}-error` : undefined}
              value={sizes[index]}
              oninput={(event) =>
                editSize(index, item.key, event.currentTarget.value)}
              onblur={() => (sizesLeft[index] = true)}
            />
            {#if fieldError}<p class="field-error" id={`${item.key}-error`}>
                {fieldError}
              </p>{/if}
          </div>
        </div>{/each}
      <p class="muted mt-4 text-xs">Oldest records are removed at the limit.</p>
    </section>
    <section class="settings-section" aria-labelledby="settings-names">
      <header class="settings-section-header">
        <h2 id="settings-names" class="section-title">Name lookup</h2>
      </header>
      <div class="setting-row">
        <div>
          <Label for="reverse-resolver">Reverse DNS resolver</Label>
          <p class="field-help muted">Used for display names only.</p>
        </div>
        <Input
          id="reverse-resolver"
          value={settings.reverseDnsResolver ?? ""}
          oninput={(event) =>
            (settings.reverseDnsResolver = event.currentTarget.value || null)}
          placeholder="Disabled"
        />
      </div>
    </section>
    <section class="settings-section" aria-labelledby="settings-session">
      <header class="settings-section-header">
        <h2 id="settings-session" class="section-title">Session</h2>
      </header>
      <div class="settings-section-body justify-items-start">
        <SignOutButton onSignOut={signOut} />
      </div>
    </section>
  </div>
</section>
<Dialog.Root
  open={removing !== null}
  onOpenChange={(open) => {
    if (!open && !saving) removing = null;
  }}
>
  <Dialog.Content
    showCloseButton={!saving}
    onEscapeKeydown={(event) => {
      if (saving) event.preventDefault();
    }}
    onInteractOutside={(event) => {
      if (saving) event.preventDefault();
    }}
  >
    <Dialog.Header
      ><Dialog.Title>Remove {removing?.name}?</Dialog.Title><Dialog.Description
        >This removes the instance and {removalRules} instance-specific {removalRules ===
        1
          ? "rule"
          : "rules"}. Instance traffic rules will no longer apply to these
        addresses. Shared rules remain.</Dialog.Description
      ></Dialog.Header
    >
    <p class="font-mono text-xs break-all">{removing?.addresses.join(", ")}</p>
    {#if removalError}<p class="field-error" role="alert">
        {removalError}
      </p>{/if}
    <Dialog.Footer
      ><Button
        variant="outline"
        disabled={saving}
        onclick={() => (removing = null)}>Cancel</Button
      ><Button variant="destructive" disabled={saving} onclick={removeInstance}
        >{saving ? "Removing…" : "Remove instance"}</Button
      ></Dialog.Footer
    >
  </Dialog.Content>
</Dialog.Root>
<Dialog.Root bind:open={instanceOpen}
  ><Dialog.Content
    class="max-h-[90dvh] overflow-y-auto"
    showCloseButton={!instanceDirty && !saving}
    onEscapeKeydown={(event) => {
      if (instanceDirty || saving) event.preventDefault();
    }}
    onInteractOutside={(event) => {
      if (instanceDirty || saving) event.preventDefault();
    }}
    ><Dialog.Header
      ><Dialog.Title>{editing ? "Edit instance" : "Add instance"}</Dialog.Title
      ><Dialog.Description
        >{editing
          ? "Update its name or its IPv4 and IPv6 addresses and networks. Existing rules remain attached to this instance."
          : "Use a stable name and its IPv4 or IPv6 addresses. A network such as 10.10.0.0/24 covers every host in it; a host or network inside it can be its own instance and keeps this instance's rules."}</Dialog.Description
      ></Dialog.Header
    >
    <form
      class="space-y-4"
      onsubmit={(event) => {
        event.preventDefault();
        void saveInstance();
      }}
    >
      <div class="field-group">
        <Label for="instance-name">Name</Label><Input
          id="instance-name"
          bind:value={name}
          required
          maxlength={128}
          disabled={saving}
          aria-invalid={!!nameError}
          aria-describedby={nameError ? "instance-name-error" : undefined}
        />
        {#if nameError}<p class="field-error" id="instance-name-error">
            {nameError}
          </p>{/if}
      </div>
      <div class="field-group">
        <Label for="instance-addresses">Addresses</Label><Input
          id="instance-addresses"
          bind:value={addresses}
          required
          placeholder="Comma-separated IP addresses or networks"
          disabled={saving}
          aria-invalid={!!addressError}
          aria-describedby={addressError ? "instance-address-error" : undefined}
        />
        {#if addressError}<p class="field-error" id="instance-address-error">
            {addressError}
          </p>{/if}
      </div>
      {#if instanceError}<p class="field-error" role="alert">
          {instanceError}
        </p>{/if}<Dialog.Footer
        ><Button
          type="button"
          variant="ghost"
          disabled={saving}
          onclick={() => (instanceOpen = false)}>Cancel</Button
        ><Button type="submit" disabled={saving}
          >{saving
            ? "Saving…"
            : editing
              ? "Save instance"
              : "Add instance"}</Button
        ></Dialog.Footer
      >
    </form></Dialog.Content
  ></Dialog.Root
>
<Dialog.Root
  open={leavingTo !== null}
  onOpenChange={(open) => {
    if (!open) leavingTo = null;
  }}
>
  <Dialog.Content
    onOpenAutoFocus={(event) => {
      event.preventDefault();
      document.querySelector<HTMLButtonElement>("[data-leave-cancel]")?.focus();
    }}
  >
    <Dialog.Header
      ><Dialog.Title>Discard unsaved changes?</Dialog.Title><Dialog.Description
        >Your Settings changes have not been saved.</Dialog.Description
      ></Dialog.Header
    >
    <Dialog.Footer
      ><Button
        variant="outline"
        data-leave-cancel
        onclick={() => (leavingTo = null)}>Keep editing</Button
      ><Button variant="destructive" onclick={discardAndLeave}
        >Discard changes</Button
      ></Dialog.Footer
    >
  </Dialog.Content>
</Dialog.Root>
