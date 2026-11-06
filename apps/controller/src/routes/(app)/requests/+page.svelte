<script lang="ts">
  import { onMount, untrack } from "svelte";
  import { page } from "$app/state";
  import { Ban, RefreshCw } from "@lucide/svelte";
  import type { PageProps } from "./$types";
  import {
    requestNamesSchema,
    requestsSnapshotSchema,
    type RequestNames,
  } from "@traffic-policy/contracts/dashboard";
  import { RefreshRunner } from "#lib/refresh-runner.ts";
  import { api } from "#lib/client.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Badge } from "#lib/components/ui/badge/index.ts";
  import RuleEditor from "#lib/components/RuleEditor.svelte";
  import InspectorPanel from "#lib/components/InspectorPanel.svelte";
  import type { RuleDraft } from "@traffic-policy/contracts/dashboard";
  import StatusLine from "#lib/components/StatusLine.svelte";
  import Time from "#lib/components/Time.svelte";
  import DirectionIcon from "#lib/components/DirectionIcon.svelte";
  import RuleDecision from "#lib/components/RuleDecision.svelte";
  import { policyTree, ruleName, type DecisionState } from "#lib/rule-state.ts";
  import {
    decideTraffic,
    serviceLabel,
    subjectContext,
  } from "@traffic-policy/core";
  import {
    instanceSchema,
    ipSchema,
    type Rule,
  } from "@traffic-policy/contracts";
  import * as Dialog from "#lib/components/ui/dialog/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import Choice from "#lib/components/Choice.svelte";

  type Request = (typeof data.requests)[number];

  // A Request a rule decides; host Requests are decided by registering the host.
  type RuleRequest = Exclude<Request, { kind: "host" }>;

  let { data }: PageProps = $props();

  // Kept in a mustache so formatting cannot move or drop the spaces around it.
  const separator = " · ";

  let model = $state.raw(untrack(() => data)),
    filter = $state("needs-review"),
    selected = $state<string | null>(null),
    inspectorOpen = $state(false),
    error = $state("");

  let open = $state(false),
    scope = $state<Partial<RuleDraft> | null>(null),
    editing = $state.raw<Rule | null>(null),
    amend = $state.raw<{ dnsDestinations: string[] } | null>(null);

  const shown = $derived(
    model.requests.filter((request) => request.state === filter),
  );

  const stateLabels: Record<(typeof data.requests)[number]["state"], string> = {
    "needs-review": "Needs review",
    applying: "Applying",
    failed: "Failed",
    resolved: "Resolved",
    dismissed: "Dismissed",
  };

  // What the Allow/Block pair shows as the request's current decision.
  const decisions: Record<
    (typeof data.requests)[number]["state"],
    { state: DecisionState | null; description: string }
  > = {
    "needs-review": { state: "block", description: "Blocked, needs review" },
    applying: { state: "waiting", description: "Blocked, rule being applied" },
    failed: { state: "block", description: "Blocked, rule failed to apply" },
    resolved: { state: null, description: "Resolved" },
    dismissed: { state: "block", description: "Blocked, dismissed" },
  };

  const focused = $derived(
    model.requests.find((request) => request.id === selected),
  );

  const tabs = [
    { value: "needs-review", label: "Needs review" },
    { value: "applying", label: "Applying" },
    { value: "failed", label: "Failed" },
    { value: "dismissed", label: "Dismissed" },
  ] as const;

  // Needs review uses the exact count; the list holds only the newest requests.
  const counts = $derived({
    "needs-review": model.status.needsReview,
    applying: model.requests.filter((request) => request.state === "applying")
      .length,
    failed: model.requests.filter((request) => request.state === "failed")
      .length,
    dismissed: model.requests.filter((request) => request.state === "dismissed")
      .length,
  });

  const sourceLabels: Record<RequestNames["names"][number]["source"], string> =
    {
      dns: "DNS answer",
      tls: "TLS",
      http: "HTTP",
    };

  let names = $state.raw<RequestNames["names"] | null>(null),
    namesError = $state("");

  // Loaded when a request is selected; the lookup scans retained DNS and connection records.
  $effect(() => {
    const id = selected;
    const controller = new AbortController();

    names = null;
    namesError = "";

    const request = untrack(() =>
      model.requests.find((value) => value.id === id),
    );

    if (!id || request?.kind !== "connection") return;
    api(
      `requests/${encodeURIComponent(id)}/names`,
      "GET",
      undefined,
      controller.signal,
    )
      .then((value) => {
        names = requestNamesSchema.parse(value).names;
      })
      .catch(() => {
        if (!controller.signal.aborted)
          namesError = "Names could not be loaded. Select the request again.";
      });

    return () => controller.abort();
  });

  // Allow rules for a name seen at the request's address that would decide it if they admitted the
  // address as a DNS answer, for the request's latest client.
  const refusing = $derived.by(() => {
    const request = focused;

    if (!request || request.kind !== "connection" || !names) return [];

    const context = request.clients[0]
      ? subjectContext(
          policyTree(model.instances, model.rules),
          request.clients[0].address,
        )
      : null;

    if (!context) return [];

    const found: {
      rule: Rule;
      name: string;
      reason: "outside" | "not-public";
    }[] = [];

    for (const { hostname } of names)
      for (const { rule, reason } of decideTraffic(
        model.rules,
        context,
        request,
        model.localNetworks,
        Date.now(),
        hostname,
      ).refused)
        if (
          rule.action === "allow" &&
          !found.some((entry) => entry.rule.id === rule.id)
        )
          found.push({ rule, name: hostname, reason });

    return found;
  });

  let refreshing = $state(false);

  const runner = new RefreshRunner<typeof data>({
    onValue: (next) => {
      model = next;
      error = "";
    },
    onError: () => {
      error = "Requests could not be refreshed. Try again.";
    },
    onBusy: (busy) => {
      refreshing = busy;
    },
  });

  // The host a Monitor link names, which every refresh keeps loading.
  const host = $derived(
    ipSchema.nullable().parse(page.url.searchParams.get("host")),
  );

  const missingHost = $derived(
    host !== null &&
      !model.requests.some(
        (request) => request.kind === "host" && request.clientIp === host,
      )
      ? host
      : null,
  );

  function refresh(supersede = true) {
    return runner.run(
      async (signal) =>
        requestsSnapshotSchema.parse(
          await api(
            host === null
              ? "requests"
              : `requests?host=${encodeURIComponent(host)}`,
            "GET",
            undefined,
            signal,
          ),
        ),
      supersede,
    );
  }

  // Each load, including one for a link to another host from this page, replaces the Requests.
  // Monitor links here with an unregistered host: open its Request, which the load includes
  // however old it is.
  $effect(() => {
    const next = data;

    untrack(() => {
      // A poll still loading for the previous URL must not replace this load.
      runner.cancel();
      model = next;

      const linked = model.requests.find(
        (request) => request.kind === "host" && request.clientIp === host,
      );

      if (linked) {
        filter = linked.state;
        selected = linked.id;
        inspectorOpen = true;
      } else if (host !== null) {
        // The linked host has no Request; keep no other Request open in its place.
        selected = null;
        inspectorOpen = false;
      }
    });
  });

  onMount(() => {
    const timer = setInterval(() => {
      void refresh(false);
    }, 5000);

    return () => {
      clearInterval(timer);
      runner.dispose();
    };
  });

  // Decides a Request for its instance, or for one of its clients' addresses.
  function decide(
    request: RuleRequest,
    action: "allow" | "block",
    address: string | null = null,
  ) {
    editing = null;
    amend = null;
    scope = {
      action,
      subject: address
        ? { kind: "address", value: address }
        : { kind: "instance", instanceId: request.instanceId },
      ...(request.kind === "dns"
        ? {
            direction: "outgoing",
            peer:
              request.question === "."
                ? { kind: "any" }
                : { kind: "hostname", value: request.question },
            protocol: null,
            portStart: null,
            portEnd: null,
          }
        : {
            direction: request.direction,
            peer: { kind: "ip", value: request.peerIp },
            protocol: request.protocol,
            portStart: request.port,
            portEnd: request.port,
          }),
    };
    open = true;
  }

  function refusalText(
    rule: Rule,
    name: string,
    reason: "outside" | "not-public",
  ) {
    const why =
      reason === "outside"
        ? "outside the rule's permitted destination networks"
        : "which is not a public address";

    const note = rule.dnsDestinations
      ? ""
      : " Listing a network limits the rule to its listed networks, so it no longer allows public addresses.";

    return `${name} resolves to this address, ${why}, so ${ruleName(rule)} does not apply.${note}`;
  }

  // An address is its own scope unless it is exactly one of its instance's addresses.
  const ownAddress = (request: RuleRequest, address: string) =>
    model.instances
      .find((instance) => instance.id === request.instanceId)
      ?.addresses.includes(address) ?? false;

  let registering = $state<string | null>(null),
    registerTarget = $state("new"),
    registerName = $state(""),
    registerAddress = $state(""),
    registerError = $state(""),
    registerSaving = $state(false);

  function register(address: string) {
    registering = address;
    registerTarget = "new";
    registerName = "";
    registerAddress = address;
    registerError = "";
  }

  // Rules written for exactly the registered address move to a new instance of its own. Added to
  // an instance with other addresses, they would apply to all of them, so saving is refused.
  const promoted = $derived(
    model.rules.filter(
      (rule) =>
        rule.subject.kind === "address" &&
        rule.subject.value === registerAddress.trim(),
    ),
  );

  async function saveRegistration() {
    if (registerSaving) return;
    registerError = "";

    const existing = model.instances.find(
      (instance) => instance.id === registerTarget,
    );

    const parsed = instanceSchema.safeParse(
      existing
        ? {
            ...existing,
            addresses: [...existing.addresses, registerAddress.trim()],
          }
        : {
            id: crypto.randomUUID(),
            name: registerName,
            addresses: [registerAddress.trim()],
          },
    );

    if (!parsed.success) {
      registerError = parsed.error.issues[0]?.message ?? "Review the values.";

      return;
    }

    registerSaving = true;

    try {
      await api("instances", "PUT", {
        expectedRevision: model.status.desiredRevision,
        instance: parsed.data,
      });
      registering = null;
      await refresh();
    } catch (failure) {
      registerError =
        failure instanceof Error
          ? failure.message
          : "The host could not be registered";
    } finally {
      registerSaving = false;
    }
  }

  let dismissing = $state<string | null>(null);

  // A dismissed host stops asking for review; registering it still applies the rules.
  async function dismiss(address: string) {
    if (dismissing) return;
    dismissing = address;
    error = "";

    try {
      await api(
        `requests/hosts/${encodeURIComponent(address)}/dismiss`,
        "POST",
        {},
      );
      await refresh();
    } catch (failure) {
      error =
        failure instanceof Error
          ? failure.message
          : "The host Request could not be dismissed";
    } finally {
      dismissing = null;
    }
  }

  // Opens the rule with the request's exact address added to its permitted destination networks.
  function allowThrough(rule: Rule, address: string) {
    editing = rule;
    amend = {
      dnsDestinations: [
        ...(rule.dnsDestinations ?? []),
        `${address}/${address.includes(":") ? 128 : 32}`,
      ],
    };
    scope = null;
    open = true;
  }
</script>

<svelte:head><title>Requests · Traffic Policy</title></svelte:head>
<header class="page-header">
  <h1 class="page-title">Requests</h1>
  <div class="header-actions">
    <StatusLine
      pending={model.status.pending}
      lastError={model.status.lastError as string | null}
      lastSeen={model.status.lastSeen as string | null}
    />
    <Button
      variant="ghost"
      size="icon"
      aria-label="Refresh requests"
      disabled={refreshing}
      onclick={() => refresh()}><RefreshCw size={16} /></Button
    >
  </div>
</header>
<div class="split-view">
  <section class="page-content">
    <div class="control-row mb-4">
      {#each tabs as item (item.value)}<Button
          variant={filter === item.value ? "selected" : "ghost"}
          size="sm"
          aria-pressed={filter === item.value}
          onclick={() => (filter = item.value)}
          >{item.label}{#if counts[item.value]}<span class="muted numeric"
              >{counts[item.value].toLocaleString()}</span
            >{/if}</Button
        >{/each}
    </div>
    {#if error}<p class="field-error" role="alert">{error}</p>{/if}
    {#if missingHost}<p class="field-help mb-4" role="status">
        {missingHost} has no host Request. Registering the host or reaching the queue
        limit removes it.
      </p>{/if}
    {#if model.retention.discarded !== "0"}<p
        class="field-help mb-4"
        role="status"
      >
        {model.retention.discarded} older pending {model.retention.discarded ===
        "1"
          ? "request was"
          : "requests were"} removed when the queue reached its limit.
      </p>{/if}
    {#if model.retention.dnsOmitted !== "0"}<p
        class="field-help mb-4"
        role="status"
      >
        {BigInt(model.retention.dnsOmitted).toLocaleString()} denied DNS {model
          .retention.dnsOmitted === "1"
          ? "lookup"
          : "lookups"} over the rate limit {model.retention.dnsOmitted === "1"
          ? "wasn't"
          : "weren't"} recorded.
      </p>{/if}
    {#if model.retention.pending > model.requests.length}<p
        class="field-help muted mb-4"
      >
        Showing the newest {model.requests.length} of {model.retention.pending.toLocaleString()}
        pending requests.
      </p>{/if}
    {#if shown.some((request) => request.kind === "host")}<section class="mb-4">
        <h2 class="section-title mb-2">Unregistered hosts</h2>
        {#each shown.filter((request) => request.kind === "host") as request (request.id)}<div
            class="list-row"
            data-selected={selected === request.id}
          >
            <button
              class="min-w-0 flex-1 text-left"
              onclick={() => {
                selected = request.id;
                inspectorOpen = true;
              }}
              ><span class="block break-all font-mono">{request.clientIp}</span
              ><span class="muted text-xs"
                >{request.attempts} dropped {request.attempts === "1"
                  ? "packet"
                  : "packets"}, sampled{#if request.names[0]}{separator}{request
                    .names[0].name}{/if}</span
              ></button
            >{#if request.state === "needs-review"}<Button
                variant="ghost"
                size="sm"
                disabled={dismissing === request.clientIp}
                onclick={() => dismiss(request.clientIp)}>Dismiss</Button
              >{/if}<Button
              variant="outline"
              size="sm"
              onclick={() => register(request.clientIp)}>Register</Button
            >
          </div>{/each}
      </section>{/if}
    {#each model.instances as instance (instance.id)}<section class="mb-4">
        {#if shown.some((request) => request.kind !== "host" && request.instanceId === instance.id)}<h2
            class="section-title mb-2"
          >
            {instance.name}
          </h2>{/if}
        {#each shown.filter((request): request is RuleRequest => request.kind !== "host" && request.instanceId === instance.id) as request (request.id)}{@const sampled =
            request.kind === "dns"
              ? `${request.attempts} denied DNS ${request.attempts === "1" ? "lookup" : "lookups"}`
              : `${request.attempts} blocked ${request.attempts === "1" ? "packet" : "packets"}, sampled`}
          {@const destination =
            request.kind === "dns" ? request.question : request.peerIp}
          {@const service =
            request.kind === "dns"
              ? request.queryType
              : serviceLabel(request.protocol, request.port)}
          <div class="list-row" data-selected={selected === request.id}>
            <button
              class="min-w-0 flex-1 text-left"
              onclick={() => {
                selected = request.id;
                inspectorOpen = true;
              }}
              ><span class="block break-all">{destination}</span><span
                class="rule-label muted text-xs"
                ><DirectionIcon
                  direction={request.kind === "dns"
                    ? "outgoing"
                    : request.direction}
                /><span>{service}</span><span
                  class="inline-flex items-center gap-1"
                  title={sampled}
                  ><Ban
                    size={13}
                    class="text-destructive"
                    aria-hidden="true"
                  /><span aria-hidden="true">{request.attempts}</span><span
                    class="sr-only">{sampled}</span
                  ></span
                ></span
              ></button
            ><RuleDecision
              state={decisions[request.state].state}
              scope={`${destination} ${service}`}
              description={decisions[request.state].description}
              onallow={() => decide(request, "allow")}
              onblock={() => decide(request, "block")}
            />
          </div>{/each}
      </section>{/each}
    {#if !shown.length}<div class="empty-state">
        No requests in this view.
      </div>{/if}
  </section>
  <InspectorPanel label="Request inspector" bind:open={inspectorOpen}>
    {#if focused?.kind === "host"}<h2 class="section-title mb-4">
        Unregistered host
      </h2>
      <p class="break-all font-mono">{focused.clientIp}</p>
      <p class="field-help mt-2">
        No instance covers this address, so its traffic is dropped. Register it
        to apply your rules; its later denials become ordinary requests.
      </p>
      <div class="mt-4">
        <span class="muted text-xs">Recent destinations</span>
        {#if focused.destinations.length}<ul class="space-y-1">
            {#each focused.destinations as destination (destination.address)}<li
              >
                <span class="break-all font-mono">{destination.address}</span
                ><span class="muted text-xs"
                  >{separator}<Time value={destination.at} /></span
                >
              </li>{/each}
          </ul>{:else}<p class="muted">None recorded.</p>{/if}
      </div>
      <div class="mt-4">
        <span class="muted text-xs">Names it looked up</span>
        {#if focused.names.length}<ul class="space-y-1">
            {#each focused.names as name (name.name)}<li>
                <span class="break-all">{name.name}</span><span
                  class="muted text-xs"
                  >{separator}<Time value={name.at} /></span
                >
              </li>{/each}
          </ul>{:else}<p class="muted">None seen by Suricata.</p>{/if}
      </div>
      <div class="mt-4 space-y-3">
        <div>
          <span class="muted text-xs">First observed</span>
          <p><Time value={focused.firstAt} /></p>
        </div>
        <div>
          <span class="muted text-xs">Last observed</span>
          <p><Time value={focused.lastAt} /></p>
        </div>
        <div class="control-row">
          <Button
            onclick={() =>
              focused.kind === "host" && register(focused.clientIp)}
            >Register</Button
          >{#if focused.state === "needs-review"}<Button
              variant="outline"
              disabled={dismissing === focused.clientIp}
              onclick={() =>
                focused.kind === "host" && dismiss(focused.clientIp)}
              >Dismiss</Button
            >{/if}
        </div>
      </div>{:else if focused}<h2 class="section-title mb-4">
        {focused.kind === "dns" ? "Denied DNS lookup" : "Blocked attempt"}
      </h2>
      <p class="break-all font-mono">
        {focused.kind === "dns" ? focused.question : focused.peerIp}
      </p>
      {#if focused.kind === "dns"}
        <div class="mt-4">
          <span class="muted text-xs">Query type</span>
          <p>{focused.queryType}</p>
        </div>
        {#if focused.question === "."}<p class="field-help mt-2">
            Allowing this needs an Any peer rule.
          </p>{/if}
      {:else}
        <div class="mt-4">
          <span class="muted text-xs">Names seen at this address</span>
          {#if namesError}<p class="field-error" role="alert">
              {namesError}
            </p>{:else if names === null}<p class="muted">
              Loading…
            </p>{:else if names.length}<ul class="space-y-1">
              {#each names as name (name.hostname)}<li>
                  <span class="block break-all">{name.hostname}</span><span
                    class="muted text-xs"
                    >{sourceLabels[name.source]}{separator}<Time
                      value={name.lastSeenAt}
                    /></span
                  >
                </li>{/each}
            </ul>
            {#each refusing as { rule, name, reason } (rule.id)}<div
                class="mt-3 space-y-2"
              >
                <p class="field-help">
                  {refusalText(rule, name, reason)}
                </p>
                <Button
                  variant="outline"
                  size="sm"
                  onclick={() =>
                    focused.kind === "connection" &&
                    allowThrough(rule, focused.peerIp)}
                  >Allow through {"value" in rule.peer
                    ? rule.peer.value
                    : ruleName(rule)}</Button
                >
              </div>{/each}{:else}<p class="muted">
              No names seen for this address from this instance.
            </p>{/if}
        </div>
      {/if}
      <div class="mt-4">
        <span class="muted text-xs">Recent clients</span>
        <ul class="space-y-2">
          {#each focused.clients as client (client.address)}<li
              class="flex flex-wrap items-center gap-2"
            >
              <span class="break-all font-mono">{client.address}</span><span
                class="muted text-xs"><Time value={client.at} /></span
              >{#if !ownAddress(focused, client.address)}<Button
                  variant="outline"
                  size="sm"
                  onclick={() => decide(focused, "allow", client.address)}
                  >Allow for this address</Button
                >{/if}
            </li>{/each}
        </ul>
      </div>
      <div class="mt-4 space-y-3">
        <div>
          <span class="muted text-xs">First observed</span>
          <p><Time value={focused.firstAt} /></p>
        </div>
        <div>
          <span class="muted text-xs">Last observed</span>
          <p><Time value={focused.lastAt} /></p>
        </div>
        <Badge variant="outline">{stateLabels[focused.state]}</Badge>
      </div>{:else}<p class="muted">Select a request.</p>{/if}
  </InspectorPanel>
</div>
<Dialog.Root
  open={registering !== null}
  onOpenChange={(value) => {
    if (!value && !registerSaving) registering = null;
  }}
  ><Dialog.Content
    ><Dialog.Header
      ><Dialog.Title>Register host</Dialog.Title><Dialog.Description
        >Add the address to an instance so your rules apply to it. A network
        covers every host in it.</Dialog.Description
      ></Dialog.Header
    >
    <form
      class="space-y-4"
      onsubmit={(event) => {
        event.preventDefault();
        void saveRegistration();
      }}
    >
      <div class="field-group">
        <Label for="register-target">Instance</Label><Choice
          fullWidth
          id="register-target"
          label="Instance"
          bind:value={registerTarget}
          options={[
            { value: "new", label: "New instance" },
            ...model.instances.map((instance) => ({
              value: instance.id,
              label: `Add to ${instance.name}`,
            })),
          ]}
        />
      </div>
      {#if registerTarget === "new"}<div class="field-group">
          <Label for="register-name">Name</Label><Input
            id="register-name"
            bind:value={registerName}
            required
            maxlength={128}
            disabled={registerSaving}
          />
        </div>{/if}
      <div class="field-group">
        <Label for="register-address">Address or network</Label><Input
          id="register-address"
          bind:value={registerAddress}
          required
          disabled={registerSaving}
        />
      </div>
      {#if promoted.length && registerTarget === "new"}<p class="field-help">
          {promoted.length}
          {promoted.length === 1 ? "rule" : "rules"} for exactly this address will
          move to the instance.
        </p>{:else if promoted.length}<p class="field-help">
          {promoted.length}
          {promoted.length === 1 ? "rule is" : "rules are"} written for exactly this
          address. Remove {promoted.length === 1 ? "it" : "them"} or register the
          address as its own instance.
        </p>{/if}
      {#if registerError}<p class="field-error" role="alert">
          {registerError}
        </p>{/if}
      <Dialog.Footer
        ><Button
          type="button"
          variant="ghost"
          disabled={registerSaving}
          onclick={() => (registering = null)}>Cancel</Button
        ><Button type="submit" disabled={registerSaving}>Register</Button
        ></Dialog.Footer
      >
    </form></Dialog.Content
  ></Dialog.Root
>
<RuleEditor
  bind:open
  rule={editing}
  {amend}
  {scope}
  instances={model.instances}
  rules={model.rules}
  revision={model.status.desiredRevision}
  onSaved={() => refresh()}
/>
