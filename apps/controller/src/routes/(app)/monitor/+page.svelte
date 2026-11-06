<script lang="ts">
  import { onMount, untrack } from "svelte";
  import {
    ArrowDown,
    ArrowUp,
    ChevronRight,
    ChevronDown,
    RefreshCw,
  } from "@lucide/svelte";
  import type { PageProps } from "./$types";
  import type { Rule } from "@traffic-policy/contracts";
  import { api, displayTrafficBytes } from "#lib/client.ts";
  import {
    groupBlocked,
    groupDestinations,
    groupNames,
  } from "#lib/monitor-groups.ts";
  import {
    isCatchAll,
    isSettingsCatchAll,
    ruleState,
    scopeKey,
    serviceLabel,
    subjectPath,
  } from "@traffic-policy/core";
  import {
    combineStates,
    decideService,
    inspectorBuiltIns,
    inspectorRules,
    policyTree,
    reviewKeys,
    ruleTitle,
    stateDescription,
    type ServiceDecision,
  } from "#lib/rule-state.ts";
  import Time from "#lib/components/Time.svelte";
  import { currentTime } from "#lib/clock.ts";
  import {
    formatFullInstant,
    formatInstantInSentence,
  } from "#lib/format-time.ts";
  import RuleDecision from "#lib/components/RuleDecision.svelte";
  import RuleLabel from "#lib/components/RuleLabel.svelte";
  import DirectionIcon from "#lib/components/DirectionIcon.svelte";
  import { MonitorView } from "#lib/monitor-view.ts";
  import {
    monitorSnapshotSchema,
    rulesSnapshotSchema,
  } from "@traffic-policy/contracts/dashboard";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import TrafficPeriodPicker from "#lib/components/TrafficPeriodPicker.svelte";
  import TrafficChart from "#lib/components/TrafficChart.svelte";
  import TrafficMeasure from "#lib/components/TrafficMeasure.svelte";
  import RuleEditor from "#lib/components/RuleEditor.svelte";
  import type { RuleDraft } from "@traffic-policy/contracts/dashboard";
  import StatusLine from "#lib/components/StatusLine.svelte";
  import InspectorPanel from "#lib/components/InspectorPanel.svelte";

  let { data }: PageProps = $props();

  const controller = new MonitorView(
    untrack(() => data),
    async (query, signal) =>
      monitorSnapshotSchema.parse(
        await api(`monitor?${query}`, "GET", undefined, signal),
      ),
  );

  let view = $state.raw(untrack(() => controller.snapshot));

  let search = $state(""),
    expanded = $state<string[]>(
      untrack(() => data.instances.map((instance) => instance.id)),
    ),
    expandedPeers = $state<string[]>([]),
    editorOpen = $state(false),
    inspectorOpen = $state(false),
    scope = $state<Partial<RuleDraft> | null>(null),
    editing = $state<Rule | null>(null),
    revision = $state(untrack(() => data.status.desiredRevision));

  const model = $derived(view.model),
    roster = $derived(view.roster),
    listingTruncated = $derived(view.servicesTruncated),
    error = $derived(view.error),
    refreshing = $derived(view.busy),
    hasMeasurements = $derived(view.hasMeasurements),
    hasRoster = $derived(view.hasRoster);

  const selected = $derived(
    view.scope.kind === "service" ? view.scope.key : null,
  );

  const selectedPeer = $derived(
    view.scope.kind === "destination" ? view.scope.key : null,
  );

  const selectedInstance = $derived(
    view.scope.kind === "all" ? null : view.scope.instanceId,
  );

  const focused = $derived(roster.find((service) => service.key === selected));

  const serviceScope = $derived(
    view.scope.kind === "service" ? view.scope : null,
  );

  const nameScope = $derived(
    view.scope.kind === "domain" || view.scope.kind === "hostname"
      ? view.scope
      : null,
  );

  const observedNames = $derived(view.names);

  const inspectorNames = $derived(
    model.names.filter(
      (name) =>
        name.instanceId === selectedInstance &&
        ((!serviceScope && !peerAddress) ||
          name.peerIp === (serviceScope?.peerIp ?? peerAddress)),
    ),
  );

  let expandedNames = $state<string[]>([]),
    collapsedAddresses = $state<string[]>([]);

  const nameKey = (kind: string, instanceId: string, name: string) =>
    JSON.stringify([kind, instanceId, name]);

  function expandName(key: string) {
    expandedNames = expandedNames.includes(key)
      ? expandedNames.filter((value) => value !== key)
      : [...expandedNames, key];
  }

  const peerAddress = $derived(
    view.scope.kind === "destination" ? view.scope.peerIp : null,
  );

  onMount(() => {
    const unsubscribe = controller.subscribe((next) => {
      view = next;
    });

    controller.start();

    return () => {
      unsubscribe();
      controller.dispose();
    };
  });

  const allDestinations = $derived(groupDestinations(roster));

  const focusedPeer = $derived(
    allDestinations.find((peer) => peer.key === selectedPeer),
  );

  const shown = $derived(
    roster.filter(
      (service) =>
        !search ||
        `${service.peerIp} ${observedNames
          .filter(
            (name) =>
              name.instanceId === service.instanceId &&
              name.peerIp === service.peerIp,
          )
          .map((name) => name.hostname)
          .join(
            " ",
          )} ${model.instances.find((instance) => instance.id === service.instanceId)?.name} ${service.direction} ${service.protocol === 6 ? "TCP" : service.protocol === 17 ? "UDP" : service.protocol} ${service.port ?? ""}`
          .toLowerCase()
          .includes(search.toLowerCase()),
    ),
  );

  const destinations = $derived(groupDestinations(shown));

  const groups = $derived(
    model.instances.map((instance) => ({
      ...instance,
      peers: destinations.filter((peer) => peer.instanceId === instance.id),
    })),
  );

  const selectedName = $derived(
    model.instances.find((instance) => instance.id === selectedInstance)?.name,
  );

  function expand(id: string) {
    expanded = expanded.includes(id)
      ? expanded.filter((value) => value !== id)
      : [...expanded, id];
  }

  function expandPeer(key: string) {
    expandedPeers = expandedPeers.includes(key)
      ? expandedPeers.filter((value) => value !== key)
      : [...expandedPeers, key];
  }

  // Kept in a mustache so formatting cannot move or drop the spaces around it.
  const separator = " · ";

  // The gateway's own addresses, which Monitor shows and rules name as the gateway.
  const gatewayAddresses = $derived(
    new Set(model.status.gateway?.addresses ?? []),
  );

  const peerOf = (address?: string): RuleDraft["peer"] =>
    !address
      ? { kind: "any" }
      : gatewayAddresses.has(address)
        ? { kind: "gateway" }
        : { kind: "ip", value: address };

  async function create(
    action: "allow" | "block",
    instanceId: string,
    service?: (typeof data.services)[number],
    peerIp?: string,
    namedPeer?: { kind: "domain" | "hostname"; value: string },
    direction: "outgoing" | "incoming" | "both" = "both",
  ) {
    const rules = rulesSnapshotSchema.parse(await api("rules"));
    revision = rules.revision;

    const selectedScope: Required<RuleDraft> = {
      action,
      subject: { kind: "instance", instanceId },
      direction: namedPeer ? "outgoing" : (service?.direction ?? direction),
      peer: namedPeer ?? peerOf(service?.peerIp ?? peerIp),
      protocol: service?.protocol ?? null,
      portStart: service?.port ?? null,
      portEnd: service?.port ?? null,
      icmpType: null,
      icmpCode: null,
      enabled: true,
      priority: "normal",
      notBefore: null,
      expiresAt: null,
      dnsDestinations: null,
      reason: "",
    };

    scope = selectedScope;
    editing =
      rules.rules.find((rule) => scopeKey(rule) === scopeKey(selectedScope)) ??
      null;

    if (editing) editing = { ...editing, action };
    editorOpen = true;
  }

  // List rows open the inspector; on narrow screens it appears as a sheet.
  function inspect(target: Parameters<typeof controller.select>[0]) {
    controller.select(target);
    inspectorOpen = true;
  }

  async function editRule(rule: Rule, action: "allow" | "block") {
    const rules = rulesSnapshotSchema.parse(await api("rules"));
    revision = rules.revision;
    scope = null;
    editing = {
      ...(rules.rules.find((value) => value.id === rule.id) ?? rule),
      action,
    };
    editorOpen = true;
  }

  // A destination rule follows its observed services' direction; mixed directions use both.
  function peerDirection(services: { direction: "outgoing" | "incoming" }[]) {
    const directions = new Set(services.map((service) => service.direction));

    return directions.size === 1 ? [...directions][0]! : "both";
  }

  const reviews = $derived(reviewKeys(view.reviews));

  const decisions = $derived(
    new Map(
      roster.flatMap((service) => {
        const decision = decideService(
          model.rules,
          model.instances,
          model.localNetworks,
          reviews,
          service,
          undefined,
          undefined,
          model.status.gateway,
        );

        return decision ? [[service.key, decision] as const] : [];
      }),
    ),
  );

  function serviceDecisions(services: { key: string }[]) {
    return services.map((service) => decisions.get(service.key));
  }

  // Name rows evaluate their services by name, so a rule for that name decides without a DNS caveat.
  function nameDecisions(
    peers: { services: (typeof roster)[number][] }[],
    name: string,
  ) {
    return peers.flatMap((peer) =>
      peer.services.map(
        (service) =>
          decideService(
            model.rules,
            model.instances,
            model.localNetworks,
            reviews,
            service,
            name,
            undefined,
            model.status.gateway,
          ) ?? undefined,
      ),
    );
  }

  function rowState(list: (ServiceDecision | undefined)[]) {
    const state = combineStates(list.map((decision) => decision?.state));

    return {
      state,
      description: stateDescription(
        state,
        list.length === 1 ? list[0] : undefined,
      ),
    };
  }

  const selectionDecisions = $derived.by(() => {
    if (!selectedInstance) return [];

    if (serviceScope) return serviceDecisions([serviceScope]);

    if (focusedPeer) return serviceDecisions(focusedPeer.services);

    if (nameScope) {
      const named = groupNames(
        allDestinations.filter((peer) => peer.instanceId === selectedInstance),
        observedNames,
      );

      const hosts =
        nameScope.kind === "domain"
          ? (named.domains.find((domain) => domain.name === nameScope.name)
              ?.hosts ?? [])
          : named.domains
              .flatMap((domain) => domain.hosts)
              .filter((host) => host.name === nameScope.name);

      return hosts.flatMap((host) => nameDecisions(host.peers, host.name));
    }

    return serviceDecisions(
      roster.filter((service) => service.instanceId === selectedInstance),
    );
  });

  const ruleRows = $derived(inspectorRules(selectionDecisions));

  const builtIns = $derived(inspectorBuiltIns(selectionDecisions));

  const summaryEvents = $derived(model.eventSummary?.events ?? []);

  const eventGroups = $derived(
    summaryEvents.filter((group) => group.type !== "blocked"),
  );

  const eventLabels = {
    traffic: "Traffic",
    metadata: "Protocol metadata",
    dns: "DNS",
    blocked: "Blocked",
  } as const;

  const blockedRule = (ruleId: string | null) =>
    model.rules.find((rule) => rule.id === ruleId) ?? null;

  const packetCount = new Intl.NumberFormat();

  const blocked = $derived(
    model.eventSummary
      ? groupBlocked(model.eventSummary, view.scope.kind === "instance")
      : null,
  );
</script>

{#snippet peerRows(
  peers: ((typeof destinations)[number] & { names?: string[] })[],
  instanceName: string,
)}
  {#each peers as peer (peer.key)}
    {@const peerState = rowState(serviceDecisions(peer.services))}
    <div
      class="list-row monitor-row monitor-destination"
      data-selected={!selected && selectedPeer === peer.key}
    >
      <Button
        variant="ghost"
        size="icon"
        aria-label={`${expandedPeers.includes(peer.key) ? "Collapse" : "Expand"} destination ${peer.peerIp}`}
        aria-expanded={expandedPeers.includes(peer.key)}
        onclick={() => expandPeer(peer.key)}
        >{#if expandedPeers.includes(peer.key)}<ChevronDown
            size={16}
          />{:else}<ChevronRight size={16} />{/if}</Button
      >
      <button
        class="monitor-name"
        aria-label={`Inspect destination ${peer.peerIp} in ${instanceName}`}
        aria-pressed={!selected && selectedPeer === peer.key}
        onclick={() =>
          inspect({
            kind: "destination",
            instanceId: peer.instanceId,
            peerIp: peer.peerIp,
            key: peer.key,
          })}
        ><span class="block"
          >{#if gatewayAddresses.has(peer.peerIp)}Gateway <span
              class="muted text-xs">{peer.peerIp}</span
            >{:else}{peer.peerIp}{/if}</span
        >{#if peer.names?.length}<span
            class="muted text-xs"
            title={peer.names.length > 2 ? peer.names.join(", ") : undefined}
            >{peer.names.slice(0, 2).join(", ")}{peer.names.length > 2
              ? ` +${peer.names.length - 2}`
              : ""}</span
          >{/if}</button
      >
      <div
        class="monitor-measure"
        title={listingTruncated
          ? "Totals for visible services"
          : "Destination traffic"}
      >
        <TrafficMeasure received={peer.receivedBytes} sent={peer.sentBytes} />
      </div>
      <div class="monitor-actions">
        <RuleDecision
          state={peerState.state}
          scope={`destination ${peer.peerIp}`}
          description={peerState.description}
          onallow={() =>
            create(
              "allow",
              peer.instanceId,
              undefined,
              peer.peerIp,
              undefined,
              peerDirection(peer.services),
            )}
          onblock={() =>
            create(
              "block",
              peer.instanceId,
              undefined,
              peer.peerIp,
              undefined,
              peerDirection(peer.services),
            )}
        />
      </div>
    </div>
    {#if expandedPeers.includes(peer.key)}
      {#each peer.services as service (service.key)}
        {@const serviceState = rowState(serviceDecisions([service]))}
        {@const label = serviceLabel(service.protocol, service.port)}
        <div
          class="list-row monitor-row monitor-service"
          data-selected={selected === service.key}
        >
          <button
            class="monitor-name"
            aria-label={`Inspect service ${label} ${service.direction} for ${peer.peerIp}`}
            aria-pressed={selected === service.key}
            onclick={() => inspect({ kind: "service", ...service })}
            ><span class="rule-label"
              ><DirectionIcon direction={service.direction} /><span
                >{label}</span
              ></span
            ></button
          >
          <div class="monitor-measure">
            <TrafficMeasure
              received={service.receivedBytes}
              sent={service.sentBytes}
              meter
            />
          </div>
          <div class="monitor-actions">
            <RuleDecision
              state={serviceState.state}
              scope={`${peer.peerIp} ${label} ${service.direction}`}
              description={serviceState.description}
              onallow={() => create("allow", peer.instanceId, service)}
              onblock={() => create("block", peer.instanceId, service)}
            />
          </div>
        </div>
      {/each}
    {/if}
  {/each}
{/snippet}

<svelte:head><title>Monitor · Traffic Policy</title></svelte:head>
<header class="page-header">
  <h1 class="page-title">Monitor</h1>
  <div class="header-actions">
    <StatusLine
      pending={model.status.pending}
      lastError={model.status.lastError as string | null}
      lastSeen={model.status.lastSeen as string | null}
    />
    <TrafficPeriodPicker
      bind:value={() => view.period, (value) => controller.setPeriod(value)}
      bind:since={() => view.since, (value) => controller.setSince(value)}
    />
    <Button
      variant="ghost"
      size="icon"
      aria-label="Refresh traffic"
      disabled={refreshing}
      onclick={() => controller.refresh()}
      ><RefreshCw
        size={16}
        class={refreshing ? "animate-spin" : undefined}
      /></Button
    >
  </div>
</header>
<div class="split-view" aria-busy={refreshing}>
  <section class="page-content min-w-0">
    <div class="control-row mb-4">
      <Input
        aria-label="Search traffic"
        placeholder="Search instances, destinations, or services"
        bind:value={search}
        class="min-w-0 flex-1"
      />
      {#if selected || selectedPeer || selectedInstance}<Button
          variant="outline"
          onclick={() => controller.select({ kind: "all" })}>All traffic</Button
        >{/if}
    </div>
    {#if error}<p class="field-error mb-3" role="alert">
        {error}
        {#if hasMeasurements}Displayed measurements have not been updated.{/if}
      </p>{/if}
    {#if listingTruncated}<p class="text-pending mb-3 text-xs">
        The first 1,000 services are shown. Destination sums cover visible
        services; selection totals and the timeline cover the complete
        selection.
      </p>{/if}
    {#if model.namesTruncated}<p class="text-pending mb-3 text-xs">
        Name observations are limited for this period. Use a shorter period for
        complete name grouping. IP traffic totals are unchanged.
      </p>{/if}
    <!-- The scrollable list needs keyboard focus. -->
    <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
    <div
      class="monitor-list"
      role="region"
      aria-label="Traffic destinations"
      tabindex="0"
    >
      {#if !hasRoster}<p class="muted py-6 text-center" role="status">
          {error
            ? "Traffic is unavailable for this period."
            : "Loading traffic for this period…"}
        </p>{:else}
        {#each groups as group (group.id)}
          {@const groupState = rowState(
            serviceDecisions(group.peers.flatMap((peer) => peer.services)),
          )}
          <section class="mb-3" aria-label={group.name}>
            <div
              class="list-row monitor-row"
              data-selected={!selected &&
                !selectedPeer &&
                !nameScope &&
                selectedInstance === group.id}
            >
              <!-- An instance with no destinations keeps the column but has nothing to expand. -->
              <Button
                variant="ghost"
                size="icon"
                class={group.peers.length ? undefined : "invisible"}
                disabled={!group.peers.length}
                aria-label={`${expanded.includes(group.id) ? "Collapse" : "Expand"} ${group.name}`}
                aria-expanded={expanded.includes(group.id)}
                onclick={() => expand(group.id)}
                >{#if expanded.includes(group.id)}<ChevronDown
                    size={16}
                  />{:else}<ChevronRight size={16} />{/if}</Button
              >
              <button
                class="monitor-name font-semibold"
                aria-label={`Inspect instance ${group.name}`}
                aria-pressed={!selected &&
                  !selectedPeer &&
                  !nameScope &&
                  selectedInstance === group.id}
                onclick={() =>
                  inspect({ kind: "instance", instanceId: group.id })}
                >{group.name}<span class="muted ml-2 text-xs font-normal"
                  >{group.peers.length}
                  {group.peers.length === 1
                    ? "destination"
                    : "destinations"}</span
                ></button
              >
              <div class="monitor-actions">
                <RuleDecision
                  state={groupState.state}
                  scope={`instance ${group.name}`}
                  description={groupState.description}
                  onallow={() => create("allow", group.id)}
                  onblock={() => create("block", group.id)}
                />
              </div>
            </div>
            {#if expanded.includes(group.id)}
              {@const named = groupNames(group.peers, observedNames)}
              {#each named.domains as domain (domain.name)}
                {@const domainKey = nameKey("domain", group.id, domain.name)}
                {@const domainState = rowState(
                  domain.hosts.flatMap((host) =>
                    nameDecisions(host.peers, host.name),
                  ),
                )}
                <div
                  class="list-row monitor-row monitor-destination"
                  data-selected={nameScope?.key === domainKey}
                >
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label={`Expand domain ${domain.name}`}
                    aria-expanded={expandedNames.includes(domainKey)}
                    onclick={() => expandName(domainKey)}
                    >{#if expandedNames.includes(domainKey)}<ChevronDown
                        size={16}
                      />{:else}<ChevronRight size={16} />{/if}</Button
                  >
                  <button
                    class="monitor-name break-all"
                    aria-label={`Inspect domain ${domain.name}`}
                    aria-pressed={nameScope?.key === domainKey}
                    onclick={() =>
                      inspect({
                        kind: "domain",
                        instanceId: group.id,
                        name: domain.name,
                        key: domainKey,
                      })}
                    >{domain.name}<span class="block muted text-xs"
                      >{domain.hosts.length} observed {domain.hosts.length === 1
                        ? "hostname"
                        : "hostnames"}</span
                    ></button
                  >
                  <div class="monitor-measure">
                    <TrafficMeasure
                      received={domain.receivedBytes}
                      sent={domain.sentBytes}
                    />
                  </div>
                  <div class="monitor-actions">
                    <RuleDecision
                      state={domainState.state}
                      scope={`domain ${domain.name}`}
                      description={domainState.description}
                      onallow={() =>
                        create("allow", group.id, undefined, undefined, {
                          kind: "domain",
                          value: domain.name,
                        })}
                      onblock={() =>
                        create("block", group.id, undefined, undefined, {
                          kind: "domain",
                          value: domain.name,
                        })}
                    />
                  </div>
                </div>
                {#if expandedNames.includes(domainKey)}
                  <div class="pl-4">
                    {#each domain.hosts as host (host.name)}
                      {@const hostKey = nameKey(
                        "hostname",
                        group.id,
                        host.name,
                      )}
                      {@const hostState = rowState(
                        nameDecisions(host.peers, host.name),
                      )}
                      <div
                        class="list-row monitor-row monitor-destination"
                        data-selected={nameScope?.key === hostKey}
                      >
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={`Expand hostname ${host.name}`}
                          aria-expanded={expandedNames.includes(hostKey)}
                          onclick={() => expandName(hostKey)}
                          >{#if expandedNames.includes(hostKey)}<ChevronDown
                              size={16}
                            />{:else}<ChevronRight size={16} />{/if}</Button
                        >
                        <button
                          class="monitor-name break-all"
                          aria-label={`Inspect hostname ${host.name}`}
                          aria-pressed={nameScope?.key === hostKey}
                          onclick={() =>
                            inspect({
                              kind: "hostname",
                              instanceId: group.id,
                              name: host.name,
                              key: hostKey,
                            })}>{host.name}</button
                        >
                        <div class="monitor-measure">
                          <TrafficMeasure
                            received={host.receivedBytes}
                            sent={host.sentBytes}
                          />
                        </div>
                        <div class="monitor-actions">
                          <RuleDecision
                            state={hostState.state}
                            scope={`hostname ${host.name}`}
                            description={hostState.description}
                            onallow={() =>
                              create("allow", group.id, undefined, undefined, {
                                kind: "hostname",
                                value: host.name,
                              })}
                            onblock={() =>
                              create("block", group.id, undefined, undefined, {
                                kind: "hostname",
                                value: host.name,
                              })}
                          />
                        </div>
                      </div>
                      {#if expandedNames.includes(hostKey)}<div class="pl-4">
                          {@render peerRows(host.peers, group.name)}
                        </div>{/if}
                    {/each}
                  </div>
                {/if}
              {/each}
              {#if named.ungrouped.length}
                {@const addressesOpen = !collapsedAddresses.includes(group.id)}
                <div class="list-row monitor-row monitor-destination">
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label={`${addressesOpen ? "Collapse" : "Expand"} IP addresses in ${group.name}`}
                    aria-expanded={addressesOpen}
                    onclick={() =>
                      (collapsedAddresses = addressesOpen
                        ? [...collapsedAddresses, group.id]
                        : collapsedAddresses.filter(
                            (value) => value !== group.id,
                          ))}
                    >{#if addressesOpen}<ChevronDown
                        size={16}
                      />{:else}<ChevronRight size={16} />{/if}</Button
                  >
                  <span class="monitor-name"
                    >IP addresses<span class="block muted text-xs"
                      >{named.ungrouped.length}
                      {named.ungrouped.length === 1
                        ? "address"
                        : "addresses"}</span
                    ></span
                  >
                </div>
                {#if addressesOpen}<div class="pl-4">
                    {@render peerRows(named.ungrouped, group.name)}
                  </div>{/if}
              {/if}
            {/if}
          </section>
        {/each}
        {#if !model.instances.length}<div class="empty-state">
            Add an instance in Settings to start managing its permissions.
          </div>{:else if roster.length && !shown.length}<p
            class="muted py-6 text-center"
          >
            No destinations or services match this search.
          </p>{/if}
      {/if}
    </div>
    <section class="monitor-timeline" aria-label="Selection traffic timeline">
      <div class="relative">
        <div
          class={hasMeasurements ? undefined : "invisible"}
          aria-hidden={!hasMeasurements}
        >
          <div class="mb-3 flex gap-8">
            <div>
              <div class="muted flex items-center gap-1 text-xs">
                <ArrowDown size={14} />Received
              </div>
              <div class="metric-value mt-1 text-chart-1">
                {displayTrafficBytes(model.receivedBytes)}
              </div>
            </div>
            <div>
              <div class="muted flex items-center gap-1 text-xs">
                <ArrowUp size={14} />Sent
              </div>
              <div class="metric-value mt-1 text-chart-2">
                {displayTrafficBytes(model.sentBytes)}
              </div>
            </div>
          </div>
          <TrafficChart
            timeline={model.timeline}
            from={model.from}
            to={model.to}
          />
        </div>
        {#if !hasMeasurements}<p
            role="status"
            class="absolute inset-0 flex items-center justify-center muted text-xs"
          >
            {error
              ? "Traffic is unavailable for this selection."
              : "Loading traffic for this selection…"}
          </p>{/if}
      </div>
    </section>
    {#if model.unregistered.drops.length || model.unregistered.clientPackets !== "0" || model.unregistered.upstreamPackets !== "0"}<section
        class="mt-6"
        aria-labelledby="monitor-unregistered"
      >
        <h2 id="monitor-unregistered" class="section-title mb-2">
          Unregistered drops
        </h2>
        <p class="field-help mb-2">
          Connections with no instance on either end are dropped. {BigInt(
            model.unregistered.clientPackets,
          ).toLocaleString()} packets from client networks, which also appear in Requests
          for registration; {BigInt(
            model.unregistered.upstreamPackets,
          ).toLocaleString()} from upstream interfaces. Sampled drops are grouped
          by source, destination, and service{model.unregistered.samplesLimited
            ? ", from the newest 5,000 samples"
            : ""}.
        </p>
        {#each model.unregistered.drops as drop (`${drop.side}|${drop.clientIp}|${drop.peerIp}|${drop.protocol}|${drop.port}`)}<div
            class="list-row flex-wrap text-xs"
          >
            <span class="muted shrink-0"><Time value={drop.lastAt} /></span
            ><span class="min-w-0 flex-1 break-all font-mono"
              >{drop.clientIp} → {drop.peerIp}</span
            ><span class="muted shrink-0"
              >{[
                drop.gateway
                  ? ["Gateway", drop.gateway.services.join(" or ")]
                      .filter(Boolean)
                      .join(" ")
                  : null,
                serviceLabel(drop.protocol, drop.port),
                drop.side === "client" ? "Client interface" : "Upstream",
              ]
                .filter(Boolean)
                .join(separator)}</span
            >
            <p class="muted basis-full">
              {drop.samples.toLocaleString()}
              {drop.samples === 1 ? "sample" : "samples"} since
              <Time value={drop.firstAt} />{#if drop.request}{separator}<a
                  class="link-subtle"
                  href={`/requests?host=${encodeURIComponent(drop.clientIp)}`}
                  >Request</a
                >{/if}
            </p>
            {#if drop.side === "client" && drop.gateway?.services.includes("DNS")}<p
                class="muted basis-full break-words"
              >
                Lookups from this host in this span: {drop.names.length
                  ? drop.names.map(({ name }) => name).join(", ")
                  : "none seen by Suricata"}
              </p>{/if}
          </div>{/each}
        {#if model.unregistered.dropsTruncated}<p
            class="text-pending mt-2 text-xs"
          >
            Showing the 50 most recent groups. Choose a shorter period to see
            others.
          </p>{/if}
      </section>{/if}
  </section>
  <InspectorPanel label="Traffic inspector" bind:open={inspectorOpen}>
    {#if selectedInstance}
      <h2 class="section-title mb-4">
        {selected
          ? "Service"
          : nameScope?.kind === "domain"
            ? "Domain"
            : nameScope?.kind === "hostname"
              ? "Hostname"
              : selectedPeer
                ? "Destination"
                : "Instance"}
      </h2>
      <p class="font-semibold break-words">{selectedName}</p>
      {#if nameScope}<p class="mt-2 break-all">{nameScope.name}</p>{/if}
      {#if serviceScope || peerAddress}<p
          class="mt-2 break-all font-mono text-sm"
        >
          {serviceScope ? serviceScope.peerIp : peerAddress}
        </p>{/if}
      {#if serviceScope}<p class="rule-label mt-2">
          <DirectionIcon direction={serviceScope.direction} /><span
            >{serviceLabel(serviceScope.protocol, serviceScope.port)}</span
          >
        </p>{/if}
      {#if hasMeasurements}<dl class="mt-4 flex gap-8">
          <div>
            <dt class="muted flex items-center gap-1 text-xs">
              <ArrowDown size={14} />Received
            </dt>
            <dd class="numeric">
              {displayTrafficBytes(model.receivedBytes)}
            </dd>
          </div>
          <div>
            <dt class="muted flex items-center gap-1 text-xs">
              <ArrowUp size={14} />Sent
            </dt>
            <dd class="numeric">{displayTrafficBytes(model.sentBytes)}</dd>
          </div>
        </dl>{:else}<p class="muted mt-4 text-xs">
          {error
            ? "Measurements are unavailable for this selection."
            : "Loading measurements…"}
        </p>{/if}
      {#if hasMeasurements}
        <h3
          class="section-title mt-6 mb-2"
          title="Current configuration. Past traffic may have been decided by rules that have since changed."
        >
          Rules
        </h3>
        {#each builtIns as row (`${row.direction}|${row.label}`)}
          <div class="list-row inspector-rule">
            <RuleDecision
              state="allow"
              scope={row.label}
              description="Allows this traffic"
              onallow={() => {}}
              onblock={() => {}}
              locked="Built into the gateway"
            />
            <span class="rule-label min-w-0"
              ><DirectionIcon direction={row.direction} /><span
                class="min-w-0 break-words">{row.label}</span
              ></span
            >
          </div>
        {/each}
        {#each ruleRows as row (row.rule.id)}
          {@const own =
            isCatchAll(row.rule) ||
            (row.rule.subject.kind === "instance" &&
              row.rule.subject.instanceId === selectedInstance)}
          <div class="list-row inspector-rule" data-dim={row.note !== null}>
            <RuleDecision
              state={ruleState(row.rule) === "active" ? row.rule.action : null}
              scope={`rule ${ruleTitle(row.rule)}`}
              description={row.note ??
                `${row.rule.action === "allow" ? "Allows" : "Blocks"} this traffic`}
              onallow={() => editRule(row.rule, "allow")}
              onblock={() => editRule(row.rule, "block")}
              locked={isSettingsCatchAll(row.rule)
                ? "Change the catch-all in Settings"
                : null}
            />
            <span class="min-w-0" title={row.note ?? undefined}
              ><RuleLabel
                rule={row.rule}
                dns={row.dns}
                instances={own ? null : model.instances}
                path={own
                  ? null
                  : subjectPath(
                      row.rule.subject,
                      policyTree(model.instances, model.rules),
                      model.instances,
                    )}
              />{#if row.note}<span class="sr-only">{row.note}</span>{/if}</span
            >
          </div>
        {:else}{#if !builtIns.length}<p class="muted text-xs">
              No measured traffic in this period to evaluate.
            </p>{/if}{/each}
        <a class="link-subtle mt-2 inline-block text-xs" href="/rules"
          >All rules</a
        >
        {#if blocked?.rules.length || blocked?.instanceBlocked}
          <h3
            class="section-title mt-6 mb-2"
            title="Packet totals count every blocked packet. Destinations are sampled up to 10 packets per second for each rule."
          >
            Blocked
          </h3>
          {#each blocked?.rules ?? [] as entry (entry.key)}
            {@const rule = blockedRule(entry.ruleId)}
            <div class="list-row inspector-event">
              <span class="rule-label min-w-0 flex-1"
                >{#if entry.direction}<DirectionIcon
                    direction={entry.direction}
                  />{/if}<span class="min-w-0 break-words"
                  >{rule ? ruleTitle(rule) : "Deleted rule"}{rule &&
                  ruleState(rule) === "expired"
                    ? " · expired"
                    : ""}</span
                ></span
              >
              {#if entry.packets !== null}<span
                  class="numeric shrink-0 text-xs"
                  title={`Packets this rule blocked for ${selectedName ?? "this instance"} in this period, all destinations. Counting starts at the minute containing the period start, or the hour when the period starts more than a day ago.`}
                  >{packetCount.format(entry.packets)}
                  {entry.packets === 1n ? "packet" : "packets"}</span
                >{/if}
            </div>
            {#each entry.rows as group (`${group.direction}|${group.protocol}|${group.port}|${group.ruleId}`)}
              <div class="list-row inspector-event">
                <span class="min-w-0 flex-1 pl-6 font-mono text-sm"
                  >{serviceLabel(
                    group.protocol,
                    group.port,
                  )}{#if rule && rule.modifiedAt > group.lastAt}<span
                      class="muted font-sans"
                    >
                      · rule changed since</span
                    >{/if}</span
                >
                <span
                  class="muted shrink-0 text-xs"
                  title={model.eventSummary?.eventsLimited
                    ? `${group.count} sampled among the newest 5,000 events. Older samples are not counted.`
                    : model.eventSummary?.scannedFrom
                      ? `${group.count} sampled among the newest 100,000 events. Older events were not checked.`
                      : entry.incomplete
                        ? `${group.count} sampled. The rule blocked more packets than it sampled, so this destination may have more.`
                        : `${group.count} blocked packets, all sampled`}
                  >{group.count}{entry.incomplete ||
                  model.eventSummary?.eventsLimited ||
                  model.eventSummary?.scannedFrom
                    ? "+"
                    : ""} · <Time value={group.lastAt} /></span
                >
              </div>
            {:else}<p class="muted pl-6 text-xs">
                {blocked?.partial
                  ? "No sample rows in this summary"
                  : "No retained samples in this period"}
              </p>{/each}
          {/each}
          {#if blocked?.instanceBlocked && selectedInstance}<p
              class="text-pending mt-2 text-xs"
            >
              This instance blocked packets in this period. Matching samples may
              be outside the checked events.
            </p>
            <Button
              class="mt-2"
              variant="outline"
              size="sm"
              onclick={() =>
                controller.select({
                  kind: "instance",
                  instanceId: selectedInstance,
                })}>Inspect instance</Button
            >{/if}
        {/if}
        <h3 class="section-title mt-6 mb-2">Observed names</h3>
        {#each inspectorNames as name (`${name.instanceId}|${name.peerIp}|${name.hostname}`)}
          <div class="list-row inspector-event">
            <span class="min-w-0 flex-1 break-all">{name.hostname}</span>
            <span class="muted shrink-0 text-xs" title={name.peerIp}
              >{name.source.toUpperCase()}{name.protocol === null
                ? ""
                : ` · ${serviceLabel(name.protocol, name.port)}`} · <Time
                value={name.observedAt}
              /></span
            >
          </div>
        {:else}<p class="muted text-xs">
            No HTTP or TLS names observed.
          </p>{/each}
        <h3 class="section-title mt-6 mb-2">Events</h3>
        {#each eventGroups as group (`${group.type}|${group.direction}|${group.protocol}|${group.port}`)}
          <div class="list-row inspector-event">
            <span class="rule-label min-w-0 flex-1"
              >{#if group.direction}<DirectionIcon
                  direction={group.direction}
                />{/if}<span class="font-mono text-sm"
                >{serviceLabel(group.protocol, group.port)}</span
              ><span>{eventLabels[group.type]}</span></span
            >
            <span class="muted shrink-0 text-xs"
              >{group.count} · <Time value={group.lastAt} /></span
            >
          </div>
        {:else}<p class="muted text-xs">
            {model.eventSummary?.scannedFrom
              ? "No events among the newest 100,000 in this period."
              : "No events retained in this period."}
          </p>{/each}
        {#if model.eventSummary?.scannedFrom}<p
            class="text-pending mt-2 text-xs"
          >
            Checked the newest 100,000 events in this period; the oldest is from <time
              datetime={model.eventSummary.scannedFrom}
              title={formatFullInstant(model.eventSummary.scannedFrom)}
              >{formatInstantInSentence(
                model.eventSummary.scannedFrom,
                currentTime(),
              )}</time
            >. Older events were not checked.
          </p>{/if}
        {#if view.scannedAt !== null}<p class="muted mt-2 text-xs">
            Scanned the whole period {formatInstantInSentence(
              new Date(view.scannedAt).toISOString(),
              currentTime(),
            )}. Rescan to include newer events.
          </p>{/if}
        {#if model.eventSummary?.scannedFrom || view.scannedAt !== null || view.scanning}<Button
            class="mt-2"
            variant="outline"
            size="sm"
            disabled={view.scanning}
            onclick={() => controller.scanWholePeriod()}
            >{view.scanning
              ? "Scanning…"
              : view.scannedAt !== null
                ? "Rescan"
                : "Scan whole period"}</Button
          >{/if}
        {#if view.scanError}<p class="field-error mt-2" role="alert">
            {view.scanError}
          </p>{/if}
        {#if model.eventSummary?.eventsLimited}<p
            class="text-pending mt-2 text-xs"
          >
            Counts cover the newest 5,000 events in this period. Use a shorter
            period for complete counts.
          </p>{/if}
        {#if model.eventSummary?.eventsTruncated}<p
            class="text-pending mt-2 text-xs"
          >
            Showing the 100 most recent groups. Narrow the selection for more.
          </p>{/if}
      {/if}
      {#if hasMeasurements && hasRoster && (selected || selectedPeer) && !focused && !focusedPeer}<p
          class="muted mt-3 text-xs"
        >
          The selected scope has no measured services in this period.
        </p>{/if}
    {:else}<p class="muted">Select an item.</p>{/if}
  </InspectorPanel>
</div>
<RuleEditor
  bind:open={editorOpen}
  rule={editing}
  {scope}
  instances={model.instances}
  rules={model.rules}
  {revision}
  onSaved={async () => {
    await controller.refresh();
    revision = controller.snapshot.model.status.desiredRevision;
  }}
/>
