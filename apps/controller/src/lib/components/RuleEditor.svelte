<script lang="ts">
  import {
    ArrowLeft,
    ArrowLeftRight,
    ArrowRight,
    Ban,
    Check,
    Layers,
    TriangleAlert,
  } from "@lucide/svelte";
  import type { Instance, Rule, RuleSet } from "@traffic-policy/contracts";
  import type { RuleDraft } from "@traffic-policy/contracts/dashboard";
  import type { RequestPeer } from "#lib/request-peer.ts";
  import {
    formatPorts,
    parsePorts,
    ruleInputSchema,
    subjectScope,
  } from "@traffic-policy/contracts";
  import { api, ApiError } from "#lib/client.ts";
  import * as Dialog from "#lib/components/ui/dialog/index.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import { Textarea } from "#lib/components/ui/textarea/index.ts";
  import { Switch } from "#lib/components/ui/switch/index.ts";
  import { dnsAddressRefusal, overriddenBy } from "@traffic-policy/core";
  import { currentTime } from "#lib/clock.ts";
  import { formatInstantInSentence } from "#lib/format-time.ts";
  import { policyTree } from "#lib/rule-state.ts";
  import { nextDay, nextQuarterHour } from "#lib/date-picking.ts";
  import Choice from "./Choice.svelte";
  import DateTimeField from "./DateTimeField.svelte";
  import RuleLabel from "./RuleLabel.svelte";

  let {
    open = $bindable(false),
    rule = null,
    scope = null,
    amend = null,
    peerChoices = [],
    suggestionsComplete = true,
    peerAddress = null,
    localNetworks = [],
    instances,
    ruleSets,
    rules = [],
    revision,
    onSaved,
  }: {
    open: boolean;
    rule?: Rule | null;
    scope?: Partial<RuleDraft> | null;
    // Changes proposed on top of `rule`, shown as unsaved for review.
    amend?: { dnsDestinations: string[] } | null;
    peerChoices?: RequestPeer[];
    // False when more DNS names may share the address than `peerChoices` lists.
    suggestionsComplete?: boolean;
    // The address the rule is for, checked against a hostname or domain rule's networks.
    peerAddress?: string | null;
    localNetworks?: string[];
    instances: Instance[];
    ruleSets: RuleSet[];
    // The current rules, used to warn when another rule overrides this one.
    rules?: Rule[];
    revision: string;
    onSaved: () => Promise<void>;
  } = $props();

  const fresh = () => ({
    action: "allow",
    // "any", an instance or rule set ID, or "address" for the address field below.
    subject: "any",
    subjectAddress: "",
    direction: "outgoing",
    peerKind: "any",
    peerValue: "",
    protocol: "any",
    ports: "",
    icmpType: "",
    icmpCode: "",
    priority: "normal",
    enabled: true,
    lifetime: "permanent",
    notBefore: "",
    expiresAt: "",
    // Off admits public answers outside the local networks; on admits only the listed networks.
    limitNetworks: false,
    dnsDestinations: "",
    reason: "",
  });

  let fields = $state(fresh());

  let loadedKey = $state<string | null>(null),
    initial = $state(""),
    expectedRevision = $state("");

  // The start and end the editor opened with, put back when the lifetime leaves Custom.
  let loadedTimes = { notBefore: "", expiresAt: "" };

  let saving = $state(false),
    error = $state("");

  let fieldErrors = $state<{ path: string; message: string }[]>([]);

  const dirty = $derived(initial !== JSON.stringify(fields));

  // Why the typed ports are not a port list, shown under the field as they are typed.
  const portsError = $derived.by(() => {
    try {
      parsePorts(fields.ports);

      return "";
    } catch (failure) {
      return failure instanceof Error ? failure.message : "Enter valid ports";
    }
  });

  function choosePeer(value: string) {
    const peer = peerChoices.find((choice) => JSON.stringify(choice) === value);

    if (peer) {
      fields.peerKind = peer.kind;
      fields.peerValue = peer.value;
    }
  }

  // Custom starts at once and ends a day from the next quarter hour unless an end is already set;
  // leaving Custom puts back the loaded times, so trying Custom leaves nothing to save.
  function chooseLifetime(value: string) {
    fields.lifetime = value;

    if (value !== "custom") {
      fields.notBefore = loadedTimes.notBefore;
      fields.expiresAt = loadedTimes.expiresAt;

      return;
    }

    fields.expiresAt ||= nextDay(nextQuarterHour());
  }

  $effect(() => {
    const key = rule?.id ?? "new";

    if (!open) {
      loadedKey = null;

      return;
    }

    if (loadedKey === key) return;
    const value = rule ?? scope;
    const next = fresh();

    if (value) {
      next.action = value.action ?? "allow";
      next.subject =
        value.subject?.kind === "instance"
          ? value.subject.instanceId
          : value.subject?.kind === "ruleSet"
            ? value.subject.ruleSetId
            : value.subject?.kind === "address"
              ? "address"
              : "any";
      next.subjectAddress =
        value.subject?.kind === "address" ? value.subject.value : "";
      next.direction = value.direction ?? "outgoing";
      next.peerKind = value.peer?.kind ?? "any";
      next.peerValue =
        value.peer && "value" in value.peer ? value.peer.value : "";
      next.protocol =
        value.protocol === undefined || value.protocol === null
          ? value.ports === undefined || value.ports === null
            ? "any"
            : "tcpudp"
          : String(value.protocol);
      next.ports =
        value.ports === undefined || value.ports === null
          ? ""
          : formatPorts(value.ports);
      next.icmpType =
        value.icmpType === undefined || value.icmpType === null
          ? ""
          : String(value.icmpType);
      next.icmpCode =
        value.icmpCode === undefined || value.icmpCode === null
          ? ""
          : String(value.icmpCode);
      next.priority = value.priority ?? "normal";
      next.enabled = value.enabled ?? true;
      next.lifetime =
        value.notBefore || value.expiresAt ? "custom" : "permanent";
      next.notBefore = value.notBefore ?? "";
      next.expiresAt = value.expiresAt ?? "";
      next.limitNetworks = Boolean(value.dnsDestinations);
      next.dnsDestinations = value.dnsDestinations?.join(", ") ?? "";
      next.reason = value.reason ?? "";
    }

    initial = JSON.stringify(next);
    loadedTimes = { notBefore: next.notBefore, expiresAt: next.expiresAt };

    if (rule && amend) {
      next.limitNetworks = true;
      next.dnsDestinations = amend.dnsDestinations.join(", ");
    }

    fields = next;
    expectedRevision = revision;
    loadedKey = key;
    error = "";
    fieldErrors = [];
  });

  type RuleInput = ReturnType<typeof ruleInputSchema.parse>;

  // The rule set chosen as the subject, if any.
  const subjectSet = $derived(
    ruleSets.find((ruleSet) => ruleSet.id === fields.subject),
  );

  // How far a rule in the chosen set reaches.
  const subjectSetUse = $derived.by(() => {
    if (!subjectSet) return null;

    if (subjectSet.members.kind === "global") return "Used by every instance.";
    const count = subjectSet.members.instanceIds.length;

    return count
      ? `Used by ${count} ${count === 1 ? "instance" : "instances"}.`
      : "Not attached to an instance.";
  });

  // The rule the fields describe, or why they don't describe one yet.
  function draft():
    { ok: true; value: RuleInput } | { ok: false; failure: Error } {
    try {
      let notBefore: string | null = null,
        expiresAt: string | null = null;

      if (fields.lifetime === "custom") {
        const start = fields.notBefore
            ? new Date(fields.notBefore).getTime()
            : null,
          end = fields.expiresAt ? new Date(fields.expiresAt).getTime() : null;

        // An expired rule keeps its end unless it is changed, so it can be edited and stay expired.
        if (
          end !== null &&
          end <= Date.now() &&
          fields.expiresAt !== loadedTimes.expiresAt
        )
          throw new Error("Select an end in the future");

        // An empty start or one that has passed takes effect at once, so only a later start bounds
        // the end.
        const later = start !== null && start > Date.now() ? start : null;

        if (later !== null && end !== null && end <= later)
          throw new Error("Select an end after the start");

        notBefore = later === null ? null : fields.notBefore;
        expiresAt = fields.expiresAt || null;
      } else if (fields.lifetime !== "permanent")
        expiresAt = new Date(
          Math.floor(Date.now() / 1000) * 1000 + Number(fields.lifetime) * 1000,
        ).toISOString();

      // A port without a protocol matches TCP and UDP only; other protocols have no ports.
      const ported = ["6", "17", "tcpudp"].includes(fields.protocol);

      const ports = ported ? parsePorts(fields.ports) : null;

      if (fields.protocol === "tcpudp" && ports === null)
        throw new Error("Enter ports for TCP/UDP");

      const limited =
        ["hostname", "domain"].includes(fields.peerKind) &&
        fields.limitNetworks;

      if (limited && !fields.dnsDestinations.trim())
        throw new Error("Enter at least one network");

      const dnsDestinations = limited
        ? fields.dnsDestinations.split(",").map((value) => value.trim())
        : null;

      const value = ruleInputSchema.parse({
        subject:
          fields.subject === "any"
            ? { kind: "global" }
            : fields.subject === "address"
              ? { kind: "address", value: fields.subjectAddress }
              : subjectSet
                ? { kind: "ruleSet", ruleSetId: fields.subject }
                : { kind: "instance", instanceId: fields.subject },
        action: fields.action,
        direction: fields.direction,
        peer:
          fields.peerKind === "any" || fields.peerKind === "gateway"
            ? { kind: fields.peerKind }
            : { kind: fields.peerKind, value: fields.peerValue },
        protocol: ["any", "tcpudp"].includes(fields.protocol)
          ? null
          : Number(fields.protocol),
        ports,
        icmpType:
          !["1", "58"].includes(fields.protocol) || fields.icmpType === ""
            ? null
            : Number(fields.icmpType),
        icmpCode:
          !["1", "58"].includes(fields.protocol) || fields.icmpCode === ""
            ? null
            : Number(fields.icmpCode),
        priority: fields.priority,
        enabled: fields.enabled,
        notBefore,
        expiresAt,
        dnsDestinations,
        reason: fields.reason,
      });

      return { ok: true, value };
    } catch (failure) {
      return {
        ok: false,
        failure:
          failure instanceof Error
            ? failure
            : new Error("Rule could not be saved"),
      };
    }
  }

  // Why a hostname or domain draft would not admit the address it is for, or null.
  const unadmitted = $derived.by(() => {
    if (
      !open ||
      !peerAddress ||
      !["hostname", "domain"].includes(fields.peerKind)
    )
      return null;
    const candidate = draft();

    return candidate.ok
      ? dnsAddressRefusal(candidate.value, peerAddress, localNetworks)
      : null;
  });

  // An address subject with no scope of its own gets one when saved. Answers its clients already
  // hold stay with their previous scope, so a hostname or domain rule waits for a new lookup.
  const newScope = $derived.by(() => {
    if (
      !open ||
      fields.subject !== "address" ||
      !["hostname", "domain"].includes(fields.peerKind)
    )
      return null;
    const candidate = draft();

    if (!candidate.ok || candidate.value.subject.kind !== "address")
      return null;
    const { value } = candidate.value.subject;

    return policyTree(instances, rules, ruleSets).entries.some(
      (entry) => entry.network === value,
    )
      ? null
      : value;
  });

  // What the peer value field takes for the chosen kind.
  const peerValue = $derived(
    fields.peerKind === "ip"
      ? { label: "IP address", example: "e.g. 192.0.2.10" }
      : fields.peerKind === "cidr"
        ? { label: "Network in CIDR notation", example: "e.g. 192.0.2.0/24" }
        : fields.peerKind === "domain"
          ? { label: "Domain", example: "e.g. example.com" }
          : { label: "Hostname", example: "e.g. host.example.com" },
  );

  function addDestination(address: string) {
    const network = `${address}/${address.includes(":") ? 128 : 32}`;

    fields.limitNetworks = true;
    fields.dnsDestinations = fields.dnsDestinations.trim()
      ? `${fields.dnsDestinations.trim()}, ${network}`
      : network;
  }

  const override = $derived.by(() => {
    const candidate = open ? draft() : null;

    if (!candidate?.ok) return null;

    const value: Rule = {
      ...candidate.value,
      id: rule?.id ?? "00000000-0000-4000-8000-000000000000",
      createdAt: rule?.createdAt ?? "",
      modifiedAt: rule?.modifiedAt ?? "",
    };

    const found = overriddenBy(value, rules, instances, ruleSets);

    if (!found) return null;

    const highPriority =
      found.rule.priority === "high" && value.priority !== "high";

    return {
      ...found,
      highPriority,
      // Rules for the same subject tie there, and Block wins a tie. Between subjects the
      // winner's subject can rank higher instead, so no reason is given.
      blockWins:
        !highPriority &&
        subjectScope(found.rule.subject) === subjectScope(value.subject),
      // Offered only when High priority would let this rule take effect.
      fixable:
        value.priority === "normal" &&
        !overriddenBy(
          { ...value, priority: "high" },
          rules,
          instances,
          ruleSets,
        ),
    };
  });

  async function save() {
    if (saving) return;
    saving = true;
    error = "";
    fieldErrors = [];

    try {
      const candidate = draft();

      if (!candidate.ok) throw candidate.failure;
      const value = candidate.value;

      await api(rule ? `rules/${rule.id}` : "rules", rule ? "PUT" : "POST", {
        expectedRevision,
        rule: value,
      });
      await onSaved();
      open = false;
    } catch (failure) {
      error =
        failure instanceof Error ? failure.message : "Rule could not be saved";

      if (failure instanceof ApiError) {
        fieldErrors = failure.failure.fields ?? [];

        if (failure.status === 409) {
          await onSaved();
          expectedRevision = revision;
        }
      }
    } finally {
      saving = false;
    }
  }
</script>

<Dialog.Root bind:open>
  <Dialog.Content
    class="max-h-[90dvh] overflow-y-auto sm:max-w-xl"
    showCloseButton={!dirty && !saving}
    onOpenAutoFocus={(event) => {
      event.preventDefault();
      document.querySelector<HTMLElement>("#rule-action")?.focus();
    }}
    onEscapeKeydown={(event) => {
      if (dirty || saving) event.preventDefault();
    }}
    onInteractOutside={(event) => {
      if (dirty || saving) event.preventDefault();
    }}
  >
    <Dialog.Header
      class="flex-row flex-wrap items-center gap-x-5 gap-y-2 pr-10"
    >
      <Dialog.Title class="flex-1"
        >{rule ? "Edit rule" : "Create rule"}</Dialog.Title
      >
      <div class="flex items-center gap-x-5">
        <div class="flex items-center gap-2">
          <Switch
            id="rule-priority"
            bind:checked={
              () => fields.priority === "high",
              (high) => (fields.priority = high ? "high" : "normal")
            }
          /><Label for="rule-priority">High priority</Label>
        </div>
        <div class="flex items-center gap-2">
          <Switch id="rule-enabled" bind:checked={fields.enabled} /><Label
            for="rule-enabled">Enabled</Label
          >
        </div>
      </div></Dialog.Header
    >
    <form
      onsubmit={(event) => {
        event.preventDefault();
        void save();
      }}
      class="space-y-4"
    >
      {#if override}<div role="status" class="rule-override">
          <TriangleAlert
            size={16}
            class="text-pending mt-0.5 shrink-0"
            aria-hidden="true"
          />
          <div class="min-w-0 space-y-2">
            <p>
              {override.until
                ? `No effect until the winning rule ends ${formatInstantInSentence(override.until, currentTime())}.`
                : "This rule has no effect."}
              <span class="font-medium"
                >{override.rule.action === "allow" ? "Allow" : "Block"}</span
              >
              <RuleLabel rule={override.rule} {instances} {ruleSets} /> matches the
              same traffic and wins{override.highPriority
                ? ", because it has High priority."
                : override.blockWins
                  ? ", because Block wins at equal priority."
                  : "."}
            </p>
            {#if override.fixable}<Button
                variant="outline"
                size="sm"
                type="button"
                onclick={() => (fields.priority = "high")}
                >Make High priority</Button
              >{/if}
          </div>
        </div>{/if}
      <div class="grid gap-4 sm:grid-cols-2">
        <div class="field-group">
          <Label for="rule-action">Action</Label><Choice
            fullWidth
            id="rule-action"
            label="Action"
            bind:value={fields.action}
            options={[
              {
                value: "allow",
                label: "Allow",
                icon: Check,
                iconClass: "text-allow",
              },
              {
                value: "block",
                label: "Block",
                icon: Ban,
                iconClass: "text-destructive",
              },
            ]}
          />
        </div>
        <div class="field-group">
          <Label for="rule-direction">Direction</Label><Choice
            fullWidth
            id="rule-direction"
            label="Direction"
            bind:value={fields.direction}
            options={[
              { value: "outgoing", label: "Outgoing", icon: ArrowRight },
              { value: "incoming", label: "Incoming", icon: ArrowLeft },
              { value: "both", label: "Both", icon: ArrowLeftRight },
            ]}
          />
        </div>
      </div>
      <div class="field-group">
        <Label for="rule-instance">Applies to</Label>
        <div
          class={["kind-value", fields.subject === "address" && "has-value"]}
        >
          <div class="min-w-0">
            <Choice
              fullWidth
              id="rule-instance"
              label="Applies to"
              bind:value={fields.subject}
              options={[
                { value: "any", label: "Any", builtIn: true },
                ...instances.map((instance) => ({
                  value: instance.id,
                  label: instance.name,
                })),
                { value: "address", label: "Address in an instance" },
                ...ruleSets.map((ruleSet) => ({
                  value: ruleSet.id,
                  label: ruleSet.name,
                  icon: Layers,
                })),
              ]}
            />
          </div>
          {#if fields.subject === "address"}<Input
              id="rule-subject-address"
              aria-label="Address or network"
              bind:value={fields.subjectAddress}
              placeholder="IP or CIDR inside an instance"
              required
            />{/if}
        </div>
        {#if subjectSetUse}<p class="muted text-xs">{subjectSetUse}</p>{/if}
      </div>
      <div class="field-group">
        <Label for="rule-peer">Peer</Label>
        <div
          class={[
            "kind-value",
            !["any", "gateway"].includes(fields.peerKind) && "has-value",
          ]}
        >
          <div class="min-w-0">
            <Choice
              fullWidth
              id="rule-peer"
              label="Peer kind"
              bind:value={fields.peerKind}
              options={[
                { value: "any", label: "Any", builtIn: true },
                { value: "gateway", label: "Gateway", builtIn: true },
                { value: "ip", label: "IP address" },
                { value: "cidr", label: "Network" },
                { value: "hostname", label: "Hostname" },
                { value: "domain", label: "Domain and subdomains" },
              ]}
            />
          </div>
          {#if !["any", "gateway"].includes(fields.peerKind)}<Input
              id="rule-peer-value"
              aria-label={peerValue.label}
              bind:value={fields.peerValue}
              placeholder={peerValue.example}
              required
            />{/if}
        </div>
        {#if fields.peerKind === "gateway"}<p class="muted text-xs">
            Traffic to or from the gateway itself, not traffic it forwards.
          </p>{:else if newScope}<p class="muted text-xs">
            Takes effect on the next lookup from {newScope}.
          </p>{/if}
        {#if fields.peerKind === "hostname" || fields.peerKind === "domain"}<div
            class="mt-1 flex items-center gap-2"
          >
            <Switch
              id="rule-limit-networks"
              bind:checked={fields.limitNetworks}
            /><Label for="rule-limit-networks">Limit to networks</Label>
          </div>{/if}
      </div>
      {#if fields.limitNetworks && (fields.peerKind === "hostname" || fields.peerKind === "domain")}<div
          class="field-group"
        >
          <Label for="dns-networks">Networks</Label><Input
            id="dns-networks"
            bind:value={fields.dnsDestinations}
            placeholder="e.g. 192.168.1.0/24, 10.0.0.0/8"
          />
        </div>{/if}
      {#if peerChoices.length > 1}<div class="field-group">
          <Label for="request-peer">Observed destination</Label>
          <Choice
            id="request-peer"
            label="Observed destination"
            fullWidth
            bind:value={
              () =>
                JSON.stringify({
                  kind: fields.peerKind,
                  value: fields.peerValue,
                }),
              choosePeer
            }
            options={peerChoices.map((peer) => ({
              value: JSON.stringify(peer),
              label:
                peer.kind === "hostname"
                  ? peer.value
                  : `IP address · ${peer.value}`,
            }))}
          />{#if !suggestionsComplete}<p class="field-help muted">
              More names share this address.
            </p>{/if}
        </div>{/if}
      <div class="field-group">
        <Label for="rule-protocol">Service</Label>
        <div
          class={[
            "kind-value",
            ["6", "17", "tcpudp"].includes(fields.protocol) && "has-value",
            ["1", "58"].includes(fields.protocol) && "has-values",
          ]}
        >
          <div class="min-w-0">
            <Choice
              fullWidth
              id="rule-protocol"
              label="Service"
              bind:value={fields.protocol}
              options={[
                { value: "any", label: "Any", builtIn: true },
                { value: "6", label: "TCP" },
                { value: "17", label: "UDP" },
                { value: "tcpudp", label: "TCP/UDP" },
                { value: "1", label: "ICMP" },
                { value: "58", label: "ICMPv6" },
              ]}
            />
          </div>
          {#if ["6", "17", "tcpudp"].includes(fields.protocol)}<Input
              id="rule-ports"
              aria-label="Ports"
              bind:value={fields.ports}
              placeholder="Any port, or e.g. 443, 8000-8080"
              aria-invalid={portsError ? "true" : undefined}
              aria-describedby={portsError ? "rule-ports-error" : undefined}
            />{:else if fields.protocol === "1" || fields.protocol === "58"}<Input
              id="icmp-type"
              aria-label="ICMP type"
              inputmode="numeric"
              pattern="[0-9]*"
              bind:value={fields.icmpType}
              placeholder="Any type"
            /><Input
              id="icmp-code"
              aria-label="ICMP code"
              inputmode="numeric"
              pattern="[0-9]*"
              bind:value={fields.icmpCode}
              placeholder="Any code"
            />{/if}
        </div>
        {#if portsError && ["6", "17", "tcpudp"].includes(fields.protocol)}<p
            id="rule-ports-error"
            class="field-error"
          >
            {portsError}
          </p>{/if}
      </div>
      <div class="field-group">
        <Label for="rule-lifetime">Lifetime</Label><Choice
          fullWidth
          id="rule-lifetime"
          label="Lifetime"
          bind:value={() => fields.lifetime, chooseLifetime}
          options={[
            { value: "permanent", label: "Permanent" },
            { value: "900", label: "15 minutes" },
            { value: "3600", label: "1 hour" },
            { value: "28800", label: "8 hours" },
            { value: "86400", label: "24 hours" },
            { value: "custom", label: "Custom" },
          ]}
        />
      </div>
      {#if fields.lifetime === "custom"}<div class="grid gap-4 sm:grid-cols-2">
          <div class="field-group">
            <Label for="rule-start">Starts</Label><DateTimeField
              id="rule-start"
              label="Starts"
              placeholder="Now"
              bind:value={fields.notBefore}
            />
          </div>
          <div class="field-group">
            <Label for="rule-expiry">Ends</Label><DateTimeField
              id="rule-expiry"
              label="Ends"
              placeholder="No end"
              bind:value={fields.expiresAt}
            />
          </div>
        </div>{/if}
      {#if unadmitted && peerAddress}<div role="status" class="rule-override">
          <TriangleAlert
            size={16}
            class="text-pending mt-0.5 shrink-0"
            aria-hidden="true"
          />
          <div class="min-w-0 space-y-2">
            <p>
              This request went to {peerAddress}, {unadmitted === "outside"
                ? "outside this rule's networks"
                : "which isn't a public address"}, so this rule won't match it.
            </p>
            <Button
              variant="outline"
              size="sm"
              type="button"
              onclick={() => addDestination(peerAddress)}
              >Add to networks</Button
            >
          </div>
        </div>{/if}
      <div class="field-group">
        <Label for="rule-reason">Reason</Label><Textarea
          id="rule-reason"
          bind:value={fields.reason}
          maxlength={1024}
        />
      </div>
      {#if error}<div role="alert" class="field-error">
          <p>{error}</p>
          {#each fieldErrors as issue, index (index)}<p>
              {issue.path}: {issue.message}
            </p>{/each}
        </div>{/if}
      <!-- The footer stays visible while the fields scroll; its fill matches the muted footer over the dialog. -->
      <Dialog.Footer
        class="sticky -bottom-4 z-10 bg-[color-mix(in_oklab,var(--muted)_50%,var(--popover))]"
        ><span class="muted mr-auto text-xs"
          >{dirty ? "Unsaved changes" : ""}</span
        ><Button
          variant="ghost"
          type="button"
          disabled={saving}
          onclick={() => {
            open = false;
          }}>Cancel</Button
        ><Button type="submit" disabled={saving}
          >{saving ? "Saving…" : "Save rule"}</Button
        ></Dialog.Footer
      >
    </form>
  </Dialog.Content>
</Dialog.Root>
