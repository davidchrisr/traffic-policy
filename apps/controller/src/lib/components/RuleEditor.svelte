<script lang="ts">
  import {
    ArrowLeft,
    ArrowLeftRight,
    ArrowRight,
    Ban,
    Check,
    TriangleAlert,
  } from "@lucide/svelte";
  import type { Instance, Rule } from "@traffic-policy/contracts";
  import type { RuleDraft } from "@traffic-policy/contracts/dashboard";
  import {
    formatPorts,
    parsePorts,
    ruleInputSchema,
  } from "@traffic-policy/contracts";
  import { api, ApiError } from "#lib/client.ts";
  import * as Dialog from "#lib/components/ui/dialog/index.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import { Textarea } from "#lib/components/ui/textarea/index.ts";
  import { Checkbox } from "#lib/components/ui/checkbox/index.ts";
  import { overriddenBy } from "@traffic-policy/core";
  import { currentTime } from "#lib/clock.ts";
  import { formatInstantInSentence } from "#lib/format-time.ts";
  import Choice from "./Choice.svelte";
  import RuleLabel from "./RuleLabel.svelte";

  let {
    open = $bindable(false),
    rule = null,
    scope = null,
    amend = null,
    instances,
    rules = [],
    revision,
    onSaved,
  }: {
    open: boolean;
    rule?: Rule | null;
    scope?: Partial<RuleDraft> | null;
    // Changes proposed on top of `rule`, shown as unsaved for review.
    amend?: { dnsDestinations: string[] } | null;
    instances: Instance[];
    // The current rules, used to warn when another rule overrides this one.
    rules?: Rule[];
    revision: string;
    onSaved: () => Promise<void>;
  } = $props();

  const fresh = () => ({
    action: "allow",
    // "any", an instance ID, or "address" for the address field below.
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
    dnsDestinations: "",
    reason: "",
  });

  let fields = $state(fresh());

  let loadedKey = $state<string | null>(null),
    initial = $state(""),
    expectedRevision = $state("");

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

  function localTime(raw: string | null | undefined): string {
    if (!raw) return "";
    const date = new Date(raw);

    return new Date(date.getTime() - date.getTimezoneOffset() * 60000)
      .toISOString()
      .slice(0, 19);
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
      next.lifetime = value.expiresAt ? "custom" : "permanent";
      next.notBefore = localTime(value.notBefore);
      next.expiresAt = localTime(value.expiresAt);
      next.dnsDestinations = value.dnsDestinations?.join(", ") ?? "";
      next.reason = value.reason ?? "";
    }

    initial = JSON.stringify(next);

    if (rule && amend) next.dnsDestinations = amend.dnsDestinations.join(", ");
    fields = next;
    expectedRevision = revision;
    loadedKey = key;
    error = "";
    fieldErrors = [];
  });

  type RuleInput = ReturnType<typeof ruleInputSchema.parse>;

  // The rule the fields describe, or why they don't describe one yet.
  function draft():
    { ok: true; value: RuleInput } | { ok: false; failure: Error } {
    try {
      let expiresAt: string | null = null;

      if (fields.lifetime === "custom") {
        if (!fields.expiresAt) throw new Error("Select an expiry time");
        expiresAt = new Date(fields.expiresAt).toISOString();
      } else if (fields.lifetime !== "permanent")
        expiresAt = new Date(
          Math.floor(Date.now() / 1000) * 1000 + Number(fields.lifetime) * 1000,
        ).toISOString();

      // A port without a protocol matches TCP and UDP only; other protocols have no ports.
      const ported = ["6", "17", "tcpudp"].includes(fields.protocol);

      const ports = ported ? parsePorts(fields.ports) : null;

      if (fields.protocol === "tcpudp" && ports === null)
        throw new Error("Enter ports for TCP/UDP");

      const value = ruleInputSchema.parse({
        subject:
          fields.subject === "any"
            ? { kind: "global" }
            : fields.subject === "address"
              ? { kind: "address", value: fields.subjectAddress }
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
        notBefore: fields.notBefore
          ? new Date(fields.notBefore).toISOString()
          : null,
        expiresAt,
        dnsDestinations:
          ["hostname", "domain"].includes(fields.peerKind) &&
          fields.dnsDestinations.trim()
            ? fields.dnsDestinations.split(",").map((value) => value.trim())
            : null,
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

  const override = $derived.by(() => {
    const candidate = open ? draft() : null;

    if (!candidate?.ok) return null;

    const value: Rule = {
      ...candidate.value,
      id: rule?.id ?? "00000000-0000-4000-8000-000000000000",
      createdAt: rule?.createdAt ?? "",
      modifiedAt: rule?.modifiedAt ?? "",
    };

    const found = overriddenBy(value, rules, instances);

    if (!found) return null;

    return {
      ...found,
      highPriority: found.rule.priority === "high" && value.priority !== "high",
      // Offered only when High priority would let this rule take effect.
      fixable:
        value.priority === "normal" &&
        !overriddenBy({ ...value, priority: "high" }, rules, instances),
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
    onEscapeKeydown={(event) => {
      if (dirty || saving) event.preventDefault();
    }}
    onInteractOutside={(event) => {
      if (dirty || saving) event.preventDefault();
    }}
  >
    <Dialog.Header
      ><Dialog.Title>{rule ? "Edit rule" : "Create rule"}</Dialog.Title
      ><Dialog.Description
        >Choose the exact scope and lifetime of this permission.</Dialog.Description
      ></Dialog.Header
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
              <RuleLabel rule={override.rule} {instances} /> matches the same traffic
              and wins, {override.highPriority
                ? "because it has High priority."
                : "because Block wins at equal priority."}
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
          <Label for="rule-priority">Priority</Label><Choice
            fullWidth
            id="rule-priority"
            label="Priority"
            bind:value={fields.priority}
            options={[
              { value: "normal", label: "Normal" },
              { value: "high", label: "High" },
            ]}
          />
        </div>
      </div>
      <div class="field-group">
        <Label for="rule-instance">Instance</Label><Choice
          fullWidth
          id="rule-instance"
          label="Instance"
          bind:value={fields.subject}
          options={[
            { value: "any", label: "Any instance" },
            ...instances.map((instance) => ({
              value: instance.id,
              label: instance.name,
            })),
            { value: "address", label: "Address in an instance" },
          ]}
        />
      </div>
      {#if fields.subject === "address"}<div class="field-group">
          <Label for="rule-subject-address">Address or network</Label><Input
            id="rule-subject-address"
            bind:value={fields.subjectAddress}
            required
          />
          <p class="muted text-xs">
            An IP or CIDR inside an instance. It keeps that instance's rules and
            adds this one. Registering the address as an instance later moves
            this rule to it.
          </p>
        </div>{/if}
      <div class="grid gap-4 sm:grid-cols-2">
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
        <div class="field-group">
          <Label for="rule-peer">Peer</Label><Choice
            fullWidth
            id="rule-peer"
            label="Peer kind"
            bind:value={fields.peerKind}
            options={[
              { value: "any", label: "Any peer" },
              { value: "gateway", label: "Gateway" },
              { value: "ip", label: "IP address" },
              { value: "cidr", label: "Network" },
              { value: "hostname", label: "Hostname" },
              { value: "domain", label: "Domain and subdomains" },
            ]}
          />
        </div>
      </div>
      {#if fields.peerKind === "gateway"}<p class="muted text-xs">
          The gateway at any of its addresses: connections it receives from or
          starts to the subject, never traffic it forwards.
        </p>{:else if fields.peerKind !== "any"}<div class="field-group">
          <Label for="rule-peer-value"
            >{fields.peerKind === "cidr"
              ? "Network in CIDR notation"
              : "Peer value"}</Label
          ><Input
            id="rule-peer-value"
            bind:value={fields.peerValue}
            required
          />{#if fields.peerKind === "hostname" || fields.peerKind === "domain"}<p
              class="muted text-xs"
            >
              DNS selectors require outgoing direction. Shared IP addresses
              cannot isolate hostnames.
            </p>{/if}
        </div>{/if}
      <div class="grid gap-3 sm:grid-cols-3">
        <div class="field-group">
          <Label for="rule-protocol">Protocol</Label><Choice
            fullWidth
            id="rule-protocol"
            label="Protocol"
            bind:value={fields.protocol}
            options={[
              { value: "any", label: "Any" },
              { value: "6", label: "TCP" },
              { value: "17", label: "UDP" },
              { value: "tcpudp", label: "TCP/UDP" },
              { value: "1", label: "ICMP" },
              { value: "58", label: "ICMPv6" },
            ]}
          />
        </div>
        {#if ["6", "17", "tcpudp"].includes(fields.protocol)}<div
            class="field-group sm:col-span-2"
          >
            <Label for="rule-ports">Ports</Label><Input
              id="rule-ports"
              bind:value={fields.ports}
              placeholder="Any"
              aria-invalid={portsError ? "true" : undefined}
              aria-describedby="rule-ports-help"
            />
            <p
              id="rule-ports-help"
              class={portsError ? "field-error" : "muted text-xs"}
            >
              {portsError ||
                "Ports and ranges, separated by commas, such as 443 or 443-1000, 8080."}
            </p>
          </div>{/if}
      </div>
      {#if fields.protocol === "1" || fields.protocol === "58"}<div
          class="grid gap-3 sm:grid-cols-2"
        >
          <div class="field-group">
            <Label for="icmp-type">ICMP type</Label><Input
              id="icmp-type"
              inputmode="numeric"
              pattern="[0-9]*"
              bind:value={fields.icmpType}
              placeholder="Any"
            />
          </div>
          <div class="field-group">
            <Label for="icmp-code">ICMP code</Label><Input
              id="icmp-code"
              inputmode="numeric"
              pattern="[0-9]*"
              bind:value={fields.icmpCode}
              placeholder="Any"
            />
          </div>
        </div>{/if}
      <div class="grid gap-4 sm:grid-cols-2">
        <div class="field-group">
          <Label for="rule-start">Activation</Label><Input
            id="rule-start"
            type="datetime-local"
            step="1"
            bind:value={fields.notBefore}
          />
          <p class="muted text-xs">Leave empty to activate immediately.</p>
        </div>
        <div class="field-group">
          <Label for="rule-lifetime">Lifetime</Label><Choice
            fullWidth
            id="rule-lifetime"
            label="Lifetime"
            bind:value={fields.lifetime}
            options={[
              { value: "permanent", label: "Permanent" },
              { value: "900", label: "15 minutes" },
              { value: "3600", label: "1 hour" },
              { value: "28800", label: "8 hours" },
              { value: "86400", label: "24 hours" },
              { value: "custom", label: "Until a deadline" },
            ]}
          />
        </div>
      </div>
      {#if fields.lifetime === "custom"}<div class="field-group">
          <Label for="rule-expiry">Expiry</Label><Input
            id="rule-expiry"
            type="datetime-local"
            step="1"
            bind:value={fields.expiresAt}
            required
          />
        </div>{/if}
      {#if fields.peerKind === "hostname" || fields.peerKind === "domain"}<div
          class="field-group"
        >
          <Label for="dns-networks">Permitted destination networks</Label><Input
            id="dns-networks"
            bind:value={fields.dnsDestinations}
            placeholder="Public addresses only"
          />
          <p class="muted text-xs">Empty means public addresses only.</p>
        </div>{/if}
      <div class="flex items-center gap-2">
        <Checkbox id="rule-enabled" bind:checked={fields.enabled} /><Label
          for="rule-enabled">Enabled</Label
        >
      </div>
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
