<script lang="ts">
  import { onMount } from "svelte";
  import {
    Check,
    Ban,
    MoreHorizontal,
    ArrowDown,
    ArrowUp,
    ChevronDown,
    ChevronRight,
  } from "@lucide/svelte";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import { Textarea } from "#lib/components/ui/textarea/index.ts";
  import { Checkbox } from "#lib/components/ui/checkbox/index.ts";
  import { Badge } from "#lib/components/ui/badge/index.ts";
  import { Skeleton } from "#lib/components/ui/skeleton/index.ts";
  import { Separator } from "#lib/components/ui/separator/index.ts";
  import * as Card from "#lib/components/ui/card/index.ts";
  import * as Alert from "#lib/components/ui/alert/index.ts";
  import * as Dialog from "#lib/components/ui/dialog/index.ts";
  import * as DropdownMenu from "#lib/components/ui/dropdown-menu/index.ts";
  import * as Tabs from "#lib/components/ui/tabs/index.ts";
  import * as Tooltip from "#lib/components/ui/tooltip/index.ts";
  import * as ScrollArea from "#lib/components/ui/scroll-area/index.ts";
  import { Switch } from "#lib/components/ui/switch/index.ts";
  import BuiltInValue from "#lib/components/BuiltInValue.svelte";
  import DateTimeField from "#lib/components/DateTimeField.svelte";
  import { nextDay, nextQuarterHour } from "#lib/date-picking.ts";
  import TrafficChart from "#lib/components/TrafficChart.svelte";
  import TrafficMeasure from "#lib/components/TrafficMeasure.svelte";
  import InspectorPanel from "#lib/components/InspectorPanel.svelte";
  import { displayTrafficBytes } from "#lib/client.ts";
  import StatusLine from "#lib/components/StatusLine.svelte";
  import SignOutButton from "#lib/components/SignOutButton.svelte";
  import TrafficPeriodPicker from "#lib/components/TrafficPeriodPicker.svelte";
  import RuleDecision from "#lib/components/RuleDecision.svelte";
  import RuleLabel from "#lib/components/RuleLabel.svelte";
  import { ruleSchema } from "@traffic-policy/contracts";
  import {
    servicesSnapshotSchema,
    type ServicesSnapshot,
  } from "@traffic-policy/contracts/services";

  // Labeled fixture: a temporary, high-priority outgoing rule for one TCP/UDP port.
  const exampleRule = ruleSchema.parse({
    id: "00000000-0000-4000-8000-000000000101",
    instanceId: null,
    direction: "outgoing",
    peer: { kind: "ip", value: "203.0.113.10" },
    protocol: null,
    ports: [{ start: 18081, end: 18081 }],
    icmpType: null,
    icmpCode: null,
    action: "allow",
    priority: "high",
    enabled: true,
    notBefore: null,
    expiresAt: "2030-01-01T00:00:00.000Z",
    dnsDestinations: null,
    createdAt: "2026-01-01T00:00:00.000Z",
    modifiedAt: "2026-01-01T00:00:00.000Z",
    reason: "",
  });

  const running = {
    loadState: "loaded",
    activeState: "active",
    subState: "running",
    result: "success",
    exitStatus: null,
    restarts: "0",
  };

  // Labeled fixture: every service runs, or all but log rotation, which failed.
  async function loadServices(
    maintenanceFailed = false,
  ): Promise<ServicesSnapshot> {
    const checkedAt = new Date().toISOString();

    return servicesSnapshotSchema.parse({
      checkedAt,
      controller: {
        available: true,
        snapshot: {
          scope: "controller",
          checkedAt,
          services: [
            { id: "controller", ...running },
            { id: "machine", ...running },
          ],
        },
      },
      gateway: {
        available: true,
        snapshot: {
          scope: "gateway",
          checkedAt,
          services: [
            { id: "gateway", ...running },
            { id: "enforcement", ...running },
            { id: "suricata", ...running },
            maintenanceFailed
              ? {
                  id: "suricata-rotate",
                  ...running,
                  activeState: "failed",
                  subState: "failed",
                  result: "exit-code",
                  exitStatus: 1,
                }
              : { id: "suricata-rotate", ...running },
          ],
        },
      },
    });
  }

  let trafficPeriod = $state("300"),
    trafficSince = $state(Date.now());

  let demoSignedOut = $state(false);

  let gatewaySeen = $state(new Date().toISOString());

  let checked = $state(true),
    highPriority = $state(false),
    enabled = $state(true),
    ends = $state(nextDay(nextQuarterHour()));

  let instanceExpanded = $state(true),
    peerExpanded = $state(true);

  let selection = $state("peer"),
    inspectorOpen = $state(false);

  const services = [
    {
      key: "tcp",
      label: "TCP port 443",
      received: "10485760",
      sent: "786432",
    },
    { key: "udp", label: "UDP port 53", received: "2097152", sent: "262144" },
  ];

  const selectedService = $derived(
    services.find((service) => service.key === selection),
  );

  let pairs = $state<
    {
      background: string;
      foreground: string;
      ratio: number;
      bg: string;
      fg: string;
    }[]
  >([]);

  const roles = [
    ["background", "foreground"],
    ["card", "card-foreground"],
    ["popover", "popover-foreground"],
    ["primary", "primary-foreground"],
    ["secondary", "secondary-foreground"],
    ["muted", "muted-foreground"],
    ["accent", "accent-foreground"],
    ["traffic-pill-background", "traffic-pill-foreground"],
  ];

  const colors = [
    "background",
    "card",
    "muted",
    "accent",
    "border",
    "ring",
    "destructive",
    "allow",
    "pending",
    "chart-1",
    "chart-2",
  ];

  const baseTime = Date.parse("2026-10-10T00:00:00Z");

  const sampleMinute = 60_000;

  const sampleDuration = 20 * sampleMinute;

  const timeline = [
    {
      at: new Date(baseTime).toISOString(),
      sentBytes: "262144",
      receivedBytes: "4194304",
    },
    {
      at: new Date(baseTime + 5 * sampleMinute).toISOString(),
      sentBytes: "524288",
      receivedBytes: "4194304",
    },
    {
      at: new Date(baseTime + 15 * sampleMinute).toISOString(),
      sentBytes: "262144",
      receivedBytes: "4194304",
    },
  ];

  function luminance(hex: string) {
    const digits = hex.replace("#", "");

    const full =
      digits.length === 3
        ? [...digits].map((digit) => digit + digit).join("")
        : digits;

    const rgb = full
      .match(/../g)!
      .map((component) => parseInt(component, 16) / 255)
      .map((component) =>
        component <= 0.04045
          ? component / 12.92
          : ((component + 0.055) / 1.055) ** 2.4,
      );

    return rgb[0]! * 0.2126 + rgb[1]! * 0.7152 + rgb[2]! * 0.0722;
  }

  onMount(() => {
    const timer = setInterval(
      () => (gatewaySeen = new Date().toISOString()),
      5000,
    );

    const css = getComputedStyle(document.body);
    pairs = roles.map(([background, foreground]) => {
      const bg = css.getPropertyValue(`--${background}`).trim(),
        fg = css.getPropertyValue(`--${foreground}`).trim();

      const a = luminance(bg),
        b = luminance(fg);

      return {
        background: background!,
        foreground: foreground!,
        bg,
        fg,
        ratio: (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05),
      };
    });

    return () => clearInterval(timer);
  });
</script>

<div class="catalog">
  <header class="page-header">
    <div>
      <h1 class="page-title">Traffic Policy design system</h1>
      <p class="muted text-xs">
        These labeled examples use the same shared components and tokens as
        product pages. DESIGN.md defines the contract.
      </p>
    </div>
  </header>
  <nav class="catalog-nav" aria-label="Design system sections">
    {#each [["foundations", "Foundations"], ["selection", "Text selection"], ["actions", "Actions"], ["inputs", "Inputs"], ["navigation", "Navigation"], ["overlays", "Overlays"], ["monitor", "Monitor layout"], ["constraints", "Decisions"]] as [id, label] (id)}<a
        href={`#${id}`}>{label}</a
      >{/each}
  </nav>
  <div class="page-content space-y-10 catalog-preview">
    <section id="foundations">
      <h2 class="section-title mb-4">Foundations</h2>
      <div class="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {#each pairs as pair (pair.background)}<div
            class="rounded-md border p-4"
            style:background={pair.bg}
            style:color={pair.fg}
          >
            <div class="text-2xl">Aa</div>
            <p class="mt-2 text-xs">{pair.background} / {pair.foreground}</p>
            <p class="numeric mt-1 text-xs">
              {pair.ratio.toFixed(2)}:1 · {pair.bg} / {pair.fg}
            </p>
          </div>{/each}
      </div>
      <div class="mt-5 flex flex-wrap gap-3">
        {#each colors as color (color)}<div class="text-xs">
            <div
              class="mb-1 h-8 w-16 rounded-sm border"
              style:background={`var(--${color})`}
            ></div>
            {color}
          </div>{/each}
      </div>
      <div class="mt-6 space-y-3">
        <p class="page-title">Page title · 24 / 32 · 700</p>
        <p class="section-title">Section title · 16 / 24 · 600</p>
        <p>
          Body · 14 / 20 · 400. Review a destination and change its permission.
        </p>
        <p class="muted text-xs">
          Supporting text · 12 / 18 · 400. Missing measurements remain
          unmeasured.
        </p>
        <p class="metric-value">22 / 28 · 700 · 12.34 MB</p>
      </div>
      <div class="catalog-panel mt-6 max-w-xl">
        <h3 class="section-title mb-3">Inter 4.1</h3>
        <p>Development workstation · app.example</p>
        <p class="muted mt-1 text-xs">Outgoing · TCP 443 · Policy applied</p>
        <p class="numeric mt-3">12.34 MB · 1,024 packets · 08:42:16</p>
        <p class="mt-3">Il1 · O0 · 192.0.2.20 · permissions</p>
      </div>
      <div class="mt-6 flex flex-wrap items-end gap-4">
        {#each [4, 8, 12, 16, 24, 32] as spacing (spacing)}<div>
            <div
              class="bg-muted"
              style:width={`${spacing * 3}px`}
              style:height={`${spacing}px`}
            ></div>
            <p class="muted mt-1 text-xs">{spacing}px</p>
          </div>{/each}
      </div>
      <div class="mt-6 flex gap-4">
        {#each [4, 5, 8] as radius (radius)}<div
            class="border bg-card p-4"
            style:border-radius={`${radius}px`}
          >
            {radius}px radius
          </div>{/each}
      </div>
      <div class="mt-5 flex items-center gap-5">
        <Check size={16} strokeWidth={1.75} /><Check
          size={18}
          strokeWidth={1.75}
        /><Ban size={24} strokeWidth={1.75} /><span class="muted text-xs"
          >Lucide · 16 / 18 / 24px</span
        >
      </div>
    </section>
    <section id="selection">
      <h2 class="section-title mb-3">Text selection</h2>
      <p class="muted mb-3">
        Drag across this text, or focus the input and select its value. Selected
        text uses a blue background and white foreground, independently of
        selected rows.
      </p>
      <div class="catalog-panel">
        <p class="selection-specimen">
          Development workstation connects to app.example on TCP port 443.
        </p>
        <div class="mt-3 max-w-lg">
          <Label for="selection-address">Selectable address</Label><Input
            id="selection-address"
            value="192.0.2.20:9444"
          />
        </div>
        <p class="mt-3 text-xs">
          <span class="selection-sample">Selected text preview</span><span
            class="muted ml-3">#2464b8 / #ffffff · 5.85:1</span
          >
        </p>
      </div>
    </section>
    <Separator />
    <section id="actions">
      <h2 class="section-title mb-4">Actions and states</h2>
      <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
          <thead
            ><tr
              ><th class="py-2">Variant</th
              >{#each ["Default", "Hover", "Focus", "Pressed", "Disabled"] as state (state)}<th
                  class="px-2">{state}</th
                >{/each}</tr
            ></thead
          ><tbody
            >{#each ["default", "secondary", "selected", "outline", "ghost", "destructive"] as variant (variant)}<tr
                ><th class="py-3 font-normal">{variant}</th
                >{#each ["default", "hover", "focus", "pressed", "disabled"] as state (state)}<td
                    class="px-2"
                    ><Button
                      variant={variant as
                        | "default"
                        | "secondary"
                        | "selected"
                        | "outline"
                        | "ghost"
                        | "destructive"}
                      data-preview={state}
                      data-variant={variant}
                      disabled={state === "disabled"}>Save rule</Button
                    ></td
                  >{/each}</tr
              >{/each}</tbody
          >
        </table>
      </div>
      <div class="control-row mt-4">
        <Button size="sm">Small</Button><Button>Standard</Button><Button
          size="lg">Large</Button
        ><Button variant="outline"><Check size={16} />Allow</Button><Button
          variant="outline"><Ban size={16} />Block</Button
        ><Button size="icon" variant="ghost" aria-label="More actions"
          ><MoreHorizontal size={16} /></Button
        ><Badge variant="outline">High</Badge><Badge variant="secondary"
          >Pending</Badge
        >
      </div>
    </section>
    <section id="inputs">
      <h2 class="section-title mb-4">Inputs</h2>
      <div class="mb-4">
        <Label for="catalog-traffic-period">Traffic period</Label
        ><TrafficPeriodPicker
          id="catalog-traffic-period"
          bind:value={trafficPeriod}
          bind:since={trafficSince}
        />
        <p class="muted mt-1 text-xs">
          Illustrative period menu. From now resets its start when selected.
        </p>
      </div>
      <div class="grid max-w-3xl gap-5 sm:grid-cols-2">
        <div class="field-group">
          <Label for="catalog-name">Instance name</Label><Input
            id="catalog-name"
            value="Development workstation"
            aria-describedby="catalog-name-help"
          />
          <p id="catalog-name-help" class="field-help muted text-xs">
            Use a stable, recognizable name.
          </p>
        </div>
        <div class="field-group">
          <Label for="catalog-error">Address</Label><Input
            id="catalog-error"
            value="10.22.999.1"
            aria-invalid="true"
            aria-describedby="catalog-error-text"
          />
          <p id="catalog-error-text" class="field-error">
            Enter a valid IPv4 or IPv6 address.
          </p>
        </div>
        <div class="field-group">
          <Label for="catalog-disabled">Disabled field</Label><Input
            id="catalog-disabled"
            value="Read-only state"
            disabled
          />
        </div>
        <div class="flex flex-wrap items-center gap-x-5 gap-y-2">
          <div class="flex items-center gap-2">
            <Switch id="catalog-priority" bind:checked={highPriority} /><Label
              for="catalog-priority">High priority</Label
            >
          </div>
          <div class="flex items-center gap-2">
            <Switch id="catalog-enabled" bind:checked={enabled} /><Label
              for="catalog-enabled">Enabled</Label
            >
          </div>
        </div>
        <div class="field-group">
          <Label for="catalog-ends">Ends</Label><DateTimeField
            id="catalog-ends"
            label="Ends"
            placeholder="No end"
            bind:value={ends}
          />
        </div>
        <p>
          <BuiltInValue kind="any" /> and <BuiltInValue kind="gateway" /> stand apart
          from names people enter.
        </p>
        <div class="field-group">
          <Label for="catalog-reason">Reason</Label><Textarea
            id="catalog-reason"
            value="Allow the application's documented service endpoint."
          />
        </div>
        <div class="flex items-center gap-2">
          <Checkbox id="catalog-remember" bind:checked /><Label
            for="catalog-remember">Remember me</Label
          >
        </div>
      </div>
    </section>
    <section id="navigation">
      <h2 class="section-title mb-4">Navigation and feedback</h2>
      <Tabs.Root value="rules"
        ><Tabs.List
          ><Tabs.Trigger value="rules">Rules</Tabs.Trigger><Tabs.Trigger
            value="history">History</Tabs.Trigger
          ></Tabs.List
        ><Tabs.Content value="rules"
          ><p class="muted py-3">
            Current configuration appears in Rules.
          </p></Tabs.Content
        ><Tabs.Content value="history"
          ><p class="muted py-3">
            Individual change events appear in History.
          </p></Tabs.Content
        ></Tabs.Root
      >
      <div class="mt-4 grid gap-4 lg:grid-cols-2">
        <Alert.Root
          ><Check size={16} /><Alert.Title>Rules are up to date</Alert.Title
          ><Alert.Description
            >Gateway is online. All rule changes are applied.</Alert.Description
          ></Alert.Root
        ><Alert.Root variant="destructive"
          ><Ban size={16} /><Alert.Title
            >Change could not be applied</Alert.Title
          ><Alert.Description
            >The draft is preserved. The last confirmed rules remain visible.</Alert.Description
          ></Alert.Root
        >
      </div>
      <div class="mt-4">
        <p class="muted mb-2 text-xs">
          Illustrative status: rules applied, applying, out of date, and not
          confirmed with every service running, then log rotation failed. Hover
          or focus for details. Product headers place this indicator beside page
          actions.
        </p>
        <div class="control-row">
          <StatusLine
            pending={false}
            lastError={null}
            lastSeen={gatewaySeen}
            loadServices={() => loadServices()}
          />
          <StatusLine
            pending={true}
            lastError={null}
            lastSeen={gatewaySeen}
            loadServices={() => loadServices()}
          />
          <StatusLine
            pending={false}
            lastError={null}
            lastSeen={null}
            loadServices={() => loadServices()}
          />
          <StatusLine
            pending={false}
            lastError="The requested policy could not be applied."
            lastSeen={gatewaySeen}
            loadServices={() => loadServices()}
          />
          <StatusLine
            pending={false}
            lastError={null}
            lastSeen={gatewaySeen}
            loadServices={() => loadServices(true)}
          />
        </div>
      </div>
      <div class="mt-4 space-y-2">
        <Skeleton class="h-4 w-56" /><Skeleton class="h-4 w-80 max-w-full" />
      </div>
    </section>
    <section id="overlays">
      <h2 class="section-title mb-4">Overlays</h2>
      <div class="mb-4">
        <p class="muted mb-2 text-xs">
          Illustrative sign-out button. Confirmation only updates this example.
        </p>
        <div class="w-40">
          <SignOutButton
            onSignOut={async () => {
              demoSignedOut = true;
            }}
          />
        </div>
        {#if demoSignedOut}<p class="muted mt-2 text-xs">
            Confirmation completed.
          </p>{/if}
      </div>
      <div class="control-row">
        <Dialog.Root
          ><Dialog.Trigger>Open dialog</Dialog.Trigger><Dialog.Content
            ><Dialog.Header
              ><Dialog.Title>Review permission</Dialog.Title><Dialog.Description
                >Confirm the selected instance and destination.</Dialog.Description
              ></Dialog.Header
            >
            <p>Development workstation → app.example · TCP port 443</p>
            <Dialog.Footer
              ><Dialog.Close>Cancel</Dialog.Close><Button>Save rule</Button
              ></Dialog.Footer
            ></Dialog.Content
          ></Dialog.Root
        ><DropdownMenu.Root
          ><DropdownMenu.Trigger>Open menu</DropdownMenu.Trigger
          ><DropdownMenu.Content
            ><DropdownMenu.Item>Edit rule</DropdownMenu.Item><DropdownMenu.Item
              >Renew for 1 hour</DropdownMenu.Item
            ><DropdownMenu.Separator /><DropdownMenu.Item
              >Delete rule</DropdownMenu.Item
            ></DropdownMenu.Content
          ></DropdownMenu.Root
        ><Tooltip.Provider
          ><Tooltip.Root
            ><Tooltip.Trigger>Hover or focus for help</Tooltip.Trigger
            ><Tooltip.Content
              >Rule priority controls precedence.</Tooltip.Content
            ></Tooltip.Root
          ></Tooltip.Provider
        >
      </div>
    </section>
    <section id="data">
      <h2 class="section-title mb-4">Data and composition</h2>
      <Card.Root class="max-w-3xl"
        ><Card.Header
          ><Card.Title>Illustrative transfer measurements</Card.Title
          ><Card.Description
            >The gap is intentionally unmeasured.</Card.Description
          ></Card.Header
        ><Card.Content
          ><TrafficChart
            {timeline}
            from={new Date(baseTime).toISOString()}
            to={new Date(baseTime + sampleDuration).toISOString()}
            minTickIntervalMs={5 * sampleMinute}
            labelFontSize={12}
          />
          <div class="control-row text-xs">
            <ArrowDown size={14} class="text-chart-1" />Received <ArrowUp
              size={14}
              class="text-chart-2"
            />Sent
          </div></Card.Content
        ></Card.Root
      ><ScrollArea.Root class="mt-5 h-40 max-w-3xl rounded-md border"
        >{#each ["Development workstation", "A very long instance name that must wrap or truncate without breaking the row", "Controlled target"] as name (name)}<div
            class="list-row"
          >
            <Check size={18} class="text-allow" /><span
              class="min-w-0 flex-1 break-words"
              >{name} · outgoing · app.example · TCP 443</span
            ><Badge variant="outline">Normal</Badge>
          </div>{/each}
        <div class="empty-state">
          No further illustrative rows.
        </div></ScrollArea.Root
      >
    </section>
    <section id="monitor">
      <h2 class="section-title mb-3">Monitor layout</h2>
      <p class="muted mb-4">
        Illustrative data. Expand the instance and destination, then select a
        service to inspect it. The list comes before the timeline.
      </p>
      <div class="mb-4 grid gap-2" aria-label="Rule decision states">
        {#each [["allow", "Allowed by a rule"], ["block", "Blocked by a rule"], ["waiting", "Waiting for review"], ["varies", "Varies or depends on DNS"]] as const as [state, label] (state)}<div
            class="flex items-center gap-3"
          >
            <RuleDecision
              {state}
              scope="illustrative destination"
              description={label}
              onallow={() => {}}
              onblock={() => {}}
            /><span class="text-sm">{label}</span>
          </div>{/each}
        <div class="flex items-center gap-3">
          <RuleDecision
            state="block"
            scope="the catch-all"
            description="Blocks this traffic"
            onallow={() => {}}
            onblock={() => {}}
            locked="Applies when no rule matches. Set in Settings."
          /><span class="text-sm">Catch-all, changed in Settings</span>
        </div>
        <RuleLabel rule={exampleRule} dns="Illustrative DNS dependence" />
      </div>
      <div class="catalog-monitor">
        <div class="min-w-0">
          <div class="p-4 border-b">
            <Input
              aria-label="Monitor search example"
              placeholder="Search instances or destinations"
            />
          </div>
          <div class="list-row monitor-row">
            <Button
              variant="ghost"
              size="icon"
              aria-label="Expand development workstation"
              aria-expanded={instanceExpanded}
              onclick={() => (instanceExpanded = !instanceExpanded)}
              >{#if instanceExpanded}<ChevronDown
                  size={16}
                />{:else}<ChevronRight size={16} />{/if}</Button
            >
            <span class="monitor-name min-w-0 flex-1 font-semibold"
              >Development workstation</span
            >
            <div class="monitor-actions">
              <RuleDecision
                state="varies"
                scope="illustrative instance"
                description="Services have different current decisions"
                onallow={() => {}}
                onblock={() => {}}
              />
            </div>
          </div>
          {#if instanceExpanded}
            <div
              class="list-row monitor-row monitor-destination"
              data-selected={selection === "peer"}
            >
              <Button
                variant="ghost"
                size="icon"
                aria-label="Expand app.example"
                aria-expanded={peerExpanded}
                onclick={() => (peerExpanded = !peerExpanded)}
                >{#if peerExpanded}<ChevronDown size={16} />{:else}<ChevronRight
                    size={16}
                  />{/if}</Button
              >
              <button
                class="monitor-name min-w-0 flex-1 text-left"
                onclick={() => {
                  selection = "peer";
                  inspectorOpen = true;
                }}
                ><span class="block">app.example</span><span
                  class="muted text-xs">203.0.113.10</span
                ></button
              >
              <span class="monitor-measure"
                ><TrafficMeasure
                  received="12582912"
                  sent="1048576"
                  scale={20971520n}
                /></span
              >
              <div class="monitor-actions">
                <RuleDecision
                  state="allow"
                  scope="illustrative destination"
                  description="Allowed by an illustrative rule"
                  onallow={() => {}}
                  onblock={() => {}}
                />
              </div>
            </div>
            {#if peerExpanded}{#each services as service (service.key)}<button
                  class="list-row monitor-row catalog-row monitor-service"
                  aria-pressed={selection === service.key}
                  onclick={() => {
                    selection = service.key;
                    inspectorOpen = true;
                  }}
                >
                  <span class="monitor-name min-w-0 flex-1"
                    >{service.label}</span
                  ><span class="monitor-measure"
                    ><TrafficMeasure
                      received={service.received}
                      sent={service.sent}
                      scale={20971520n}
                    /></span
                  >
                </button>{/each}{/if}
          {/if}
          <div class="border-t p-4">
            <div class="flex gap-8 mb-3">
              <div>
                <p class="muted text-xs">Received</p>
                <p class="metric-value text-chart-1">12.58 MB</p>
              </div>
              <div>
                <p class="muted text-xs">Sent</p>
                <p class="metric-value text-chart-2">1.04 MB</p>
              </div>
            </div>
            <TrafficChart
              {timeline}
              from={new Date(baseTime).toISOString()}
              to={new Date(baseTime + sampleDuration).toISOString()}
              height={150}
              minTickIntervalMs={5 * sampleMinute}
              labelFontSize={12}
            />
            <p class="muted text-xs">
              Illustrative 20-minute timeline · Sent above, Received below ·
              missing buckets remain gaps.
            </p>
          </div>
        </div>
        <InspectorPanel
          label="Preview traffic inspector"
          bind:open={inspectorOpen}
        >
          <h3 class="section-title mb-4">
            {selectedService?.label ?? "app.example"}
          </h3>
          <p class="muted text-xs">Development workstation · outgoing</p>
          <p class="mt-3 font-mono text-sm break-all">203.0.113.10</p>
          <dl class="mt-4 space-y-3">
            <div>
              <dt class="muted text-xs">Received</dt>
              <dd class="numeric">
                {displayTrafficBytes(selectedService?.received ?? "12582912")}
              </dd>
            </div>
            <div>
              <dt class="muted text-xs">Sent</dt>
              <dd class="numeric">
                {displayTrafficBytes(selectedService?.sent ?? "1048576")}
              </dd>
            </div>
          </dl>
          <p class="muted mt-4 text-xs">
            Preview controls illustrate placement.
          </p>
          <div class="control-row mt-2">
            <Button variant="outline"
              ><Check size={16} class="text-allow" />Allow</Button
            ><Button variant="outline"
              ><Ban size={16} class="text-destructive" />Block</Button
            >
          </div>
        </InspectorPanel>
      </div>
    </section>
    <section id="constraints">
      <section
        class="settings-section mb-6"
        aria-labelledby="catalog-section-title"
      >
        <header class="settings-section-header">
          <h2 id="catalog-section-title" class="section-title">
            Settings section
          </h2>
          <p>Section headers separate a related group of fields.</p>
        </header>
        <div class="setting-row">
          <div>
            <Label for="catalog-section-limit">Active permission limit</Label>
            <p class="field-help muted">
              Labels use a 20px line height with a 4px gap before supporting
              text.
            </p>
          </div>
          <Input id="catalog-section-limit" value="4096" />
        </div>
      </section>
      <h2 class="section-title mb-3">Design constraints</h2>
      <p class="muted">
        Keep field and button heights aligned, use semantic transfer colors,
        preserve drafts, and distinguish desired policy from gateway
        confirmation. Static state previews supplement live keyboard testing.
      </p>
      <ul class="mt-4 space-y-2 text-sm">
        <li>Primary hover uses #1b70ef, keeping white labels at 4.55:1.</li>
        <li>
          Essential field boundaries use #767676; decorative separators use
          #292929.
        </li>
        <li>
          Desktop reference: 188px navigation, inspector at least 360px and 30%
          of the content width. The inspector stacks in narrow previews.
        </li>
      </ul>
    </section>
  </div>
</div>

<style>
  :global(.catalog-preview [data-preview="focus"]) {
    outline: 2px solid var(--ring);
    outline-offset: 2px;
  }
  .selection-sample {
    background: var(--text-selection-background);
    color: var(--text-selection-foreground);
    padding: 2px 4px;
  }
</style>
