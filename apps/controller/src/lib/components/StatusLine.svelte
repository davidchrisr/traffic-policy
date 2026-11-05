<script lang="ts">
  import { onMount } from "svelte";
  import {
    Cable,
    CircleAlert,
    CircleCheck,
    ListChecks,
    LoaderCircle,
    Radar,
    Router,
  } from "@lucide/svelte";
  import { Popover } from "bits-ui";
  import {
    servicesSnapshotSchema,
    type ServicesSnapshot,
  } from "@traffic-policy/contracts/services";
  import { api } from "#lib/client.ts";
  import { formatFullInstant, formatInstant } from "#lib/format-time.ts";
  import { RefreshRunner } from "#lib/refresh-runner.ts";
  import {
    statusItems,
    worstTone,
    type StatusItemId,
    type StatusTone,
  } from "#lib/service-status-view.ts";
  import { Button } from "#lib/components/ui/button/index.ts";

  let {
    pending,
    lastError,
    lastSeen,
    loadServices = async (signal: AbortSignal) =>
      servicesSnapshotSchema.parse(
        await api("services", "GET", undefined, signal),
      ),
  }: {
    pending: boolean;
    lastError: string | null;
    lastSeen: string | null;
    // The component catalog supplies fixtures; product pages read the controller.
    loadServices?: (signal: AbortSignal) => Promise<ServicesSnapshot>;
  } = $props();

  let now = $state(Date.now()),
    services = $state.raw<ServicesSnapshot | null>(null),
    servicesFailed = $state(false);

  const runner = new RefreshRunner<ServicesSnapshot>({
    onValue: (value) => {
      services = value;
      servicesFailed = false;
    },
    onError: () => {
      services = null;
      servicesFailed = true;
    },
    onBusy: () => {},
  });

  onMount(() => {
    void runner.run((signal) => loadServices(signal));

    const clock = setInterval(() => (now = Date.now()), 1000);

    const poll = setInterval(
      () => void runner.run((signal) => loadServices(signal), false),
      5000,
    );

    return () => {
      clearInterval(clock);
      clearInterval(poll);
      runner.dispose();
    };
  });

  const stale = $derived(
    lastSeen === null || now - Date.parse(lastSeen) > 15000,
  );

  const servicesStale = $derived(
    services !== null && now - Date.parse(services.checkedAt) > 15000,
  );

  const items = $derived(
    statusItems(
      { pending, lastError, stale },
      services,
      servicesStale,
      servicesFailed,
    ),
  );

  const tone = $derived(worstTone(items.map((item) => item.tone)));

  const attention = $derived(items.filter((item) => item.problems.length));

  const summary = $derived(
    attention.length
      ? attention.flatMap((item) => item.problems).join(". ")
      : "Rules applied. Gateway link connected. Gateway and Suricata running.",
  );

  const icons = {
    rules: ListChecks,
    link: Cable,
    gateway: Router,
    suricata: Radar,
  } satisfies Record<StatusItemId, typeof Router>;

  const toneClass: Record<StatusTone, string> = {
    allow: "text-allow",
    pending: "text-pending",
    destructive: "text-destructive",
    muted: "text-muted-foreground",
  };
</script>

<div class="status-line" aria-live="polite">
  <Popover.Root>
    <Popover.Trigger>
      {#snippet child({ props })}
        <Button
          {...props}
          variant="ghost"
          class="gateway-status"
          aria-label={`Status. ${summary}`}
        >
          {#if tone === "destructive"}<CircleAlert
              size={16}
              class="text-destructive"
            />
          {:else if tone === "pending" && attention.every((item) => item.id === "rules" && pending)}<LoaderCircle
              size={16}
              class="text-pending"
            />
          {:else if tone === "pending"}<CircleAlert
              size={16}
              class="text-pending"
            />
          {:else if tone === "allow"}<CircleCheck
              size={16}
              class="text-allow"
            />
          {:else}<CircleAlert size={16} class="muted" />{/if}
          <span>Status</span>
        </Button>
      {/snippet}
    </Popover.Trigger>
    <Popover.Portal>
      <Popover.Content
        side="bottom"
        align="end"
        sideOffset={8}
        class="status-card data-open:animate-in data-open:fade-in-0 data-open:zoom-in-95 data-closed:animate-out data-closed:fade-out-0 data-closed:zoom-out-95 data-[side=bottom]:slide-in-from-top-2 duration-100"
      >
        <ul class="status-card-list">
          {#each items as item (item.id)}
            {@const Icon = icons[item.id]}
            <li title={item.description}>
              <span class="status-card-item">
                <Icon
                  size={16}
                  class={toneClass[item.tone]}
                  aria-hidden="true"
                />{item.label}<span class="sr-only">. {item.description}</span>
              </span>
              {#if item.problems.length}<ul class="status-card-problems">
                  {#each item.problems as problem (problem)}<li
                      class={toneClass[item.tone]}
                    >
                      {problem}
                    </li>{/each}
                </ul>{/if}
            </li>
          {/each}
        </ul>
        {#if services}<p
            class="status-card-foot muted"
            title={formatFullInstant(services.checkedAt)}
          >
            Updated {formatInstant(
              services.checkedAt,
              // The clock ticks each second, so a fresh check can be newer than it.
              new Date(Math.max(now, Date.parse(services.checkedAt))),
            )}
          </p>{/if}
      </Popover.Content>
    </Popover.Portal>
  </Popover.Root>
</div>
