<script lang="ts">
  import type { LayoutProps } from "./$types";
  import { onMount } from "svelte";
  import { page } from "$app/state";
  import {
    dashboardStatusSchema,
    type DashboardStatus,
  } from "@traffic-policy/contracts/dashboard";
  import { api } from "#lib/client.ts";
  import { RefreshRunner } from "#lib/refresh-runner.ts";
  import { shareStatus } from "#lib/live-status.ts";
  import LogoMark from "#lib/components/LogoMark.svelte";
  import PaneResizer from "#lib/components/PaneResizer.svelte";
  import {
    Activity,
    ListFilter,
    Layers,
    Inbox,
    History,
    Settings,
  } from "@lucide/svelte";

  let { children }: LayoutProps = $props();

  let needsReview = $state(0),
    status = $state.raw<DashboardStatus | null>(null),
    nav = $state<HTMLElement>(),
    navWidth = $state<number>();

  shareStatus({
    get current() {
      return status;
    },
  });

  const runner = new RefreshRunner<DashboardStatus>({
    onValue: (next) => {
      status = next;
      needsReview = next.needsReview;
    },
    // An unknown count is not shown; pages and the status line report the failure.
    onError: () => {
      needsReview = 0;
    },
    onBusy: () => {},
  });

  const loadStatus = () =>
    runner.run(
      async (signal) =>
        dashboardStatusSchema.parse(
          await api("status", "GET", undefined, signal),
        ),
      false,
    );

  onMount(() => {
    void loadStatus();

    const poll = setInterval(() => void loadStatus(), 5000);

    return () => {
      clearInterval(poll);
      runner.dispose();
    };
  });

  const navigation = [
    { href: "/monitor", label: "Monitor", icon: Activity },
    { href: "/rules", label: "Rules", icon: ListFilter },
    { href: "/rule-sets", label: "Rule sets", icon: Layers },
    { href: "/requests", label: "Requests", icon: Inbox },
    { href: "/history", label: "History", icon: History },
    { href: "/settings", label: "Settings", icon: Settings },
  ];
</script>

<div
  class="app-shell"
  style:--nav-width={navWidth === undefined ? undefined : `${navWidth}px`}
>
  <aside class="app-nav" bind:this={nav}>
    <a href="/monitor" class="app-brand text-base font-bold text-foreground!"
      ><LogoMark />Traffic Policy</a
    >
    <nav aria-label="Main navigation">
      {#each navigation as item (item.href)}<a
          href={item.href}
          aria-current={page.url.pathname === item.href ? "page" : undefined}
          ><item.icon size={18} strokeWidth={1.75} /><span>{item.label}</span
          >{#if item.href === "/requests" && needsReview}<span
              class="nav-count numeric"
              aria-label={`${needsReview} waiting for review`}
              >{needsReview}</span
            >{/if}</a
        >{/each}
    </nav>
  </aside>
  <PaneResizer
    class="nav-resizer"
    label="Resize navigation"
    pane={nav}
    side="start"
    min={176}
    max={() => 280}
    storageKey="traffic-policy.nav-width"
    bind:width={navWidth}
  />
  <main class="app-main">{@render children()}</main>
</div>
