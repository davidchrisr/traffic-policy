<script lang="ts">
  import { onMount } from "svelte";
  import { displayTrafficBytes } from "#lib/client.ts";
  import { trafficPlot } from "#lib/traffic-chart.ts";

  let {
    timeline,
    from,
    to,
    height = 180,
    minTickIntervalMs = 60000,
    labelFontSize = 12,
  }: {
    timeline: { at: string; sentBytes: string; receivedBytes: string }[];
    from: string;
    to: string;
    height?: number;
    minTickIntervalMs?: number;
    labelFontSize?: number;
  } = $props();

  let element: HTMLDivElement;

  let chart = $state<import("echarts/core").EChartsType | null>(null);

  let phase = $state<"loading" | "ready" | "error">("loading");

  let observer: ResizeObserver | null = null;

  function failChart(cause: unknown) {
    console.error("Traffic chart could not be rendered", cause);
    observer?.disconnect();
    observer = null;
    chart?.dispose();
    chart = null;
    phase = "error";
  }

  const summary = $derived(
    timeline.reduce(
      (total, item) => ({
        sent: total.sent + BigInt(item.sentBytes),
        received: total.received + BigInt(item.receivedBytes),
      }),
      { sent: 0n, received: 0n },
    ),
  );

  function options() {
    if (!element) return {};
    const css = getComputedStyle(element);
    const plot = trafficPlot(timeline);
    const color = (token: string) => css.getPropertyValue(token).trim();
    const duration = Date.parse(to) - Date.parse(from);

    // Ranges over two days label whole days, so ticks land on local midnights.
    const multiDay = duration > 2 * 86400000;

    const timeLabel = new Intl.DateTimeFormat(
      undefined,
      multiDay
        ? { month: "short", day: "numeric" }
        : duration >= 86400000
          ? {
              month: "short",
              day: "numeric",
              hour: "2-digit",
              minute: "2-digit",
              hour12: false,
            }
          : { hour: "2-digit", minute: "2-digit", hour12: false },
    );

    return {
      animation: !matchMedia("(prefers-reduced-motion: reduce)").matches,
      color: [color("--chart-1"), color("--chart-2")],
      textStyle: {
        fontFamily: css.getPropertyValue("--font-sans"),
        fontSize: labelFontSize,
        color: color("--muted-foreground"),
      },
      grid: { left: 82, right: 12, top: 12, bottom: 32 },
      tooltip: {
        trigger: "axis",
        renderMode: "richText",
        backgroundColor: color("--popover"),
        borderColor: color("--border"),
        textStyle: { color: color("--foreground") },
        formatter: (
          parameters: import("echarts").TooltipComponentFormatterCallbackParams,
        ) => {
          const first = Array.isArray(parameters) ? parameters[0] : undefined;

          const item =
            first?.dataIndex === undefined
              ? undefined
              : timeline[first.dataIndex];

          return item
            ? `${new Date(item.at).toLocaleString()}\n↓ Received: ${displayTrafficBytes(item.receivedBytes)} (${item.receivedBytes} B)\n↑ Sent: ${displayTrafficBytes(item.sentBytes)} (${item.sentBytes} B)`
            : "";
        },
      },
      xAxis: {
        type: "time",
        min: Date.parse(from),
        max: Date.parse(to),
        minInterval: multiDay
          ? Math.max(minTickIntervalMs, 86400000)
          : minTickIntervalMs,
        splitNumber: 5,
        axisLabel: {
          color: color("--muted-foreground"),
          fontSize: labelFontSize,
          hideOverlap: true,
          formatter: (value: number) => timeLabel.format(new Date(value)),
        },
        axisLine: { onZero: false, lineStyle: { color: color("--border") } },
        axisTick: { show: false },
        splitLine: {
          show: true,
          lineStyle: { color: color("--border"), opacity: 0.4 },
        },
      },
      yAxis: {
        type: "value",
        min: -(plot.peak || 1000),
        max: plot.peak || 1000,
        splitNumber: 4,
        axisLabel: {
          color: color("--muted-foreground"),
          fontSize: labelFontSize,
          formatter: (value: number) =>
            `${value > 0 ? "↑ " : value < 0 ? "↓ " : ""}${displayTrafficBytes(BigInt(Math.floor(Math.abs(value))).toString())}`,
        },
        splitLine: { lineStyle: { color: color("--muted") } },
      },
      series: [
        {
          name: "Received bytes",
          type: "bar",
          stack: "bytes",
          barMaxWidth: 10,
          barMinWidth: 2,
          itemStyle: { borderRadius: [0, 0, 2, 2] },
          data: plot.received,
        },
        {
          name: "Sent bytes",
          type: "bar",
          stack: "bytes",
          barMaxWidth: 10,
          barMinWidth: 2,
          itemStyle: { borderRadius: [2, 2, 0, 0] },
          data: plot.sent,
          markLine: {
            silent: true,
            symbol: "none",
            label: { show: false },
            lineStyle: { color: color("--border"), type: "solid" },
            data: [{ yAxis: 0 }],
          },
        },
      ],
      aria: {
        enabled: true,
        label: {
          description: `Sent above the baseline, received below. Received ${displayTrafficBytes(summary.received.toString())}, sent ${displayTrafficBytes(summary.sent.toString())}. Missing measurements are not zeros.`,
        },
      },
    };
  }

  onMount(() => {
    let disposed = false;
    void (async () => {
      try {
        const [core, charts, components, renderers] = await Promise.all([
          import("echarts/core"),
          import("echarts/charts"),
          import("echarts/components"),
          import("echarts/renderers"),
        ]);

        if (disposed) return;
        core.use([
          charts.BarChart,
          components.GridComponent,
          components.TooltipComponent,
          components.AriaComponent,
          components.MarkLineComponent,
          renderers.CanvasRenderer,
        ]);
        chart = core.init(element, null, { renderer: "canvas" });
        chart.setOption(options());
        observer = new ResizeObserver(() => {
          try {
            chart?.resize();
          } catch (failure) {
            failChart(failure);
          }
        });
        observer.observe(element);
        phase = "ready";
      } catch (failure) {
        if (!disposed) failChart(failure);
      }
    })();

    return () => {
      disposed = true;
      observer?.disconnect();
      chart?.dispose();
      chart = null;
    };
  });

  $effect(() => {
    const current = chart;

    if (current) {
      try {
        current.setOption(options(), { notMerge: true });
      } catch (failure) {
        failChart(failure);
      }
    }
  });
</script>

<div
  class="relative"
  aria-busy={phase === "loading"}
  style:height={`${height}px`}
>
  <div
    bind:this={element}
    class="h-full"
    role="img"
    aria-hidden={phase !== "ready"}
    aria-label={`Traffic timeline: sent above the baseline, received below. Received ${displayTrafficBytes(summary.received.toString())}, sent ${displayTrafficBytes(summary.sent.toString())}`}
  ></div>
  {#if phase === "loading"}<p
      role="status"
      class="absolute inset-0 flex items-center justify-center muted text-xs"
    >
      Loading chart…
    </p>
  {:else if phase === "error"}<p
      role="alert"
      class="absolute inset-0 flex items-center justify-center px-4 text-center field-error"
    >
      Chart is unavailable. Reload the page to try again.
    </p>{/if}
</div>
{#if phase === "ready" && !timeline.length}<p class="muted text-center text-xs">
    No measured traffic in this period.
  </p>{/if}
