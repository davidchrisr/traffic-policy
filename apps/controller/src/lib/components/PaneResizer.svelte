<script lang="ts">
  import { onMount } from "svelte";

  // An invisible edge between two panes. It lightens on hover, and dragging or the arrow keys
  // resize the pane on its `side`. Home or a double-click returns to the CSS default width.
  let {
    label,
    pane,
    side,
    min,
    max,
    storageKey,
    width = $bindable(),
    class: className = "",
  }: {
    label: string;
    pane: HTMLElement | undefined;
    side: "start" | "end";
    min: number;
    max: (element: HTMLElement) => number;
    storageKey: string;
    width?: number;
    class?: string;
  } = $props();

  const step = 16;

  let start = $state<{ x: number; width: number } | null>(null),
    current = $state<number>(),
    limit = $state<number>();

  // The pane and its maximum change with the window and with the other pane, so the separator's
  // values follow both through a ResizeObserver.
  $effect(() => {
    if (!pane) return;
    const element = pane;

    const observer = new ResizeObserver(() => {
      current = Math.round(element.getBoundingClientRect().width);
      limit = Math.round(Math.max(min, max(element)));
    });

    observer.observe(element);
    observer.observe(element.parentElement!);

    return () => observer.disconnect();
  });

  onMount(() => {
    const stored = Number(localStorage.getItem(storageKey));

    if (stored > 0) width = stored;
  });

  function resize(element: HTMLElement, value: number) {
    width = Math.round(
      Math.min(Math.max(value, min), Math.max(min, max(element))),
    );
    localStorage.setItem(storageKey, String(width));
  }

  function reset() {
    width = undefined;
    localStorage.removeItem(storageKey);
  }

  function onpointerdown(
    event: PointerEvent & { currentTarget: HTMLDivElement },
  ) {
    if (event.button !== 0 || !pane) return;
    event.preventDefault();
    event.currentTarget.setPointerCapture(event.pointerId);
    start = { x: event.clientX, width: pane.getBoundingClientRect().width };
  }

  function onpointermove(event: PointerEvent) {
    if (!start || !pane) return;
    const delta = event.clientX - start.x;

    resize(pane, start.width + (side === "start" ? delta : -delta));
  }

  function onkeydown(event: KeyboardEvent) {
    if (event.key === "Home") {
      event.preventDefault();
      reset();

      return;
    }

    if ((event.key !== "ArrowLeft" && event.key !== "ArrowRight") || !pane)
      return;
    event.preventDefault();
    const delta = event.key === "ArrowRight" ? step : -step;

    resize(
      pane,
      pane.getBoundingClientRect().width + (side === "start" ? delta : -delta),
    );
  }
</script>

<!-- A focusable separator is the WAI-ARIA window splitter, which Svelte treats as non-interactive. -->
<!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
<div
  class="pane-resizer {className}"
  role="separator"
  aria-orientation="vertical"
  aria-label={label}
  aria-valuenow={current}
  aria-valuemin={min}
  aria-valuemax={limit}
  tabindex="0"
  data-dragging={start !== null}
  {onpointerdown}
  {onpointermove}
  onpointerup={() => (start = null)}
  onpointercancel={() => (start = null)}
  ondblclick={reset}
  {onkeydown}
></div>
