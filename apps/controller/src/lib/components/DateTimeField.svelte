<script lang="ts">
  import { Calendar as CalendarIcon, X } from "@lucide/svelte";
  import {
    fromDate,
    getLocalTimeZone,
    toCalendarDate,
    today,
    type DateValue,
  } from "@internationalized/date";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Calendar } from "#lib/components/ui/calendar/index.ts";
  import * as Popover from "#lib/components/ui/popover/index.ts";
  import {
    instantAt,
    minutesOf,
    nextOccurrence,
    nextQuarterHour,
    passOf,
  } from "#lib/date-picking.ts";
  import { formatDateTimeField, formatTimeOfDay } from "#lib/format-time.ts";

  // An instant picked as a local date from a calendar and a local time from a list in 15-minute
  // steps; a time between steps, such as a saved one, stays in the list. The value stays the
  // instant it was given until a day or time is picked.
  let {
    id,
    label,
    placeholder = "Select a time",
    value = $bindable(""),
  }: {
    id: string;
    label: string;
    placeholder?: string;
    value?: string;
  } = $props();

  let open = $state(false),
    trigger = $state<HTMLElement | null>(null);

  // The time with keyboard focus, which holds the list's Tab stop until the popover closes.
  let focusedAt = $state<number | null>(null);

  // The browser's language on the Gregorian calendar, which the day grid always uses.
  const locale = new Intl.Locale(
    Intl.DateTimeFormat().resolvedOptions().locale,
    {
      calendar: "gregory",
    },
  ).toString();

  const zone = getLocalTimeZone();

  const date = $derived(value ? new Date(value) : null);

  const local = $derived(date ? fromDate(date, zone) : null);

  const day = $derived(local ? toCalendarDate(local) : undefined);

  const minutes = $derived(local ? minutesOf(local) : null);

  const times = $derived.by(() => {
    const steps = Array.from({ length: 96 }, (_, index) => index * 15);

    if (minutes !== null && minutes % 15 !== 0)
      steps.splice(Math.ceil(minutes / 15), 0, minutes);

    return steps;
  });

  // An empty field takes the next quarter hour as its time when only a day is picked.
  const base = () => local ?? fromDate(new Date(nextQuarterHour()), zone);

  // The time the list offers first while open: the selected one, or the next quarter hour that an
  // empty field would take.
  const anchor = $derived(open ? minutesOf(base()) : null);

  // A field on the second pass through an hour that a clock change repeats stays on that pass.
  const pass = $derived(passOf(local, zone));

  function pickDay(next: DateValue) {
    value = instantAt(next, minutesOf(base()), zone, pass);
  }

  // An empty field takes the next time the picked time comes around.
  function pickTime(next: number) {
    value = day
      ? instantAt(day, next, zone, pass)
      : (nextOccurrence(next, zone) ?? value);
  }

  function timeLabel(at: number) {
    return formatTimeOfDay(
      new Date(2000, 0, 1, Math.floor(at / 60), at % 60),
      locale,
    );
  }

  // Arrow keys, Home, and End move between times, so the list is a single Tab stop.
  function moveFocus(event: KeyboardEvent & { currentTarget: HTMLElement }) {
    const buttons = [...event.currentTarget.querySelectorAll("button")];

    const index = buttons.findIndex(
      (button) => button === document.activeElement,
    );

    const target = new Map([
      ["ArrowDown", buttons[index + 1]],
      ["ArrowUp", buttons[index - 1]],
      ["Home", buttons[0]],
      ["End", buttons.at(-1)],
    ]).get(event.key);

    if (!target) return;

    event.preventDefault();
    target.focus();
  }

  function clear() {
    value = "";
    trigger?.focus();
  }

  // Opens with the offered time in the middle of the list.
  function centerSelected(list: HTMLElement) {
    const offered = list.querySelector<HTMLElement>("[tabindex='0']");

    if (offered)
      list.scrollTop =
        offered.offsetTop - (list.clientHeight - offered.offsetHeight) / 2;
  }
</script>

<div class="relative">
  <Popover.Root
    bind:open
    onOpenChange={(next) => {
      if (!next) focusedAt = null;
    }}
  >
    <Popover.Trigger
      bind:ref={trigger}
      {id}
      aria-label={`${label}: ${date ? formatDateTimeField(date, locale) : placeholder}`}
      class={[
        "border-input bg-card hover:bg-hover focus-visible:outline-ring flex h-(--control-height) w-full items-center gap-1.5 rounded-lg border py-1 pl-2.5 text-left text-sm whitespace-nowrap transition-colors duration-100 outline-none select-none focus-visible:outline-2 focus-visible:outline-offset-2",
        value ? "pr-9" : "pr-2",
      ]}
      ><CalendarIcon
        size={16}
        class="text-muted-foreground shrink-0"
        aria-hidden="true"
      /><span
        class={["min-w-0 flex-1 truncate", !date && "text-muted-foreground"]}
        >{date ? formatDateTimeField(date, locale) : placeholder}</span
      ></Popover.Trigger
    >
    <Popover.Content align="start" class="w-auto flex-row gap-0 p-0">
      <Calendar
        type="single"
        value={day}
        onValueChange={(next: DateValue | undefined) => next && pickDay(next)}
        minValue={today(zone)}
        preventDeselect
        weekdayFormat="narrow"
        calendarLabel={label}
        {locale}
      />
      <div class="relative w-28 border-l">
        <div
          class="absolute inset-0 overflow-y-auto p-1"
          role="toolbar"
          aria-orientation="vertical"
          aria-label={`${label} time`}
          tabindex={-1}
          onkeydown={moveFocus}
          {@attach centerSelected}
        >
          {#each times as at (at)}<button
              type="button"
              class={[
                "w-full rounded-md px-2 py-1 text-sm whitespace-nowrap",
                at === minutes
                  ? "bg-primary text-primary-foreground"
                  : "hover:bg-accent hover:text-accent-foreground",
              ]}
              aria-pressed={at === minutes}
              tabindex={at === (focusedAt ?? anchor) ? 0 : -1}
              onfocus={() => (focusedAt = at)}
              onclick={() => pickTime(at)}>{timeLabel(at)}</button
            >{/each}
        </div>
      </div>
    </Popover.Content>
  </Popover.Root>{#if value}<Button
      variant="ghost"
      size="icon-xs"
      class="text-muted-foreground absolute top-1 right-1"
      aria-label={`Clear ${label}`}
      onclick={clear}><X size={14} aria-hidden="true" /></Button
    >{/if}
</div>
