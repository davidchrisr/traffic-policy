import {
  CalendarDateTime,
  fromDate,
  getLocalTimeZone,
  toCalendarDate,
  toCalendarDateTime,
  toZoned,
  type DateValue,
  type Disambiguation,
  type ZonedDateTime,
} from "@internationalized/date";

// Days and times picked in a date field's time zone. Times are minutes after local midnight;
// instants are ISO strings.

const step = 15 * 60000;

// The first quarter hour after now.
export function nextQuarterHour(now = Date.now()): string {
  return new Date(Math.floor(now / step) * step + step).toISOString();
}

// The same local time on the next calendar day.
export function nextDay(instant: string, zone = getLocalTimeZone()): string {
  return fromDate(new Date(instant), zone)
    .add({ days: 1 })
    .toDate()
    .toISOString();
}

export const minutesOf = (local: ZonedDateTime) =>
  local.hour * 60 + local.minute;

// A local day and time; the disambiguation picks the pass through an hour that a clock change
// repeats, and a time a clock change skips moves past the gap.
export function instantAt(
  on: DateValue,
  at: number,
  zone: string,
  disambiguation: Disambiguation = "compatible",
): string {
  return toZoned(
    new CalendarDateTime(
      on.year,
      on.month,
      on.day,
      Math.floor(at / 60),
      at % 60,
    ),
    zone,
    disambiguation,
  )
    .toDate()
    .toISOString();
}

// How a newly picked day or time resolves a repeated hour: a value on the second pass stays on it.
export function passOf(
  local: ZonedDateTime | null,
  zone: string,
): Disambiguation {
  return local &&
    toZoned(toCalendarDateTime(local), zone, "earlier").compare(local) !== 0
    ? "later"
    : "compatible";
}

// The next time a local time comes around after now, including the second pass through an hour
// that a clock change repeats. A clock change skips an hour at most once in a few days, so one of
// the next three days has the time.
export function nextOccurrence(
  at: number,
  zone: string,
  now = Date.now(),
): string | undefined {
  const start = toCalendarDate(fromDate(new Date(now), zone));

  return [0, 1, 2]
    .flatMap((days) => {
      const on = start.add({ days });

      return [instantAt(on, at, zone), instantAt(on, at, zone, "later")];
    })
    .find(
      (instant) =>
        new Date(instant).getTime() > now &&
        minutesOf(fromDate(new Date(instant), zone)) === at,
    );
}
