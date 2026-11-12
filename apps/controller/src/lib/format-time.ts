const formatters = new Map<string, Intl.DateTimeFormat>();

// Building a formatter costs far more than using one, and the shared clock re-formats every
// visible time on each tick.
function format(
  date: Date,
  locale: string | undefined,
  options: Intl.DateTimeFormatOptions,
): string {
  const key = `${locale ?? ""}|${JSON.stringify(options)}`;
  let formatter = formatters.get(key);

  if (!formatter) {
    formatter = new Intl.DateTimeFormat(locale, options);
    formatters.set(key, formatter);
  }

  return formatter.format(date);
}

const dayStart = (value: Date) =>
  new Date(value.getFullYear(), value.getMonth(), value.getDate()).getTime();

const HOUR = 3600000;

// Short local time: relative through six calendar days ("just now", "7 min ago", "3 hr ago",
// "Yesterday", "4 days ago", and the future forms), then month and day with the time this year, and
// month, day, and year otherwise.
export function formatInstant(
  value: string,
  now = new Date(),
  locale?: string,
): string {
  const date = new Date(value);
  const elapsed = now.getTime() - date.getTime();

  if (elapsed >= 0 && elapsed < 60000) return "just now";

  const minutes = Math.round(Math.abs(elapsed) / 60000);

  if (minutes < 60)
    return elapsed > 0
      ? `${minutes} min ago`
      : `in ${Math.max(minutes, 1)} min`;

  // Minutes round up to 60 from 59.5, so the hour count starts at 1.
  const hours = Math.max(1, Math.floor(Math.abs(elapsed) / HOUR));

  if (hours < 24) return elapsed > 0 ? `${hours} hr ago` : `in ${hours} hr`;

  const days = Math.round((dayStart(now) - dayStart(date)) / 86400000);

  if (days === 1) return "Yesterday";

  if (days === -1) return "Tomorrow";

  if (Math.abs(days) < 7)
    return days > 0 ? `${days} days ago` : `in ${-days} days`;

  if (date.getFullYear() === now.getFullYear())
    return `${format(date, locale, { month: "short", day: "numeric" })}, ${format(date, locale, { timeStyle: "short" })}`;

  return format(date, locale, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

// The same text for use inside a sentence ("ends tomorrow").
export function formatInstantInSentence(
  value: string,
  now = new Date(),
  locale?: string,
): string {
  const text = formatInstant(value, now, locale);

  return text === "Yesterday" || text === "Tomorrow"
    ? text.toLowerCase()
    : text;
}

export function formatFullInstant(value: string, locale?: string): string {
  return format(new Date(value), locale, {
    dateStyle: "medium",
    timeStyle: "medium",
  });
}

// A date field's day and time ("Thu, 12 Nov 2026, 09:00", or "9:00 AM" where the locale uses a
// 12-hour clock).
export function formatDateTimeField(date: Date, locale?: string): string {
  return `${format(date, locale, { weekday: "short", day: "numeric", month: "short", year: "numeric" })}, ${formatTimeOfDay(date, locale)}`;
}

export function formatTimeOfDay(date: Date, locale?: string): string {
  return format(date, locale, { timeStyle: "short" });
}
