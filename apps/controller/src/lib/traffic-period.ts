export const trafficPeriods = [
  { value: "all", label: "Show all" },
  { value: "2592000", label: "Last 30 days" },
  { value: "604800", label: "Last week" },
  { value: "259200", label: "Last 3 days" },
  { value: "86400", label: "Last 24 hours" },
  { value: "18000", label: "Last 5 hours" },
  { value: "3600", label: "Last hour" },
  { value: "600", label: "Last 10 minutes" },
  { value: "300", label: "Last 5 minutes" },
  { value: "120", label: "Last 2 minutes" },
] as const;

// The longest window Monitor reads, the 180 days of retained history; a longer one is refused.
const RETAINED_MS = 180 * 86400000;

export function trafficWindow(period: string, now: number, since: number) {
  const from =
    period === "all"
      ? now - RETAINED_MS
      : period === "from-now"
        ? since
        : now - Number(period) * 1000;

  return {
    from: new Date(from).toISOString(),
    to: new Date(now).toISOString(),
  };
}

export const DEFAULT_TRAFFIC_PERIOD = "300";

export const TRAFFIC_PERIOD_COOKIE = "tp_monitor_period";

// The Monitor period a browser remembers: a period value, or `from-now:<start ms>`.
export function periodCookie(period: string, since: number) {
  return period === "from-now" ? `from-now:${since}` : period;
}

// Reads a remembered period. An unknown value, or a From now start in the future or beyond the
// retained 180 days, is not a period and reads as null, so the caller uses the default.
export function readPeriodCookie(value: string | undefined, now: number) {
  if (trafficPeriods.some((item) => item.value === value))
    return { period: value!, since: now };

  const match = /^from-now:(\d{1,15})$/.exec(value ?? "");

  if (!match) return null;

  const since = Number(match[1]);

  if (since > now || since < now - RETAINED_MS) return null;

  return { period: "from-now", since };
}
