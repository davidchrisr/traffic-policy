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

export function trafficWindow(period: string, now: number, since: number) {
  const from =
    period === "all"
      ? now - 180 * 86400000
      : period === "from-now"
        ? since
        : now - Number(period) * 1000;

  return {
    from: new Date(from).toISOString(),
    to: new Date(now).toISOString(),
  };
}
