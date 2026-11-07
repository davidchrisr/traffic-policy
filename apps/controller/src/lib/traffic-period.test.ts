import { describe, expect, it } from "vitest";
import {
  periodCookie,
  readPeriodCookie,
  trafficWindow,
} from "./traffic-period.ts";

describe("traffic periods", () => {
  it("keeps a From now anchor fixed as the end moves and supports resetting it", () => {
    const start = Date.parse("2026-10-10T00:00:00Z");
    expect(trafficWindow("from-now", start, start)).toEqual({
      from: new Date(start).toISOString(),
      to: new Date(start).toISOString(),
    });
    expect(trafficWindow("from-now", start + 5000, start).from).toBe(
      new Date(start).toISOString(),
    );
    expect(trafficWindow("from-now", start + 10000, start + 7000).from).toBe(
      new Date(start + 7000).toISOString(),
    );
  });
  it("uses rolling durations and bounds Show all to retained history", () => {
    const now = Date.parse("2026-10-10T00:00:00Z");

    for (const seconds of [
      120, 300, 600, 3600, 18000, 86400, 259200, 604800, 2592000,
    ]) {
      const window = trafficWindow(String(seconds), now, now);
      expect(Date.parse(window.to) - Date.parse(window.from)).toBe(
        seconds * 1000,
      );
    }

    const all = trafficWindow("all", now, now);
    expect(Date.parse(all.to) - Date.parse(all.from)).toBe(180 * 86400000);
  });
  it("remembers a period, or a From now start, in a cookie value", () => {
    const now = Date.parse("2026-10-10T00:00:00Z");
    expect(periodCookie("604800", now)).toBe("604800");
    expect(readPeriodCookie("604800", now)).toEqual({
      period: "604800",
      since: now,
    });
    expect(readPeriodCookie(periodCookie("from-now", now - 5000), now)).toEqual(
      { period: "from-now", since: now - 5000 },
    );
  });
  it("reads an unknown or future cookie value as no period", () => {
    const now = Date.parse("2026-10-10T00:00:00Z");

    for (const value of [undefined, "", "301", "from-now", "from-now:x"])
      expect(readPeriodCookie(value, now)).toBeNull();

    expect(readPeriodCookie(`from-now:${now + 1}`, now)).toBeNull();
    // Monitor refuses windows beyond the retained 180 days, so an older start is not used.
    expect(
      readPeriodCookie(`from-now:${now - 180 * 86400000 - 1}`, now),
    ).toBeNull();
    expect(readPeriodCookie(`from-now:${now - 180 * 86400000}`, now)).toEqual({
      period: "from-now",
      since: now - 180 * 86400000,
    });
  });
});
