import { describe, expect, it } from "vitest";
import { trafficWindow } from "./traffic-period.ts";

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
});
