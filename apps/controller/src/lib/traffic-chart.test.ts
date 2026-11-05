import { describe, expect, it } from "vitest";
import { trafficPlot } from "./traffic-chart.ts";

describe("split-baseline traffic plot", () => {
  it("plots received below zero and sent above, retaining missing buckets and raw counters", () => {
    const samples = [
      { at: "2026-10-10T00:00:00Z", receivedBytes: "7050", sentBytes: "10170" },
      { at: "2026-10-10T00:15:00Z", receivedBytes: "0", sentBytes: "0" },
    ];

    const plot = trafficPlot(samples);
    expect(plot.received).toEqual([
      [Date.parse(samples[0]!.at), -7050],
      [Date.parse(samples[1]!.at), -0],
    ]);
    expect(plot.sent).toEqual([
      [Date.parse(samples[0]!.at), 10170],
      [Date.parse(samples[1]!.at), 0],
    ]);
    expect(plot.peak).toBe(10170);
    expect(samples[0]!.receivedBytes).toBe("7050");
    expect(samples[0]!.sentBytes).toBe("10170");
  });
  it("keeps an unmeasured timeline empty", () => {
    expect(trafficPlot([])).toEqual({ received: [], sent: [], peak: 0 });
  });
});
