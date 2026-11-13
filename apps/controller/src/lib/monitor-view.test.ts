import { afterEach, describe, expect, it, vi } from "vitest";
import type {
  MonitorSnapshot,
  MonitorService,
} from "@traffic-policy/contracts/dashboard";
import { ApiError } from "./client.ts";
import { MonitorView } from "./monitor-view.ts";

const instanceId = "11111111-1111-4111-8111-111111111111";

const service: MonitorService = {
  key: "opaque-service-id",
  instanceId,
  direction: "outgoing",
  peerIp: "10.22.242.20",
  protocol: 6,
  port: null,
  sentBytes: "10",
  receivedBytes: "20",
};

function snapshot(services: MonitorService[] = [service]): MonitorSnapshot {
  return {
    from: new Date(0).toISOString(),
    to: new Date(300000).toISOString(),
    resolutionSeconds: 5,
    sentBytes: "10",
    receivedBytes: "20",
    services,
    servicesTruncated: false,
    timeline: [],
    instances: [
      { id: instanceId, name: "Client", addresses: ["10.22.241.10"] },
    ],
    status: {
      desiredRevision: "1",
      appliedRevision: null,
      pending: true,
      lastError: null,
      lastSeen: null,
      receipt: null,
      conditions: [],
      needsReview: 0,
      gateway: null,
    },
    coverage: "Fixture",
    names: [],
    namesTruncated: false,
    eventSummary: null,
    reviews: [],
    rules: [],
    ruleSets: [],
    localNetworks: [],
    unregistered: {
      clientPackets: "0",
      upstreamPackets: "0",
      drops: [],
      dropsTruncated: false,
      samplesLimited: false,
    },
  };
}

async function settle() {
  for (let i = 0; i < 12; i++) await Promise.resolve();
}

const views: MonitorView[] = [];

afterEach(() => {
  for (const view of views.splice(0)) view.dispose();
  vi.useRealTimers();
});

function create(
  load: (
    query: URLSearchParams,
    signal: AbortSignal,
  ) => Promise<MonitorSnapshot>,
  now = () => 300000,
  period?: { period: string; since: number },
) {
  const view = new MonitorView(snapshot(), load, now, period);
  views.push(view);

  return view;
}

describe("Monitor view ownership", () => {
  it("uses service fields with opaque keys and preserves scope across empty periods", async () => {
    const calls: URLSearchParams[] = [];

    const view = create(async (query) => {
      calls.push(query);

      return snapshot([]);
    });

    view.select({ kind: "service", ...service });
    await view.refresh();
    expect(calls[0]!.get("instanceId")).toBe(instanceId);
    expect(calls[0]!.get("port")).toBe("null");
    expect(calls[0]!.get("direction")).toBe("outgoing");
    expect(calls[1]!.has("instanceId")).toBe(false);
    expect(view.snapshot.scope).toMatchObject({
      kind: "service",
      key: "opaque-service-id",
      port: null,
    });
    expect(view.snapshot.roster).toEqual([]);
    expect(view.snapshot.hasMeasurements).toBe(true);
    view.setPeriod("120");
    await view.refresh();
    expect(calls[2]!.get("peerIp")).toBe(service.peerIp);
  });
  it("does not refetch or cancel an in-flight load when the same entry is selected", async () => {
    let resolve!: (value: MonitorSnapshot) => void;
    let signal!: AbortSignal;

    const load = vi.fn((_query: URLSearchParams, next: AbortSignal) => {
      signal = next;

      return new Promise<MonitorSnapshot>((yes) => {
        resolve = yes;
      });
    });

    const view = create(load);
    view.select({ kind: "instance", instanceId });
    const request = view.refresh();
    await settle();
    const count = load.mock.calls.length;
    view.select({ kind: "instance", instanceId });
    await settle();
    expect(load).toHaveBeenCalledTimes(count);
    expect(signal.aborted).toBe(false);
    resolve(snapshot()); // Both fixture calls need independent resolution below.
    view.dispose();
    await request;
  });
  it("coalesces From now changes and resets the fixed anchor", async () => {
    vi.useFakeTimers();
    let now = 300000;
    const calls: URLSearchParams[] = [];

    const view = create(
      async (query) => {
        calls.push(query);

        return snapshot();
      },
      () => now,
    );

    view.start();
    await settle();
    calls.length = 0;
    view.setSince(now);
    view.setPeriod("from-now");
    await settle();
    expect(calls).toHaveLength(1);
    expect(calls[0]!.get("from")).toBe(new Date(now).toISOString());
    now += 20000;
    view.setSince(now);
    await settle();
    expect(calls).toHaveLength(2);
    expect(calls[1]!.get("from")).toBe(new Date(now).toISOString());
  });
  it("opens with the period its initial snapshot was loaded for", async () => {
    const calls: URLSearchParams[] = [];

    const view = create(
      async (query) => {
        calls.push(query);

        return snapshot();
      },
      () => 900000,
      { period: "from-now", since: 100000 },
    );

    expect(view.snapshot).toMatchObject({ period: "from-now", since: 100000 });
    await view.refresh();
    expect(calls[0]!.get("from")).toBe(new Date(100000).toISOString());
  });
  it("keeps a scoped reply separate from the full roster and rejects an obsolete view", async () => {
    let finishOld!: (value: MonitorSnapshot) => void;

    const view = create((query) =>
      query.has("instanceId")
        ? new Promise((yes) => {
            finishOld = yes;
          })
        : Promise.resolve(snapshot()),
    );

    view.select({ kind: "instance", instanceId });
    const old = view.refresh();
    await settle();
    expect(view.snapshot.hasMeasurements).toBe(false);
    view.select({ kind: "all" });
    await view.refresh();
    finishOld({ ...snapshot([]), sentBytes: "999" });
    await old;
    expect(view.snapshot.model.sentBytes).toBe("10");
    expect(view.snapshot.roster).toEqual([service]);
    expect(view.snapshot.hasMeasurements).toBe(true);
  });
  it("loads the event summary on user changes and every 15 seconds of polls, keeping it between", async () => {
    vi.useFakeTimers();
    let now = 300000;
    const scoped: (string | null)[] = [];

    const summary: MonitorSnapshot["eventSummary"] = {
      events: [],
      eventsTruncated: false,
      eventsLimited: false,
      scannedFrom: null,
      blockedTotals: [],
    };

    const view = create(
      async (query) => {
        if (query.has("instanceId")) scoped.push(query.get("events"));
        else expect(query.has("events")).toBe(false);

        return {
          ...snapshot(),
          eventSummary: query.get("events") === "recent" ? summary : null,
        };
      },
      () => now,
    );

    view.start();
    await settle();
    view.select({ kind: "instance", instanceId });
    await settle();
    expect(scoped).toEqual(["recent"]);

    for (let tick = 0; tick < 2; tick++) {
      now += 5000;
      await vi.advanceTimersByTimeAsync(5000);
    }

    expect(scoped).toEqual(["recent", null, null]);
    expect(view.snapshot.model.eventSummary).toEqual(summary);
    now += 5000;
    await vi.advanceTimersByTimeAsync(5000);
    expect(scoped.at(-1)).toBe("recent");
    await view.refresh();
    expect(scoped.at(-1)).toBe("recent");
    view.select({ kind: "all" });
    await settle();
    expect(view.snapshot.model.eventSummary).toBeNull();
  });
  it("keeps a whole-period scan for its view until rescanned while polls continue", async () => {
    vi.useFakeTimers();
    let now = 300000;
    const scoped: (string | null)[] = [];
    let fail = false;

    const recent: MonitorSnapshot["eventSummary"] = {
      events: [],
      eventsTruncated: false,
      eventsLimited: false,
      scannedFrom: new Date(200000).toISOString(),
      blockedTotals: [],
    };

    const full = { ...recent!, scannedFrom: null };

    const view = create(
      async (query, signal) => {
        const events = query.get("events");

        if (query.has("instanceId")) scoped.push(events);

        if (events === "full" && query.get("instanceId") !== instanceId)
          await new Promise((_resolve, reject) =>
            signal.addEventListener("abort", () => reject(signal.reason)),
          );

        if (events === "full" && fail)
          throw new ApiError(409, {
            code: "event_scan_busy",
            message: "Another whole-period scan is running.",
          });

        return {
          ...snapshot(),
          eventSummary:
            events === "recent" ? recent : events === "full" ? full : null,
        };
      },
      () => now,
    );

    view.start();
    view.select({ kind: "instance", instanceId });
    await settle();
    expect(view.snapshot.model.eventSummary).toEqual(recent);
    await view.scanWholePeriod();
    expect(view.snapshot.model.eventSummary).toEqual(full);
    expect(view.snapshot.scannedAt).toBe(now);
    expect(view.snapshot.scanning).toBe(false);

    for (let tick = 0; tick < 4; tick++) {
      now += 5000;
      await vi.advanceTimersByTimeAsync(5000);
    }

    await view.refresh();
    expect(scoped.slice(1)).toEqual(["full", null, null, null, null, null]);
    expect(view.snapshot.model.eventSummary).toEqual(full);

    fail = true;
    await view.scanWholePeriod();
    now += 5000;
    await vi.advanceTimersByTimeAsync(5000);
    expect(view.snapshot.scanError).toBe(
      "Another whole-period scan is running.",
    );
    expect(view.snapshot.model.eventSummary).toEqual(full);

    // A view change drops the kept summary and abandons a running scan.
    view.select({
      kind: "instance",
      instanceId: "33333333-3333-4333-8333-333333333333",
    });
    await settle();
    expect(view.snapshot.scannedAt).toBeNull();
    expect(view.snapshot.scanError).toBe("");
    const scanning = view.scanWholePeriod();
    expect(view.snapshot.scanning).toBe(true);
    view.select({ kind: "instance", instanceId });
    await scanning;
    expect(view.snapshot.scanning).toBe(false);
    expect(view.snapshot.scanError).toBe("");
    expect(view.snapshot.scannedAt).toBeNull();
    await settle();
    expect(scoped.at(-1)).toBe("recent");
  });
  it("marks failed new periods unavailable without relabeling old data", async () => {
    const view = create(async () => {
      throw new Error("fixture failure");
    });

    view.setPeriod("86400");
    await view.refresh();
    expect(view.snapshot.hasRoster).toBe(false);
    expect(view.snapshot.hasMeasurements).toBe(false);
    expect(view.snapshot.error).toContain("could not be refreshed");
    expect(view.snapshot.model.sentBytes).toBe("10");
  });
});
