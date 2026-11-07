import { describe, expect, it } from "vitest";
import {
  groupBlocked,
  groupDestinations,
  groupNames,
  trafficBar,
  trafficTotals,
} from "./monitor-groups.ts";

describe("Monitor destination grouping", () => {
  it("keeps instances separate and preserves service identity across directions", () => {
    const service = {
      instanceId: "a",
      peerIp: "203.0.113.10",
      receivedBytes: "10",
      sentBytes: "2",
    };

    const groups = groupDestinations([
      { ...service, key: "tcp-out" },
      { ...service, key: "tcp-in" },
      { ...service, instanceId: "b", key: "other-instance" },
      { ...service, peerIp: "2001:db8::1", key: "ipv6" },
    ]);

    expect(groups).toHaveLength(3);
    expect(groups[0]!.services.map((value) => value.key)).toEqual([
      "tcp-out",
      "tcp-in",
    ]);
    expect(groups[0]!.receivedBytes).toBe("20");
    expect(groups[1]!.instanceId).toBe("b");
    expect(groups[2]!.peerIp).toBe("2001:db8::1");
  });
  it("sums counters above the safe integer range without rounding", () => {
    const service = { instanceId: "a", peerIp: "203.0.113.10", sentBytes: "1" };

    const [group] = groupDestinations([
      { ...service, key: "a", receivedBytes: "9007199254740993" },
      { ...service, key: "b", receivedBytes: "9007199254740993" },
    ]);

    expect(group!.receivedBytes).toBe("18014398509481986");
    expect(group!.sentBytes).toBe("2");
  });
  it("lists IPs with no name or several names as IP addresses with their names", () => {
    const peer = {
      instanceId: "a",
      receivedBytes: "1",
      sentBytes: "1",
    };

    const grouped = groupNames(
      [
        { ...peer, key: "one", peerIp: "203.0.113.10" },
        { ...peer, key: "two", peerIp: "203.0.113.20" },
        { ...peer, key: "none", peerIp: "203.0.113.30" },
      ],
      [
        {
          instanceId: "a",
          peerIp: "203.0.113.10",
          hostname: "api.example.com",
          domain: "example.com",
        },
        {
          instanceId: "a",
          peerIp: "203.0.113.20",
          hostname: "proof.example",
          domain: null,
        },
        {
          instanceId: "a",
          peerIp: "203.0.113.20",
          hostname: "api.example.co.uk",
          domain: "example.co.uk",
        },
      ],
    );

    expect(grouped.domains.map((domain) => domain.name)).toEqual([
      "example.com",
    ]);
    expect(grouped.ungrouped.map(({ key, names }) => ({ key, names }))).toEqual(
      [
        { key: "two", names: ["api.example.co.uk", "proof.example"] },
        { key: "none", names: [] },
      ],
    );
  });
});

describe("Monitor blocked rules", () => {
  const ruleA = "00000000-0000-4000-8000-00000000000a",
    ruleB = "00000000-0000-4000-8000-00000000000b",
    ruleC = "00000000-0000-4000-8000-00000000000c",
    deleted = "00000000-0000-4000-8000-0000000000dd";

  const sample = (
    ruleId: string,
    direction: "outgoing" | "incoming",
    port: number,
    count = "1",
  ) => ({
    type: "blocked" as const,
    direction,
    protocol: 6,
    port,
    ruleId,
    count,
    lastAt: "2026-10-31T10:00:00.000Z",
  });

  const summary = (
    patch: Partial<Parameters<typeof groupBlocked>[0]> = {},
  ): Parameters<typeof groupBlocked>[0] => ({
    events: [
      sample(ruleA, "outgoing", 443, "3"),
      { ...sample(ruleA, "outgoing", 80), type: "traffic", ruleId: null },
      sample(ruleA, "incoming", 22),
      sample(deleted, "outgoing", 25),
      sample(ruleA, "outgoing", 853),
    ],
    eventsTruncated: false,
    eventsLimited: false,
    scannedFrom: null,
    blockedTotals: [
      { ruleId: ruleA, direction: "outgoing", packets: "4", samples: "4" },
      { ruleId: ruleA, direction: "incoming", packets: "9", samples: "1" },
      { ruleId: ruleB, direction: "outgoing", packets: "5", samples: "0" },
      {
        ruleId: ruleC,
        direction: "incoming",
        packets: "9007199254740993",
        samples: "0",
      },
      { ruleId: ruleB, direction: "incoming", packets: "5", samples: "0" },
      { ruleId: ruleC, direction: "outgoing", packets: "0", samples: "0" },
    ],
    ...patch,
  });

  it("groups samples by rule and direction and lists rules with only counted packets after them", () => {
    const { rules, partial, instanceBlocked } = groupBlocked(summary(), true);

    expect(
      rules.map(({ key, rows, packets, incomplete }) => ({
        key,
        ports: rows.map((row) => row.port),
        packets,
        incomplete,
      })),
    ).toEqual([
      {
        key: `${ruleA}|outgoing`,
        ports: [443, 853],
        packets: 4n,
        incomplete: false,
      },
      { key: `${ruleA}|incoming`, ports: [22], packets: 9n, incomplete: true },
      // A deleted rule keeps its samples without counted packets.
      {
        key: `${deleted}|outgoing`,
        ports: [25],
        packets: null,
        incomplete: false,
      },
      // Most packets first, beyond the safe integer range; equal counts in key order. Zero counts
      // are left out.
      {
        key: `${ruleC}|incoming`,
        ports: [],
        packets: 9007199254740993n,
        incomplete: true,
      },
      { key: `${ruleB}|incoming`, ports: [], packets: 5n, incomplete: true },
      { key: `${ruleB}|outgoing`, ports: [], packets: 5n, incomplete: true },
    ]);
    expect(partial).toBe(false);
    expect(instanceBlocked).toBe(false);
  });
  it("lists only sampled rules outside the instance view", () => {
    const { rules, instanceBlocked } = groupBlocked(summary(), false);

    expect(rules.map((rule) => rule.key)).toEqual([
      `${ruleA}|outgoing`,
      `${ruleA}|incoming`,
      `${deleted}|outgoing`,
    ]);
    expect(instanceBlocked).toBe(false);
  });
  it.each([
    { scannedFrom: "2026-10-30T00:00:00.000Z" },
    { eventsLimited: true },
    { eventsTruncated: true },
  ])("reports a partial summary when %o", (patch) => {
    expect(groupBlocked(summary(patch), true)).toMatchObject({
      partial: true,
      instanceBlocked: false,
    });
    expect(groupBlocked(summary(patch), false)).toMatchObject({
      partial: true,
      instanceBlocked: true,
    });
    expect(
      groupBlocked(
        summary({
          ...patch,
          events: [],
          blockedTotals: [
            {
              ruleId: ruleC,
              direction: "outgoing",
              packets: "0",
              samples: "0",
            },
          ],
        }),
        false,
      ),
    ).toMatchObject({ rules: [], instanceBlocked: false });
  });
});

describe("Monitor traffic bars", () => {
  it("measures a row against its scale and splits it by direction", () => {
    expect(
      trafficBar({ receivedBytes: "750", sentBytes: "250" }, 4000n),
    ).toEqual({ fill: 25, received: 75, empty: false });
    expect(trafficBar({ receivedBytes: "3", sentBytes: "0" }, 3n)).toEqual({
      fill: 100,
      received: 100,
      empty: false,
    });
  });

  it("keeps a tiny share nonempty and marks a row without traffic", () => {
    expect(
      trafficBar({ receivedBytes: "1", sentBytes: "0" }, 1000000n),
    ).toMatchObject({ fill: 0, empty: false });
    expect(trafficBar({ receivedBytes: "0", sentBytes: "0" }, 0n)).toEqual({
      fill: 0,
      received: 0,
      empty: true,
    });
  });

  it("sums totals beyond the safe integer range", () => {
    expect(
      trafficTotals([
        { receivedBytes: "9007199254740993", sentBytes: "1" },
        { receivedBytes: "1", sentBytes: "2" },
      ]),
    ).toEqual({ receivedBytes: "9007199254740994", sentBytes: "3" });
  });
});
