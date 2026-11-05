import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { eventSchema } from "@traffic-policy/contracts";
import {
  blockedObservation,
  UnregisteredNameSampler,
  dnsObservation,
  dnsDeniedObservation,
  DnsDenialSampler,
  LostDenialReporter,
  queryTypeName,
  TrafficAccounting,
} from "./telemetry.ts";
import type { ConnectionSnapshot } from "./connections.ts";

const client = "11111111-1111-4111-8111-111111111111",
  target = "22222222-2222-4222-8222-222222222222";

const policy = {
  instances: [
    {
      id: client,
      name: "Client",
      addresses: ["10.22.241.10"],
      ownershipId: client,
    },
    {
      id: target,
      name: "Target",
      addresses: ["10.22.242.20"],
      ownershipId: target,
    },
  ],
  gatewayAddresses: ["10.22.241.1"],
};

const connection: ConnectionSnapshot = {
  id: "flow-1",
  sentBytes: "9007199254740993",
  receivedBytes: "40",
  flow: {
    initiatorIp: "10.22.241.10",
    responderIp: "10.22.242.20",
    originalDestinationIp: "10.22.242.99",
    protocol: 17,
    originalServicePort: 18083,
    responderServicePort: 18081,
    icmpType: null,
    icmpCode: null,
  },
};

describe("native observation normalization", () => {
  it("records denied DNS questions with the enforcement service's decision identity and no packet destination", () => {
    const event = dnsDeniedObservation({
      observedAt: "2026-11-02T00:00:00.000Z",
      clientIp: "10.22.241.10",
      question: "proof.example",
      queryType: "AAAA",
      decision: {
        allowed: false,
        ruleId: null,
        catchAll: true,
        instanceId: client,
        revision: "42",
        policyHash: "a".repeat(64),
      },
    });

    expect(eventSchema.parse(event)).toMatchObject({
      observedAt: "2026-11-02T00:00:00.000Z",
      type: "dns",
      source: "resolver-gate",
      instanceId: client,
      question: "proof.example",
      direction: null,
      peerIp: null,
      protocol: null,
      port: null,
      details: {
        outcome: "policy-denied",
        queryType: "AAAA",
        catchall: true,
        appliedRevision: "42",
      },
    });
  });

  it("names query types that dns-packet leaves unnamed", () => {
    expect(queryTypeName("A")).toBe("A");
    expect(queryTypeName("UNKNOWN_64")).toBe("SVCB");
    expect(queryTypeName("UNKNOWN_65")).toBe("HTTPS");
    expect(queryTypeName("UNKNOWN_4242")).toBe("TYPE4242");
  });

  it("counts a connection to the gateway inside a subnet instance once, with the gateway as its peer on the port it serves", () => {
    const accounting = new TrafficAccounting();

    const owners = {
      instances: [
        {
          id: client,
          name: "Clients",
          addresses: ["10.22.241.0/24"],
          ownershipId: client,
        },
      ],
      gatewayAddresses: ["10.22.241.1"],
    };

    // A lookup sent to another resolver, redirected to the gateway's DNS gate.
    const redirected = {
      ...connection,
      flow: {
        ...connection.flow,
        responderIp: "10.22.241.1",
        originalDestinationIp: "192.0.2.53",
        originalServicePort: 53,
        responderServicePort: 5353,
      },
    };

    accounting.newConnection(redirected, owners, "2026-10-10T00:00:00.000Z");

    const events = accounting.observe(
      { ...redirected, sentBytes: "100", receivedBytes: "40" },
      owners,
      "2026-10-10T00:00:01.000Z",
    );

    expect(
      events.map(({ instanceId, direction, peerIp, port }) => ({
        instanceId,
        direction,
        peerIp,
        port,
      })),
    ).toEqual([
      {
        instanceId: client,
        direction: "outgoing",
        peerIp: "10.22.241.1",
        port: 5353,
      },
    ]);
  });

  it("rebaselines a reassigned owner while retaining the other endpoint's counters", () => {
    const accounting = new TrafficAccounting();

    const sample = (
      sentBytes: string,
      receivedBytes: string,
      seconds: number,
      owners = policy,
    ) =>
      accounting.observe(
        { ...connection, sentBytes, receivedBytes },
        owners,
        new Date(Date.UTC(2026, 9, 10, 0, 0, seconds)).toISOString(),
      );

    accounting.newConnection(connection, policy, "2026-10-10T00:00:00.000Z");
    sample("100", "40", 1);

    const next = {
      instances: policy.instances.map((instance) =>
        instance.id === client
          ? {
              ...instance,
              id: "33333333-3333-4333-8333-333333333333",
              ownershipId: "44444444-4444-4444-8444-444444444444",
            }
          : instance,
      ),
      gatewayAddresses: policy.gatewayAddresses,
    };

    const transition = sample("150", "60", 2, next);
    expect(transition).toHaveLength(1);
    expect(transition[0]!.instanceId).toBe(target);
    expect(accounting.takePartial()).toBe(true);
    expect(accounting.takePartial()).toBe(false);
    expect(
      sample("190", "75", 3, next).find(
        (event) => event.direction === "outgoing",
      ),
    ).toMatchObject({
      instanceId: next.instances[0]!.id,
      sentBytes: "40",
      receivedBytes: "15",
    });
    // The clean sample after the reported loss counts as recovery.
    expect(accounting.takePartial()).toBe(false);
  });
  it("does not reset a sampled baseline when an older NEW arrives from the backlog", () => {
    const accounting = new TrafficAccounting();

    const sample = (bytes: string, seconds: string) =>
      accounting.observe(
        { ...connection, sentBytes: bytes, receivedBytes: "0" },
        policy,
        `2026-10-10T00:00:${seconds}.000Z`,
      );

    expect(sample("100", "05")).toEqual([]);
    expect(sample("150", "10")[0]!.sentBytes).toBe("50");
    const staged = accounting.fork();
    staged.newConnection(connection, policy, "2026-10-10T00:00:01.000Z");
    expect(
      staged.observe(
        { ...connection, sentBytes: "200", receivedBytes: "0" },
        policy,
        "2026-10-10T00:00:15.000Z",
      )[0]!.sentBytes,
    ).toBe("50");
  });
  it("records the enforcement service-confirmed DNS owner and revision without a mutable policy lookup", () => {
    const resolution = {
      clientIp: "10.22.241.10",
      question: "proof.example",
      responseAt: new Date().toISOString(),
      answers: [
        {
          owner: "proof.example",
          type: "A" as const,
          value: "10.22.242.20",
          ttl: 60,
        },
      ],
    };

    const confirmation = {
      protocolVersion: 1 as const,
      revision: "2",
      policyHash: "a".repeat(64),
      bootId: randomUUID(),
      appliedAt: resolution.responseAt,
      permissions: 1,
      instanceId: target,
    };

    const event = dnsObservation(resolution, confirmation);
    expect(event.instanceId).toBe(target);
    expect(event.details).toMatchObject({
      appliedRevision: "2",
      outcome: "confirmed",
    });
    confirmation.instanceId = client;
    expect(event.instanceId).toBe(target);
    const failed = dnsObservation(resolution, null);
    expect(failed.instanceId).toBeNull();
    expect(failed.details).not.toHaveProperty("appliedRevision");
  });
  it("leaves the committed baseline unchanged when a prepared sample cannot be persisted", () => {
    const accounting = new TrafficAccounting();
    accounting.newConnection(connection, policy, "2026-10-09T20:00:00.000Z");
    accounting.observe(
      { ...connection, sentBytes: "100", receivedBytes: "40" },
      policy,
      "2026-10-09T20:00:01.000Z",
    );
    const staged = accounting.fork();
    expect(
      staged.observe(
        { ...connection, sentBytes: "150", receivedBytes: "60" },
        policy,
        "2026-10-09T20:00:02.000Z",
      )[0]?.sentBytes,
    ).toBe("50");

    const retried = accounting
      .fork()
      .observe(
        { ...connection, sentBytes: "170", receivedBytes: "70" },
        policy,
        "2026-10-09T20:00:03.000Z",
      );

    expect(retried[0]?.sentBytes).toBe("70");
    expect(retried[0]?.receivedBytes).toBe("30");
  });
  it("accounts for a short flow from NEW through DESTROY even when no snapshot saw it", () => {
    const accounting = new TrafficAccounting();
    accounting.newConnection(connection, policy, "2026-10-09T20:00:00.000Z");

    const events = accounting.observe(
      connection,
      policy,
      "2026-10-09T20:00:01.000Z",
      true,
      "terminal-fixture",
    );

    expect(events).toHaveLength(2);
    expect(events[0]?.sentBytes).toBe("9007199254740993");
    expect(events[0]?.peerIp).toBe("10.22.242.99");
    expect(events[0]?.port).toBe(18083);
    expect(events[1]?.receivedBytes).toBe("9007199254740993");
    expect(events[1]?.port).toBe(18081);
    expect(
      accounting.observe(connection, policy, "2026-10-09T20:00:02.000Z"),
    ).toEqual([]);
  });
  it("adds terminal counters to the previous snapshot without counting the total twice", () => {
    const accounting = new TrafficAccounting();
    accounting.newConnection(connection, policy, "2026-10-09T20:00:00.000Z");
    accounting.observe(
      { ...connection, sentBytes: "100", receivedBytes: "40" },
      policy,
      "2026-10-09T20:00:01.000Z",
    );

    const events = accounting.observe(
      { ...connection, sentBytes: "150", receivedBytes: "60" },
      policy,
      "2026-10-09T20:00:02.000Z",
      true,
    );

    expect(events[0]?.sentBytes).toBe("50");
    expect(events[0]?.receivedBytes).toBe("20");
  });
  it("keeps the original destination for outgoing NAT and the translated port for incoming NAT", () => {
    const original =
      "ip saddr 10.22.241.10 ip daddr 10.22.242.99 ip protocol udp udp sport 50000 udp dport 18083";

    const translated =
      "ip saddr 10.22.241.10 ip daddr 10.22.242.20 ip protocol udp udp sport 50000 udp dport 18081";

    const record = (side: string, instance: string) => ({
      id: randomUUID(),
      sequence: "1",
      observedAt: new Date().toISOString(),
      kind: "trace" as const,
      instances: [],
      record: `trace id abcd inet traffic_policy b4_${side}_${instance.replaceAll("-", "")}_00000000000040008000000000000001_3_c packet: ${original}\ntranslated:packet: ${translated}`,
    });

    const outgoing = blockedObservation(record("o", client)),
      incoming = blockedObservation(record("i", target));

    expect(outgoing?.peerIp).toBe("10.22.242.99");
    expect(outgoing?.port).toBe(18083);
    expect(incoming?.peerIp).toBe("10.22.241.10");
    expect(incoming?.port).toBe(18081);
    expect(outgoing?.details.appliedRevision).toBe("3");
    expect(outgoing?.details.catchall).toBe(true);
    // The managed end: the initiator going out, the translated responder coming in.
    expect(outgoing?.details.clientIp).toBe("10.22.241.10");
    expect(incoming?.details.clientIp).toBe("10.22.242.20");
  });
  it("attributes an unregistered drop to the address that started it and the side it arrived on", () => {
    const record = (chain: string, packet: string) => ({
      id: randomUUID(),
      sequence: "1",
      observedAt: new Date().toISOString(),
      kind: "trace" as const,
      instances: [],
      record: `trace id abcd inet traffic_policy ${chain} packet: ${packet}`,
    });

    expect(
      eventSchema.parse(
        blockedObservation(
          record(
            "u_c",
            'iif "lan0" ip saddr 10.22.241.99 ip daddr 93.184.216.34 ip protocol tcp tcp sport 50000 tcp dport 443',
          ),
        ),
      ),
    ).toMatchObject({
      type: "blocked",
      instanceId: null,
      direction: null,
      ruleId: null,
      peerIp: "93.184.216.34",
      protocol: 6,
      port: 443,
      details: { clientIp: "10.22.241.99", unregistered: "client" },
    });
    expect(
      blockedObservation(
        record(
          "u_u",
          "ip6 saddr 2001:db8::5 ip6 daddr fd10::1 ip6 nexthdr tcp tcp sport 1 tcp dport 22",
        ),
      )?.details,
    ).toMatchObject({ clientIp: "2001:db8::5", unregistered: "upstream" });
  });
});

describe("DNS denial sampling", () => {
  const denial = (
    instanceId: string,
    question = "flood.example",
    revision = "1",
    catchAll = true,
  ) => ({
    observedAt: "2026-01-01T00:00:00.000Z",
    clientIp: "10.22.241.10",
    question,
    queryType: "A",
    decision: {
      allowed: false,
      ruleId: catchAll ? null : "block-rule",
      catchAll,
      instanceId,
      revision,
      policyHash: "a".repeat(64),
    },
  });

  it("records a name once per window, so a retry flood does not hide a new name", () => {
    let now = 0;
    const sampler = new DnsDenialSampler(() => now);

    const repeats = Array.from({ length: 50 }, () =>
      sampler.sample(denial(client)),
    );

    expect(repeats.filter(Boolean)).toHaveLength(1);
    // Other query types of the name share its record.
    expect(sampler.sample({ ...denial(client), queryType: "AAAA" })).toBeNull();
    expect(sampler.sample(denial(client, "new.example"))).toMatchObject({
      question: "new.example",
      observedAt: "2026-01-01T00:00:00.000Z",
    });
    // Each client of an instance is recorded, so a Request lists every host that asked.
    expect(
      sampler.sample({ ...denial(client), clientIp: "10.22.241.11" }),
    ).not.toBeNull();
    // Repeats are not lost names.
    expect(sampler.lost).toBe(0);
    now = 59_999;
    expect(sampler.sample(denial(client))).toBeNull();
    now = 60_000;
    expect(sampler.sample(denial(client))).not.toBeNull();
  });
  it("keeps each unregistered client's name once per window within the denial limits", () => {
    let now = 0;
    const sampler = new UnregisteredNameSampler(() => now);

    expect(sampler.admit("10.22.241.99", "wanted.example")).toBe(true);
    expect(sampler.admit("10.22.241.99", "wanted.example")).toBe(false);
    expect(sampler.admit("10.22.241.98", "wanted.example")).toBe(true);
    expect(
      Array.from({ length: 25 }, (_, n) =>
        sampler.admit("10.22.241.97", `${n}.example`),
      ).filter(Boolean),
    ).toHaveLength(20);
    now = 60_000;
    expect(sampler.admit("10.22.241.99", "wanted.example")).toBe(true);
  });
  it("records a name again at once when a different decision denies it", () => {
    const sampler = new DnsDenialSampler(() => 0);

    expect(sampler.sample(denial(client))).not.toBeNull();
    expect(sampler.sample(denial(client, "flood.example", "2"))).toMatchObject({
      details: { appliedRevision: "2" },
    });
  });
  it("limits new names to 20 at once and 10 per second for each instance, counting the rest as lost", () => {
    let now = 0;
    const sampler = new DnsDenialSampler(() => now);

    const recorded = Array.from({ length: 30 }, (_, index) =>
      sampler.sample(denial(client, `n${index}.example`)),
    );

    expect(recorded.filter(Boolean)).toHaveLength(20);
    expect(sampler.lost).toBe(10);
    now = 1000;

    const next = Array.from({ length: 11 }, (_, index) =>
      sampler.sample(denial(client, `m${index}.example`)),
    );

    expect(next.filter(Boolean)).toHaveLength(10);
    expect(sampler.lost).toBe(11);
  });
  it("limits all instances to 200 new names at once", () => {
    const sampler = new DnsDenialSampler(() => 0);
    const instances = Array.from({ length: 11 }, () => randomUUID());

    const recorded = instances.flatMap((instanceId) =>
      Array.from({ length: 20 }, (_, index) =>
        sampler.sample(denial(instanceId, `${index}.example`)),
      ),
    );

    // The first 10 instances use the total burst; the last one's names are lost.
    expect(recorded.filter(Boolean)).toHaveLength(200);
    expect(sampler.lost).toBe(20);
  });
  it("keeps explicit-Block denials from using up the catch-all budget", () => {
    const sampler = new DnsDenialSampler(() => 0);

    const blocked = Array.from({ length: 30 }, (_, index) =>
      sampler.sample(denial(client, `b${index}.example`, "1", false)),
    );

    expect(blocked.filter(Boolean)).toHaveLength(20);

    const caught = Array.from({ length: 20 }, (_, index) =>
      sampler.sample(denial(client, `c${index}.example`)),
    );

    expect(caught.filter(Boolean)).toHaveLength(20);
    expect(sampler.lost).toBe(10);
  });
  it("records a name again after its append failed", () => {
    const sampler = new DnsDenialSampler(() => 0);
    const event = sampler.sample(denial(client))!;

    sampler.forget(event);
    expect(sampler.sample(denial(client))).not.toBeNull();
  });
});

describe("lost denial reports", () => {
  it("keeps the count when an append fails and reports it with the next one", async () => {
    const sampler = new DnsDenialSampler(() => 0);
    const reported: unknown[] = [];
    let fail = true;

    const reporter = new LostDenialReporter(sampler, async (details) => {
      if (fail) throw new Error("disk full");
      reported.push(details);
    });

    sampler.lost = 5;
    await expect(reporter.report()).rejects.toThrow("disk full");
    expect(sampler.lost).toBe(5);
    fail = false;
    await reporter.report();
    expect(reported).toMatchObject([
      { code: "dns_denials_omitted", occurrences: 5, recovered: true },
    ]);
    expect(sampler.lost).toBe(0);
    // Nothing lost, nothing reported.
    await reporter.report();
    expect(reported).toHaveLength(1);
  });
  it("reports a condition the contract accepts, and the contract rejects bad occurrence counts", () => {
    const condition = (occurrences: number | string) => ({
      id: randomUUID(),
      observedAt: "2026-01-01T00:00:00.000Z",
      type: "condition",
      instanceId: null,
      direction: null,
      peerIp: null,
      protocol: null,
      port: null,
      sentBytes: "0",
      receivedBytes: "0",
      ruleId: null,
      question: null,
      source: "gateway",
      details: { code: "dns_denials_omitted", occurrences, recovered: true },
    });

    expect(eventSchema.safeParse(condition(5)).success).toBe(true);

    for (const occurrences of [0, 1.5, "5"])
      expect(eventSchema.safeParse(condition(occurrences)).success).toBe(false);
  });
  it("shares a report in progress, and on close reports what was lost meanwhile", async () => {
    const sampler = new DnsDenialSampler(() => 0);
    const reported: unknown[] = [];
    let release = () => {};

    const reporter = new LostDenialReporter(sampler, async (details) => {
      reported.push(details);

      if (reported.length === 1)
        await new Promise<void>((resolve) => (release = resolve));
    });

    sampler.lost = 3;
    const first = reporter.report();

    expect(reporter.report()).toBe(first);
    sampler.lost += 2;
    const closing = reporter.close();

    release();
    await closing;
    expect(reported).toMatchObject([{ occurrences: 3 }, { occurrences: 2 }]);
    expect(sampler.lost).toBe(0);
  });
});
