import { describe, expect, it, vi } from "vitest";
import ipaddr from "ipaddr.js";
import {
  ScopeTree,
  canonicalName,
  policySchema,
  ruleSchema,
  type AddressLease,
  type Policy,
  type Rule,
} from "@traffic-policy/contracts";
import { DnsRuleIndex, type LeaseBinding } from "./dns-rules.ts";
import {
  addressInNetwork,
  decideDns,
  nameMatches,
  subjectContext,
} from "./index.ts";
import { addressLeases, iteratePermissionsForLeases } from "./leases.ts";

const client = "11111111-1111-4111-8111-111111111111";

const other = "22222222-2222-4222-8222-222222222222";

const timestamp = "2026-10-16T00:00:00.000Z";

const now = Date.parse(timestamp);

const tree = new ScopeTree([
  { id: client, addresses: ["10.0.0.1"] },
  { id: other, addresses: ["10.0.0.2"] },
]);

const clientContext = subjectContext(tree, "10.0.0.1")!,
  otherContext = subjectContext(tree, "10.0.0.2")!;

// `instanceId` is shorthand for an instance subject.
function rule(
  number: number,
  partial: Partial<Rule> & { instanceId?: string | null } = {},
): Rule {
  const { instanceId, ...rest } = partial;

  return ruleSchema.parse({
    id: `00000000-0000-4000-8000-${String(number).padStart(12, "0")}`,
    subject: instanceId ? { kind: "instance", instanceId } : { kind: "global" },
    direction: "outgoing",
    peer: { kind: "domain", value: "example.com" },
    protocol: null,
    portStart: null,
    portEnd: null,
    icmpType: null,
    icmpCode: null,
    action: "allow",
    priority: "normal",
    enabled: true,
    notBefore: null,
    expiresAt: null,
    dnsDestinations: ["192.0.2.0/24", "2001:db8::/32"],
    createdAt: timestamp,
    modifiedAt: timestamp,
    reason: "",
    ...rest,
  });
}

function policy(rules: Rule[]): Policy {
  return policySchema.parse({
    protocolVersion: 1,
    revision: "1",
    generatedAt: timestamp,
    instances: [
      // Dual-stack, so an IPv6 answer to an IPv4 lookup binds on each instance's IPv6 path.
      { id: client, name: "Client", addresses: ["10.0.0.1", "fd00::1"] },
      { id: other, name: "Other", addresses: ["10.0.0.2", "fd00::2"] },
    ],
    rules: [
      ...rules,
      rule(999999, {
        direction: "both",
        peer: { kind: "any" },
        dnsDestinations: null,
        action: "block",
      }),
    ],
    settings: {
      dnsGraceSeconds: 0,
      permissionLimit: 4096,
      trafficHistoryBytes: "268435456",
      dnsHistoryBytes: "134217728",
      blockedHistoryBytes: "106954752",
      otherHistoryBytes: "27262976",
      auditBytes: "134217728",
      collectorBytes: "134217728",
      gatewayDiskBytes: "4294967296",
      controllerDiskBytes: "8589934592",
      historyMaxAgeDays: null,
      auditMaxAgeDays: null,
      localNetworks: [],
      reverseDnsResolver: null,
    },
  });
}

function lease(
  question: string,
  address = "192.0.2.10",
  instanceId = client,
): AddressLease {
  return {
    path: `4|${instanceId}@32`,
    clientIp: instanceId === client ? "10.0.0.1" : "10.0.0.2",
    // The lease schema normalizes questions as DNS carries them.
    question: canonicalName(question),
    address,
    responseAt: timestamp,
    ttlSeconds: 60,
    expiresAt: "2026-10-16T00:01:00.000Z",
  };
}

// Independent oracle retains the former full-scan matching behavior.
// The rules a lease binds, wherever they are held.
const rulesOf = (bindings: LeaseBinding[]) =>
  bindings.flatMap((binding) => binding.rules);

function reference(value: Policy, answer: AddressLease): Rule[] {
  return value.rules.filter(
    (candidate) =>
      candidate.enabled &&
      (candidate.peer.kind === "hostname" ||
        candidate.peer.kind === "domain") &&
      (candidate.subject.kind === "global" ||
        (candidate.subject.kind === "instance" &&
          answer.path === `4|${candidate.subject.instanceId}@32`)) &&
      nameMatches(candidate.peer, answer.question) &&
      (candidate.dnsDestinations
        ? candidate.dnsDestinations.some((network) =>
            addressInNetwork(answer.address, network),
          )
        : ipaddr.process(answer.address).range() === "unicast" &&
          !value.settings.localNetworks.some((network) =>
            addressInNetwork(answer.address, network),
          )),
  );
}

describe("DNS admission", () => {
  it("keeps an unresolved question in review when only one service has an explicit Block", () => {
    const value = policy([
      rule(1, { action: "block", protocol: 6, portStart: 22, portEnd: 22 }),
    ]);

    expect(decideDns(value.rules, clientContext, "example.com", now)).toEqual({
      allowed: false,
      ruleId: value.rules[1]!.id,
      catchAll: true,
    });
    expect(
      decideDns(
        [rule(1, { action: "block" }), ...value.rules],
        clientContext,
        "example.com",
        now,
      ).catchAll,
    ).toBe(false);
  });

  it("uses name, scope, direction, and active time without an invented service", () => {
    expect(
      decideDns(
        [rule(1)],
        clientContext,
        canonicalName("API.EXAMPLE.COM."),
        now,
      ).allowed,
    ).toBe(true);

    for (const candidate of [
      rule(1, { instanceId: other }),
      rule(1, {
        direction: "incoming",
        peer: { kind: "any" },
        dnsDestinations: null,
      }),
      rule(1, { enabled: false }),
      rule(1, { expiresAt: timestamp }),
      rule(1, { notBefore: "2026-10-17T00:00:00.000Z" }),
      rule(1, { peer: { kind: "hostname", value: "example.com" } }),
      rule(1, {
        peer: { kind: "ip", value: "192.0.2.1" },
        dnsDestinations: null,
      }),
      rule(1, {
        peer: { kind: "cidr", value: "192.0.2.0/24" },
        dnsDestinations: null,
      }),
    ])
      expect(
        decideDns([candidate], clientContext, "api.example.com", now).allowed,
      ).toBe(false);
    expect(decideDns([rule(1)], clientContext, "other.test", now).allowed).toBe(
      false,
    );
  });

  it("attributes a denial to the Block that completes the losing Allow's coverage", () => {
    // A global Allow ranks below the catch-all of the same shape. The SSH Block ranks first but
    // leaves every other service open; the catch-all decides, so the lookup needs review.
    const ssh = rule(1, {
      action: "block",
      priority: "high",
      protocol: 6,
      portStart: 22,
      portEnd: 22,
    });

    const catchAll = rule(2, {
      action: "block",
      direction: "both",
      peer: { kind: "any" },
      dnsDestinations: null,
    });

    const allowAll = rule(3, {
      direction: "both",
      peer: { kind: "any" },
      dnsDestinations: null,
    });

    expect(
      decideDns(
        [ssh, catchAll, allowAll],
        clientContext,
        "api.example.com",
        now,
      ),
    ).toEqual({ allowed: false, ruleId: catchAll.id, catchAll: true });

    // A Block covering every service the Allow names decides on its own.
    const https = rule(4, { protocol: 6, portStart: 443, portEnd: 443 });

    const httpsBlock = rule(5, {
      action: "block",
      priority: "high",
      protocol: 6,
      portStart: 443,
      portEnd: 443,
    });

    expect(
      decideDns(
        [ssh, httpsBlock, https, catchAll],
        clientContext,
        "api.example.com",
        now,
      ),
    ).toEqual({ allowed: false, ruleId: httpsBlock.id, catchAll: false });
  });

  it("admits every question under an any-destination service Allow", () => {
    const allow = rule(1, {
      peer: { kind: "any" },
      dnsDestinations: null,
      protocol: 6,
      portStart: 443,
      portEnd: 443,
    });

    for (const name of ["example.com", "unknown.test", "."])
      expect(decideDns([allow], clientContext, name, now)).toMatchObject({
        allowed: true,
        ruleId: allow.id,
      });
  });

  it("keeps DNS available when another service is blocked", () => {
    const block = rule(1, {
      action: "block",
      protocol: 6,
      portStart: 22,
      portEnd: 22,
    });

    expect(
      decideDns([block, rule(2)], clientContext, "example.com", now).allowed,
    ).toBe(true);
    expect(
      decideDns(
        [block, rule(2, { protocol: 6, portStart: 443, portEnd: 443 })],
        clientContext,
        "example.com",
        now,
      ).allowed,
    ).toBe(true);
    expect(
      decideDns(
        [block, rule(2, { protocol: 6, portStart: 22, portEnd: 22 })],
        clientContext,
        "example.com",
        now,
      ).allowed,
    ).toBe(false);
  });

  it("combines higher-ranked service Blocks, preserving uncovered endpoints", () => {
    const allow = rule(1, { protocol: 6, portStart: 0, portEnd: 65535 });

    const low = rule(2, {
      action: "block",
      protocol: 6,
      portStart: 0,
      portEnd: 31,
    });

    const high = rule(3, {
      action: "block",
      protocol: 6,
      portStart: 32,
      portEnd: 65535,
    });

    expect(
      decideDns([allow, low, high], clientContext, "example.com", now).allowed,
    ).toBe(false);

    for (const [start, end] of [
      [33, 65535],
      [32, 65534],
    ])
      expect(
        decideDns(
          [allow, low, { ...high, portStart: start!, portEnd: end! }],
          clientContext,
          "example.com",
          now,
        ).allowed,
      ).toBe(true);
    expect(
      decideDns(
        [allow, rule(4, { action: "block", priority: "high" })],
        clientContext,
        "example.com",
        now,
      ).allowed,
    ).toBe(false);
  });

  it("compares ICMP type and code without treating them as ports", () => {
    const allow = rule(1, { protocol: 1, icmpType: 8 });

    const block = rule(2, {
      action: "block",
      protocol: 1,
      icmpType: 8,
      icmpCode: 0,
    });

    expect(
      decideDns([allow, block], clientContext, "example.com", now).allowed,
    ).toBe(true);
    expect(
      decideDns(
        [{ ...allow, icmpCode: 0 }, block],
        clientContext,
        "example.com",
        now,
      ).allowed,
    ).toBe(false);
  });
});

describe("indexed DNS rule matching", () => {
  it("preserves overlapping exact/domain rules, client scope and policy order", () => {
    const value = policy([
      rule(1),
      rule(2, {
        instanceId: other,
        peer: { kind: "hostname", value: "api.shop.example.com" },
      }),
      rule(3, {
        instanceId: client,
        peer: { kind: "hostname", value: "api.shop.example.com" },
      }),
      rule(4, {
        peer: { kind: "domain", value: "shop.example.com" },
        action: "block",
      }),
      rule(5, { enabled: false }),
    ]);

    const index = new DnsRuleIndex(value);
    const answer = lease("API.SHOP.EXAMPLE.COM.");
    expect(
      rulesOf(index.match(answer)).map((candidate) => candidate.id),
    ).toEqual([value.rules[0]!.id, value.rules[2]!.id, value.rules[3]!.id]);
    expect(rulesOf(index.match(answer))).toEqual(reference(value, answer));
    expect(
      rulesOf(index.match(lease(answer.question, answer.address, other))),
    ).toEqual(reference(value, lease(answer.question, answer.address, other)));
  });

  it("matches apex and deep subdomains at label boundaries, including normalized IDNA", () => {
    const value = policy([
      rule(1),
      rule(2, { peer: { kind: "hostname", value: "bücher.example" } }),
    ]);

    const index = new DnsRuleIndex(value);

    for (const name of [
      "example.com",
      "a.b.example.com",
      "badexample.com",
      "example.com.evil",
      "XN--BCHER-KVA.EXAMPLE.",
      "bücher.example",
    ]) {
      const answer = lease(name);
      expect(rulesOf(index.match(answer)), name).toEqual(
        reference(value, answer),
      );
    }

    expect(rulesOf(index.match(lease("badexample.com")))).toEqual([]);
    expect(rulesOf(index.match(lease("a.b.example.com")))).toHaveLength(1);
    expect(rulesOf(index.match(lease("XN--BCHER-KVA.EXAMPLE.")))).toHaveLength(
      1,
    );
    expect(rulesOf(index.match(lease("BÜCHER.EXAMPLE.")))).toHaveLength(1);
  });

  it("keeps network restrictions and default local/non-unicast exclusions for both families", () => {
    const value = policy([
      rule(1),
      rule(2, { dnsDestinations: null }),
      rule(3, { dnsDestinations: ["8.8.8.0/24", "2001:4860::/32"] }),
    ]);

    value.settings.localNetworks = ["8.8.8.0/24", "2001:4860::/32"];
    const index = new DnsRuleIndex(value);

    for (const address of [
      "192.0.2.10",
      "192.0.3.10",
      "2001:db8::10",
      "8.8.8.8",
      "2001:4860:4860::8888",
      "1.1.1.1",
      "127.0.0.1",
      "fe80::1",
      "::ffff:192.0.2.10",
    ]) {
      const answer = lease("api.example.com", address);
      expect(rulesOf(index.match(answer)), address).toEqual(
        reference(value, answer),
      );
    }
  });

  it("owns matching inputs and rebuilds correctly after expansion, narrowing and deletion", () => {
    const value = policy([
      rule(1, { peer: { kind: "hostname", value: "api.example.com" } }),
    ]);

    const original = new DnsRuleIndex(value);
    value.rules[0]!.peer = { kind: "domain", value: "example.com" };
    value.rules[0]!.dnsDestinations = ["192.0.2.0/25"];
    const expanded = new DnsRuleIndex(value);
    expect(rulesOf(original.match(lease("cdn.example.com")))).toEqual([]);
    expect(rulesOf(expanded.match(lease("cdn.example.com")))).toHaveLength(1);
    expect(
      rulesOf(original.match(lease("api.example.com", "192.0.2.200"))),
    ).toHaveLength(1);
    expect(
      rulesOf(expanded.match(lease("api.example.com", "192.0.2.200"))),
    ).toEqual([]);
    value.rules = [];
    expect(
      rulesOf(new DnsRuleIndex(value).match(lease("cdn.example.com"))),
    ).toEqual([]);
    expect(rulesOf(expanded.match(lease("cdn.example.com")))).toHaveLength(1);
  });

  it("retains the requested CNAME name and independent associations for a shared IP", () => {
    const value = policy([
      rule(1, { peer: { kind: "hostname", value: "api.example.com" } }),
      rule(2, { peer: { kind: "hostname", value: "cdn.example.com" } }),
      rule(3, { peer: { kind: "hostname", value: "edge.vendor.com" } }),
    ]);

    const index = new DnsRuleIndex(value);

    const answers = addressLeases(value, {
      clientIp: "10.0.0.1",
      question: "api.example.com",
      responseAt: timestamp,
      answers: [
        {
          owner: "api.example.com",
          type: "CNAME",
          value: "edge.vendor.com",
          ttl: 2,
        },
        { owner: "edge.vendor.com", type: "A", value: "192.0.2.10", ttl: 60 },
      ],
    });

    const permissions = [
      ...iteratePermissionsForLeases(
        value,
        [...answers, lease("cdn.example.com")],
        now,
        index,
      ),
    ];

    expect(permissions.map((permission) => permission.ruleId)).toEqual([
      value.rules[0]!.id,
      value.rules[1]!.id,
    ]);
    expect(permissions[0]!.expiresAt).toBe("2026-10-16T00:00:02.000Z");
    expect([
      ...iteratePermissionsForLeases(value, answers, now + 2000, index),
    ]).toEqual([]);
  });

  it("preserves rule deadlines and scheduled permissions", () => {
    const value = policy([
      rule(1, { expiresAt: "2026-10-16T00:00:03.000Z" }),
      rule(2, { notBefore: "2026-10-16T00:00:30.000Z" }),
      rule(3, { expiresAt: "2026-10-15T23:59:59.000Z" }),
    ]);

    const index = new DnsRuleIndex(value);

    const permissions = [
      ...iteratePermissionsForLeases(
        value,
        [lease("api.example.com")],
        now,
        index,
      ),
    ];

    expect(permissions.map((permission) => permission.ruleId)).toEqual([
      value.rules[0]!.id,
      value.rules[1]!.id,
    ]);
    expect(permissions[0]!.expiresAt).toBe("2026-10-16T00:00:03.000Z");
  });

  it("parses shared CIDRs once and does not reparse networks while matching", () => {
    const value = policy([
      rule(1),
      rule(2, { peer: { kind: "hostname", value: "api.example.com" } }),
    ]);

    const parse = vi.spyOn(ipaddr, "parseCIDR");

    try {
      const index = new DnsRuleIndex(value);
      expect(parse).toHaveBeenCalledTimes(2);
      parse.mockClear();

      for (let n = 0; n < 100; n++)
        expect(rulesOf(index.match(lease("api.example.com")))).toHaveLength(2);
      expect(parse).not.toHaveBeenCalled();
    } finally {
      parse.mockRestore();
    }
  });

  it("agrees with the full-scan oracle across unrelated rules and query combinations", () => {
    const rules: Rule[] = [];

    for (let n = 0; n < 128; n++)
      rules.push(
        rule(n + 1, {
          peer: {
            kind: n % 2 === 0 ? "domain" : "hostname",
            value: `site${n % 16}.example.com`,
          },
          instanceId: n % 3 === 0 ? client : n % 3 === 1 ? other : null,
          enabled: n % 5 !== 0,
          dnsDestinations:
            n % 7 === 0
              ? null
              : [n % 2 === 0 ? "192.0.2.0/24" : "2001:db8::/32"],
        }),
      );

    const value = policy(rules),
      index = new DnsRuleIndex(value);

    for (let n = 0; n < 96; n++) {
      const answer = lease(
        `${n % 3 === 0 ? "api." : ""}site${n % 24}.example.com`,
        n % 2 === 0 ? "192.0.2.10" : "2001:db8::10",
        n % 3 === 0 ? other : client,
      );

      expect(rulesOf(index.match(answer))).toEqual(reference(value, answer));
    }
  });
  it("finds the instance that owns a client address", () => {
    const index = new DnsRuleIndex(policy([]));

    expect(index.context("10.0.0.1")?.instanceId).toBe(client);
    expect(index.context("10.0.0.2")?.instanceId).toBe(other);
    expect(index.context("10.0.0.3")).toBeNull();
  });

  it("decides lookups exactly as the full scan across peers, scopes, services, and schedules", () => {
    const peers: Rule["peer"][] = [
      { kind: "any" },
      { kind: "domain", value: "example.com" },
      { kind: "domain", value: "api.example.com" },
      { kind: "hostname", value: "api.example.com" },
      { kind: "hostname", value: "example.com" },
      { kind: "ip", value: "192.0.2.1" },
      { kind: "cidr", value: "192.0.2.0/24" },
    ];

    const rules: Rule[] = [];

    for (let n = 0; n < 160; n++)
      rules.push(
        rule(n + 1, {
          peer: peers[n % peers.length]!,
          instanceId: n % 3 === 0 ? client : n % 3 === 1 ? other : null,
          // DNS selectors require outgoing direction.
          direction:
            n % peers.length === 0 || n % peers.length >= 5
              ? (["outgoing", "incoming", "both"] as const)[n % 3]!
              : "outgoing",
          action: n % 4 < 2 ? "allow" : "block",
          priority: n % 11 === 0 ? "high" : "normal",
          enabled: n % 13 !== 0,
          protocol: n % 5 === 0 ? 6 : n % 5 === 1 ? 17 : null,
          portStart: n % 5 === 0 ? 443 : null,
          portEnd: n % 5 === 0 ? 443 : null,
          notBefore: n % 17 === 0 ? new Date(now + 60_000).toISOString() : null,
          expiresAt:
            n % 19 === 0 ? new Date(now + 120_000).toISOString() : null,
          dnsDestinations: null,
        }),
      );

    const value = policy(rules),
      index = new DnsRuleIndex(value);

    for (const at of [now, now + 90_000, now + 180_000])
      for (const context of [clientContext, otherContext])
        for (const question of [
          ".",
          "example.com",
          "api.example.com",
          "deep.api.example.com",
          "other.example.com",
          "example.org",
        ])
          expect(index.decide(context, question, at)).toEqual(
            decideDns(value.rules, context, question, at),
          );
  });
});
