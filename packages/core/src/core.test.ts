import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  ScopeTree,
  addressInteger,
  flowSchema,
  nameSchema,
  policySchema,
  policyTransportSchema,
  MAX_POLICY_BYTES,
  MAX_MACHINE_FRAME_BYTES,
  resolutionSchema,
  ruleSchema,
  uint64Schema,
} from "@traffic-policy/contracts";
import type { Policy, Resolution, Rule } from "@traffic-policy/contracts";
import {
  catchAllActions,
  compareRules,
  decideDns,
  decideTraffic,
  describeRule,
  isSettingsCatchAll,
  overriddenBy,
  ruleMatches,
  ruleScopeLabel,
  ruleState,
  scopeTree,
  serviceLabel,
  subjectContext,
} from "./index.ts";
import {
  addressLeases,
  iteratePermissionsForLeases,
  reconcileLeases,
} from "./leases.ts";
import {
  blockCounterName,
  compileNftables,
  compileDnsUpdate,
  connectionMarkScope,
  connectionMarkScopes,
  dnsChains,
  dnsSetName,
  GUARD_TABLE,
  parseBlockCounter,
  policyNodes,
  TABLE,
} from "./nftables.ts";

const clientId = "11111111-1111-4111-8111-111111111111";

const marksFor = (value: Policy) =>
  new Map(
    connectionMarkScopes(value).map((scope, index) => [scope, index + 1]),
  );

const targetId = "22222222-2222-4222-8222-222222222222";

const timestamp = "2026-10-10T00:00:00.000Z";

const now = Date.parse(timestamp);

let sequence = 0;

const instances = [
  { id: clientId, name: "Client", addresses: ["10.22.241.10"] },
  { id: targetId, name: "Target", addresses: ["10.22.242.20"] },
];

const contextOf = (address: string) =>
  subjectContext(new ScopeTree(instances), address)!;

const clientContext = contextOf("10.22.241.10"),
  targetContext = contextOf("10.22.242.20");

const infrastructure = {
  upstreamInterfaces: ["wan0"],
  controllerAddresses: ["192.0.2.9"],
  machinePort: 9443,
  controllerPort: 9445,
  upstreamDns: { address: "192.0.2.53", port: 53 },
};

// The chain name of the node owning a managed address.
function nodeName(value: Policy, address: string): string {
  const target = addressInteger(address);

  return policyNodes(scopeTree(value)).ranges.find(
    (range) =>
      range.family === target.family &&
      range.start <= target.value &&
      target.value <= range.end,
  )!.node.name;
}

// `instanceId` is shorthand for an instance subject.
function rule(
  partial: Partial<Rule> & { instanceId?: string | null } = {},
): Rule {
  const { instanceId, ...rest } = partial;

  return ruleSchema.parse({
    id: `00000000-0000-4000-8000-${String(++sequence).padStart(12, "0")}`,
    subject: instanceId ? { kind: "instance", instanceId } : { kind: "global" },
    direction: "both",
    peer: { kind: "any" },
    protocol: null,
    portStart: null,
    portEnd: null,
    icmpType: null,
    icmpCode: null,
    action: "block",
    priority: "normal",
    enabled: true,
    notBefore: null,
    expiresAt: null,
    dnsDestinations: null,
    createdAt: timestamp,
    modifiedAt: timestamp,
    reason: "",
    ...rest,
  });
}

function policy(rules: Rule[]): Policy {
  return policySchema.parse({
    protocolVersion: 1,
    revision: "9007199254740993",
    generatedAt: timestamp,
    instances: structuredClone(instances),
    rules: [...rules, rule()],
    settings: {
      dnsGraceSeconds: 7200,
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

// The gateway derives grants through address leases, not directly from answers.
function grantsFor(value: Policy, resolution: Resolution) {
  return [
    ...iteratePermissionsForLeases(
      value,
      addressLeases(value, resolution),
      now,
    ),
  ];
}

function chainBody(program: string, name: string): string {
  const start = program.indexOf(`  chain ${name} {\n`);
  expect(start).toBeGreaterThanOrEqual(0);

  return program.slice(start, program.indexOf("\n  }", start));
}

const flow = flowSchema.parse({
  initiatorIp: "10.22.241.10",
  responderIp: "10.22.242.20",
  originalDestinationIp: "10.22.242.20",
  protocol: 6,
  originalServicePort: 443,
  responderServicePort: 443,
  icmpType: null,
  icmpCode: null,
});

describe("Settings catch-all", () => {
  it("covers only the enabled, normal-priority, permanent global catch-all", () => {
    expect(isSettingsCatchAll(rule())).toBe(true);
    expect(isSettingsCatchAll(rule({ priority: "high" }))).toBe(false);
    expect(isSettingsCatchAll(rule({ enabled: false }))).toBe(false);
    expect(isSettingsCatchAll(rule({ expiresAt: timestamp }))).toBe(false);
    expect(isSettingsCatchAll(rule({ instanceId: clientId }))).toBe(false);
  });

  it("reads each direction's action by rule precedence", () => {
    expect(
      catchAllActions([
        rule(),
        rule({ direction: "outgoing", action: "allow" }),
        rule({ action: "allow", priority: "high" }),
      ]),
    ).toEqual({ outgoing: "allow", incoming: "block" });
    expect(catchAllActions([rule({ direction: "outgoing" })])).toEqual({
      outgoing: "block",
      incoming: null,
    });
  });
});

describe("DNS denial attribution", () => {
  it("leaves questions unresolved when no unrestricted Block or Allow applies", () => {
    const ssh = rule({ protocol: 6, portStart: 22, portEnd: 22 });
    const echo = rule({ protocol: 1, icmpType: 8 });

    for (const rules of [[], [ssh], [echo, ssh]])
      expect(decideDns(rules, clientContext, "api.example.com", now)).toEqual({
        allowed: false,
        ruleId: null,
        catchAll: true,
      });
  });

  it("selects the highest-ranked unrestricted Block independently of input order", () => {
    const fallback = rule();

    const named = rule({
      direction: "outgoing",
      peer: { kind: "domain", value: "example.com" },
    });

    const exact = rule({
      instanceId: clientId,
      direction: "outgoing",
      peer: { kind: "hostname", value: "api.example.com" },
    });

    const ssh = rule({
      priority: "high",
      protocol: 6,
      portStart: 22,
      portEnd: 22,
    });

    for (const rules of [
      [fallback, named, exact, ssh],
      [ssh, exact, named, fallback],
    ])
      expect(decideDns(rules, clientContext, "api.example.com", now)).toEqual({
        allowed: false,
        ruleId: exact.id,
        catchAll: false,
      });
    expect(decideDns([ssh, fallback], clientContext, ".", now)).toEqual({
      allowed: false,
      ruleId: fallback.id,
      catchAll: true,
    });
  });

  it("keeps attribution when an Allow is fully covered by the winning Block", () => {
    const fallback = rule();

    const block = rule({
      priority: "high",
      direction: "outgoing",
      peer: { kind: "hostname", value: "api.example.com" },
    });

    const allow = rule({
      action: "allow",
      direction: "outgoing",
      peer: { kind: "hostname", value: "api.example.com" },
      protocol: 6,
      portStart: 443,
      portEnd: 443,
    });

    const expected = { allowed: false, ruleId: block.id, catchAll: false };

    expect(
      decideDns([fallback, block], clientContext, "api.example.com", now),
    ).toEqual(expected);
    expect(
      decideDns(
        [allow, fallback, block],
        clientContext,
        "api.example.com",
        now,
      ),
    ).toEqual(expected);
  });

  it("ignores Allows outside the question, scope, direction, or active time", () => {
    const fallback = rule();

    const excluded: (Partial<Rule> & { instanceId?: string })[] = [
      { enabled: false },
      { expiresAt: timestamp },
      { notBefore: new Date(now + 1000).toISOString() },
      { instanceId: targetId },
      { direction: "incoming" },
      {
        direction: "outgoing",
        peer: { kind: "hostname", value: "other.example" },
      },
      { peer: { kind: "ip", value: "192.0.2.1" } },
      { peer: { kind: "cidr", value: "192.0.2.0/24" } },
    ];

    for (const partial of excluded) {
      const allow = rule({ action: "allow", ...partial });

      expect(
        decideDns([allow, fallback], clientContext, "api.example.com", now),
      ).toEqual({
        allowed: false,
        ruleId: fallback.id,
        catchAll: true,
      });
    }
  });

  it("honors the exact start and expiry of an Allow on repeated questions", () => {
    const fallback = rule();
    const start = now + 1000;
    const end = now + 2000;

    const allow = rule({
      action: "allow",
      direction: "outgoing",
      peer: { kind: "hostname", value: "api.example.com" },
      protocol: 6,
      portStart: 443,
      portEnd: 443,
      notBefore: new Date(start).toISOString(),
      expiresAt: new Date(end).toISOString(),
    });

    const rules = [fallback, allow];

    for (const at of [start - 1, end, end + 1])
      expect(decideDns(rules, clientContext, "api.example.com", at)).toEqual({
        allowed: false,
        ruleId: fallback.id,
        catchAll: true,
      });

    for (const at of [start, end - 1])
      expect(decideDns(rules, clientContext, "api.example.com", at)).toEqual({
        allowed: true,
        ruleId: allow.id,
        catchAll: false,
      });
  });

  it("honors scheduled Blocks while no Allow applies", () => {
    const fallback = rule();
    const start = now + 1000;
    const end = now + 2000;

    const block = rule({
      direction: "outgoing",
      peer: { kind: "hostname", value: "api.example.com" },
      notBefore: new Date(start).toISOString(),
      expiresAt: new Date(end).toISOString(),
    });

    const rules = [block, fallback];

    for (const at of [start - 1, end])
      expect(decideDns(rules, clientContext, "api.example.com", at)).toEqual({
        allowed: false,
        ruleId: fallback.id,
        catchAll: true,
      });

    for (const at of [start, end - 1])
      expect(decideDns(rules, clientContext, "api.example.com", at)).toEqual({
        allowed: false,
        ruleId: block.id,
        catchAll: false,
      });
  });
});

describe("overridden rules", () => {
  const target = (partial: Partial<Rule> = {}) =>
    rule({
      instanceId: clientId,
      direction: "outgoing",
      peer: { kind: "ip", value: "10.22.242.20" },
      portStart: 18081,
      portEnd: 18081,
      ...partial,
    });

  const later = new Date(now + 3600000).toISOString();
  const latest = new Date(now + 7200000).toISOString();

  it("finds a Block that wins the equal-priority tie against a temporary Allow", () => {
    const block = target();
    const allow = target({ action: "allow", expiresAt: later });

    expect(overriddenBy(allow, [block, allow], instances, now)).toEqual({
      rule: block,
      until: null,
    });
    expect(overriddenBy(block, [block, allow], instances, now)).toBeNull();
  });

  it("ignores rules that only partly cover or are outranked by specificity", () => {
    const allow = target({ action: "allow" });

    for (const other of [
      target({ portStart: null, portEnd: null, protocol: null }),
      target({ peer: { kind: "cidr", value: "10.22.242.0/24" } }),
      rule({ peer: { kind: "cidr", value: "10.22.242.0/24" } }),
    ])
      expect(overriddenBy(allow, [other], instances, now)).toBeNull();

    // A TCP Block outranks a TCP/UDP Allow but leaves its UDP traffic alone.
    expect(
      overriddenBy(allow, [target({ protocol: 6 })], instances, now),
    ).toBeNull();

    // An internal-only High Block leaves the same name's public answers to the Allow.
    const named = { kind: "hostname" as const, value: "x.example" };
    const publicAllow = target({ action: "allow", peer: named });

    expect(
      overriddenBy(
        publicAllow,
        [
          target({
            peer: named,
            priority: "high",
            dnsDestinations: ["10.0.0.0/8"],
          }),
        ],
        instances,
        now,
      ),
    ).toBeNull();
    expect(
      overriddenBy(
        publicAllow,
        [target({ peer: named, priority: "high" })],
        instances,
        now,
      )?.rule.priority,
    ).toBe("high");
  });

  it("reports High priority covering rules and when a temporary winner ends", () => {
    const broad = rule({ priority: "high", expiresAt: later });
    const allow = target({ action: "allow" });

    expect(overriddenBy(allow, [broad], instances, now)).toEqual({
      rule: broad,
      until: later,
    });
    expect(
      overriddenBy(
        target({ action: "allow", expiresAt: later }),
        [broad],
        instances,
        now,
      )?.until,
    ).toBeNull();
    expect(
      overriddenBy(
        allow,
        [broad, rule({ priority: "high", expiresAt: latest })],
        instances,
        now,
      )?.until,
    ).toBe(latest);
    expect(
      overriddenBy(
        allow,
        [rule({ priority: "high", enabled: false })],
        instances,
        now,
      ),
    ).toBeNull();
    expect(
      overriddenBy(
        target({ action: "allow", enabled: false }),
        [broad],
        instances,
        now,
      ),
    ).toBeNull();
  });

  it("treats a domain as covering its hostnames", () => {
    const hostname = target({
      action: "allow",
      peer: { kind: "hostname", value: "api.example.com" },
      portStart: null,
      portEnd: null,
    });

    expect(
      overriddenBy(
        hostname,
        [
          target({
            peer: { kind: "domain", value: "example.com" },
            portStart: null,
            portEnd: null,
            priority: "high",
          }),
        ],
        instances,
        now,
      ),
    ).not.toBeNull();
  });
});

describe("policy semantics", () => {
  it("rejects DNS destination restrictions on non-DNS selectors", () => {
    for (const peer of [
      { kind: "any" as const },
      { kind: "ip" as const, value: "10.22.242.20" },
      { kind: "cidr" as const, value: "10.22.242.0/24" },
    ]) {
      expect(() => rule({ peer, dnsDestinations: ["10.22.242.0/24"] })).toThrow(
        "DNS destination networks require a hostname or domain selector",
      );
    }

    expect(
      rule({
        direction: "outgoing",
        peer: { kind: "hostname", value: "proof.example" },
        dnsDestinations: ["10.22.242.0/24"],
      }).dnsDestinations,
    ).toEqual(["10.22.242.0/24"]);
  });
  it("bounds encoded policy bytes with room for command and status framing", () => {
    const value = policy(
      Array.from({ length: 2000 }, () => rule({ id: crypto.randomUUID() })),
    );

    let remaining = MAX_POLICY_BYTES - Buffer.byteLength(JSON.stringify(value));

    for (const entry of value.rules) {
      const bytes = Math.min(1024, remaining);
      entry.reason = "x".repeat(bytes);
      remaining -= bytes;
    }

    expect(remaining).toBe(0);
    expect(Buffer.byteLength(JSON.stringify(value))).toBe(MAX_POLICY_BYTES);
    expect(policyTransportSchema.safeParse(value).success).toBe(true);
    expect(
      Buffer.byteLength(
        JSON.stringify({
          id: crypto.randomUUID(),
          operation: "apply",
          policy: value,
        }),
      ),
    ).toBeLessThan(MAX_MACHINE_FRAME_BYTES);
    expect(
      Buffer.byteLength(
        JSON.stringify({
          id: crypto.randomUUID(),
          ok: true,
          value: { policy: value, metadata: "x".repeat(60 * 1024) },
        }),
      ),
    ).toBeLessThan(MAX_MACHINE_FRAME_BYTES);
    value.rules.find((entry) => entry.reason.length < 1024)!.reason += "é";
    expect(policyTransportSchema.safeParse(value).success).toBe(false);
  });
  it("orders peer before instance and uses an explicit priority override", () => {
    const instanceBlock = rule({ instanceId: clientId, action: "block" });

    const specificAllow = rule({
      peer: { kind: "ip", value: "10.22.242.20" },
      action: "allow",
    });

    expect([instanceBlock, specificAllow].sort(compareRules)[0]).toBe(
      specificAllow,
    );
    const override = rule({ priority: "high" });
    expect([instanceBlock, specificAllow, override].sort(compareRules)[0]).toBe(
      override,
    );
  });
  it("lets a Block win equal scope while narrower ports retain precedence", () => {
    const allow = rule({ action: "allow" });
    const block = rule();
    expect(compareRules(block, allow)).toBeLessThan(0);

    const narrow = rule({
      protocol: 6,
      portStart: 443,
      portEnd: 443,
      action: "allow",
    });

    const broad = rule({ protocol: 6, portStart: 1, portEnd: 65535 });
    expect(compareRules(narrow, broad)).toBeLessThan(0);
  });
  it("labels a port without a protocol as TCP or UDP and any traffic as any", () => {
    expect(serviceLabel(null, null)).toBe("any");
    expect(serviceLabel(null, 18081)).toBe("TCP/UDP:18081");
    expect(serviceLabel(6, null)).toBe("TCP");
    expect(serviceLabel(6, 8000, 8100)).toBe("TCP:8000–8100");
    expect(serviceLabel(47, null)).toBe("Protocol 47");
    expect(
      ruleScopeLabel(
        rule({
          peer: { kind: "ip", value: "10.22.242.20" },
          portStart: 18081,
          portEnd: 18081,
        }),
      ),
    ).toBe("10.22.242.20 · TCP/UDP:18081");
    expect(ruleScopeLabel(rule({ protocol: 1, icmpType: 8 }))).toBe(
      "Any peer · ICMP type 8",
    );
    expect(describeRule(rule({ direction: "outgoing" }))).toBe(
      "Any instance · Outgoing · Any peer · any",
    );
  });
  it("decides observed traffic, reports outranking DNS rules, and lists equally specific rules", () => {
    const target = clientContext;
    const catchAll = rule();

    const named = rule({
      action: "allow",
      direction: "outgoing",
      peer: { kind: "hostname", value: "proof.example" },
      protocol: 6,
      portStart: 18080,
      portEnd: 18081,
    });

    const traffic = {
      direction: "outgoing" as const,
      peerIp: "8.8.8.8",
      protocol: 6,
      port: 18080,
    };

    expect(decideTraffic([catchAll, named], target, traffic, [], now)).toEqual({
      winner: catchAll,
      dns: [named],
      equal: [],
      refused: [],
    });
    expect(
      decideTraffic(
        [catchAll, named],
        target,
        traffic,
        [],
        now,
        "proof.example",
      ),
    ).toEqual({ winner: named, dns: [], equal: [], refused: [] });
    expect(
      decideTraffic(
        [catchAll, named],
        target,
        traffic,
        [],
        now,
        "other.example",
      ),
    ).toEqual({ winner: catchAll, dns: [], equal: [], refused: [] });

    const internal = { ...traffic, peerIp: "10.22.242.20" };
    const block = rule({ peer: { kind: "ip", value: "10.22.242.20" } });

    const temporaryAllow = rule({
      action: "allow",
      peer: { kind: "ip", value: "10.22.242.20" },
      expiresAt: "2026-10-11T00:00:00.000Z",
    });

    expect(
      decideTraffic(
        [catchAll, temporaryAllow, block],
        target,
        internal,
        [],
        now,
      ),
    ).toEqual({ winner: block, dns: [], equal: [temporaryAllow], refused: [] });
  });
  it("leaves out a DNS rule where it refuses the peer address as an answer", () => {
    const target = clientContext;
    const catchAll = rule();

    const named = rule({
      action: "allow",
      direction: "outgoing",
      peer: { kind: "hostname", value: "nas.home" },
    });

    const traffic = (peerIp: string) => ({
      direction: "outgoing" as const,
      peerIp,
      protocol: 6,
      port: 445,
    });

    // A private answer is refused without permitted destination networks.
    expect(
      decideTraffic([catchAll, named], target, traffic("192.168.1.5"), [], now),
    ).toEqual({ winner: catchAll, dns: [], equal: [], refused: [] });
    expect(
      decideTraffic(
        [catchAll, named],
        target,
        traffic("192.168.1.5"),
        [],
        now,
        "nas.home",
      ),
    ).toEqual({
      winner: catchAll,
      dns: [],
      equal: [],
      refused: [{ rule: named, reason: "not-public" }],
    });

    // A public prefix listed in localNetworks is refused the same way.
    expect(
      decideTraffic(
        [catchAll, named],
        target,
        traffic("8.8.8.8"),
        ["8.8.8.0/24"],
        now,
        "nas.home",
      ).refused,
    ).toEqual([{ rule: named, reason: "not-public" }]);

    const permitted = { ...named, dnsDestinations: ["192.168.1.0/24"] };

    expect(
      decideTraffic(
        [catchAll, permitted],
        target,
        traffic("192.168.1.5"),
        [],
        now,
        "nas.home",
      ),
    ).toEqual({ winner: permitted, dns: [], equal: [], refused: [] });
    expect(
      decideTraffic(
        [catchAll, permitted],
        target,
        traffic("192.168.1.5"),
        [],
        now,
      ).dns,
    ).toEqual([permitted]);
    expect(
      decideTraffic(
        [catchAll, permitted],
        target,
        traffic("192.168.2.5"),
        [],
        now,
        "nas.home",
      ).refused,
    ).toEqual([{ rule: permitted, reason: "outside" }]);
  });
  it("checks both managed endpoints and lets an Allow continue to the other endpoint", () => {
    const outgoing = rule({
      instanceId: clientId,
      direction: "outgoing",
      action: "allow",
    });

    const value = policy([outgoing]);
    const [client, target] = [clientContext, targetContext];
    const ordered = [...value.rules].sort(compareRules);

    expect(
      ordered.find((candidate) =>
        ruleMatches(candidate, client, "outgoing", flow, [], now),
      )?.action,
    ).toBe("allow");
    expect(
      ordered.find((candidate) =>
        ruleMatches(candidate, target, "incoming", flow, [], now),
      )?.action,
    ).toBe("block");

    const program = compileNftables(value, [], {
      marks: marksFor(value),
      tableExists: false,
      dnsPort: 5353,
      infrastructure,
      now,
      policyHash: "a".repeat(64),
    });

    const forward = chainBody(program, "forward");
    expect(forward).toContain("ct original ip saddr vmap @o4");
    expect(forward).toContain("ct reply ip saddr vmap @i4");
    expect(program).toContain(
      `10.22.241.10 : jump o4_${nodeName(value, "10.22.241.10")}`,
    );
    expect(program).toContain(
      `10.22.242.20 : jump i4_${nodeName(value, "10.22.242.20")}`,
    );
    expect(
      chainBody(program, `o4_${nodeName(value, "10.22.241.10")}`),
    ).toContain(`counter return comment "rule:${outgoing.id}"`);
  });
  it("lets managed clients reach the local DNS gate before their rules", () => {
    const program = compileNftables(policy([]), [], {
      marks: marksFor(policy([])),
      tableExists: false,
      dnsPort: 5353,
      infrastructure,
      now,
      policyHash: "a".repeat(64),
    });

    const exempt = (hook: string, port: string) => {
      const body = chainBody(program, hook);

      const rule = body.indexOf(
        `meta l4proto { tcp, udp } th ${port} 5353 counter accept comment "gateway-dns"`,
      );

      expect(rule).toBeGreaterThan(body.indexOf("ct state invalid"));
      expect(rule).toBeLessThan(body.indexOf(" vmap "));
    };

    exempt("input", "dport");
    exempt("output", "sport");
    expect(chainBody(program, "forward")).not.toContain("gateway-dns");
  });
  it("uses original destination and port for outgoing and translated port for incoming", () => {
    const outgoing = rule({
      instanceId: clientId,
      direction: "outgoing",
      action: "allow",
      peer: { kind: "ip", value: "10.22.242.99" },
      protocol: 6,
      portStart: 10443,
      portEnd: 10443,
    });

    const incoming = rule({
      instanceId: targetId,
      direction: "incoming",
      action: "allow",
      protocol: 6,
      portStart: 443,
      portEnd: 443,
    });

    const translated = {
      ...flow,
      originalDestinationIp: "10.22.242.99",
      originalServicePort: 10443,
    };

    const value = policy([outgoing, incoming]);
    const [client, target] = [clientContext, targetContext];

    expect(ruleMatches(outgoing, client, "outgoing", translated, [], now)).toBe(
      true,
    );
    expect(ruleMatches(outgoing, client, "outgoing", flow, [], now)).toBe(
      false,
    );
    expect(ruleMatches(incoming, target, "incoming", translated, [], now)).toBe(
      true,
    );

    const program = compileNftables(value, [], {
      marks: marksFor(value),
      tableExists: false,
      dnsPort: 5353,
      infrastructure,
      now,
      policyHash: "a".repeat(64),
    });

    expect(
      chainBody(program, `o4_${nodeName(value, "10.22.241.10")}`),
    ).toContain(
      "ct original ip daddr 10.22.242.99 ct protocol 6 ct original proto-dst 10443",
    );
    expect(
      chainBody(program, `i4_${nodeName(value, "10.22.242.20")}`),
    ).toContain("ct protocol 6 ct reply proto-src 443");
  });
  it("counts each Block rule's drops in one named counter per instance and direction", () => {
    const blocked = rule({ protocol: 17, portStart: 18099, portEnd: 18099 });
    const value = policy([blocked]);

    value.instances[0]!.addresses.push("fd42::10");

    const program = compileNftables(value, [], {
      marks: marksFor(value),
      tableExists: false,
      dnsPort: 5353,
      infrastructure,
      now,
      policyHash: "a".repeat(64),
    });

    const counter = blockCounterName(blocked, clientId, "outgoing");

    expect(program.split(`  counter ${counter} {\n`)).toHaveLength(2);
    expect(program.split(`counter name "${counter}" drop`)).toHaveLength(3);
    expect(parseBlockCounter(counter)).toEqual({
      direction: "outgoing",
      instanceId: clientId,
      ruleId: blocked.id,
    });
    expect(parseBlockCounter(`b4_${counter}`)).toBeNull();
  });
  it("keeps enablement, schedule, and expiry independent", () => {
    const expired = rule({ expiresAt: timestamp });
    expect(ruleState(expired, now)).toBe("expired");
    expect(ruleState({ ...expired, enabled: false }, now)).toBe("disabled");
    expect(
      ruleState(rule({ notBefore: "2026-10-10T00:00:01.000Z" }), now),
    ).toBe("scheduled");
  });
  it("rejects missing permanent catch-alls and address ambiguity", () => {
    const value = policy([]);
    expect(policySchema.safeParse({ ...value, rules: [] }).success).toBe(false);
    expect(
      policySchema.safeParse({
        ...value,
        instances: [
          ...value.instances,
          {
            id: "33333333-3333-4333-8333-333333333333",
            name: "Ambiguous",
            addresses: ["10.22.241.10"],
          },
        ],
      }).success,
    ).toBe(false);
  });
});

describe("authoritative DNS leases", () => {
  it("follows linked CNAMEs with the lowest TTL and the rule hard deadline", () => {
    const dns = rule({
      instanceId: clientId,
      direction: "outgoing",
      peer: { kind: "hostname", value: "app.example" },
      action: "allow",
      expiresAt: "2026-10-10T00:00:10.000Z",
      dnsDestinations: ["10.22.242.0/24"],
    });

    const value = policy([dns]);

    const permissions = grantsFor(value, {
      clientIp: "10.22.241.10",
      question: "app.example",
      responseAt: timestamp,
      answers: [
        { owner: "app.example", type: "CNAME", value: "edge.example", ttl: 2 },
        { owner: "edge.example", type: "A", value: "10.22.242.20", ttl: 60 },
        {
          owner: "unrelated.example",
          type: "A",
          value: "10.22.242.21",
          ttl: 60,
        },
      ],
    });

    expect(permissions).toHaveLength(1);
    expect(permissions[0]).toMatchObject({
      question: "app.example",
      ttlSeconds: 2,
      expiresAt: "2026-10-10T00:00:10.000Z",
    });
  });
  it("does not authorize private destinations without explicit networks", () => {
    const dns = rule({
      direction: "outgoing",
      peer: { kind: "domain", value: "example" },
      action: "allow",
    });

    const permissions = grantsFor(policy([dns]), {
      clientIp: "10.22.241.10",
      question: "app.example",
      responseAt: timestamp,
      answers: [
        { owner: "app.example", type: "A", value: "10.22.242.20", ttl: 60 },
      ],
    });

    expect(permissions).toEqual([]);
  });
  it("recalculates an active deadline without reviving an expired grant", () => {
    const dns = rule({
      direction: "outgoing",
      peer: { kind: "hostname", value: "app.example" },
      action: "allow",
      dnsDestinations: ["10.22.242.0/24"],
    });

    const value = policy([dns]);
    value.settings.dnsGraceSeconds = 1;

    const leases = addressLeases(value, {
      clientIp: "10.22.241.10",
      question: "app.example",
      responseAt: timestamp,
      answers: [
        { owner: "app.example", type: "A", value: "10.22.242.20", ttl: 1 },
      ],
    });

    value.settings.dnsGraceSeconds = 10;
    const live = reconcileLeases(value, leases, now + 1000, true);
    expect(
      [...iteratePermissionsForLeases(value, live, now + 1000)][0]?.expiresAt,
    ).toBe("2026-10-10T00:00:11.000Z");
    expect(reconcileLeases(value, leases, now + 2000, true)).toEqual([]);
  });
  it("authorizes underscore names and CNAME targets while rejecting malformed labels", () => {
    const dns = rule({
      direction: "outgoing",
      peer: { kind: "domain", value: "s3.example" },
      action: "allow",
      dnsDestinations: ["10.22.242.0/24"],
    });

    const resolution = resolutionSchema.parse({
      clientIp: "10.22.241.10",
      question: "My_Bucket.s3.example.",
      responseAt: timestamp,
      answers: [
        {
          owner: "my_bucket.s3.example",
          type: "CNAME",
          value: "edge_1.cdn.example",
          ttl: 60,
        },
        {
          owner: "edge_1.cdn.example",
          type: "A",
          value: "10.22.242.20",
          ttl: 60,
        },
      ],
    });

    expect(resolution.question).toBe("my_bucket.s3.example");
    expect(grantsFor(policy([dns]), resolution)).toMatchObject([
      {
        ruleId: dns.id,
        address: "10.22.242.20",
        question: "my_bucket.s3.example",
      },
    ]);
    expect(nameSchema.parse("_service.example")).toBe("_service.example");
  });
  it("accepts only ASCII hostname labels and converts internationalized names to IDNA", () => {
    expect(nameSchema.parse(" API.Example.COM. ")).toBe("api.example.com");
    expect(nameSchema.parse("Bücher.example")).toBe("xn--bcher-kva.example");
    // IDNA maps a look-alike to its visible ASCII form instead of keeping it as Unicode.
    expect(nameSchema.parse("рaypal.com")).toBe("xn--aypal-uye.com");

    for (const name of [
      "-edge.example",
      "edge-.example",
      "a..example",
      ".",
      "",
      `${"a".repeat(64)}.example`,
      `${"a.".repeat(127)}example`,
      "*.example.com",
      "https://example.com/path",
      "user@example.com",
      "Office Printer._ipp._tcp.example.com",
      "tab\there.example",
      // A right-to-left override would make a name display as another.
      "moc\u202e.example",
    ])
      expect(nameSchema.safeParse(name).success).toBe(false);
  });
});

describe("native compilation and contracts", () => {
  it("keeps endpoint checks and ordered continuations while DNS transactions avoid static policy replacement", () => {
    const dns = rule({
      instanceId: clientId,
      direction: "outgoing",
      peer: { kind: "hostname", value: "app.example" },
      action: "allow",
      dnsDestinations: ["10.22.242.0/24"],
    });

    const value = policy([dns]);
    value.settings.dnsGraceSeconds = 0;

    const grants = grantsFor(value, {
      clientIp: "10.22.241.10",
      question: "app.example",
      responseAt: timestamp,
      answers: [
        { owner: "app.example", type: "A", value: "10.22.242.20", ttl: 2 },
      ],
    });

    const groups = dnsChains(value, grants, marksFor(value)),
      group = groups[0]!;

    const full = compileNftables(value, grants, {
      marks: marksFor(value),
      tableExists: true,
      dnsPort: 5353,
      infrastructure,
      now,
      policyHash: "a".repeat(64),
    });

    expect(full).toContain(`goto ${group.name}`);
    expect(full).toContain(`goto ${group.next}`);
    expect(full).toContain(`chain ${group.next}`);
    expect(full).toContain("10.22.242.20 : jump i4_");
    const update = compileDnsUpdate(groups, now + 500);
    expect(update).toContain(`flush chain inet traffic_policy ${group.name}`);
    expect(update).toContain("timeout 1500ms");
    expect(update).not.toMatch(
      /delete table|flush table|add table|chain forward|ct reply/,
    );

    const expiry = compileDnsUpdate(
      dnsChains(value, [], marksFor(value)),
      now + 2500,
    );

    expect(expiry).not.toContain("add element");
    expect(expiry).toContain(`goto ${group.next}`);
  });
  it("marks connections a DNS Allow rule admits and keeps them open while the rule is in force", () => {
    const allowed = rule({
      instanceId: clientId,
      direction: "outgoing",
      peer: { kind: "hostname", value: "app.example" },
      protocol: 6,
      portStart: 443,
      portEnd: 443,
      action: "allow",
      expiresAt: "2026-10-11T00:00:00.000Z",
      dnsDestinations: ["10.22.242.0/24"],
    });

    const blocked = rule({
      instanceId: clientId,
      direction: "outgoing",
      peer: { kind: "hostname", value: "ads.example" },
      action: "block",
      dnsDestinations: ["10.22.242.0/24"],
    });

    const value = policy([allowed, blocked]);

    const grants = grantsFor(value, {
      clientIp: "10.22.241.10",
      question: "app.example",
      responseAt: timestamp,
      answers: [
        { owner: "app.example", type: "A", value: "10.22.242.20", ttl: 2 },
      ],
    });

    const marks = new Map([
      [connectionMarkScope(allowed, `4|${clientId}@32`), 7],
    ]);

    const program = compileNftables(value, grants, {
      marks,
      tableExists: false,
      dnsPort: 5353,
      infrastructure,
      now,
      policyHash: "a".repeat(64),
    });

    const instance = chainBody(
      program,
      `o4_${nodeName(value, "10.22.241.10")}`,
    ).split("\n");

    const keepOpen = instance.findIndex((line) =>
      line.includes("ct state established ct mark and 0xffffff == 7"),
    );

    expect(instance[keepOpen]).toContain(
      `meta time < ${Date.parse(allowed.expiresAt!) / 1000} counter return comment "rule:${allowed.id}"`,
    );
    // The open-connection check sits right before the rule's DNS permission check.
    expect(instance[keepOpen + 1]).toContain(
      `@${dnsSetName(`4|${clientId}@32`, allowed.id, 4)}`,
    );

    const [admit, deny] = dnsChains(value, grants, marks);

    expect(admit!.mark).toBe(7);
    expect(deny!.mark).toBeNull();
    expect(compileDnsUpdate([admit!], now)).toContain(
      `ct original ip daddr 10.22.242.20 meta time < ${Date.parse(admit!.bindings[0]!.expiresAt) / 1000} ct mark set ct mark and 0xff000000 or 7 counter return`,
    );
    expect(program).not.toContain("ct mark set ct mark and 0xff000000 or 0");
    expect(connectionMarkScopes(value)).toEqual([
      connectionMarkScope(allowed, `4|${clientId}@32`),
    ]);
    // A new peer or service is a new scope, so it gets a new mark.
    expect(
      connectionMarkScope(
        { ...allowed, portStart: 8443, portEnd: 8443 },
        clientId,
      ),
    ).not.toBe(connectionMarkScope(allowed, clientId));
    expect(
      connectionMarkScope({ ...allowed, reason: "edited" }, clientId),
    ).toBe(connectionMarkScope(allowed, clientId));
    expect(() =>
      compileNftables(value, grants, {
        marks: new Map(),
        tableExists: false,
        dnsPort: 5353,
        infrastructure,
        now,
        policyHash: "a".repeat(64),
      }),
    ).toThrow(`Rule ${allowed.id} has no connection mark`);
  });
  it("bounds DNS lifetimes conservatively and encodes native timestamps in epoch seconds", () => {
    const dns = rule({
      instanceId: clientId,
      direction: "outgoing",
      peer: { kind: "hostname", value: "app.example" },
      action: "allow",
      dnsDestinations: ["10.22.242.0/24"],
    });

    const value = policy([dns]);
    value.settings.dnsGraceSeconds = 0;

    const permissions = grantsFor(value, {
      clientIp: "10.22.241.10",
      question: "app.example",
      responseAt: "2026-10-10T00:00:00.123Z",
      answers: [
        { owner: "app.example", type: "A", value: "10.22.242.20", ttl: 2 },
      ],
    });

    const program = compileNftables(value, permissions, {
      marks: marksFor(value),
      tableExists: true,
      dnsPort: 5353,
      infrastructure,
      now,
      policyHash: "a".repeat(64),
    });

    expect(permissions[0]!.expiresAt).toBe("2026-10-10T00:00:02.000Z");
    expect(program).toContain(
      `meta time < ${Date.parse(permissions[0]!.expiresAt) / 1000}`,
    );
    expect(program).toContain("ct original ip daddr 10.22.242.20");

    const scheduled = rule({
      instanceId: clientId,
      notBefore: "2026-10-10T00:00:01.000Z",
      expiresAt: "2026-10-10T00:00:02.000Z",
    });

    const timed = compileNftables(policy([scheduled]), [], {
      marks: marksFor(policy([scheduled])),
      tableExists: true,
      dnsPort: 5353,
      infrastructure,
      now,
      policyHash: "a".repeat(64),
    });

    expect(timed).toContain(
      `meta time >= ${Date.parse(scheduled.notBefore!) / 1000}`,
    );
    expect(timed).toContain(
      `meta time < ${Date.parse(scheduled.expiresAt!) / 1000}`,
    );
  });
  it("keeps uint64 values lossless and rejects oversized counters", () => {
    expect(uint64Schema.parse("18446744073709551615")).toBe(
      "18446744073709551615",
    );
    expect(uint64Schema.safeParse("18446744073709551616").success).toBe(false);
    expect(uint64Schema.safeParse("01").success).toBe(false);
  });
  it("emits both endpoint checks and confines replacement to its owned table", () => {
    const value = policy([rule({ action: "allow" })]);

    const program = compileNftables(value, [], {
      marks: marksFor(value),
      tableExists: true,
      dnsPort: 5353,
      infrastructure,
      now,
      policyHash: "a".repeat(64),
    });

    const replacements = (tableExists: boolean) =>
      compileNftables(value, [], {
        marks: marksFor(value),
        tableExists,
        dnsPort: 5353,
        infrastructure,
        now,
        policyHash: "a".repeat(64),
      })
        .split("\n")
        .filter((line) => /^(add|delete) table /.test(line));

    expect(replacements(true)).toEqual([
      `add table inet ${GUARD_TABLE}`,
      `delete table inet ${GUARD_TABLE}`,
      `delete table inet ${TABLE}`,
    ]);
    expect(replacements(false)).toEqual([
      `add table inet ${GUARD_TABLE}`,
      `delete table inet ${GUARD_TABLE}`,
    ]);
    expect(program).not.toContain("flush ruleset");
    expect(program).toContain("ct original ip saddr vmap @o4");
    expect(program).toContain("ct reply ip saddr vmap @i4");
    expect(program).not.toContain("ct state established accept");
  });
  it("loads the packaged forwarding guard before networking and removes it with the first policy", () => {
    const packaged = (name: string) =>
      readFileSync(join(process.cwd(), "packaging/linux", name), "utf8");

    const guard = packaged("forward-guard.nft");
    expect(guard).toContain(`table inet ${GUARD_TABLE} {`);
    expect(guard).toContain(
      "type filter hook forward priority -20; policy drop;",
    );

    const unit = packaged("tp-forward-guard.service");
    expect(unit).toContain("Before=network-pre.target");
    // Distribution rulesets flush everything; loading first would lose the guard.
    expect(unit).toMatch(/^After=.*nftables\.service/m);
    expect(unit).toContain("/opt/traffic-policy/app/forward-guard.mjs");
    expect(unit).not.toContain("ExecCondition=");
    expect(packaged("90-traffic-policy.conf")).not.toMatch(
      /^net\.(ipv4\.ip_forward|ipv6\.conf\.all\.forwarding)=1$/m,
    );
    expect(packaged("tp-enforcement.service")).toMatch(
      /^After=.*tp-forward-guard\.service/m,
    );
    expect(packaged("tp-enforcement.service")).toContain(
      "RuntimeDirectoryPreserve=yes",
    );
  });
});
