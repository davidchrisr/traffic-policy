import { describe, expect, it } from "vitest";
import {
  ScopeTree,
  canonicalAddress,
  policySchema,
  ruleSchema,
  type Policy,
  type Rule,
} from "@traffic-policy/contracts";
import { DnsRuleIndex } from "./dns-rules.ts";
import {
  InstanceOwners,
  overriddenBy,
  ruleMatches,
  scopeTree,
  subjectContext,
  subjectPath,
} from "./index.ts";
import {
  addressLeases,
  iteratePermissionsForLeases,
  reconcileLeases,
} from "./leases.ts";
import {
  compileNftables,
  connectionMarkScopes,
  dnsChains,
  nodeRules,
  policyNodes,
} from "./nftables.ts";

const bridge = "11111111-1111-4111-8111-111111111111";

const runner = "22222222-2222-4222-8222-222222222222";

const timestamp = "2026-11-03T00:00:00.000Z";

const now = Date.parse(timestamp);

let sequence = 0;

function rule(partial: Partial<Rule> = {}): Rule {
  return ruleSchema.parse({
    id: `00000000-0000-4000-8000-${String(++sequence).padStart(12, "0")}`,
    subject: { kind: "global" },
    direction: "outgoing",
    peer: { kind: "any" },
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
    dnsDestinations: null,
    createdAt: timestamp,
    modifiedAt: timestamp,
    reason: "",
    ...partial,
  });
}

const catchAll = () => rule({ direction: "both", action: "block" });

// The most specific scope of a `ScopeTree.pathKey`.
const leafOf = (path: string) =>
  path.slice(path.lastIndexOf("|") + 1, path.lastIndexOf("@"));

// example-network covers a /24; build-runner is a nested /26 inside it.
function policy(rules: Rule[], instances?: Policy["instances"]): Policy {
  return policySchema.parse({
    protocolVersion: 1,
    revision: "7",
    generatedAt: timestamp,
    instances: instances ?? [
      { id: bridge, name: "example-network", addresses: ["10.10.0.0/24"] },
      { id: runner, name: "build-runner", addresses: ["10.10.0.64/26"] },
    ],
    rules: [...rules, catchAll()],
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

const options = (value: Policy) => ({
  marks: new Map(
    connectionMarkScopes(value).map((scope, index) => [scope, index + 1]),
  ),
  tableExists: false,
  dnsPort: 5353,
  now,
  policyHash: "a".repeat(64),
  infrastructure: {
    upstreamInterfaces: ["wan0", "wg0"],
    controllerAddresses: ["192.0.2.9", "2001:db8::9"],
    machinePort: 9443,
    controllerPort: 9445,
    upstreamDns: { address: "192.0.2.53", port: 53 },
  },
});

function chainBody(program: string, name: string): string {
  const start = program.indexOf(`  chain ${name} {\n`);
  expect(start).toBeGreaterThanOrEqual(0);

  return program.slice(start, program.indexOf("\n  }", start));
}

describe("subnet instances and address rules", () => {
  it("normalizes host networks to addresses and validates where address rules sit", () => {
    expect(canonicalAddress("10.10.0.5/32")).toBe("10.10.0.5");
    expect(canonicalAddress("10.10.0.77/26")).toBe("10.10.0.64/26");
    expect(canonicalAddress("2001:db8::1/128")).toBe("2001:db8::1");

    const valid = policy([
      rule({ subject: { kind: "address", value: "10.10.0.70" } }),
    ]);

    expect(valid.rules[0]!.subject).toEqual({
      kind: "address",
      value: "10.10.0.70",
    });

    const problems = (subject: Rule["subject"]) =>
      policySchema
        .safeParse({ ...valid, rules: [rule({ subject }), catchAll()] })
        .error?.issues.map((issue) => issue.message);

    expect(problems({ kind: "address", value: "10.20.0.0/24" })).toEqual([
      "Address rule 10.20.0.0/24 is outside every instance",
    ]);
    expect(problems({ kind: "address", value: "10.10.0.64/26" })).toEqual([
      "Address rule 10.10.0.64/26 names an instance address; use the instance",
    ]);
  });

  it("finds the most specific scope and treats addresses outside every instance as unregistered", () => {
    const tree = scopeTree(
      policy([rule({ subject: { kind: "address", value: "10.10.0.70" } })]),
    );

    expect(tree.find("10.10.0.70")?.scope).toBe("10.10.0.70");
    expect(tree.find("10.10.0.71")?.scope).toBe(runner);
    expect(tree.find("10.10.0.200")?.scope).toBe(bridge);
    expect(tree.find("10.10.1.1")).toBeNull();
    expect(
      ScopeTree.path(tree.find("10.10.0.70")!).map((entry) => entry.scope),
    ).toEqual([bridge, runner, "10.10.0.70"]);
    const owners = new InstanceOwners(policy([]).instances);

    expect(owners.find("10.10.0.70")?.id).toBe(runner);
    expect(owners.find("10.10.0.200")?.id).toBe(bridge);
    expect(owners.find("10.10.1.1")).toBeUndefined();
    expect(subjectContext(tree, "10.10.0.70")).toMatchObject({
      path: `4|${bridge}@24|${runner}@26|10.10.0.70@32`,
      instanceId: runner,
      ranks: new Map([
        [bridge, 25],
        [runner, 27],
        ["10.10.0.70", 33],
      ]),
    });

    // Labels name a scope; its place among the containing scopes is shown separately.
    const { instances } = policy([]);

    expect(
      subjectPath({ kind: "address", value: "10.10.0.70" }, tree, instances),
    ).toBe("example-network › build-runner › 10.10.0.70");
    expect(
      subjectPath({ kind: "instance", instanceId: runner }, tree, instances),
    ).toBe("example-network › build-runner");
    expect(
      subjectPath({ kind: "instance", instanceId: bridge }, tree, instances),
    ).toBeNull();
    expect(subjectPath({ kind: "global" }, tree, instances)).toBeNull();
  });

  it("inherits containing scopes' rules and lets a deeper scope win only an otherwise equal tie", () => {
    const parentPortBlock = rule({
      subject: { kind: "instance", instanceId: bridge },
      action: "block",
      protocol: 6,
      portStart: 22,
      portEnd: 22,
    });

    const parentBlock = rule({
      subject: { kind: "instance", instanceId: bridge },
      action: "block",
    });

    const childAllow = rule({
      subject: { kind: "instance", instanceId: runner },
    });

    const value = policy([parentPortBlock, parentBlock, childAllow]);
    const { nodes } = policyNodes(scopeTree(value));
    const child = nodes.find((node) => leafOf(node.path) === runner)!;
    const parent = nodes.find((node) => leafOf(node.path) === bridge)!;

    // The port makes the parent's Block more specific; the child's Allow beats the parent's
    // equally broad Block.
    expect(nodeRules(value, child, "outgoing").slice(0, 3)).toEqual([
      parentPortBlock,
      childAllow,
      parentBlock,
    ]);
    expect(nodeRules(value, parent, "outgoing")).not.toContain(childAllow);

    const instances = value.instances;

    expect(overriddenBy(childAllow, value.rules, instances, now)).toBeNull();
    expect(
      overriddenBy(
        rule({
          subject: { kind: "instance", instanceId: runner },
          protocol: 6,
          portStart: 22,
          portEnd: 22,
        }),
        [{ ...parentPortBlock, priority: "high" }],
        instances,
        now,
      )?.rule.id,
    ).toBe(parentPortBlock.id);
  });

  it("dispatches disjoint ranges to node chains and drops unregistered traffic by interface", () => {
    const value = policy(
      [],
      [
        {
          id: bridge,
          name: "example-network",
          addresses: ["10.10.0.0/24", "fd10::/64"],
        },
        { id: runner, name: "build-runner", addresses: ["10.10.0.64/26"] },
      ],
    );

    const program = compileNftables(value, [], options(value));
    const { nodes } = policyNodes(scopeTree(value));

    const name = (leaf: string, family: 4 | 6) =>
      nodes.find(
        (node) => leafOf(node.path) === leaf && node.family === family,
      )!.name;

    expect(program).toContain(
      `elements = { 10.10.0.0-10.10.0.63 : jump o4_${name(bridge, 4)}, 10.10.0.128-10.10.0.255 : jump o4_${name(bridge, 4)}, 10.10.0.64-10.10.0.127 : jump o4_${name(runner, 4)} }`,
    );
    expect(program).toContain(
      `fd10::-fd10::ffff:ffff:ffff:ffff : jump i6_${name(bridge, 6)}`,
    );
    expect(program).toContain("elements = { 10.10.0.0/24 }");

    const forward = chainBody(program, "forward");

    expect(forward).toContain(
      'meta nfproto ipv4 ct original ip saddr != @owned4 ct reply ip saddr != @owned4 iifname { "wan0", "wg0" } jump u_u',
    );
    expect(forward.indexOf("jump u_u")).toBeGreaterThan(
      forward.indexOf("vmap @i6"),
    );
    expect(forward.indexOf("jump u_c")).toBeGreaterThan(
      forward.indexOf("jump u_u"),
    );
    expect(chainBody(program, "u_c")).toContain(
      'counter name "k_u_c" drop comment "unregistered"',
    );
    expect(chainBody(program, "trace_ingress")).toContain(
      "ip saddr 10.10.0.0/24 limit rate",
    );
  });

  it("keeps the gateway reachable for link configuration and the controller, then drops unregistered sources before the DNS gate", () => {
    const value = policy([]);
    const program = compileNftables(value, [], options(value));
    const input = chainBody(program, "input");

    const order = [
      'iifname "lo" counter accept',
      "udp sport 68 udp dport 67 counter accept",
      "icmpv6 type { 130, 131, 132, 133, 135, 136, 143 } counter accept",
      'iifname { "wan0", "wg0" } icmpv6 type 134 counter accept',
      "icmpv6 type { 134, 137 } counter drop",
      'ct original ip saddr { 192.0.2.9 } ct protocol 6 ct original proto-dst 9443 counter accept comment "controller"',
      "ct direction reply ct original ip daddr 192.0.2.53 ct protocol { 6, 17 } ct original proto-dst 53 counter accept",
      'ct original ip6 daddr { 2001:db8::9 } ct protocol 6 ct original proto-dst 9445 counter accept comment "controller"',
      "ct direction original ct original ip saddr != @owned4 iifname",
      'th dport 5353 counter accept comment "gateway-dns"',
      "meta nfproto ipv4 ct direction original ct original ip saddr vmap @o4",
      "meta nfproto ipv4 ct direction reply ct reply ip saddr vmap @i4",
    ].map((line) => input.indexOf(line));

    expect(order).not.toContain(-1);
    expect([...order].sort((a, b) => a - b)).toEqual(order);

    // The gateway is one end in input and output, so only the other end is dispatched.
    const output = chainBody(program, "output");

    expect(output).toContain(
      "meta nfproto ipv4 ct direction reply ct original ip saddr vmap @o4",
    );
    expect(output).toContain(
      "meta nfproto ipv4 ct direction original ct reply ip saddr vmap @i4",
    );
    expect(output).not.toContain("jump u_");
    expect(output).toContain(
      "icmpv6 type { 130, 131, 132, 133, 134, 135, 136, 137, 143 } counter accept",
    );
    expect(output).toContain(
      "ct direction original ct original ip daddr 192.0.2.53",
    );
  });

  it("compiles a Gateway peer to the hooks where the gateway is an endpoint, on the port it serves", () => {
    const ssh = rule({
      subject: { kind: "instance", instanceId: bridge },
      direction: "outgoing",
      peer: { kind: "gateway" },
      protocol: 6,
      portStart: 22,
      portEnd: 22,
    });

    const value = policy([ssh]);
    const program = compileNftables(value, [], options(value));
    const { nodes } = policyNodes(scopeTree(value));

    const chain = chainBody(
      program,
      `o4_${nodes.find((node) => leafOf(node.path) === bridge && node.family === 4)!.name}`,
    );

    expect(chain).toContain(
      `ct direction original fib daddr type local ct protocol 6 ct reply proto-src 22 counter return comment "rule:${ssh.id}"`,
    );
    expect(chain).toContain(
      `ct direction reply fib saddr type local ct protocol 6 ct reply proto-src 22 counter return comment "rule:${ssh.id}"`,
    );

    // Gateway lines are reachable from forward too, so packets forged from a gateway address are
    // dropped there before dispatch.
    const forward = chainBody(program, "forward");
    const drop = 'fib saddr type local counter drop comment "local-source"';

    expect(forward).toContain(drop);
    expect(forward.indexOf(drop)).toBeLessThan(forward.indexOf("vmap @o4"));

    const context = subjectContext(scopeTree(value), "10.10.0.5")!;

    const flow = {
      initiatorIp: "10.10.0.5",
      responderIp: "10.10.0.1",
      originalDestinationIp: "10.10.0.1",
      protocol: 6,
      originalServicePort: 22,
      responderServicePort: 22,
      icmpType: null,
      icmpCode: null,
    };

    expect(ruleMatches(ssh, context, "outgoing", flow, [], now, true)).toBe(
      true,
    );
    expect(ruleMatches(ssh, context, "outgoing", flow, [], now)).toBe(false);
  });

  it("decides DNS for an address rule's client only and keeps permissions in the client's most specific scope", () => {
    const address = rule({
      subject: { kind: "address", value: "10.10.0.70" },
      peer: { kind: "hostname", value: "api.example.com" },
    });

    const parent = rule({
      subject: { kind: "instance", instanceId: bridge },
      peer: { kind: "hostname", value: "cdn.example.com" },
    });

    const global = rule({
      peer: { kind: "hostname", value: "cdn.example.com" },
    });

    const value = policy([address, parent, global]);
    const index = new DnsRuleIndex(value);

    expect(
      index.decide(index.context("10.10.0.70")!, "api.example.com", now),
    ).toMatchObject({ allowed: true, ruleId: address.id });
    expect(
      index.decide(index.context("10.10.0.71")!, "api.example.com", now)
        .allowed,
    ).toBe(false);

    const permissions = [
      ...iteratePermissionsForLeases(
        value,
        addressLeases(
          value,
          {
            clientIp: "10.10.0.70",
            question: "cdn.example.com",
            responseAt: timestamp,
            answers: [
              {
                owner: "cdn.example.com",
                type: "A",
                value: "93.184.216.34",
                ttl: 60,
              },
            ],
          },
          index,
        ),
        now,
        index,
      ),
    ];

    const path = `4|${bridge}@24|${runner}@26|10.10.0.70@32`;

    expect(
      permissions.map((permission) => [permission.ruleId, permission.path]),
    ).toEqual([
      [parent.id, path],
      [global.id, path],
    ]);
  });

  it("keeps a sibling's lookups through a containing instance's Allow from opening a nested Block's host", () => {
    const allow = rule({
      subject: { kind: "instance", instanceId: bridge },
      peer: { kind: "hostname", value: "api.example.com" },
    });

    const block = rule({
      subject: { kind: "address", value: "10.10.0.70" },
      peer: { kind: "hostname", value: "api.example.com" },
      action: "block",
    });

    const value = policy([allow, block]);
    const index = new DnsRuleIndex(value);

    // A sibling elsewhere in the bridge resolves the name the nested host may not use.
    const permissions = [
      ...iteratePermissionsForLeases(
        value,
        addressLeases(
          value,
          {
            clientIp: "10.10.0.200",
            question: "api.example.com",
            responseAt: timestamp,
            answers: [
              {
                owner: "api.example.com",
                type: "A",
                value: "93.184.216.34",
                ttl: 60,
              },
            ],
          },
          index,
        ),
        now,
        index,
      ),
    ];

    const bindings = (path: string) =>
      dnsChains(value, permissions, options(value).marks).find(
        (chain) =>
          chain.path === path &&
          chain.ruleId === allow.id &&
          chain.family === 4,
      )!.bindings;

    expect(
      bindings(`4|${bridge}@24`).map((binding) => binding.address),
    ).toEqual(["93.184.216.34"]);
    expect(bindings(`4|${bridge}@24|${runner}@26|10.10.0.70@32`)).toEqual([]);
  });

  it("keeps an instance's lookups on one path from opening addresses on a path with other inherited rules", () => {
    const group = "33333333-3333-4333-8333-333333333333";

    const allow = rule({
      peer: { kind: "hostname", value: "api.example.com" },
    });

    const block = rule({
      subject: { kind: "instance", instanceId: bridge },
      peer: { kind: "hostname", value: "api.example.com" },
      action: "block",
    });

    // One instance with an address inside the bridge and another outside every other instance.
    const value = policy(
      [allow, block],
      [
        { id: bridge, name: "example-network", addresses: ["10.10.0.0/24"] },
        { id: group, name: "group", addresses: ["10.10.0.10", "10.20.0.10"] },
      ],
    );

    const index = new DnsRuleIndex(value);
    const inside = index.context("10.10.0.10")!;
    const outside = index.context("10.20.0.10")!;

    expect(inside.instanceId).toBe(group);
    expect(outside.instanceId).toBe(group);
    expect(inside.path).not.toBe(outside.path);
    expect(index.decide(inside, "api.example.com", now).allowed).toBe(false);

    const leases = addressLeases(
      value,
      {
        clientIp: "10.20.0.10",
        question: "api.example.com",
        responseAt: timestamp,
        answers: [
          {
            owner: "api.example.com",
            type: "A",
            value: "93.184.216.34",
            ttl: 60,
          },
        ],
      },
      index,
    );

    const permissions = [
      ...iteratePermissionsForLeases(value, leases, now, index),
    ];

    const bindings = (path: string) =>
      dnsChains(value, permissions, options(value).marks)
        .filter((chain) => chain.path === path && chain.family === 4)
        .flatMap((chain) => chain.bindings);

    expect(bindings(outside.path)).toHaveLength(1);
    expect(bindings(inside.path)).toEqual([]);

    // An address rule above the inside address changes its path, not its most specific scope.
    const split = policy(
      [
        allow,
        block,
        rule({ subject: { kind: "address", value: "10.10.0.0/28" } }),
      ],
      value.instances,
    );

    const insideLease = {
      ...leases[0]!,
      clientIp: "10.10.0.10",
      path: inside.path,
    };

    expect(reconcileLeases(value, [insideLease], now, false)).toHaveLength(1);
    expect(reconcileLeases(split, [insideLease], now, false)).toEqual([]);
  });
  it("binds an answer in the other family on each of the client instance's paths in that family, by the rules there", () => {
    const peer = { kind: "hostname" as const, value: "api.example.com" };

    const host = rule({
      subject: { kind: "address", value: "10.10.0.5" },
      peer,
    });

    const shared = rule({
      subject: { kind: "instance", instanceId: bridge },
      peer,
    });

    const blocked = rule({
      subject: { kind: "address", value: "fd10::5" },
      peer,
      action: "block",
    });

    const ping = rule({ peer, protocol: 1 });

    const value = policy(
      [host, shared, blocked, ping],
      [
        {
          id: bridge,
          name: "example-network",
          addresses: ["10.10.0.0/24", "fd10::/64"],
        },
      ],
    );

    const index = new DnsRuleIndex(value);

    const leases = addressLeases(
      value,
      {
        clientIp: "10.10.0.5",
        question: "api.example.com",
        responseAt: timestamp,
        answers: [
          {
            owner: "api.example.com",
            type: "A",
            value: "93.184.216.34",
            ttl: 60,
          },
          {
            owner: "api.example.com",
            type: "AAAA",
            value: "2606:2800:220:1::1",
            ttl: 60,
          },
        ],
      },
      index,
    );

    const bound = (address: string) =>
      index
        .match(leases.find((lease) => lease.address === address)!)
        .map(({ path, rules }) => [path, rules.map((value) => value.id)]);

    // The client's own family binds on its path only. The other binds on every IPv6 path of the
    // instance where a rule for the name applies: not the IPv4 address rule or the ICMP rule, and
    // the IPv6 address rule's Block keeps its place in that path's order.
    expect(bound("93.184.216.34")).toEqual([
      [`4|${bridge}@24|10.10.0.5@32`, [host.id, shared.id, ping.id]],
    ]);
    expect(bound("2606:2800:220:1::1")).toEqual([
      [`6|${bridge}@64`, [shared.id]],
      [`6|${bridge}@64|fd10::5@128`, [shared.id, blocked.id]],
    ]);

    const permissions = [
      ...iteratePermissionsForLeases(value, leases, now, index),
    ];

    const chains = dnsChains(value, permissions, options(value).marks);

    for (const permission of permissions) {
      expect(permission.leasePath).toBe(`4|${bridge}@24|10.10.0.5@32`);
      expect(
        chains.some(
          (chain) =>
            chain.path === permission.path &&
            chain.ruleId === permission.ruleId &&
            chain.bindings.some(
              (binding) => binding.address === permission.address,
            ),
        ),
      ).toBe(true);
    }
  });
  it("binds an answer in the other family only on paths some address has", () => {
    const peer = { kind: "hostname" as const, value: "api.example.com" };

    // Two address rules cover the instance's IPv6 network, so no address has its own path.
    const value = policy(
      [
        rule({ subject: { kind: "instance", instanceId: bridge }, peer }),
        ...["fd10::/65", "fd10::8000:0:0:0/65"].map((network) =>
          rule({ subject: { kind: "address", value: network } }),
        ),
      ],
      [
        {
          id: bridge,
          name: "example-network",
          addresses: ["10.10.0.0/24", "fd10::/64"],
        },
      ],
    );

    const [lease] = addressLeases(value, {
      clientIp: "10.10.0.5",
      question: "api.example.com",
      responseAt: timestamp,
      answers: [
        {
          owner: "api.example.com",
          type: "AAAA",
          value: "2606:2800:220:1::1",
          ttl: 60,
        },
      ],
    });

    expect(
      new DnsRuleIndex(value).match(lease!).map((binding) => binding.path),
    ).toEqual([
      `6|${bridge}@64|fd10::/65@65`,
      `6|${bridge}@64|fd10::8000:0:0:0/65@65`,
    ]);
  });
  it("keeps a lease on its path when the client that refreshed it moves to another", () => {
    const allow = rule({
      peer: { kind: "hostname", value: "api.example.com" },
    });

    const value = policy([allow]);

    const [lease] = addressLeases(value, {
      clientIp: "10.10.0.6",
      question: "api.example.com",
      responseAt: timestamp,
      answers: [
        {
          owner: "api.example.com",
          type: "A",
          value: "93.184.216.34",
          ttl: 60,
        },
      ],
    });

    // An address rule for the client gives it a path of its own; the bridge's path remains.
    const moved = policy([
      allow,
      rule({ subject: { kind: "address", value: "10.10.0.6" } }),
    ]);

    expect(reconcileLeases(moved, [lease!], now, false)).toEqual([lease]);
    expect(
      new DnsRuleIndex(moved).match(lease!).map((binding) => binding.path),
    ).toEqual([`4|${bridge}@24`]);
  });
});
