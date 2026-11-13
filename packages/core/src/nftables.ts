import ipaddr from "ipaddr.js";
import {
  ScopeTree,
  formatPorts,
  integerAddress,
  subjectScope,
  type Permission,
  type Policy,
  type Rule,
  type ScopeEntry,
} from "@traffic-policy/contracts";
import {
  compareRules,
  contextRank,
  entryContext,
  isCatchAll,
  reconcilePermissions,
  pathScopes,
  scopeTree,
} from "./index.ts";
import { hashDocument } from "./io.server.ts";

export const TABLE = "traffic_policy";

// The boot guard drops forwarding until the first full installation. Removing
// it in that transaction leaves no unfiltered window.
export const GUARD_TABLE = "traffic_policy_guard";

const compact = (identity: string) => identity.replaceAll("-", "");

const quote = (value: string) => JSON.stringify(value);

// A scope path (`ScopeTree.pathKey`) in nftables names.
const pathName = (path: string) => hashDocument(path).slice(0, 16);

export function dnsSetName(
  path: string,
  ruleId: string,
  family: 4 | 6,
): string {
  return `d${family}_${pathName(path)}_${compact(ruleId)}`;
}

// nft accepts epoch seconds and converts them to kernel nanoseconds itself.
function instant(value: string): string {
  return Math.floor(Date.parse(value) / 1000).toString();
}

// A distinct path of scopes in one family. Its chains hold the global rules and the rules of every
// scope on the path, each ranked by how specifically its scope covers the path's addresses.
export interface PolicyNode {
  name: string;
  family: 4 | 6;
  ranks: ReadonlyMap<string, number>;
  // The path's `ScopeTree.pathKey`, which holds the DNS permissions of its addresses.
  path: string;
  // The most specific instance on the path, which block counts and traces report.
  instanceId: string;
}

export interface NodeRange {
  family: 4 | 6;
  start: bigint;
  end: bigint;
  node: PolicyNode;
}

export interface PolicyNodes {
  nodes: PolicyNode[];
  // Disjoint address ranges: each entry minus its children, owned by the entry's node.
  ranges: NodeRange[];
  // Entries with no parent; together they cover every address an instance covers.
  roots: ScopeEntry[];
}

export function policyNodes(tree: ScopeTree): PolicyNodes {
  const nodes = new Map<string, PolicyNode>();
  const owners = new Map<ScopeEntry, PolicyNode>();

  for (const entry of tree.entries) {
    const key = ScopeTree.pathKey(entry);
    let node = nodes.get(key);

    if (!node) {
      const { ranks, instanceId } = entryContext(entry, key);

      node = {
        name: pathName(key),
        family: entry.family,
        ranks,
        path: key,
        instanceId,
      };
      nodes.set(key, node);
    }

    owners.set(entry, node);
  }

  const ranges: NodeRange[] = [];

  for (const entry of tree.entries) {
    const node = owners.get(entry)!;
    let next = entry.start;

    for (const child of entry.children) {
      if (child.start > next)
        ranges.push({
          family: entry.family,
          start: next,
          end: child.start - 1n,
          node,
        });
      next = child.end + 1n;
    }

    if (next <= entry.end)
      ranges.push({ family: entry.family, start: next, end: entry.end, node });
  }

  return {
    nodes: [...nodes.values()],
    ranges,
    roots: tree.entries.filter((entry) => !entry.parent),
  };
}

const applies = (
  rule: Rule,
  node: PolicyNode,
  direction: "outgoing" | "incoming",
) =>
  rule.enabled &&
  contextRank(rule, node) !== null &&
  (rule.direction === "both" || rule.direction === direction);

// The rules of a node's chain for one direction, in precedence order.
export function nodeRules(
  policy: Policy,
  node: PolicyNode,
  direction: "outgoing" | "incoming",
): Rule[] {
  const rank = (rule: Rule) => contextRank(rule, node) ?? 0;

  return policy.rules
    .filter((rule) => applies(rule, node, direction))
    .sort((left, right) => compareRules(left, right, rank));
}

export function blockTraceChain(
  rule: Rule,
  instanceId: string,
  direction: "outgoing" | "incoming",
  family: 4 | 6,
  revision: string,
): string {
  return `b${family}_${direction[0]}_${compact(instanceId)}_${compact(rule.id)}_${revision}_${isCatchAll(rule) ? "c" : "t"}`;
}

// Connection marks use the low 24 bits of the conntrack mark; the high 8 bits stay with other tools.
export const CONNECTION_MARK_MASK = 0xffffff;

// Endpoint wrappers restore this borrowed packet bit before an allowed packet returns to its hook.
const DNS_ADMISSION_FLAG = 0x80000000;

// The connection mark of each DNS Allow rule for each path holding its permissions, keyed by
// connectionMarkScope.
export type MarkAssignments = ReadonlyMap<string, number>;

// What a DNS Allow rule admits for one path. Editing the rule's peer or service gives it a new
// key, and so a new mark, so connections admitted before the edit stop matching it.
export function connectionMarkScope(rule: Rule, path: string): string {
  return `${pathName(path)}:${rule.id}:${hashDocument({
    peer: rule.peer,
    dnsDestinations: rule.dnsDestinations,
    protocol: rule.protocol,
    ports: rule.ports,
    icmpType: rule.icmpType,
    icmpCode: rule.icmpCode,
  })}`;
}

const keepsConnections = (rule: Rule) =>
  rule.enabled &&
  rule.action === "allow" &&
  (rule.peer.kind === "hostname" || rule.peer.kind === "domain");

// Every DNS Allow rule paired with each path holding its permissions: every path through its
// subject, or every path for a global rule.
export function connectionMarkScopes(policy: Policy): string[] {
  const paths = [...pathScopes(scopeTree(policy))];

  return policy.rules.filter(keepsConnections).flatMap((rule) => {
    const subject = subjectScope(rule.subject);

    return paths.flatMap(([path, scopes]) =>
      subject === null || scopes.has(subject)
        ? [connectionMarkScope(rule, path)]
        : [],
    );
  });
}

function connectionMark(
  marks: MarkAssignments,
  rule: Rule,
  path: string,
): number | null {
  if (!keepsConnections(rule)) return null;
  const mark = marks.get(connectionMarkScope(rule, path));

  if (mark === undefined)
    throw new Error(`Rule ${rule.id} has no connection mark`);

  return mark;
}

// An open connection that a DNS Allow rule admitted keeps that rule's mark, so it stays allowed
// after the DNS permission expires, while the rule is in force and wins.
function keepOpenExpression(rule: Rule, mark: number): string {
  return [
    "ct state established",
    `ct mark and 0x${CONNECTION_MARK_MASK.toString(16)} == ${mark}`,
    ...(rule.notBefore ? [`meta time >= ${instant(rule.notBefore)}`] : []),
    ...(rule.expiresAt ? [`meta time < ${instant(rule.expiresAt)}`] : []),
    `counter return comment ${quote(`rule:${rule.id}`)}`,
  ].join(" ");
}

const uuid = (value: string) =>
  `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;

// The named counter of a Block rule's drops for one instance and direction. IPv4 and IPv6 trace
// chains share it, and the name leaves out the revision, so it only identifies the rule.
export function blockCounterName(
  rule: Rule,
  instanceId: string,
  direction: "outgoing" | "incoming",
): string {
  return `k_${direction[0]}_${compact(instanceId)}_${compact(rule.id)}`;
}

// Reads the rule, instance, and direction back from a blockCounterName.
export function parseBlockCounter(name: string) {
  const match = name.match(/^k_([oi])_([a-f0-9]{32})_([a-f0-9]{32})$/);

  if (!match) return null;

  return {
    direction: match[1] === "o" ? ("outgoing" as const) : ("incoming" as const),
    instanceId: uuid(match[2]!),
    ruleId: uuid(match[3]!),
  };
}

// Drops of connections with no instance on either end, split by whether the packet arrived on a
// client interface.
export const UNREGISTERED_COUNTERS = {
  client: "k_u_c",
  upstream: "k_u_u",
} as const;

// Reads which side an unregistered drop counter counts.
export function parseUnregisteredCounter(
  name: string,
): "client" | "upstream" | null {
  return name === UNREGISTERED_COUNTERS.client
    ? "client"
    : name === UNREGISTERED_COUNTERS.upstream
      ? "upstream"
      : null;
}

// The rule's statements in a node chain, or null when it cannot apply in the node's family.
function ruleExpression(
  rule: Rule,
  node: PolicyNode,
  direction: "outgoing" | "incoming",
  revision: string,
  permission?: { address: string; expiresAt: string },
  verdict?: string,
): string[] | null {
  const family = node.family;
  const ip = family === 4 ? "ip" : "ip6";

  const peer =
    direction === "outgoing"
      ? `ct original ${ip} daddr`
      : `ct original ${ip} saddr`;

  // A service the gateway provides is the port it serves, after any redirect to it.
  const port =
    direction === "outgoing" && rule.peer.kind !== "gateway"
      ? "ct original proto-dst"
      : "ct reply proto-src";

  const expression: string[] = [];

  if (
    (rule.protocol === 1 && family === 6) ||
    (rule.protocol === 58 && family === 4)
  )
    return null;

  if (rule.peer.kind === "ip" || rule.peer.kind === "cidr") {
    const address = rule.peer.value.split("/")[0]!;

    if (ipaddr.process(address).kind() !== (family === 4 ? "ipv4" : "ipv6"))
      return null;
    expression.push(`${peer} ${rule.peer.value}`);
  } else if (rule.peer.kind === "hostname" || rule.peer.kind === "domain") {
    expression.push(`${peer} @${dnsSetName(node.path, rule.id, family)}`);

    if (permission)
      expression.push(
        `${peer} ${permission.address}`,
        `meta time < ${instant(permission.expiresAt)}`,
      );
  }

  if (rule.protocol !== null) expression.push(`ct protocol ${rule.protocol}`);
  else if (rule.ports !== null) expression.push("ct protocol { 6, 17 }");

  if (rule.ports !== null) {
    const ports = formatPorts(rule.ports);

    expression.push(
      `${port} ${rule.ports.length === 1 ? ports : `{ ${ports} }`}`,
    );
  }

  if (rule.icmpType !== null)
    expression.push(`ct original proto-dst & 0xff00 ${rule.icmpType * 256}`);

  if (rule.icmpCode !== null)
    expression.push(`ct original proto-dst & 0x00ff ${rule.icmpCode}`);

  if (rule.notBefore)
    expression.push(`meta time >= ${instant(rule.notBefore)}`);

  if (rule.expiresAt) expression.push(`meta time < ${instant(rule.expiresAt)}`);
  expression.push(
    `counter ${verdict ?? (rule.action === "allow" ? "return" : `jump ${blockTraceChain(rule, node.instanceId, direction, family, revision)}`)} comment ${quote(`rule:${rule.id}`)}`,
  );

  const body = expression.join(" ");

  if (rule.peer.kind !== "gateway") return [body];

  // The gateway is an endpoint only in input and output, where the kernel knows it as a local
  // address: the destination of a connection's original packets toward it and the source of their
  // replies, or the reverse for connections it starts.
  const [original, reply] =
    direction === "outgoing" ? ["daddr", "saddr"] : ["saddr", "daddr"];

  return [
    `ct direction original fib ${original} type local ${body}`,
    `ct direction reply fib ${reply} type local ${body}`,
  ];
}

export interface DnsChain {
  // The scope path holding the permissions this chain binds.
  path: string;
  name: string;
  set: string;
  family: 4 | 6;
  ruleId: string;
  verdict: string;
  // Set on the connections a live permission admits; null for a Block rule.
  mark: number | null;
  bindings: { address: string; expiresAt: string }[];
}

const familyOf = (address: string) =>
  ipaddr.process(address).kind() === "ipv4" ? 4 : 6;

export function dnsChains(
  policy: Policy,
  permissions: Permission[],
  marks: MarkAssignments,
  nodes = policyNodes(scopeTree(policy)).nodes,
): DnsChain[] {
  // The latest deadline of each address, by holding path, rule, and family.
  const deadlines = new Map<string, Map<string, string>>();

  for (const permission of permissions) {
    const key = `${permission.path}|${permission.ruleId}|${familyOf(permission.address)}`;
    let addresses = deadlines.get(key);

    if (!addresses) {
      addresses = new Map();
      deadlines.set(key, addresses);
    }

    if (
      Date.parse(permission.expiresAt) >
      Date.parse(addresses.get(permission.address) ?? "1970-01-01")
    )
      addresses.set(permission.address, permission.expiresAt);
  }

  const result: DnsChain[] = [];

  for (const node of nodes)
    for (const rule of policy.rules) {
      if (rule.peer.kind !== "hostname" && rule.peer.kind !== "domain")
        continue;

      for (const direction of ["outgoing", "incoming"] as const) {
        if (
          !applies(rule, node, direction) ||
          !ruleExpression(rule, node, direction, policy.revision)
        )
          continue;
        const { path } = node;
        const identity = `${node.family}_${direction[0]}_${node.name}_${compact(rule.id)}`;

        result.push({
          path,
          name: `l${identity}`,
          set: dnsSetName(path, rule.id, node.family),
          family: node.family,
          ruleId: rule.id,
          verdict:
            rule.action === "allow"
              ? `meta mark set meta mark or 0x${DNS_ADMISSION_FLAG.toString(16)} return`
              : `jump ${blockTraceChain(rule, node.instanceId, direction, node.family, policy.revision)}`,
          mark: connectionMark(marks, rule, path),
          bindings: [
            ...(deadlines.get(`${path}|${rule.id}|${node.family}`) ?? []),
          ]
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([address, expiresAt]) => ({ address, expiresAt })),
        });
      }
    }

  return result;
}

export function dnsChainRules(chain: DnsChain): string[] {
  return chain.bindings.map(
    (binding) =>
      `ct original ${chain.family === 4 ? "ip" : "ip6"} daddr ${binding.address} meta time < ${instant(binding.expiresAt)}${chain.mark === null ? "" : ` ct mark set ct mark and 0x${(~CONNECTION_MARK_MASK >>> 0).toString(16)} or ${chain.mark}`} counter ${chain.verdict} comment ${quote(`rule:${chain.ruleId}`)}`,
  );
}

// One native transaction replaces only the changed DNS chains and their sets. Chains of one rule
// in several nodes share a set, which is refilled once.
export function compileDnsUpdate(chains: DnsChain[], now: number): string {
  const lines: string[] = [];
  const sets = new Set<string>();

  for (const chain of chains) {
    lines.push(`flush chain inet ${TABLE} ${chain.name}`);

    if (!sets.has(chain.set)) {
      sets.add(chain.set);
      lines.push(`flush set inet ${TABLE} ${chain.set}`);

      const live = chain.bindings.filter(
        (binding) => Date.parse(binding.expiresAt) > now,
      );

      if (live.length)
        lines.push(
          `add element inet ${TABLE} ${chain.set} { ${live
            .map(
              (binding) =>
                `${binding.address} timeout ${Math.max(1, Date.parse(binding.expiresAt) - now)}ms`,
            )
            .join(", ")} }`,
        );
    }

    for (const rule of dnsChainRules(chain))
      lines.push(`add rule inet ${TABLE} ${chain.name} ${rule}`);
  }

  return lines.length ? `${lines.join("\n")}\n` : "";
}

// Gateway endpoints that policy never filters, so the gateway stays reachable and configurable.
export interface Infrastructure {
  // Interfaces facing upstream networks; unregistered drops arriving on any other interface are
  // reported for registration.
  upstreamInterfaces: readonly string[];
  // The controller, which must always reach the gateway to repair its policy, over the machine
  // link only: its connections to the gateway's machine port and the gateway's to its own.
  controllerAddresses: readonly string[];
  machinePort: number;
  controllerPort: number;
  upstreamDns: { address: string; port: number };
}

// Link and address configuration for the gateway as router and DHCP server, and as a DHCP client
// upstream: clients send these from 0.0.0.0 or link-local addresses, which no instance covers.
const DHCP = [
  'udp sport 68 udp dport 67 counter accept comment "dhcp"',
  'udp sport 67 udp dport 68 counter accept comment "dhcp"',
  'udp sport 546 udp dport 547 counter accept comment "dhcpv6"',
  'udp sport 547 udp dport 546 counter accept comment "dhcpv6"',
];

const range = (value: NodeRange) =>
  value.start === value.end
    ? integerAddress(value.family, value.start)
    : `${integerAddress(value.family, value.start)}-${integerAddress(value.family, value.end)}`;

export function compileNftables(
  policy: Policy,
  livePermissions: Permission[],
  options: {
    tableExists: boolean;
    dnsPort: number;
    now?: number;
    policyHash: string;
    existingPermissionCount?: number;
    marks: MarkAssignments;
    infrastructure: Infrastructure;
  },
): string {
  const now = options.now ?? Date.now();
  const permissions = reconcilePermissions(policy, livePermissions, now);
  const { nodes, ranges, roots } = policyNodes(scopeTree(policy));
  const dynamic = dnsChains(policy, permissions, options.marks, nodes);
  const groups = new Map<string, DnsChain>();

  for (const value of dynamic)
    if (!groups.has(value.name)) groups.set(value.name, value);

  const {
    upstreamInterfaces,
    controllerAddresses,
    machinePort,
    controllerPort,
    upstreamDns,
  } = options.infrastructure;

  const uniquePermissions = new Set(
    permissions.map(
      (permission) =>
        `${permission.path}|${permission.ruleId}|${permission.address}`,
    ),
  ).size;

  const effectiveLimit = Math.max(
    policy.settings.permissionLimit,
    options.existingPermissionCount ?? 0,
  );

  if (uniquePermissions > effectiveLimit)
    throw new Error("Live permission limit exhausted");

  // Adding before deleting makes guard removal valid whether or not it exists.
  const lines: string[] = [
    `add table inet ${GUARD_TABLE}`,
    `delete table inet ${GUARD_TABLE}`,
    ...(options.tableExists ? [`delete table inet ${TABLE}`] : []),
  ];

  lines.push(
    `table inet ${TABLE} {`,
    `  comment ${quote(`revision:${policy.revision};hash:${options.policyHash}`)}`,
  );

  const counters = new Set<string>(Object.values(UNREGISTERED_COUNTERS));
  const traces = new Set<string>();
  const sets = new Set<string>();

  for (const chain of dynamic) {
    if (sets.has(chain.set)) continue;
    sets.add(chain.set);

    const elements = chain.bindings.map(
      (binding) =>
        `${binding.address} timeout ${Math.max(1, Date.parse(binding.expiresAt) - now)}ms`,
    );

    lines.push(
      `  set ${chain.set} {`,
      `    type ipv${chain.family}_addr`,
      "    flags timeout",
      `    size ${effectiveLimit}`,
      ...(elements.length ? [`    elements = { ${elements.join(", ")} }`] : []),
      "  }",
    );
  }

  for (const family of [4, 6] as const) {
    const owned = roots
      .filter((entry) => entry.family === family)
      .map((entry) => entry.network);

    lines.push(
      `  set owned${family} {`,
      `    type ipv${family}_addr`,
      "    flags interval",
      ...(owned.length ? [`    elements = { ${owned.join(", ")} }`] : []),
      "  }",
    );

    for (const direction of ["outgoing", "incoming"] as const) {
      const elements = ranges
        .filter((value) => value.family === family)
        .map(
          (value) =>
            `${range(value)} : jump ${direction[0]}${family}_${value.node.name}`,
        );

      lines.push(
        `  map ${direction[0]}${family} {`,
        `    type ipv${family}_addr : verdict`,
        "    flags interval",
        ...(elements.length
          ? [`    elements = { ${elements.join(", ")} }`]
          : []),
        "  }",
      );
    }
  }

  for (const node of nodes)
    for (const direction of ["outgoing", "incoming"] as const) {
      const name = `${direction[0]}${node.family}_${node.name}`;
      const rules = nodeRules(policy, node, direction);

      if (direction === "outgoing" && rules.some(keepsConnections))
        lines.push(
          `  chain ${name} {`,
          `    meta mark and 0x${DNS_ADMISSION_FLAG.toString(16)} != 0 goto m_${name}`,
          `    goto u_${name}`,
          "  }",
          `  chain m_${name} {`,
          `    meta mark set meta mark and 0x${(~DNS_ADMISSION_FLAG >>> 0).toString(16)}`,
          `    jump r_${name}`,
          `    meta mark set meta mark or 0x${DNS_ADMISSION_FLAG.toString(16)}`,
          "    return",
          "  }",
          `  chain u_${name} {`,
          `    jump r_${name}`,
          `    meta mark set meta mark and 0x${(~DNS_ADMISSION_FLAG >>> 0).toString(16)}`,
          "    return",
          "  }",
          `  chain r_${name} {`,
        );
      else lines.push(`  chain ${name} {`);

      for (const rule of rules) {
        if (rule.peer.kind === "hostname" || rule.peer.kind === "domain") {
          const group = groups.get(
            `l${node.family}_${direction[0]}_${node.name}_${compact(rule.id)}`,
          );

          if (!group) continue;

          if (group.mark !== null)
            lines.push(`    ${keepOpenExpression(rule, group.mark)}`);

          const expression = ruleExpression(
            rule,
            node,
            direction,
            policy.revision,
            undefined,
            `jump ${group.name}`,
          );

          if (expression)
            lines.push(...expression.map((value) => `    ${value}`));

          if (group.mark !== null)
            lines.push(
              `    meta mark and 0x${DNS_ADMISSION_FLAG.toString(16)} != 0 counter return comment ${quote(`rule:${rule.id}`)}`,
            );
          continue;
        }

        const expression = ruleExpression(
          rule,
          node,
          direction,
          policy.revision,
        );

        if (expression)
          lines.push(...expression.map((value) => `    ${value}`));
      }

      lines.push('    counter drop comment "missing-winner"', "  }");

      for (const rule of rules.filter((value) => value.action === "block")) {
        const chain = blockTraceChain(
          rule,
          node.instanceId,
          direction,
          node.family,
          policy.revision,
        );

        if (
          traces.has(chain) ||
          !ruleExpression(rule, node, direction, policy.revision)
        )
          continue;
        traces.add(chain);
        const counter = blockCounterName(rule, node.instanceId, direction);

        counters.add(counter);
        lines.push(
          `  chain ${chain} {`,
          "    ct direction original limit rate 10/second burst 20 packets meta nftrace set 1",
          `    counter name ${quote(counter)} drop comment ${quote(`rule:${rule.id}`)}`,
          "  }",
        );
      }
    }

  for (const chain of dynamic)
    lines.push(
      `  chain ${chain.name} {`,
      ...dnsChainRules(chain).map((rule) => `    ${rule}`),
      "  }",
    );

  // Unregistered drops trace themselves: no ingress trace marks packets outside every instance.
  for (const [side, counter] of Object.entries(UNREGISTERED_COUNTERS))
    lines.push(
      `  chain u_${side[0]} {`,
      "    ct direction original limit rate 10/second burst 20 packets meta nftrace set 1",
      `    counter name ${quote(counter)} drop comment "unregistered"`,
      "  }",
    );
  lines.push(
    "  chain trace_ingress {",
    "    type filter hook prerouting priority -150; policy accept;",
  );

  for (const entry of roots)
    for (const endpoint of ["saddr", "daddr"])
      lines.push(
        `    meta nfproto ipv${entry.family} ct direction original ${entry.family === 4 ? "ip" : "ip6"} ${endpoint} ${entry.network} limit rate 10/second burst 20 packets meta nftrace set 1`,
      );

  lines.push("  }");

  const interfaces = `{ ${upstreamInterfaces.map(quote).join(", ")} }`;

  // An unregistered drop from an upstream interface is only recorded; others are reported for
  // registration.
  const unregistered = (match: (family: 4 | 6, ip: string) => string) =>
    ([4, 6] as const).flatMap((family) => {
      const condition = match(family, family === 4 ? "ip" : "ip6");

      return [
        `    meta nfproto ipv${family} ${condition} iifname ${interfaces} jump u_u`,
        `    meta nfproto ipv${family} ${condition} jump u_c`,
      ];
    });

  // The machine link with the controller, and the gateway's own lookups upstream. A lookup is
  // matched by the direction its packets cross the hook, so clients cannot reach the upstream
  // address through the exemption.
  const infrastructure = (lookup: "original" | "reply") =>
    [4, 6].flatMap((family) => {
      const ip = family === 4 ? "ip" : "ip6";

      const controllers = controllerAddresses.filter(
        (address) => familyOf(address) === family,
      );

      return [
        ...(controllers.length
          ? [
              ["saddr", machinePort],
              ["daddr", controllerPort],
            ].map(
              ([endpoint, port]) =>
                `    meta nfproto ipv${family} ct original ${ip} ${endpoint} { ${controllers.join(", ")} } ct protocol 6 ct original proto-dst ${port} counter accept comment "controller"`,
            )
          : []),
        ...(familyOf(upstreamDns.address) === family
          ? [
              `    meta nfproto ipv${family} ct direction ${lookup} ct original ${ip} daddr ${upstreamDns.address} ct protocol { 6, 17 } ct original proto-dst ${upstreamDns.port} counter accept comment "upstream-dns"`,
            ]
          : []),
      ];
    });

  // In forward, both ends may be managed. In input and output the gateway is one end, so only the
  // other is dispatched: the initiator of a connection it receives, or the responder of one it
  // starts.
  const dispatch = (direction: "outgoing" | "incoming", condition = "") =>
    [4, 6].map(
      (family) =>
        `    meta nfproto ipv${family} ${condition}${direction === "outgoing" ? "ct original" : "ct reply"} ${family === 4 ? "ip" : "ip6"} saddr vmap @${direction[0]}${family}`,
    );

  const hooks = {
    forward: [
      // Nothing forwarded comes from the gateway, which sends through output. The kernel drops such
      // IPv4 packets as martians but forwards IPv6 ones, which would match Gateway peer rules.
      '    fib saddr type local counter drop comment "local-source"',
      ...dispatch("outgoing"),
      ...dispatch("incoming"),
      ...unregistered(
        (family, ip) =>
          `ct original ${ip} saddr != @owned${family} ct reply ${ip} saddr != @owned${family}`,
      ),
    ],
    input: [
      '    iifname "lo" counter accept',
      ...DHCP.map((rule) => `    ${rule}`),
      // MLD, router solicitations, and neighbour discovery. Only upstream routers may advertise
      // routes to the gateway, and no host may redirect it.
      '    icmpv6 type { 130, 131, 132, 133, 135, 136, 143 } counter accept comment "ipv6-link"',
      `    iifname ${interfaces} icmpv6 type 134 counter accept comment "ipv6-router"`,
      '    icmpv6 type { 134, 137 } counter drop comment "ipv6-router"',
      ...infrastructure("reply"),
      ...unregistered(
        (family, ip) =>
          `ct direction original ct original ${ip} saddr != @owned${family}`,
      ),
      // Managed clients always reach the local DNS gate; hostname rules depend on it. Packet
      // ports follow any redirect to the listener.
      `    meta l4proto { tcp, udp } th dport ${options.dnsPort} counter accept comment "gateway-dns"`,
      ...dispatch("outgoing", "ct direction original "),
      ...dispatch("incoming", "ct direction reply "),
    ],
    output: [
      '    oifname "lo" counter accept',
      ...DHCP.map((rule) => `    ${rule}`),
      // As a router, the gateway also advertises routes and sends redirects.
      '    icmpv6 type { 130, 131, 132, 133, 134, 135, 136, 137, 143 } counter accept comment "ipv6-link"',
      ...infrastructure("original"),
      `    meta l4proto { tcp, udp } th sport ${options.dnsPort} counter accept comment "gateway-dns"`,
      ...dispatch("outgoing", "ct direction reply "),
      ...dispatch("incoming", "ct direction original "),
    ],
  };

  for (const [hook, rules] of Object.entries(hooks))
    lines.push(
      `  chain ${hook} {`,
      `    type filter hook ${hook} priority -10; policy accept;`,
      "    ct state invalid counter drop",
      ...rules,
      "  }",
    );

  for (const counter of counters) lines.push(`  counter ${counter} {`, "  }");
  lines.push("}");

  return `${lines.join("\n")}\n`;
}
