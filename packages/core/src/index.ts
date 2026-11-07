import ipaddr from "ipaddr.js";
import {
  ScopeTree,
  canonicalCidr,
  canonicalIp,
  formatPorts,
  integerAddress,
  subjectScope,
} from "@traffic-policy/contracts";
import type {
  Flow,
  Instance,
  Peer,
  Permission,
  Policy,
  PortRange,
  Rule,
  ScopeEntry,
  Subject,
} from "@traffic-policy/contracts";

export function addressInNetwork(address: string, network: string): boolean {
  const ip = ipaddr.process(address);
  const [subnet, prefix] = ipaddr.parseCIDR(network);

  return ip.kind() === subnet.kind() && ip.match(subnet, prefix);
}

export function peerRank(peer: Peer): number[] {
  switch (peer.kind) {
    case "ip":
    case "gateway":
      return [5, 0];
    case "hostname":
      return [4, 0];
    case "domain":
      return [3, peer.value.split(".").length];
    case "cidr": {
      const [ip, prefix] = ipaddr.parseCIDR(peer.value);

      return prefix === (ip.kind() === "ipv4" ? 32 : 128)
        ? [5, 0]
        : [2, prefix];
    }

    case "any":
      return [1, 0];
  }
}

// Where a managed address sits among the policy's scopes.
export interface SubjectContext {
  address: string;
  // Each scope covering the address, ranked by its covering entry's prefix plus one.
  ranks: ReadonlyMap<string, number>;
  // The address's scope path (`ScopeTree.pathKey`), which holds its DNS permissions.
  path: string;
  // The most specific instance covering the address.
  instanceId: string;
}

export function subjectContext(
  tree: ScopeTree,
  address: string,
): SubjectContext | null {
  const entry = tree.find(address);

  return entry ? entryContext(entry, ScopeTree.pathKey(entry), address) : null;
}

// The most specific instance covering each address, for instance lists that may hold networks.
export class InstanceOwners<
  T extends { readonly id: string; readonly addresses: readonly string[] },
> {
  private readonly tree: ScopeTree;
  private readonly instances: ReadonlyMap<string, T>;

  constructor(instances: readonly T[]) {
    this.tree = new ScopeTree(instances);
    this.instances = new Map(instances.map((value) => [value.id, value]));
  }

  find(address: string): T | undefined {
    const entry = this.tree.find(address);

    return entry ? this.instances.get(ScopeTree.instanceOf(entry)) : undefined;
  }
}

// Whether any address belongs to the entry most specifically, rather than to the scopes nested in
// it; only such entries' paths have traffic.
function reachable(entry: ScopeEntry): boolean {
  const covered = entry.children.reduce(
    (total, child) => total + child.end - child.start + 1n,
    0n,
  );

  return covered <= entry.end - entry.start;
}

// Each instance's scope paths that some address has, by family: one entry for each path, in tree
// order.
export function reachablePaths(
  tree: ScopeTree,
): Map<string, Record<4 | 6, ScopeEntry[]>> {
  const index = new Map<string, Record<4 | 6, ScopeEntry[]>>();
  const seen = new Set<string>();

  for (const entry of tree.entries) {
    const path = ScopeTree.pathKey(entry);

    if (seen.has(path) || !reachable(entry)) continue;
    seen.add(path);
    const owner = ScopeTree.instanceOf(entry);
    let paths = index.get(owner);

    if (!paths) {
      paths = { 4: [], 6: [] };
      index.set(owner, paths);
    }

    paths[entry.family].push(entry);
  }

  return index;
}

// A scope's own place among the scopes: its first address's path, without scopes nested inside it.
// Callers that already hold the path key or an address on the entry pass them.
export function entryContext(
  entry: ScopeEntry,
  path = ScopeTree.pathKey(entry),
  address = integerAddress(entry.family, entry.start),
): SubjectContext {
  const ranks = new Map<string, number>();

  for (const value of ScopeTree.path(entry))
    ranks.set(value.scope, value.prefix + 1);

  return { address, ranks, path, instanceId: ScopeTree.instanceOf(entry) };
}

// Every scope a policy's rules can name, so its tree includes address-rule ranges.
export function scopeTree(policy: Pick<Policy, "instances" | "rules">) {
  return new ScopeTree(
    policy.instances,
    policy.rules.flatMap((rule) =>
      rule.subject.kind === "address" ? [rule.subject.value] : [],
    ),
  );
}

// The rule's subject rank at the context's address, or null when the rule does not apply there.
export function contextRank(
  rule: Pick<Rule, "subject">,
  context: Pick<SubjectContext, "ranks">,
): number | null {
  const scope = subjectScope(rule.subject);

  return scope === null ? 0 : (context.ranks.get(scope) ?? null);
}

// The scopes on each path of the tree, by `ScopeTree.pathKey`.
export function pathScopes(tree: ScopeTree): Map<string, Set<string>> {
  return new Map(
    tree.entries.map((entry) => [
      ScopeTree.pathKey(entry),
      new Set(ScopeTree.path(entry).map((value) => value.scope)),
    ]),
  );
}

// Without an address, scoped rules rank above global ones; used to order rules for display.
export const defaultSubjectRank = (rule: Pick<Rule, "subject">) =>
  rule.subject.kind === "global" ? 0 : 1;

// Whether a port is in one of the ranges.
export function inPorts(ranges: PortRange[], port: number): boolean {
  return ranges.some(({ start, end }) => start <= port && port <= end);
}

export function ruleRank(
  rule: Rule,
  subject = defaultSubjectRank(rule),
): number[] {
  return [
    rule.priority === "high" ? 1 : 0,
    ...peerRank(rule.peer),
    rule.ports === null ? 0 : 1,
    // Fewer ports rank higher; a single range ranks as it did before port lists.
    rule.ports === null
      ? 0
      : 65537 -
        rule.ports.reduce((sum, range) => sum + range.end - range.start + 1, 0),
    rule.icmpType === null ? 0 : 1,
    rule.icmpCode === null ? 0 : 1,
    rule.protocol === null ? 0 : 1,
    subject,
    rule.direction === "both" ? 0 : 1,
    rule.action === "block" ? 1 : 0,
  ];
}

export function compareRules(
  left: Rule,
  right: Rule,
  subject: (rule: Rule) => number = defaultSubjectRank,
): number {
  const a = ruleRank(left, subject(left)),
    b = ruleRank(right, subject(right));

  for (let index = 0; index < a.length; index++) {
    const difference = b[index]! - a[index]!;

    if (difference) return difference;
  }

  return left.id.localeCompare(right.id);
}

export function ruleState(
  rule: Rule,
  now = Date.now(),
): "disabled" | "expired" | "scheduled" | "active" {
  if (!rule.enabled) return "disabled";

  if (rule.expiresAt && Date.parse(rule.expiresAt) <= now) return "expired";

  if (rule.notBefore && Date.parse(rule.notBefore) > now) return "scheduled";

  return "active";
}

// `name` must already be normalized, as the contract schemas leave DNS names and hostnames.
export function nameMatches(peer: Peer, name: string): boolean {
  return (
    (peer.kind === "hostname" || peer.kind === "domain") &&
    (name === peer.value ||
      (peer.kind === "domain" && name.endsWith(`.${peer.value}`)))
  );
}

// `gateway` tells whether the flow's peer is the gateway itself.
export function ruleMatches(
  rule: Rule,
  context: SubjectContext,
  direction: "outgoing" | "incoming",
  flow: Flow,
  permissions: Permission[],
  now: number,
  gateway = false,
): boolean {
  if (
    ruleState(rule, now) !== "active" ||
    contextRank(rule, context) === null ||
    (rule.direction !== "both" && rule.direction !== direction) ||
    (rule.protocol !== null && rule.protocol !== flow.protocol)
  )
    return false;

  const port =
    direction === "outgoing"
      ? flow.originalServicePort
      : flow.responderServicePort;

  if (rule.ports !== null && (port === null || !inPorts(rule.ports, port)))
    return false;

  if (
    (rule.icmpType !== null && rule.icmpType !== flow.icmpType) ||
    (rule.icmpCode !== null && rule.icmpCode !== flow.icmpCode)
  )
    return false;

  const peer =
    direction === "outgoing" ? flow.originalDestinationIp : flow.initiatorIp;

  switch (rule.peer.kind) {
    case "any":
      return true;
    case "gateway":
      return gateway;
    case "ip":
      return canonicalIp(peer) === rule.peer.value;
    case "cidr":
      return addressInNetwork(peer, rule.peer.value);
    case "hostname":
    case "domain":
      return permissions.some(
        (permission) =>
          permission.ruleId === rule.id &&
          permission.path === context.path &&
          permission.address === canonicalIp(peer) &&
          Date.parse(permission.expiresAt) > now,
      );
  }
}

// Why a hostname or domain rule refuses a DNS answer address, or null when it admits it. A rule
// with permitted destination networks admits only those; one without admits public addresses only.
export function dnsAddressRefusal(
  rule: Pick<Rule, "dnsDestinations">,
  address: string,
  localNetworks: string[],
): "outside" | "not-public" | null {
  if (rule.dnsDestinations)
    return rule.dnsDestinations.some((network) =>
      addressInNetwork(address, network),
    )
      ? null
      : "outside";

  return ipaddr.process(address).range() === "unicast" &&
    !localNetworks.some((network) => addressInNetwork(address, network))
    ? null
    : "not-public";
}

const permittedDnsAddress = (rule: Rule, policy: Policy, address: string) =>
  dnsAddressRefusal(rule, address, policy.settings.localNetworks) === null;

export function reconcilePermissions(
  policy: Policy,
  permissions: Permission[],
  now = Date.now(),
): Permission[] {
  const paths = pathScopes(scopeTree(policy));

  return permissions.flatMap((permission) => {
    if (Date.parse(permission.expiresAt) <= now) return [];

    const rule = policy.rules.find(
      (candidate) => candidate.id === permission.ruleId,
    );

    const scopes = paths.get(permission.path);

    if (
      !rule ||
      !scopes ||
      !rule.enabled ||
      (rule.expiresAt !== null && Date.parse(rule.expiresAt) <= now) ||
      (rule.subject.kind !== "global" &&
        !scopes.has(subjectScope(rule.subject)!)) ||
      !nameMatches(rule.peer, permission.question) ||
      !permittedDnsAddress(rule, policy, permission.address)
    )
      return [];

    const deadline =
      Math.floor(
        Math.min(
          Date.parse(permission.responseAt) +
            (permission.ttlSeconds + policy.settings.dnsGraceSeconds) * 1000,
          rule.expiresAt ? Date.parse(rule.expiresAt) : Infinity,
        ) / 1000,
      ) * 1000;

    return deadline <= now
      ? []
      : [{ ...permission, expiresAt: new Date(deadline).toISOString() }];
  });
}

const protocolNames = new Map([
  [6, "TCP"],
  [17, "UDP"],
  [1, "ICMP"],
  [58, "ICMPv6"],
]);

// A protocol with a rule's port ranges.
export function serviceRangesLabel(
  protocol: number | null,
  ports: PortRange[] | null,
): string {
  if (protocol === null && ports === null) return "any";

  const name =
    protocol === null
      ? "TCP/UDP"
      : (protocolNames.get(protocol) ?? `Protocol ${protocol}`);

  return ports === null ? name : `${name}:${formatPorts(ports, "–")}`;
}

// A protocol with an observed port.
export function serviceLabel(protocol: number | null, port: number | null) {
  return serviceRangesLabel(
    protocol,
    port === null ? null : [{ start: port, end: port }],
  );
}

export function ruleScopeLabel(
  rule: Pick<Rule, "peer" | "protocol" | "ports" | "icmpType" | "icmpCode">,
): string {
  const peer =
    rule.peer.kind === "any"
      ? "Any peer"
      : rule.peer.kind === "gateway"
        ? "Gateway"
        : rule.peer.value;

  const icmp = `${rule.icmpType === null ? "" : ` type ${rule.icmpType}`}${rule.icmpCode === null ? "" : ` code ${rule.icmpCode}`}`;

  return `${peer} · ${serviceRangesLabel(rule.protocol, rule.ports)}${icmp}`;
}

export const directionLabels = {
  outgoing: "Outgoing",
  incoming: "Incoming",
  both: "Both directions",
} as const;

export function subjectLabel(
  subject: Subject,
  instances: Pick<Instance, "id" | "name">[] = [],
): string {
  switch (subject.kind) {
    case "global":
      return "Any instance";
    case "instance":
      return (
        instances.find((value) => value.id === subject.instanceId)?.name ??
        "Instance"
      );
    case "address":
      return subject.value;
  }
}

// Where a subject sits among the scopes, one line for each of its ranges: the instances and
// address rules containing it, outermost first, ending with the subject. Null for global
// subjects, scopes the tree lacks, and scopes nothing contains.
export function subjectPath(
  subject: Subject,
  tree: ScopeTree,
  instances: Pick<Instance, "id" | "name">[] = [],
): string | null {
  const scope = subjectScope(subject);

  if (scope === null) return null;
  const names = new Map(instances.map((value) => [value.id, value.name]));

  const paths = tree.entries
    .filter((entry) => entry.scope === scope)
    .map((entry) => ScopeTree.path(entry))
    .filter((path) => path.length > 1)
    .map((path) =>
      path
        .map((entry) =>
          entry.instanceId
            ? (names.get(entry.instanceId) ?? "Instance")
            : entry.network,
        )
        .join(" › "),
    );

  return paths.length ? [...new Set(paths)].join("\n") : null;
}

export function describeRule(rule: Rule, instances: Instance[] = []): string {
  return `${subjectLabel(rule.subject, instances)} · ${directionLabels[rule.direction]} · ${ruleScopeLabel(rule)}`;
}

export function isCatchAll(
  rule: Pick<Rule, "subject" | "peer" | "protocol" | "ports">,
): boolean {
  return (
    rule.subject.kind === "global" &&
    rule.peer.kind === "any" &&
    rule.protocol === null &&
    rule.ports === null
  );
}

// The catch-all that Settings owns: permanent, enabled, normal priority, and global. A
// temporary, disabled, or High-priority catch-all stays an ordinary rule.
export function isSettingsCatchAll(rule: Rule): boolean {
  return (
    isCatchAll(rule) &&
    rule.icmpType === null &&
    rule.enabled &&
    rule.priority === "normal" &&
    rule.notBefore === null &&
    rule.expiresAt === null
  );
}

// The action Settings shows for each direction, decided by rule precedence when several
// catch-alls cover it; null means no Settings catch-all covers the direction.
export function catchAllActions(rules: Rule[]) {
  const action = (direction: "outgoing" | "incoming") =>
    rules
      .filter(
        (rule) =>
          isSettingsCatchAll(rule) &&
          (rule.direction === direction || rule.direction === "both"),
      )
      .sort(compareRules)
      .at(0)?.action ?? null;

  return { outgoing: action("outgoing"), incoming: action("incoming") };
}

function peerCovers(outer: Peer, inner: Peer): boolean {
  if (outer.kind === "any") return true;

  if (inner.kind === "any") return false;

  if (outer.kind === "gateway" || inner.kind === "gateway")
    return outer.kind === inner.kind;

  if (outer.kind === "domain" && inner.kind !== "ip" && inner.kind !== "cidr")
    return (
      inner.value === outer.value || inner.value.endsWith(`.${outer.value}`)
    );

  if (outer.kind === "hostname" || inner.kind === "hostname")
    return outer.kind === inner.kind && outer.value === inner.value;

  if (
    (outer.kind !== "ip" && outer.kind !== "cidr") ||
    (inner.kind !== "ip" && inner.kind !== "cidr")
  )
    return false;

  const network = (peer: Peer & { value: string }) =>
    peer.kind === "cidr"
      ? ipaddr.parseCIDR(peer.value)
      : ([
          ipaddr.process(peer.value),
          ipaddr.process(peer.value).kind() === "ipv4" ? 32 : 128,
        ] as const);

  const [outerAddress, outerPrefix] = network(outer);
  const [innerAddress, innerPrefix] = network(inner);

  return (
    outerAddress.kind() === innerAddress.kind() &&
    innerPrefix >= outerPrefix &&
    innerAddress.match(outerAddress, outerPrefix)
  );
}

// Whether every address `inner` applies to is also one `outer` applies to.
function subjectCovers(outer: Subject, inner: Subject, tree: ScopeTree) {
  const outerScope = subjectScope(outer),
    innerScope = subjectScope(inner);

  if (outerScope === null || outerScope === innerScope) return true;

  if (innerScope === null) return false;
  const entries = tree.entries.filter((entry) => entry.scope === innerScope);

  return (
    entries.length > 0 &&
    entries.every((entry) =>
      ScopeTree.path(entry).some((value) => value.scope === outerScope),
    )
  );
}

// True when `outer` matches every packet `inner` matches, ignoring time and state. `tree` must
// hold both rules' scopes.
export function ruleCovers(outer: Rule, inner: Rule, tree: ScopeTree): boolean {
  const named = (rule: Rule) =>
    rule.peer.kind === "hostname" || rule.peer.kind === "domain";

  // A DNS rule only admits answers in its destination ranges, so a named rule covers another only
  // with the same ranges. Equal ranges miss a few wider ones but never claim a false cover.
  if (
    named(outer) &&
    named(inner) &&
    JSON.stringify(outer.dnsDestinations) !==
      JSON.stringify(inner.dnsDestinations)
  )
    return false;

  const ported = (rule: Rule) =>
    rule.protocol === 6 ||
    rule.protocol === 17 ||
    (rule.protocol === null && rule.ports !== null);

  const protocol =
    outer.protocol === null
      ? outer.ports === null || ported(inner)
      : outer.protocol === inner.protocol;

  return (
    subjectCovers(outer.subject, inner.subject, tree) &&
    (outer.direction === "both" || outer.direction === inner.direction) &&
    peerCovers(outer.peer, inner.peer) &&
    protocol &&
    (outer.ports === null ||
      (inner.ports !== null &&
        inner.ports.every((range) =>
          outer.ports!.some(
            (wider) => wider.start <= range.start && range.end <= wider.end,
          ),
        ))) &&
    (outer.icmpType === null || outer.icmpType === inner.icmpType) &&
    (outer.icmpCode === null || outer.icmpCode === inner.icmpCode)
  );
}

export interface Override {
  rule: Rule;
  // When the overriding rule ends and this one takes effect; null when it never does.
  until: string | null;
}

// An active rule with the opposite action that matches everything `rule` matches and outranks
// it, so `rule` decides nothing. A covering rule can only outrank by High priority or by Block
// winning an exact tie. With several, the one that lasts longest is reported.
//
// A covering rule's subject contains `rule`'s, so at every address it ranks the same when both name
// the same scope and lower otherwise.
export function overriddenBy(
  rule: Rule,
  rules: Rule[],
  instances: Instance[],
  now = Date.now(),
): Override | null {
  if (!rule.enabled) return null;
  const tree = scopeTree({ instances, rules: [...rules, rule] });
  const scope = subjectScope(rule.subject);

  const subject = (value: Rule) =>
    subjectScope(value.subject) === scope ? 1 : 0;

  const winner = rules
    .filter(
      (other) =>
        other.id !== rule.id &&
        other.action !== rule.action &&
        ruleState(other, now) === "active" &&
        ruleCovers(other, rule, tree) &&
        compareRules(other, rule, subject) < 0,
    )
    .sort((left, right) =>
      left.expiresAt === null
        ? -1
        : right.expiresAt === null
          ? 1
          : right.expiresAt.localeCompare(left.expiresAt),
    )
    .at(0);

  if (!winner) return null;

  return {
    rule: winner,
    until:
      winner.expiresAt !== null &&
      (rule.expiresAt === null || rule.expiresAt > winner.expiresAt)
        ? winner.expiresAt
        : null,
  };
}

export interface ObservedTraffic {
  direction: "outgoing" | "incoming";
  peerIp: string;
  protocol: number;
  port: number | null;
  // Whether the peer is the gateway itself.
  gateway?: boolean;
}

export interface TrafficDecision {
  winner: Rule | null;
  // Hostname or domain rules that outrank the winner while a DNS answer admits the peer.
  dns: Rule[];
  // Other matching rules that are equally specific; the winner's action or ID decides between them.
  equal: Rule[];
  // With a name: rules for it that outrank the winner but refuse the peer address as a DNS answer.
  refused: { rule: Rule; reason: "outside" | "not-public" }[];
}

// Evaluates the controller's desired policy without DNS-derived permissions. Hostname and domain
// rules apply only where they admit the peer as a DNS answer. With a name, rules for that name are
// treated as matching, and rules for other names are ignored.
export function decideTraffic(
  rules: Rule[],
  context: SubjectContext,
  traffic: ObservedTraffic,
  localNetworks: string[],
  now = Date.now(),
  name?: string,
): TrafficDecision {
  const incoming = traffic.direction === "incoming",
    address = context.address;

  const flow: Flow = {
    initiatorIp: incoming ? traffic.peerIp : address,
    responderIp: incoming ? address : traffic.peerIp,
    originalDestinationIp: incoming ? address : traffic.peerIp,
    protocol: traffic.protocol,
    originalServicePort: traffic.port,
    responderServicePort: traffic.port,
    icmpType: null,
    icmpCode: null,
  };

  const named = (rule: Rule) =>
    rule.peer.kind === "hostname" || rule.peer.kind === "domain";

  const refusal = (rule: Rule) =>
    named(rule) ? dnsAddressRefusal(rule, traffic.peerIp, localNetworks) : null;

  // Matches the service and, for a hostname or domain rule, its name when one is given.
  const matchesService = (rule: Rule) => {
    if (name !== undefined && named(rule) && !nameMatches(rule.peer, name))
      return false;

    return ruleMatches(
      named(rule) ? { ...rule, peer: { kind: "any" } } : rule,
      context,
      traffic.direction,
      flow,
      [],
      now,
      traffic.gateway,
    );
  };

  // Without a name, a hostname or domain rule never matches: no DNS answer is assumed.
  const matches = (rule: Rule) =>
    (!named(rule) || name !== undefined) &&
    matchesService(rule) &&
    refusal(rule) === null;

  const subject = (rule: Rule) => contextRank(rule, context) ?? 0;

  const ordered = [...rules].sort((left, right) =>
    compareRules(left, right, subject),
  );

  const winner = ordered.find(matches) ?? null;

  const outranking = winner
    ? ordered.slice(0, ordered.indexOf(winner))
    : ordered;

  const refused =
    name === undefined
      ? []
      : outranking.flatMap((rule) => {
          const reason = refusal(rule);

          return reason && matchesService(rule) ? [{ rule, reason }] : [];
        });

  if (!winner) return { winner, dns: [], equal: [], refused };

  const rank = ruleRank(winner, subject(winner)).slice(0, -1).join();

  return {
    winner,
    refused,
    dns:
      name === undefined
        ? outranking.filter(
            (rule) =>
              named(rule) && matchesService(rule) && refusal(rule) === null,
          )
        : [],
    equal: ordered.filter(
      (rule) =>
        rule !== winner &&
        ruleRank(rule, subject(rule)).slice(0, -1).join() === rank &&
        matches(rule),
    ),
  };
}

export function scopeKey(
  rule: Pick<
    Rule,
    | "subject"
    | "direction"
    | "peer"
    | "protocol"
    | "ports"
    | "icmpType"
    | "icmpCode"
  >,
): string {
  return JSON.stringify([
    rule.subject,
    rule.direction,
    rule.peer,
    rule.protocol,
    rule.ports,
    rule.icmpType,
    rule.icmpCode,
  ]);
}

export { canonicalCidr };

export { DnsRuleIndex } from "./dns-rules.ts";

export { decideDns } from "./dns-policy.ts";

export {
  addressLeases,
  leaseKey,
  permissionLeaseKey,
  iteratePermissionsForLeases,
  reconcileLeases,
} from "./leases.ts";
