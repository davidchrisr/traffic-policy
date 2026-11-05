import {
  ScopeTree,
  type Instance,
  type Rule,
  type ScopeEntry,
} from "@traffic-policy/contracts";
import type {
  GatewayEndpoint,
  MonitorSnapshot,
} from "@traffic-policy/contracts/dashboard";
import {
  compareRules,
  decideTraffic,
  entryContext,
  isCatchAll,
  reachablePaths,
  ruleScopeLabel,
  scopeTree,
  type ObservedTraffic,
  type TrafficDecision,
} from "@traffic-policy/core";

// One scope tree per rule list, shared by every service decided against it.
const trees = new WeakMap<Rule[], ScopeTree>();

export function policyTree(instances: Instance[], rules: Rule[]): ScopeTree {
  let tree = trees.get(rules);

  if (!tree) {
    tree = scopeTree({ instances, rules });
    trees.set(rules, tree);
  }

  return tree;
}

// One entry for each scope path of each instance that some address has, by family, from its own
// addresses and the address rules inside it; its own addresses come first, so the first entry
// gives the main decision. Addresses on one path are decided alike, so a service is decided once
// per path.
const instancePaths = new WeakMap<
  ScopeTree,
  Map<string, Record<4 | 6, ScopeEntry[]>>
>();

function pathsOf(tree: ScopeTree, instanceId: string): ScopeEntry[][] {
  let index = instancePaths.get(tree);

  if (!index) {
    index = reachablePaths(tree);

    for (const paths of index.values())
      for (const family of [4, 6] as const)
        paths[family].sort(
          (left, right) => Number(!left.instanceId) - Number(!right.instanceId),
        );

    instancePaths.set(tree, index);
  }

  const paths = index.get(instanceId);

  return paths ? [paths[4], paths[6]] : [[], []];
}

export type DecisionState = "allow" | "block" | "waiting" | "varies";

export interface ServiceDecision extends TrafficDecision {
  state: DecisionState;
  peerIp: string;
  // The name the service was evaluated for, if any.
  name: string | null;
  // Addresses of the instance, or address rules inside it, that the service is decided for
  // differently, with the hostname rules that decide there while DNS admits the peer.
  exceptions: { address: string; winner: Rule | null; dns: Rule[] }[];
  // The gateway accept that admits the service before any rule, if one does.
  builtIn: BuiltIn | null;
}

// A gateway accept and, when it admits only some of a service's packets, which ones.
export interface BuiltIn {
  name: string;
  condition: string | null;
}

// The gateway's fixed accepts a service with the gateway can meet: its DNS gate, DHCP, the machine
// link with the controller, and its lookups to the upstream resolver. DHCP is accepted only between
// the protocol's ports, which Monitor does not record, so it is always conditional. The machine
// link and lookups are accepted only for those addresses, so they cover a whole service only when
// the instance is nothing but those addresses. ICMPv6 neighbour discovery and MLD are accepted too,
// but Monitor records no ICMP types.
function builtInAccept(
  service: Service,
  endpoint: GatewayEndpoint,
  tree: ScopeTree,
  instances: Instance[],
): BuiltIn | null {
  const udp = service.protocol === 17,
    tcp = service.protocol === 6;

  if (
    service.direction === "outgoing" &&
    (udp || tcp) &&
    service.port === endpoint.dnsPort
  )
    return { name: "DNS gate", condition: null };

  // The gateway serves DHCP and may itself be a DHCP client, so each port is accepted from its pair
  // in either direction.
  const pair = udp ? DHCP_PAIRS.get(service.port) : undefined;

  if (pair) return { name: "DHCP", condition: `from port ${pair}` };

  // The machine link and the upstream lookups can share a port; their addresses then combine.
  const accepts = [
    ...(tcp &&
    service.port ===
      (service.direction === "outgoing"
        ? endpoint.machinePort
        : endpoint.controllerPort)
      ? [["machine link", endpoint.controllerAddresses] as const]
      : []),
    ...(service.direction === "incoming" &&
    (udp || tcp) &&
    service.port === endpoint.upstreamDns.port
      ? [["upstream DNS", [endpoint.upstreamDns.address]] as const]
      : []),
  ].flatMap(([name, addresses]) => {
    const inside = addresses.filter((address) => {
      const entry = tree.find(address);

      return entry && ScopeTree.instanceOf(entry) === service.instanceId;
    });

    return inside.length ? [{ name, inside }] : [];
  });

  if (!accepts.length) return null;
  const inside = accepts.flatMap((accept) => accept.inside);
  const own = instances.find(({ id }) => id === service.instanceId);

  return {
    name: accepts.map((accept) => accept.name).join(" or "),
    condition: own?.addresses.every((address) => inside.includes(address))
      ? null
      : `for ${inside.join(", ")}`,
  };
}

// Each DHCP and DHCPv6 port, with the port its peer must send from. Monitor ports can be null.
const DHCP_PAIRS = new Map<number | null, number>([
  [67, 68],
  [68, 67],
  [547, 546],
  [546, 547],
]);

type Service = ObservedTraffic & { instanceId: string };

export const reviewKey = (service: Service) =>
  JSON.stringify([
    service.instanceId,
    service.direction,
    service.peerIp,
    service.protocol,
    service.port,
  ]);

export function reviewKeys(reviews: MonitorSnapshot["reviews"]): Set<string> {
  return new Set(reviews.map(reviewKey));
}

// Current desired policy for one observed service. A row waits for review only while the
// catch-all decides it and a review request is open; outcomes that depend on DNS or differ between
// the instance's scope paths in the peer's family vary. With the gateway's endpoint, a service with the gateway
// is decided as the gateway's own: by Gateway peer rules, or by an accept that precedes them.
export function decideService(
  rules: Rule[],
  instances: Instance[],
  localNetworks: string[],
  reviews: Set<string>,
  service: Service,
  name?: string,
  now = Date.now(),
  endpoint: GatewayEndpoint | null = null,
): ServiceDecision | null {
  const tree = policyTree(instances, rules);
  const [v4, v6] = pathsOf(tree, service.instanceId);
  const [primary, ...others] = service.peerIp.includes(":") ? v6 : v4;

  if (!primary) return null;
  let builtIn: BuiltIn | null = null;

  if (endpoint?.addresses.includes(service.peerIp)) {
    builtIn = builtInAccept(service, endpoint, tree, instances);

    if (builtIn && !builtIn.condition)
      return {
        winner: null,
        dns: [],
        equal: [],
        refused: [],
        state: "allow",
        peerIp: service.peerIp,
        name: name ?? null,
        exceptions: [],
        builtIn,
      };

    service = { ...service, gateway: true };
  }

  const decision = decideTraffic(
    rules,
    entryContext(primary),
    service,
    localNetworks,
    now,
    name,
  );

  const action = (winner: Rule | null) => winner?.action ?? "block";

  const conditions = (rules: Rule[]) => rules.map((rule) => rule.id).join(",");

  const exceptions = others.flatMap((entry) => {
    const { winner, dns } = decideTraffic(
      rules,
      entryContext(entry),
      service,
      localNetworks,
      now,
      name,
    );

    return action(winner) === action(decision.winner) &&
      conditions(dns) === conditions(decision.dns)
      ? []
      : [{ address: entry.network, winner, dns }];
  });

  const ruled: DecisionState =
    decision.dns.length || exceptions.length
      ? "varies"
      : !decision.winner
        ? "block"
        : isCatchAll(decision.winner) && reviews.has(reviewKey(service))
          ? "waiting"
          : decision.winner.action;

  // A conditional accept matters only where rules would not allow the service anyway.
  if (ruled === "allow") builtIn = null;
  const state = builtIn ? "varies" : ruled;

  return {
    ...decision,
    state,
    peerIp: service.peerIp,
    name: name ?? null,
    exceptions,
    builtIn,
  };
}

// Why each refused rule does not decide the decision's traffic.
export function refusalNotes(decision: ServiceDecision): string[] {
  return decision.refused.map(
    ({ rule, reason }) =>
      `${decision.name} resolves to ${decision.peerIp}, ${reason === "outside" ? "outside the rule's permitted destination networks" : "which is not a public address"}, so ${ruleName(rule)} does not apply. Add the address to the rule's permitted destination networks for it to apply.`,
  );
}

export function combineStates(
  states: (DecisionState | undefined)[],
): DecisionState | null {
  const known = states.filter((state) => state !== undefined);

  if (!known.length) return null;

  return known.every((state) => state === known[0]) ? known[0]! : "varies";
}

export function stateDescription(
  state: DecisionState | null,
  decision?: ServiceDecision | null,
): string {
  switch (state) {
    case null:
      return "No measured traffic";
    case "waiting":
      return withRefusals(
        "Blocked by the catch-all and waiting for review",
        decision,
      );
    case "varies": {
      if (!decision) return "Services have different current decisions";

      const ruled = decision.dns.length
        ? `Depends on DNS. ${decision.dns.map(dnsOutcome).join(" ")} Otherwise ${outcome(decision.winner)}`
        : capitalize(outcome(decision.winner));

      const exceptions = decision.exceptions.map(
        ({ address, winner, dns }) =>
          `${dns.length ? `${dns.map(dnsCondition).join(" or ")}, otherwise ${outcome(winner)}` : outcome(winner)} for ${address}`,
      );

      const text = `${ruled}${exceptions.length ? `, except ${exceptions.join(", ")}` : ""}.`;

      return decision.builtIn
        ? `Allowed ${decision.builtIn.condition} by the gateway's built-in ${decision.builtIn.name} accept. Other traffic: ${text}`
        : text;
    }

    case "allow":
    case "block":
      return decision?.builtIn
        ? `Allowed by the gateway's built-in ${decision.builtIn.name} accept, which no rule can change`
        : decision
          ? withRefusals(capitalize(outcome(decision.winner)), decision)
          : capitalize(state === "allow" ? "allowed" : "blocked");
  }
}

function withRefusals(text: string, decision?: ServiceDecision | null) {
  const notes = decision ? refusalNotes(decision) : [];

  return notes.length ? `${text}. ${notes.join(" ")}` : text;
}

const capitalize = (value: string) =>
  `${value[0]!.toUpperCase()}${value.slice(1)}`;

export const ruleName = (rule: Rule) =>
  isCatchAll(rule) ? "the catch-all" : ruleScopeLabel(rule);

export const ruleTitle = (rule: Rule) =>
  isCatchAll(rule) ? "Catch-all" : ruleScopeLabel(rule);

const outcome = (rule: Rule | null) =>
  rule
    ? `${rule.action === "allow" ? "allowed" : "blocked"} by ${ruleName(rule)}`
    : "blocked";

// The name a hostname or domain rule's DNS condition is about.
const dnsName = (rule: Rule) =>
  rule.peer.kind === "hostname" || rule.peer.kind === "domain"
    ? rule.peer.value
    : ruleScopeLabel(rule);

const dnsCondition = (rule: Rule) =>
  `${rule.action === "allow" ? "allowed" : "blocked"} while ${dnsName(rule)} resolves to this address`;

const dnsOutcome = (rule: Rule) => `${capitalize(dnsCondition(rule))}.`;

export interface InspectorRule {
  rule: Rule;
  // Set when a hostname or domain rule decides only while DNS admits the address.
  dns: string | null;
  // Set when an equally specific rule has no effect now.
  note: string | null;
}

// The current rules that decide the selection's services, followed by equally specific rules
// that have no effect now, in precedence order.
export function inspectorRules(
  decisions: (ServiceDecision | null | undefined)[],
): InspectorRule[] {
  const rows: Record<string, InspectorRule> = {};
  const decided = decisions.filter((decision) => decision?.winner);

  for (const decision of decided) {
    const winner = decision!.winner!;

    for (const rule of decision!.dns)
      rows[rule.id] = {
        rule,
        dns: `Applies only while ${dnsName(rule)} resolves to this address. Otherwise ${ruleName(winner)} decides.`,
        note: null,
      };

    rows[winner.id] ??= { rule: winner, dns: null, note: null };
  }

  // The rules that decide other paths of an instance, for the addresses they decide.
  for (const decision of decisions)
    for (const { address, winner, dns } of decision?.exceptions ?? []) {
      for (const rule of dns)
        rows[rule.id] ??= {
          rule,
          dns: `Applies for ${address} only while ${dnsName(rule)} resolves to this address. ${winner ? `Otherwise ${ruleName(winner)} decides.` : "Otherwise blocked."}`,
          note: null,
        };

      if (winner)
        rows[winner.id] ??= {
          rule: winner,
          dns: null,
          note: `Decides for ${address}.`,
        };
    }

  for (const decision of decided) {
    const winner = decision!.winner!;

    for (const rule of decision!.equal)
      rows[rule.id] ??= {
        rule,
        dns: null,
        note:
          rule.action !== winner.action
            ? "No effect. Block wins between otherwise equal rules."
            : winner.expiresAt && !rule.expiresAt
              ? "Same scope. Takes over when the temporary rule expires."
              : "Same scope as the rule that decides this traffic.",
      };
  }

  for (const decision of decisions)
    for (const { rule, reason } of decision?.refused ?? [])
      rows[rule.id] ??= {
        rule,
        dns: null,
        note: `No effect for ${decision!.peerIp}: ${reason === "outside" ? "outside its permitted destination networks" : "not a public address"}. Add the address to its permitted destination networks for it to apply.`,
      };

  return Object.values(rows).sort((left, right) =>
    compareRules(left.rule, right.rule),
  );
}
