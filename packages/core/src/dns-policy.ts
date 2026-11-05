import type { DnsDecision, Rule } from "@traffic-policy/contracts";
import {
  compareRules,
  contextRank,
  isCatchAll,
  nameMatches,
  ruleState,
  type SubjectContext,
} from "./index.ts";

function serviceRange(rule: Rule, protocol: number): [number, number] | null {
  if (rule.protocol !== null && rule.protocol !== protocol) return null;

  if (rule.portStart !== null)
    return protocol === 6 || protocol === 17
      ? [rule.portStart, rule.portEnd!]
      : null;

  if (protocol === 1 || protocol === 58) {
    if (rule.icmpType === null) return [0, 65535];
    const start = rule.icmpType * 256;

    return rule.icmpCode === null
      ? [start, start + 255]
      : [start + rule.icmpCode, start + rule.icmpCode];
  }

  return [0, protocol === 6 || protocol === 17 ? 65535 : 0];
}

function visitRange(
  blocked: Uint32Array,
  start: number,
  end: number,
  write: boolean,
): boolean {
  const first = start >>> 5;
  const last = end >>> 5;

  for (let word = first; word <= last; word++) {
    const lower = word === first ? 0xffffffff << (start & 31) : 0xffffffff;
    const upper = word === last ? 0xffffffff >>> (31 - (end & 31)) : 0xffffffff;
    const mask = (lower & upper) >>> 0;

    if (!write && (blocked[word]! & mask) >>> 0 !== mask) return true;

    if (write) blocked[word] = blocked[word]! | mask;
  }

  return false;
}

// Blocked services by protocol. `all` is set by a Block on every service, which covers any rule
// without building the per-protocol maps.
type Coverage = { all: boolean; protocols: Map<number, Uint32Array> };

const emptyCoverage = (): Coverage => ({ all: false, protocols: new Map() });

// Adds the rule's services to the blocked coverage.
function cover(coverage: Coverage, rule: Rule) {
  if (
    rule.protocol === null &&
    rule.portStart === null &&
    rule.icmpType === null
  ) {
    coverage.all = true;

    return;
  }

  for (
    let protocol = rule.protocol ?? 0;
    protocol <= (rule.protocol ?? 255);
    protocol++
  ) {
    const range = serviceRange(rule, protocol);

    if (!range) continue;
    let blocked = coverage.protocols.get(protocol);

    if (!blocked) {
      blocked = new Uint32Array([1, 6, 17, 58].includes(protocol) ? 2048 : 1);
      coverage.protocols.set(protocol, blocked);
    }

    visitRange(blocked, ...range, true);
  }
}

// Whether any of the rule's services is outside the blocked coverage.
function open(coverage: Coverage, rule: Rule): boolean {
  if (coverage.all) return false;

  for (
    let protocol = rule.protocol ?? 0;
    protocol <= (rule.protocol ?? 255);
    protocol++
  ) {
    const range = serviceRange(rule, protocol);
    const blocked = range ? coverage.protocols.get(protocol) : undefined;

    if (range && (!blocked || visitRange(blocked, ...range, false)))
      return true;
  }

  return false;
}

// The Block that completes the coverage of a losing Allow, in rank order: without it, the Allow
// would have kept a service.
function decisive(blocks: Rule[], allow: Rule): Rule | undefined {
  const coverage = emptyCoverage();

  return blocks.find((block) => {
    cover(coverage, block);

    return !open(coverage, allow);
  });
}

// A lookup has no intended service. At least one service must remain allowed after
// higher-ranked Blocks; IP/CIDR rules cannot match a question before it resolves. `question` is
// "." or a normalized DNS name, as the contract schemas leave it.
export function decideDns(
  rules: Rule[],
  context: SubjectContext,
  question: string,
  now = Date.now(),
): DnsDecision {
  return rankDns(
    rules.filter((rule) => appliesToDns(rule, context, question, now)),
    context,
  );
}

// Whether the rule takes part in the client's lookup of `question` at `now`.
export function appliesToDns(
  rule: Rule,
  context: SubjectContext,
  question: string,
  now: number,
): boolean {
  return (
    ruleState(rule, now) === "active" &&
    contextRank(rule, context) !== null &&
    rule.direction !== "incoming" &&
    (rule.peer.kind === "any" ||
      (question !== "." && nameMatches(rule.peer, question)))
  );
}

// Decides a lookup from exactly the rules that apply to the client, in any order. Sorts
// `candidates`.
export function rankDns(
  candidates: Rule[],
  context: SubjectContext,
): DnsDecision {
  candidates.sort((left, right) =>
    compareRules(left, right, (rule) => contextRank(rule, context) ?? 0),
  );

  // The Block that denies the highest-ranked Allow.
  let denying: Rule | undefined;

  // Without an applicable Allow, service coverage cannot change the denial.
  if (candidates.some((rule) => rule.action === "allow")) {
    const blocked = emptyCoverage();
    const blocks: Rule[] = [];

    for (const rule of candidates) {
      if (rule.action === "allow") {
        if (open(blocked, rule))
          return { allowed: true, ruleId: rule.id, catchAll: isCatchAll(rule) };
        denying ??= decisive(blocks, rule);
      } else {
        cover(blocked, rule);
        blocks.push(rule);
      }
    }
  }

  // Without an Allow, a service-only Block does not decide the whole question.
  // Attribute that denial to the first unrestricted Block, normally the default.
  const winner =
    denying ??
    candidates.find(
      (rule) =>
        rule.action === "block" &&
        rule.protocol === null &&
        rule.portStart === null,
    );

  return {
    allowed: false,
    ruleId: winner?.id ?? null,
    catchAll: !winner || isCatchAll(winner),
  };
}
