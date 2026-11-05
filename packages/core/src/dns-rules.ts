import ipaddr from "ipaddr.js";
import {
  ScopeTree,
  subjectScope,
  type AddressLease,
  type DnsDecision,
  type Policy,
  type Rule,
} from "@traffic-policy/contracts";
import { appliesToDns, rankDns } from "./dns-policy.ts";
import {
  entryContext,
  reachablePaths,
  scopeTree,
  subjectContext,
  type SubjectContext,
} from "./index.ts";

type Network = ReturnType<typeof ipaddr.parseCIDR>;

interface IndexedRule {
  rule: Rule;
  position: number;
  networks: Network[] | null;
}

type ScopedRules = Map<string | null, IndexedRule[]>;

type NameRules = Map<string, ScopedRules>;

// Where a lease's answer address is enforced, with the rules that admit it there.
export interface LeaseBinding {
  path: string;
  rules: Rule[];
}

// An index keeps the rule objects of one policy snapshot, so callers must not edit that policy
// afterward; a changed policy gets a new index.
export class DnsRuleIndex {
  private readonly hostnames: NameRules = new Map();
  private readonly domains: NameRules = new Map();
  private readonly anyPeer = new Map<string | null, Rule[]>();
  private readonly localNetworks: Network[];
  // Each scope path's context, and the paths of each instance that some address has, by family.
  private readonly paths = new Map<string, SubjectContext>();
  private readonly instancePaths = new Map<string, Record<4 | 6, string[]>>();
  readonly tree: ScopeTree;

  constructor(policy: Policy) {
    const networks = new Map<string, Network>();

    const parseNetwork = (text: string) => {
      let network = networks.get(text);

      if (!network) {
        network = ipaddr.parseCIDR(text);
        networks.set(text, network);
      }

      return network;
    };

    this.localNetworks = policy.settings.localNetworks.map(parseNetwork);
    this.tree = scopeTree(policy);

    for (const entry of this.tree.entries) {
      const context = entryContext(entry);

      if (!this.paths.has(context.path)) this.paths.set(context.path, context);
    }

    // Answers bind only on paths some address has.
    for (const [instanceId, entries] of reachablePaths(this.tree))
      this.instancePaths.set(instanceId, {
        4: entries[4].map(ScopeTree.pathKey),
        6: entries[6].map(ScopeTree.pathKey),
      });

    for (const [position, source] of policy.rules.entries()) {
      if (!source.enabled) continue;
      const scope = subjectScope(source.subject);

      if (source.peer.kind === "any") {
        let rules = this.anyPeer.get(scope);

        if (!rules) {
          rules = [];
          this.anyPeer.set(scope, rules);
        }

        rules.push(source);
        continue;
      }

      if (source.peer.kind !== "hostname" && source.peer.kind !== "domain")
        continue;

      const names =
        source.peer.kind === "hostname" ? this.hostnames : this.domains;

      let scopes = names.get(source.peer.value);

      if (!scopes) {
        scopes = new Map();
        names.set(source.peer.value, scopes);
      }

      let rules = scopes.get(scope);

      if (!rules) {
        rules = [];
        scopes.set(scope, rules);
      }

      rules.push({
        rule: source,
        position,
        networks: source.dnsDestinations?.map(parseNetwork) ?? null,
      });
    }
  }

  // Where a canonical client address sits among the policy's scopes; null when no instance covers
  // it.
  context(address: string): SubjectContext | null {
    return subjectContext(this.tree, address);
  }

  // Equals decideDns(policy.rules, ...) but ranks only the rules that can apply to the question.
  decide(context: SubjectContext, question: string, now: number): DnsDecision {
    const candidates = [...(this.anyPeer.get(null) ?? [])];

    for (const scope of context.ranks.keys())
      candidates.push(...(this.anyPeer.get(scope) ?? []));

    if (question !== ".")
      for (const indexed of this.named(question, context))
        candidates.push(indexed.rule);

    return rankDns(
      candidates.filter((rule) => appliesToDns(rule, context, question, now)),
      context,
    );
  }

  // Where a lease's address is enforced. An address in the client's family binds on the lease's
  // own path. One in the other family binds on each path of the client's instance in that family,
  // since nothing tells which of them the client uses. Each path binds the hostname and domain
  // rules that apply there and admit the address, so its own rule order still decides. A lease
  // whose path no longer exists binds nothing.
  match(lease: AddressLease): LeaseBinding[] {
    const context = this.paths.get(lease.path);

    if (!context) return [];
    const address = ipaddr.process(lease.address);
    const family = address.kind() === "ipv4" ? 4 : 6;

    const targets = lease.path.startsWith(`${family}|`)
      ? [lease.path]
      : this.instancePaths.get(context.instanceId)![family];

    const inNetwork = ([subnet, prefix]: Network) =>
      address.kind() === subnet.kind() && address.match(subnet, prefix);

    return targets.flatMap((path) => {
      const candidates = this.named(lease.question, this.paths.get(path)!);

      // Rule order is part of existing permission serialization and must not
      // depend on whether a candidate came from an exact or suffix lookup.
      candidates.sort((left, right) => left.position - right.position);

      // An ICMP rule of the other family has no chain in this one.
      const rules = candidates
        .filter(
          (candidate) =>
            candidate.rule.protocol !== (family === 4 ? 58 : 1) &&
            (candidate.networks
              ? candidate.networks.some(inNetwork)
              : address.range() === "unicast" &&
                !this.localNetworks.some(inNetwork)),
        )
        .map((candidate) => candidate.rule);

      return rules.length ? [{ path, rules }] : [];
    });
  }

  // Hostname rules for the name and Domain rules for it and each parent, global or for a scope
  // covering the client.
  private named(name: string, context: SubjectContext): IndexedRule[] {
    const candidates: IndexedRule[] = [];

    const collect = (scopes: ScopedRules | undefined) => {
      if (!scopes) return;
      const rules = scopes.get(null);

      if (rules) candidates.push(...rules);

      for (const scope of context.ranks.keys()) {
        const scoped = scopes.get(scope);

        if (scoped) candidates.push(...scoped);
      }
    };

    collect(this.hostnames.get(name));

    for (let suffix = name; ;) {
      collect(this.domains.get(suffix));
      const dot = suffix.indexOf(".");

      if (dot < 0) break;
      suffix = suffix.slice(dot + 1);
    }

    return candidates;
  }
}
