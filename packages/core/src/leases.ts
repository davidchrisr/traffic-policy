import {
  ScopeTree,
  canonicalIp,
  canonicalName,
} from "@traffic-policy/contracts";
import type {
  AddressLease,
  Permission,
  Policy,
  Resolution,
} from "@traffic-policy/contracts";
import { DnsRuleIndex } from "./dns-rules.ts";
import { scopeTree } from "./index.ts";

export function addressLeases(
  policy: Policy,
  resolution: Resolution,
  index = new DnsRuleIndex(policy),
): AddressLease[] {
  const context = index.context(resolution.clientIp);

  if (!context) throw new Error("DNS client is not enrolled");
  let owner = resolution.question;
  let chainTtl = 4294967295;
  const visited = new Set<string>();

  for (let depth = 0; depth <= 16; depth++) {
    if (visited.has(owner)) throw new Error("CNAME chain contains a cycle");
    visited.add(owner);

    const aliases = resolution.answers.filter(
      (answer) => answer.type === "CNAME" && answer.owner === owner,
    );

    if (!aliases.length) break;

    if (
      depth === 16 ||
      new Set(aliases.map((answer) => canonicalName(answer.value))).size !==
        1 ||
      resolution.answers.some(
        (answer) => answer.owner === owner && answer.type !== "CNAME",
      )
    ) {
      throw new Error("CNAME chain is invalid");
    }

    chainTtl = Math.min(chainTtl, ...aliases.map((answer) => answer.ttl));
    owner = canonicalName(aliases[0]!.value);
  }

  const leases = new Map<string, AddressLease>();

  for (const answer of resolution.answers.filter(
    (value) => value.owner === owner && value.type !== "CNAME",
  )) {
    const ttlSeconds = Math.min(answer.ttl, chainTtl);
    const address = canonicalIp(answer.value);

    const expiresAt = new Date(
      Date.parse(resolution.responseAt) +
        (ttlSeconds + policy.settings.dnsGraceSeconds) * 1000,
    ).toISOString();

    const existing = leases.get(address);

    if (!existing || Date.parse(existing.expiresAt) > Date.parse(expiresAt)) {
      leases.set(address, {
        path: context.path,
        clientIp: resolution.clientIp,
        address,
        question: resolution.question,
        responseAt: resolution.responseAt,
        ttlSeconds,
        expiresAt,
      });
    }
  }

  return [...leases.values()];
}

export function leaseKey(
  lease: Pick<AddressLease, "path" | "question" | "address">,
): string {
  return `${lease.path}|${lease.question}|${lease.address}`;
}

// The lease a permission was derived from.
export const permissionLeaseKey = (permission: Permission) =>
  `${permission.leasePath}|${permission.question}|${permission.address}`;

export function reconcileLeases(
  policy: Policy,
  leases: AddressLease[],
  now: number,
  changeGrace: boolean,
): AddressLease[] {
  const paths = new Set(scopeTree(policy).entries.map(ScopeTree.pathKey));

  return leases.flatMap((lease) => {
    if (Date.parse(lease.expiresAt) <= now) return [];

    // A lease belongs to the scope path its client had, not to the client: it ends when no address
    // has that path any more.
    if (!paths.has(lease.path)) return [];

    const expiresAt = changeGrace
      ? new Date(
          Date.parse(lease.responseAt) +
            (lease.ttlSeconds + policy.settings.dnsGraceSeconds) * 1000,
        ).toISOString()
      : lease.expiresAt;

    return Date.parse(expiresAt) <= now ? [] : [{ ...lease, expiresAt }];
  });
}

export function* iteratePermissionsForLeases(
  policy: Policy,
  leases: AddressLease[],
  now: number,
  index = new DnsRuleIndex(policy),
): Generator<Permission> {
  for (const lease of leases) {
    if (Date.parse(lease.expiresAt) <= now) continue;

    for (const { path, rules } of index.match(lease))
      for (const rule of rules) {
        // Native absolute timestamps have whole-second precision. Shorten the
        // permission rather than extending the DNS record's original lifetime.
        const deadline =
          Math.floor(
            Math.min(
              Date.parse(lease.expiresAt),
              rule.expiresAt ? Date.parse(rule.expiresAt) : Infinity,
            ) / 1000,
          ) * 1000;

        if (
          deadline <= now ||
          (rule.notBefore && deadline <= Date.parse(rule.notBefore))
        )
          continue;
        yield {
          path,
          leasePath: lease.path,
          ruleId: rule.id,
          address: lease.address,
          question: lease.question,
          responseAt: lease.responseAt,
          ttlSeconds: lease.ttlSeconds,
          expiresAt: new Date(deadline).toISOString(),
        };
      }
  }
}
