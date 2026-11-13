import ipaddr from "ipaddr.js";

// A canonical address or network as an inclusive integer range in its family.
export interface NetworkRange {
  readonly family: 4 | 6;
  readonly prefix: number;
  readonly start: bigint;
  readonly end: bigint;
}

const toInteger = (bytes: number[]) =>
  bytes.reduce((value, byte) => (value << 8n) | BigInt(byte), 0n);

export function networkRange(value: string): NetworkRange {
  const [address, length] = value.includes("/")
    ? ipaddr.parseCIDR(value)
    : [ipaddr.process(value), null];

  const family = address.kind() === "ipv4" ? 4 : 6;
  const bits = family === 4 ? 32 : 128;
  const prefix = length ?? bits;
  const host = (1n << BigInt(bits - prefix)) - 1n;
  const start = toInteger(address.toByteArray()) & ~host;

  return { family, prefix, start, end: start | host };
}

// An address as an integer in its family.
export interface AddressInteger {
  family: 4 | 6;
  value: bigint;
}

export function addressInteger(value: string): AddressInteger {
  const address = ipaddr.process(value);

  return {
    family: address.kind() === "ipv4" ? 4 : 6,
    value: toInteger(address.toByteArray()),
  };
}

export function integerAddress(family: 4 | 6, value: bigint): string {
  const bytes: number[] = [];

  for (let index = family === 4 ? 4 : 16; index > 0; index--) {
    bytes.unshift(Number(value & 0xffn));
    value >>= 8n;
  }

  return ipaddr.fromByteArray(bytes).toString();
}

// One instance address or address-rule subject. An address rule's scope is its own canonical
// value; an instance's is its ID.
export interface ScopeEntry extends NetworkRange {
  readonly network: string;
  readonly scope: string;
  readonly instanceId: string | null;
  // The rule sets attached to the entry's instance; none on an address-rule entry.
  readonly sets: readonly string[];
  readonly parent: ScopeEntry | null;
  readonly children: readonly ScopeEntry[];
}

interface MutableEntry extends NetworkRange {
  network: string;
  scope: string;
  instanceId: string | null;
  sets: readonly string[];
  parent: MutableEntry | null;
  children: MutableEntry[];
}

// A rule set as the tree reads it.
export interface ScopeRuleSet {
  readonly id: string;
  readonly members:
    | { readonly kind: "global" }
    | { readonly kind: "instances"; readonly instanceIds: readonly string[] };
}

const NO_SETS: readonly string[] = [];

// Instance addresses and address-rule subjects. CIDRs either nest or are disjoint, so the entries
// form a tree: an address belongs to every entry on the path from its root entry to its most
// specific one. Rule sets are no part of the tree's shape: each entry lists the sets attached to
// its instance, and paths and their keys stay the same whatever is attached.
export class ScopeTree {
  readonly entries: readonly ScopeEntry[];
  // The rule sets attached to every instance.
  readonly universal: readonly string[];
  // Validation problems; a policy with any is rejected.
  readonly problems: readonly string[];
  private readonly families: Record<4 | 6, MutableEntry[]> = { 4: [], 6: [] };

  constructor(
    instances: readonly { id: string; addresses: readonly string[] }[],
    addresses: Iterable<string> = [],
    ruleSets: readonly ScopeRuleSet[] = [],
  ) {
    const problems = new Set<string>();
    const networks = new Map<string, MutableEntry>();
    const attached = new Map<string, string[]>();

    for (const { id, members } of ruleSets)
      if (members.kind === "instances")
        for (const instanceId of members.instanceIds) {
          const sets = attached.get(instanceId);

          if (sets) sets.push(id);
          else attached.set(instanceId, [id]);
        }

    this.universal = ruleSets.flatMap(({ id, members }) =>
      members.kind === "global" ? [id] : [],
    );

    const add = (network: string, scope: string, instanceId: string | null) => {
      const entry: MutableEntry = {
        ...networkRange(network),
        network,
        scope,
        instanceId,
        sets: (instanceId && attached.get(instanceId)) || NO_SETS,
        parent: null,
        children: [],
      };

      networks.set(network, entry);
      this.families[entry.family].push(entry);
    };

    for (const instance of instances)
      for (const address of instance.addresses) {
        if (networks.has(address))
          problems.add("An address belongs to multiple instances");
        else add(address, instance.id, instance.id);
      }

    for (const address of addresses) {
      const existing = networks.get(address);

      if (existing?.instanceId)
        problems.add(
          `Address rule ${address} names an instance address; use the instance`,
        );
      else if (!existing) add(address, address, null);
    }

    for (const family of [4, 6] as const) {
      const sorted = this.families[family];

      sorted.sort((left, right) =>
        left.start === right.start
          ? left.prefix - right.prefix
          : left.start < right.start
            ? -1
            : 1,
      );

      const open: MutableEntry[] = [];

      for (const entry of sorted) {
        while (open.length && open.at(-1)!.end < entry.start) open.pop();
        const parent = open.at(-1) ?? null;

        entry.parent = parent;
        parent?.children.push(entry);
        open.push(entry);

        if (!entry.instanceId && !instanceAncestor(entry))
          problems.add(
            `Address rule ${entry.network} is outside every instance`,
          );
      }
    }

    this.entries = [...this.families[4], ...this.families[6]];
    this.problems = [...problems];
  }

  // The most specific entry containing a canonical address, or null when none does.
  find(address: string): ScopeEntry | null {
    const { family, value } = addressInteger(address);
    const sorted = this.families[family];

    let low = 0,
      high = sorted.length - 1,
      found = -1;

    while (low <= high) {
      const middle = (low + high) >>> 1;

      if (sorted[middle]!.start <= value) {
        found = middle;
        low = middle + 1;
      } else high = middle - 1;
    }

    // The last entry starting at or before the address contains it or has an ancestor that does.
    for (
      let entry = found < 0 ? null : sorted[found]!;
      entry;
      entry = entry.parent
    )
      if (entry.end >= value) return entry;

    return null;
  }

  // The entries from the root to `entry`.
  static path(entry: ScopeEntry): ScopeEntry[] {
    const path: ScopeEntry[] = [];

    for (
      let current: ScopeEntry | null = entry;
      current;
      current = current.parent
    )
      path.unshift(current);

    return path;
  }

  // Identifies the entry's family and complete path of scopes; addresses with equal keys inherit
  // the same rules.
  static pathKey(entry: ScopeEntry): string {
    return `${entry.family}|${ScopeTree.path(entry)
      .map((value) => `${value.scope}@${value.prefix}`)
      .join("|")}`;
  }

  // The most specific instance on the entry's path.
  static instanceOf(entry: ScopeEntry): string {
    return instanceAncestor(entry)!.instanceId!;
  }

  // Every scope whose rules apply at the entry: the scopes on its path and the rule sets attached
  // to them or to every instance.
  static scopes(tree: ScopeTree, entry: ScopeEntry): Set<string> {
    const scopes = new Set(tree.universal);

    for (
      let current: ScopeEntry | null = entry;
      current;
      current = current.parent
    ) {
      scopes.add(current.scope);

      for (const id of current.sets) scopes.add(id);
    }

    return scopes;
  }
}

function instanceAncestor(entry: ScopeEntry): ScopeEntry | null {
  for (
    let current: ScopeEntry | null = entry;
    current;
    current = current.parent
  )
    if (current.instanceId) return current;

  return null;
}
