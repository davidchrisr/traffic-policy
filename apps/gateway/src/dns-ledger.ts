import type {
  AddressLease,
  Permission,
  GatewayReceipt,
  Policy,
} from "@traffic-policy/contracts";
import { ScopeTree } from "@traffic-policy/contracts";
import {
  DnsRuleIndex,
  iteratePermissionsForLeases,
  leaseKey,
  permissionLeaseKey,
} from "@traffic-policy/core";
import {
  dnsChains,
  type DnsChain,
  type MarkAssignments,
} from "@traffic-policy/core/nftables";
import { ServiceError } from "@traffic-policy/core/io";
import {
  DNS_INSTANCE_LEASE_LIMIT,
  DNS_STATE_LIMIT,
  stateBytes,
  type Snapshot,
} from "./policy-enforcer-state.ts";
import { Deadlines } from "./deadlines.ts";

interface Contribution {
  value: Permission;
  bytes: number;
  deadline: number;
  leaseKey: string;
}

interface Learned {
  key: string;
  value: AddressLease;
  bytes: number;
  deadline: number;
  permissions: Map<string, Contribution>;
  permissionBytes: number;
}

interface Grant {
  key: string;
  // The grant's chain group: holding path, rule, and family.
  group: string;
  address: string;
  sources: Map<string, Contribution>;
  deadline: number;
}

interface GrantChange {
  base: Grant;
  sources: Map<string, Contribution | null>;
  size: number;
  deadline: number;
}

const bytes = (value: AddressLease | Permission) =>
  Buffer.byteLength(JSON.stringify(value));

const grantKey = (value: Permission) =>
  `${value.path}|${value.ruleId}|${value.address}`;

// A lease's permissions, one for each holding path and rule.
const bindingKey = (value: Permission) => `${value.path}|${value.ruleId}`;

const groupKey = (path: string, rule: string, family: number) =>
  `${path}|${rule}|${family}`;

const stateError = () =>
  new ServiceError(
    507,
    "dns_state_capacity",
    "DNS memory state exceeds its allocation. Reduce active resolutions or matching DNS rules.",
  );

const instanceStateError = () =>
  new ServiceError(
    507,
    "dns_instance_capacity",
    "This instance holds its full allocation of DNS answers. Reduce its active resolutions.",
  );

const assertBytes = (value: number) => {
  if (value > 67108864)
    throw new ServiceError(
      507,
      "enforcement_state_capacity",
      "Enforcement state exceeds its reserved memory capacity",
    );
};

export class DnsLedger {
  readonly leases = new Map<string, Learned>();
  readonly grants = new Map<string, Grant>();
  readonly groups = new Map<string, Map<string, Grant>>();
  readonly templates = new Map<string, DnsChain[]>();
  readonly leaseDeadlines = new Deadlines<Learned>();
  readonly permissionDeadlines = new Deadlines<Contribution>();
  readonly grantDeadlines = new Deadlines<Grant>();
  // Leases held by each instance, through the scope paths of its addresses.
  readonly instanceLeases = new Map<string, number>();
  private readonly pathInstances = new Map<string, string>();
  readonly baseBytes: number;
  leaseBytes = 0;
  permissionBytes = 0;
  associations = 0;
  private stats: {
    at: number;
    leases: number;
    grants: number;
    leaseCursor: ReturnType<Deadlines<Learned>["cursor"]>;
    grantCursor: ReturnType<Deadlines<Grant>["cursor"]>;
  } | null = null;

  constructor(
    readonly policy: Policy,
    readonly receipt: GatewayReceipt,
    readonly index: DnsRuleIndex,
    initial: AddressLease[],
    permissions: Permission[],
    marks: MarkAssignments,
  ) {
    this.baseBytes = Number(
      stateBytes({ policy, receipt, leases: [], permissions: [] }),
    );

    for (const entry of index.tree.entries)
      this.pathInstances.set(
        ScopeTree.pathKey(entry),
        ScopeTree.instanceOf(entry),
      );

    for (const value of initial) {
      const key = leaseKey(value);

      const entry: Learned = {
        key,
        value,
        bytes: bytes(value),
        deadline: Date.parse(value.expiresAt),
        permissions: new Map(),
        permissionBytes: 0,
      };

      this.leases.set(key, entry);
      this.leaseBytes += entry.bytes;
      this.leaseDeadlines.set(entry, entry.deadline);
      const instance = this.instanceOf(value);
      this.instanceLeases.set(
        instance,
        (this.instanceLeases.get(instance) ?? 0) + 1,
      );
    }

    for (const value of permissions) {
      const key = permissionLeaseKey(value),
        entry = this.leases.get(key);

      if (!entry) throw new Error("Permission has no learned DNS answer");

      const contribution: Contribution = {
        value,
        bytes: bytes(value),
        deadline: Date.parse(value.expiresAt),
        leaseKey: key,
      };

      entry.permissions.set(bindingKey(value), contribution);
      entry.permissionBytes += contribution.bytes;
      this.permissionBytes += contribution.bytes;
      this.associations++;
      this.permissionDeadlines.set(contribution, contribution.deadline);
      const identity = grantKey(value);
      let grant = this.grants.get(identity);

      if (!grant) {
        grant = this.emptyGrant(value);
        this.grants.set(identity, grant);
        let group = this.groups.get(grant.group);

        if (!group) {
          group = new Map();
          this.groups.set(grant.group, group);
        }

        group.set(grant.address, grant);
      }

      grant.sources.set(key, contribution);
      grant.deadline = Math.max(grant.deadline, contribution.deadline);
      this.grantDeadlines.set(grant, grant.deadline);
    }

    for (const template of dnsChains(policy, [], marks)) {
      const group = groupKey(template.path, template.ruleId, template.family);

      const list = this.templates.get(group) ?? [];
      list.push(template);
      this.templates.set(group, list);
    }

    assertBytes(this.serializedBytes);

    if (
      this.leases.size > DNS_STATE_LIMIT ||
      this.associations > DNS_STATE_LIMIT
    )
      throw stateError();
  }
  // Leases are reconciled to the policy's scope paths, so a lease without one is a defect.
  instanceOf(lease: AddressLease): string {
    const instance = this.pathInstances.get(lease.path);

    if (instance === undefined) throw new Error("DNS lease has no scope path");

    return instance;
  }
  emptyGrant(value: Permission): Grant {
    return {
      key: grantKey(value),
      group: groupKey(
        value.path,
        value.ruleId,
        value.address.includes(":") ? 6 : 4,
      ),
      address: value.address,
      sources: new Map(),
      deadline: 0,
    };
  }
  get serializedBytes() {
    return (
      this.baseBytes +
      this.leaseBytes +
      this.permissionBytes +
      Math.max(0, this.leases.size - 1) +
      Math.max(0, this.associations - 1)
    );
  }
  private live(now: number) {
    if (!this.stats || now < this.stats.at)
      this.stats = {
        at: now,
        leases: 0,
        grants: 0,
        leaseCursor: this.leaseDeadlines.cursor(),
        grantCursor: this.grantDeadlines.cursor(),
      };
    const stats = this.stats;
    stats.at = now;
    stats.leaseCursor.drain(now, () => stats.leases++);
    stats.grantCursor.drain(now, () => stats.grants++);

    return {
      leases: this.leases.size - stats.leases,
      grants: this.grants.size - stats.grants,
    };
  }
  permissionCount(now: number) {
    return this.live(now).grants;
  }
  resolutionCount(now: number) {
    return this.live(now).leases;
  }
  permissionDeadline(path: string, rule: string, address: string) {
    return this.grants.get(`${path}|${rule}|${address}`)?.deadline ?? 0;
  }
  leaseValues() {
    return [...this.leases.values()].map((entry) => entry.value);
  }
  snapshot(): Snapshot {
    return {
      policy: this.policy,
      receipt: this.receipt,
      leases: this.leaseValues(),
      permissions: [...this.leases.values()].flatMap((entry) =>
        [...entry.permissions.values()].map((permission) => permission.value),
      ),
    };
  }
  begin(now: number) {
    return new DnsBatch(this, now);
  }
  invalidate() {
    this.stats = null;
  }
}

export class DnsBatch {
  private readonly changes = new Map<string, Learned | null>();
  private readonly grantChanges = new Map<string, GrantChange>();
  private readonly groups = new Map<string, Map<string, GrantChange>>();
  private readonly leaseCursor;
  private readonly permissionCursor;
  private readonly leaseDeadlines = new Deadlines<Learned>();
  private readonly permissionDeadlines = new Deadlines<Contribution>();
  private leaseBytes: number;
  private permissionBytes: number;
  private leases: number;
  // Each instance's lease count change from the ledger's.
  private readonly instanceLeases = new Map<string, number>();
  private associations: number;
  private grants: number;

  constructor(
    private readonly base: DnsLedger,
    now: number,
  ) {
    this.leaseCursor = base.leaseDeadlines.cursor();
    this.permissionCursor = base.permissionDeadlines.cursor();
    this.leaseBytes = base.leaseBytes;
    this.permissionBytes = base.permissionBytes;
    this.leases = base.leases.size;
    this.associations = base.associations;
    this.grants = base.grants.size;
    this.expire(now);
  }
  get serializedBytes() {
    return (
      this.base.baseBytes +
      this.leaseBytes +
      this.permissionBytes +
      Math.max(0, this.leases - 1) +
      Math.max(0, this.associations - 1)
    );
  }
  lease(key: string) {
    return this.changes.has(key)
      ? (this.changes.get(key) ?? null)
      : (this.base.leases.get(key) ?? null);
  }
  private grant(value: Permission) {
    const key = grantKey(value);
    let change = this.grantChanges.get(key);

    if (!change) {
      const base = this.base.grants.get(key) ?? this.base.emptyGrant(value);
      change = {
        base,
        sources: new Map(),
        size: base.sources.size,
        deadline: base.deadline,
      };
      this.grantChanges.set(key, change);
      let group = this.groups.get(base.group);

      if (!group) {
        group = new Map();
        this.groups.set(base.group, group);
      }

      group.set(base.address, change);
    }

    return change;
  }
  private changeSource(
    key: string,
    old: Contribution | null,
    next: Contribution | null,
    now: number,
  ) {
    if (old === next) return;

    const change = this.grant((next ?? old)!.value),
      wasLive = change.size > 0;

    if ((change.base.sources.get(key) ?? null) === next)
      change.sources.delete(key);
    else change.sources.set(key, next);
    change.size += Number(next !== null) - Number(old !== null);

    if (!change.size) change.deadline = 0;
    else if (next && next.deadline >= change.deadline)
      change.deadline = next.deadline;
    else if (old?.deadline === change.deadline) {
      change.deadline = 0;

      for (const [source, value] of change.base.sources) {
        const active = change.sources.has(source)
          ? change.sources.get(source)
          : value;

        if (active && active.deadline > now)
          change.deadline = Math.max(change.deadline, active.deadline);
      }

      for (const [source, value] of change.sources)
        if (!change.base.sources.has(source) && value && value.deadline > now)
          change.deadline = Math.max(change.deadline, value.deadline);
    }

    this.grants += Number(change.size > 0) - Number(wasLive);

    if (!change.sources.size) {
      this.grantChanges.delete(change.base.key);
      const group = this.groups.get(change.base.group);
      group?.delete(change.base.address);

      if (!group?.size) this.groups.delete(change.base.group);
    }
  }
  private countInstance(lease: AddressLease, change: number) {
    const instance = this.base.instanceOf(lease);
    this.instanceLeases.set(
      instance,
      (this.instanceLeases.get(instance) ?? 0) + change,
    );
  }
  private instanceCount(instance: string) {
    return (
      (this.base.instanceLeases.get(instance) ?? 0) +
      (this.instanceLeases.get(instance) ?? 0)
    );
  }
  private replace(key: string, next: Learned | null, now: number) {
    const old = this.lease(key);

    if (old === next) return;

    // A lease keeps its key, and so its scope path and instance, when replaced.
    if (!old) this.countInstance(next!.value, 1);
    else if (!next) this.countInstance(old.value, -1);

    if (old) {
      this.leaseBytes -= old.bytes;
      this.permissionBytes -= old.permissionBytes;
      this.associations -= old.permissions.size;
      this.leases--;
      this.leaseDeadlines.delete(old);

      for (const permission of old.permissions.values())
        this.permissionDeadlines.delete(permission);
    }

    if (next) {
      this.leaseBytes += next.bytes;
      this.permissionBytes += next.permissionBytes;
      this.associations += next.permissions.size;
      this.leases++;
    }

    for (const [binding, permission] of old?.permissions ?? [])
      this.changeSource(
        key,
        permission,
        next?.permissions.get(binding) ?? null,
        now,
      );

    for (const [binding, permission] of next?.permissions ?? [])
      if (!old?.permissions.has(binding))
        this.changeSource(key, null, permission, now);

    if (next === (this.base.leases.get(key) ?? null)) this.changes.delete(key);
    else {
      this.changes.set(key, next);

      if (next) {
        this.leaseDeadlines.set(next, next.deadline);

        for (const permission of next.permissions.values())
          this.permissionDeadlines.set(permission, permission.deadline);
      }
    }
  }
  expire(now: number) {
    const expireLease = (entry: Learned) => {
      if (this.lease(entry.key) === entry) this.replace(entry.key, null, now);
    };

    this.leaseCursor.drain(now, expireLease);
    this.leaseDeadlines.drain(now, expireLease);
    const expired = new Map<string, Set<Contribution>>();

    const expirePermission = (entry: Contribution) => {
      if (
        this.lease(entry.leaseKey)?.permissions.get(bindingKey(entry.value)) !==
        entry
      )
        return;
      let values = expired.get(entry.leaseKey);

      if (!values) {
        values = new Set();
        expired.set(entry.leaseKey, values);
      }

      values.add(entry);
    };

    this.permissionCursor.drain(now, expirePermission);
    this.permissionDeadlines.drain(now, expirePermission);

    for (const [key, values] of expired) {
      const old = this.lease(key);

      if (!old) continue;
      const permissions = new Map(old.permissions);
      let permissionBytes = old.permissionBytes;

      for (const value of values) {
        permissions.delete(bindingKey(value.value));
        permissionBytes -= value.bytes;
      }

      this.replace(key, { ...old, permissions, permissionBytes }, now);
    }
  }
  selected(value: AddressLease) {
    const old = this.lease(leaseKey(value));

    return !old ||
      Date.parse(value.responseAt) > Date.parse(old.value.responseAt) ||
      (value.responseAt === old.value.responseAt &&
        Date.parse(value.expiresAt) < old.deadline)
      ? value
      : old.value;
  }
  stage(incoming: AddressLease[], now: number) {
    this.expire(now);

    const existing = this.grants,
      replacements = new Map<string, AddressLease>();

    for (const value of incoming)
      if (this.selected(value) === value)
        replacements.set(leaseKey(value), value);
    let retained = this.associations;
    let retainedBytes = this.permissionBytes;
    let plannedLeaseBytes = this.leaseBytes;
    let plannedLeases = this.leases;
    const plannedInstances = new Map<string, number>();

    for (const [key, value] of replacements) {
      const old = this.lease(key);
      retained -= old?.permissions.size ?? 0;
      retainedBytes -= old?.permissionBytes ?? 0;
      plannedLeaseBytes += bytes(value) - (old?.bytes ?? 0);

      if (!old) {
        plannedLeases++;
        const instance = this.base.instanceOf(value);
        plannedInstances.set(
          instance,
          (plannedInstances.get(instance) ?? 0) + 1,
        );
      }
    }

    if (plannedLeases > DNS_STATE_LIMIT) throw stateError();
    const prepared = new Map<string, Learned>();
    let added = 0;
    let addedBytes = 0;

    const checkBytes = () =>
      assertBytes(
        this.base.baseBytes +
          plannedLeaseBytes +
          retainedBytes +
          addedBytes +
          Math.max(0, plannedLeases - 1) +
          Math.max(0, retained + added - 1),
      );

    checkBytes();

    for (const [key, value] of replacements) {
      const entry: Learned = {
        key,
        value,
        bytes: bytes(value),
        deadline: Date.parse(value.expiresAt),
        permissions: new Map(),
        permissionBytes: 0,
      };

      for (const permission of iteratePermissionsForLeases(
        this.base.policy,
        [value],
        now,
        this.base.index,
      )) {
        if (retained + added === DNS_STATE_LIMIT) throw stateError();

        const contribution: Contribution = {
          value: permission,
          bytes: bytes(permission),
          deadline: Date.parse(permission.expiresAt),
          leaseKey: key,
        };

        entry.permissions.set(bindingKey(permission), contribution);
        entry.permissionBytes += contribution.bytes;
        added++;
        addedBytes += contribution.bytes;
        checkBytes();
      }

      prepared.set(key, entry);
    }

    // Refreshing a held lease adds none, so an instance at its allocation keeps its answers.
    for (const [instance, added] of plannedInstances)
      if (this.instanceCount(instance) + added > DNS_INSTANCE_LEASE_LIMIT)
        throw instanceStateError();

    const undo = new Map<string, Learned | null>();

    const restore = () => {
      for (const [key, entry] of undo) this.replace(key, entry, now);
    };

    try {
      for (const [key, entry] of prepared) {
        undo.set(key, this.lease(key));
        this.replace(key, entry, now);
      }

      this.assert(existing);
    } catch (error) {
      restore();
      throw error;
    }

    return restore;
  }
  private assert(existing: number) {
    if (this.leases > DNS_STATE_LIMIT || this.associations > DNS_STATE_LIMIT)
      throw stateError();

    if (
      this.grants > this.base.policy.settings.permissionLimit &&
      this.grants > existing
    )
      throw new ServiceError(
        507,
        "permission_capacity",
        "Live permission allocation is exhausted",
      );
    assertBytes(this.serializedBytes);
  }
  chains(now: number): DnsChain[] {
    this.expire(now);
    this.assert(this.base.permissionCount(now));
    const result: DnsChain[] = [];

    for (const [group, changes] of this.groups) {
      if (
        ![...changes.values()].some(
          (change) =>
            change.deadline !==
            (this.base.grants.get(change.base.key)?.deadline ?? 0),
        )
      )
        continue;
      const templates = this.base.templates.get(group);

      // Permissions bind only where the policy has DNS chains, so a missing one is a defect;
      // confirming the answer without it would report access that is not installed.
      if (!templates)
        throw new Error("DNS permission has no enforcement chain");
      const bindings = new Map<string, number>();

      for (const grant of this.base.groups.get(group)?.values() ?? [])
        bindings.set(grant.address, grant.deadline);

      for (const [address, change] of changes)
        if (change.size) bindings.set(address, change.deadline);
        else bindings.delete(address);

      const values = [...bindings]
        .filter(([, deadline]) => deadline > now)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([address, deadline]) => ({
          address,
          expiresAt: new Date(deadline).toISOString(),
        }));

      for (const template of templates)
        result.push({ ...template, bindings: values });
    }

    return result;
  }
  commit() {
    for (const [key, next] of this.changes) {
      const old = this.base.leases.get(key);

      if (old) {
        this.base.leaseDeadlines.delete(old);

        for (const permission of old.permissions.values())
          this.base.permissionDeadlines.delete(permission);
      }

      if (next) {
        this.base.leases.set(key, next);
        this.base.leaseDeadlines.set(next, next.deadline);

        for (const permission of next.permissions.values())
          this.base.permissionDeadlines.set(permission, permission.deadline);
      } else this.base.leases.delete(key);
    }

    for (const change of this.grantChanges.values()) {
      const grant = change.base;

      for (const [key, value] of change.sources)
        if (value) grant.sources.set(key, value);
        else grant.sources.delete(key);
      grant.deadline = change.deadline;

      if (!grant.sources.size) {
        this.base.grants.delete(grant.key);
        this.base.grantDeadlines.delete(grant);
        const group = this.base.groups.get(grant.group);
        group?.delete(grant.address);

        if (!group?.size) this.base.groups.delete(grant.group);
      } else {
        this.base.grants.set(grant.key, grant);
        this.base.grantDeadlines.set(grant, grant.deadline);
        let group = this.base.groups.get(grant.group);

        if (!group) {
          group = new Map();
          this.base.groups.set(grant.group, group);
        }

        group.set(grant.address, grant);
      }
    }

    for (const [instance, change] of this.instanceLeases) {
      const count = (this.base.instanceLeases.get(instance) ?? 0) + change;

      if (count) this.base.instanceLeases.set(instance, count);
      else this.base.instanceLeases.delete(instance);
    }

    this.base.leaseBytes = this.leaseBytes;
    this.base.permissionBytes = this.permissionBytes;
    this.base.associations = this.associations;
    this.base.invalidate();
  }
}
