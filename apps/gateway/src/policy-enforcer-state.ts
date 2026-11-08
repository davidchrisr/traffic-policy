import type {
  Policy,
  AddressLease,
  Permission,
  GatewayReceipt,
} from "@traffic-policy/contracts";
import {
  DnsRuleIndex,
  iteratePermissionsForLeases,
} from "@traffic-policy/core";
import { ServiceError } from "@traffic-policy/core/io";
import { randomUUID } from "node:crypto";
import type { ObservedInstance } from "@traffic-policy/contracts/enforcement";

export interface Snapshot {
  policy: Policy;
  leases: AddressLease[];
  permissions: Permission[];
  receipt: GatewayReceipt | null;
}

export const DNS_STATE_LIMIT = 100000;

// Leases one instance may hold, so one client's lookups cannot fill the shared DNS_STATE_LIMIT.
export const DNS_INSTANCE_LEASE_LIMIT = 10000;

export function permissionsForLeases(
  policy: Policy,
  leases: AddressLease[],
  now: number,
  index = new DnsRuleIndex(policy),
): Permission[] {
  const permissions: Permission[] = [];

  for (const permission of iteratePermissionsForLeases(
    policy,
    leases,
    now,
    index,
  )) {
    if (permissions.length === DNS_STATE_LIMIT)
      throw new ServiceError(
        507,
        "dns_state_capacity",
        "DNS memory state exceeds its allocation. Reduce active resolutions or matching DNS rules.",
      );
    permissions.push(permission);
  }

  return permissions;
}

export function stateBytes(snapshot: Snapshot): bigint {
  const bytes = BigInt(Buffer.byteLength(JSON.stringify(snapshot))) + 1048576n;

  if (bytes > 67108864n)
    throw new ServiceError(
      507,
      "enforcement_state_capacity",
      "Enforcement state exceeds its reserved memory capacity",
    );

  return bytes;
}

export const permissionCount = (permissions: Permission[]) =>
  new Set(
    permissions.map(
      (value) => `${value.path}|${value.ruleId}|${value.address}`,
    ),
  ).size;

export function assertPermissionAllocation(
  permissions: Permission[],
  limit: number,
  existing: number,
) {
  const count = permissionCount(permissions);

  if (count > limit && count > existing)
    throw new ServiceError(
      507,
      "permission_capacity",
      "Live permission allocation is exhausted",
    );
}

export type ManagedInstanceView = Readonly<
  Omit<ObservedInstance, "addresses"> & { addresses: readonly string[] }
>;

export function instanceView(
  policy: Policy,
  previous: readonly ManagedInstanceView[] = [],
): readonly ManagedInstanceView[] {
  const earlier = new Map(previous.map((value) => [value.id, value]));

  return Object.freeze(
    policy.instances.map((instance) => {
      const prior = earlier.get(instance.id);

      const same =
        prior &&
        prior.addresses.length === instance.addresses.length &&
        instance.addresses.every((address) =>
          prior.addresses.includes(address),
        );

      return Object.freeze({
        ...instance,
        ownershipId: same ? prior.ownershipId : randomUUID(),
        addresses: Object.freeze([...instance.addresses]),
      });
    }),
  );
}
