import { expect, it } from "vitest";
import {
  policySchema,
  ruleSchema,
  type Policy,
  type AddressLease,
  type GatewayReceipt,
} from "@traffic-policy/contracts";
import { DnsRuleIndex, leaseKey, reconcileLeases } from "@traffic-policy/core";
import { dnsChains } from "@traffic-policy/core/nftables";
import { hashDocument } from "@traffic-policy/core/io";
import { DnsLedger } from "./dns-ledger.ts";
import { sequentialMarks } from "./test-native.ts";
import {
  permissionsForLeases,
  permissionCount,
  stateBytes,
  assertPermissionAllocation,
  type Snapshot,
} from "./policy-enforcer-state.ts";

const at = "2026-10-16T00:00:00.000Z",
  now = Date.parse(at);

const client = "11111111-1111-4111-8111-111111111111",
  other = "22222222-2222-4222-8222-222222222222";

function policy(limit = 4096): Policy {
  const common = {
    subject: { kind: "global" },
    direction: "both",
    peer: { kind: "any" },
    protocol: null,
    portStart: null,
    portEnd: null,
    icmpType: null,
    icmpCode: null,
    action: "block",
    priority: "normal",
    enabled: true,
    notBefore: null,
    expiresAt: null,
    dnsDestinations: null,
    createdAt: at,
    modifiedAt: at,
    reason: "東京",
  };

  return policySchema.parse({
    protocolVersion: 1,
    revision: "1",
    generatedAt: at,
    instances: [
      { id: client, name: "Client", addresses: ["10.0.0.1"] },
      { id: other, name: "Other", addresses: ["10.0.0.2"] },
    ],
    rules: [
      {
        ...common,
        id: "00000000-0000-4000-8000-000000000001",
        direction: "outgoing",
        peer: { kind: "domain", value: "example.com" },
        action: "allow",
        dnsDestinations: ["192.0.2.0/24", "2001:db8::/32"],
      },
      { ...common, id: "00000000-0000-4000-8000-000000000002" },
    ],
    settings: {
      dnsGraceSeconds: 0,
      permissionLimit: limit,
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

function receipt(value: Policy): GatewayReceipt {
  return {
    protocolVersion: 1,
    revision: value.revision,
    policyHash: hashDocument(value),
    bootId: client,
    appliedAt: at,
    permissions: 0,
  };
}

// The scope path of an instance's only host address.
const hostPath = (instance: string) => `4|${instance}@32`;

function lease(
  question: string,
  address = "192.0.2.10",
  time = now,
  ttl = 60,
  instance = client,
): AddressLease {
  return {
    path: hostPath(instance),
    clientIp: instance === client ? "10.0.0.1" : "10.0.0.2",
    question,
    address,
    responseAt: new Date(time).toISOString(),
    ttlSeconds: ttl,
    expiresAt: new Date(time + ttl * 1000).toISOString(),
  };
}

function open(value = policy(), leases: AddressLease[] = []) {
  return new DnsLedger(
    value,
    receipt(value),
    new DnsRuleIndex(value),
    leases,
    permissionsForLeases(value, leases, now),
    sequentialMarks(value),
  );
}

function reference(
  previous: Snapshot,
  incoming: AddressLease[],
  time: number,
): Snapshot {
  const values = new Map(
    reconcileLeases(previous.policy, previous.leases, time, false).map(
      (value) => [leaseKey(value), value],
    ),
  );

  for (const value of incoming) {
    const key = leaseKey(value),
      old = values.get(key);

    if (
      !old ||
      Date.parse(value.responseAt) > Date.parse(old.responseAt) ||
      (value.responseAt === old.responseAt &&
        Date.parse(value.expiresAt) < Date.parse(old.expiresAt))
    )
      values.set(key, value);
  }

  const leases = [...values.values()],
    permissions = permissionsForLeases(previous.policy, leases, time);

  assertPermissionAllocation(
    permissions,
    previous.policy.settings.permissionLimit,
    permissionCount(
      permissionsForLeases(previous.policy, previous.leases, time),
    ),
  );
  const result = { ...previous, leases, permissions };
  stateBytes(result);

  return result;
}

function image(value: Snapshot) {
  return {
    leases: value.leases.toSorted((a, b) =>
      leaseKey(a).localeCompare(leaseKey(b)),
    ),
    permissions: value.permissions.toSorted((a, b) =>
      `${leaseKey(a)}|${a.ruleId}`.localeCompare(`${leaseKey(b)}|${b.ruleId}`),
    ),
  };
}

it("stages changes without exposing them and accounts exact serialized bytes", () => {
  const ledger = open(),
    before = ledger.snapshot(),
    batch = ledger.begin(now);

  batch.stage([lease("a.example.com"), lease("b.example.com")], now);
  expect(ledger.snapshot()).toEqual(before);

  const expected = reference(
    before,
    [lease("a.example.com"), lease("b.example.com")],
    now,
  );

  expect(batch.serializedBytes).toBe(Number(stateBytes(expected)));
  expect(batch.chains(now)[0]!.bindings).toHaveLength(1);
  batch.commit();
  expect(image(ledger.snapshot())).toEqual(image(expected));
  expect(ledger.permissionCount(now)).toBe(1);
  expect(ledger.resolutionCount(now)).toBe(2);
  expect(ledger.serializedBytes).toBe(Number(stateBytes(ledger.snapshot())));
});

it("rolls back an invalid lookup while preserving previously staged work", () => {
  const ledger = open(policy(1)),
    batch = ledger.begin(now);

  batch.stage([lease("a.example.com")], now);
  const bytes = batch.serializedBytes;
  expect(() =>
    batch.stage(
      [
        lease("b.example.com", "192.0.2.11"),
        lease("c.example.com", "192.0.2.12"),
      ],
      now,
    ),
  ).toThrow("allocation is exhausted");
  expect(batch.serializedBytes).toBe(bytes);
  const undo = batch.stage([lease("b.example.com")], now);
  undo();
  expect(batch.serializedBytes).toBe(bytes);
  batch.commit();
  expect(ledger.leaseValues().map((value) => value.question)).toEqual([
    "a.example.com",
  ]);
  expect(ledger.permissionCount(now)).toBe(1);
});

it("keeps global-rule learned permissions separate for each instance", () => {
  const ledger = open(),
    batch = ledger.begin(now);

  batch.stage([lease("a.example.com")], now);
  batch.stage([lease("a.example.com", "192.0.2.10", now, 60, other)], now);
  expect(ledger.permissionCount(now)).toBe(0);
  const changes = batch.chains(now);
  expect(new Set(changes.map((chain) => chain.path))).toEqual(
    new Set([hostPath(client), hostPath(other)]),
  );
  batch.commit();
  expect(ledger.permissionCount(now)).toBe(2);
  expect(ledger.grants.size).toBe(2);
  expect(ledger.leases.size).toBe(2);
});

it("rebuilds permissions a nested client learned through its containing instance's rule", () => {
  const base = policy();
  const subnet = "33333333-3333-4333-8333-333333333333";

  const value = policySchema.parse({
    ...base,
    instances: [
      ...base.instances,
      { id: subnet, name: "Subnet", addresses: ["10.0.0.0/24"] },
    ],
    rules: base.rules.map((rule) =>
      rule.action === "allow"
        ? { ...rule, subject: { kind: "instance", instanceId: subnet } }
        : rule,
    ),
  });

  const path = `4|${subnet}@24|${client}@32`;
  const ledger = open(value, [{ ...lease("a.example.com"), path }]);

  expect(ledger.permissionCount(now)).toBe(1);
  expect(
    ledger.snapshot().permissions.map((permission) => permission.path),
  ).toEqual([path]);
});

it("holds an answer in the other family on the instance's paths there and restores it from its lease", () => {
  const base = policy();

  const value = policySchema.parse({
    ...base,
    instances: [
      { ...base.instances[0]!, addresses: ["10.0.0.1", "fd00::1"] },
      base.instances[1]!,
    ],
  });

  const ledger = open(value),
    batch = ledger.begin(now);

  batch.stage([lease("a.example.com", "2001:db8::10")], now);
  expect(batch.chains(now).map((chain) => [chain.path, chain.family])).toEqual([
    [`6|${client}@128`, 6],
  ]);
  batch.commit();

  const { leases, permissions } = ledger.snapshot();

  expect(permissions.map(({ path, leasePath }) => [path, leasePath])).toEqual([
    [`6|${client}@128`, hostPath(client)],
  ]);
  expect(open(value, leases).permissionCount(now)).toBe(1);
});

it("refuses to confirm a permission that has no chain to hold it", () => {
  const value = policy();

  // An index from another policy derives a permission for a rule the ledger's policy lacks.
  const other = policySchema.parse({
    ...value,
    rules: [
      {
        ...value.rules[0]!,
        id: "00000000-0000-4000-8000-000000000003",
      },
      ...value.rules,
    ],
  });

  const ledger = new DnsLedger(
    value,
    receipt(value),
    new DnsRuleIndex(other),
    [],
    [],
    sequentialMarks(value),
  );

  const batch = ledger.begin(now);
  batch.stage([lease("a.example.com")], now);
  expect(() => batch.chains(now)).toThrow(
    "DNS permission has no enforcement chain",
  );
});

it("retains shared-IP support when the longest contribution shortens or expires", () => {
  const ledger = open(),
    first = ledger.begin(now);

  first.stage(
    [
      lease("a.example.com", "192.0.2.10", now, 10),
      lease("b.example.com", "192.0.2.10", now, 20),
    ],
    now,
  );
  first.chains(now);
  first.commit();
  const second = ledger.begin(now + 1000);
  second.stage(
    [lease("b.example.com", "192.0.2.10", now + 1000, 1)],
    now + 1000,
  );
  expect(
    ledger.permissionDeadline(
      hostPath(client),
      ledger.policy.rules[0]!.id,
      "192.0.2.10",
    ),
  ).toBe(now + 20000);
  expect(second.chains(now + 1000)[0]!.bindings[0]!.expiresAt).toBe(
    new Date(now + 10000).toISOString(),
  );
  second.commit();
  expect(ledger.permissionCount(now + 2000)).toBe(1);
  expect(ledger.resolutionCount(now + 2000)).toBe(1);
  const expired = ledger.begin(now + 2000);
  expired.chains(now + 2000);
  expired.commit();
  expect(ledger.leaseValues().map((value) => value.question)).toEqual([
    "a.example.com",
  ]);
  expect(ledger.serializedBytes).toBe(Number(stateBytes(ledger.snapshot())));
  expect(ledger.permissionCount(now + 10000)).toBe(0);
  const empty = ledger.begin(now + 10000);
  empty.chains(now + 10000);
  empty.commit();
  expect(ledger.leases.size).toBe(0);
});

it("expires rule contributions without discarding their still-valid learned answers", () => {
  const value = policy();
  value.rules[0]!.expiresAt = new Date(now + 3000).toISOString();

  const ledger = open(value),
    batch = ledger.begin(now);

  batch.stage([lease("a.example.com")], now);
  batch.chains(now);
  batch.commit();
  expect(ledger.permissionCount(now + 4000)).toBe(0);
  expect(ledger.resolutionCount(now + 4000)).toBe(1);
  const expired = ledger.begin(now + 4000);
  expired.chains(now + 4000);
  expired.commit();
  expect(ledger.snapshot().permissions).toEqual([]);
  expect(ledger.leases.size).toBe(1);
  expect(ledger.serializedBytes).toBe(Number(stateBytes(ledger.snapshot())));
});

it("agrees with the former full-state path across refreshes, expiry and rejected allocations", () => {
  const value = policy(7),
    ledger = open(value);

  let expected = ledger.snapshot();

  for (let group = 0; group < 12; group++) {
    const time = now + group * 500,
      batch = ledger.begin(time);

    let accepted = 0;

    for (let n = 0; n < 8; n++) {
      const number = group * 8 + n,
        incoming = [
          lease(
            `q${number % 13}.example.com`,
            number % 3 === 0 ? "2001:db8::10" : `192.0.2.${10 + (number % 8)}`,
            time,
            number % 4 === 0 ? 1 : 60,
            number % 5 === 0 ? other : client,
          ),
        ];

      let next: Snapshot;

      try {
        next = reference(expected, incoming, time);
      } catch {
        expect(() => batch.stage(incoming, time)).toThrow();
        continue;
      }

      batch.stage(incoming, time);
      expected = next;
      accepted++;
      expect(batch.serializedBytes).toBe(Number(stateBytes(expected)));
    }

    if (!accepted) continue;
    expected = reference(expected, [], time);

    const before = dnsChains(
        value,
        ledger.snapshot().permissions,
        sequentialMarks(value),
      ),
      after = dnsChains(value, expected.permissions, sequentialMarks(value));

    const changed = after.filter(
      (chain) =>
        hashDocument(chain.bindings) !==
        hashDocument(before.find((old) => old.name === chain.name)?.bindings),
    );

    expect(batch.chains(time)).toEqual(changed);
    batch.commit();
    expect(image(ledger.snapshot())).toEqual(image(expected));
    expect(ledger.serializedBytes).toBe(Number(stateBytes(expected)));
  }
});

it("bounds multiplied contributions without changing confirmed state", () => {
  const value = policy();
  value.rules.push(
    ruleSchema.parse({
      ...value.rules[0]!,
      id: "00000000-0000-4000-8000-000000000003",
    }),
  );

  const values = Array.from({ length: 50000 }, (_, n) =>
      lease(`q${n}.example.com`),
    ),
    ledger = open(value, values),
    batch = ledger.begin(now);

  expect(() => batch.stage([lease("new.example.com")], now)).toThrow(
    "DNS memory state exceeds",
  );
  expect(ledger.leases.size).toBe(50000);
  expect(ledger.associations).toBe(100000);
}, 15000);

it("enforces the exact state-byte boundary without committing a rejected answer", () => {
  const value = policy(),
    empty = open(value),
    long = `${"a".repeat(60)}.${"b".repeat(60)}.${"c".repeat(60)}.example.com`;

  const sample = lease(`q000000.${long}`),
    permission = permissionsForLeases(value, [sample], now)[0]!;

  const perEntry =
    Buffer.byteLength(JSON.stringify(sample)) +
    Buffer.byteLength(JSON.stringify(permission)) +
    2;

  const count = Math.floor((67108864 - empty.baseBytes + 2) / perEntry);
  expect(count).toBeLessThan(100000);

  const values = Array.from({ length: count }, (_, n) =>
      lease(`q${String(n).padStart(6, "0")}.${long}`),
    ),
    ledger = open(value, values),
    batch = ledger.begin(now);

  expect(ledger.serializedBytes).toBeLessThanOrEqual(67108864);
  expect(ledger.serializedBytes).toBe(Number(stateBytes(ledger.snapshot())));
  expect(() =>
    batch.stage([lease(`q${String(count).padStart(6, "0")}.${long}`)], now),
  ).toThrow("reserved memory capacity");
  expect(batch.serializedBytes).toBe(ledger.serializedBytes);
  expect(ledger.leases.size).toBe(count);
}, 20000);
