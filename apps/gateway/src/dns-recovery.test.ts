import { expect, it, vi, afterEach } from "vitest";
import {
  mkdir,
  mkdtemp,
  readFile,
  writeFile,
  readdir,
  rm,
} from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import {
  policySchema,
  ruleSchema,
  type Policy,
  type Resolution,
} from "@traffic-policy/contracts";
import {
  atomicJson,
  hashDocument,
  ServiceError,
} from "@traffic-policy/core/io";
import { PolicyEnforcer } from "./policy-enforcer.ts";
import { FilePolicyJournal } from "./policy-journal.ts";
import { TestNative, testConnectionMarks } from "./test-native.ts";
import { permissionsForLeases } from "./policy-enforcer-state.ts";
import { TrafficAccounting } from "./telemetry.ts";
import type { ConnectionSnapshot } from "./connections.ts";
import { MAX_MACHINE_FRAME_BYTES } from "@traffic-policy/contracts";

const directories: string[] = [];

const owners: PolicyEnforcer[] = [];

afterEach(async () => {
  for (const owner of owners.splice(0)) await owner.close();
  vi.useRealTimers();

  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
});

function batchAnswer(address = "10.22.242.20", ttl = 60): Resolution {
  return {
    clientIp: "10.22.241.10",
    question: "proof.example",
    responseAt: new Date().toISOString(),
    answers: [{ owner: "proof.example", type: "A", value: address, ttl }],
  };
}

async function openOwner(
  directory: string,
  native: TestNative,
  persist: typeof atomicJson = atomicJson,
  journal = new FilePolicyJournal(directory, persist),
) {
  const owner = await PolicyEnforcer.open({
    bootId: randomUUID(),
    marks: testConnectionMarks(),
    native,
    journal,
    capacity: () => {},
  });

  owners.push(owner);

  return owner;
}

async function fixture(
  persist: typeof atomicJson = atomicJson,
  value = policy(),
) {
  await mkdir(join(process.cwd(), ".local/tmp/tests"), {
    recursive: true,
  });

  const directory = await mkdtemp(
    join(process.cwd(), ".local/tmp/tests/unit-"),
  );

  directories.push(directory);

  const native = new TestNative(),
    journal = new FilePolicyJournal(directory, persist),
    capacity = vi.fn();

  const enforcer = await PolicyEnforcer.open({
    bootId: randomUUID(),
    marks: testConnectionMarks(),
    native,
    journal,
    capacity,
  });

  owners.push(enforcer);

  await enforcer.apply(value);

  return {
    enforcer,
    native,
    journal,
    directory,
    value,
    capacity,
    resolve: () => enforcer.resolve(batchAnswer()),
    counts: () => ({ full: native.full, delta: native.delta }),
  };
}

const instanceId = "11111111-1111-4111-8111-111111111111";

function policy(): Policy {
  const now = new Date().toISOString();

  const block = ruleSchema.parse({
    id: randomUUID(),
    subject: { kind: "global" },
    direction: "both",
    peer: { kind: "any" },
    protocol: null,
    ports: null,
    icmpType: null,
    icmpCode: null,
    action: "block",
    priority: "normal",
    enabled: true,
    notBefore: null,
    expiresAt: null,
    dnsDestinations: null,
    createdAt: now,
    modifiedAt: now,
    reason: "",
  });

  return policySchema.parse({
    protocolVersion: 1,
    revision: "1",
    generatedAt: now,
    instances: [
      { id: instanceId, name: "Client", addresses: ["10.22.241.10"] },
    ],
    rules: [
      {
        ...block,
        id: randomUUID(),
        subject: { kind: "instance", instanceId },
        direction: "outgoing",
        peer: { kind: "hostname", value: "proof.example" },
        action: "allow",
        dnsDestinations: ["10.22.242.0/24"],
      },
      block,
    ],
    settings: {
      dnsGraceSeconds: 0,
      permissionLimit: 4096,
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

it("returns the denying decision for an answer after its Allow is revoked", async () => {
  const f = await fixture();
  await expect(f.resolve()).resolves.toMatchObject({ revision: "1" });

  const revoked = {
    ...f.value,
    revision: "2",
    rules: f.value.rules.filter((rule) => rule.action === "block"),
  };

  await f.enforcer.apply(revoked);
  const before = f.counts();
  await expect(f.resolve()).resolves.toMatchObject({
    allowed: false,
    catchAll: true,
    revision: "2",
    policyHash: hashDocument(revoked),
  });
  expect(f.counts()).toEqual(before);
});

it("preserves FIFO policy changes and prepare boundaries between DNS batches", async () => {
  const f = await fixture();
  const first = f.enforcer.resolve(batchAnswer());
  const applied = f.enforcer.apply({ ...f.value, revision: "2" });
  const second = f.enforcer.resolve(batchAnswer("10.22.242.21"));
  const prepared = f.enforcer.prepare({ ...f.value, revision: "3" });
  const third = f.enforcer.resolve(batchAnswer("10.22.242.22"));
  const receipts = await Promise.all([first, second, third]);
  await applied;
  await prepared;
  expect(receipts.map((receipt) => receipt.revision)).toEqual(["1", "2", "2"]);
  expect(f.native.delta).toBe(3);
  expect(f.enforcer.collection().receipt.revision).toBe("2");
});

it("rejects a connection dump spanning installation without blocking DNS work", async () => {
  const f = await fixture();
  let release!: (xml: string) => void;

  const dump = new Promise<string>((resolve) => {
    release = resolve;
  });

  vi.spyOn(f.native, "connections").mockReturnValueOnce(dump);
  const pending = f.enforcer.connections();
  await expect(f.resolve()).resolves.toMatchObject({ revision: "1" });
  await f.enforcer.apply({ ...f.value, revision: "2" });
  release("<conntrack/>");
  await expect(pending).rejects.toMatchObject({
    code: "connection_snapshot_changed",
  });
});

it("does not expose an old lifecycle owner during full policy installation", async () => {
  const f = await fixture();
  const original = f.native.applyFull.bind(f.native);
  let release!: () => void;

  const held = new Promise<void>((resolve) => {
    release = resolve;
  });

  const installed = vi
    .spyOn(f.native, "applyFull")
    .mockImplementation(async (program) => {
      await held;
      await original(program);
    });

  const pending = f.enforcer.apply({ ...f.value, revision: "2" });

  try {
    await vi.waitFor(() => expect(installed).toHaveBeenCalled());
    expect(() => f.enforcer.managedOwners(["10.22.241.10"])).toThrow(
      "Instance ownership is unavailable",
    );
  } finally {
    release();
    await pending;
  }

  expect(f.enforcer.managedOwners(["10.22.241.10"])).toHaveLength(1);
});

it("finds the managed owners of flow addresses once each, in policy order", async () => {
  const f = await fixture();
  const second = randomUUID();

  await f.enforcer.apply({
    ...f.value,
    revision: "2",
    instances: [
      ...f.value.instances,
      { id: second, name: "Server", addresses: ["10.22.241.20", "fd00::20"] },
    ],
  });

  expect(
    f.enforcer
      .managedOwners(["fd00::20", "10.22.241.10", "10.22.241.20", "192.0.2.1"])
      .map((owner) => owner.id),
  ).toEqual([instanceId, second]);
  expect(f.enforcer.managedOwners(["192.0.2.1"])).toEqual([]);
});

it("returns snapshot ownership and changes its identity on reassignment and re-enrollment", async () => {
  const f = await fixture();
  const first = await f.enforcer.connections();
  expect(first).toMatchObject({
    revision: "1",
    policyHash: hashDocument(f.value),
  });

  const renamed = {
    ...f.value,
    revision: "2",
    instances: f.value.instances.map((instance) => ({
      ...instance,
      name: "Renamed",
    })),
  };

  await f.enforcer.apply(renamed);
  const second = await f.enforcer.connections();
  expect(second.instances[0]!.ownershipId).toBe(
    first.instances[0]!.ownershipId,
  );
  await f.enforcer.apply({
    ...renamed,
    revision: "3",
    instances: [],
    rules: [renamed.rules.at(-1)!],
  });
  await f.enforcer.apply({ ...renamed, revision: "4" });
  const returned = await f.enforcer.connections();
  expect(returned.instances[0]!.id).toBe(first.instances[0]!.id);
  expect(returned.instances[0]!.ownershipId).not.toBe(
    first.instances[0]!.ownershipId,
  );
  expect(returned.instances[0]!.addresses).toEqual(
    first.instances[0]!.addresses,
  );
});

it.each(["journal", "uncertain", "rejected"] as const)(
  "keeps accounting ownership consistent across an interrupted reassignment at %s",
  async (failure) => {
    const f = await fixture();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const before = await f.enforcer.connections();
    const accounting = new TrafficAccounting();

    const connection: ConnectionSnapshot = {
      id: "reassigned-flow",
      sentBytes: "100",
      receivedBytes: "10",
      flow: {
        initiatorIp: "10.22.241.10",
        responderIp: "203.0.113.20",
        originalDestinationIp: "203.0.113.20",
        protocol: 6,
        originalServicePort: 443,
        responderServicePort: 443,
        icmpType: null,
        icmpCode: null,
      },
    };

    accounting.observe(connection, before, before.observedAt);
    accounting.partial = false;

    const reassigned = {
      ...f.value,
      revision: "2",
      instances: f.value.instances.map((instance) => ({
        ...instance,
        id: randomUUID(),
      })),
      rules: [f.value.rules.at(-1)!],
    };

    if (failure === "journal") {
      const replace = f.journal.replace.bind(f.journal);
      vi.spyOn(f.journal, "replace")
        .mockImplementationOnce(replace)
        .mockRejectedValueOnce(new Error("Interrupted reassignment"));
    } else {
      const apply = f.native.applyFull.bind(f.native);
      vi.spyOn(f.native, "applyFull").mockImplementationOnce(
        async (program) => {
          if (failure === "rejected")
            throw new ServiceError(
              503,
              "kernel_operation_failed",
              "Interrupted reassignment",
            );
          await apply(program);
          throw new Error("Interrupted reassignment");
        },
      );
    }

    await expect(f.enforcer.apply(reassigned)).rejects.toThrow(
      "Interrupted reassignment",
    );
    await f.enforcer.apply({ ...f.value, revision: "3" });
    const returned = await f.enforcer.connections();

    const delta = accounting.observe(
      { ...connection, sentBytes: "300", receivedBytes: "30" },
      returned,
      returned.observedAt,
    );

    if (failure === "rejected") {
      expect(returned.instances[0]!.ownershipId).toBe(
        before.instances[0]!.ownershipId,
      );
      expect(delta[0]!.sentBytes).toBe("200");
      expect(accounting.partial).toBe(false);
    } else {
      expect(returned.instances[0]!.ownershipId).not.toBe(
        before.instances[0]!.ownershipId,
      );
      expect(delta).toEqual([]);
      expect(accounting.partial).toBe(true);
    }

    expect(
      accounting.observe(
        { ...connection, sentBytes: "400", receivedBytes: "40" },
        returned,
        returned.observedAt,
      )[0]!.sentBytes,
    ).toBe("100");
  },
);

it("reserves the encoded ownership map and envelope from the native snapshot budget", async () => {
  const value = policy();
  value.instances = Array.from({ length: 350 }, (_, index) => ({
    id: randomUUID(),
    name: "Client ".padEnd(128, "x"),
    addresses: [`10.23.${Math.floor(index / 256)}.${index % 256}`],
  }));
  value.rules = [value.rules.at(-1)!];
  const f = await fixture(atomicJson, value);
  const query = vi.spyOn(f.native, "connections");
  const snapshot = await f.enforcer.connections();

  const overhead = Buffer.byteLength(
    JSON.stringify({
      id: randomUUID(),
      ok: true,
      value: { ...snapshot, xml: "" },
    }) + "\n",
  );

  expect(overhead).toBeGreaterThan(65536);
  expect(query).toHaveBeenCalledWith(
    snapshot.instances,
    MAX_MACHINE_FRAME_BYTES - overhead,
  );
});

it("reindexes learned answers on rule expansion and deletion without publishing a prepared policy", async () => {
  const value = policy();
  // The broad service Allow permits the second lookup before its name has a rule.
  value.rules.push({
    ...value.rules[1]!,
    id: randomUUID(),
    action: "allow",
    protocol: 6,
    ports: [{ start: 443, end: 443 }],
  });
  const f = await fixture(undefined, value);
  await f.resolve();
  await f.enforcer.resolve({
    ...batchAnswer(),
    question: "cdn.example",
    answers: [
      { owner: "cdn.example", type: "A", value: "10.22.242.21", ttl: 60 },
    ],
  });
  expect(f.enforcer.collection().permissions).toBe(1);

  const expanded = structuredClone(f.value);
  expanded.revision = "2";
  expanded.rules[0]!.peer = { kind: "domain", value: "example" };
  await f.enforcer.prepare(expanded);
  expect((await f.resolve()).revision).toBe("1");
  expect(f.enforcer.collection().permissions).toBe(1);

  await f.enforcer.apply(expanded);
  expect(f.enforcer.collection().permissions).toBe(2);
  expect((await f.resolve()).revision).toBe("2");

  const removed = structuredClone(expanded);
  removed.revision = "3";
  removed.rules = removed.rules.slice(1);
  await f.enforcer.apply(removed);
  expect(f.enforcer.collection().permissions).toBe(0);
  expect(await f.resolve()).toMatchObject({ permissions: 0 });
});

it("keeps confirmed counts unchanged while a native DNS batch is pending", async () => {
  const f = await fixture();
  await f.resolve();

  let release = () => {},
    started = () => {};

  const held = new Promise<void>((resolve) => {
      release = resolve;
    }),
    admitted = new Promise<void>((resolve) => {
      started = resolve;
    });

  const apply = f.native.applyDns.bind(f.native);
  vi.spyOn(f.native, "applyDns").mockImplementationOnce(
    async (chains, time) => {
      started();
      await held;
      await apply(chains, time);
    },
  );
  const pending = f.enforcer.resolve(batchAnswer("10.22.242.21"));
  await admitted;
  expect(f.enforcer.collection().permissions).toBe(1);
  expect(f.enforcer.collection().resolutions).toBe(1);
  release();
  await pending;
  expect(f.enforcer.collection().permissions).toBe(2);
  expect(f.enforcer.collection().resolutions).toBe(2);
});

it("keeps any-instance DNS grants separate and removes only the deleted instance's state", async () => {
  const value = policy(),
    other = randomUUID();

  value.rules[0]!.subject = { kind: "global" };
  value.instances.push({
    id: other,
    name: "Other client",
    addresses: ["10.22.241.11"],
  });
  const f = await fixture(atomicJson, value);
  await f.resolve();
  expect(f.enforcer.collection().permissions).toBe(1);
  await f.enforcer.resolve({ ...batchAnswer(), clientIp: "10.22.241.11" });
  expect(f.enforcer.collection().permissions).toBe(2);
  expect(f.enforcer.collection().resolutions).toBe(2);
  await f.enforcer.apply({
    ...value,
    revision: "2",
    instances: value.instances.filter((instance) => instance.id !== other),
  });
  expect(f.enforcer.collection().permissions).toBe(1);
  expect(f.enforcer.collection().resolutions).toBe(1);
});

it("rejects an expired batch member while confirming another member with a live permission", async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(Math.floor(Date.now() / 1000) * 1000);
  const f = await fixture();
  const apply = f.native.applyDns.bind(f.native);
  vi.spyOn(f.native, "applyDns").mockImplementationOnce(async (groups, now) => {
    await apply(groups, now);
    vi.setSystemTime(now + 2000);
  });

  const results = await Promise.allSettled([
    f.enforcer.resolve(batchAnswer("10.22.242.20", 1)),
    f.enforcer.resolve(batchAnswer("10.22.242.21")),
  ]);

  expect(results[0]).toMatchObject({
    status: "rejected",
    reason: { code: "dns_authorization_expired" },
  });
  expect(results[1]).toMatchObject({
    status: "fulfilled",
    value: { instanceId, revision: "1" },
  });
  expect(f.enforcer.collection().permissions).toBe(1);
});

it("caches a frozen instance projection across DNS publication", async () => {
  const f = await fixture();
  const owner = () => f.enforcer.managedOwners(["10.22.241.10"])[0]!;
  const view = owner();
  expect(Object.isFrozen(view)).toBe(true);
  expect(Object.isFrozen(view.addresses)).toBe(true);
  expect(Reflect.set(view, "name", "Changed")).toBe(false);
  await f.resolve();
  expect(owner()).toBe(view);
  await f.enforcer.apply({
    ...f.value,
    revision: "2",
    instances: [{ ...f.value.instances[0]!, name: "Renamed" }],
  });
  expect(owner()).not.toBe(view);
  expect(owner().name).toBe("Renamed");
});

it("pins the resolution receipt to the policy that authorized a reassigned client", async () => {
  const f = await fixture();
  const replacement = randomUUID();

  const next = {
    ...f.value,
    revision: "2",
    instances: [{ ...f.value.instances[0]!, id: replacement }],
    rules: f.value.rules.map((rule) => ({
      ...rule,
      subject:
        rule.subject.kind === "instance" &&
        rule.subject.instanceId === instanceId
          ? { kind: "instance" as const, instanceId: replacement }
          : rule.subject,
    })),
  };

  await f.enforcer.apply(next);
  const confirmation = await f.resolve();
  expect(confirmation).toMatchObject({
    instanceId: replacement,
    revision: "2",
    policyHash: hashDocument(next),
  });
  await f.enforcer.apply({
    ...next,
    revision: "3",
    instances: [{ ...next.instances[0]!, id: instanceId }],
    rules: next.rules.map((rule) => ({
      ...rule,
      subject:
        rule.subject.kind === "instance" &&
        rule.subject.instanceId === replacement
          ? { kind: "instance" as const, instanceId }
          : rule.subject,
    })),
  });
  expect(confirmation.instanceId).toBe(replacement);
});

it("waits for initialization without publishing a synthetic policy", async () => {
  await mkdir(join(process.cwd(), ".local/tmp/tests"), {
    recursive: true,
  });

  const directory = await mkdtemp(
    join(process.cwd(), ".local/tmp/tests/unit-"),
  );

  directories.push(directory);

  const owner = await openOwner(directory, new TestNative());
  expect(() => owner.collection()).toThrow("No policy has been applied");
  expect(owner.managedOwners(["10.22.241.10"])).toEqual([]);
});

it("fails zero-TTL authorization rather than acknowledging an empty admission", async () => {
  const f = await fixture();
  await expect(
    f.enforcer.resolve({
      clientIp: "10.22.241.10",
      question: "proof.example",
      responseAt: new Date().toISOString(),
      answers: [
        { owner: "proof.example", type: "A", value: "10.22.242.20", ttl: 0 },
      ],
    }),
  ).rejects.toMatchObject({ code: "dns_authorization_expired" });
  expect(f.enforcer.collection().permissions).toBe(0);
});

it("confirms sixteen compatible answers without checkpoint writes, disk-capacity scans or native inspection", async () => {
  const f = await fixture(),
    before = await readFile(join(f.directory, "applied.json"), "utf8");

  const persist = vi.spyOn(f.journal, "replace"),
    remove = vi.spyOn(f.journal, "removeDurably"),
    inspect = vi.spyOn(f.native, "tablePresent");

  f.capacity.mockClear();

  const receipts = await Promise.all(
    Array.from({ length: 16 }, (_, i) =>
      f.enforcer.resolve(batchAnswer(`10.22.242.${20 + i}`)),
    ),
  );

  expect(
    receipts.every(
      (r) =>
        r.instanceId === instanceId &&
        "permissions" in r &&
        r.permissions === 16 &&
        r.revision === "1",
    ),
  ).toBe(true);
  expect(f.native.delta).toBe(1);
  expect(f.enforcer.collection().resolutions).toBe(16);
  await f.enforcer.status();

  for (const spy of [persist, remove, inspect, f.capacity])
    expect(spy).not.toHaveBeenCalled();
  expect(await readFile(join(f.directory, "applied.json"), "utf8")).toBe(
    before,
  );
  expect(await readdir(f.directory)).toEqual(["applied.json"]);
});

it("bounds a burst to sixteen requests per native commit", async () => {
  const f = await fixture(),
    apply = vi.spyOn(f.native, "applyDns");

  await Promise.all(
    Array.from({ length: 33 }, (_, i) =>
      f.enforcer.resolve(batchAnswer(`10.22.242.${20 + i}`)),
    ),
  );
  expect(
    apply.mock.calls.map(([groups]) => groups[0]!.bindings.length),
  ).toEqual([16, 32, 33]);
  expect(f.native.delta).toBe(3);
});

it("confirms clients independently within one batch", async () => {
  const value = policy(),
    other = randomUUID();

  value.instances.push({
    id: other,
    name: "Other",
    addresses: ["10.22.241.11"],
  });
  value.rules.push({
    ...value.rules[0]!,
    id: randomUUID(),
    subject: { kind: "instance", instanceId: other },
  });

  const f = await fixture(atomicJson, value),
    receipts = await Promise.all([
      f.resolve(),
      f.enforcer.resolve({ ...batchAnswer(), clientIp: "10.22.241.11" }),
    ]);

  expect(receipts.map((r) => r.instanceId)).toEqual([instanceId, other]);
  expect(f.native.delta).toBe(1);
});

it("isolates invalid, stale and over-capacity members", async () => {
  const value = policy();
  value.settings.permissionLimit = 1;
  const f = await fixture(atomicJson, value);

  const results = await Promise.allSettled(
    [
      batchAnswer(),
      { ...batchAnswer(), clientIp: "10.22.241.99" },
      {
        ...batchAnswer(),
        responseAt: new Date(Date.now() - 10000).toISOString(),
      },
      batchAnswer("10.22.242.21"),
      batchAnswer(),
    ].map((a) => f.enforcer.resolve(a)),
  );

  expect(results.map((r) => r.status)).toEqual([
    "fulfilled",
    "rejected",
    "rejected",
    "rejected",
    "fulfilled",
  ]);
  expect(results[1]).toMatchObject({ reason: { code: "unknown_dns_client" } });
  expect(results[2]).toMatchObject({ reason: { code: "stale_dns_response" } });
  expect(results[3]).toMatchObject({ reason: { code: "permission_capacity" } });
  expect(f.enforcer.collection().resolutions).toBe(1);
});

it("commits the earlier answer before a shorter conflicting lease", async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  const f = await fixture();

  const results = await Promise.allSettled([
    f.resolve(),
    f.enforcer.resolve(batchAnswer("10.22.242.20", 0)),
  ]);

  expect(results[0]).toMatchObject({
    status: "fulfilled",
    value: { permissions: 1 },
  });
  expect(results[1]).toMatchObject({
    status: "rejected",
    reason: { code: "dns_authorization_expired" },
  });
  expect(f.native.delta).toBe(2);
  expect(f.enforcer.collection().permissions).toBe(0);
});

it("rejects only the affected batch after a definite atomic DNS rejection", async () => {
  const f = await fixture();
  await f.resolve();
  vi.spyOn(f.native, "applyDns").mockRejectedValueOnce(
    new ServiceError(503, "kernel_operation_failed", "Atomic update rejected"),
  );
  await expect(
    f.enforcer.resolve(batchAnswer("10.22.242.21")),
  ).rejects.toMatchObject({ code: "kernel_operation_failed" });
  expect(f.enforcer.collection().permissions).toBe(1);
  await expect(f.resolve()).resolves.toMatchObject({ permissions: 1 });
  expect(f.native.full).toBe(1);
});

it("recovers uncertain DNS completion automatically without publishing the rejected batch", async () => {
  const code = "kernel_operation_uncertain";

  const f = await fixture(),
    apply = f.native.applyDns.bind(f.native);

  await f.resolve();
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

  vi.spyOn(f.native, "applyDns").mockImplementationOnce(async (...args) => {
    await apply(...args);
    throw new ServiceError(503, code, "injected failure");
  });

  const results = await Promise.allSettled([
    f.enforcer.resolve(batchAnswer("10.22.242.21")),
    f.enforcer.resolve(batchAnswer("10.22.242.22")),
  ]);

  expect(results.every((r) => r.status === "rejected")).toBe(true);
  expect(() => f.enforcer.collection()).toThrow("last firewall update");
  await expect(f.enforcer.status()).rejects.toMatchObject({
    code: "enforcement_unavailable",
  });
  await expect(f.resolve()).rejects.toMatchObject({
    code: "enforcement_unavailable",
  });
  expect(f.native.delta).toBe(2);
  await vi.advanceTimersByTimeAsync(1000);
  await f.enforcer.prepare(f.value);
  expect(f.enforcer.collection().permissions).toBe(1);
  expect(f.native.full).toBe(2);
  expect(
    [...f.native.installed.values()]
      .flatMap((group) => group.bindings)
      .map((binding) => binding.address),
  ).toEqual(["10.22.242.20"]);
  await expect(f.resolve()).resolves.toMatchObject({ permissions: 1 });
});

it("backs off recovery attempts and cancels retries after a newer policy succeeds", async () => {
  const f = await fixture();
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  vi.spyOn(f.native, "applyDns").mockRejectedValueOnce(
    new ServiceError(503, "kernel_operation_uncertain", "Interrupted"),
  );
  await expect(f.resolve()).rejects.toThrow("Interrupted");

  const apply = vi
    .spyOn(f.native, "applyFull")
    .mockRejectedValue(
      new ServiceError(503, "kernel_operation_failed", "Still failing"),
    );

  await vi.advanceTimersByTimeAsync(1000);
  await f.enforcer.prepare(f.value);
  expect(apply).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(1999);
  expect(apply).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(1);
  await f.enforcer.prepare(f.value);
  expect(apply).toHaveBeenCalledTimes(2);
  apply.mockRestore();
  await f.enforcer.apply({ ...f.value, revision: "2" });
  const count = f.native.full;
  await vi.advanceTimersByTimeAsync(60000);
  expect(f.native.full).toBe(count);
  expect(f.enforcer.collection().policy.revision).toBe("2");
});

it("cancels pending recovery on shutdown", async () => {
  const f = await fixture();
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  vi.spyOn(f.native, "applyDns").mockRejectedValueOnce(
    new ServiceError(503, "kernel_operation_uncertain", "Interrupted"),
  );
  await expect(f.resolve()).rejects.toThrow();
  await f.enforcer.close();
  await vi.advanceTimersByTimeAsync(60000);
  expect(f.native.full).toBe(1);
  await expect(f.enforcer.apply(f.value)).rejects.toMatchObject({
    code: "enforcement_stopping",
  });
});

it("allows a newer configured policy to supersede a failed native application", async () => {
  const f = await fixture();
  const next = { ...f.value, revision: "2" };
  vi.spyOn(f.native, "applyFull").mockRejectedValue(
    new ServiceError(503, "kernel_operation_failed", "Bad policy"),
  );
  await expect(f.enforcer.apply(next)).rejects.toThrow("Bad policy");
  await expect(f.enforcer.apply(f.value)).rejects.toMatchObject({
    code: "stale_revision",
  });
  await expect(
    f.enforcer.prepare({ ...next, generatedAt: new Date(0).toISOString() }),
  ).rejects.toMatchObject({ code: "revision_conflict" });
  vi.restoreAllMocks();
  await expect(
    f.enforcer.prepare({ ...next, revision: "3" }),
  ).resolves.toMatchObject({ revision: "3" });
  await f.enforcer.apply({ ...next, revision: "3" });
  expect(f.enforcer.collection().policy.revision).toBe("3");
  expect(await f.journal.read("full-pending")).toBeNull();
});

it("restores the last applied policy when a saved pending policy cannot install", async () => {
  const f = await fixture();
  await f.journal.replace("full-pending", {
    version: 1,
    policy: { ...f.value, revision: "2" },
    receipt: null,
  });
  const compile = f.native.compileFull.bind(f.native);
  vi.spyOn(f.native, "compileFull").mockImplementation(async (input) => {
    if (input.policy.revision === "2")
      throw new Error("Pending policy is invalid");

    return compile(input);
  });
  const next = await openOwner(f.directory, f.native);
  expect(next.collection().policy.revision).toBe("1");
  // The next restart tries the newer policy again.
  expect((await f.journal.read("full-pending"))?.policy.revision).toBe("2");
  await expect(next.apply(f.value)).rejects.toMatchObject({
    code: "stale_revision",
  });
  await next.apply({ ...f.value, revision: "3" });
  expect(next.collection().policy.revision).toBe("3");
  expect(await f.journal.read("full-pending")).toBeNull();
});

it.each(["kernel_operation_failed", "kernel_operation_uncertain"])(
  "keeps the newest saved policy when every restore fails, ending with %s",
  async (code) => {
    const f = await fixture();
    await f.journal.replace("full-pending", {
      version: 1,
      policy: { ...f.value, revision: "2" },
      receipt: null,
    });

    const apply = vi
      .spyOn(f.native, "applyFull")
      .mockRejectedValueOnce(
        new ServiceError(503, "kernel_operation_failed", "Rejected"),
      )
      .mockRejectedValueOnce(new ServiceError(503, code, "Restore failure"));

    const failed = await openOwner(f.directory, f.native);
    await expect(failed.status()).rejects.toMatchObject({
      code: "enforcement_restore_failed",
    });
    await failed.close();
    expect((await f.journal.read("full-pending"))?.policy.revision).toBe("2");
    expect((await f.journal.read("full-applied"))?.policy.revision).toBe("1");

    apply.mockRestore();
    const restarted = await openOwner(f.directory, f.native);
    expect((await restarted.status()).receipt.revision).toBe("2");
    expect(await f.journal.read("full-pending")).toBeNull();
  },
);

it("keeps the enforcement service repairable when neither saved policy can restore", async () => {
  const f = await fixture();
  await f.journal.replace("full-pending", {
    version: 1,
    policy: { ...f.value, revision: "2" },
    receipt: null,
  });

  const apply = vi
    .spyOn(f.native, "applyFull")
    .mockRejectedValue(new Error("Restore failure"));

  const next = await openOwner(f.directory, f.native);
  expect(() => next.managedOwners(["10.22.241.10"])).toThrow(
    "Saved firewall policy could not be restored",
  );
  await expect(next.status()).rejects.toMatchObject({
    code: "enforcement_restore_failed",
  });
  apply.mockRestore();
  await next.apply({ ...f.value, revision: "3" });
  expect(next.collection().policy.revision).toBe("3");
});

it.each(["kernel_operation_failed", "kernel_operation_uncertain"])(
  "retries a saved policy automatically after a transient %s restore",
  async (code) => {
    const f = await fixture();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    vi.spyOn(f.native, "applyFull").mockRejectedValueOnce(
      new ServiceError(503, code, "Transient restore failure"),
    );

    const next = await openOwner(f.directory, f.native);
    await expect(next.status()).rejects.toMatchObject({
      code: "enforcement_restore_failed",
    });
    await vi.advanceTimersByTimeAsync(1000);
    // Preparation queues behind the recovery mutation it should observe.
    await next.prepare(f.value);
    expect((await next.status()).receipt.revision).toBe("1");
    await expect(next.resolve(batchAnswer())).resolves.toMatchObject({
      permissions: 1,
    });
    await next.close();
  },
);

it("recovers an uncertain full-policy application without another delivery", async () => {
  const f = await fixture(),
    next = { ...f.value, revision: "2" },
    apply = f.native.applyFull.bind(f.native);

  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  vi.spyOn(f.native, "applyFull").mockImplementationOnce(async (program) => {
    await apply(program);
    throw new ServiceError(503, "kernel_operation_uncertain", "Timed out");
  });

  await expect(f.enforcer.apply(next)).rejects.toThrow("Timed out");
  await expect(f.enforcer.resolve(batchAnswer())).rejects.toMatchObject({
    code: "enforcement_unavailable",
  });
  await vi.advanceTimersByTimeAsync(1000);
  // Preparation queues behind the recovery mutation it should observe.
  await f.enforcer.prepare(next);
  expect((await f.enforcer.status()).receipt.revision).toBe("2");
  expect(f.native.full).toBe(3);
  expect(await f.journal.read("full-pending")).toBeNull();
  await expect(f.resolve()).resolves.toMatchObject({ permissions: 1 });
});

it("reinstalls the policy and live DNS permissions after an external ruleset flush", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  const f = await fixture();
  await f.resolve();
  f.native.flush();
  await vi.advanceTimersByTimeAsync(5000);
  // Preparation queues behind the reinstall it should observe.
  await f.enforcer.prepare(f.value);
  expect(f.native.full).toBe(2);
  expect((await f.enforcer.status()).permissions).toBe(1);
  expect(
    [...f.native.installed.values()]
      .flatMap((group) => group.bindings)
      .map((binding) => binding.address),
  ).toEqual(["10.22.242.20"]);
  await vi.advanceTimersByTimeAsync(60000);
  expect(f.native.full).toBe(2);
});

it("checks the table at once when a DNS update is rejected", async () => {
  const f = await fixture();
  f.native.flush();
  await expect(f.resolve()).rejects.toMatchObject({
    code: "kernel_operation_failed",
  });
  await vi.waitFor(() => expect(f.native.full).toBe(2));
  await expect(f.resolve()).resolves.toMatchObject({ permissions: 1 });
});

it("reports enforcement unavailable while a flushed table cannot be reinstalled", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  const f = await fixture();
  f.native.flush();

  const apply = vi
    .spyOn(f.native, "applyFull")
    .mockRejectedValue(
      new ServiceError(503, "kernel_operation_failed", "Still failing"),
    );

  await vi.advanceTimersByTimeAsync(5000);
  await expect(f.enforcer.status()).rejects.toMatchObject({
    code: "enforcement_unavailable",
  });
  apply.mockRestore();
  await vi.advanceTimersByTimeAsync(1000);
  await f.enforcer.prepare(f.value);
  expect((await f.enforcer.status()).receipt.revision).toBe("1");
});

it("keeps serving the previous policy after an atomic full-policy rejection", async () => {
  const f = await fixture();
  await f.resolve();
  vi.spyOn(f.native, "applyFull").mockRejectedValueOnce(
    new ServiceError(503, "kernel_operation_failed", "Atomic update rejected"),
  );

  await expect(f.enforcer.apply({ ...f.value, revision: "2" })).rejects.toThrow(
    "Atomic update rejected",
  );
  expect((await f.enforcer.status()).receipt.revision).toBe("1");
  await expect(
    f.enforcer.resolve(batchAnswer("10.22.242.21")),
  ).resolves.toMatchObject({ permissions: 2 });
  expect(await f.journal.read("full-pending")).toBeNull();
  await f.enforcer.apply({ ...f.value, revision: "2" });
  expect(f.enforcer.collection().policy.revision).toBe("2");
});

it("keeps malformed checkpoints unavailable until an explicit valid policy installs", async () => {
  const f = await fixture();
  await writeFile(join(f.directory, "pending.json"), "broken");
  await writeFile(join(f.directory, "applied.json"), "broken");
  const next = await openOwner(f.directory, f.native);
  await expect(next.status()).rejects.toMatchObject({
    code: "enforcement_restore_failed",
  });
  await next.apply({ ...f.value, revision: "2" });
  expect(next.collection().policy.revision).toBe("2");
});

it("publishes DNS state only after command completion while status stays read-only", async () => {
  const f = await fixture();
  let enter!: () => void, release!: () => void;

  const entered = new Promise<void>((r) => {
      enter = r;
    }),
    blocked = new Promise<void>((r) => {
      release = r;
    }),
    original = f.native.applyDns.bind(f.native);

  vi.spyOn(f.native, "applyDns").mockImplementationOnce(async (...args) => {
    enter();
    await blocked;
    await original(...args);
  });
  const query = f.resolve();
  await entered;
  expect((await f.enforcer.status()).permissions).toBe(0);
  expect(f.enforcer.collection()).not.toHaveProperty("nativeValidated");
  release();
  await expect(query).resolves.toMatchObject({ permissions: 1 });
});

it("starts with empty DNS permissions after a restart", async () => {
  const f = await fixture();
  await f.resolve();
  await f.enforcer.apply({ ...f.value, revision: "2" });

  const saved = JSON.parse(
    await readFile(join(f.directory, "applied.json"), "utf8"),
  );

  expect(Object.keys(saved).sort()).toEqual(["policy", "receipt", "version"]);
  expect(saved.version).toBe(1);

  const restarted = await openOwner(f.directory, f.native);
  expect(restarted.collection()).toMatchObject({
    permissions: 0,
    resolutions: 0,
    policy: { revision: "2" },
  });
  expect(
    [...f.native.installed.values()].every((g) => g.bindings.length === 0),
  ).toBe(true);
  await expect(restarted.resolve(batchAnswer())).resolves.toMatchObject({
    permissions: 1,
  });
});

it.each(["full-pending", "native-apply", "full-applied", "cleanup"])(
  "does not acknowledge a configured policy interrupted at %s",
  async (point) => {
    const f = await fixture(),
      next = { ...f.value, revision: "2" };

    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

    if (point === "full-pending" || point === "full-applied") {
      const original = f.journal.replace.bind(f.journal);
      let fail = true;
      vi.spyOn(f.journal, "replace").mockImplementation(async (kind, value) => {
        if (fail && kind === point) {
          fail = false;
          throw new Error("interrupted commit");
        }

        await original(kind, value);
      });
    } else if (point === "native-apply") {
      const original = f.native.applyFull.bind(f.native);
      vi.spyOn(f.native, "applyFull").mockImplementationOnce(
        async (program) => {
          await original(program);
          throw new Error("interrupted commit");
        },
      );
    } else {
      const original = f.journal.removeDurably.bind(f.journal);
      vi.spyOn(f.journal, "removeDurably").mockImplementationOnce(
        async (...kinds) => {
          await original(...kinds);
          throw new Error("interrupted commit");
        },
      );
    }

    await expect(f.enforcer.apply(next)).rejects.toThrow("interrupted commit");

    if (point === "full-pending") {
      // Nothing reached the kernel, so the previous policy keeps serving.
      expect((await f.enforcer.status()).receipt.revision).toBe("1");
      await f.enforcer.apply(next);
    } else {
      await expect(f.enforcer.status()).rejects.toMatchObject({
        code: "enforcement_unavailable",
      });
      // Recovery needs no further delivery from the controller.
      await vi.advanceTimersByTimeAsync(1000);
      await f.enforcer.prepare(next);
    }

    expect(f.enforcer.collection().receipt.revision).toBe("2");
    expect(await f.journal.read("full-pending")).toBeNull();
  },
);

it("finishes a pending configured policy on restart with empty DNS state", async () => {
  const f = await fixture();
  await f.resolve();
  const original = f.journal.replace.bind(f.journal);
  vi.spyOn(f.journal, "replace")
    .mockImplementationOnce(original)
    .mockRejectedValueOnce(new Error("checkpoint failed"));
  await expect(f.enforcer.apply({ ...f.value, revision: "2" })).rejects.toThrow(
    "checkpoint failed",
  );
  const restarted = await openOwner(f.directory, f.native);
  expect(restarted.collection()).toMatchObject({
    permissions: 0,
    policy: { revision: "2" },
  });
});

it("keeps live over-limit permissions until expiry, but does not restore them after restart", async () => {
  const value = policy();
  value.settings.permissionLimit = 2;
  const f = await fixture(atomicJson, value);
  await Promise.all([
    f.resolve(),
    f.enforcer.resolve(batchAnswer("10.22.242.21")),
  ]);
  await f.enforcer.apply({
    ...value,
    revision: "2",
    settings: { ...value.settings, permissionLimit: 1 },
  });
  expect(f.enforcer.collection().permissions).toBe(2);
  await expect(
    f.enforcer.resolve(batchAnswer("10.22.242.22")),
  ).rejects.toMatchObject({ code: "permission_capacity" });
  const next = await openOwner(f.directory, f.native);
  expect(next.collection().permissions).toBe(0);
  await next.resolve(batchAnswer("10.22.242.22"));
  await expect(next.resolve(batchAnswer("10.22.242.23"))).rejects.toMatchObject(
    { code: "permission_capacity" },
  );
});

it("shares one native permission across questions without persisting their leases", async () => {
  const value = policy();
  value.settings.permissionLimit = 1;
  value.rules[0]!.peer = { kind: "domain", value: "proof.example" };
  const f = await fixture(atomicJson, value);

  for (const question of ["a.proof.example", "b.proof.example"]) {
    await expect(
      f.enforcer.resolve({
        ...batchAnswer(),
        question,
        answers: [
          { owner: question, type: "A", value: "10.22.242.20", ttl: 60 },
        ],
      }),
    ).resolves.toMatchObject({ permissions: 1 });
  }

  expect(f.enforcer.collection().resolutions).toBe(2);
  const next = await openOwner(f.directory, f.native);
  expect(next.collection().resolutions).toBe(0);
});

it("uses unchanged memory state without another native operation", async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  const f = await fixture();
  await f.resolve();
  const before = f.counts();
  await f.resolve();
  await f.enforcer.apply(f.value);
  await f.enforcer.status();
  expect(f.counts()).toEqual(before);
});

it("rejects stale revisions and conflicting policy identities", async () => {
  const f = await fixture();
  await f.enforcer.apply({ ...f.value, revision: "2" });
  await expect(f.enforcer.apply(f.value)).rejects.toMatchObject({
    code: "stale_revision",
  });
  await expect(
    f.enforcer.apply({ ...f.value, revision: "2", instances: [] }),
  ).rejects.toMatchObject({ code: "revision_conflict" });
});

it("bounds expanded DNS memory before allocating a multiplied permission set", () => {
  const value = policy();
  value.rules[0]!.peer = { kind: "domain", value: "proof.example" };
  value.rules.push({ ...value.rules[0]!, id: randomUUID() });

  const responseAt = new Date().toISOString(),
    expiresAt = new Date(Date.now() + 60000).toISOString();

  const leases = Array.from({ length: 50001 }, (_, i) => ({
    path: `4|${instanceId}@32`,
    clientIp: "10.22.241.10",
    question: `${i}.proof.example`,
    address: "10.22.242.20",
    responseAt,
    ttlSeconds: 60,
    expiresAt,
  }));

  expect(() => permissionsForLeases(value, leases, Date.now())).toThrow(
    "DNS memory state exceeds",
  );
}, 15000);

it("withholds an answer when a scheduled DNS Block takes effect during its install", async () => {
  const directory = await mkdtemp(
    join(process.cwd(), ".local/tmp/tests/unit-"),
  );

  directories.push(directory);

  const native = new TestNative();
  const start = Date.now();
  let time = start;

  const enforcer = await PolicyEnforcer.open({
    bootId: randomUUID(),
    marks: testConnectionMarks(),
    native,
    journal: new FilePolicyJournal(directory),
    capacity: () => {},
    clock: () => time,
  });

  owners.push(enforcer);

  const value = policy();
  const allow = value.rules[0]!;
  const block = randomUUID();

  await enforcer.apply({
    ...value,
    rules: [
      ...value.rules,
      {
        ...allow,
        id: block,
        action: "block",
        priority: "high",
        dnsDestinations: null,
        notBefore: new Date(start + 1000).toISOString(),
      },
    ],
  });

  const applyDns = native.applyDns.bind(native);

  native.applyDns = async (changes, now) => {
    time = start + 2000;

    return applyDns(changes, now);
  };

  await expect(enforcer.resolve(batchAnswer())).resolves.toMatchObject({
    allowed: false,
    ruleId: block,
    revision: value.revision,
  });
});
