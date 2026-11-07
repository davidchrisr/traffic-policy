import { afterEach, expect, it, vi } from "vitest";
import {
  mkdtemp,
  readFile,
  readdir,
  mkdir,
  rm,
  unlink,
  open,
  writeFile,
  chmod,
} from "node:fs/promises";
import { join, dirname } from "node:path";
import { randomUUID } from "node:crypto";
import {
  policySchema,
  type Policy,
  type GatewayReceipt,
  type GatewayEvent,
} from "@traffic-policy/contracts";
import {
  atomicJson,
  hashDocument,
  hasErrorCode,
  ServiceError,
} from "@traffic-policy/core/io";
import { EventBuffer } from "./buffer.ts";
import { GatewayPolicy } from "./gateway-policy.ts";
import { PolicyEnforcer } from "./policy-enforcer.ts";
import { FilePolicyJournal } from "./policy-journal.ts";
import { TestNative, testConnectionMarks } from "./test-native.ts";
import type { GatewayConfig } from "./config.ts";
import type { enforcementRequest } from "./enforcement-client.ts";
import type { StorageBudget } from "@traffic-policy/core/storage";
import {
  parseEnforcementResult,
  type EnforcementRequest,
} from "@traffic-policy/contracts/enforcement";

const roots: string[] = [];

const buffers: EventBuffer[] = [];

afterEach(async () => {
  for (const buffer of buffers.splice(0)) await buffer.close();

  for (const root of roots.splice(0)) await rm(root, { recursive: true });
});

function policy(): Policy {
  const now = new Date().toISOString();

  return policySchema.parse({
    protocolVersion: 1,
    revision: "1",
    generatedAt: now,
    instances: [],
    rules: [
      {
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
      },
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
      controllerDiskBytes: "8589934592",
      gatewayDiskBytes: "4294967296",
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
    bootId: "11111111-1111-4111-8111-111111111111",
    appliedAt: value.generatedAt,
    permissions: 0,
  };
}

function state(value: Policy) {
  return {
    policy: value,
    receipt: receipt(value),
    permissions: 0,
    resolutions: 0,
  };
}

async function clearIntent(path: string) {
  try {
    await unlink(path);
  } catch (error) {
    if (!hasErrorCode(error, "ENOENT")) throw error;
  }

  const directory = await open(dirname(path), "r");

  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

async function fixture(
  initial: Policy | null = null,
  persist: typeof atomicJson = atomicJson,
  removeIntent = clearIntent,
) {
  const parent = join(process.cwd(), ".tmp/tests/gateway-policy");
  await mkdir(parent, { recursive: true });
  const directory = await mkdtemp(join(parent, "policy-"));
  roots.push(directory);
  const value = policy();

  const config = {
    stateDirectory: directory,
    enforcementSocket: join(directory, "enforcement.sock"),
    collectorBytes: "134217728",
    suricataFile: join(directory, "suricata", "eve.json"),
  } as GatewayConfig;

  let confirmed = initial;
  const prepare = vi.fn(async (_policy: Policy) => {});

  const native = vi.fn(async (next: Policy) => {
    confirmed = structuredClone(next);

    return receipt(next);
  });

  const request = vi.fn(
    async (_socket: string, command: EnforcementRequest) => {
      if (command.operation === "prepare") {
        await prepare(command.policy);

        return {
          revision: command.policy.revision,
          policyHash: hashDocument(command.policy),
        };
      }

      if (command.operation === "apply") return native(command.policy);

      if (!confirmed)
        throw new ServiceError(
          503,
          "not_initialized",
          "No policy has been applied",
        );

      return state(confirmed);
    },
  );

  const client: typeof enforcementRequest = async <
    C extends EnforcementRequest,
  >(
    socket: string,
    command: C,
  ) =>
    parseEnforcementResult<C["operation"]>(
      command.operation,
      await request(socket, command),
    );

  const createBuffer = (prepared: GatewayConfig, budget: StorageBudget) => {
    const buffer = new EventBuffer(
      prepared,
      async (batch) => batch,
      budget.writeJson,
      undefined,
      budget,
    );

    buffers.push(buffer);

    return buffer;
  };

  const opened = await GatewayPolicy.open(config, {
    request: client,
    persist,
    removeIntent,
    createBuffer,
  });

  return {
    ...opened,
    directory,
    config,
    value,
    request,
    client,
    prepare,
    native,
    createBuffer,
  };
}

it("admits DNS lookups against the last confirmed policy", async () => {
  const f = await fixture();
  expect(() => f.owner.admitDns("10.22.241.10", "example.com")).toThrow(
    expect.objectContaining({ code: "not_initialized" }),
  );
  const instanceId = randomUUID();

  const blocked = {
    ...f.value,
    instances: [
      { id: instanceId, name: "Client", addresses: ["10.22.241.10"] },
    ],
  };

  await f.owner.apply(blocked);
  expect(f.owner.admitDns("10.22.241.10", "example.com")).toEqual({
    allowed: false,
    ruleId: blocked.rules[0]!.id,
    catchAll: true,
    instanceId,
    revision: "1",
    policyHash: hashDocument(blocked),
  });
  expect(f.owner.admitDns("10.22.241.11", "example.com")).toBeNull();

  const allowed = {
    ...blocked,
    revision: "2",
    rules: [{ ...blocked.rules[0]!, action: "allow" as const }],
  };

  await f.owner.apply(allowed);
  expect(f.owner.admitDns("10.22.241.10", "example.com")).toMatchObject({
    allowed: true,
    revision: "2",
    policyHash: hashDocument(allowed),
  });
});

it("does not start native work or change policy/quota after failed preparation", async () => {
  const f = await fixture();
  f.prepare.mockRejectedValueOnce(
    new ServiceError(507, "permission_capacity", "full"),
  );
  await expect(f.owner.apply(f.value)).rejects.toMatchObject({ status: 507 });
  expect(f.native).not.toHaveBeenCalled();
  expect(f.owner.confirmedView()).toBeNull();
  expect(f.budget.limit).toBe(4294967296n);
  await expect(
    readFile(join(f.directory, "policy-apply.json")),
  ).rejects.toMatchObject({ code: "ENOENT" });
  await f.owner.apply(f.value);
  expect(f.native).toHaveBeenCalledTimes(1);
});

it.each(["revision", "policyHash"] as const)(
  "rejects a mismatched prepare %s before starting native work",
  async (field) => {
    const f = await fixture();
    f.request.mockResolvedValueOnce({
      revision: field === "revision" ? "2" : f.value.revision,
      policyHash:
        field === "policyHash" ? "0".repeat(64) : hashDocument(f.value),
    });

    await expect(f.owner.apply(f.value)).rejects.toMatchObject({
      status: 503,
      code: "policy_drift",
    });
    expect(f.native).not.toHaveBeenCalled();
    expect(f.owner.confirmedView()).toBeNull();
    await expect(
      readFile(join(f.directory, "policy-apply.json")),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await f.owner.apply(f.value);
    expect(f.native).toHaveBeenCalledTimes(1);
  },
);

it.each([
  { operation: "status", disk: "8589934592" },
  { operation: "status", disk: "2147483648" },
  { operation: "collection", disk: "8589934592" },
  { operation: "collection", disk: "2147483648" },
] as const)(
  "adopts $operation confirmation and quota $disk after a lost apply reply even when recovery fails",
  async ({ operation, disk }) => {
    const initial = policy();
    const f = await fixture(initial);

    const next = {
      ...initial,
      revision: "2",
      instances: [
        { id: randomUUID(), name: "New client", addresses: ["10.22.241.10"] },
      ],
      settings: { ...initial.settings, gatewayDiskBytes: disk },
    };

    const native = f.native.getMockImplementation()!;
    f.native.mockImplementationOnce(async (value) => {
      await native(value);
      throw new ServiceError(502, "lost_reply", "Apply reply was lost");
    });

    await expect(f.owner.apply(next)).rejects.toMatchObject({
      code: "lost_reply",
    });
    expect(f.owner.confirmedView()?.policy).toEqual(initial);
    expect(f.budget.limit).toBe(BigInt(initial.settings.gatewayDiskBytes));
    f.native.mockRejectedValueOnce(
      new ServiceError(429, "enforcement_busy", "Busy"),
    );

    const read =
      operation === "status" ? f.owner.health() : f.owner.collection();

    await expect(read).rejects.toMatchObject({ code: "enforcement_busy" });
    expect(f.owner.confirmedView()?.policy).toEqual(next);
    expect(f.owner.admitDns("10.22.241.10", "example.com")).not.toBeNull();
    expect(f.budget.limit).toBe(BigInt(disk));
    expect(
      JSON.parse(await readFile(join(f.directory, "policy-apply.json"), "utf8"))
        .phase,
    ).toBe("native-started");

    await f.owner.recover();
    await expect(
      readFile(join(f.directory, "policy-apply.json")),
    ).rejects.toMatchObject({ code: "ENOENT" });
  },
);

it("retains observed confirmation when collector recovery fails before the native callback", async () => {
  const initial = policy();
  const f = await fixture(initial);

  const next = {
    ...initial,
    revision: "2",
    settings: { ...initial.settings, gatewayDiskBytes: "8589934592" },
  };

  const native = f.native.getMockImplementation()!;
  f.native.mockImplementationOnce(async (value) => {
    await native(value);
    throw new Error("Apply reply was lost");
  });
  await expect(f.owner.apply(next)).rejects.toThrow("Apply reply was lost");
  vi.spyOn(f.buffer, "coordinateAllocation").mockRejectedValueOnce(
    new Error("Collector recovery failed"),
  );

  await expect(f.owner.collection()).rejects.toThrow(
    "Collector recovery failed",
  );
  expect(f.native).toHaveBeenCalledTimes(1);
  expect(f.owner.confirmedView()?.policy).toEqual(next);
  expect(f.budget.limit).toBe(8589934592n);
  expect(
    JSON.parse(await readFile(join(f.directory, "policy-apply.json"), "utf8"))
      .phase,
  ).toBe("native-started");
  await f.owner.recover();
});

it("uses an observed increased quota for recovery writes before retrying native work", async () => {
  const initial = policy();
  const f = await fixture(initial);

  const next = {
    ...initial,
    revision: "2",
    settings: { ...initial.settings, gatewayDiskBytes: "8589934592" },
  };

  const native = f.native.getMockImplementation()!;
  f.native.mockImplementationOnce(async (value) => {
    await native(value);
    throw new Error("Apply reply was lost");
  });
  await expect(f.owner.apply(next)).rejects.toThrow("Apply reply was lost");

  const usage = vi.spyOn(f.budget, "status").mockReturnValue({
    allocatedBytes: "4294967296",
    logicalBytes: "4294967296",
    limitBytes: "4294967296",
    reserveBytes: "268435456",
  });

  expect(() => f.budget.assertRoom(16384n, true)).toThrow(
    "Storage limit reached",
  );
  const allocation = f.buffer.coordinateAllocation.bind(f.buffer);
  vi.spyOn(f.buffer, "coordinateAllocation").mockImplementationOnce(
    async (...args) => {
      await f.budget.writeJson(join(f.directory, "recovery-proof.json"), {
        complete: true,
      });

      return allocation(...args);
    },
  );

  try {
    await expect(f.owner.health()).resolves.toMatchObject({ policy: next });
    expect(
      JSON.parse(
        await readFile(join(f.directory, "recovery-proof.json"), "utf8"),
      ),
    ).toEqual({ complete: true });
    expect(f.budget.limit).toBe(8589934592n);
  } finally {
    usage.mockRestore();
  }
});

it("resumes interrupted collector completion while retaining native confirmation", async () => {
  const f = await fixture();
  const original = f.buffer.coordinateAllocation.bind(f.buffer);
  let fail = true;
  vi.spyOn(f.buffer, "coordinateAllocation").mockImplementation(
    async (...args) => {
      const result = await original(...args);

      if (fail) {
        fail = false;
        throw new Error("collector trim interrupted");
      }

      return result;
    },
  );
  await expect(f.owner.apply(f.value)).rejects.toThrow(
    "collector trim interrupted",
  );
  expect(
    JSON.parse(await readFile(join(f.directory, "policy-apply.json"), "utf8"))
      .phase,
  ).toBe("native-committed");
  expect(f.owner.confirmedView()?.policy).toEqual(f.value);
  await f.owner.recover();
  expect(f.prepare).toHaveBeenCalledTimes(1);
  await expect(
    readFile(join(f.directory, "policy-apply.json")),
  ).rejects.toMatchObject({ code: "ENOENT" });
});

it("retries intent persistence before sending an uncertain native request", async () => {
  let fail = true;

  const f = await fixture(null, async (...args) => {
    if (fail) {
      fail = false;
      throw new Error("intent write failed");
    }

    await atomicJson(...args);
  });

  await expect(f.owner.apply(f.value)).rejects.toThrow("intent write failed");
  expect(f.native).not.toHaveBeenCalled();
  await f.owner.recover();
  expect(f.native).toHaveBeenCalledTimes(1);
});

it("retains a started intent without publishing uncertain native work", async () => {
  const f = await fixture();
  f.native.mockRejectedValueOnce(
    new ServiceError(507, "storage_limit", "full during recovery"),
  );
  await expect(f.owner.apply(f.value)).rejects.toMatchObject({ status: 507 });
  expect(
    JSON.parse(await readFile(join(f.directory, "policy-apply.json"), "utf8"))
      .phase,
  ).toBe("native-started");
  expect(f.owner.confirmedView()).toBeNull();
  await f.owner.recover();
});

it("supersedes a persistently failing native intent with a newer revision", async () => {
  const f = await fixture();
  f.native.mockRejectedValue(
    new ServiceError(503, "kernel_operation_failed", "Bad policy"),
  );
  await expect(f.owner.apply(f.value)).rejects.toThrow("Bad policy");
  await expect(
    f.owner.apply({ ...f.value, generatedAt: new Date(0).toISOString() }),
  ).rejects.toMatchObject({ code: "revision_conflict" });
  f.native.mockReset();
  f.native.mockImplementation(async (next) => receipt(next));
  await f.owner.apply({ ...f.value, revision: "2" });
  expect(f.native).toHaveBeenCalledTimes(1);
  expect(f.native.mock.calls[0]![0].revision).toBe("2");
  expect(f.owner.confirmedView()?.policy.revision).toBe("2");
  await expect(
    readFile(join(f.directory, "policy-apply.json")),
  ).rejects.toMatchObject({ code: "ENOENT" });
});

it("retains an earlier durable intent when a replacement fails preparation", async () => {
  const f = await fixture();
  f.native.mockRejectedValueOnce(new Error("Bad policy"));
  await expect(f.owner.apply(f.value)).rejects.toThrow();
  f.prepare.mockRejectedValueOnce(new Error("Replacement invalid"));
  await expect(f.owner.apply({ ...f.value, revision: "2" })).rejects.toThrow(
    "Replacement invalid",
  );
  expect(
    JSON.parse(await readFile(join(f.directory, "policy-apply.json"), "utf8"))
      .policy.revision,
  ).toBe("1");
  await f.owner.recover();
  expect(f.owner.confirmedView()?.policy.revision).toBe("1");
});

it("supersedes an interrupted saved intent after gateway restart", async () => {
  const f = await fixture();
  f.native.mockRejectedValue(new Error("Bad policy"));
  await expect(f.owner.apply(f.value)).rejects.toThrow();
  await f.buffer.close();

  const next = await GatewayPolicy.open(f.config, {
    request: f.client,
    createBuffer: f.createBuffer,
  });

  f.native.mockReset();
  f.native.mockImplementation(async (value) => receipt(value));
  await next.owner.apply({ ...f.value, revision: "2" });
  expect(f.native.mock.calls.map(([value]) => value.revision)).toEqual(["2"]);
  expect(next.owner.confirmedView()?.policy.revision).toBe("2");
});

it("keeps both quota directions and DNS enrollment aligned with native confirmation during failed local completion", async () => {
  const initial = policy();
  const f = await fixture(initial);
  const original = f.buffer.coordinateAllocation.bind(f.buffer);
  let fail = false;
  vi.spyOn(f.buffer, "coordinateAllocation").mockImplementation(
    async (...args) => {
      const result = await original(...args);

      if (fail) throw new Error("collector completion interrupted");

      return result;
    },
  );

  const changes = [
    { revision: "2", disk: "8589934592", collector: "268435456" },
    { revision: "3", disk: "2147483648", collector: "67108864" },
  ];

  for (const change of changes) {
    const next = {
      ...initial,
      revision: change.revision,
      instances: [
        { id: randomUUID(), name: "New client", addresses: ["10.22.241.10"] },
      ],
      settings: {
        ...initial.settings,
        gatewayDiskBytes: change.disk,
        collectorBytes: change.collector,
      },
    };

    fail = true;
    await expect(f.owner.apply(next)).rejects.toThrow(
      "collector completion interrupted",
    );
    expect(f.owner.confirmedView()?.policy).toEqual(next);
    expect(f.owner.admitDns("10.22.241.10", "example.com")).not.toBeNull();
    expect(f.budget.limit).toBe(BigInt(change.disk));
    await expect(f.owner.health()).rejects.toThrow(
      "collector completion interrupted",
    );
    expect(f.budget.limit).toBe(BigInt(change.disk));
    fail = false;
    await f.owner.recover();
    expect((await f.owner.health()).policy.revision).toBe(change.revision);
    expect(f.buffer.status().allocationBytes).toBe(change.collector);
  }
});

it("keeps native policy and quota when the confirmation checkpoint fails", async () => {
  let fail = true;

  const f = await fixture(null, async (path, document) => {
    if (
      fail &&
      JSON.stringify(document).includes('"phase":"native-committed"')
    ) {
      fail = false;
      throw new Error("confirmation checkpoint interrupted");
    }

    await atomicJson(path, document);
  });

  const next = {
    ...f.value,
    settings: { ...f.value.settings, gatewayDiskBytes: "8589934592" },
  };

  await expect(f.owner.apply(next)).rejects.toThrow(
    "confirmation checkpoint interrupted",
  );
  expect(f.owner.confirmedView()?.policy).toEqual(next);
  expect(f.budget.limit).toBe(8589934592n);
  await f.owner.recover();
  expect(f.prepare).toHaveBeenCalledTimes(1);
});

it("keeps application pending after intent unlink until directory cleanup succeeds", async () => {
  let fail = true;

  const f = await fixture(null, atomicJson, async (path) => {
    try {
      await unlink(path);
    } catch (error) {
      if (!hasErrorCode(error, "ENOENT")) throw error;
    }

    if (fail) {
      fail = false;
      throw new Error("intent cleanup interrupted");
    }

    const directory = await open(dirname(path), "r");

    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  });

  await expect(f.owner.apply(f.value)).rejects.toThrow(
    "intent cleanup interrupted",
  );
  expect(f.owner.confirmedView()?.policy).toEqual(f.value);
  await f.owner.recover();
  expect(f.prepare).toHaveBeenCalledTimes(1);
  expect(f.native).toHaveBeenCalledTimes(2);
});

it("returns delayed old reads without regressing shared policy, quota or allocation", async () => {
  const initial = policy();
  const f = await fixture(initial);
  const original = f.request.getMockImplementation()!;
  let release!: () => void, entered!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  const reading = new Promise<void>((resolve) => (entered = resolve));
  f.request.mockImplementation(async (socket, command) => {
    if (command.operation === "collection") {
      entered();
      await gate;

      return state(initial);
    }

    return original(socket, command);
  });
  const delayed = f.owner.collection();
  await reading;

  const next = {
    ...initial,
    revision: "2",
    settings: {
      ...initial.settings,
      gatewayDiskBytes: "8589934592",
      collectorBytes: "268435456",
    },
  };

  await f.owner.apply(next);
  const allocation = vi.spyOn(f.buffer, "allocation");
  const health = await f.owner.health();
  expect(health).not.toHaveProperty("nativeValidated");
  expect(health.policy.revision).toBe("2");
  release();
  const old = await delayed;
  expect(old.policy.revision).toBe("1");
  expect(old).not.toHaveProperty("nativeValidated");
  expect(f.owner.confirmedView()?.policy).toEqual(next);
  expect(f.budget.limit).toBe(8589934592n);
  expect(f.buffer.status().allocationBytes).toBe("268435456");
  expect(allocation).not.toHaveBeenCalled();
});

it("allows enforcement reads during native work and orders their adoption behind application", async () => {
  const initial = policy();
  const f = await fixture(initial);
  const original = f.native.getMockImplementation()!;
  let release!: () => void, entered!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  const applying = new Promise<void>((resolve) => (entered = resolve));
  f.native.mockImplementation(async (next) => {
    entered();
    await gate;

    return original(next);
  });
  const next = { ...initial, revision: "2" };
  const application = f.owner.apply(next);
  await applying;
  const health = f.owner.health();
  await vi.waitFor(() =>
    expect(
      f.request.mock.calls.some(
        ([, command]) => command.operation === "status",
      ),
    ).toBe(true),
  );
  release();
  await application;
  expect((await health).policy.revision).toBe("1");
  expect(f.owner.confirmedView()?.policy).toEqual(next);
});

it("rejects conflicting confirmed identities without side effects", async () => {
  const initial = policy();
  const f = await fixture(initial);

  const conflicting = {
    ...initial,
    settings: { ...initial.settings, collectorBytes: "268435456" },
  };

  f.request.mockResolvedValue(state(conflicting));
  await expect(f.owner.health()).rejects.toMatchObject({
    code: "invalid_enforcement_response",
  });
  expect(f.owner.confirmedView()?.policy).toEqual(initial);
  expect(f.budget.limit).toBe(4294967296n);
});

it("keeps the confirmed copy and DNS index while refreshes report the same policy", async () => {
  const f = await fixture();
  await f.owner.apply(f.value);
  const view = f.owner.confirmedView();
  await f.owner.health();
  await f.owner.health();
  expect(f.owner.confirmedView()).toBe(view);
});

it("starts with the last confirmed limits while the enforcement service cannot confirm a policy", async () => {
  const value = policy();
  value.settings = {
    ...value.settings,
    collectorBytes: "268435456",
    gatewayDiskBytes: "8589934592",
  };
  const f = await fixture(value);
  await f.owner.health();
  await f.buffer.close();
  f.request.mockRejectedValue(
    new ServiceError(
      503,
      "enforcement_restore_failed",
      "Saved firewall policy could not be restored. Apply a corrected policy.",
    ),
  );

  const restarted = await GatewayPolicy.open(f.config, {
    request: f.client,
    createBuffer: f.createBuffer,
  });

  expect(restarted.buffer.status().allocationBytes).toBe("268435456");
  expect(restarted.budget.limit).toBe(8589934592n);
  expect(restarted.owner.confirmedView()).toBeNull();
});

it("remains repairable after a failed restore, failed repair and gateway restart", async () => {
  const f = await fixture();
  await f.buffer.close();
  f.value.instances.push({
    id: randomUUID(),
    name: "Client",
    addresses: ["10.0.0.1"],
  });

  const directory = join(f.directory, "enforcement");
  await mkdir(directory);
  const journal = new FilePolicyJournal(directory);
  await journal.replace("full-pending", {
    version: 1,
    policy: f.value,
    receipt: null,
  });
  const native = new TestNative();

  const application = vi
    .spyOn(native, "applyFull")
    .mockRejectedValue(
      new ServiceError(503, "kernel_operation_failed", "Policy cannot install"),
    );

  const enforcer = await PolicyEnforcer.open({
    bootId: randomUUID(),
    marks: testConnectionMarks(),
    journal,
    native,
    capacity: () => {},
  });

  f.request.mockImplementation(async (_socket, command) => {
    switch (command.operation) {
      case "prepare":
        return enforcer.prepare(command.policy);
      case "apply":
        return enforcer.apply(command.policy);
      case "status":
        return enforcer.status();
      case "collection":
        return enforcer.collection();
      default:
        throw new Error("Unexpected enforcement command");
    }
  });

  const openGateway = () =>
    GatewayPolicy.open(f.config, {
      request: f.client,
      createBuffer: f.createBuffer,
    });

  try {
    await atomicJson(join(f.directory, "policy-apply.json"), {
      version: 1,
      policy: f.value,
      phase: "native-started",
      receipt: null,
    });
    const first = await openGateway();
    await expect(first.owner.health()).rejects.toMatchObject({
      code: "kernel_operation_failed",
    });
    // An atomic rejection leaves the restore failure as the enforcement service condition.
    await expect(enforcer.status()).rejects.toMatchObject({
      code: "enforcement_restore_failed",
    });
    await first.buffer.close();
    const restarted = await openGateway();
    expect(restarted.owner.confirmedView()).toBeNull();
    expect(() => restarted.owner.admitDns("10.0.0.1", "example.com")).toThrow(
      expect.objectContaining({ code: "not_initialized" }),
    );
    await expect(restarted.owner.health()).rejects.toMatchObject({
      code: "kernel_operation_failed",
    });
    expect(restarted.owner.confirmedView()).toBeNull();
    application.mockRestore();
    const corrected = { ...f.value, revision: "2" };
    await restarted.owner.apply(corrected);
    expect((await restarted.owner.health()).policy).toEqual(corrected);
    expect(restarted.owner.admitDns("10.0.0.1", "example.com")).not.toBeNull();
    await expect(
      readFile(join(f.directory, "policy-apply.json")),
    ).rejects.toMatchObject({ code: "ENOENT" });
  } finally {
    await enforcer.close();
  }
});

it.each(["native-started", "native-committed"])(
  "recovers a saved %s intent when bootstrap reports initial setup",
  async (phase) => {
    const f = await fixture();
    await f.buffer.close();
    await writeFile(
      join(f.directory, "policy-apply.json"),
      JSON.stringify({
        version: 1,
        policy: f.value,
        phase,
        receipt: phase === "native-committed" ? receipt(f.value) : null,
      }),
    );

    const opened = await GatewayPolicy.open(f.config, {
      request: f.client,
      createBuffer: f.createBuffer,
    });

    await opened.owner.health();
    expect(opened.owner.confirmedView()?.policy).toEqual(f.value);
    expect(f.prepare).not.toHaveBeenCalled();
    await expect(
      readFile(join(f.directory, "policy-apply.json")),
    ).rejects.toMatchObject({ code: "ENOENT" });
  },
);

it.each([
  ["invalid JSON", "{", "Saved policy application could not be read"],
  [
    "an earlier format",
    JSON.stringify({
      version: 1,
      policy: {},
      phase: "prepared",
      receipt: null,
    }),
    "policy.protocolVersion:",
  ],
  [
    "an oversized diagnostic",
    JSON.stringify({
      version: 1,
      policy: policy(),
      phase: "prepared",
      receipt: null,
      ["x".repeat(5000)]: true,
    }),
    "document:",
  ],
])(
  "sets aside a saved application in %s and reports it once",
  async (_case, saved, message) => {
    const initial = policy();
    const f = await fixture(initial);
    await f.buffer.close();
    await writeFile(join(f.directory, "policy-apply.json"), saved);

    const opened = await GatewayPolicy.open(f.config, {
      request: f.client,
      createBuffer: f.createBuffer,
    });

    const append = vi.spyOn(opened.buffer, "append");
    await opened.owner.health();
    expect(append).toHaveBeenCalledOnce();
    expect(append.mock.calls[0]![0][0]!.details).toMatchObject({
      code: "gateway_intent_unreadable",
      message: expect.stringContaining(message),
      occurrences: 1,
      recovered: true,
    });
    expect(
      String(append.mock.calls[0]![0][0]!.details.message).length,
    ).toBeLessThanOrEqual(4096);

    const aside = (await readdir(f.directory)).filter((name) =>
      name.startsWith("policy-apply.json.unreadable-"),
    );

    expect(aside).toHaveLength(1);
    expect(await readFile(join(f.directory, aside[0]!), "utf8")).toBe(saved);
    await expect(
      readFile(join(f.directory, "policy-apply.json")),
    ).rejects.toMatchObject({ code: "ENOENT" });

    await opened.owner.apply({ ...initial, revision: "2" });
    expect(opened.owner.confirmedView()?.policy.revision).toBe("2");
    expect(append).toHaveBeenCalledOnce();
  },
);

it("keeps failing on a saved application it cannot read from disk", async () => {
  const f = await fixture(policy());
  await mkdir(join(f.directory, "policy-apply.json"));
  await expect(f.owner.health()).rejects.toMatchObject({ code: "EISDIR" });
});

it.each(["eviction intent", "unlink", "directory sync", "eviction completion"])(
  "retains native confirmation and the gateway obligation after a real %s failure",
  async (boundary) => {
    const initial = policy();
    const f = await fixture(initial);
    await f.buffer.close();
    let fail = false;

    const opened = await GatewayPolicy.open(f.config, {
      request: f.client,
      createBuffer: (config, budget) => {
        const buffer = new EventBuffer(
          config,
          async (batch) => batch,
          async (...args) => {
            const text = JSON.stringify(args[1]);

            if (
              fail &&
              args[0].endsWith("buffer.json") &&
              ((boundary === "eviction intent" &&
                text.includes('"evicting":{')) ||
                (boundary === "eviction completion" &&
                  text.includes('"lost":"1"') &&
                  text.includes('"evicting":null')))
            )
              throw new Error("collector boundary interrupted");
            await budget.writeJson(...args);
          },
          async () => {
            if (fail && boundary === "directory sync")
              throw new Error("collector boundary interrupted");

            const directory = await open(
              join(config.stateDirectory, "segments"),
              "r",
            );

            try {
              await directory.sync();
            } finally {
              await directory.close();
            }
          },
          budget,
        );

        buffers.push(buffer);

        return buffer;
      },
    });

    const event = (): GatewayEvent => ({
      id: randomUUID(),
      observedAt: new Date().toISOString(),
      type: "condition",
      instanceId: null,
      direction: null,
      peerIp: null,
      protocol: null,
      port: null,
      sentBytes: "0",
      receivedBytes: "0",
      ruleId: null,
      question: null,
      source: "gateway",
      details: { message: "retained history" },
    });

    await opened.buffer.append([event()]);
    await opened.buffer.append([event()]);

    const allocation = (
      BigInt(opened.buffer.status().bytes) / 2n +
      32n
    ).toString();

    const next = {
      ...initial,
      revision: "2",
      settings: {
        ...initial.settings,
        collectorBytes: allocation,
        gatewayDiskBytes: "8589934592",
      },
    };

    fail = true;

    if (boundary === "unlink")
      await chmod(join(f.directory, "segments"), 0o500);

    try {
      await expect(opened.owner.apply(next)).rejects.toThrow();
      expect(opened.owner.confirmedView()?.policy).toEqual(next);
      expect(opened.budget.limit).toBe(8589934592n);
      expect(
        JSON.parse(
          await readFile(join(f.directory, "policy-apply.json"), "utf8"),
        ).phase,
      ).toBe("native-committed");
    } finally {
      fail = false;

      if (boundary === "unlink")
        await chmod(join(f.directory, "segments"), 0o750);
    }

    await opened.owner.recover();
    expect(opened.buffer.status()).toMatchObject({
      lostBatches: "1",
      allocationBytes: allocation,
      writePending: false,
    });
    expect(f.prepare).toHaveBeenCalledTimes(1);
    await expect(
      readFile(join(f.directory, "policy-apply.json")),
    ).rejects.toMatchObject({ code: "ENOENT" });
  },
);

it("uses the confirmed increased quota for dependent cleanup writes", async () => {
  const f = await fixture(null, atomicJson, async (path) => {
    await budget.writeJson(join(dirname(path), "cleanup-proof.json"), {
      complete: true,
    });
    await clearIntent(path);
  });

  const budget = f.budget;

  const usage = vi.spyOn(budget, "status").mockReturnValue({
    allocatedBytes: "4294967296",
    logicalBytes: "4294967296",
    limitBytes: "4294967296",
    reserveBytes: "268435456",
  });

  expect(() => budget.assertRoom(16384n, true)).toThrow(
    "Storage limit reached",
  );

  const next = {
    ...f.value,
    settings: { ...f.value.settings, gatewayDiskBytes: "8589934592" },
  };

  await f.owner.apply(next);
  expect(
    JSON.parse(await readFile(join(f.directory, "cleanup-proof.json"), "utf8")),
  ).toEqual({ complete: true });
  expect(budget.limit).toBe(8589934592n);
  usage.mockRestore();
});

it("refuses old or conflicting applications before recording a new obligation", async () => {
  const initial = { ...policy(), revision: "2" };
  const f = await fixture(initial);
  await expect(
    f.owner.apply({ ...initial, revision: "1" }),
  ).rejects.toMatchObject({ code: "stale_revision" });
  await expect(
    f.owner.apply({
      ...initial,
      settings: { ...initial.settings, dnsGraceSeconds: 1 },
    }),
  ).rejects.toMatchObject({ code: "revision_conflict" });
  expect(f.prepare).not.toHaveBeenCalled();
  expect(f.native).not.toHaveBeenCalled();
  await expect(
    readFile(join(f.directory, "policy-apply.json")),
  ).rejects.toMatchObject({ code: "ENOENT" });
});
