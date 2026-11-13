import { expect, it, vi, beforeEach } from "vitest";
import { ServiceError, hashDocument, readJson } from "@traffic-policy/core/io";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { policySchema } from "@traffic-policy/contracts";
import { confirmEnforcementConfiguration, startGateway } from "./server.ts";
import { startEnforcementService } from "./enforcement-service.ts";
import { PolicyEnforcer } from "./policy-enforcer.ts";
import { TestNative, testConnectionMarks } from "./test-native.ts";
import { KernelEvents } from "./kernel-events.ts";
import type { EventBuffer } from "./buffer.ts";
import { acquireEnforcementOwnership } from "./enforcement-owner.ts";

const mocks = vi.hoisted(() => ({
  read: vi.fn(),
  construct: vi.fn(),
  close: vi.fn(),
  releaseOwnership: vi.fn(async () => {}),
  config: {
    stateDirectory: "/fixture/gateway",
    enforcementSocket: "/fixture/enforcement.sock",
    collectorBytes: "650",
    suricataFile: "/fixture/suricata/eve.json",
  },
}));

vi.mock("./enforcement-owner.ts", () => ({
  acquireEnforcementOwnership: vi.fn(async () => mocks.releaseOwnership),
}));

vi.mock("./enforcement-client.ts", () => ({
  enforcementRequest: mocks.read,
  closeEnforcementConnections: vi.fn(),
}));

vi.mock("@traffic-policy/core/io", async (original) => ({
  ...(await original<typeof import("@traffic-policy/core/io")>()),
  readJson: vi.fn(async () => mocks.config),
}));

vi.mock("node:fs/promises", async (original) => ({
  ...(await original<typeof import("node:fs/promises")>()),
  chown: vi.fn(async () => {}),
}));

vi.mock("./buffer.ts", () => ({
  EventBuffer: class {
    private lifecycle: NonNullable<
      ConstructorParameters<typeof EventBuffer>[5]
    >;
    constructor(...args: ConstructorParameters<typeof EventBuffer>) {
      mocks.construct(...args);
      this.lifecycle = args[5]!;
    }
    async start() {
      throw new Error("recovery boundary");
    }
    async close() {
      mocks.close();
      await this.lifecycle.close();
    }
  },
}));

beforeEach(() => vi.clearAllMocks());

function policy() {
  const generatedAt = new Date().toISOString();

  return policySchema.parse({
    protocolVersion: 1,
    revision: "1",
    generatedAt,
    instances: [],
    rules: [
      {
        id: "22222222-2222-4222-8222-222222222222",
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
        createdAt: generatedAt,
        modifiedAt: generatedAt,
        reason: "",
      },
    ],
    ruleSets: [],
    settings: {
      dnsReleaseMode: "require-allow",
      dnsGraceSeconds: 0,
      permissionLimit: 4096,
      trafficHistoryBytes: "524288",
      dnsHistoryBytes: "262144",
      blockedHistoryBytes: "209715",
      otherHistoryBytes: "52429",
      auditBytes: "1048576",
      collectorBytes: "4096",
      controllerDiskBytes: "8589934592",
      gatewayDiskBytes: "8589934592",
      historyMaxAgeDays: null,
      auditMaxAgeDays: null,
      localNetworks: [],
      reverseDnsResolver: null,
    },
  });
}

it("loads confirmed collector and disk limits before entering reservation recovery", async () => {
  const value = policy();

  mocks.read.mockResolvedValue({
    policy: value,
    receipt: {
      protocolVersion: 1,
      revision: value.revision,
      policyHash: hashDocument(value),
      bootId: "11111111-1111-4111-8111-111111111111",
      appliedAt: value.generatedAt,
      permissions: 0,
    },
    permissions: 0,
    resolutions: 0,
  });
  await expect(startGateway("/fixture/config.json")).rejects.toThrow(
    "recovery boundary",
  );
  expect(mocks.read).toHaveBeenCalledWith(mocks.config.enforcementSocket, {
    operation: "collection",
  });
  expect(mocks.construct.mock.calls[0]![0]).toMatchObject({
    collectorBytes: "4096",
  });
  expect(mocks.construct.mock.calls[0]![4]).toMatchObject({
    limit: 8589934592n,
  });
  expect(mocks.close).toHaveBeenCalledTimes(1);
});

it("rejects malformed enforcement state before recovering or trimming the buffer", async () => {
  mocks.read.mockRejectedValue(
    new ServiceError(
      502,
      "invalid_enforcement_response",
      "Enforcement service returned an invalid response",
    ),
  );
  await expect(startGateway("/fixture/config.json")).rejects.toThrow();
  expect(mocks.construct).not.toHaveBeenCalled();
});

it.each([
  "not_initialized",
  "enforcement_restore_failed",
  "enforcement_unavailable",
  "policy_application_pending",
])(
  "allows management startup with configuration limits after explicit %s",
  async (code) => {
    mocks.read.mockRejectedValue(
      new ServiceError(503, code, "No policy is confirmed"),
    );
    await expect(startGateway("/fixture/config.json")).rejects.toThrow(
      "recovery boundary",
    );
    expect(mocks.construct.mock.calls[0]![0]).toMatchObject({
      collectorBytes: "650",
    });
    expect(mocks.close).toHaveBeenCalledTimes(1);
  },
);

it("does not recover or trim using bootstrap limits after an enforcement service failure", async () => {
  mocks.read.mockRejectedValue(new Error("enforcement unavailable"));
  await expect(startGateway("/fixture/config.json")).rejects.toThrow(
    "enforcement unavailable",
  );
  expect(mocks.construct).not.toHaveBeenCalled();
});

it("refuses to start when the enforcement service exempts a different DNS port, machine link, or upstream resolver", async () => {
  const upstreamDns = { address: "192.0.2.53", port: 53 };

  const config = {
    enforcementSocket: "/fixture/enforcement.sock",
    dnsPort: 5353,
    machinePort: 9443,
    controllerUrl: "https://controller.example.test:9445",
    upstreamDns,
  };

  const exempted = {
    dnsPort: 5353,
    machinePort: 9443,
    controllerPort: 9445,
    controllerAddresses: ["192.0.2.20"],
    upstreamDns,
  };

  mocks.read.mockResolvedValueOnce(exempted);
  await expect(confirmEnforcementConfiguration(config)).resolves.toEqual(
    exempted,
  );
  mocks.read.mockResolvedValueOnce({ ...exempted, dnsPort: 53535 });
  await expect(confirmEnforcementConfiguration(config)).rejects.toThrow(
    "Enforcement dnsPort 53535 does not match gateway dnsPort 5353",
  );
  mocks.read.mockResolvedValueOnce({ ...exempted, machinePort: 9444 });
  await expect(confirmEnforcementConfiguration(config)).rejects.toThrow(
    "Enforcement machinePort 9444 does not match gateway machinePort 9443",
  );
  mocks.read.mockResolvedValueOnce({ ...exempted, controllerPort: 443 });
  await expect(confirmEnforcementConfiguration(config)).rejects.toThrow(
    "Enforcement controllerPort 443 does not match the port of gateway controllerUrl https://controller.example.test:9445",
  );
  mocks.read.mockResolvedValueOnce({
    ...exempted,
    upstreamDns: { ...upstreamDns, port: 5300 },
  });
  await expect(confirmEnforcementConfiguration(config)).rejects.toThrow(
    "Enforcement upstreamDns 192.0.2.53:5300 does not match gateway upstreamDns 192.0.2.53:53",
  );
});

it("rejects duplicate ownership before opening the policy enforcer", async () => {
  vi.spyOn(process, "getuid").mockReturnValue(0);
  const opened = vi.spyOn(PolicyEnforcer, "open");
  vi.mocked(acquireEnforcementOwnership).mockRejectedValueOnce(
    new Error("Already owned"),
  );

  try {
    await expect(
      startEnforcementService("/fixture/enforcement.json"),
    ).rejects.toThrow("Already owned");
    expect(opened).not.toHaveBeenCalled();
    expect(mocks.releaseOwnership).not.toHaveBeenCalled();
  } finally {
    vi.restoreAllMocks();
  }
});

it("releases ownership and signal handlers after failed enforcement startup", async () => {
  const directory = await mkdtemp(
    join(process.cwd(), ".local/tmp/tests/enforcement-startup-"),
  );

  const listeners = process.listeners("SIGTERM");
  const interrupts = process.listeners("SIGINT");
  vi.spyOn(process, "getuid").mockReturnValue(0);
  vi.spyOn(PolicyEnforcer, "open").mockRejectedValueOnce(
    new Error("Restore failed"),
  );
  vi.mocked(readJson).mockResolvedValueOnce({
    stateDirectory: directory,
    socketPath: join(directory, "enforcement.sock"),
    dnsPort: 5353,
    groupId: 988,
    upstreamInterfaces: ["eth0"],
    controllerAddresses: ["192.0.2.20"],
    machinePort: 9443,
    controllerPort: 9445,
    upstreamDns: { address: "192.0.2.53", port: 53 },
  });

  try {
    await expect(
      startEnforcementService("/fixture/enforcement.json"),
    ).rejects.toThrow("Restore failed");
    expect(mocks.releaseOwnership).toHaveBeenCalledOnce();
    expect(process.listeners("SIGTERM")).toEqual(listeners);
    expect(process.listeners("SIGINT")).toEqual(interrupts);
  } finally {
    vi.restoreAllMocks();
    await rm(directory, { recursive: true });
  }
});

it("cancels recovery at SIGTERM while draining an admitted enforcement command and its reply", async () => {
  const { enforcementRequest, closeEnforcementConnections } =
    await vi.importActual<typeof import("./enforcement-client.ts")>(
      "./enforcement-client.ts",
    );

  const base = join(process.cwd(), ".local/tmp/tests/enforcement-lifecycle");
  await mkdir(base, { recursive: true });
  const directory = await mkdtemp(join(base, "shutdown-"));
  const socketPath = join(directory, "enforcement.sock");
  const value = policy();
  const instanceId = randomUUID();
  value.instances.push({
    id: instanceId,
    name: "Client",
    addresses: ["10.0.0.1"],
  });
  value.rules.unshift({
    ...value.rules[0]!,
    id: randomUUID(),
    subject: { kind: "instance", instanceId },
    direction: "outgoing",
    peer: { kind: "hostname", value: "proof.example" },
    action: "allow",
    dnsDestinations: ["10.0.0.0/8"],
  });
  const native = new TestNative();

  const enforcer = await PolicyEnforcer.open({
    bootId: randomUUID(),
    marks: testConnectionMarks(),
    native,
    journal: {
      read: async () => null,
      replace: async () => {},
      removeDurably: async () => {},
    },
    capacity: () => {},
  });

  await enforcer.apply(value);
  const listeners = process.listeners("SIGTERM");
  const interruptListeners = process.listeners("SIGINT");
  vi.spyOn(process, "getuid").mockReturnValue(0);
  vi.spyOn(PolicyEnforcer, "open").mockResolvedValue(enforcer);
  vi.spyOn(KernelEvents.prototype, "start").mockImplementation(() => {});

  const exit = vi
    .spyOn(process, "exit")
    .mockImplementation(vi.fn<typeof process.exit>());

  let release = () => {};

  let admit = () => {};

  let stop: (() => void) | null = null;

  let reply: Promise<void> | null = null;

  const closing = vi.spyOn(enforcer, "close");

  const held = new Promise<void>((resolve) => {
    release = resolve;
  });

  const admitted = new Promise<void>((resolve) => {
    admit = resolve;
  });

  try {
    vi.stubEnv("NOTIFY_SOCKET", undefined);
    vi.mocked(readJson).mockResolvedValueOnce({
      socketPath,
      stateDirectory: directory,
      groupId: 988,
      dnsPort: 5353,
      upstreamInterfaces: ["eth0"],
      controllerAddresses: ["192.0.2.20"],
      machinePort: 9443,
      controllerPort: 9445,
      upstreamDns: { address: "192.0.2.53", port: 53 },
    });
    await startEnforcementService("/fixture/enforcement.json");
    expect(
      await enforcementRequest(socketPath, { operation: "configuration" }),
    ).toEqual({
      dnsPort: 5353,
      machinePort: 9443,
      controllerPort: 9445,
      controllerAddresses: ["192.0.2.20"],
      upstreamDns: { address: "192.0.2.53", port: 53 },
    });

    const shutdown = process
      .listeners("SIGTERM")
      .find((listener) => !listeners.includes(listener));

    if (!shutdown)
      throw new Error("Enforcement did not register its signal handler");
    stop = () => shutdown("SIGTERM");
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    vi.spyOn(native, "applyDns").mockRejectedValueOnce(
      new ServiceError(503, "kernel_operation_uncertain", "Interrupted"),
    );
    await expect(
      enforcer.resolve({
        clientIp: "10.0.0.1",
        question: "proof.example",
        responseAt: new Date().toISOString(),
        answers: [
          { owner: "proof.example", type: "A", value: "10.0.0.2", ttl: 60 },
        ],
      }),
    ).rejects.toThrow("Interrupted");

    const application = vi
      .spyOn(native, "applyFull")
      .mockImplementation(async () => {
        admit();
        await held;
        throw new ServiceError(503, "kernel_operation_failed", "Policy failed");
      });

    reply = expect(
      enforcementRequest(socketPath, {
        operation: "apply",
        policy: { ...value, revision: "2" },
      }),
    ).rejects.toMatchObject({ code: "kernel_operation_failed" });

    await admitted;
    stop();
    await vi.advanceTimersByTimeAsync(1000);
    expect(exit).not.toHaveBeenCalled();
    expect(process.listeners("SIGTERM")).toContain(shutdown);
    stop();
    expect(mocks.releaseOwnership).not.toHaveBeenCalled();
    expect(closing).toHaveBeenCalledTimes(1);
    await expect(enforcer.prepare(value)).rejects.toMatchObject({
      code: "enforcement_stopping",
    });
    release();
    await reply;
    await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(0));
    expect(mocks.releaseOwnership).toHaveBeenCalledOnce();
    expect(application).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(30000);
    expect(application).toHaveBeenCalledTimes(1);
  } finally {
    release();
    stop?.();
    await enforcer.close();

    if (stop) await vi.waitFor(() => expect(exit).toHaveBeenCalled());
    await reply;
    closeEnforcementConnections(socketPath);

    for (const listener of process.listeners("SIGTERM"))
      if (!listeners.includes(listener))
        process.removeListener("SIGTERM", listener);

    for (const listener of process.listeners("SIGINT"))
      if (!interruptListeners.includes(listener))
        process.removeListener("SIGINT", listener);
    vi.useRealTimers();
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    await rm(directory, { recursive: true });
  }
});
