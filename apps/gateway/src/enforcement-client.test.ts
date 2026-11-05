import { createServer, type Socket } from "node:net";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { expect, expectTypeOf, it } from "vitest";
import {
  enforcementRequest,
  closeEnforcementConnections,
} from "./enforcement-client.ts";
import { CommandFrame } from "./command-frame.ts";
import { randomUUID } from "node:crypto";
import { policySchema } from "@traffic-policy/contracts";
import { hashDocument } from "@traffic-policy/core/io";
import {
  enforcementCommandSchema,
  enforcementResultSchemas,
  type EnforcementResult,
  type EnforcementRequest,
  type EnforcementCommand,
  type EnforcementOperation,
} from "@traffic-policy/contracts/enforcement";

async function fixture(
  reply: (socket: Socket, id: string, command: EnforcementCommand) => void,
) {
  const base = join(process.cwd(), ".tmp/tests/enforcement-client");
  await mkdir(base, { recursive: true });

  const directory = await mkdtemp(join(base, "transport-")),
    path = join(directory, "enforcement.sock");

  const clients = new Set<Socket>();

  const server = createServer({ allowHalfOpen: true }, (socket) => {
    clients.add(socket);
    socket.on("error", () => {});
    const frames = new CommandFrame();
    socket.on("data", (chunk) => {
      frames.write(chunk, (raw) => {
        const command = enforcementCommandSchema.parse(raw);
        reply(socket, command.id, command);
      });
    });
  });

  await new Promise<void>((resolve) => server.listen(path, resolve));

  return {
    path,
    connections: () => clients.size,
    close: async () => {
      closeEnforcementConnections(path);

      for (const client of clients) client.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await rm(directory, { recursive: true });
    },
  };
}

it("decodes fragmented UTF-8 and completes a response frame without waiting for connection teardown", async () => {
  const f = await fixture((socket, id) => {
    const frame = Buffer.from(
      JSON.stringify({
        id,
        ok: true,
        value: {
          bootId: randomUUID(),
          revision: "1",
          policyHash: "a".repeat(64),
          instances: [],
          gatewayAddresses: [],
          observedAt: new Date().toISOString(),
          xml: "監視",
        },
      }) + "\n",
    );

    const start = frame.indexOf(Buffer.from("監"));
    socket.write(frame.subarray(0, start + 1));
    setTimeout(() => socket.write(frame.subarray(start + 1)), 20);
  });

  try {
    expect(
      (await enforcementRequest(f.path, { operation: "connections" }, 1000))
        .xml,
    ).toBe("監視");
  } finally {
    await f.close();
  }
});

function protocol() {
  const at = new Date().toISOString();

  const policy = policySchema.parse({
    protocolVersion: 1,
    revision: "1",
    generatedAt: at,
    instances: [],
    rules: [
      {
        id: randomUUID(),
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
      gatewayDiskBytes: "4294967296",
      controllerDiskBytes: "8589934592",
      historyMaxAgeDays: null,
      auditMaxAgeDays: null,
      localNetworks: [],
      reverseDnsResolver: null,
    },
  });

  const receipt = {
    protocolVersion: 1 as const,
    revision: policy.revision,
    policyHash: hashDocument(policy),
    bootId: randomUUID(),
    appliedAt: at,
    permissions: 0,
  };

  const commands = {
    apply: { operation: "apply", policy },
    prepare: { operation: "prepare", policy },
    resolve: {
      operation: "resolve",
      resolution: {
        clientIp: "10.22.241.10",
        question: "proof.example",
        responseAt: at,
        answers: [],
      },
    },
    status: { operation: "status" },
    collection: { operation: "collection" },
    configuration: { operation: "configuration" },
    connections: { operation: "connections" },
    counters: { operation: "counters", page: null },
    events: { operation: "events", epoch: null, after: "0" },
  } satisfies {
    [O in EnforcementOperation]: Extract<EnforcementRequest, { operation: O }>;
  };

  const common = { policy, receipt, permissions: 0, resolutions: 0 };

  const results = {
    apply: receipt,
    prepare: { revision: policy.revision, policyHash: receipt.policyHash },
    resolve: { ...receipt, instanceId: randomUUID() },
    status: common,
    collection: common,
    configuration: {
      dnsPort: 5353,
      machinePort: 9443,
      controllerPort: 9445,
      controllerAddresses: ["192.0.2.20"],
      upstreamDns: { address: "192.0.2.53", port: 53 },
    },
    connections: {
      bootId: receipt.bootId,
      revision: policy.revision,
      policyHash: receipt.policyHash,
      instances: [],
      gatewayAddresses: ["127.0.0.1"],
      observedAt: at,
      xml: "<conntrack/>",
    },
    counters: {
      reading: randomUUID(),
      observedAt: at,
      boot: receipt.bootId,
      counters: [{ table: "7", name: "k_o_x", packets: "42" }],
      next: null,
      uncounted: null,
    },
    events: {
      epoch: randomUUID(),
      sequence: "0",
      events: [],
      gatewayAddresses: ["127.0.0.1"],
      reset: true,
      gap: false,
      condition: null,
    },
  } satisfies { [O in EnforcementOperation]: EnforcementResult<O> };

  return { commands, results };
}

it.each<EnforcementOperation>([
  "apply",
  "prepare",
  "resolve",
  "status",
  "collection",
  "configuration",
  "connections",
  "counters",
  "events",
])(
  "validates shared %s requests and returns its operation-specific result",
  async (operation) => {
    const { commands, results } = protocol();

    const f = await fixture((socket, id, command) =>
      socket.end(
        JSON.stringify({ id, ok: true, value: results[command.operation] }) +
          "\n",
      ),
    );

    try {
      expect(await enforcementRequest(f.path, commands[operation])).toEqual(
        results[operation],
      );
    } finally {
      await f.close();
    }
  },
);

it("returns the decision when the enforcement service's policy denies a resolution", async () => {
  const { commands, results } = protocol();

  const denial = {
    allowed: false,
    ruleId: randomUUID(),
    catchAll: false,
    instanceId: randomUUID(),
    revision: results.apply.revision,
    policyHash: results.apply.policyHash,
  };

  const f = await fixture((socket, id) =>
    socket.end(JSON.stringify({ id, ok: true, value: denial }) + "\n"),
  );

  try {
    expect(await enforcementRequest(f.path, commands.resolve)).toEqual(denial);
  } finally {
    await f.close();
  }
});

it.each([
  "apply",
  "prepare",
  "resolve",
  "status",
  "collection",
  "configuration",
  "connections",
  "events",
] as const)(
  "rejects malformed successful %s payloads at the client boundary",
  async (operation) => {
    const { commands } = protocol();

    const f = await fixture((socket, id) =>
      socket.end(JSON.stringify({ id, ok: true, value: {} }) + "\n"),
    );

    try {
      await expect(
        enforcementRequest(f.path, commands[operation]),
      ).rejects.toMatchObject({
        status: 502,
        code: "invalid_enforcement_response",
      });
    } finally {
      await f.close();
    }
  },
);

it("rejects internally inconsistent policy receipts", async () => {
  const { commands, results } = protocol();

  const cases = [
    {
      command: commands.status,
      value: {
        ...results.status,
        receipt: { ...results.apply, policyHash: "a".repeat(64) },
      },
    },
    {
      command: commands.collection,
      value: {
        ...results.collection,
        receipt: { ...results.apply, revision: "2" },
      },
    },
    {
      command: commands.resolve,
      value: { ...results.resolve, instanceId: null },
    },
    { command: commands.events, value: { ...results.events, events: [{}] } },
  ];

  for (const item of cases) {
    const f = await fixture((socket, id) =>
      socket.end(JSON.stringify({ id, ok: true, value: item.value }) + "\n"),
    );

    try {
      await expect(
        enforcementRequest(f.path, item.command),
      ).rejects.toMatchObject({
        status: 502,
        code: "invalid_enforcement_response",
      });
    } finally {
      await f.close();
    }
  }
});

it("infers each operation's exact validated result type", () => {
  const { commands } = protocol();
  const apply = () => enforcementRequest("unused", commands.apply);
  const prepare = () => enforcementRequest("unused", commands.prepare);
  const resolve = () => enforcementRequest("unused", commands.resolve);
  const status = () => enforcementRequest("unused", commands.status);
  const collection = () => enforcementRequest("unused", commands.collection);
  const connections = () => enforcementRequest("unused", commands.connections);
  const events = () => enforcementRequest("unused", commands.events);
  expectTypeOf(apply).returns.toEqualTypeOf<
    Promise<EnforcementResult<"apply">>
  >();
  expectTypeOf(prepare).returns.toEqualTypeOf<
    Promise<EnforcementResult<"prepare">>
  >();
  expectTypeOf(resolve).returns.toEqualTypeOf<
    Promise<EnforcementResult<"resolve">>
  >();
  expectTypeOf(status).returns.toEqualTypeOf<
    Promise<EnforcementResult<"status">>
  >();
  expectTypeOf(collection).returns.toEqualTypeOf<
    Promise<EnforcementResult<"collection">>
  >();
  expectTypeOf(connections).returns.toEqualTypeOf<
    Promise<EnforcementResult<"connections">>
  >();
  expectTypeOf(events).returns.toEqualTypeOf<
    Promise<EnforcementResult<"events">>
  >();
});

it("rejects unknown response identities and malformed envelopes", async () => {
  const { results } = protocol();

  for (const invalid of ["identity", "extra frame"]) {
    const f = await fixture((socket, id) =>
      socket.end(
        JSON.stringify({
          id: invalid === "identity" ? randomUUID() : id,
          ok: true,
          value: results.connections,
          unexpected: invalid === "extra frame" ? true : undefined,
        }) +
          "\n" +
          (invalid === "extra frame" ? "{}\n" : ""),
      ),
    );

    try {
      await expect(
        enforcementRequest(f.path, { operation: "connections" }),
      ).rejects.toThrow(
        invalid === "identity" ? "identity mismatch" : "invalid response",
      );
    } finally {
      await f.close();
    }
  }
});

it("multiplexes overlapping responses on one reusable connection", async () => {
  const { results } = protocol();
  const requests: { socket: Socket; id: string }[] = [];
  let ready = () => {};

  const admitted = new Promise<void>((resolve) => {
    ready = resolve;
  });

  const f = await fixture((socket, id) => {
    requests.push({ socket, id });

    if (requests.length === 3) ready();
  });

  try {
    const pending = Array.from({ length: 3 }, () =>
      enforcementRequest(f.path, { operation: "connections" }),
    );

    await admitted;
    expect(f.connections()).toBe(1);

    for (const [n, item] of requests.toReversed().entries())
      item.socket.write(
        JSON.stringify({
          id: item.id,
          ok: true,
          value: { ...results.connections, xml: String(n) },
        }) + "\n",
      );
    expect((await Promise.all(pending)).map((result) => result.xml)).toEqual([
      "2",
      "1",
      "0",
    ]);
  } finally {
    await f.close();
  }
});

it("isolates an expired RPC, ignores its late reply, and drains healthy peers", async () => {
  const { results } = protocol();
  const requests: { socket: Socket; id: string }[] = [];
  let ready = () => {};

  const admitted = new Promise<void>((resolve) => {
    ready = resolve;
  });

  const f = await fixture((socket, id) => {
    requests.push({ socket, id });

    if (requests.length === 2) ready();

    if (requests.length === 3)
      socket.write(
        JSON.stringify({ id, ok: true, value: results.connections }) + "\n",
      );
  });

  try {
    const expired = enforcementRequest(
      f.path,
      { operation: "connections" },
      100,
    ).catch((error) => error);

    const healthy = enforcementRequest(
      f.path,
      { operation: "connections" },
      2000,
    );

    await admitted;
    expect(await expired).toBeInstanceOf(Error);
    expect(
      (await enforcementRequest(f.path, { operation: "connections" }, 2000))
        .xml,
    ).toBe(results.connections.xml);
    expect(f.connections()).toBe(2);

    for (const item of requests.slice(0, 2))
      item.socket.write(
        JSON.stringify({ id: item.id, ok: true, value: results.connections }) +
          "\n",
      );
    expect((await healthy).xml).toBe(results.connections.xml);
  } finally {
    await f.close();
  }
});

it("fails a disconnected request without replay and connects for a subsequent request", async () => {
  const { results } = protocol();
  let received = 0;

  const f = await fixture((socket, id) => {
    received++;

    if (received === 1) socket.destroy();
    else
      socket.write(
        JSON.stringify({ id, ok: true, value: results.connections }) + "\n",
      );
  });

  try {
    await expect(
      enforcementRequest(f.path, { operation: "connections" }),
    ).rejects.toThrow("before its complete");
    expect(received).toBe(1);
    expect(
      (await enforcementRequest(f.path, { operation: "connections" })).xml,
    ).toBe(results.connections.xml);
    expect(received).toBe(2);
    expect(f.connections()).toBe(2);
  } finally {
    await f.close();
  }
});

it("bounds incomplete replies and establishes a fresh connection after rejecting them", async () => {
  const { results } = protocol();
  let count = 0;

  const f = await fixture((socket, id) => {
    count++;

    if (count === 1) socket.write(Buffer.alloc(2 * 1024 * 1024 + 1, 32));
    else
      socket.write(
        JSON.stringify({ id, ok: true, value: results.connections }) + "\n",
      );
  });

  try {
    await expect(
      enforcementRequest(f.path, { operation: "connections" }),
    ).rejects.toThrow("exceeds its limit");
    expect(
      await enforcementRequest(f.path, { operation: "connections" }),
    ).toEqual(results.connections);
    expect(f.connections()).toBe(2);
  } finally {
    await f.close();
  }
});

it("rejects oversized outgoing commands before creating a socket", async () => {
  const { commands } = protocol();
  commands.apply.policy.rules[0]!.reason = "x".repeat(2 * 1024 * 1024);

  const f = await fixture(() => {
    throw new Error("Oversized command reached peer");
  });

  try {
    await expect(
      enforcementRequest(f.path, commands.apply),
    ).rejects.toMatchObject({
      status: 413,
      code: "command_capacity",
    });
    expect(f.connections()).toBe(0);
  } finally {
    await f.close();
  }
});

it("keeps the shared prepare schema strict for operation-specific payloads", () => {
  const { commands, results } = protocol();
  expect(
    enforcementCommandSchema.safeParse({
      id: randomUUID(),
      ...commands.status,
      policy: commands.apply.policy,
    }).success,
  ).toBe(false);
  expect(
    enforcementCommandSchema.safeParse({
      id: randomUUID(),
      operation: "events",
      epoch: null,
      after: "01",
    }).success,
  ).toBe(false);
  expect(
    enforcementResultSchemas.prepare.safeParse(results.apply).success,
  ).toBe(false);
});

it("uses a total deadline even when an incomplete peer keeps sending data", async () => {
  let timer: ReturnType<typeof setInterval> | undefined;

  const f = await fixture((socket) => {
    timer = setInterval(() => socket.write(" "), 5);
  });

  try {
    await expect(
      enforcementRequest(f.path, { operation: "status" }, 100),
    ).rejects.toThrow("timed out");
  } finally {
    clearInterval(timer);
    await f.close();
  }
});

it.each([
  { code: 17 },
  { code: "" },
  { code: "x".repeat(65) },
  { message: { reason: "failure" } },
  { status: "503" },
  { status: 200 },
  { ok: "false" },
])("rejects malformed enforcement rejection metadata %j", async (metadata) => {
  const f = await fixture((socket, id) =>
    socket.end(
      JSON.stringify({
        id,
        ok: false,
        status: 503,
        code: "dns_authorization_expired",
        message: "Controlled rejection",
        ...metadata,
      }) + "\n",
    ),
  );

  try {
    await expect(
      enforcementRequest(f.path, { operation: "status" }),
    ).rejects.toMatchObject({
      status: 502,
      code: "invalid_enforcement_response",
      message: "Enforcement service returned an invalid response",
    });
  } finally {
    await f.close();
  }
});

it("preserves valid enforcement rejection metadata", async () => {
  const f = await fixture((socket, id) =>
    socket.end(
      JSON.stringify({
        id,
        ok: false,
        status: 429,
        code: "busy",
        message: "Enforcement queue is full",
      }) + "\n",
    ),
  );

  try {
    await expect(
      enforcementRequest(f.path, { operation: "status" }),
    ).rejects.toMatchObject({
      status: 429,
      code: "busy",
      message: "Enforcement queue is full",
    });
  } finally {
    await f.close();
  }
});

it("rejects a successful envelope without its required operation result", async () => {
  const f = await fixture((socket, id) =>
    socket.end(JSON.stringify({ id, ok: true }) + "\n"),
  );

  try {
    await expect(
      enforcementRequest(f.path, { operation: "status" }),
    ).rejects.toMatchObject({
      code: "invalid_enforcement_response",
      status: 502,
    });
  } finally {
    await f.close();
  }
});

it("preserves a enforcement error code at the 64-character boundary", async () => {
  const code = "x".repeat(64);

  const f = await fixture((socket, id) =>
    socket.end(
      JSON.stringify({
        id,
        ok: false,
        status: 503,
        code,
        message: "Controlled rejection",
      }) + "\n",
    ),
  );

  try {
    await expect(
      enforcementRequest(f.path, { operation: "status" }),
    ).rejects.toMatchObject({ code });
  } finally {
    await f.close();
  }
});
