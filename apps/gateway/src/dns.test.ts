import { expect, it, vi } from "vitest";
import { createSocket, type Socket as DatagramSocket } from "node:dgram";
import { createServer, createConnection, type Socket } from "node:net";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import dnsPacket from "dns-packet";
import { z } from "zod";
import {
  resolutionSchema,
  type ResolutionReceipt,
} from "@traffic-policy/contracts";
import { ServiceError } from "@traffic-policy/core/io";
import {
  startDnsGate,
  configureDnsReceiveBuffer,
  dnsReceiveBuffers,
} from "./dns.ts";
import { CommandFrame } from "./command-frame.ts";
import {
  DnsFailureDiagnostics,
  type DnsDiagnostic,
} from "./dns-diagnostics.ts";
import type { GatewayConfig } from "./config.ts";

async function fixture(
  mode:
    | "success"
    | "enforcement_failure"
    | "validation_failure"
    | "malformed_enforcement",
  now: () => number = () => performance.now(),
  options: {
    holdEnforcement?: boolean;
    recordWait?: Promise<void>;
    enforcementMessage?: string;
    recordError?: Error;
    trickleTcp?: boolean;
    silentUdp?: boolean;
    enrolled?: boolean;
    compressedResponse?: boolean;
    wrongTcpQuestion?: boolean;
    questionType?: number;
    denied?: boolean;
    revokeAfterQuery?: boolean;
    questionName?: string;
    responseCode?: number;
    admissionFailure?: boolean;
  } = {},
) {
  const base = join(process.cwd(), ".local/tmp/tests/dns-logging");
  await mkdir(base, { recursive: true });
  const directory = await mkdtemp(join(base, "fixture-"));
  const path = join(directory, "enforcement.sock");
  const upstream = createSocket("udp4");
  let upstreamCalls = 0;

  const upstreamAnswer = (bytes: Buffer) => {
    upstreamCalls++;
    const query = dnsPacket.decode(bytes);
    const question = query.questions![0]!;

    if (options.responseCode)
      return dnsPacket.encode({
        type: "response",
        id: query.id,
        flags: 0x180 | options.responseCode,
        questions: query.questions,
      });

    if (options.questionType) {
      const header = dnsPacket.encode({
        type: "response",
        id: query.id,
        flags: 0x1a0,
        questions: query.questions,
      });

      const record = Buffer.alloc(12);
      const data = Buffer.from([0, 1, 0, 0, 1, 0, 3, 2, 104, 50]);

      header.writeUInt16BE(1, 6);
      record.writeUInt16BE(0xc00c, 0);
      record.writeUInt16BE(options.questionType, 2);
      record.writeUInt16BE(1, 4);
      record.writeUInt32BE(60, 6);
      record.writeUInt16BE(data.length, 10);

      return Buffer.concat([header, record, data]);
    }

    if (options.compressedResponse) {
      const header = dnsPacket.encode({
        type: "response",
        id: query.id,
        flags: 0x180,
        questions: query.questions,
      });

      header.writeUInt16BE(1, 6);

      return Buffer.concat([
        header,
        Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 2, 0, 4, 127, 0, 0, 2]),
      ]);
    }

    return dnsPacket.encode({
      type: "response",
      id: query.id,
      flags: 0x180,
      questions: query.questions,
      answers: Array.from(
        { length: mode === "validation_failure" ? 257 : 1 },
        () => ({
          name: question.name,
          type: "A",
          class: "IN",
          ttl: 2,
          data: "127.0.0.2",
        }),
      ),
    });
  };

  upstream.on("message", (bytes, peer) => {
    if (!options.silentUdp)
      upstream.send(upstreamAnswer(bytes), peer.port, peer.address);
  });
  await new Promise<void>((resolve) => upstream.bind(0, "127.0.0.1", resolve));
  const upstreamClients = new Set<Socket>();
  let forwarded = () => {};

  const tcpForwarded = new Promise<void>((resolve) => {
    forwarded = resolve;
  });

  const upstreamTcp = createServer((socket) => {
    upstreamClients.add(socket);
    socket.once("close", () => upstreamClients.delete(socket));
    socket.on("error", () => {});
    let input = Buffer.alloc(0);
    let answered = false;
    let trickle: ReturnType<typeof setInterval> | undefined;
    socket.once("close", () => clearInterval(trickle));
    socket.on("data", (bytes) => {
      if (answered) return;
      input = Buffer.concat([input, bytes]);

      if (input.length < 2 || input.length < input.readUInt16BE(0) + 2) return;
      answered = true;
      forwarded();

      if (options.trickleTcp) {
        socket.write(Buffer.from([255, 255]));
        trickle = setInterval(() => socket.write(Buffer.from([0])), 100);

        return;
      }

      const answer = upstreamAnswer(
        input.subarray(2, input.readUInt16BE(0) + 2),
      );

      const output = options.wrongTcpQuestion
        ? dnsPacket.encode({
            ...dnsPacket.decode(answer),
            questions: [{ name: "wrong.example", type: "A", class: "IN" }],
          })
        : answer;

      const length = Buffer.alloc(2);
      length.writeUInt16BE(output.length);
      socket.end(Buffer.concat([length, output]));
    });
  });

  await new Promise<void>((resolve) =>
    upstreamTcp.listen(upstream.address().port, "127.0.0.1", resolve),
  );
  const clients = new Set<Socket>();
  let enforcementCalls = 0;
  let held = options.holdEnforcement ?? false;
  const replies: (() => void)[] = [];
  const enforcementWaiters: { count: number; resolve: () => void }[] = [];

  const releaseEnforcement = () => {
    held = false;
    replies.splice(0).forEach((reply) => reply());
  };

  const command = z
    .object({
      id: z.string().uuid(),
      operation: z.literal("resolve"),
      resolution: resolutionSchema,
    })
    .strict();

  const receipt: ResolutionReceipt = {
    protocolVersion: 1,
    revision: "45",
    policyHash: "a".repeat(64),
    bootId: "11111111-1111-4111-8111-111111111111",
    appliedAt: new Date().toISOString(),
    permissions: 1,
    instanceId: "22222222-2222-4222-8222-222222222222",
  };

  const decision = () => ({
    allowed:
      !options.denied && !(options.revokeAfterQuery && upstreamCalls > 0),
    instanceId: receipt.instanceId,
    revision: receipt.revision,
    policyHash: receipt.policyHash,
    ruleId: "33333333-3333-4333-8333-333333333333",
    catchAll: true,
  });

  // The enforcement service may already hold a policy the gateway has not recorded.
  const enforcementDenial = {
    ...decision(),
    allowed: false,
    revision: "46",
    policyHash: "b".repeat(64),
  };

  const enforcement = createServer({ allowHalfOpen: true }, (socket) => {
    clients.add(socket);
    socket.on("error", () => {});
    socket.once("close", () => clients.delete(socket));
    const frames = new CommandFrame();
    socket.on("data", (bytes) => {
      frames.write(bytes, (raw) => {
        const request = command.parse(raw);
        enforcementCalls++;

        const reply = () =>
          socket.write(
            JSON.stringify(
              mode === "enforcement_failure" || mode === "malformed_enforcement"
                ? {
                    id: request.id,
                    ok: false,
                    status: 503,
                    code:
                      mode === "malformed_enforcement"
                        ? 17
                        : "dns_authorization_expired",
                    message:
                      options.enforcementMessage ??
                      "Controlled enforcement rejection",
                  }
                : {
                    id: request.id,
                    ok: true,
                    value: options.revokeAfterQuery
                      ? enforcementDenial
                      : receipt,
                  },
            ) + "\n",
          );

        if (held) replies.push(reply);
        else reply();

        for (const waiter of enforcementWaiters)
          if (enforcementCalls >= waiter.count) waiter.resolve();
      });
    });
  });

  await new Promise<void>((resolve) => enforcement.listen(path, resolve));
  const reservation = createServer();
  await new Promise<void>((resolve) =>
    reservation.listen(0, "127.0.0.1", resolve),
  );
  const address = reservation.address();

  if (!address || !(address instanceof Object)) throw new Error("Missing port");
  await new Promise<void>((resolve) => reservation.close(() => resolve()));

  const config: GatewayConfig = {
    gatewayId: "33333333-3333-4333-8333-333333333333",
    listenAddress: "127.0.0.1",
    machinePort: 9443,
    controllerUrl: "https://127.0.0.1:9445",
    controllerIdentity: "fixture-controller",
    dnsListenAddresses: ["127.0.0.1"],
    dnsPort: address.port,
    dnsReceiveBufferBytes: 65536,
    upstreamDns: { address: "127.0.0.1", port: upstream.address().port },
    enforcementSocket: path,
    stateDirectory: directory,
    collectorBytes: "1048576",
    suricataFile: join(directory, "suricata", "eve.json"),
    tls: { ca: "unused", certificate: "unused", key: "unused" },
  };

  const entries: DnsDiagnostic[] = [];
  const confirmations: (ResolutionReceipt | null)[] = [];
  const denials: import("./dns.ts").DnsDenial[] = [];

  const diagnostics = new DnsFailureDiagnostics(
    (entry) => entries.push(entry),
    now,
  );

  const observations = new DnsFailureDiagnostics(
    (entry) => entries.push(entry),
    now,
    "resolver-observation",
  );

  const close = await startDnsGate(
    config,
    async (_resolution, confirmation) => {
      await options.recordWait;

      if (options.recordError) throw options.recordError;
      confirmations.push(confirmation);
    },
    () => {
      if (options.admissionFailure)
        throw new ServiceError(
          503,
          "not_initialized",
          "No policy has been applied",
        );

      return options.enrolled === false ? null : decision();
    },
    async (denial) => {
      denials.push(denial);
    },
    diagnostics,
    observations,
    (socket) => configureDnsReceiveBuffer(socket, 128 * 1024),
  );

  const sender = createSocket("udp4");

  const receive = () =>
    new Promise<ReturnType<typeof dnsPacket.decode>>((resolve, reject) => {
      const message = (bytes: Buffer) => {
        sender.off("error", error);
        resolve(dnsPacket.decode(bytes));
      };

      const error = (cause: Error) => {
        sender.off("message", message);
        reject(cause);
      };

      sender.once("message", message);
      sender.once("error", error);
    });

  const answer = receive();

  const initialQuery = dnsPacket.encode({
    type: "query",
    id: 17,
    flags: 0x100,
    questions: [
      { name: options.questionName ?? "proof.example", type: "A", class: "IN" },
    ],
  });

  if (options.questionType)
    initialQuery.writeUInt16BE(options.questionType, initialQuery.length - 4);
  sender.send(initialQuery, address.port, "127.0.0.1");

  return {
    config,
    entries,
    confirmations,
    denials,
    answer,
    port: address.port,
    waitForTcpForward: () => tcpForwarded,
    stop: close,
    holdEnforcement: () => {
      held = true;
    },
    releaseEnforcement,
    waitForEnforcement: (count: number) =>
      enforcementCalls >= count
        ? Promise.resolve()
        : new Promise<void>((resolve) =>
            enforcementWaiters.push({ count, resolve }),
          ),
    enforcementCalls: () => enforcementCalls,
    upstreamCalls: () => upstreamCalls,
    exchange: () => {
      const reply = receive();

      sender.send(
        dnsPacket.encode({
          type: "query",
          id: 17,
          flags: 0x100,
          questions: [{ name: "proof.example", type: "A", class: "IN" }],
        }),
        address.port,
        "127.0.0.1",
      );

      return reply;
    },
    close: async () => {
      releaseEnforcement();
      await close();
      sender.close();
      await new Promise<void>((resolve) => upstream.close(resolve));

      for (const socket of upstreamClients) socket.destroy();
      await new Promise<void>((resolve) => upstreamTcp.close(() => resolve()));

      for (const socket of clients) socket.destroy();
      await new Promise<void>((resolve) => enforcement.close(() => resolve()));
      await rm(directory, { recursive: true });
    },
  };
}

it("releases all bound listeners when configuring a later DNS buffer fails", async () => {
  const lab = await fixture("success");

  try {
    await lab.answer;
    await lab.stop();
    const config = { ...lab.config, dnsListenAddresses: ["127.0.0.1", "::1"] };
    let configured = 0;

    await expect(
      startDnsGate(
        config,
        async () => {},
        () => {
          throw new Error("unused");
        },
        async () => {},
        undefined,
        undefined,
        (socket) => {
          configured++;

          if (configured === 2) throw new Error("Receive buffer rejected");
          configureDnsReceiveBuffer(socket, 128 * 1024);
        },
      ),
    ).rejects.toThrow("Receive buffer rejected");
    expect(configured).toBe(2);

    const stop = await startDnsGate(
      config,
      async () => {},
      () => {
        throw new Error("unused");
      },
      async () => {},
      undefined,
      undefined,
      (socket) => configureDnsReceiveBuffer(socket, 128 * 1024),
    );

    await stop();
  } finally {
    await lab.close();
  }
});

function tcpExchange(port: number, questionType = 1) {
  const socket = createConnection({ host: "127.0.0.1", port });
  socket.on("error", () => {});

  const connected = new Promise<void>((resolve) =>
    socket.once("connect", resolve),
  );

  let wire: Buffer | null = null;

  const reply = new Promise<ReturnType<typeof dnsPacket.decode>>(
    (resolve, reject) => {
      let input = Buffer.alloc(0);
      socket.on("data", (bytes) => {
        input = Buffer.concat([input, bytes]);

        if (input.length < 2 || input.length < input.readUInt16BE(0) + 2)
          return;

        try {
          wire = Buffer.from(input.subarray(2, input.readUInt16BE(0) + 2));
          resolve(dnsPacket.decode(wire));
        } catch (error) {
          reject(error);
        }
      });
    },
  );

  const packet = dnsPacket.encode({
    type: "query",
    id: 37,
    flags: 0x100,
    questions: [{ name: "proof.example", type: "A", class: "IN" }],
  });

  packet.writeUInt16BE(questionType, packet.length - 4);

  const length = Buffer.alloc(2);
  length.writeUInt16BE(packet.length);
  const frame = Buffer.concat([length, packet]);

  return {
    socket,
    connected,
    reply,
    wireBytes: () => wire,
    send: (copies = 1) =>
      socket.write(Buffer.concat(Array.from({ length: copies }, () => frame))),
  };
}

it.each([1, 16, 28, 64, 65])(
  "refuses unapproved DNS type %s before contacting upstream",
  async (type) => {
    const f = await fixture("success", undefined, {
      questionType: type,
      denied: true,
    });

    try {
      const answer = await f.answer;
      expect((answer.flags ?? 0) & 15).toBe(5);
      expect(answer.answers).toEqual([]);
      expect(f.upstreamCalls()).toBe(0);
      expect(f.denials).toMatchObject([
        { question: "proof.example", decision: { allowed: false } },
      ]);
      const tcp = tcpExchange(f.port, type);

      try {
        await tcp.connected;
        tcp.send();
        expect(((await tcp.reply).flags ?? 0) & 15).toBe(5);
        expect(f.upstreamCalls()).toBe(0);
      } finally {
        tcp.socket.destroy();
      }
    } finally {
      await f.close();
    }
  },
);

it.each([undefined, 65])(
  "withholds DNS type %s when policy changes during the upstream request",
  async (questionType) => {
    const f = await fixture("success", undefined, {
      questionType,
      revokeAfterQuery: true,
    });

    try {
      const answer = await f.answer;
      expect((answer.flags ?? 0) & 15).toBe(5);
      expect(answer.answers).toEqual([]);
      expect(f.upstreamCalls()).toBe(1);
      expect(f.confirmations).toEqual([]);
      // An A answer is withheld by the enforcement service's check, and the denial names the enforcement service's policy.
      expect(f.denials).toMatchObject([
        { decision: { allowed: false, revision: questionType ? "45" : "46" } },
      ]);
    } finally {
      await f.close();
    }
  },
);

it("returns SERVFAIL without upstream traffic before the gateway has a confirmed policy", async () => {
  const f = await fixture("success", undefined, { admissionFailure: true });

  try {
    expect(((await f.answer).flags ?? 0) & 15).toBe(2);
    expect(f.upstreamCalls()).toBe(0);
    expect(f.denials).toEqual([]);
    expect(f.entries).toMatchObject([
      { code: "not_initialized", stage: "admission" },
    ]);
  } finally {
    await f.close();
  }
});

it.each([
  "bad\u0001.example",
  "Office Printer._ipp._tcp.example.com",
  "*.example.com",
  // Forms that canonicalName would accept but that ask upstream for another name.
  "bücher.example",
  " padded.example",
])(
  "refuses the question %j without upstream traffic or a recorded request",
  async (questionName) => {
    const f = await fixture("success", undefined, { questionName });

    try {
      expect(((await f.answer).flags ?? 0) & 15).toBe(5);
      expect(f.upstreamCalls()).toBe(0);
      expect(f.denials).toEqual([]);
      expect(f.entries).toMatchObject([
        { code: "dns_invalid_name", stage: "admission", upstreamMs: null },
      ]);
    } finally {
      await f.close();
    }
  },
);

it.each([false, true])(
  "checks the root question and preserves an admitted negative response, denied %s",
  async (denied) => {
    const f = await fixture("success", undefined, {
      questionName: ".",
      responseCode: 3,
      denied,
    });

    try {
      expect(((await f.answer).flags ?? 0) & 15).toBe(denied ? 5 : 3);
      expect(f.upstreamCalls()).toBe(denied ? 0 : 1);
      expect(f.enforcementCalls()).toBe(0);

      if (denied) expect(f.denials[0]?.question).toBe(".");
    } finally {
      await f.close();
    }
  },
);

it.each([64, 65])(
  "preserves upstream DNS type %s replies over UDP and TCP without creating permissions",
  async (type) => {
    const f = await fixture("success", undefined, { questionType: type });

    try {
      const answer = await f.answer;
      expect(answer.id).toBe(17);
      expect((answer.flags ?? 0) & 15).toBe(0);
      expect((answer.flags ?? 0) & 0x1a0).toBe(0x1a0);
      expect(answer.answers).toMatchObject([
        {
          name: "proof.example",
          type: `UNKNOWN_${type}`,
          class: "IN",
          ttl: 60,
          data: Buffer.from([0, 1, 0, 0, 1, 0, 3, 2, 104, 50]),
        },
      ]);
      expect(answer.questions?.[0]?.type).toBe(`UNKNOWN_${type}`);
      const tcp = tcpExchange(f.port, type);

      try {
        await tcp.connected;
        tcp.send();
        const reply = await tcp.reply;
        expect(reply.id).toBe(37);
        expect(reply.answers).toEqual(answer.answers);
        expect((reply.flags ?? 0) & 0x1a0).toBe(0x1a0);
        expect((reply.flags ?? 0) & 15).toBe(0);
      } finally {
        tcp.socket.destroy();
      }

      expect(f.enforcementCalls()).toBe(0);
      expect(f.upstreamCalls()).toBe(2);
      expect(f.confirmations).toEqual([]);
    } finally {
      await f.close();
    }
  },
);

it("refuses HTTPS discovery from an unenrolled client", async () => {
  const f = await fixture("success", undefined, {
    questionType: 65,
    enrolled: false,
  });

  try {
    expect(((await f.answer).flags ?? 0) & 15).toBe(2);
    expect(f.upstreamCalls()).toBe(0);
  } finally {
    await f.close();
  }
});

it("accepts compressed TCP answers, restores the client ID and authorizes the decoded answer", async () => {
  const f = await fixture("success", undefined, { compressedResponse: true });
  const exchange = tcpExchange(f.port);

  try {
    await f.answer;
    const calls = f.enforcementCalls();
    await exchange.connected;
    exchange.send();
    const reply = await exchange.reply;
    expect(reply.id).toBe(37);
    expect(reply.answers?.[0]).toMatchObject({
      name: "proof.example",
      data: "127.0.0.2",
    });
    expect(f.enforcementCalls()).toBe(calls + 1);

    const wire = exchange.wireBytes()!;
    expect(wire.readUInt16BE(0)).toBe(37);
    expect(dnsPacket.decode(wire)).toEqual(reply);
  } finally {
    exchange.socket.destroy();
    await f.close();
  }
});

it("rejects a mismatched TCP question before authorizing its answer", async () => {
  const f = await fixture("success", undefined, { wrongTcpQuestion: true });
  const exchange = tcpExchange(f.port);

  try {
    await f.answer;
    const calls = f.enforcementCalls();
    await exchange.connected;
    exchange.send();
    expect(((await exchange.reply).flags ?? 0) & 15).toBe(2);
    expect(f.enforcementCalls()).toBe(calls);
    expect(f.entries).toContainEqual(
      expect.objectContaining({
        event: "dns_failure",
        code: "validation_failure",
        stage: "validation",
      }),
    );
  } finally {
    exchange.socket.destroy();
    await f.close();
  }
});

it("reports admission failures before forwarding a query", async () => {
  const f = await fixture("success", undefined, { enrolled: false });

  try {
    expect(((await f.answer).flags ?? 0) & 15).toBe(2);
    expect(f.enforcementCalls()).toBe(0);
    expect(f.entries).toContainEqual(
      expect.objectContaining({
        event: "dns_failure",
        stage: "admission",
        code: "dns_client_not_enrolled",
        upstreamMs: null,
        enforcementMs: null,
      }),
    );
  } finally {
    await f.close();
  }
});

it("keeps successful DNS answers, TTLs and enforcement receipts unchanged without diagnostics", async () => {
  const f = await fixture("success");

  try {
    const answer = await f.answer;
    expect((answer.flags ?? 0) & 15).toBe(0);
    expect(answer.id).toBe(17);
    expect(answer.answers?.[0]).toMatchObject({ ttl: 2, data: "127.0.0.2" });
    expect(f.confirmations[0]).toMatchObject({
      revision: "45",
      permissions: 1,
    });
    expect(f.enforcementCalls()).toBe(1);
    expect(f.entries).toHaveLength(0);
  } finally {
    await f.close();
  }
});

it("preserves the enforcement service rejection code and stage while returning the existing SERVFAIL", async () => {
  const f = await fixture("enforcement_failure");

  try {
    const answer = await f.answer;
    expect((answer.flags ?? 0) & 15).toBe(2);
    expect(answer.id).toBe(17);
    expect(f.confirmations).toEqual([null]);
    expect(f.entries[0]).toMatchObject({
      event: "dns_failure",
      code: "dns_authorization_expired",
      message: "DNS authorization failed",
      stage: "enforcement",
    });
    const entry = f.entries[0];

    if (entry.event !== "dns_failure") throw new Error("Missing detail");
    expect(entry.upstreamMs).toBeGreaterThanOrEqual(0);
    expect(entry.enforcementMs).toBeGreaterThanOrEqual(0);
    expect(entry.responseAgeMs).toBeGreaterThanOrEqual(0);
  } finally {
    await f.close();
  }
});

it("keeps DNS answer addresses and query text out of enforcement failure diagnostics", async () => {
  const message =
    "nft failed: add element private.example { 198.51.100.44 } certificate-secret";

  const f = await fixture("enforcement_failure", () => 0, {
    enforcementMessage: message,
  });

  try {
    expect((await f.answer).flags! & 15).toBe(2);
    await f.stop();
    expect(f.entries[0]).toMatchObject({
      code: "dns_authorization_expired",
      message: "DNS authorization failed",
    });

    for (const value of [
      "private.example",
      "198.51.100.44",
      "certificate-secret",
    ])
      expect(JSON.stringify(f.entries)).not.toContain(value);
  } finally {
    await f.close();
  }
});

it("bounds persistence diagnostics independently while returning successful DNS answers", async () => {
  const f = await fixture("success", () => 0, {
    recordError: new Error("Private observation data"),
  });

  try {
    expect((await f.answer).flags! & 15).toBe(0);

    for (let count = 1; count < 500; count++)
      expect((await f.exchange()).flags! & 15).toBe(0);
    await f.stop();
    expect(
      f.entries.filter((entry) => entry.service === "resolver-gate"),
    ).toHaveLength(0);
    expect(
      f.entries.filter((entry) => entry.event === "dns_failure"),
    ).toHaveLength(20);
    expect(f.entries.at(-1)).toMatchObject({
      service: "resolver-observation",
      event: "dns_failure_summary",
      failures: 500,
      detailed: 20,
      suppressed: 480,
    });
    expect(JSON.stringify(f.entries)).not.toContain("Private observation data");
  } finally {
    await f.close();
  }
}, 15000);

it("identifies upstream validation failure without contacting the enforcement service", async () => {
  const f = await fixture("validation_failure");

  try {
    const answer = await f.answer;
    expect((answer.flags ?? 0) & 15).toBe(2);
    expect(f.enforcementCalls()).toBe(0);
    expect(f.entries[0]).toMatchObject({
      event: "dns_failure",
      code: "validation_failure",
      stage: "validation",
      enforcementMs: null,
      responseAgeMs: null,
    });
  } finally {
    await f.close();
  }
});

it("returns all 500 failure replies while suppressing detailed logs and retaining exact totals", async () => {
  const f = await fixture("enforcement_failure", () => 0);

  try {
    expect((await f.answer).flags! & 15).toBe(2);

    for (let count = 1; count < 500; count++)
      expect((await f.exchange()).flags! & 15).toBe(2);
  } finally {
    await f.close();
  }

  expect(f.enforcementCalls()).toBe(500);
  expect(
    f.entries.filter((entry) => entry.event === "dns_failure"),
  ).toHaveLength(20);
  expect(
    f.entries.filter((entry) => entry.event === "dns_diagnostics_rate_limited"),
  ).toHaveLength(1);
  expect(f.entries.at(-1)).toMatchObject({
    event: "dns_failure_summary",
    failures: 500,
    detailed: 20,
    suppressed: 480,
    byCode: [{ code: "dns_authorization_expired", failures: 500 }],
  });
}, 15000);

it("returns SERVFAIL and records the failure when enforcement rejection metadata is malformed", async () => {
  const f = await fixture("malformed_enforcement");

  try {
    expect((await f.answer).flags! & 15).toBe(2);
    await f.stop();
    expect(f.confirmations).toEqual([null]);
    expect(f.entries[0]).toMatchObject({
      event: "dns_failure",
      code: "invalid_enforcement_response",
      stage: "enforcement",
    });
    expect(f.entries.at(-1)).toMatchObject({
      event: "dns_failure_summary",
      failures: 1,
    });
  } finally {
    await f.close();
  }
});

it("drains an admitted DNS failure and its observation before flushing diagnostics", async () => {
  let finishRecord = () => {};

  const recordWait = new Promise<void>((resolve) => {
    finishRecord = resolve;
  });

  const f = await fixture("enforcement_failure", () => 0, {
    holdEnforcement: true,
    recordWait,
  });

  try {
    await f.waitForEnforcement(1);
    let drained = false;

    const drain = f.stop().then(() => {
      drained = true;
    });

    expect(f.stop()).toBe(f.stop());
    await new Promise((resolve) => setImmediate(resolve));
    expect(drained).toBe(false);
    expect(f.entries).toHaveLength(0);
    f.releaseEnforcement();
    expect((await f.answer).flags! & 15).toBe(2);
    expect(drained).toBe(false);
    expect(
      f.entries.filter((entry) => entry.event === "dns_failure_summary"),
    ).toHaveLength(0);
    finishRecord();
    await drain;
    expect(f.confirmations).toEqual([null]);
    expect(f.entries.at(-1)).toMatchObject({
      event: "dns_failure_summary",
      failures: 1,
      detailed: 1,
      suppressed: 0,
    });
  } finally {
    finishRecord();
    await f.close();
  }
});

it("drains admitted TCP work and prevents queued TCP work from starting after shutdown", async () => {
  const f = await fixture("enforcement_failure");
  const exchange = tcpExchange(f.port);

  try {
    await f.answer;
    await exchange.connected;
    f.holdEnforcement();

    exchange.send(2);
    await f.waitForEnforcement(2);
    const drain = f.stop();
    f.releaseEnforcement();
    expect((await exchange.reply).flags! & 15).toBe(2);
    await drain;
    expect(f.enforcementCalls()).toBe(2);
    expect(f.entries.at(-1)).toMatchObject({
      event: "dns_failure_summary",
      failures: 2,
    });
  } finally {
    exchange.socket.destroy();
    await f.close();
  }
});

it("enforces the total two-second UDP upstream deadline", async () => {
  const started = performance.now();
  const f = await fixture("success", undefined, { silentUdp: true });

  try {
    expect((await f.answer).flags! & 15).toBe(2);
    expect(performance.now() - started).toBeGreaterThanOrEqual(1800);
    expect(performance.now() - started).toBeLessThan(4500);
    await f.stop();
    expect(f.enforcementCalls()).toBe(0);
    expect(f.entries[0]).toMatchObject({
      code: "upstream_dns_timeout",
      stage: "upstream",
    });
  } finally {
    await f.close();
  }
});

it("times out trickled TCP upstream replies and drains shutdown within the total deadline", async () => {
  const f = await fixture("success", undefined, { trickleTcp: true });
  const exchange = tcpExchange(f.port);

  try {
    await f.answer;
    await exchange.connected;
    const started = performance.now();
    exchange.send();
    await f.waitForTcpForward();
    const drain = f.stop();
    expect((await exchange.reply).flags! & 15).toBe(2);
    await drain;
    expect(performance.now() - started).toBeGreaterThanOrEqual(1800);
    expect(performance.now() - started).toBeLessThan(4500);
    expect(f.enforcementCalls()).toBe(1);
    expect(f.entries[0]).toMatchObject({
      code: "upstream_dns_timeout",
      stage: "upstream",
    });
  } finally {
    exchange.socket.destroy();
    await f.close();
  }
});

it("preserves a TCP query while enforcement work outlasts the client idle timeout", async () => {
  const f = await fixture("success");
  const exchange = tcpExchange(f.port);

  try {
    await f.answer;
    await exchange.connected;
    f.holdEnforcement();
    exchange.send();
    await f.waitForEnforcement(2);
    await new Promise((resolve) => setTimeout(resolve, 5500));
    expect(exchange.socket.destroyed).toBe(false);
    f.releaseEnforcement();
    expect((await exchange.reply).flags! & 15).toBe(0);
    await f.stop();
    expect(f.entries).toHaveLength(0);
  } finally {
    exchange.socket.destroy();
    await f.close();
  }
}, 12000);

it("reports a receive buffer the kernel caps instead of failing", () => {
  // Linux reports twice the granted SO_RCVBUF; this socket is granted at most 4 MiB.
  let granted = 0;

  const socket = {
    setRecvBufferSize: (bytes: number) => {
      granted = Math.min(bytes, 4194304);
    },
    getRecvBufferSize: () => granted * 2,
  } as Pick<DatagramSocket, "setRecvBufferSize" | "getRecvBufferSize">;

  const log = vi.spyOn(console, "error").mockImplementation(() => {});

  try {
    expect(configureDnsReceiveBuffer(socket, 4194304)).toBeNull();

    const capped = configureDnsReceiveBuffer(socket, 8388608);

    expect(capped).toContain("is 4194304 bytes, below the configured 8388608");
    expect(capped).toContain("Raise net.core.rmem_max to 8388608");
    expect(log).toHaveBeenCalledOnce();
  } finally {
    log.mockRestore();
  }
});

it("configures every DNS listener and reports the first capped one", () => {
  const listener = (limit: number) => {
    let granted = 0;

    return {
      requested: [] as number[],
      setRecvBufferSize(bytes: number) {
        this.requested.push(bytes);
        granted = Math.min(bytes, limit);
      },
      getRecvBufferSize: () => granted * 2,
    };
  };

  const sockets = [listener(4194304), listener(2097152), listener(8388608)];
  const buffers = dnsReceiveBuffers(8388608);
  const log = vi.spyOn(console, "error").mockImplementation(() => {});

  try {
    for (const socket of sockets) buffers.configure(socket);
  } finally {
    log.mockRestore();
  }

  expect(sockets.map((socket) => socket.requested)).toEqual([
    [8388608],
    [8388608],
    [8388608],
  ]);
  expect(buffers.condition).toContain("is 4194304 bytes");
});
