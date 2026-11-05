import { expect, it } from "vitest";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { createConnection } from "node:net";
import { randomUUID } from "node:crypto";
import {
  createEnforcementTransport,
  type EnforcementDispatch,
} from "./enforcement-transport.ts";
import {
  enforcementRequest,
  closeEnforcementConnections,
} from "./enforcement-client.ts";
import { ENFORCEMENT_DNS_LIMIT } from "./enforcement-admission.ts";
import { MAX_MACHINE_FRAME_BYTES } from "@traffic-policy/contracts";

const receipt = {
  protocolVersion: 1 as const,
  revision: "1",
  policyHash: "a".repeat(64),
  bootId: "11111111-1111-4111-8111-111111111111",
  appliedAt: new Date().toISOString(),
  permissions: 1,
  instanceId: "22222222-2222-4222-8222-222222222222",
};

const query = {
  operation: "resolve" as const,
  resolution: {
    clientIp: "10.0.0.1",
    question: "example.com",
    responseAt: new Date().toISOString(),
    answers: [],
  },
};

function deferred() {
  let resolve = () => {};

  const promise = new Promise<void>((accept) => {
    resolve = accept;
  });

  return { promise, resolve };
}

async function fixture(dispatch: EnforcementDispatch) {
  const base = join(process.cwd(), ".tmp/tests/enforcement-transport");
  await mkdir(base, { recursive: true });

  const directory = await mkdtemp(join(base, "transport-")),
    path = join(directory, "enforcement.sock");

  const transport = createEnforcementTransport(dispatch);
  let connections = 0;
  transport.server.on("connection", () => {
    connections++;
  });
  await new Promise<void>((resolve, reject) => {
    transport.server.once("error", reject);
    transport.server.listen(path, resolve);
  });

  return {
    path,
    transport,
    connections: () => connections,
    close: async () => {
      closeEnforcementConnections(path);
      await transport.close();
      await rm(directory, { recursive: true });
    },
  };
}

it("admits 512 concurrent DNS RPCs on one connection and serves independent control work", async () => {
  const held = deferred(),
    admitted = deferred();

  let count = 0;

  const f = await fixture(async (command) => {
    if (command.operation === "resolve") {
      count++;

      if (count === 512) admitted.resolve();
      await held.promise;

      return receipt;
    }

    return {
      bootId: receipt.bootId,
      revision: receipt.revision,
      policyHash: receipt.policyHash,
      instances: [],
      gatewayAddresses: [],
      observedAt: new Date().toISOString(),
      xml: "control available",
    };
  });

  try {
    const requests = Array.from({ length: 512 }, () =>
      enforcementRequest(f.path, query),
    );

    await admitted.promise;
    expect(count).toBe(512);
    expect(f.connections()).toBe(1);
    expect(
      (await enforcementRequest(f.path, { operation: "connections" })).xml,
    ).toBe("control available");
    expect(f.connections()).toBe(2);
    held.resolve();
    expect(await Promise.all(requests)).toHaveLength(512);
    expect(await enforcementRequest(f.path, query)).toEqual(receipt);
    expect(f.connections()).toBe(2);
  } finally {
    held.resolve();
    await f.close();
  }
});

it("releases settled command slots before delayed response write callbacks", async () => {
  const callbacks = deferred();
  let dispatched = 0;

  const f = await fixture(async () => {
    dispatched++;

    return receipt;
  });

  f.transport.server.on("connection", (socket) => {
    const write = socket.write.bind(socket);
    socket.write = (
      chunk: string | Uint8Array,
      encodingOrCallback?: BufferEncoding | ((error?: Error | null) => void),
      callback?: (error?: Error | null) => void,
    ) => {
      // oxlint-disable anti-slop/no-runtime-typeof -- This fixture preserves Node's overloaded write arguments while deliberately delaying callback notification.
      const done =
        typeof encodingOrCallback === "function"
          ? encodingOrCallback
          : callback;

      const encoding =
        typeof encodingOrCallback === "string" ? encodingOrCallback : "utf8";
      // oxlint-enable anti-slop/no-runtime-typeof

      return write(chunk, encoding, (error) => {
        void callbacks.promise.then(() => done?.(error));
      });
    };
  });

  try {
    expect(
      await Promise.all(
        Array.from({ length: ENFORCEMENT_DNS_LIMIT }, () =>
          enforcementRequest(f.path, query),
        ),
      ),
    ).toHaveLength(ENFORCEMENT_DNS_LIMIT);
    expect(await enforcementRequest(f.path, query)).toEqual(receipt);
    expect(dispatched).toBe(ENFORCEMENT_DNS_LIMIT + 1);
    let closed = false;

    const closing = f.transport.close().then(() => {
      closed = true;
    });

    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(closed).toBe(false);
    callbacks.resolve();
    await closing;
  } finally {
    callbacks.resolve();
    await f.close();
  }
}, 15000);

it("rejects duplicate in-flight identities and drains admitted work after disconnection", async () => {
  const held = deferred(),
    admitted = deferred();

  let completed = false,
    count = 0;

  const f = await fixture(async () => {
    count++;
    admitted.resolve();
    await held.promise;
    completed = true;

    return receipt;
  });

  const socket = createConnection(f.path);
  socket.on("error", () => {});

  const closed = new Promise<void>((resolve) =>
    socket.once("close", () => resolve()),
  );

  try {
    const command = JSON.stringify({ ...query, id: randomUUID() }) + "\n";
    socket.write(command + command);
    await admitted.promise;
    await closed;
    expect(count).toBe(1);
    let drained = false;

    const closing = f.transport.close().then(() => {
      drained = true;
    });

    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(drained).toBe(false);
    expect(completed).toBe(false);
    held.resolve();
    await closing;
    expect(completed).toBe(true);
  } finally {
    held.resolve();
    socket.destroy();
    await f.close();
  }
});

it("drains accepted commands and closes idle persistent connections during shutdown", async () => {
  const held = deferred(),
    admitted = deferred();

  const f = await fixture(async () => {
    admitted.resolve();
    await held.promise;

    return receipt;
  });

  try {
    const pending = enforcementRequest(f.path, query);
    await admitted.promise;
    const closing = f.transport.close();
    held.resolve();
    expect(await pending).toEqual(receipt);
    await closing;
  } finally {
    held.resolve();
    await f.close();
  }
});

it("returns a capacity error without disconnecting pending control requests", async () => {
  let count = 0;

  const entered = deferred(),
    held = deferred();

  const f = await fixture(async (command) => {
    if (command.operation === "configuration") {
      entered.resolve();
      await held.promise;

      return {
        dnsPort: 5353,
        machinePort: 9443,
        controllerPort: 9445,
        controllerAddresses: ["192.0.2.20"],
        upstreamDns: { address: "192.0.2.53", port: 53 },
      };
    }

    return {
      bootId: receipt.bootId,
      revision: receipt.revision,
      policyHash: receipt.policyHash,
      instances: [],
      gatewayAddresses: [],
      observedAt: new Date().toISOString(),
      xml: ++count === 1 ? "x".repeat(MAX_MACHINE_FRAME_BYTES) : "bounded",
    };
  });

  try {
    const pending = enforcementRequest(f.path, { operation: "configuration" });
    await entered.promise;
    await expect(
      enforcementRequest(f.path, { operation: "connections" }),
    ).rejects.toMatchObject({ code: "connection_snapshot_capacity" });
    held.resolve();
    await expect(pending).resolves.toEqual({
      dnsPort: 5353,
      machinePort: 9443,
      controllerPort: 9445,
      controllerAddresses: ["192.0.2.20"],
      upstreamDns: { address: "192.0.2.53", port: 53 },
    });
    expect(
      (await enforcementRequest(f.path, { operation: "connections" })).xml,
    ).toBe("bounded");
    expect(f.connections()).toBe(1);
  } finally {
    held.resolve();
    await f.close();
  }
});

it.each([0, 1])(
  "checks the complete encoded snapshot boundary with %s excess bytes",
  async (extra) => {
    const snapshot = {
      bootId: receipt.bootId,
      revision: receipt.revision,
      policyHash: receipt.policyHash,
      instances: Array.from({ length: 350 }, (_, index) => ({
        id: randomUUID(),
        name: "Client ".padEnd(128, "x"),
        addresses: [`10.23.${Math.floor(index / 256)}.${index % 256}`],
        ownershipId: randomUUID(),
      })),
      gatewayAddresses: [],
      observedAt: new Date().toISOString(),
      xml: "",
    };

    const overhead = Buffer.byteLength(
      JSON.stringify({
        id: randomUUID(),
        ok: true,
        value: snapshot,
      }) + "\n",
    );

    expect(overhead).toBeGreaterThan(65536);
    snapshot.xml = "x".repeat(MAX_MACHINE_FRAME_BYTES - overhead + extra);
    const f = await fixture(async () => snapshot);

    try {
      const request = enforcementRequest(f.path, { operation: "connections" });

      if (extra === 0) expect((await request).xml).toBe(snapshot.xml);
      else
        await expect(request).rejects.toMatchObject({
          code: "connection_snapshot_capacity",
        });
      expect(f.connections()).toBe(1);
    } finally {
      await f.close();
    }
  },
);

it("bounds an oversized input before dispatch and releases its frame reservation", async () => {
  let count = 0;

  const f = await fixture(async () => {
    count++;

    return receipt;
  });

  const socket = createConnection(f.path);
  socket.on("error", () => {});
  socket.resume();

  const closed = new Promise<void>((resolve) =>
    socket.once("close", () => resolve()),
  );

  try {
    socket.end(Buffer.alloc(2 * 1024 * 1024 + 1, 32));
    await closed;
    expect(count).toBe(0);
    expect(await enforcementRequest(f.path, query)).toEqual(receipt);
    expect(count).toBe(1);
  } finally {
    socket.destroy();
    await f.close();
  }
});

it("rejects an unterminated command without invoking dispatch", async () => {
  let dispatched = 0;

  const f = await fixture(async () => {
    dispatched++;

    return receipt;
  });

  const socket = createConnection(f.path);
  socket.on("error", () => {});
  socket.resume();

  const closed = new Promise<void>((resolve) =>
    socket.once("close", () => resolve()),
  );

  try {
    socket.end(JSON.stringify({ ...query, id: randomUUID() }));
    await closed;
    expect(dispatched).toBe(0);
  } finally {
    socket.destroy();
    await f.close();
  }
});
