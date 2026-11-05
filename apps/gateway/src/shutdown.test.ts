import { expect, it } from "vitest";
import { createServer, request } from "node:http";
import type { Socket } from "node:net";
import { z } from "zod";
import { finishShutdown, PendingWork } from "./shutdown.ts";

it("awaits every producer even when a peer close fails, then continues all cleanup phases", async () => {
  let release = () => {};

  const held = new Promise<void>((resolve) => {
    release = resolve;
  });

  const calls: string[] = [];
  const error = new Error("Listener close failed");

  const result = finishShutdown([
    [
      () => {
        calls.push("listener");
        throw error;
      },
      async () => {
        calls.push("producer");
        await held;
        calls.push("producer-finished");
      },
    ],
    [
      () => {
        calls.push("suricata");
        throw new Error("Suricata close failed");
      },
    ],
    [
      () => {
        calls.push("buffer");
      },
    ],
  ]).catch((cause: unknown) => cause);

  await new Promise((resolve) => setImmediate(resolve));
  expect(calls).toEqual(["listener", "producer"]);
  release();
  const failure = await result;
  expect(calls).toEqual([
    "listener",
    "producer",
    "producer-finished",
    "suricata",
    "buffer",
  ]);
  expect(failure).toBeInstanceOf(AggregateError);

  if (!(failure instanceof AggregateError))
    throw new Error("Missing cleanup failure");
  expect(failure.errors).toHaveLength(2);
  expect(failure.errors[0]).toBe(error);
});

it("waits for successful cleanup phases in order", async () => {
  const calls: string[] = [];
  await finishShutdown([
    [
      () => {
        calls.push("producers");
      },
    ],
    [
      () => {
        calls.push("buffer");
      },
    ],
  ]);
  expect(calls).toEqual(["producers", "buffer"]);
});

it("waits for admitted application work after a real client disconnect and transport closure", async () => {
  const work = new PendingWork();
  let release = () => {};

  let admit = () => {};

  let disconnected = () => {};

  const mutation = new Promise<void>((resolve) => {
    release = resolve;
  });

  const started = new Promise<void>((resolve) => {
    admit = resolve;
  });

  const peerClosed = new Promise<void>((resolve) => {
    disconnected = resolve;
  });

  let applied = false;
  let bufferClosed = false;
  const sockets = new Set<Socket>();

  const server = createServer((_request, response) => {
    work.track(
      (async () => {
        admit();
        await mutation;
        applied = true;

        if (!response.destroyed) response.end();
      })(),
    );
  });

  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => {
      sockets.delete(socket);
      disconnected();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));

  const address = z
    .object({ port: z.number().int().min(1).max(65535) })
    .parse(server.address());

  const client = request({
    host: "127.0.0.1",
    port: address.port,
    path: "/policy",
    method: "PUT",
    agent: false,
  });

  client.on("error", () => {});

  try {
    client.end();
    await started;
    client.destroy();
    await peerClosed;
    let transportClosed = () => {};

    const transport = new Promise<void>((resolve) => {
      transportClosed = resolve;
    });

    const drain = finishShutdown([
      [
        () =>
          new Promise<void>((resolve, reject) =>
            server.close((error) => {
              transportClosed();

              if (error) reject(error);
              else resolve();
            }),
          ),
        () => work.drain(),
      ],
      [
        () => {
          expect(applied).toBe(true);
          bufferClosed = true;
        },
      ],
    ]);

    await transport;
    expect(applied).toBe(false);
    expect(bufferClosed).toBe(false);
    release();
    await drain;
    expect(bufferClosed).toBe(true);
  } finally {
    release();
    client.destroy();

    for (const socket of sockets) socket.destroy();

    if (server.listening)
      await new Promise<void>((resolve) => server.close(() => resolve()));
    await work.drain();
  }
});
