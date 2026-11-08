import { afterAll, beforeAll, expect, it } from "vitest";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { request } from "node:http";
import { TLSSocket } from "node:tls";
import { createConnection, createServer as createTcpServer } from "node:net";
import type { Socket } from "node:net";
import type { RequestListener } from "node:http";
import {
  createMachineServer,
  createMachineConnection,
  MACHINE_TIMEOUTS,
} from "./machine-server.server.ts";

let directory = "";

let ca: Buffer;

let cert: Buffer;

let key: Buffer;

let clientCert: Buffer;

let clientKey: Buffer;

let rogueCert: Buffer;

let rogueKey: Buffer;

beforeAll(async () => {
  directory = await mkdtemp(
    join(process.cwd(), ".local/tmp/tests/machine-tls-"),
  );

  const openssl = (...args: string[]) => {
    const result = spawnSync("openssl", args, {
      cwd: directory,
      encoding: "utf8",
    });

    if (result.status !== 0) throw new Error(result.stderr);
  };

  openssl("genpkey", "-algorithm", "ED25519", "-out", "ca.key");
  openssl(
    "req",
    "-new",
    "-x509",
    "-key",
    "ca.key",
    "-days",
    "1",
    "-subj",
    "/CN=Fixture CA",
    "-addext",
    "basicConstraints=critical,CA:TRUE",
    "-addext",
    "keyUsage=critical,keyCertSign,cRLSign",
    "-out",
    "ca.crt",
  );

  for (const name of ["server", "client"]) {
    openssl("genpkey", "-algorithm", "ED25519", "-out", `${name}.key`);
    openssl(
      "req",
      "-new",
      "-key",
      `${name}.key`,
      "-subj",
      `/CN=fixture-${name}`,
      "-out",
      `${name}.csr`,
    );
    await writeFile(
      join(directory, `${name}.ext`),
      "subjectAltName=IP:127.0.0.1\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\n",
    );
    openssl(
      "x509",
      "-req",
      "-in",
      `${name}.csr`,
      "-CA",
      "ca.crt",
      "-CAkey",
      "ca.key",
      "-CAcreateserial",
      "-days",
      "1",
      "-extfile",
      `${name}.ext`,
      "-out",
      `${name}.crt`,
    );
  }

  ca = await readFile(join(directory, "ca.crt"));
  cert = await readFile(join(directory, "server.crt"));
  key = await readFile(join(directory, "server.key"));
  clientCert = await readFile(join(directory, "client.crt"));
  clientKey = await readFile(join(directory, "client.key"));
  openssl("genpkey", "-algorithm", "ED25519", "-out", "rogue.key");
  openssl(
    "req",
    "-new",
    "-x509",
    "-key",
    "rogue.key",
    "-days",
    "1",
    "-subj",
    "/CN=fixture-client",
    "-addext",
    "keyUsage=critical,digitalSignature",
    "-addext",
    "extendedKeyUsage=clientAuth",
    "-out",
    "rogue.crt",
  );
  rogueCert = await readFile(join(directory, "rogue.crt"));
  rogueKey = await readFile(join(directory, "rogue.key"));
});

afterAll(async () => {
  if (directory) await rm(directory, { recursive: true });
});

it("preserves verified peer identity and TLS 1.3 across the real HTTPS transport", async () => {
  let handled = 0;

  const machine = createMachineServer(
    { ca, cert, key },
    (incoming, response) => {
      handled++;

      if (!(incoming.socket instanceof TLSSocket))
        throw new Error("Peer TLS context was lost");
      const identity = incoming.socket.getPeerCertificate().subject?.CN;
      response.writeHead(identity === "fixture-client" ? 200 : 403);
      response.end(
        JSON.stringify({
          identity,
          protocol: incoming.socket.getProtocol(),
          authorized: incoming.socket.authorized,
        }),
      );
    },
  );

  const server = machine.server;

  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();

    if (!address || !(address instanceof Object))
      throw new Error("Missing listener address");

    const exchange = (options: {
      ca?: Buffer;
      cert?: Buffer;
      key?: Buffer;
      maxVersion?: "TLSv1.2";
    }) =>
      new Promise<{ status: number; body: string }>((resolve, reject) => {
        const outgoing = request(
          {
            host: "127.0.0.1",
            port: address.port,
            createConnection: () =>
              createMachineConnection(
                new URL(`https://127.0.0.1:${address.port}`),
                { ca, ...options },
              ),
            headers: { Connection: "close", "X-Client-CN": "fixture-client" },
          },
          (response) => {
            let body = "";
            response.on("data", (chunk) => {
              body += chunk;
            });
            response.on("end", () =>
              resolve({ status: response.statusCode ?? 0, body }),
            );
          },
        );

        outgoing.on("error", reject);
        outgoing.end();
      });

    const valid = await exchange({ cert: clientCert, key: clientKey });
    expect(valid.status).toBe(200);
    expect(JSON.parse(valid.body)).toEqual({
      identity: "fixture-client",
      protocol: "TLSv1.3",
      authorized: true,
    });
    expect((await exchange({ cert, key })).status).toBe(403);
    await expect(exchange({})).rejects.toThrow();
    await expect(
      exchange({ cert: rogueCert, key: rogueKey }),
    ).rejects.toThrow();
    await expect(
      exchange({ ca: rogueCert, cert: clientCert, key: clientKey }),
    ).rejects.toThrow();
    await expect(
      exchange({ cert: clientCert, key: clientKey, maxVersion: "TLSv1.2" }),
    ).rejects.toThrow();
    expect(handled).toBe(2);
  } finally {
    await machine.close();
  }
});

async function fixture(handler: RequestListener) {
  const machine = createMachineServer({ ca, cert, key }, handler);
  const server = machine.server;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();

  if (!address || !(address instanceof Object))
    throw new Error("Missing fixture address");

  return { ...machine, url: new URL(`https://127.0.0.1:${address.port}`) };
}

async function client(url: URL) {
  const socket = createMachineConnection(url, {
    ca,
    cert: clientCert,
    key: clientKey,
  });

  await new Promise<void>((resolve, reject) => {
    socket.once("secureConnect", resolve);
    socket.once("error", reject);
  });

  return socket;
}

const reply: RequestListener = (incoming, response) => {
  incoming.once("end", () => {
    response.writeHead(200, { "Content-Length": 2 });
    response.end("OK");
  });
  incoming.resume();
};

it.concurrent.each([
  "handshake",
  "headers",
  "body",
  "trickled headers",
  "trickled body",
  "idle",
])(
  "enforces the total %s deadline over a real socket",
  async (phase) => {
    const machine = await fixture(reply);

    const socket =
      phase === "handshake"
        ? createConnection({
            host: machine.url.hostname,
            port: Number(machine.url.port),
          })
        : await client(machine.url);

    const closed = new Promise<void>((resolve) =>
      socket.once("close", resolve),
    );

    socket.on("error", () => {});
    const started = performance.now();
    let trickle: NodeJS.Timeout | null = null;

    try {
      if (phase.includes("headers"))
        socket.write("GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: ");

      if (phase.includes("body"))
        socket.write(
          "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10000\r\n\r\nx",
        );

      if (phase.startsWith("trickled"))
        trickle = setInterval(() => socket.write("x"), 100);

      if (phase === "idle") {
        const responded = new Promise<void>((resolve) =>
          socket.once("data", () => resolve()),
        );

        socket.write(
          "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
        );
        await responded;
      }

      await closed;

      const expected = phase.includes("body")
        ? MACHINE_TIMEOUTS.body
        : MACHINE_TIMEOUTS.headers;

      expect(performance.now() - started).toBeGreaterThanOrEqual(
        expected - 100,
      );
      expect(performance.now() - started).toBeLessThan(expected + 2000);
    } finally {
      if (trickle) clearInterval(trickle);
      socket.destroy();
      await machine.close();
    }
  },
  20000,
);

it("reuses the authenticated connection and closes idle sockets immediately on shutdown", async () => {
  let handshakes = 0;
  const machine = await fixture(reply);
  machine.server.on("secureConnection", () => {
    handshakes++;
  });
  const socket = await client(machine.url);
  let received = "";
  socket.on("data", (data) => {
    received += data.toString();
  });

  try {
    for (let index = 0; index < 3; index++) {
      const response = new Promise<void>((resolve) =>
        socket.once("data", () => resolve()),
      );

      socket.write(
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
      );
      await response;
    }

    expect(handshakes).toBe(1);
    expect(received.match(/HTTP\/1\.1 200/g)).toHaveLength(3);

    const closed = new Promise<void>((resolve) =>
      socket.once("close", resolve),
    );

    const started = performance.now();
    const closing = machine.close();
    expect(machine.close()).toBe(closing);
    await Promise.all([closing, closed]);
    expect(performance.now() - started).toBeLessThan(1000);
  } finally {
    socket.destroy();
    await machine.close();
  }
});

it.concurrent.each([false, true])(
  "drains active requests with a bounded deadline, stalled=%s",
  async (stalled) => {
    let begin: (() => void) | undefined;

    const began = new Promise<void>((resolve) => {
      begin = resolve;
    });

    const machine = await fixture((incoming, response) => {
      begin?.();
      incoming.resume();

      if (!stalled) setTimeout(() => response.end("finished"), 250);
    });

    const socket = await client(machine.url);
    let received = "";
    socket.on("data", (data) => {
      received += data.toString();
    });
    socket.on("error", () => {});

    const closed = new Promise<void>((resolve) =>
      socket.once("close", resolve),
    );

    try {
      socket.write("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
      await began;
      const started = performance.now();
      await Promise.all([machine.close(), closed]);

      if (stalled) {
        expect(performance.now() - started).toBeGreaterThanOrEqual(
          MACHINE_TIMEOUTS.drain - 100,
        );
        expect(performance.now() - started).toBeLessThan(
          MACHINE_TIMEOUTS.drain + 2000,
        );
      } else {
        expect(received).toContain("finished");
        expect(performance.now() - started).toBeLessThan(1000);
      }
    } finally {
      socket.destroy();
      await machine.close();
    }
  },
  15000,
);

it("finishes the accepted request while rejecting new pipelined requests during drain", async () => {
  let begin: (() => void) | undefined;

  const began = new Promise<void>((resolve) => {
    begin = resolve;
  });

  let handled = 0;

  const machine = await fixture((incoming, response) => {
    handled++;
    begin?.();
    incoming.resume();
    setTimeout(() => response.end("accepted"), 250);
  });

  const socket = await client(machine.url);
  let received = "";
  socket.on("data", (data) => {
    received += data.toString();
  });

  const closed = new Promise<void>((resolve) => socket.once("close", resolve));

  try {
    socket.write("GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n");
    await began;

    const closing = machine.close();
    socket.write("GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n");
    await Promise.all([closing, closed]);
    expect(handled).toBe(1);
    expect(received).toContain("accepted");
    expect(received.match(/HTTP\/1\.1 200/g)).toHaveLength(1);
  } finally {
    socket.destroy();
    await machine.close();
  }
});

it("lets an accepted request finish uploading its body during drain", async () => {
  let begin: (() => void) | undefined;

  const began = new Promise<void>((resolve) => {
    begin = resolve;
  });

  const machine = await fixture((incoming, response) => {
    begin?.();
    incoming.once("end", () => response.end("uploaded"));
    incoming.resume();
  });

  const socket = await client(machine.url);
  let received = "";
  socket.on("data", (data) => {
    received += data.toString();
  });
  const closed = new Promise<void>((resolve) => socket.once("close", resolve));

  try {
    socket.write(
      "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8\r\n\r\npart",
    );
    await began;
    const closing = machine.close();
    socket.write("done");
    await Promise.all([closing, closed]);
    expect(received).toContain("uploaded");
  } finally {
    socket.destroy();
    await machine.close();
  }
});

it("times out an outgoing TLS handshake when the peer never responds", async () => {
  const peers = new Set<Socket>();

  const server = createTcpServer((socket) => {
    peers.add(socket);
    socket.once("close", () => peers.delete(socket));
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();

  if (!address || !(address instanceof Object))
    throw new Error("Missing fixture address");

  try {
    const started = performance.now();
    await expect(
      client(new URL(`https://127.0.0.1:${address.port}`)),
    ).rejects.toThrow("Machine TLS handshake timed out");
    expect(performance.now() - started).toBeGreaterThanOrEqual(
      MACHINE_TIMEOUTS.handshake - 100,
    );
    expect(performance.now() - started).toBeLessThan(
      MACHINE_TIMEOUTS.handshake + 2000,
    );
  } finally {
    for (const peer of peers) peer.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}, 15000);
