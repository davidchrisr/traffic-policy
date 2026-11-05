import { expect, it } from "vitest";
import { createSocket, type RemoteInfo, type Socket } from "node:dgram";
import dnsPacket from "dns-packet";
import { UpstreamUdp } from "./dns-upstream.ts";

const query = (id: number, name = "proof.example") =>
  dnsPacket.decode(
    dnsPacket.encode({
      type: "query",
      id,
      flags: 0x100,
      questions: [{ name, type: "A", class: "IN" }],
    }),
  );

const answer = (bytes: Buffer, address = "10.22.242.20") => {
  const q = dnsPacket.decode(bytes);

  return dnsPacket.encode({
    type: "response",
    id: q.id,
    flags: 0x180,
    questions: q.questions,
    answers: [
      {
        name: q.questions![0]!.name,
        type: "A",
        class: "IN",
        ttl: 60,
        data: address,
      },
    ],
  });
};

async function fixture(
  handle: (socket: Socket, bytes: Buffer, peer: RemoteInfo) => void,
  capacity = 1,
  now?: () => number,
  family: "udp4" | "udp6" = "udp4",
) {
  const server = createSocket(family),
    host = family === "udp4" ? "127.0.0.1" : "::1";

  server.on("message", (bytes, peer) => handle(server, bytes, peer));
  await new Promise<void>((resolve) => server.bind(0, host, resolve));

  const client = new UpstreamUdp(
    { address: host, port: server.address().port },
    capacity,
    now,
  );

  return {
    client,
    server,
    close: async () => {
      await client.close();
      await new Promise<void>((resolve) => server.close(resolve));
    },
  };
}

it("settles startup and shutdown when a warming connected pool is closed", async () => {
  const f = await fixture(
    (socket, bytes, peer) =>
      socket.send(answer(bytes), peer.port, peer.address),
    16,
  );

  try {
    const warming = f.client.warm();
    const closing = f.client.close();
    await expect(warming).rejects.toThrow("closed");
    await closing;
  } finally {
    await f.close();
  }
});

it("reuses a source port without reusing transaction IDs and restores client IDs", async () => {
  const requests: { port: number; id: number }[] = [];

  const f = await fixture((socket, bytes, peer) => {
    requests.push({ port: peer.port, id: bytes.readUInt16BE(0) });
    socket.send(answer(bytes), peer.port, peer.address);
  });

  try {
    for (let i = 0; i < 20; i++) {
      const reply = await f.client.exchange(query(i));
      expect(dnsPacket.decode(reply).id).toBe(i);
    }

    expect(new Set(requests.map((r) => r.port)).size).toBe(1);
    expect(new Set(requests.map((r) => r.id)).size).toBe(20);
  } finally {
    await f.close();
  }
});

it("ignores a delayed prior reply, wrong question and wrong sender while a reused port is active", async () => {
  let first: Buffer | null = null;
  const foreign = createSocket("udp4");
  await new Promise<void>((resolve) => foreign.bind(0, "127.0.0.1", resolve));

  const f = await fixture((socket, bytes, peer) => {
    if (!first) {
      first = bytes;
      socket.send(answer(bytes), peer.port, peer.address);

      return;
    }

    const packet = dnsPacket.decode(bytes);
    socket.send(answer(first), peer.port, peer.address);
    socket.send(
      dnsPacket.encode({
        type: "response",
        id: packet.id,
        flags: 0x180,
        questions: [{ name: "wrong.example", type: "A", class: "IN" }],
      }),
      peer.port,
      peer.address,
    );
    foreign.send(answer(bytes, "10.22.242.99"), peer.port, peer.address);
    socket.send(Buffer.from([0]), peer.port, peer.address);
    setTimeout(
      () => socket.send(answer(bytes, "10.22.242.21"), peer.port, peer.address),
      20,
    );
  });

  try {
    await f.client.exchange(query(1));
    const reply = dnsPacket.decode(await f.client.exchange(query(2)));
    expect(reply.id).toBe(2);
    expect(reply.answers?.[0]).toMatchObject({ data: "10.22.242.21" });
  } finally {
    await f.close();
    foreign.close();
  }
});

it("admits concurrent queries beyond the idle retention size and demultiplexes identical names", async () => {
  const waiting: { bytes: Buffer; peer: RemoteInfo }[] = [];

  const f = await fixture((socket, bytes, peer) => {
    waiting.push({ bytes, peer });

    if (waiting.length === 4)
      for (const [i, r] of waiting.toReversed().entries())
        socket.send(
          answer(r.bytes, `10.22.242.${20 + i}`),
          r.peer.port,
          r.peer.address,
        );
  });

  try {
    const replies = await Promise.all(
      [1, 2, 3, 4].map((id) => f.client.exchange(query(id))),
    );

    expect(replies.map((reply) => dnsPacket.decode(reply).id)).toEqual([
      1, 2, 3, 4,
    ]);
    expect(new Set(waiting.map((r) => r.peer.port)).size).toBe(4);
  } finally {
    await f.close();
  }
});

it("times out once without replaying the query and accepts a later independent lookup", async () => {
  let calls = 0;

  const f = await fixture((socket, bytes, peer) => {
    if (++calls > 1) socket.send(answer(bytes), peer.port, peer.address);
  });

  try {
    await expect(f.client.exchange(query(1))).rejects.toMatchObject({
      code: "upstream_dns_timeout",
    });
    expect(calls).toBe(1);
    expect(dnsPacket.decode(await f.client.exchange(query(2))).id).toBe(2);
    expect(calls).toBe(2);
  } finally {
    await f.close();
  }
});

it("retires old ports and closes safely during an active lookup", async () => {
  let now = 0;
  const ports: number[] = [];

  const f = await fixture(
    (socket, bytes, peer) => {
      ports.push(peer.port);
      socket.send(answer(bytes), peer.port, peer.address);
    },
    1,
    () => now,
  );

  try {
    await f.client.exchange(query(1));
    now = 30001;
    await f.client.exchange(query(2));
    expect(ports).toHaveLength(2);
    const pending = f.client.exchange(query(3));
    const outcome = pending.catch((error) => error);
    await f.client.close();
    expect(await outcome).toBeInstanceOf(Error);
    await expect(f.client.exchange(query(4))).rejects.toThrow("closed");
  } finally {
    await f.close();
  }
});

it("prepares idle ports before serving without issuing DNS requests", async () => {
  const ports = new Set<number>();

  const f = await fixture((socket, bytes, peer) => {
    ports.add(peer.port);
    socket.send(answer(bytes), peer.port, peer.address);
  }, 4);

  try {
    await f.client.warm();
    expect(ports.size).toBe(0);

    const replies = await Promise.all(
      [1, 2, 3, 4].map((id) => f.client.exchange(query(id))),
    );

    expect(replies.map((reply) => dnsPacket.decode(reply).id)).toEqual([
      1, 2, 3, 4,
    ]);
    expect(ports.size).toBe(4);
  } finally {
    await f.close();
  }
});

it("supports IPv6 upstream sockets", async () => {
  const f = await fixture(
    (socket, bytes, peer) =>
      socket.send(answer(bytes), peer.port, peer.address),
    1,
    undefined,
    "udp6",
  );

  try {
    expect(dnsPacket.decode(await f.client.exchange(query(7))).id).toBe(7);
  } finally {
    await f.close();
  }
});

it("settles a lookup and closes its socket when shutdown races initial binding", async () => {
  const f = await fixture((socket, bytes, peer) =>
    socket.send(answer(bytes), peer.port, peer.address),
  );

  try {
    const pending = f.client.exchange(query(1)).catch((error) => error);
    await f.client.close();
    expect(await pending).toBeInstanceOf(Error);
  } finally {
    await f.close();
  }
});
