import { createSocket, type Socket, type RemoteInfo } from "node:dgram";
import { randomFillSync } from "node:crypto";
import dnsPacket from "dns-packet";
import { canonicalIp } from "@traffic-policy/contracts";
import { hasErrorCode, ServiceError } from "@traffic-policy/core/io";
import type { GatewayConfig } from "./config.ts";

type Packet = ReturnType<typeof dnsPacket.decode>;

type Pending = {
  id: number;
  query: Packet;
  accept: (bytes: Buffer) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
};

type Channel = {
  socket: Socket;
  expiresAt: number;
  used: Uint8Array;
  uses: number;
  idleIndex: number;
  pending: Pending | null;
  bound: boolean;
  binding: boolean;
  closingStarted: boolean;
  retired: boolean;
  closed: Promise<void>;
  finishClose: () => void;
};

const TIMEOUT_MS = 2000;

const MAX_AGE_MS = 30000;

const MAX_USES = 2048;

const randomWords = new Uint32Array(1024);

let randomIndex = randomWords.length;

// Returns a uniform integer in [0, bound) from a pooled crypto fill, so a lookup does not pay
// crypto.randomInt's per-call cost. Rejection sampling keeps the result unbiased.
function randomBelow(bound: number): number {
  if (!Number.isInteger(bound) || bound < 1 || bound > 2 ** 32)
    throw new RangeError(`Random bound ${bound} is outside 1 to 2^32`);
  const limit = 2 ** 32 - (2 ** 32 % bound);

  for (;;) {
    if (randomIndex === randomWords.length) {
      randomFillSync(randomWords);
      randomIndex = 0;
    }

    const word = randomWords[randomIndex++]!;

    if (word < limit) return word % bound;
  }
}

/** One query per socket keeps receive-buffer demand bounded. Idle ports rotate. */
export class UpstreamUdp {
  private readonly channels = new Set<Channel>();
  private readonly idle: Channel[] = [];
  private readonly closing = new Set<Promise<void>>();
  private stopped = false;
  private warming: Promise<void> | null = null;
  private readonly timer: ReturnType<typeof setInterval>;

  constructor(
    private readonly upstream: GatewayConfig["upstreamDns"],
    private readonly capacity: number,
    private readonly now: () => number = () => performance.now(),
  ) {
    this.timer = setInterval(() => {
      for (const channel of [...this.idle])
        if (this.expired(channel)) this.retire(channel);
    }, 1000);
    this.timer.unref();
  }

  private expired(channel: Channel) {
    return this.now() >= channel.expiresAt || channel.uses >= MAX_USES;
  }

  private removeIdle(channel: Channel) {
    const index = channel.idleIndex;

    if (index < 0) return;
    const last = this.idle.pop()!;

    if (last !== channel) {
      this.idle[index] = last;
      last.idleIndex = index;
    }

    channel.idleIndex = -1;
  }

  private closeSocket(channel: Channel) {
    if (channel.binding || channel.closingStarted) return;
    channel.closingStarted = true;

    try {
      channel.socket.close();
    } catch (error) {
      if (!hasErrorCode(error, "ERR_SOCKET_DGRAM_NOT_RUNNING")) throw error;
      channel.finishClose();
    }
  }

  private retire(channel: Channel) {
    if (channel.retired) return;
    channel.retired = true;
    this.channels.delete(channel);
    this.removeIdle(channel);
    this.closing.add(channel.closed);
    void channel.closed.then(() => this.closing.delete(channel.closed));
    this.closeSocket(channel);
  }

  private create(): Channel {
    const socket = createSocket(
      this.upstream.address.includes(":") ? "udp6" : "udp4",
    );

    let finishClose!: () => void;

    const closed = new Promise<void>((resolve) => {
      finishClose = resolve;
    });

    const channel: Channel = {
      socket,
      expiresAt: this.now() + MAX_AGE_MS - randomBelow(MAX_AGE_MS / 2),
      used: new Uint8Array(8192),
      uses: 0,
      idleIndex: -1,
      pending: null,
      bound: false,
      binding: false,
      closingStarted: false,
      retired: false,
      closed,
      finishClose,
    };

    this.channels.add(channel);
    socket.once("close", finishClose);
    socket.once("listening", () => {
      if (channel.retired) {
        channel.binding = false;
        this.closeSocket(channel);

        return;
      }

      try {
        socket.connect(this.upstream.port, this.upstream.address);
      } catch (error) {
        socket.emit(
          "error",
          error instanceof Error ? error : new Error(String(error)),
        );
      }
    });
    socket.once("connect", () => {
      channel.bound = true;
      channel.binding = false;

      if (channel.retired) {
        this.closeSocket(channel);

        return;
      }

      const pending = channel.pending;

      if (pending) this.send(channel, pending);
      else {
        socket.unref();
        channel.idleIndex = this.idle.length;
        this.idle.push(channel);
      }
    });
    socket.on("error", (error) => {
      channel.binding = false;
      const pending = channel.pending;

      if (pending) this.complete(channel, pending, error);

      if (channel.retired) this.closeSocket(channel);
      else this.retire(channel);
    });
    socket.on("message", (bytes, peer) => this.receive(channel, bytes, peer));

    return channel;
  }

  private send(channel: Channel, pending: Pending) {
    try {
      channel.socket.send(
        dnsPacket.encode({ ...pending.query, id: pending.id }),
        (error) => {
          if (error && channel.pending === pending) {
            this.complete(channel, pending, error);
            this.retire(channel);
          }
        },
      );
    } catch (error) {
      this.complete(
        channel,
        pending,
        error instanceof Error ? error : new Error(String(error)),
      );
    }
  }

  private receive(channel: Channel, bytes: Buffer, peer: RemoteInfo) {
    const pending = channel.pending;

    if (!pending || peer.port !== this.upstream.port) return;
    let reply: Packet;

    try {
      if (
        peer.address !== this.upstream.address &&
        canonicalIp(peer.address) !== this.upstream.address
      )
        return;
      reply = dnsPacket.decode(bytes);
    } catch {
      return;
    }

    const expected = pending.query.questions?.[0],
      question = reply.questions?.[0];

    if (
      reply.type !== "response" ||
      reply.id !== pending.id ||
      reply.questions?.length !== 1 ||
      !expected ||
      !question ||
      question.name.toLowerCase().replace(/\.$/, "") !==
        expected.name.toLowerCase().replace(/\.$/, "") ||
      question.type !== expected.type ||
      (question.class ?? "IN") !== (expected.class ?? "IN")
    )
      return;
    const encoded = Buffer.from(bytes);
    encoded.writeUInt16BE(pending.query.id ?? 0, 0);
    this.complete(channel, pending, null, encoded);
  }

  private complete(
    channel: Channel,
    pending: Pending,
    error: Error | null,
    bytes?: Buffer,
  ) {
    if (channel.pending !== pending) return;
    channel.pending = null;
    clearTimeout(pending.timer);

    if (error) pending.reject(error);
    else pending.accept(bytes!);

    if (
      this.stopped ||
      this.expired(channel) ||
      error ||
      this.channels.size > this.capacity
    )
      this.retire(channel);
    else {
      channel.socket.unref();
      channel.idleIndex = this.idle.length;
      this.idle.push(channel);
    }
  }

  exchange(query: Packet): Promise<Buffer> {
    if (this.stopped)
      return Promise.reject(new Error("Upstream DNS transport is closed"));
    let channel: Channel | null = null;

    while (this.channels.size >= this.capacity && this.idle.length) {
      const index = randomBelow(this.idle.length);
      const selected = this.idle[index]!;
      this.removeIdle(selected);

      if (this.expired(selected)) this.retire(selected);
      else {
        channel = selected;
        break;
      }
    }

    channel ??= this.create();
    const owned = channel;
    channel.socket.ref();
    let id = randomBelow(65536);

    while (channel.used[id >>> 3]! & (1 << (id & 7))) id = randomBelow(65536);
    channel.used[id >>> 3]! |= 1 << (id & 7);
    channel.uses++;

    return new Promise<Buffer>((accept, reject) => {
      const pending: Pending = {
        id,
        query,
        accept,
        reject,
        timer: setTimeout(() => {
          this.complete(
            owned,
            pending,
            new ServiceError(
              504,
              "upstream_dns_timeout",
              "Upstream DNS timed out",
            ),
          );
        }, TIMEOUT_MS),
      };

      owned.pending = pending;

      try {
        if (owned.bound) this.send(owned, pending);
        else {
          owned.binding = true;
          owned.socket.bind(0);
        }
      } catch (error) {
        owned.binding = false;
        this.complete(
          owned,
          pending,
          error instanceof Error ? error : new Error(String(error)),
        );
      }
    });
  }

  warm(): Promise<void> {
    if (this.stopped)
      return Promise.reject(new Error("Upstream DNS transport is closed"));

    if (this.warming) return this.warming;
    const tasks: Promise<void>[] = [];

    while (this.channels.size < this.capacity) {
      const channel = this.create();
      tasks.push(
        new Promise<void>((resolve, reject) => {
          const ready = () => {
            channel.socket.off("error", failed);
            channel.socket.off("close", closed);
            resolve();
          };

          const failed = (error: Error) => {
            channel.socket.off("connect", ready);
            channel.socket.off("close", closed);
            reject(error);
          };

          const closed = () =>
            failed(new Error("Upstream DNS transport closed before readiness"));

          channel.socket.once("connect", ready);
          channel.socket.once("error", failed);
          channel.socket.once("close", closed);
          channel.binding = true;

          try {
            channel.socket.bind(0);
          } catch (error) {
            channel.binding = false;
            this.retire(channel);
            failed(error instanceof Error ? error : new Error(String(error)));
          }
        }),
      );
    }

    this.warming = Promise.all(tasks)
      .then(() => {})
      .finally(() => {
        this.warming = null;
      });

    return this.warming;
  }

  async close() {
    this.stopped = true;
    clearInterval(this.timer);

    for (const channel of [...this.channels]) {
      const pending = channel.pending;

      if (pending)
        this.complete(
          channel,
          pending,
          new Error("Upstream DNS transport closed"),
        );
      this.retire(channel);
    }

    await Promise.all([...this.closing]);
  }
}
