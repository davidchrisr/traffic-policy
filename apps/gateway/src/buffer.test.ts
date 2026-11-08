import { afterEach, describe, expect, it, vi } from "vitest";
import {
  mkdtemp,
  readFile,
  writeFile,
  rm,
  readdir,
  open,
  mkdir,
  chmod,
  stat,
  unlink,
} from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { EventBuffer } from "./buffer.ts";
import type { GatewayConfig } from "./config.ts";
import type { GatewayEvent } from "@traffic-policy/contracts";
import { eventSchema, resolutionSchema } from "@traffic-policy/contracts";
import { atomicJson, hashDocument } from "@traffic-policy/core/io";
import { dnsObservation } from "./telemetry.ts";

const roots: string[] = [];

const buffers: EventBuffer[] = [];

function deferred() {
  let resolve = () => {};

  const promise = new Promise<void>((accept) => {
    resolve = accept;
  });

  return { promise, resolve };
}

afterEach(async () => {
  for (const buffer of buffers.splice(0)) await buffer.close();

  for (const root of roots.splice(0)) await rm(root, { recursive: true });
});

const observation = (): GatewayEvent => ({
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
  details: { code: "fixture", message: "Retention test" },
});

const dnsEvent = (): GatewayEvent => ({
  ...observation(),
  type: "dns",
  source: "resolver-gate",
  question: "proof.example",
  details: { outcome: "confirmed", addresses: "10.22.242.20" },
});

it("waits behind queued delivery and prefetches a Suricata batch while the last batch is sending", async () => {
  const first = deferred();
  const second = deferred();
  const firstStarted = deferred();
  const secondStarted = deferred();
  const sent: string[] = [];

  const { buffer } = await fixture("1048576", async (batch) => {
    sent.push(batch.sequence);

    if (sent.length === 1) {
      firstStarted.resolve();
      await first.promise;
    }

    if (sent.length === 2) {
      secondStarted.resolve();
      await second.promise;
    }

    return batch;
  });

  await buffer.append([observation()]);
  await buffer.append([observation()]);
  const controller = new AbortController();

  const source = buffer.appendSource(
    [observation()],
    "eve:prefetch",
    controller.signal,
  );

  const delivery = buffer.deliver();

  try {
    await firstStarted.promise;
    expect(buffer.status().batches).toBe(2);
    first.resolve();
    await secondStarted.promise;
    await source;
    expect(buffer.status().batches).toBe(2);
    expect(buffer.status().lostBatches).toBe("0");
    second.resolve();
    await delivery;
    expect(sent).toEqual(["1", "2", "3"]);
    expect(buffer.status().batches).toBe(0);
    expect(buffer.status().persistenceError).toBeNull();
  } finally {
    controller.abort();
    first.resolve();
    second.resolve();
    await Promise.allSettled([source, delivery]);
  }
});

it.each(["abort", "close"])(
  "settles a waiting Suricata append on %s without a persistence error",
  async (mode) => {
    const { buffer } = await fixture();
    await buffer.append([observation()]);
    await buffer.append([observation()]);
    const controller = new AbortController();

    const waiting = buffer.appendSource(
      [observation()],
      "eve:waiting",
      controller.signal,
    );

    const rejected =
      mode === "abort"
        ? expect(waiting).rejects.toMatchObject({ name: "AbortError" })
        : expect(waiting).rejects.toThrow("persistence is stopped");

    // This operation is queued after the source's admission check.
    await buffer.append([observation()]);

    if (mode === "abort") {
      controller.abort();
      await rejected;
    } else {
      await buffer.close();
      await rejected;
    }

    expect(buffer.status().batches).toBe(3);
    expect(buffer.status().lostBatches).toBe("0");
    expect(buffer.status().persistenceError).toBeNull();
  },
);

it("preserves canonical batch and event hashes while deduplicating an owned DNS group", async () => {
  const { root, buffer } = await fixture();

  const first = {
    ...dnsEvent(),
    details: { message: "café 漢字 🚦", outcome: "confirmed" },
  };

  const duplicate = {
    ...first,
    details: { outcome: "confirmed", message: "café 漢字 🚦" },
  };

  const second = dnsEvent();
  await Promise.all([
    buffer.appendDns(first),
    buffer.appendDns(duplicate),
    buffer.appendDns(second),
  ]);
  const [segment] = await readdir(join(root, "segments"));

  const batch = JSON.parse(
    await readFile(join(root, "segments", segment!), "utf8"),
  );

  expect(batch.events).toEqual([first, second]);
  await buffer.close();
  const state = JSON.parse(await readFile(join(root, "buffer.json"), "utf8"));
  expect(state.lastCommitHash).toBe(hashDocument(batch.events));
  expect(state.dnsCommit).toEqual(
    [first, second].map((event) => ({
      id: event.id,
      hash: hashDocument(event),
    })),
  );
});

it("retains every address of a maximum-size valid DNS resolution", async () => {
  const { root, buffer } = await fixture();

  const addresses = Array.from(
    { length: 256 },
    (_, index) =>
      `1111:2222:3333:4444:5555:6666:7777:${(0x8000 + index).toString(16)}`,
  );

  const resolution = resolutionSchema.parse({
    clientIp: "10.22.241.10",
    question: "large.example",
    responseAt: new Date().toISOString(),
    answers: addresses.map((value) => ({
      owner: "large.example",
      type: "AAAA",
      value,
      ttl: 60,
    })),
  });

  const event = dnsObservation(resolution, null);

  await buffer.appendDns(event);
  const [segment] = await readdir(join(root, "segments"));

  const saved = JSON.parse(
    await readFile(join(root, "segments", segment!), "utf8"),
  );

  expect(saved.events).toEqual([event]);
  expect(saved.events[0].details.addresses).toBe(addresses.join(", "));
  expect(buffer.status()).toMatchObject({ batches: 1, rejectedRecords: "0" });
  expect(
    eventSchema.safeParse({
      ...event,
      details: { addresses: "x".repeat(65279) },
    }).success,
  ).toBe(false);
  expect(
    eventSchema.safeParse({ ...event, details: { message: "x".repeat(4097) } })
      .success,
  ).toBe(false);
  expect(eventSchema.safeParse({ ...event, type: "condition" }).success).toBe(
    false,
  );
  expect(eventSchema.safeParse({ ...event, source: "suricata" }).success).toBe(
    false,
  );
});

it("stores every lookup independently in one durable DNS batch", async () => {
  const persist = vi.fn(atomicJson);
  let release!: () => void;

  const held = new Promise<void>((resolve) => {
    release = resolve;
  });

  const { root, buffer } = await fixture(
    "1048576",
    async (batch) => {
      await held;

      return batch;
    },
    persist,
  );

  try {
    const events = Array.from({ length: 1024 }, dnsEvent);
    const before = persist.mock.calls.length;
    await Promise.all(events.map((event) => buffer.appendDns(event)));
    const segments = await readdir(join(root, "segments"));
    expect(segments).toHaveLength(1);

    const saved = JSON.parse(
      await readFile(join(root, "segments", segments[0]!), "utf8"),
    );

    expect(saved.events.map((event: GatewayEvent) => event.id)).toEqual(
      events.map((event) => event.id),
    );
    expect(
      persist.mock.calls
        .slice(before)
        .filter(([path]) => path.includes("/segments/")),
    ).toHaveLength(1);
    expect(
      persist.mock.calls
        .slice(before)
        .filter(([path]) => path.endsWith("buffer.json")),
    ).toHaveLength(0);
    expect(buffer.status()).toMatchObject({
      pendingDnsRecords: 0,
      rejectedRecords: "0",
      batches: 1,
    });
  } finally {
    release();
  }
});

it.each([false, true])(
  "recovers standalone DNS segments beyond a checkpoint with keyed intent=%s",
  async (keyed) => {
    let release!: () => void;

    const held = new Promise<void>((resolve) => {
      release = resolve;
    });

    const { root, config, buffer } = await fixture(
      "16777216",
      async (batch) => {
        await held;

        return batch;
      },
    );

    try {
      const source = observation();

      if (keyed) await buffer.append([source], "eve:before-dns");
      const checkpoint = await readFile(join(root, "buffer.json"));
      let events: GatewayEvent[] = [];

      for (let group = 0; group < 3; group++) {
        events = Array.from({ length: 32 }, dnsEvent);
        await Promise.all(events.map((event) => buffer.appendDns(event)));
      }

      expect(await readFile(join(root, "buffer.json"))).toEqual(checkpoint);

      const segments = await Promise.all(
        (await readdir(join(root, "segments"))).map(async (name) => ({
          name,
          bytes: await readFile(join(root, "segments", name)),
        })),
      );

      release();
      await buffer.close();
      // Restore the crash boundary with a stale checkpoint and durable newer segments.
      await writeFile(join(root, "buffer.json"), checkpoint);

      for (const { name, bytes } of segments)
        await writeFile(join(root, "segments", name), bytes);
      const restored = new EventBuffer(config);
      buffers.push(restored);
      await restored.start();
      await Promise.all(events.map((event) => restored.appendDns(event)));

      if (keyed) await restored.append([source], "eve:before-dns");
      expect(await readdir(join(root, "segments"))).toHaveLength(
        segments.length,
      );

      const state = JSON.parse(
        await readFile(join(root, "buffer.json"), "utf8"),
      );

      expect(state.sequence).toBe(String(segments.length));
      expect(state.dnsCommit.map((event: { id: string }) => event.id)).toEqual(
        events.map((event) => event.id),
      );
      expect(state.sourceCommit?.key ?? null).toBe(
        keyed ? "eve:before-dns" : null,
      );
      await restored.appendDns(dnsEvent());
      expect((await readdir(join(root, "segments"))).sort().at(-1)).toBe(
        String(segments.length + 1).padStart(20, "0") + ".json",
      );
      expect(restored.status()).toMatchObject({
        rejectedRecords: "0",
        lostBatches: "0",
        pendingDnsRecords: 0,
      });
    } finally {
      release();
    }
  },
);

it("fences a standalone segment directory before advancing recovered metadata", async () => {
  const { root, config, buffer } = await fixture();
  const before = await readFile(join(root, "buffer.json"));
  await buffer.appendDns(dnsEvent());
  const name = (await readdir(join(root, "segments")))[0]!;
  const bytes = await readFile(join(root, "segments", name));
  await buffer.close();
  await writeFile(join(root, "buffer.json"), before);
  await writeFile(join(root, "segments", name), bytes);

  const failed = new EventBuffer(config, undefined, atomicJson, async () => {
    throw Error("standalone directory sync failed");
  });

  buffers.push(failed);
  await expect(failed.start()).rejects.toThrow(
    "standalone directory sync failed",
  );
  expect(await readFile(join(root, "buffer.json"))).toEqual(before);
  const restored = new EventBuffer(config);
  buffers.push(restored);
  await restored.start();
  expect(
    JSON.parse(await readFile(join(root, "buffer.json"), "utf8")).sequence,
  ).toBe("1");
});

it("checkpoints newer DNS metadata before deleting an older acknowledged keyed intent", async () => {
  let fail = false;
  const sent: string[] = [];

  const { root, config, buffer } = await fixture(
    "1048576",
    async (batch) => {
      sent.push(batch.sequence);

      return batch;
    },
    async (path, value) => {
      if (fail && path.endsWith("buffer.json"))
        throw Error("metadata fence failed");
      await atomicJson(path, value);
    },
  );

  const source = observation(),
    event = dnsEvent();

  await buffer.append([source], "eve:older-intent");
  await buffer.appendDns(event);
  fail = true;
  await expect(buffer.deliver()).rejects.toThrow("metadata fence failed");
  expect((await readdir(join(root, "segments"))).sort()).toEqual([
    "00000000000000000001.json",
    "00000000000000000002.json",
  ]);
  fail = false;
  await buffer.deliver();
  expect(sent).toEqual(["1", "2"]);
  await buffer.close();
  const restored = new EventBuffer(config);
  buffers.push(restored);
  await restored.start();
  await restored.append([source], "eve:older-intent");
  await restored.appendDns(event);
  expect(await readdir(join(root, "segments"))).toHaveLength(0);
});

it("recovers a DNS segment after rename failure without a duplicate payload checkpoint", async () => {
  let fail = true;

  const { root, config, buffer } = await fixture(
    "1048576",
    undefined,
    async (path, value) => {
      await atomicJson(path, value);

      if (fail && path.includes("/segments/")) {
        fail = false;
        throw Error("DNS rename sync interrupted");
      }
    },
  );

  const before = await readFile(join(root, "buffer.json")),
    event = dnsEvent();

  await expect(buffer.appendDns(event)).rejects.toThrow(
    "DNS rename sync interrupted",
  );
  expect(await readFile(join(root, "buffer.json"))).toEqual(before);

  const name = (await readdir(join(root, "segments")))[0]!,
    bytes = await readFile(join(root, "segments", name));

  await buffer.close();
  await writeFile(join(root, "buffer.json"), before);
  await writeFile(join(root, "segments", name), bytes);
  const restored = new EventBuffer(config);
  buffers.push(restored);
  await restored.start();
  await restored.appendDns(event);
  expect(await readdir(join(root, "segments"))).toEqual([name]);
  expect(restored.status()).toMatchObject({
    lostBatches: "0",
    rejectedRecords: "0",
    pendingDnsRecords: 0,
  });
});

it("bounds batch records and bytes without aggregating lookup history", async () => {
  const { root, buffer } = await fixture("16777216");

  const large = Array.from({ length: 4 }, () => ({
    ...dnsEvent(),
    details: Object.fromEntries(
      Array.from({ length: 90 }, (_, index) => [
        `field${index}`,
        "x".repeat(4000),
      ]),
    ),
  }));

  await Promise.all(large.map((event) => buffer.appendDns(event)));

  const saved = await Promise.all(
    (await readdir(join(root, "segments"))).map(async (name) => {
      const text = await readFile(join(root, "segments", name), "utf8");
      expect(Buffer.byteLength(text)).toBeLessThanOrEqual(1048576);

      return JSON.parse(text).events as GatewayEvent[];
    }),
  );

  expect(
    saved
      .flat()
      .map((event) => event.id)
      .sort(),
  ).toEqual(large.map((event) => event.id).sort());
  expect(saved).toHaveLength(2);
  await Promise.all(
    Array.from({ length: 280 }, dnsEvent).map((event) =>
      buffer.appendDns(event),
    ),
  );
  expect((await readdir(join(root, "segments"))).length).toBe(3);
});

it("keeps keyed checkpoint operations between adjacent DNS batches", async () => {
  const { root, buffer } = await fixture();

  const first = dnsEvent(),
    second = dnsEvent(),
    suricata = observation();

  await Promise.all([
    buffer.appendDns(first),
    buffer.append([suricata], "eve:ordered"),
    buffer.appendDns(second),
  ]);
  const segments = (await readdir(join(root, "segments"))).sort();

  const ids = await Promise.all(
    segments.map(
      async (name) =>
        JSON.parse(await readFile(join(root, "segments", name), "utf8"))
          .events[0].id,
    ),
  );

  expect(ids).toEqual([first.id, suricata.id, second.id]);
  await buffer.append([suricata], "eve:ordered");
  expect(buffer.status().batches).toBe(3);
});

it("serves committed status while a write is held without publishing uncommitted records", async () => {
  let entered!: () => void, release!: () => void;

  const writing = new Promise<void>((resolve) => {
    entered = resolve;
  });

  const hold = new Promise<void>((resolve) => {
    release = resolve;
  });

  const { buffer } = await fixture(
    "1048576",
    undefined,
    async (path, document) => {
      if (path.includes("/segments/")) {
        entered();
        await hold;
      }

      await atomicJson(path, document);
    },
  );

  const event = dnsEvent();
  const append = buffer.appendDns(event);
  event.details.addresses = "mutated caller";
  await writing;

  try {
    const view = buffer.status();
    expect(view).toMatchObject({
      batches: 0,
      bytes: "0",
      pendingDnsRecords: 1,
      writePending: true,
    });
    view.batches = 999;
    expect(buffer.status().batches).toBe(0);
  } finally {
    release();
  }

  await append;
  expect(buffer.status()).toMatchObject({
    batches: 1,
    pendingDnsRecords: 0,
    writePending: false,
  });
});

it("persists and reports status while delivery is waiting on the controller", async () => {
  let entered!: () => void, release!: () => void;

  const sending = new Promise<void>((resolve) => {
    entered = resolve;
  });

  const hold = new Promise<void>((resolve) => {
    release = resolve;
  });

  const { buffer } = await fixture("16777216", async (batch) => {
    entered();
    await hold;

    return batch;
  });

  await buffer.append([observation()]);
  const delivery = buffer.deliver();
  await sending;

  try {
    await Promise.all(
      Array.from({ length: 32 }, dnsEvent).map((event) =>
        buffer.appendDns(event),
      ),
    );
    expect(buffer.status()).toMatchObject({
      batches: 2,
      lostBatches: "0",
      pendingDnsRecords: 0,
    });
  } finally {
    release();
  }

  await delivery;
  expect(buffer.status().batches).toBe(0);
});

it("bounds pending records and counts only the refused live observation", async () => {
  const saved: GatewayEvent[] = [];
  let entered!: () => void, release!: () => void;
  let held = false;

  const waiting = new Promise<void>((resolve) => {
    entered = resolve;
  });

  const hold = new Promise<void>((resolve) => {
    release = resolve;
  });

  const { buffer } = await fixture(
    "16777216",
    undefined,
    async (path, document) => {
      if (path.includes("/segments/")) {
        if (!held) {
          held = true;
          entered();
          await hold;
        }

        saved.push(...(document as { events: GatewayEvent[] }).events);
      }

      await atomicJson(path, document);
    },
  );

  const events = Array.from({ length: 16384 }, dnsEvent);

  const writes = Promise.allSettled(
    events.map((event) => buffer.appendDns(event)),
  );

  await waiting;

  try {
    await expect(buffer.appendDns(dnsEvent())).rejects.toMatchObject({
      code: "collector_queue_capacity",
    });
    expect(buffer.status()).toMatchObject({
      pendingDnsRecords: 16384,
      rejectedRecords: "1",
      rejectionCheckpointPending: true,
      lostBatches: "0",
    });
  } finally {
    release();
  }

  expect((await writes).every((result) => result.status === "fulfilled")).toBe(
    true,
  );
  expect(new Set(saved.map((event) => event.id))).toEqual(
    new Set(events.map((event) => event.id)),
  );
  await buffer.close();
  expect(buffer.status()).toMatchObject({
    pendingDnsRecords: 0,
    rejectedRecords: "1",
    rejectionCheckpointPending: false,
  });
});

it("detaches refused DNS groups so later observations settle and shutdown can drain", async () => {
  let release!: () => void, entered!: () => void;

  const hold = new Promise<void>((resolve) => {
    release = resolve;
  });

  const blocked = new Promise<void>((resolve) => {
    entered = resolve;
  });

  let held = false;

  const { buffer } = await fixture(
    "16777216",
    undefined,
    async (path, document) => {
      if (path.includes("/segments/") && !held) {
        held = true;
        entered();
        await hold;
      }

      await atomicJson(path, document);
    },
  );

  const writes = Promise.allSettled(
    Array.from({ length: 64 }, () => buffer.append([observation()])),
  );

  await blocked;

  try {
    await expect(buffer.appendDns(dnsEvent())).rejects.toThrow("queue is full");

    const subsequent = buffer.appendDns(dnsEvent()).then(
      () => "accepted",
      () => "rejected",
    );

    const settled = await Promise.race([
      subsequent,
      new Promise<string>((resolve) => setTimeout(() => resolve("hung"), 100)),
    ]);

    expect(settled).toBe("rejected");
    expect(buffer.status()).toMatchObject({
      pendingDnsRecords: 0,
      rejectedRecords: "2",
    });
  } finally {
    release();
  }

  expect((await writes).every((result) => result.status === "fulfilled")).toBe(
    true,
  );
  await buffer.appendDns(dnsEvent());
  await buffer.close();
  expect(buffer.status()).toMatchObject({
    pendingDnsRecords: 0,
    pendingWrites: 0,
  });
});

it("bounds retained bytes independently of the pending record count", async () => {
  const { buffer } = await fixture("134217728");
  let entered!: () => void, release!: () => void;

  const waiting = new Promise<void>((resolve) => {
    entered = resolve;
  });

  const hold = new Promise<void>((resolve) => {
    release = resolve;
  });

  const blocker = buffer.coordinateAllocation("134217728", async () => {
    entered();
    await hold;
  });

  await waiting;

  const events = Array.from({ length: 280 }, () => ({
    ...dnsEvent(),
    details: Object.fromEntries(
      Array.from({ length: 60 }, (_, index) => [
        `field${index}`,
        "x".repeat(4000),
      ]),
    ),
  }));

  const writes = Promise.allSettled(
    events.map((event) => buffer.appendDns(event)),
  );

  try {
    const view = buffer.status();
    expect(view.pendingDnsRecords).toBeLessThan(280);
    expect(BigInt(view.pendingDnsBytes)).toBeLessThanOrEqual(67108864n);
    expect(BigInt(view.rejectedRecords)).toBeGreaterThan(0n);
  } finally {
    release();
  }

  await blocker;
  const settled = await writes;
  expect(settled.filter((value) => value.status === "rejected")).toHaveLength(
    Number(buffer.status().rejectedRecords),
  );
});

it("recovers a failed DNS batch and recognizes each retained lookup on retry", async () => {
  let fail = true;

  const { root, config, buffer } = await fixture(
    "16777216",
    undefined,
    async (path, document) => {
      if (fail && path.includes("/segments/")) {
        fail = false;
        throw new Error("DNS segment interrupted");
      }

      await atomicJson(path, document);
    },
  );

  const events = Array.from({ length: 1024 }, dnsEvent);

  const results = await Promise.allSettled(
    events.map((event) => buffer.appendDns(event)),
  );

  expect(results.every((value) => value.status === "rejected")).toBe(true);
  expect(buffer.status()).toMatchObject({
    rejectedRecords: "0",
    lostBatches: "0",
    writePending: true,
  });
  await buffer.close();
  const restored = new EventBuffer(config);
  buffers.push(restored);
  await restored.start();
  await restored.appendDns(events[0]!);
  expect(restored.status()).toMatchObject({
    batches: 1,
    rejectedRecords: "0",
    writePending: false,
  });
  const segment = (await readdir(join(root, "segments")))[0]!;
  expect(
    JSON.parse(
      await readFile(join(root, "segments", segment), "utf8"),
    ).events.map((event: GatewayEvent) => event.id),
  ).toEqual(events.map((event) => event.id));
});

it("persists known rejected records separately from evicted batches", async () => {
  const { config, buffer } = await fixture();
  await expect(
    buffer.appendDns({ ...dnsEvent(), details: { tooLong: "x".repeat(4097) } }),
  ).rejects.toMatchObject({ code: "invalid_dns_observation" });
  expect(buffer.status()).toMatchObject({
    rejectedRecords: "1",
    lostBatches: "0",
  });
  await buffer.close();
  const restored = new EventBuffer(config);
  buffers.push(restored);
  await restored.start();
  expect(restored.status()).toMatchObject({
    rejectedRecords: "1",
    lostBatches: "0",
    coverageCondition: null,
  });
});

it("reports unknown volatile loss after an unclean capture session without inventing a count", async () => {
  const { root, config, buffer } = await fixture();
  await buffer.close();
  const path = join(root, "buffer.json");
  const state = JSON.parse(await readFile(path, "utf8"));
  await atomicJson(path, { ...state, sessionOpen: true });
  const restored = new EventBuffer(config);
  buffers.push(restored);
  await restored.start();
  expect(restored.status()).toMatchObject({
    rejectedRecords: "0",
    lostBatches: "0",
  });
  expect(restored.status().coverageCondition).toContain("clean shutdown");

  const notice = restored.interruptionNotice()!;
  await restored.clearInterruptionNotice("A newer notice");
  expect(restored.interruptionNotice()).toBe(notice);
  await restored.clearInterruptionNotice(notice);
  expect(restored.interruptionNotice()).toBeNull();
  expect(restored.status().coverageCondition).toBeNull();
  await restored.close();

  const reopened = new EventBuffer(config);
  buffers.push(reopened);
  await reopened.start();
  expect(reopened.status().coverageCondition).toBeNull();
});

it("finishes a partially synchronized acknowledgement before sending a newer sequence", async () => {
  const { config, buffer: initial } = await fixture();
  await initial.close();
  const sent: string[] = [];
  let fail = false;

  const buffer = new EventBuffer(
    config,
    async (batch) => {
      sent.push(batch.sequence);

      return batch;
    },
    atomicJson,
    async () => {
      if (fail) {
        fail = false;
        throw new Error("acknowledgement directory interrupted");
      }

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
  );

  buffers.push(buffer);
  await buffer.start();
  await buffer.append([observation()]);
  fail = true;
  await expect(buffer.deliver()).rejects.toThrow(
    "acknowledgement directory interrupted",
  );
  await buffer.append([observation()]);
  await buffer.deliver();
  expect(sent).toEqual(["1", "2"]);
  expect(buffer.status()).toMatchObject({ batches: 0, lostBatches: "0" });
});

it("preserves unpinned history when an incoming batch cannot fit beside the delivery pin", async () => {
  let acknowledge!: () => void;
  let entered!: () => void;

  const sending = new Promise<void>((resolve) => {
    entered = resolve;
  });

  const gate = new Promise<void>((resolve) => {
    acknowledge = resolve;
  });

  const { root, buffer } = await fixture("1048576", async (batch) => {
    entered();
    await gate;

    return batch;
  });

  const large = () => ({
    ...observation(),
    details: Object.fromEntries(
      Array.from({ length: 100 }, (_, index) => [
        `field${index}`,
        "x".repeat(4000),
      ]),
    ),
  });

  await buffer.append([large(), large()]);
  await buffer.append([observation()]);
  const before = buffer.status();
  const retained = await readdir(join(root, "segments"));
  const delivery = buffer.deliver();
  await sending;

  try {
    await expect(buffer.append([large()])).rejects.toMatchObject({
      code: "collector_delivery_pinned",
    });
    expect(buffer.status()).toMatchObject({
      batches: before.batches,
      bytes: before.bytes,
      lostBatches: "0",
    });
    expect(await readdir(join(root, "segments"))).toEqual(retained);
  } finally {
    acknowledge();
    await delivery;
  }
});

it("does not count repeated unlink failures as confirmed evictions", async () => {
  const { root, buffer } = await fixture("4096");
  await buffer.append([observation()]);
  await buffer.append([observation()]);
  const directory = join(root, "segments");
  await chmod(directory, 0o500);

  try {
    await expect(buffer.allocation("650")).rejects.toMatchObject({
      code: "EACCES",
    });
    await expect(buffer.allocation("650")).rejects.toMatchObject({
      code: "EACCES",
    });
    expect(buffer.status()).toMatchObject({
      batches: 2,
      lostBatches: "0",
      writePending: true,
    });
  } finally {
    await chmod(directory, 0o750);
  }

  await buffer.deliver();
  expect(buffer.status()).toMatchObject({
    batches: 0,
    lostBatches: "1",
    writePending: false,
  });
});

it("re-establishes an eviction intent whose checkpoint failed after rename before deleting", async () => {
  let fail = false;

  const { root, buffer } = await fixture(
    "4096",
    undefined,
    async (path, document) => {
      await atomicJson(path, document);

      if (fail && path.endsWith("buffer.json")) {
        fail = false;
        throw new Error("eviction intent checkpoint interrupted");
      }
    },
  );

  await buffer.append([observation()]);
  await buffer.append([observation()]);
  fail = true;
  await expect(buffer.allocation("650")).rejects.toThrow(
    "eviction intent checkpoint interrupted",
  );
  expect(await readdir(join(root, "segments"))).toHaveLength(2);
  expect(buffer.status()).toMatchObject({
    lostBatches: "0",
    writePending: true,
  });
  await buffer.deliver();
  expect(buffer.status()).toMatchObject({
    batches: 0,
    lostBatches: "1",
    writePending: false,
  });
});

it("finishes interrupted eviction synchronization before delivering newer history", async () => {
  const { config, buffer: initial } = await fixture("4096");
  await initial.close();
  const sent: string[] = [];
  let fail = false;

  const buffer = new EventBuffer(
    config,
    async (batch) => {
      sent.push(batch.sequence);

      return batch;
    },
    atomicJson,
    async () => {
      if (fail) throw new Error("eviction directory interrupted");

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
  );

  buffers.push(buffer);
  await buffer.start();
  await buffer.append([observation()]);
  await buffer.append([observation()]);
  fail = true;
  await expect(buffer.allocation("650")).rejects.toThrow(
    "eviction directory interrupted",
  );
  await expect(buffer.deliver()).rejects.toThrow(
    "eviction directory interrupted",
  );
  expect(sent).toEqual([]);
  expect(buffer.status()).toMatchObject({
    lostBatches: "0",
    writePending: true,
  });
  fail = false;
  await buffer.deliver();
  expect(sent).toEqual(["2"]);
  expect(buffer.status()).toMatchObject({
    batches: 0,
    lostBatches: "1",
    writePending: false,
  });
});

it.each(["before rename", "after rename"])(
  "counts an eviction once when its completion checkpoint fails %s",
  async (phase) => {
    let fail = false;

    const { buffer } = await fixture(
      "4096",
      undefined,
      async (path, document) => {
        const completesEviction =
          path.endsWith("buffer.json") &&
          JSON.stringify(document).includes('"lost":"1"') &&
          JSON.stringify(document).includes('"evicting":null');

        if (fail && completesEviction && phase === "before rename") {
          fail = false;
          throw new Error("eviction completion interrupted");
        }

        await atomicJson(path, document);

        if (fail && completesEviction && phase === "after rename") {
          fail = false;
          throw new Error("eviction completion interrupted");
        }
      },
    );

    await buffer.append([observation()]);
    await buffer.append([observation()]);
    fail = true;
    await expect(buffer.allocation("650")).rejects.toThrow(
      "eviction completion interrupted",
    );
    expect(buffer.status()).toMatchObject({
      lostBatches: "0",
      writePending: true,
    });
    await buffer.deliver();
    expect(buffer.status()).toMatchObject({
      batches: 0,
      lostBatches: "1",
      writePending: false,
    });
  },
);

it.each(["present", "absent"])(
  "recovers a durable eviction intent exactly once when its segment is %s",
  async (presence) => {
    const { root, config, buffer } = await fixture("4096");
    await buffer.append([observation()]);
    await buffer.append([observation()]);
    await buffer.close();
    const statePath = join(root, "buffer.json");
    const state = JSON.parse(await readFile(statePath, "utf8"));
    const at = new Date().toISOString();
    await atomicJson(statePath, {
      ...state,
      sessionOpen: true,
      evicting: { sequence: "1", lost: "1", firstLossAt: at, lastLossAt: at },
    });

    if (presence === "absent")
      await unlink(join(root, "segments", "00000000000000000001.json"));
    const sent: string[] = [];

    const restored = new EventBuffer(config, async (batch) => {
      sent.push(batch.sequence);

      return batch;
    });

    buffers.push(restored);
    await restored.start();
    expect(restored.status()).toMatchObject({
      batches: 1,
      lostBatches: "1",
      firstLossAt: at,
      lastLossAt: at,
      writePending: false,
    });
    await restored.deliver();
    expect(sent).toEqual(["2"]);
    await restored.close();
    const restarted = new EventBuffer(config);
    buffers.push(restarted);
    await restarted.start();
    expect(restarted.status()).toMatchObject({ batches: 0, lostBatches: "1" });
  },
);

async function fixture(
  bytes = "1048576",
  send = async (batch: { epoch: string; sequence: string }) => ({
    epoch: batch.epoch,
    sequence: batch.sequence,
  }),
  persist: typeof atomicJson = atomicJson,
) {
  await mkdir(join(process.cwd(), ".local/tmp/tests"), {
    recursive: true,
  });

  const root = await mkdtemp(
    join(process.cwd(), ".local/tmp/tests/buffer-test-"),
  );

  roots.push(root);

  const config = {
    stateDirectory: root,
    collectorBytes: bytes,
  } as GatewayConfig;

  const buffer = new EventBuffer(config, send, persist);
  buffers.push(buffer);
  await buffer.start();

  return { root, config, buffer };
}

it("leaves the segment directory readable by the service group under a private umask", async () => {
  const previous = process.umask(0o077);

  try {
    const { root } = await fixture();
    expect((await stat(join(root, "segments"))).mode & 0o777).toBe(0o750);
  } finally {
    process.umask(previous);
  }
});

it("disposes its persistence owner once after the final checkpoint", async () => {
  const { config, buffer } = await fixture();
  await buffer.close();
  const dispose = vi.fn(async () => {});

  const owned = new EventBuffer(
    config,
    undefined,
    atomicJson,
    undefined,
    undefined,
    { close: dispose, error: null },
  );

  buffers.push(owned);
  await owned.start();
  await owned.appendDns(dnsEvent());
  await owned.close();
  await owned.close();
  expect(dispose).toHaveBeenCalledTimes(1);
  expect(
    JSON.parse(
      await readFile(join(config.stateDirectory, "buffer.json"), "utf8"),
    ).sessionOpen,
  ).toBe(false);
});

it("publishes idle persistence failure and disposes its owner", async () => {
  const { config, buffer } = await fixture();
  await buffer.close();
  let error: Error | null = null;
  const dispose = vi.fn(async () => {});

  const owned = new EventBuffer(
    config,
    undefined,
    atomicJson,
    undefined,
    undefined,
    {
      close: dispose,
      get error() {
        return error;
      },
    },
  );

  buffers.push(owned);
  await owned.start();
  error = new Error("idle persistence worker failed");
  expect(owned.status().persistenceError).toBe(
    "idle persistence worker failed",
  );
  await owned.close();
  expect(dispose).toHaveBeenCalledTimes(1);
});

it("disposes persistence resources when initialization fails before publication", async () => {
  const { config, buffer } = await fixture();
  await buffer.close();
  const dispose = vi.fn(async () => {});

  const owned = new EventBuffer(
    config,
    undefined,
    async () => {
      throw new Error("initial persistence failed");
    },
    undefined,
    undefined,
    { close: dispose, error: null },
  );

  buffers.push(owned);
  await expect(owned.start()).rejects.toThrow("initial persistence failed");
  await owned.close();
  expect(dispose).toHaveBeenCalledTimes(1);
});

describe("durable collector replay", () => {
  it("recovers a reserved payload under the confirmed increased allocation without evicting unread segments", async () => {
    const { config, buffer } = await fixture("650");
    await buffer.allocation("4096");
    await buffer.append([observation()]);
    await buffer.append([observation()]);
    await buffer.close();

    const interrupted = new EventBuffer(
      { ...config, collectorBytes: "4096" },
      undefined,
      async (...args) => {
        if (args[0].includes("/segments/"))
          throw new Error("segment interrupted");
        await atomicJson(...args);
      },
    );

    buffers.push(interrupted);
    await interrupted.start();
    const event = observation();
    await expect(
      interrupted.append([event], "restart:larger-allocation"),
    ).rejects.toThrow("segment interrupted");
    await interrupted.close();
    const restored = new EventBuffer({ ...config, collectorBytes: "4096" });
    buffers.push(restored);
    await restored.start();
    await restored.append([event], "restart:larger-allocation");
    expect(await restored.status()).toMatchObject({
      batches: 3,
      lostBatches: "0",
      allocationBytes: "4096",
    });
  });
  it("does not change allocation or evict observations when native preparation fails", async () => {
    const { buffer } = await fixture();
    await buffer.append([observation()]);
    await expect(
      buffer.coordinateAllocation("1", async () => {
        throw new Error("native preparation failed");
      }),
    ).rejects.toThrow("native preparation failed");
    const status = await buffer.status();
    expect(status.allocationBytes).toBe("1048576");
    expect(status.batches).toBe(1);
    expect(status.lostBatches).toBe("0");
  });
  it("recovers a missing segment from its durable payload after process restart", async () => {
    const { config, buffer } = await fixture();
    await buffer.close();

    const failed = new EventBuffer(config, undefined, async (...args) => {
      if (args[0].includes("/segments/"))
        throw new Error("segment unavailable");
      await atomicJson(...args);
    });

    buffers.push(failed);
    await failed.start();
    const event = observation();
    await expect(failed.append([event], "eve:restart")).rejects.toThrow(
      "segment unavailable",
    );
    await failed.close();
    const restored = new EventBuffer(config);
    buffers.push(restored);
    await restored.start();
    await restored.append([event], "eve:restart");
    const status = await restored.status();
    expect(status.batches).toBe(1);
    expect(status.lostBatches).toBe("0");
    expect(status.coverageCondition).toBeNull();
  });
  it("retains a retryable payload when its recovery checkpoint also fails", async () => {
    const { config, buffer } = await fixture();
    await buffer.close();

    let segmentFailure = true,
      checkpointFailure = true;

    const restored = new EventBuffer(
      config,
      async (batch) => batch,
      async (...args) => {
        if (segmentFailure && args[0].includes("/segments/")) {
          segmentFailure = false;
          throw new Error("segment failure");
        }

        const value = args[1] as { lost?: string; pending?: string | null };

        if (!segmentFailure && value.pending === null && checkpointFailure) {
          checkpointFailure = false;
          throw new Error("recovery checkpoint failure");
        }

        await atomicJson(...args);
      },
    );

    buffers.push(restored);
    await restored.start();
    const event = observation();
    await expect(restored.append([event])).rejects.toThrow("segment failure");
    await expect(restored.append([event])).rejects.toThrow(
      "recovery checkpoint failure",
    );
    await restored.append([event]);
    expect((await restored.status()).lostBatches).toBe("0");
    expect((await restored.status()).batches).toBe(1);
  });
  it("resolves a failed segment reservation before accepting a retry", async () => {
    const { root, config, buffer } = await fixture();
    await buffer.close();
    let fail = true;

    const restored = new EventBuffer(config, undefined, async (...args) => {
      if (fail && args[0].includes("/segments/")) {
        fail = false;
        throw new Error("segment write failed");
      }

      await atomicJson(...args);
    });

    buffers.push(restored);
    await restored.start();
    const event = observation();
    await expect(restored.append([event])).rejects.toThrow(
      "segment write failed",
    );
    await restored.append([event]);
    expect((await restored.status()).lostBatches).toBe("0");
    const names = await readdir(join(root, "segments"));
    expect(names).toEqual(["00000000000000000001.json"]);
    expect(
      JSON.parse(await readFile(join(root, "segments", names[0]!), "utf8"))
        .events[0].id,
    ).toBe(event.id);
  });
  it("retains a durable segment when its final checkpoint fails, and can acknowledge it", async () => {
    const { config, buffer } = await fixture();
    await buffer.close();

    let saved = false,
      fail = true;

    let acknowledgements = 0;

    const restored = new EventBuffer(
      config,
      async (batch) => {
        acknowledgements++;

        return batch;
      },
      async (...args) => {
        if (saved && fail && args[0].endsWith("buffer.json")) {
          throw new Error("final checkpoint failed");
        }

        await atomicJson(...args);

        if (args[0].includes("/segments/")) saved = true;
      },
    );

    buffers.push(restored);
    await restored.start();
    await restored.append([observation()]);
    await expect(restored.deliver()).rejects.toThrow("final checkpoint failed");
    expect(await readdir(join(config.stateDirectory, "segments"))).toHaveLength(
      1,
    );
    fail = false;
    await restored.deliver();
    expect(acknowledgements).toBe(1);
    expect((await restored.status()).batches).toBe(0);
    expect((await restored.status()).lostBatches).toBe("0");
  });
  it("recovers the sequence after a segment/checkpoint crash without overwriting retained events", async () => {
    const { root, config, buffer } = await fixture();
    const event = observation();
    await buffer.append([event]);
    await buffer.close();
    const path = join(root, "buffer.json");
    const state = JSON.parse(await readFile(path, "utf8"));
    await writeFile(
      path,
      JSON.stringify({ ...state, sequence: "0", pending: "1" }),
    );
    const restored = new EventBuffer(config);
    buffers.push(restored);
    await restored.start();
    await restored.append([observation()]);
    expect((await readdir(join(root, "segments"))).sort()).toEqual([
      "00000000000000000001.json",
      "00000000000000000002.json",
    ]);
    expect(
      JSON.parse(
        await readFile(
          join(root, "segments/00000000000000000001.json"),
          "utf8",
        ),
      ).events[0].id,
    ).toBe(event.id);
  });
  it("retains unacknowledged segments and rejects an acknowledgement for another identity", async () => {
    const { buffer } = await fixture("1048576", async () => ({
      epoch: randomUUID(),
      sequence: "1",
    }));

    await buffer.append([observation()]);
    await expect(buffer.deliver()).rejects.toThrow("identity mismatch");
    expect((await buffer.status()).batches).toBe(1);
  });
  it("evicts the oldest unread segment exactly once and keeps the newest", async () => {
    const { buffer } = await fixture("650");
    await buffer.append([observation()]);
    await buffer.append([observation()]);
    const status = await buffer.status();
    expect(status.batches).toBe(1);
    expect(status.lostBatches).toBe("1");
    expect(status.firstLossAt).not.toBeNull();
    expect(BigInt(status.bytes)).toBeLessThanOrEqual(650n);
  });
  it("protects an in-flight segment and exposes capacity pressure until it is acknowledged", async () => {
    let acknowledge!: () => void;
    let entered!: () => void;

    const sending = new Promise<void>((resolve) => {
      entered = resolve;
    });

    const gate = new Promise<void>((resolve) => {
      acknowledge = resolve;
    });

    const sent: string[] = [];

    const { buffer } = await fixture("650", async (batch) => {
      entered();
      await gate;
      sent.push(batch.sequence);

      return batch;
    });

    await buffer.append([observation()]);
    const delivery = buffer.deliver();
    await sending;
    const event = observation();
    await expect(buffer.append([event])).rejects.toMatchObject({
      code: "collector_delivery_pinned",
    });
    expect(buffer.status()).toMatchObject({ batches: 1, lostBatches: "0" });
    acknowledge();
    await delivery;
    await buffer.append([event]);
    await buffer.deliver();
    expect(sent).toEqual(["1", "2"]);
    expect((await buffer.status()).batches).toBe(0);
    expect((await buffer.status()).lostBatches).toBe("0");
  });
  it("reports uncertainty for an old missing reservation without claiming confirmed loss", async () => {
    const { root, config, buffer } = await fixture();
    await buffer.close();
    const path = join(root, "buffer.json");
    const state = JSON.parse(await readFile(path, "utf8"));
    await writeFile(
      path,
      JSON.stringify({ ...state, sequence: "1", pending: "1" }),
    );
    const restored = new EventBuffer(config);
    buffers.push(restored);
    await restored.start();
    await restored.append([observation()]);
    expect((await restored.status()).lostBatches).toBe("0");
    expect((await restored.status()).coverageCondition).toContain(
      "may be missing",
    );
    expect(await readdir(join(root, "segments"))).toEqual([
      "00000000000000000002.json",
    ]);
  });
  it("restores an interrupted payload on startup and syncs the segment directory before clearing its reservation", async () => {
    const { root, config, buffer } = await fixture();
    await buffer.close();
    let fail = true;

    const writer = new EventBuffer(
      config,
      async (batch) => batch,
      async (...args) => {
        await atomicJson(...args);

        if (fail && args[0].includes("/segments/")) {
          fail = false;
          throw new Error("directory sync failed after rename");
        }
      },
    );

    buffers.push(writer);
    await writer.start();
    const event = observation();
    await expect(writer.append([event])).rejects.toThrow(
      "directory sync failed",
    );
    await writer.close();

    const failed = new EventBuffer(config, undefined, atomicJson, async () => {
      throw new Error("startup sync failed");
    });

    buffers.push(failed);
    await expect(failed.start()).rejects.toThrow("startup sync failed");

    const pending = JSON.parse(
      await readFile(join(root, "buffer.json"), "utf8"),
    );

    expect(pending.pending.batch.events[0].id).toBe(event.id);
    let synced = false;

    const restored = new EventBuffer(
      config,
      undefined,
      async (...args) => {
        if ((args[1] as { pending: unknown }).pending === null)
          expect(synced).toBe(true);
        await atomicJson(...args);
      },
      async () => {
        const directory = await open(join(root, "segments"), "r");

        try {
          await directory.sync();
          synced = true;
        } finally {
          await directory.close();
        }
      },
    );

    buffers.push(restored);
    await restored.start();
    expect((await restored.status()).lostBatches).toBe("0");
    expect((await restored.status()).batches).toBe(1);
  });
  it("atomically resolves an old missing startup reservation when the checkpoint must retry", async () => {
    const { root, config, buffer } = await fixture();
    await buffer.close();
    const path = join(root, "buffer.json");
    const state = JSON.parse(await readFile(path, "utf8"));
    await atomicJson(path, { ...state, sequence: "1", pending: "1" });

    const failed = new EventBuffer(config, undefined, async (...args) => {
      if ((args[1] as { pending: unknown }).pending === null)
        throw new Error("startup checkpoint failed");
      await atomicJson(...args);
    });

    buffers.push(failed);
    await expect(failed.start()).rejects.toThrow("startup checkpoint failed");
    const unchanged = JSON.parse(await readFile(path, "utf8"));
    expect(unchanged.pending).toBe("1");
    expect(unchanged.lost).toBe("0");
    expect(unchanged.coverageCondition).toBeNull();
    const restored = new EventBuffer(config);
    buffers.push(restored);
    await restored.start();
    await restored.close();
    const resolved = JSON.parse(await readFile(path, "utf8"));
    expect(resolved.pending).toBeNull();
    expect(resolved.lost).toBe("0");
    expect(resolved.coverageCondition).toContain("may be missing");
    const repeated = new EventBuffer(config);
    buffers.push(repeated);
    await repeated.start();
    expect((await repeated.status()).coverageCondition).toBe(
      resolved.coverageCondition,
    );
  });
  it("keeps keyed source commits idempotent after acknowledgement and other producers", async () => {
    const { buffer } = await fixture();
    const event = observation();
    await buffer.append([event], "eve:fixture:0");
    await buffer.deliver();
    await buffer.append([observation()]);
    await buffer.append([event], "eve:fixture:0");
    expect((await buffer.status()).batches).toBe(1);
    await expect(
      buffer.append(
        [{ ...event, details: { changed: true } }],
        "eve:fixture:0",
      ),
    ).rejects.toThrow("identity conflicts");
  });
  it("does not count retained oversized retries as observation loss", async () => {
    const { buffer } = await fixture("100");
    const event = observation();
    await expect(buffer.append([event])).rejects.toThrow("exceeds");
    await expect(buffer.append([event])).rejects.toThrow("exceeds");
    const status = await buffer.status();
    expect(status.lostBatches).toBe("0");
    expect(status.firstLossAt).toBeNull();
    expect(status.persistenceError).toContain("exceeds");
  });
});
