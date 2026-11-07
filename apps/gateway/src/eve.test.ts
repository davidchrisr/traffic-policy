import { afterEach, describe, expect, it, vi } from "vitest";
import {
  appendFile,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { EveReader, eveObservation } from "./eve.ts";
import { atomicJson } from "@traffic-policy/core/io";
import type { GatewayEvent } from "@traffic-policy/contracts";
import { EventBuffer } from "./buffer.ts";
import type { GatewayConfig } from "./config.ts";
import { StorageBudget, storageUsage } from "@traffic-policy/core/storage";
import { dirname } from "node:path";
import { createHash } from "node:crypto";
import type { Policy } from "@traffic-policy/contracts";
import { DnsRuleIndex } from "@traffic-policy/core";

// DnsRuleIndex reads instances, rules, and local networks.
const policy = {
  settings: { collectorBytes: "1048576", localNetworks: [] as string[] },
  rules: [] as Policy["rules"],
  instances: [
    {
      id: "11111111-1111-4111-8111-111111111111",
      name: "Client",
      addresses: ["10.22.241.10"],
    },
  ],
} as Policy;

const index = new DnsRuleIndex(policy);

const line =
  '{"timestamp":"2026-10-09T20:00:00.123456+0000","event_type":"tls","src_ip":"10.22.241.10","dest_ip":"10.22.242.20","src_port":50000,"dest_port":443,"proto":"TCP","flow_id":9007199254740993,"tls":{"sni":"proof.example"}}';

const roots: string[] = [];

const readers: EveReader[] = [];

function deferred() {
  let resolve = () => {};

  const promise = new Promise<void>((accept) => {
    resolve = accept;
  });

  return { promise, resolve };
}

afterEach(async () => {
  for (const reader of readers.splice(0)) await reader.close();
  vi.useRealTimers();
  vi.restoreAllMocks();

  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

async function readerFixture(
  record: (
    events: GatewayEvent[],
    key: string,
    signal: AbortSignal,
  ) => Promise<void>,
  persist = atomicJson,
  getPolicy = () => policy,
) {
  const root = await mkdtemp(join(process.cwd(), ".local/tmp/tests/eve-test-"));

  roots.push(root);

  const path = join(root, "eve.json"),
    state = join(root, "state");

  await mkdir(state);
  await writeFile(path, line + "\n");

  const create = (budget?: StorageBudget) => {
    const reader = new EveReader(
      path,
      state,
      "fixture",
      () => {
        const value = getPolicy();

        return { policy: value, index: new DnsRuleIndex(value) };
      },
      record,
      new Set(),
      persist,
      budget,
    );

    readers.push(reader);

    return reader;
  };

  return { path, state, create };
}

describe("Suricata observations", () => {
  it("reports numeric flow IDs without exact integer tokens as field validation failures", () => {
    const invalid = line.replace("9007199254740993", "9.007199254740993e15");
    expect(() => eveObservation(invalid, "fixture", index)).toThrow(
      "Suricata flow identity is not lossless",
    );
  });
  it("preserves the original timestamp and a flow identity above Number.MAX_SAFE_INTEGER", () => {
    const event = eveObservation(line, "fixture", index);
    expect(event?.observedAt).toBe("2026-10-09T20:00:00.123456+00:00");
    expect(event?.details.flowId).toBe("9007199254740993");
    expect(event?.details.authoritative).toBe(false);
    expect(event?.details.hostname).toBe("proof.example");
    expect(event?.sentBytes).toBe("0");
  });
  it("retains the same source identity across replay and never synthesizes traffic counters", () => {
    expect(eveObservation(line, "fixture", index)?.id).toBe(
      eveObservation(line, "fixture", index)?.id,
    );
    expect(eveObservation(line, "fixture", index)?.type).toBe("metadata");
  });
  it("keeps an unregistered client's lookups for its registration Request and drops its other events", () => {
    const outside = line.replaceAll("10.22.241.10", "10.22.241.99");

    const query =
      '{"timestamp":"2026-10-09T20:00:00.123456+0000","event_type":"dns","src_ip":"10.22.241.99","dest_ip":"10.22.242.53","src_port":50000,"dest_port":53,"proto":"UDP","dns":{"type":"query","rrname":"Wanted.Example"}}';

    expect(eveObservation(outside, "fixture", index)).toBeNull();
    expect(eveObservation(query, "fixture", index)).toMatchObject({
      type: "dns",
      instanceId: null,
      question: "wanted.example",
      details: { clientIp: "10.22.241.99", unregistered: "client" },
    });
    expect(
      eveObservation(query.replace('"query"', '"answer"'), "fixture", index),
    ).toBeNull();
    expect(
      eveObservation(query, "fixture", index, new Set(["10.22.241.99"])),
    ).toBeNull();
    // A gateway address an instance contains is still the gateway's.
    expect(
      eveObservation(line, "fixture", index, new Set(["10.22.241.10"])),
    ).toBeNull();
  });
});

describe("Suricata source durability", () => {
  it("retains the source for retry when normalization has an unexpected runtime failure", async () => {
    const observed: GatewayEvent[] = [];

    const lookup = vi
      .spyOn(DnsRuleIndex.prototype, "context")
      .mockImplementation(() => {
        throw new Error("Injected normalizer runtime fault");
      });

    const { state, create } = await readerFixture(async (events) => {
      observed.push(...events);
    });

    const reader = create();
    await reader.start();
    await expect(reader.read()).rejects.toThrow(
      "Injected normalizer runtime fault",
    );
    await expect(
      readFile(join(state, "eve-cursor.json")),
    ).rejects.toMatchObject({ code: "ENOENT" });
    expect(observed).toHaveLength(0);
    lookup.mockRestore();
    await reader.read();
    expect(observed).toHaveLength(1);
    expect(
      JSON.parse(await readFile(join(state, "eve-cursor.json"), "utf8"))
        .lastNormalizationFailure,
    ).toBeNull();
  });
  it("persists bounded normalization failure details through restart and source removal", async () => {
    const observed: GatewayEvent[] = [];

    const { path, state, create } = await readerFixture(async (events) => {
      observed.push(...events);
    });

    const malformed = line.replace('"dest_port":443', '"dest_port":"invalid"');
    const prefix = line.replace("proof.example", "caf\u00e9.example") + "\n";
    await writeFile(path, prefix + malformed + "\n{broken\n" + line + "\n");
    const reader = create();
    await reader.start();
    await reader.read();

    const cursor = JSON.parse(
      await readFile(join(state, "eve-cursor.json"), "utf8"),
    );

    expect(cursor.lastNormalizationFailure).toMatchObject({
      code: "invalid_type",
      path: ["dest_port"],
      sourceInode: cursor.inode,
      sourceOffset: String(Buffer.byteLength(prefix)),
      recordsInRead: 2,
      digest: createHash("sha256").update(malformed).digest("hex"),
    });
    expect(cursor.lastNormalizationFailure.message.length).toBeLessThanOrEqual(
      256,
    );
    expect(JSON.stringify(cursor.lastNormalizationFailure)).not.toContain(
      "proof.example",
    );
    expect(cursor.condition).toContain("Earlier Suricata records");
    expect(reader.condition).toBeNull();
    expect(observed).toHaveLength(2);
    await reader.read();
    expect(observed.slice(2).map((event) => event.details)).toEqual([
      {
        code: "suricata_coverage",
        message: cursor.condition,
        recovered: false,
      },
      {
        code: "suricata_coverage",
        message: "Suricata records are processed again",
        recovered: true,
      },
    ]);
    expect(
      JSON.parse(await readFile(join(state, "eve-cursor.json"), "utf8"))
        .condition,
    ).toBeNull();
    await reader.close();
    await rename(path, path + ".1791580000000-aaaaaaaa.closed");
    await writeFile(path, line + "\n");
    const restored = create();
    await restored.start();
    await restored.read();
    await restored.read();

    const next = JSON.parse(
      await readFile(join(state, "eve-cursor.json"), "utf8"),
    );

    expect(next.lastNormalizationFailure).toEqual(
      cursor.lastNormalizationFailure,
    );
    await expect(
      readFile(path + ".1791580000000-aaaaaaaa.closed"),
    ).rejects.toMatchObject({ code: "ENOENT" });
    expect(next.condition).toBeNull();
    expect(observed.filter((event) => event.type === "condition")).toHaveLength(
      2,
    );
    await appendFile(path, "{broken\n");
    await restored.read();
    expect(
      JSON.parse(await readFile(join(state, "eve-cursor.json"), "utf8"))
        .lastNormalizationFailure,
    ).toMatchObject({ code: "invalid_json", path: [], recordsInRead: 1 });
  });
  it("skips a record beyond the framing limit and keeps collecting", async () => {
    const observed: GatewayEvent[] = [];

    const { path, state, create } = await readerFixture(async (events) => {
      observed.push(...events);
    });

    const oversized = "x".repeat(300 * 1024);
    await writeFile(path, `${line}\n${oversized}\n${line}\n`);
    const reader = create();
    await reader.start();

    // The oversized record leaves a coverage notice, recorded by the read after it.
    for (let read = 0; read < 4; read++) await reader.read();

    const cursor = JSON.parse(
      await readFile(join(state, "eve-cursor.json"), "utf8"),
    );

    expect(observed.map((event) => event.type)).toEqual([
      "metadata",
      "condition",
      "condition",
      "metadata",
    ]);
    expect(cursor.offset).toBe(
      String(Buffer.byteLength(`${line}\n${oversized}\n${line}\n`)),
    );
    expect(cursor.lastNormalizationFailure).toMatchObject({
      code: "record_too_large",
      sourceOffset: String(Buffer.byteLength(line) + 1),
      recordsInRead: 1,
    });
    expect(cursor.condition).toBeNull();
  });

  it("cancels delivery backpressure on shutdown and retains the source job for restart", async () => {
    const entered = deferred();
    const delivered: GatewayEvent[] = [];

    const { state, create } = await readerFixture(
      async (events, key, signal) => {
        entered.resolve();
        await buffer.appendSource(events, key, signal);
      },
    );

    const buffer = new EventBuffer(
      {
        stateDirectory: join(state, "buffer"),
        collectorBytes: "1048576",
      } as GatewayConfig,
      async (batch) => {
        delivered.push(...batch.events);

        return batch;
      },
    );

    try {
      await buffer.start();
      const event = eveObservation(line, "fixture", index)!;
      await buffer.append([
        { ...event, id: "22222222-2222-4222-8222-222222222222" },
      ]);
      await buffer.append([
        { ...event, id: "33333333-3333-4333-8333-333333333333" },
      ]);
      const reader = create();
      await reader.start();
      const reading = reader.read();
      const rejected = expect(reading).rejects;
      await entered.promise;
      await reader.close();
      await rejected.toMatchObject({ name: "AbortError" });
      expect(reader.condition).toBeNull();
      expect(
        JSON.parse(await readFile(join(state, "eve-job.json"), "utf8")).offset,
      ).toBe(0);
      await buffer.deliver();
      const restored = create();
      await restored.start();
      await restored.read();
      await buffer.deliver();
      expect(delivered.map((value) => value.id)).toEqual([
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
        event.id,
      ]);
    } finally {
      await buffer.close();
    }
  });
  it("retains smaller chunks when a source job exceeds the collector allocation", async () => {
    const chunks: number[] = [];

    const { path, create } = await readerFixture(
      async (events) => {
        chunks.push(events.length);
      },
      atomicJson,
      () => ({
        ...policy,
        settings: { ...policy.settings, collectorBytes: "131072" },
      }),
    );

    await writeFile(
      path,
      Array.from({ length: 600 }, (_, i) =>
        line.replace("proof.example", `proof${i}.example`),
      ).join("\n") + "\n",
    );
    const reader = create();
    await reader.start();
    await reader.read();
    expect(chunks).toEqual([256, 256, 88]);
  });
  it("drains multiple source chunks without a poll delay and idles after reaching the end", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const scheduled = vi.spyOn(globalThis, "setTimeout");
    const observed: GatewayEvent[] = [];

    const { path, create } = await readerFixture(async (events) => {
      observed.push(...events);
    });

    await writeFile(
      path,
      Array.from({ length: 3000 }, (_, i) =>
        line.replace("proof.example", `proof${i}.example`),
      ).join("\n") + "\n",
    );
    const reader = create();
    const reads = vi.spyOn(reader, "read");
    await reader.start();
    await vi.advanceTimersByTimeAsync(1000);
    await reads.mock.results.at(-1)!.value;
    expect(observed.length).toBeGreaterThan(0);
    expect(observed.length).toBeLessThan(3000);
    expect(scheduled).toHaveBeenLastCalledWith(expect.any(Function), 0);

    for (let i = 0; i < 4 && observed.length < 3000; i++) {
      const previous = reads.mock.calls.length;
      await vi.advanceTimersByTimeAsync(0);
      expect(reads).toHaveBeenCalledTimes(previous + 1);
      await reads.mock.results.at(-1)!.value;
    }

    expect(observed).toHaveLength(3000);
    expect(new Set(observed.map((event) => event.id)).size).toBe(3000);
    await vi.advanceTimersByTimeAsync(0);
    await reads.mock.results.at(-1)!.value;
    expect(scheduled).toHaveBeenLastCalledWith(expect.any(Function), 1000);
    await reader.close();
    const count = reads.mock.calls.length;
    await vi.advanceTimersByTimeAsync(2000);
    expect(reads).toHaveBeenCalledTimes(count);
  });
  it("captures one policy snapshot per new read and keeps it through asynchronous source reads", async () => {
    let current = policy;
    const getPolicy = vi.fn(() => structuredClone(current));
    const observed: GatewayEvent[] = [];

    const { path, create } = await readerFixture(
      async (events) => {
        observed.push(...events);
      },
      atomicJson,
      getPolicy,
    );

    const reader = create();
    await reader.start();
    const reading = reader.read();
    expect(reader.read()).toBe(reading);
    current = {
      ...policy,
      instances: [
        { ...policy.instances[0]!, id: "22222222-2222-4222-8222-222222222222" },
      ],
    };
    await reading;
    expect(getPolicy).toHaveBeenCalledTimes(1);
    expect(observed[0]?.instanceId).toBe(policy.instances[0]!.id);
    await appendFile(
      path,
      line.replace("proof.example", "next.example") + "\n",
    );
    await reader.read();
    expect(getPolicy).toHaveBeenCalledTimes(2);
    expect(observed[1]?.instanceId).toBe(current.instances[0]!.id);
    await reader.close();
    await reader.read();
    expect(getPolicy).toHaveBeenCalledTimes(2);
  });
  it("records a storage gap before evicting an unread closed source and resumes the newest file", async () => {
    const observed: GatewayEvent[] = [];
    let archived = "";
    let gapRecorded = false;

    const { path, state, create } = await readerFixture(
      async (events) => {
        observed.push(...events);
      },
      async (...args) => {
        if (
          !gapRecorded &&
          args[0].endsWith("eve-cursor.json") &&
          (args[1] as { condition?: string }).condition?.includes("discarded")
        ) {
          expect(await readFile(archived, "utf8")).toContain("proof.example");
          gapRecorded = true;
        }

        await atomicJson(...args);
      },
    );

    archived = path + ".1791580000000-aaaaaaaa.closed";
    await rename(path, archived);
    await writeFile(
      path,
      line.replace("proof.example", "newest.example") + "\n",
    );

    const root = dirname(path),
      used = BigInt(storageUsage([root]).allocatedBytes);

    const reader = create(new StorageBudget([root], used + 65536n, 0n));
    await reader.start();
    await reader.read();
    await expect(readFile(archived)).rejects.toMatchObject({ code: "ENOENT" });
    expect(
      JSON.parse(await readFile(join(state, "eve-cursor.json"), "utf8"))
        .condition,
    ).toContain("unread source bytes");
    expect(gapRecorded).toBe(true);
    expect(observed).toHaveLength(0);
    await reader.read();
    expect(observed.map((event) => event.details.recovered)).toEqual([
      false,
      true,
    ]);
    expect(String(observed[0]?.details.message)).toContain(
      "unread source bytes",
    );
    await reader.read();
    expect(observed[2]?.details.hostname).toBe("newest.example");
  });
  it("does not advance at EOF until the rotated writer is closed, including late writes", async () => {
    const observed: GatewayEvent[] = [];

    const { path, create } = await readerFixture(async (events) => {
      observed.push(...events);
    });

    const reader = create();
    await reader.start();
    await reader.read();
    const rotating = path + ".1791580000000-aaaaaaaa.rotating";
    await rename(path, rotating);
    await writeFile(path, line.replace("proof.example", "new.example") + "\n");
    await reader.read();
    expect(observed).toHaveLength(1);
    await appendFile(
      rotating,
      line.replace("proof.example", "late.example") + "\n",
    );
    await reader.read();
    expect(observed.at(-1)?.details.hostname).toBe("late.example");
    await rename(rotating, rotating.replace(".rotating", ".closed"));
    await reader.read();
    await reader.read();
    expect(observed.map((event) => event.details.hostname)).toEqual([
      "proof.example",
      "late.example",
      "new.example",
    ]);
  });
  it("resumes the old source after rotation and a reader restart, then drains multiple archives", async () => {
    const observed: GatewayEvent[] = [];

    const { path, create } = await readerFixture(async (events) => {
      observed.push(...events);
    });

    const reader = create();
    await reader.start();
    await reader.read();
    await reader.close();
    await appendFile(
      path,
      line.replace("proof.example", "unread.example") + "\n",
    );
    await rename(path, path + ".1791580000000-aaaaaaaa.closed");
    await writeFile(
      path + ".1791580000001-bbbbbbbb.closed",
      line.replace("proof.example", "second.example") + "\n",
    );
    await writeFile(
      path,
      line.replace("proof.example", "active.example") + "\n",
    );
    const restored = create();
    await restored.start();

    for (let i = 0; i < 5; i++) await restored.read();
    expect(observed.map((event) => event.details.hostname)).toEqual([
      "proof.example",
      "unread.example",
      "second.example",
      "active.example",
    ]);
  });
  it("retries the same source identity after a failed cursor checkpoint", async () => {
    let fail = true;
    const observed: GatewayEvent[] = [];

    const { state, create } = await readerFixture(
      async (events) => {
        observed.push(...events);
      },
      async (...args) => {
        if (fail && args[0].endsWith("eve-cursor.json")) {
          fail = false;
          throw new Error("checkpoint failure");
        }

        await atomicJson(...args);
      },
    );

    const reader = create();
    await reader.start();
    await expect(reader.read()).rejects.toThrow("checkpoint failure");
    await reader.read();
    expect(observed).toHaveLength(1);
    expect(
      JSON.parse(await readFile(join(state, "eve-cursor.json"), "utf8")).offset,
    ).not.toBe("0");
  });
  it("keeps the source offset when persistence fails and waits for an active read on shutdown", async () => {
    let release!: () => void, entered!: () => void;

    const ready = new Promise<void>((resolve) => {
      entered = resolve;
    });

    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });

    const { state, create } = await readerFixture(async () => {
      entered();
      await gate;
    });

    const reader = create();
    await reader.start();
    const read = reader.read();
    await ready;
    let closed = false;

    const close = reader.close().then(() => {
      closed = true;
    });

    await Promise.resolve();
    expect(closed).toBe(false);
    release();
    await Promise.all([read, close]);
    expect(
      JSON.parse(await readFile(join(state, "eve-cursor.json"), "utf8")).offset,
    ).not.toBe("0");
  });
  it("reports a missing saved source without silently skipping to a new file", async () => {
    const { path, create } = await readerFixture(async () => {});
    const reader = create();
    await reader.start();
    await reader.read();
    await reader.close();
    await rename(path, path + ".unmanaged");
    await writeFile(path, line + "\n");
    const restored = create();
    await restored.start();
    await expect(restored.read()).rejects.toThrow(
      "Unread Suricata source is missing",
    );
  });
  it("keeps normalized chunks and their progress when a later chunk fails and policy changes", async () => {
    let current = policy,
      fail = true;

    const getPolicy = vi.fn(() => structuredClone(current));

    const observed: GatewayEvent[] = [];

    const { path, create } = await readerFixture(
      async (events) => {
        if (observed.length === 1024 && fail) {
          fail = false;
          throw new Error("second chunk failed");
        }

        observed.push(...events);
      },
      atomicJson,
      getPolicy,
    );

    await writeFile(
      path,
      Array.from({ length: 1100 }, (_, i) =>
        line
          .replace(',"src_port":50000', "")
          .replace("proof.example", `proof${i}.example`),
      ).join("\n") + "\n",
    );
    const reader = create();
    await reader.start();
    await expect(reader.read()).rejects.toThrow("second chunk failed");
    expect(getPolicy).toHaveBeenCalledTimes(1);
    current = {
      ...policy,
      instances: [
        { ...policy.instances[0]!, id: "22222222-2222-4222-8222-222222222222" },
      ],
    };
    await reader.read();
    expect(getPolicy).toHaveBeenCalledTimes(1);
    expect(observed).toHaveLength(1100);
    expect(new Set(observed.map((event) => event.id)).size).toBe(1100);
    expect(
      observed.every((event) => event.instanceId === policy.instances[0]!.id),
    ).toBe(true);
  });
  it("replays the same normalized final chunk after restart when the source cursor failed", async () => {
    let current = policy,
      fail = true;

    const getPolicy = vi.fn(() => structuredClone(current));

    const observed: GatewayEvent[] = [];

    const { create } = await readerFixture(
      async (events) => {
        observed.push(...events);
      },
      async (...args) => {
        if (fail && args[0].endsWith("eve-cursor.json")) {
          fail = false;
          throw new Error("cursor failed");
        }

        await atomicJson(...args);
      },
      getPolicy,
    );

    const reader = create();
    await reader.start();
    await expect(reader.read()).rejects.toThrow("cursor failed");
    expect(getPolicy).toHaveBeenCalledTimes(1);
    await reader.close();
    current = {
      ...policy,
      instances: [
        { ...policy.instances[0]!, id: "22222222-2222-4222-8222-222222222222" },
      ],
    };
    const restored = create();
    await restored.start();
    await restored.read();
    expect(getPolicy).toHaveBeenCalledTimes(1);
    expect(observed).toHaveLength(2);
    expect(observed[0]).toEqual(observed[1]);
    expect(observed[0]?.instanceId).toBe(policy.instances[0]!.id);
  });
  it.each(["chunk progress", "source cursor"])(
    "uses the stable source receipt when %s fails after batch acknowledgement",
    async (failure) => {
      let buffer: EventBuffer;
      let progressFailure = true;

      const { path, state, create } = await readerFixture(
        async (events, key) => {
          await buffer.append(events, key);
          await buffer.deliver();
        },
        async (...args) => {
          const job = args[1] as { offset?: number };

          if (
            progressFailure &&
            ((failure === "chunk progress" &&
              args[0].endsWith("eve-job.json") &&
              job.offset === 1024) ||
              (failure === "source cursor" &&
                args[0].endsWith("eve-cursor.json")))
          ) {
            progressFailure = false;
            throw new Error("job progress failed");
          }

          await atomicJson(...args);
        },
      );

      await writeFile(
        path,
        Array.from({ length: 1100 }, (_, i) =>
          line
            .replace(',"src_port":50000', "")
            .replace("proof.example", `proof${i}.example`),
        ).join("\n") + "\n",
      );

      const delivered: GatewayEvent[] = [];

      const makeBuffer = () =>
        new EventBuffer(
          {
            stateDirectory: join(state, "buffer"),
            collectorBytes: "1048576",
          } as GatewayConfig,
          async (batch) => {
            delivered.push(...batch.events);

            return batch;
          },
        );

      buffer = makeBuffer();

      try {
        await buffer.start();
        const reader = create();
        await reader.start();
        await expect(reader.read()).rejects.toThrow("job progress failed");
        await reader.close();
        await buffer.close();
        buffer = makeBuffer();
        await buffer.start();
        const restored = create();
        await restored.start();
        await restored.read();
        expect(delivered).toHaveLength(1100);
        expect(new Set(delivered.map((event) => event.id)).size).toBe(1100);
        expect((await buffer.status()).lostBatches).toBe("0");
      } finally {
        await buffer.close();
      }
    },
  );
});
