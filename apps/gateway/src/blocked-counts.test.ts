import { describe, expect, it } from "vitest";
import { eventSchema } from "@traffic-policy/contracts";
import { COUNTER_PAGE_SIZE } from "@traffic-policy/contracts/enforcement";
import { BlockCounters } from "./block-counters.ts";
import { blockedCounts } from "./blocked-counts.ts";
import { blockCounters, type BlockCounter } from "./native-access.ts";

const instance = "11111111111141118111111111111111";

const rule = "22222222222242228222222222222222";

const name = `k_o_${instance}_${rule}`;

const at = "2026-10-26T00:00:00.000Z";

const reading = (counters: BlockCounter[]) => ({
  observedAt: at,
  boot: "boot",
  counters,
});

describe("blocked packet counters", () => {
  it("lists the non-zero Block rule counters with their table handle", () => {
    expect(
      blockCounters(9, {
        nftables: [
          { metainfo: { version: "1.1.3" } },
          { counter: { name, packets: 45, bytes: 2700 } },
          { counter: { name: name.replace("_o_", "_i_"), packets: 0 } },
          { counter: { name: "other", packets: 1000 } },
          { counter: { name: "k_u_c", packets: 7 } },
        ],
      }),
    ).toEqual([
      { table: "9", name, packets: "45" },
      { table: "9", name: "k_u_c", packets: "7" },
    ]);
  });
  it("reports unregistered drops by the side they arrived on, without an instance or rule", () => {
    const first = blockedCounts(
      null,
      reading([{ table: "9", name: "k_u_c", packets: "5" }]),
    );

    const next = blockedCounts(
      first.counters,
      reading([
        { table: "9", name: "k_u_c", packets: "8" },
        { table: "9", name: "k_u_u", packets: "2" },
      ]),
    );

    expect(
      next.events
        .map((event) => eventSchema.parse(event))
        .map((event) => [
          event.details.unregistered,
          event.details.packets,
          event.instanceId,
          event.ruleId,
        ]),
    ).toEqual([
      ["client", 3, null, null],
      ["upstream", 2, null, null],
    ]);
    expect(
      eventSchema.safeParse({
        ...next.events[0],
        instanceId: "11111111-1111-4111-8111-111111111111",
      }).success,
    ).toBe(false);
  });

  it("reports increases, takes a rebuilt table's counter whole, and only sets the baseline first", () => {
    const first = blockedCounts(
      null,
      reading([{ table: "9", name, packets: "45" }]),
    );

    expect(first.events).toEqual([]);

    // Table 9's final value arrives once, next to the rebuilt table 10.
    const next = blockedCounts(
      first.counters,
      reading([
        { table: "9", name, packets: "60" },
        { table: "10", name, packets: "3" },
      ]),
    );

    expect(
      next.events.map((event) => [event.details.packets, event.ruleId]),
    ).toEqual([
      [15, "22222222-2222-4222-8222-222222222222"],
      [3, "22222222-2222-4222-8222-222222222222"],
    ]);
    expect(eventSchema.parse(next.events[0])).toMatchObject({
      type: "blocked_count",
      instanceId: "11111111-1111-4111-8111-111111111111",
      direction: "outgoing",
    });
    expect(
      blockedCounts(
        next.counters,
        reading([{ table: "10", name, packets: "3" }]),
      ),
    ).toEqual({ events: [], counters: { [`boot:10:${name}`]: "3" } });
  });

  it("counts a table kept by a failed apply once, though the reading lists it twice", async () => {
    let listed: BlockCounter[] = [{ table: "9", name, packets: "60" }];
    const counters = new BlockCounters("boot", async () => listed);

    await expect(
      counters.replace(async () => {
        throw new Error("rejected");
      }),
    ).rejects.toThrow("rejected");
    listed = [{ table: "9", name, packets: "70" }];

    const result = blockedCounts(
      { [`boot:9:${name}`]: "45" },
      await counters.read(null),
    );

    expect(result.events.map((event) => event.details.packets)).toEqual([
      15, 10,
    ]);
    expect(result.counters).toEqual({ [`boot:9:${name}`]: "70" });
  });
});

describe("enforcement counter readings", () => {
  it("keeps a replaced table's final values for the next reading", async () => {
    let listed: BlockCounter[] = [{ table: "9", name, packets: "60" }];
    const counters = new BlockCounters("boot", async () => listed);

    await counters.replace(async () => {
      listed = [{ table: "10", name, packets: "3" }];
    });

    expect(await counters.read(null)).toMatchObject({
      boot: "boot",
      counters: [
        { table: "9", name, packets: "60" },
        { table: "10", name, packets: "3" },
      ],
      next: null,
      uncounted: null,
    });
    expect((await counters.read(null)).counters).toEqual([
      { table: "10", name, packets: "3" },
    ]);
  });

  it("applies when the final values cannot be read and reports them uncounted", async () => {
    let fail = true;
    let applied = false;

    const counters = new BlockCounters("boot", async () => {
      if (fail) throw new Error("nft failed");

      return [];
    });

    await counters.replace(async () => {
      applied = true;
    });
    fail = false;

    expect(applied).toBe(true);
    expect((await counters.read(null)).uncounted).toBe(
      "Counters could not be read before a policy apply: nft failed",
    );
    expect((await counters.read(null)).uncounted).toBeNull();
  });

  it("pages large readings and rejects a page of a finished reading", async () => {
    const listed = Array.from(
      { length: COUNTER_PAGE_SIZE + 1 },
      (_, index) => ({
        table: "9",
        name,
        packets: String(index + 1),
      }),
    );

    const counters = new BlockCounters("boot", async () => listed);
    const first = await counters.read(null);

    expect(first.counters).toHaveLength(COUNTER_PAGE_SIZE);
    expect(first.next).toBe(COUNTER_PAGE_SIZE);

    const last = await counters.read({
      reading: first.reading,
      offset: COUNTER_PAGE_SIZE,
    });

    expect(last.counters).toEqual([listed.at(-1)]);
    expect(last.next).toBeNull();
    await expect(
      counters.read({ reading: first.reading, offset: COUNTER_PAGE_SIZE }),
    ).rejects.toMatchObject({ code: "counter_reading_expired" });
  });
});
