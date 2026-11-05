import { expect, it } from "vitest";
import type { GatewayEvent } from "@traffic-policy/contracts";
import { CollectionCommit } from "./collection.ts";

it("retries a failed chunk with the same identities before committing the accounting baseline", async () => {
  const events = Array.from(
    { length: 300 },
    (_, index) => ({ id: String(index) }) as GatewayEvent,
  );

  const saved: string[][] = [];

  let fail = true,
    committed = false;

  const job = new CollectionCommit(async (chunk) => {
    if (saved.length === 1 && fail) {
      fail = false;
      throw new Error("disk write failed");
    }

    saved.push(chunk.map((event) => event.id));
  });

  await expect(
    job.write(events, async () => {
      committed = true;
    }),
  ).rejects.toThrow("disk write failed");
  expect(committed).toBe(false);
  await job.retry();
  expect(saved.flat()).toEqual(events.map((event) => event.id));
  expect(committed).toBe(true);
});

it("retries only the source checkpoint after all batches are already persisted", async () => {
  let writes = 0,
    commits = 0;

  const job = new CollectionCommit(async () => {
    writes++;
  });

  await expect(
    job.write([{ id: "fixture" } as GatewayEvent], async () => {
      if (++commits === 1) throw new Error("checkpoint write failed");
    }),
  ).rejects.toThrow("checkpoint write failed");
  await job.retry();
  expect(writes).toBe(1);
  expect(commits).toBe(2);
});
