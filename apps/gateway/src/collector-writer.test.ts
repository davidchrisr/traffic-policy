import { afterEach, expect, it } from "vitest";
import { Worker } from "node:worker_threads";
import { pathToFileURL } from "node:url";
import {
  mkdtemp,
  mkdir,
  readFile,
  writeFile,
  rm,
  readdir,
  stat,
} from "node:fs/promises";
import { join } from "node:path";
import { StorageBudget } from "@traffic-policy/core/storage";
import { CollectorWriter, collectorWorkerUrl } from "./collector-writer.ts";

const roots: string[] = [];

const writers: CollectorWriter[] = [];

afterEach(async () => {
  for (const writer of writers.splice(0)) await writer.close();

  for (const root of roots.splice(0)) await rm(root, { recursive: true });
});

async function fixture() {
  const scratch = join(process.cwd(), ".local/tmp/tests/collector-worker");
  await mkdir(scratch, { recursive: true });
  const root = await mkdtemp(join(scratch, "case-"));
  roots.push(root);

  return { root, budget: new StorageBudget([root], 1048576n, 0n) };
}

it("persists an owned document atomically and leaves no temporary file", async () => {
  const { root, budget } = await fixture(),
    writer = new CollectorWriter(budget);

  writers.push(writer);

  const value = {
      sequence: "1",
      events: [{ id: "original" }],
      label: "café 漢字 🚦",
    },
    path = join(root, "batch.json");

  const writing = writer.writeJson(path, value);
  value.events[0]!.id = "caller mutation";
  await writing;
  expect(JSON.parse(await readFile(path, "utf8"))).toEqual({
    sequence: "1",
    events: [{ id: "original" }],
    label: "café 漢字 🚦",
  });
  expect((await stat(path)).mode & 0o777).toBe(0o600);
  expect(await readdir(root)).toEqual(["batch.json"]);
});

it("rejects a value without a JSON representation before submission", async () => {
  const { root, budget } = await fixture(),
    writer = new CollectorWriter(budget);

  writers.push(writer);
  await expect(
    writer.writeJson(join(root, "invalid.json"), undefined),
  ).rejects.toThrow();
  expect(await readdir(root)).toHaveLength(0);
  await writer.writeJson(join(root, "valid.json"), { id: 1 });
  expect(JSON.parse(await readFile(join(root, "valid.json"), "utf8"))).toEqual({
    id: 1,
  });
});

it("bounds admission to one write and drains it before closing", async () => {
  const { root, budget } = await fixture(),
    gate = new SharedArrayBuffer(4);

  const source = join(root, "gate.ts");
  await writeFile(
    source,
    'import {workerData} from "node:worker_threads"; Atomics.wait(new Int32Array(workerData.gate),0,0); await import(workerData.entry);',
  );

  const worker = new Worker(pathToFileURL(source), {
      workerData: { gate, entry: collectorWorkerUrl.href },
    }),
    writer = new CollectorWriter(budget, worker);

  writers.push(writer);
  const writing = writer.writeJson(join(root, "first.json"), { id: 1 });

  try {
    await expect(
      writer.writeJson(join(root, "second.json"), { id: 2 }),
    ).rejects.toMatchObject({ code: "collector_writer_busy" });
    let closed = false;

    const closing = writer.close().then(() => {
      closed = true;
    });

    await Promise.resolve();
    expect(closed).toBe(false);
    Atomics.store(new Int32Array(gate), 0, 1);
    Atomics.notify(new Int32Array(gate), 0);
    await writing;
    await closing;
    expect(closed).toBe(true);
    expect(
      JSON.parse(await readFile(join(root, "first.json"), "utf8")),
    ).toEqual({ id: 1 });
    await expect(
      writer.writeJson(join(root, "late.json"), {}),
    ).rejects.toMatchObject({ code: "collector_writer_closed" });
  } finally {
    Atomics.store(new Int32Array(gate), 0, 1);
    Atomics.notify(new Int32Array(gate), 0);
  }
});

it("preserves filesystem error codes and permits a subsequent explicit write", async () => {
  const { root, budget } = await fixture(),
    writer = new CollectorWriter(budget);

  writers.push(writer);
  const blocker = join(root, "blocker");
  await writeFile(blocker, "unchanged");
  await expect(
    writer.writeJson(join(blocker, "data.json"), {}),
  ).rejects.toMatchObject({ code: "EEXIST" });
  expect(await readFile(blocker, "utf8")).toBe("unchanged");
  await writer.writeJson(join(root, "next.json"), { id: 2 });
  expect(JSON.parse(await readFile(join(root, "next.json"), "utf8"))).toEqual({
    id: 2,
  });
});

it("uses the current storage budget before submitting each write", async () => {
  const { root, budget } = await fixture(),
    writer = new CollectorWriter(budget);

  writers.push(writer);
  budget.limit = 1n;
  await expect(
    writer.writeJson(join(root, "limited.json"), {}),
  ).rejects.toMatchObject({ code: "storage_limit" });
  expect(await readdir(root)).toHaveLength(0);
  budget.limit = 1048576n;
  await writer.writeJson(join(root, "limited.json"), {});
  expect(
    JSON.parse(await readFile(join(root, "limited.json"), "utf8")),
  ).toEqual({});
});

it.each(["startup", "active"])(
  "surfaces %s worker failure without restarting or writing on the main thread",
  async (phase) => {
    const { root, budget } = await fixture(),
      source = join(root, "crash.ts");

    await writeFile(
      source,
      phase === "startup"
        ? 'throw new Error("worker fixture failed");'
        : 'import {parentPort} from "node:worker_threads"; parentPort.on("message",()=>{throw new Error("worker fixture failed");});',
    );

    const writer = new CollectorWriter(
      budget,
      new Worker(pathToFileURL(source)),
    );

    writers.push(writer);
    await expect(
      writer.writeJson(join(root, "first.json"), {}),
    ).rejects.toThrow("worker fixture failed");
    await expect(
      writer.writeJson(join(root, "retry.json"), {}),
    ).rejects.toThrow("worker fixture failed");
    expect(await readdir(root)).toEqual(["crash.ts"]);
  },
);

it("rejects a reply for another write identity", async () => {
  const { root, budget } = await fixture(),
    source = join(root, "wrong-id.ts");

  await writeFile(
    source,
    'import {parentPort} from "node:worker_threads"; parentPort.on("message",()=>parentPort.postMessage({kind:"written",id:999}));',
  );
  const writer = new CollectorWriter(budget, new Worker(pathToFileURL(source)));
  writers.push(writer);
  await expect(writer.writeJson(join(root, "first.json"), {})).rejects.toThrow(
    "acknowledgement identity",
  );
  expect(await readdir(root)).toEqual(["wrong-id.ts"]);
});

it("exposes unexpected idle exit before another write is attempted", async () => {
  const { root, budget } = await fixture(),
    source = join(root, "idle-exit.ts");

  await writeFile(source, "process.exit(0);");

  const worker = new Worker(pathToFileURL(source)),
    writer = new CollectorWriter(budget, worker);

  writers.push(writer);
  await new Promise<void>((resolve) => worker.once("exit", () => resolve()));
  expect(writer.error?.message).toContain("exited unexpectedly");
  await expect(writer.writeJson(join(root, "late.json"), {})).rejects.toThrow(
    "exited unexpectedly",
  );
  expect(await readdir(root)).toEqual(["idle-exit.ts"]);
});
