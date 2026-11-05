import { afterEach, expect, it, vi } from "vitest";
import {
  mkdtempSync,
  readdirSync,
  rmSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import {
  archiveOutputs,
  publishArchives,
  reconcileCapture,
  rotationState,
} from "./suricata-rotation.ts";

const directories: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();

  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true });
});

function suricataDirectory() {
  const directory = mkdtempSync(
    join(process.cwd(), ".tmp/tests/suricata-rotation-"),
  );

  directories.push(directory);

  return directory;
}

const active = { state: "active", pid: "4242" };

it("retains restart intent across a stop failure and resumes an inactive Suricata service", async () => {
  let state = { restartWhenReady: false };

  const write = async (next: typeof state) => {
    state = next;
  };

  const stop = vi.fn(async () => {
    expect(state.restartWhenReady).toBe(true);
    throw new Error("interrupted stop");
  });

  await expect(
    reconcileCapture(true, state, "active", write, stop),
  ).rejects.toThrow("interrupted stop");
  const control = vi.fn(async () => {});
  await reconcileCapture(false, state, "inactive", write, control);
  expect(control).toHaveBeenCalledWith("start");
  expect(state.restartWhenReady).toBe(false);
});

it("does not stop capture if the restart intent cannot be saved", async () => {
  const control = vi.fn(async () => {});
  await expect(
    reconcileCapture(
      true,
      { restartWhenReady: false },
      "active",
      async () => {
        throw new Error("write failed");
      },
      control,
    ),
  ).rejects.toThrow("write failed");
  expect(control).not.toHaveBeenCalled();
});

it("coalesces unchanged capture writes while keeping the status heartbeat fresh", async () => {
  let state: Parameters<typeof reconcileCapture>[1] = {
    paused: false,
    restartWhenReady: false,
    running: true,
    reason: null,
    at: new Date().toISOString(),
  };

  const write = vi.fn(async (next: typeof state) => {
    state = next;
  });

  const control = vi.fn(async () => {});
  await reconcileCapture(false, state, "active", write, control);
  await reconcileCapture(false, state, "active", write, control);
  expect(write).not.toHaveBeenCalled();
  expect(control).not.toHaveBeenCalled();
  state = { ...state, at: new Date(Date.now() - 6000).toISOString() };
  await reconcileCapture(false, state, "active", write, control);
  expect(write).toHaveBeenCalledTimes(1);
  await reconcileCapture(false, state, "inactive", write, control);
  expect(write).toHaveBeenCalledTimes(2);
  expect(state.running).toBe(false);
});

it("publishes an archive on a later pass once the writer lets it go", async () => {
  const directory = suricataDirectory();
  writeFileSync(join(directory, "eve.json"), "");
  truncateSync(join(directory, "eve.json"), 8 * 1024 * 1024);
  const state = rotationState();
  const reopen = vi.fn(async () => {});
  let holding = true;
  const holds = vi.fn(async () => holding);

  await archiveOutputs(directory, false, active, state, reopen);
  expect(readdirSync(directory)).toEqual([
    expect.stringMatching(/^eve\.json\.\d{13}-[a-f0-9-]+\.rotating$/),
  ]);
  expect(reopen).toHaveBeenCalledTimes(1);
  expect(state.unsynced).toBe(true);

  await expect(publishArchives(directory, active, state, holds)).resolves.toBe(
    false,
  );
  expect(holds).toHaveBeenCalledWith(expect.any(String), "4242");
  expect(state.unsynced).toBe(false);

  await archiveOutputs(directory, false, active, state, reopen);
  expect(reopen).toHaveBeenCalledTimes(1);

  holding = false;
  await expect(publishArchives(directory, active, state, holds)).resolves.toBe(
    true,
  );
  expect(readdirSync(directory)).toEqual([
    expect.stringMatching(/^eve\.json\.\d{13}-[a-f0-9-]+\.closed$/),
  ]);
  expect(state.signalled.size).toBe(0);
});

it("signals again for an archive left by an earlier process", async () => {
  const directory = suricataDirectory();
  const name = `stats.log.${Date.now()}-${crypto.randomUUID()}.rotating`;
  writeFileSync(join(directory, name), "stats");
  const reopen = vi.fn(async () => {});
  const state = rotationState();

  await archiveOutputs(directory, false, active, state, reopen);
  await archiveOutputs(directory, false, active, state, reopen);

  expect(reopen).toHaveBeenCalledTimes(1);
  expect(readdirSync(directory)).toEqual([name]);
});

it("reports an archive still held after a minute once", async () => {
  const directory = suricataDirectory();
  const renamed = Date.now() - 60000;
  const name = `eve.json.${renamed}-${crypto.randomUUID()}.rotating`;
  writeFileSync(join(directory, name), "{}\n");
  const error = vi.spyOn(console, "error").mockImplementation(() => {});
  const state = rotationState();
  const holds = async () => true;

  await publishArchives(directory, active, state, holds, renamed + 59999);
  expect(error).not.toHaveBeenCalled();
  await publishArchives(directory, active, state, holds, renamed + 60000);
  await publishArchives(directory, active, state, holds, renamed + 61000);
  expect(error).toHaveBeenCalledTimes(1);
  expect(error.mock.calls[0]![0]).toContain(name);
});

it("archives only non-empty outputs under storage pressure", async () => {
  const directory = suricataDirectory();
  writeFileSync(join(directory, "eve.json"), "");
  writeFileSync(join(directory, "stats.log"), "stats");
  const stopped = { state: "inactive", pid: "0" };
  const state = rotationState();
  const reopen = vi.fn(async () => {});

  await archiveOutputs(directory, true, stopped, state, reopen);
  await expect(
    publishArchives(directory, stopped, state, async () => false),
  ).resolves.toBe(true);

  expect(reopen).not.toHaveBeenCalled();
  expect(readdirSync(directory).sort()).toEqual([
    "eve.json",
    expect.stringMatching(/^stats\.log\.\d{13}-[a-f0-9-]+\.closed$/),
  ]);
});
