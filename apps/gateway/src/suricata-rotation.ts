import { hasErrorCode, readJson } from "@traffic-policy/core/io";
import { policyCheckpointSchema } from "./policy-journal.ts";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  chown,
  open,
  readdir,
  readFile,
  rename,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { StorageBudget, GATEWAY_RESERVE } from "@traffic-policy/core/storage";

const execute = promisify(execFile);

const unit = "tp-suricata.service";

const directory = "/var/lib/traffic-policy/suricata";

export async function reconcileCapture(
  pressure: boolean,
  prior: {
    restartWhenReady: boolean;
    paused?: boolean;
    running?: boolean;
    reason?: string | null;
    at?: string;
  },
  activeState: string,
  write: (state: {
    paused: boolean;
    restartWhenReady: boolean;
    reason: string | null;
    running: boolean;
    at: string;
  }) => Promise<void>,
  control: (operation: "start" | "stop") => Promise<void>,
) {
  let saved = prior;

  if (pressure && activeState === "active") {
    const intent = {
      paused: true,
      restartWhenReady: true,
      reason: "Suricata capture is paused at the storage limit",
      running: true,
      at: new Date().toISOString(),
    };

    await write(intent);
    saved = intent;
    await control("stop");
  }

  if (!pressure && prior.restartWhenReady) await control("start");

  const next = {
    paused: pressure,
    restartWhenReady:
      pressure && (prior.restartWhenReady || activeState === "active"),
    reason: pressure ? "Suricata capture is paused at the storage limit" : null,
    running: !pressure && (activeState === "active" || prior.restartWhenReady),
    at: new Date().toISOString(),
  };

  const savedAt = Date.parse(saved.at ?? "");
  const now = Date.parse(next.at);

  if (
    saved.paused !== next.paused ||
    saved.restartWhenReady !== next.restartWhenReady ||
    saved.running !== next.running ||
    saved.reason !== next.reason ||
    !Number.isFinite(savedAt) ||
    now < savedAt ||
    now - savedAt >= 5000
  )
    await write(next);
}

async function syncDirectory(path: string) {
  const file = await open(path, "r");

  try {
    await file.sync();
  } finally {
    await file.close();
  }
}

async function writerOpen(path: string, pid: string): Promise<boolean> {
  const source = await stat(path, { bigint: true });

  if (pid === "0") return false;

  if (!/^[1-9][0-9]*$/.test(pid))
    throw new Error("Suricata writer PID is unavailable");
  let descriptors: string[];

  try {
    descriptors = await readdir(`/proc/${pid}/fd`);
  } catch (error) {
    if (hasErrorCode(error, "ENOENT")) return false;
    throw error;
  }

  for (const descriptor of descriptors) {
    try {
      const fd = await stat(`/proc/${pid}/fd/${descriptor}`, { bigint: true });

      if (fd.dev !== source.dev || fd.ino !== source.ino) continue;
      const info = await readFile(`/proc/${pid}/fdinfo/${descriptor}`, "utf8");
      const flags = info.match(/^flags:\s+([0-7]+)$/m)?.[1];

      if (!flags)
        throw new Error("Suricata descriptor access flags are unavailable");

      if ((parseInt(flags, 8) & 3) !== 0) return true;
    } catch (error) {
      if (!hasErrorCode(error, "ENOENT")) throw error;
    }
  }

  return false;
}

const outputs = ["eve.json", "stats.log", "fast.log", "suricata.log"];

const rotateBytes = 8 * 1024 * 1024;

const archive =
  /^(eve\.json|stats\.log|fast\.log|suricata\.log)\.(\d{13})-[a-f0-9-]+\.rotating$/;

export type SuricataWriter = { state: string; pid: string };

export type RotationState = {
  // Whether the enforcement service has an applied policy, whose settings carry the budget.
  ready: boolean;
  // Archives the writer has been asked to release.
  signalled: Set<string>;
  // Archives reported as held for over a minute.
  reported: Set<string>;
  // Whether a rename has not been made durable yet.
  unsynced: boolean;
};

export const rotationState = (): RotationState => ({
  ready: false,
  signalled: new Set(),
  reported: new Set(),
  unsynced: false,
});

const pendingArchives = async (directory: string) =>
  (await readdir(directory)).filter((name) => archive.test(name));

// Renames full outputs, or under storage pressure every non-empty one, and asks
// the writer to reopen. Nothing here waits for a flush, so Suricata switches
// files promptly even while a directory sync is stalled.
export async function archiveOutputs(
  directory: string,
  pressure: boolean,
  writer: SuricataWriter,
  state: RotationState,
  reopen: () => Promise<void>,
  now = Date.now(),
): Promise<void> {
  const pending = await pendingArchives(directory);

  for (const name of outputs) {
    const path = join(directory, name);

    try {
      const file = await stat(path);

      if (!file.isFile())
        throw new Error("Suricata output is not a regular file");

      if (file.size < rotateBytes && !(pressure && file.size > 0)) continue;
      const rotated = `${name}.${now}-${randomUUID()}.rotating`;
      await rename(path, join(directory, rotated));
      state.unsynced = true;
      pending.push(rotated);
    } catch (error) {
      if (!hasErrorCode(error, "ENOENT")) throw error;
    }
  }

  // Signal once per archive; one left by an earlier process is signalled again.
  const unsignalled = pending.filter((name) => !state.signalled.has(name));

  if (!unsignalled.length) return;

  if (writer.state === "active") await reopen();

  for (const name of unsignalled) state.signalled.add(name);
}

// Publishes each archive once its writer has let it go, then makes the renames
// durable. Suricata reopens on its next write after the signal, which an idle
// Suricata may delay by its stats interval, so a held archive waits for a later
// pass. Returns whether no archive is still held.
export async function publishArchives(
  directory: string,
  writer: SuricataWriter,
  state: RotationState,
  holds: (path: string, pid: string) => Promise<boolean>,
  now = Date.now(),
): Promise<boolean> {
  for (const name of await readdir(directory))
    if (
      /^(stats\.log|fast\.log|suricata\.log)\.\d{13}-[a-f0-9-]+\.closed$/.test(
        name,
      )
    )
      await unlink(join(directory, name));

  const reported = new Set<string>();
  let held = 0;

  for (const name of (await pendingArchives(directory)).sort()) {
    const path = join(directory, name);

    // After rename, a replacement process can only open the new canonical
    // files, so only the captured writer can still hold an archive.
    if (await holds(path, writer.pid)) {
      held++;

      if (now - Number(archive.exec(name)![2]) >= 60000) {
        if (!state.reported.has(name))
          console.error(
            JSON.stringify({
              service: "suricata-rotation",
              file: name,
              error: "Suricata writer still holds its rotated output",
            }),
          );
        reported.add(name);
      }

      continue;
    }

    await rename(path, path.replace(/\.rotating$/, ".closed"));
    state.unsynced = true;
  }

  state.reported = reported;
  const remaining = new Set(await pendingArchives(directory));

  for (const name of state.signalled)
    if (!remaining.has(name)) state.signalled.delete(name);

  if (state.unsynced) {
    // A rename made during the sync marks the state again for the next pass.
    state.unsynced = false;
    await syncDirectory(directory);
  }

  return held === 0;
}

async function outputFull(): Promise<boolean> {
  for (const name of outputs) {
    try {
      if ((await stat(join(directory, name))).size >= rotateBytes) return true;
    } catch (error) {
      if (!hasErrorCode(error, "ENOENT")) throw error;
    }
  }

  return false;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// A fast loop renames full outputs every 250 ms. A slow loop handles storage
// pressure, capture state, published archives and the status heartbeat every
// second. Directory syncs stall only the slow loop, so a flush under heavy
// Suricata output cannot hold back a rename. An unexpected failure in either
// exits the process and systemd restarts it, reporting a persistent one as a
// failed service.
export async function runSuricataRotation(): Promise<never> {
  if (process.getuid?.() !== 0)
    throw new Error("Log rotation requires root to verify writer descriptors");

  const state = rotationState();

  const fast = async (): Promise<never> => {
    for (;;) {
      if (state.ready && (await outputFull())) {
        const writer = await writerStatus();
        await archiveOutputs(directory, false, writer, state, () =>
          reopen(writer),
        );
      }

      await sleep(250);
    }
  };

  const slow = async (): Promise<never> => {
    for (;;) {
      await rotateSuricata(state);
      await sleep(1000);
    }
  };

  return Promise.race([fast(), slow()]);
}

async function writerStatus(): Promise<SuricataWriter> {
  const status = (
    await execute("/usr/bin/systemctl", [
      "show",
      unit,
      "--property=ActiveState,MainPID",
    ])
  ).stdout;

  const state = status.match(/^ActiveState=(\S+)$/m)?.[1];
  const pid = status.match(/^MainPID=([0-9]+)$/m)?.[1];

  if (!state || !pid) throw new Error("Suricata service status is unavailable");

  return { state, pid };
}

async function reopen(writer: SuricataWriter): Promise<void> {
  try {
    await execute("/usr/bin/systemctl", [
      "kill",
      "--kill-whom=main",
      "--signal=HUP",
      unit,
    ]);
  } catch (error) {
    // A writer that exited since its status was read holds no archive, and its
    // replacement opens the new canonical files.
    const current = await writerStatus();

    if (current.state === "active" && current.pid === writer.pid) throw error;
  }
}

async function rotateSuricata(state: RotationState): Promise<void> {
  let checkpoint;

  try {
    checkpoint = await readJson(
      "/var/lib/traffic-policy/enforcement/applied.json",
      policyCheckpointSchema,
    );
  } catch (error) {
    // Rotation needs the applied policy's disk budget; wait for the first one.
    if (hasErrorCode(error, "ENOENT")) {
      state.ready = false;

      return;
    }

    throw error;
  }

  state.ready = true;
  const { policy } = checkpoint;

  const budget = new StorageBudget(
    [
      directory,
      "/var/lib/traffic-policy/gateway",
      "/var/lib/traffic-policy/enforcement",
    ],
    BigInt(policy.settings.gatewayDiskBytes),
    GATEWAY_RESERVE,
  );

  const marker = join(directory, "capture-storage.json");
  let prior = { paused: false, restartWhenReady: false };

  try {
    prior = JSON.parse(await readFile(marker, "utf8"));
  } catch (error) {
    if (!hasErrorCode(error, "ENOENT")) throw error;
  }

  const pressure =
    BigInt(budget.status().allocatedBytes) >=
    budget.limit - budget.reserve - 67108864n;

  let writer = await writerStatus();

  const reconcile = () =>
    reconcileCapture(
      pressure,
      prior,
      writer.state,
      (next) => budget.writeJson(marker, next, 0o640),
      async (operation) => {
        await execute("/usr/bin/systemctl", [operation, unit]);
      },
    );

  const controlled = pressure || prior.restartWhenReady;

  if (controlled) {
    await reconcile();
    writer = await writerStatus();
  }

  const current = writer;
  await archiveOutputs(directory, pressure, current, state, () =>
    reopen(current),
  );

  if (
    (await publishArchives(directory, current, state, writerOpen)) &&
    pressure
  ) {
    const placeholder = join(directory, "eve.json");
    await writeFile(placeholder, "", { flag: "a", mode: 0o640 });
    // The unprivileged Suricata owns its directory and must append here later.
    await chown(placeholder, (await stat(directory)).uid, -1);
  }

  if (!controlled) await reconcile();
}
