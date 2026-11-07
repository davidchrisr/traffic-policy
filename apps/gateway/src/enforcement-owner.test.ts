import { afterEach, expect, it } from "vitest";
import { mkdtemp, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { join } from "node:path";
import {
  acquireEnforcementOwnership,
  withInstallationLock,
} from "./enforcement-owner.ts";

const directories: string[] = [];

const held: Array<() => Promise<void>> = [];

afterEach(async () => {
  for (const release of held.splice(0)) await release();

  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
});

async function directory() {
  const path = await mkdtemp(
    join(process.cwd(), ".local/tmp/tests/enforcement-owner-"),
  );

  directories.push(path);

  return path;
}

it("atomically selects one concurrent owner and releases only on descriptor close", async () => {
  const path = await directory();

  const results = await Promise.allSettled([
    acquireEnforcementOwnership(path),
    acquireEnforcementOwnership(path),
  ]);

  for (const result of results)
    if (result.status === "fulfilled") held.push(result.value);

  expect(held).toHaveLength(1);
  expect(results.filter((result) => result.status === "rejected")).toHaveLength(
    1,
  );
  await expect(acquireEnforcementOwnership(path)).rejects.toThrow(
    "Another enforcement service",
  );
  await held.pop()!();
  held.push(await acquireEnforcementOwnership(path));
  expect(await readdir(path)).toHaveLength(1);
});

it("recovers ownership after a process dies without deleting its lock file", async () => {
  const path = await directory();
  const module = new URL("./enforcement-owner.ts", import.meta.url).href;
  const code = `const { acquireEnforcementOwnership } = await import(${JSON.stringify(module)}); const release = await acquireEnforcementOwnership(${JSON.stringify(path)}); console.log('owned'); process.stdin.resume(); process.on('SIGTERM', async () => { await release(); process.exit(0); });`;
  const child = spawn(process.execPath, ["-e", code], { stdio: "pipe" });

  const closed = new Promise<void>((resolve) =>
    child.once("close", () => resolve()),
  );

  try {
    await new Promise<void>((resolve, reject) => {
      child.once("error", reject);
      child.stdout.once("data", () => resolve());
      child.once("exit", () =>
        reject(new Error("Owner exited before acquiring its lock")),
      );
    });
    await expect(acquireEnforcementOwnership(path)).rejects.toThrow(
      "Another enforcement service",
    );
    child.kill("SIGKILL");
    await closed;
    held.push(await acquireEnforcementOwnership(path));
  } finally {
    child.kill("SIGKILL");
    await closed;
  }
});

it("rejects a symbolic link in place of the private ownership file", async () => {
  const path = await directory();
  await (
    await acquireEnforcementOwnership(path)
  )();
  const [name] = await readdir(path);
  await rm(join(path, name!));
  const target = join(path, "other");
  await writeFile(target, "untouched");
  await symlink(target, join(path, name!));
  await expect(acquireEnforcementOwnership(path)).rejects.toMatchObject({
    code: "ELOOP",
  });
});

it("serializes installation independently of lifetime ownership and releases after failure", async () => {
  const path = await directory();
  held.push(await acquireEnforcementOwnership(path));
  let enter!: () => void;
  let release!: () => void;

  const entered = new Promise<void>((resolve) => {
    enter = resolve;
  });

  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });

  let secondEntered = false;

  const first = withInstallationLock(async () => {
    enter();
    await gate;
    throw new Error("Interrupted installation");
  }, path);

  const rejected = expect(first).rejects.toThrow("Interrupted installation");
  await entered;

  const second = withInstallationLock(async () => {
    secondEntered = true;
  }, path);

  try {
    await new Promise<void>((resolve) => setTimeout(resolve, 30));
    expect(secondEntered).toBe(false);
  } finally {
    release();
    await rejected;
    await second;
  }

  expect(secondEntered).toBe(true);
  await expect(acquireEnforcementOwnership(path)).rejects.toThrow(
    "Another enforcement service",
  );
});
