import { constants } from "node:fs";
import { mkdir, open, readlink } from "node:fs/promises";
import { join } from "node:path";
import { spawn, spawnSync } from "node:child_process";

// flock operates on the inherited open file description. The parent retains
// that description after flock exits, so its descriptor owns the lifetime lock.
async function ownershipFile(directory: string, scope: string) {
  const namespace = await readlink("/proc/self/ns/net");
  const identity = /^net:\[([0-9]+)\]$/.exec(namespace)?.[1];

  if (!identity)
    throw new Error("Enforcement network namespace is unavailable");
  await mkdir(directory, { recursive: true, mode: 0o750 });

  const file = await open(
    join(directory, `${scope}-${identity}.lock`),
    constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW,
    0o600,
  );

  try {
    const entry = await file.stat();

    if (
      !entry.isFile() ||
      entry.uid !== process.getuid?.() ||
      (entry.mode & 0o077) !== 0 ||
      entry.nlink !== 1
    )
      throw new Error("Enforcement ownership file is not private to its owner");

    return file;
  } catch (error) {
    await file.close();
    throw error;
  }
}

export async function acquireEnforcementOwnership(
  directory = "/run/traffic-policy",
) {
  const file = await ownershipFile(directory, "enforcement");

  try {
    const result = spawnSync(
      "/usr/bin/flock",
      ["--nonblock", "--exclusive", "3"],
      { stdio: ["ignore", "pipe", "pipe", file.fd], timeout: 10000 },
    );

    if (result.error) throw result.error;

    if (result.status === 1)
      throw new Error(
        "Another enforcement service already owns this network namespace",
      );

    if (result.status !== 0)
      throw new Error("Enforcement ownership could not be acquired");

    // Never unlink the lock file: another starter may already have it open.
    return () => file.close();
  } catch (error) {
    await file.close();
    throw error;
  }
}

// This separate lock coordinates guard activation with full policy replacement.
// Waiting asynchronously leaves DNS and enforcement management responsive.
export async function withInstallationLock<T>(
  action: () => Promise<T>,
  directory = "/run/traffic-policy",
): Promise<T> {
  const file = await ownershipFile(directory, "installation");

  try {
    await new Promise<void>((resolve, reject) => {
      const child = spawn(
        "/usr/bin/flock",
        ["--exclusive", "--timeout", "10", "3"],
        { stdio: ["ignore", "ignore", "ignore", file.fd] },
      );

      const timer = setTimeout(() => child.kill("SIGKILL"), 12000);
      child.once("error", reject);
      child.once("close", (code) => {
        clearTimeout(timer);

        if (code === 0) resolve();
        else
          reject(new Error("Firewall installation lock could not be acquired"));
      });
    });

    return await action();
  } finally {
    await file.close();
  }
}
