import { hasErrorCode } from "./io.server.ts";
import { lstatSync, readdirSync, statfsSync } from "node:fs";
import { dirname, join } from "node:path";
import { atomicJson, ServiceError } from "./io.server.ts";

export const GATEWAY_RESERVE = 256n * 1024n * 1024n;

export const CONTROLLER_RESERVE = 64n * 1024n * 1024n;

export function storageUsage(paths: string[]) {
  let allocated = 0n,
    logical = 0n;

  const visited = new Set<string>();

  const scan = (path: string) => {
    let entry;

    try {
      entry = lstatSync(path, { bigint: true });
    } catch (error) {
      if (hasErrorCode(error, "ENOENT")) return;
      throw error;
    }

    if (entry.isSymbolicLink())
      throw new Error("Storage accounting refuses symbolic links");
    const identity = `${entry.dev}:${entry.ino}`;

    if (visited.has(identity)) return;
    visited.add(identity);
    allocated += entry.blocks * 512n;

    if (entry.isFile()) logical += entry.size;

    if (entry.isDirectory())
      for (const name of readdirSync(path)) scan(join(path, name));
  };

  for (const path of paths) scan(path);

  return {
    allocatedBytes: allocated.toString(),
    logicalBytes: logical.toString(),
  };
}

export class StorageBudget {
  constructor(
    readonly paths: string[],
    public limit: bigint,
    readonly reserve: bigint,
  ) {}
  status() {
    return {
      ...storageUsage(this.paths),
      limitBytes: this.limit.toString(),
      reserveBytes: this.reserve.toString(),
    };
  }
  assertRoom(incoming: bigint, critical = false) {
    const used = BigInt(this.status().allocatedBytes);
    const ceiling = this.limit - (critical ? 0n : this.reserve);

    if (used + incoming > ceiling)
      throw new ServiceError(
        507,
        "storage_limit",
        "Storage limit reached. Increase the limit or free retained data.",
      );

    for (const root of this.paths) {
      let path = root;

      for (;;) {
        try {
          const fs = statfsSync(path, { bigint: true });

          if (fs.bavail * fs.bsize < incoming + (critical ? 0n : this.reserve))
            throw new ServiceError(
              507,
              "disk_full",
              "The filesystem has insufficient free space.",
            );
          break;
        } catch (error) {
          if (!hasErrorCode(error, "ENOENT") || dirname(path) === path)
            throw error;
          path = dirname(path);
        }
      }
    }
  }
  writeJson: typeof atomicJson = async (path, value, mode) => {
    this.assertRoom(
      BigInt(Buffer.byteLength(JSON.stringify(value))) + 8192n,
      true,
    );
    await atomicJson(path, value, mode);
  };
}
