import {
  spawn,
  type ChildProcessWithoutNullStreams,
  type SpawnOptionsWithoutStdio,
} from "node:child_process";
import { networkInterfaces } from "node:os";
import { z } from "zod";
import {
  canonicalIp,
  type Policy,
  type Permission,
} from "@traffic-policy/contracts";
import type { EnforcementResult } from "@traffic-policy/contracts/enforcement";
import {
  compileNftables,
  compileDnsUpdate,
  parseBlockCounter,
  parseUnregisteredCounter,
  TABLE,
  type DnsChain,
  type Infrastructure,
  type MarkAssignments,
} from "@traffic-policy/core/nftables";
import { ServiceError } from "@traffic-policy/core/io";
import { ManagedConnections } from "./managed-connections.ts";
import { withInstallationLock } from "./enforcement-owner.ts";
import type { BlockCounters } from "./block-counters.ts";

export interface FullNativeInput {
  policy: Policy;
  permissions: Permission[];
  now: number;
  policyHash: string;
  existingAllocation: number;
  marks: MarkAssignments;
}

export interface NativeAccess {
  compileFull(input: FullNativeInput): Promise<string>;
  check(program: string): Promise<void>;
  applyFull(program: string): Promise<void>;
  applyDns(changes: DnsChain[], now: number): Promise<void>;
  tablePresent(): Promise<boolean>;
  connections(
    instances: readonly { id: string; addresses: readonly string[] }[],
    maxBytes: number,
  ): Promise<string>;
  // The addresses assigned to the gateway itself, which no instance owns.
  localAddresses(): string[];
}

export type NativeSpawn = (
  binary: string,
  args: string[],
  options: SpawnOptionsWithoutStdio,
) => ChildProcessWithoutNullStreams;

export async function runNativeCommand(
  binary: "/usr/sbin/nft" | "/usr/sbin/conntrack",
  args: string[],
  input?: string,
  spawnProcess: NativeSpawn = spawn,
  selection?: ManagedConnections,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawnProcess(binary, args, {
      stdio: "pipe",
      env: { ...process.env, TZ: "UTC" },
    });

    const output: Buffer[] = [];

    let outputBytes = 0,
      errors = "",
      interrupted = false;

    let outputError: Error | null = null;

    const timer = setTimeout(() => {
      interrupted = true;
      child.kill("SIGKILL");
    }, 10000);

    child.stdout.on("data", (bytes) => {
      if (outputError) return;
      outputBytes += bytes.length;

      if (outputBytes > 64 * 1024 * 1024) {
        interrupted = true;
        child.kill("SIGKILL");
      } else {
        try {
          output.push(selection ? selection.write(bytes) : bytes);
        } catch (error) {
          outputError =
            error instanceof Error ? error : new Error(String(error));
          child.kill("SIGKILL");
        }
      }
    });
    child.stderr.on("data", (bytes) => {
      errors = (errors + bytes.toString()).slice(0, 4096);
    });
    child.stdin.on("error", (error) => {
      interrupted = true;
      errors = (errors + error.message).slice(0, 4096);
      child.kill("SIGKILL");
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timer);

      if (outputError) reject(outputError);
      else if (code !== 0 || interrupted)
        reject(
          new ServiceError(
            503,
            interrupted || code === null
              ? "kernel_operation_uncertain"
              : "kernel_operation_failed",
            `${binary.split("/").at(-1)} failed: ${errors.trim()}`,
          ),
        );
      else {
        try {
          if (selection) output.push(selection.end());
          resolve(Buffer.concat(output).toString("utf8"));
        } catch (error) {
          reject(error);
        }
      }
    });
    child.stdin.end(input);
  });
}

const tablesSchema = z.object({
  nftables: z.array(
    z.object({
      table: z
        .object({
          family: z.string(),
          name: z.string(),
          handle: z.number().int().nonnegative(),
        })
        .optional(),
    }),
  ),
});

// The kernel handle of the managed table. A rebuilt table gets a new handle.
export async function managedTableHandle(): Promise<number | null> {
  const table = tablesSchema
    .parse(
      JSON.parse(
        await runNativeCommand("/usr/sbin/nft", ["-j", "list", "tables"]),
      ),
    )
    .nftables.find(
      (row) => row.table?.family === "inet" && row.table.name === TABLE,
    );

  return table?.table?.handle ?? null;
}

export async function managedTablePresent() {
  return (await managedTableHandle()) !== null;
}

// The parts of `nft -j list counters` that carry a named counter's packets.
const countersSchema = z.object({
  nftables: z.array(
    z.object({
      counter: z
        .object({
          name: z.string(),
          packets: z.number().int().nonnegative(),
        })
        .optional(),
    }),
  ),
});

export type BlockCounter = EnforcementResult<"counters">["counters"][number];

// Block rule counters that dropped anything. A zero counter is left out; the gateway reads a
// missing counter as zero.
export function blockCounters(
  table: number,
  // oxlint-disable-next-line anti-slop/no-unknown-parameters -- countersSchema validates the parsed nft JSON output.
  listing: unknown,
): BlockCounter[] {
  return countersSchema.parse(listing).nftables.flatMap(({ counter }) =>
    counter &&
    counter.packets > 0 &&
    (parseBlockCounter(counter.name) || parseUnregisteredCounter(counter.name))
      ? [
          {
            table: String(table),
            name: counter.name,
            packets: String(counter.packets),
          },
        ]
      : [],
  );
}

export async function listBlockCounters(): Promise<BlockCounter[]> {
  const table = await managedTableHandle();

  if (table === null) return [];

  return blockCounters(
    table,
    JSON.parse(
      await runNativeCommand("/usr/sbin/nft", [
        "-j",
        "list",
        "counters",
        "table",
        "inet",
        TABLE,
      ]),
    ),
  );
}

export const createNativeAccess = (
  dnsPort: number,
  infrastructure: Infrastructure,
  counters: BlockCounters,
): NativeAccess => ({
  compileFull: async (input) =>
    compileNftables(input.policy, input.permissions, {
      tableExists: await managedTablePresent(),
      dnsPort,
      now: input.now,
      policyHash: input.policyHash,
      existingPermissionCount: input.existingAllocation,
      marks: input.marks,
      infrastructure,
    }),
  check: async (program) => {
    await runNativeCommand(
      "/usr/sbin/nft",
      ["--check", "--file", "-"],
      program,
    );
  },
  applyFull: async (program) => {
    await counters.replace(() =>
      withInstallationLock(() =>
        runNativeCommand("/usr/sbin/nft", ["--file", "-"], program),
      ),
    );
  },
  applyDns: async (changes, now) => {
    const program = compileDnsUpdate(changes, now);

    if (program)
      await runNativeCommand("/usr/sbin/nft", ["--file", "-"], program);
  },
  tablePresent: managedTablePresent,
  localAddresses: () => [
    ...new Set(
      Object.values(networkInterfaces()).flatMap((values) =>
        (values ?? []).map((value) => canonicalIp(value.address)),
      ),
    ),
  ],
  connections: (instances, maxBytes) =>
    instances.length
      ? runNativeCommand(
          "/usr/sbin/conntrack",
          ["-L", "-o", "xml"],
          undefined,
          spawn,
          new ManagedConnections(instances, maxBytes),
        )
      : Promise.resolve("<conntrack>\n</conntrack>\n"),
});
