import { hasErrorCode } from "@traffic-policy/core/io";
import { createConnection } from "node:net";
import { chmod, chown, mkdir, readFile, unlink, lstat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { z } from "zod";
import { ipSchema } from "@traffic-policy/contracts";
import { type EnforcementCommand } from "@traffic-policy/contracts/enforcement";
import { readJson } from "@traffic-policy/core/io";
import { StorageBudget, GATEWAY_RESERVE } from "@traffic-policy/core/storage";
import { createEnforcementTransport } from "./enforcement-transport.ts";
import { PolicyEnforcer } from "./policy-enforcer.ts";
import { FilePolicyJournal } from "./policy-journal.ts";
import { createNativeAccess } from "./native-access.ts";
import { BlockCounters } from "./block-counters.ts";
import { ConnectionMarks, fileMarkStore } from "./connection-marks.ts";
import { KernelEvents } from "./kernel-events.ts";
import { ENFORCEMENT_CONNECTION_LIMIT } from "./enforcement-admission.ts";
import { finishShutdown } from "./shutdown.ts";
import { acquireEnforcementOwnership } from "./enforcement-owner.ts";

const configSchema = z
  .object({
    socketPath: z.string().startsWith("/"),
    stateDirectory: z.string().startsWith("/"),
    groupId: z.number().int().min(1),
    // Must match the gateway's dnsPort; managed clients may always reach it.
    dnsPort: z.number().int().min(1024).max(65535),
    // Interfaces facing upstream networks. Unregistered drops arriving on them are only
    // recorded; drops arriving on any other interface are reported for registration.
    upstreamInterfaces: z
      .array(z.string().regex(/^[a-zA-Z0-9_.-]{1,15}$/))
      .min(1)
      .max(32),
    // Policy never filters the machine link with the controller, so it can always repair a policy:
    // the controller's connections to machinePort and the gateway's to controllerPort. Both must
    // match the gateway's machinePort and controllerUrl.
    controllerAddresses: z.array(ipSchema).min(1).max(8),
    machinePort: z.number().int().min(1024).max(65535),
    controllerPort: z.number().int().min(1).max(65535),
    // Must match the gateway's upstreamDns; policy never filters the gateway's own lookups.
    upstreamDns: z
      .object({ address: ipSchema, port: z.number().int().min(1).max(65535) })
      .strict(),
  })
  .strict();

export async function startEnforcementService(
  configPath: string,
): Promise<void> {
  if (process.platform !== "linux" || process.getuid?.() !== 0)
    throw new Error(
      "Enforcement requires its Linux privileged service context",
    );
  const config = await readJson(configPath, configSchema);
  const releaseOwnership = await acquireEnforcementOwnership();
  let enforcer: PolicyEnforcer | null = null;
  let events: KernelEvents | null = null;
  let transport: ReturnType<typeof createEnforcementTransport> | null = null;
  let cleanup: Promise<void> | null = null;
  let stopping = false;

  const close = () => {
    cleanup ??= (async () => {
      await initialization.catch(() => {});

      try {
        await finishShutdown([
          [
            async () => transport?.close(),
            async () => enforcer?.close(),
            () => events?.close(),
          ],
          [releaseOwnership],
        ]);
      } finally {
        process.off("SIGTERM", shutdown);
        process.off("SIGINT", shutdown);
      }
    })();

    return cleanup;
  };

  const shutdown = () => {
    if (stopping) return;
    stopping = true;
    void close().then(
      () => process.exit(0),
      (error) => {
        console.error(error);
        process.exit(1);
      },
    );
  };

  const initialize = async () => {
    const bootId = (
      await readFile("/proc/sys/kernel/random/boot_id", "utf8")
    ).trim();

    await mkdir(dirname(config.socketPath), { recursive: true, mode: 0o750 });
    await chown(dirname(config.socketPath), 0, config.groupId);

    try {
      const entry = await lstat(config.socketPath);

      if (!entry.isSocket() || entry.uid !== 0)
        throw new Error("Enforcement socket path is occupied by another file");
      await new Promise<void>((resolve, reject) => {
        const probe = createConnection(config.socketPath);
        probe.setTimeout(1000, () => {
          probe.destroy();
          reject(new Error("Existing enforcement socket could not be checked"));
        });
        probe.on("connect", () => {
          probe.destroy();
          reject(new Error("Another enforcement service is already running"));
        });
        probe.on("error", (error: NodeJS.ErrnoException) => {
          if (error.code === "ECONNREFUSED") resolve();
          else reject(error);
        });
      });
      await unlink(config.socketPath);
    } catch (error) {
      if (!hasErrorCode(error, "ENOENT")) throw error;
    }

    await mkdir(config.stateDirectory, { recursive: true, mode: 0o700 });
    const parent = dirname(config.stateDirectory);
    const blockCounters = new BlockCounters(bootId);

    const nativeAccess = createNativeAccess(
      config.dnsPort,
      {
        upstreamInterfaces: config.upstreamInterfaces,
        controllerAddresses: config.controllerAddresses,
        machinePort: config.machinePort,
        controllerPort: config.controllerPort,
        upstreamDns: config.upstreamDns,
      },
      blockCounters,
    );

    const owner = await PolicyEnforcer.open({
      bootId,
      journal: new FilePolicyJournal(config.stateDirectory),
      native: nativeAccess,
      marks: new ConnectionMarks(fileMarkStore(config.stateDirectory)),
      capacity: (bytes, gatewayDiskBytes) =>
        new StorageBudget(
          [
            config.stateDirectory,
            join(parent, "gateway"),
            join(parent, "suricata"),
          ],
          BigInt(gatewayDiskBytes),
          GATEWAY_RESERVE,
        ).assertRoom(bytes, true),
    });

    enforcer = owner;

    const observations = new KernelEvents((addresses) =>
      owner.managedOwners(addresses),
    );

    events = observations;
    observations.start();

    const dispatch = async (input: EnforcementCommand) => {
      switch (input.operation) {
        case "prepare":
          return owner.prepare(input.policy);
        case "apply":
          return owner.apply(input.policy);
        case "resolve":
          return owner.resolve(input.resolution);
        case "status":
          return owner.status();
        case "collection":
          return owner.collection();
        case "events":
          return {
            ...observations.read(input.epoch, input.after),
            gatewayAddresses: nativeAccess.localAddresses(),
          };
        case "configuration":
          return {
            dnsPort: config.dnsPort,
            machinePort: config.machinePort,
            controllerPort: config.controllerPort,
            controllerAddresses: config.controllerAddresses,
            upstreamDns: config.upstreamDns,
          };
        case "connections":
          return owner.connections();
        case "counters":
          return blockCounters.read(input.page);
      }
    };

    const channel = createEnforcementTransport(dispatch);
    transport = channel;
    const server = channel.server;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(
        { path: config.socketPath, backlog: ENFORCEMENT_CONNECTION_LIMIT },
        resolve,
      );
    });
    await chmod(config.socketPath, 0o660);
    await chown(config.socketPath, 0, config.groupId);

    if (process.env.NOTIFY_SOCKET) {
      const notification = spawnSync("/usr/bin/systemd-notify", ["--ready"], {
        encoding: "utf8",
        timeout: 10000,
      });

      if (notification.error) throw notification.error;

      if (notification.status !== 0)
        throw new Error(
          `Enforcement readiness notification failed: ${notification.stderr.trim()}`,
        );
    }

    console.log(JSON.stringify({ service: "enforcement", ready: true }));
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
  const initialization = initialize();

  try {
    await initialization;
  } catch (error) {
    try {
      await close();
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        "Enforcement startup and cleanup failed",
      );
    }

    throw error;
  }
}

if (process.argv[1]?.endsWith("enforcement.mjs")) {
  const path = process.argv[2];

  if (!path) throw new Error("Enforcement configuration path is required");
  await startEnforcementService(path);
}
