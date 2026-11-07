import { hasErrorCode } from "@traffic-policy/core/io";
import { createMachineServer } from "@traffic-policy/core/machine-server";
import { readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { TLSSocket } from "node:tls";
import { z } from "zod";
import { policyTransportSchema, uint64Schema } from "@traffic-policy/contracts";
import type {
  GatewayEvent,
  Resolution,
  ResolutionReceipt,
} from "@traffic-policy/contracts";
import {
  atomicJson,
  readBody,
  readJson,
  ServiceError,
} from "@traffic-policy/core/io";
import { gatewayConfigSchema, type GatewayConfig } from "./config.ts";
import {
  enforcementRequest,
  closeEnforcementConnections,
} from "./enforcement-client.ts";
import { dnsReceiveBuffers, startDnsGate } from "./dns.ts";
import { finishShutdown, PendingWork } from "./shutdown.ts";
import { GatewayPolicy } from "./gateway-policy.ts";
import { readServiceStatus } from "@traffic-policy/core/systemd";
import { parseConnections } from "./connections.ts";
import {
  blockedObservation,
  dnsObservation,
  DnsDenialSampler,
  LostDenialReporter,
  TrafficAccounting,
  emptyEvent,
} from "./telemetry.ts";
import { EveReader } from "./eve.ts";
import { CollectionCommit } from "./collection.ts";
import {
  blockedCounts,
  blockedCountStateSchema,
  freshBlockedCountState,
  type BlockCounterReading,
  type BlockedCountState,
} from "./blocked-counts.ts";

// The enforcement service exempts its configured DNS port, machine link, and upstream resolver from
// managed policy. A mismatch would leave managed clients unable to reach this DNS gate, the
// controller unable to repair policy, or the gateway unable to resolve.
export async function confirmEnforcementConfiguration(
  config: Pick<
    GatewayConfig,
    | "enforcementSocket"
    | "dnsPort"
    | "machinePort"
    | "controllerUrl"
    | "upstreamDns"
  >,
) {
  const configuration = await enforcementRequest(config.enforcementSocket, {
    operation: "configuration",
  });

  const { dnsPort, machinePort, controllerPort, upstreamDns } = configuration;

  if (dnsPort !== config.dnsPort)
    throw new Error(
      `Enforcement dnsPort ${dnsPort} does not match gateway dnsPort ${config.dnsPort}`,
    );

  if (machinePort !== config.machinePort)
    throw new Error(
      `Enforcement machinePort ${machinePort} does not match gateway machinePort ${config.machinePort}`,
    );

  const controller = new URL(config.controllerUrl);
  const port = Number(controller.port || 443);

  if (controllerPort !== port)
    throw new Error(
      `Enforcement controllerPort ${controllerPort} does not match the port of gateway controllerUrl ${controller.origin}`,
    );

  if (
    upstreamDns.address !== config.upstreamDns.address ||
    upstreamDns.port !== config.upstreamDns.port
  )
    throw new Error(
      `Enforcement upstreamDns ${upstreamDns.address}:${upstreamDns.port} does not match gateway upstreamDns ${config.upstreamDns.address}:${config.upstreamDns.port}`,
    );

  return configuration;
}

export async function startGateway(configPath: string): Promise<void> {
  const config = await readJson(configPath, gatewayConfigSchema);

  const {
    owner: policyOwner,
    buffer,
    budget,
  } = await GatewayPolicy.open(config);

  let condition: string | null = null;
  // The gateway's own addresses from the latest connection snapshot, reported to the controller.
  let gatewayAddresses: string[] | null = null;
  let sampling: Promise<void> | null = null;
  let stopping = false;
  const collection = new CollectionCommit((events) => buffer.append(events));
  let accounting = new TrafficAccounting();
  let previousBoot: string | null = null;
  const cursorPath = join(config.stateDirectory, "kernel-cursor.json");

  const cursorSchema = z
    .object({
      epoch: z.string().uuid().nullable(),
      sequence: uint64Schema,
      condition: z.string().nullable(),
    })
    .strict();

  let cursor: z.infer<typeof cursorSchema> = {
    epoch: null,
    sequence: "0",
    condition: null,
  };

  try {
    cursor = await readJson(cursorPath, cursorSchema);
  } catch (error) {
    if (!hasErrorCode(error, "ENOENT")) throw error;
  }

  const countsPath = join(config.stateDirectory, "blocked-counts.json");

  let counts = freshBlockedCountState();

  try {
    counts = await readJson(countsPath, blockedCountStateSchema);
  } catch (error) {
    if (!hasErrorCode(error, "ENOENT")) throw error;
  }

  // Counts are stored in one-minute buckets, so reading more often only costs work.
  let countersReadAt = 0;

  const readBlockCounters = async (): Promise<
    BlockCounterReading & { uncounted: string | null }
  > => {
    let page = await enforcementRequest(config.enforcementSocket, {
      operation: "counters",
      page: null,
    });

    const first = page;
    const counters = [...page.counters];

    while (page.next !== null) {
      page = await enforcementRequest(config.enforcementSocket, {
        operation: "counters",
        page: { reading: first.reading, offset: page.next },
      });
      counters.push(...page.counters);
    }

    return { ...first, counters };
  };

  const collectBlockedCounts = async () => {
    if (Date.now() - countersReadAt < 60000) return;
    countersReadAt = Date.now();

    let events: GatewayEvent[] = [],
      counters = counts.counters,
      failure: string | null = null;

    try {
      const reading = await readBlockCounters();

      ({ events, counters } = blockedCounts(counts.counters, reading));
      failure = reading.uncounted;
    } catch (error) {
      failure =
        error instanceof Error
          ? error.message
          : "Blocked packet counters could not be read";
    }

    if (failure !== counts.condition) {
      const event = emptyEvent();
      event.details = {
        code: "blocked_count_collection",
        message: failure ?? "Blocked packet counters are read again",
        recovered: failure === null,
      };
      events.push(event);
    }

    const state: BlockedCountState = {
      version: 1,
      counters,
      condition: failure,
    };

    // Saved before the counts are appended, so a crash in between loses those counts rather
    // than reporting them twice.
    if (JSON.stringify(state) !== JSON.stringify(counts)) {
      await atomicJson(countsPath, state);
      counts = state;
    }

    if (events.length) await collection.write(events, async () => {});
  };

  try {
    await policyOwner.health();
  } catch (error) {
    condition =
      error instanceof Error ? error.message : "Gateway is not initialized";
  }

  // The gateway's addresses for Suricata: its listeners, and every address the enforcement service
  // last reported.
  const listeners = [config.listenAddress, ...config.dnsListenAddresses];
  const suricataGateway = new Set(listeners);

  const suricata = new EveReader(
    config.suricataFile,
    config.stateDirectory,
    config.gatewayId,
    () => policyOwner.confirmedView(),
    (events, key, signal) => buffer.appendSource(events, key, signal),
    suricataGateway,
    budget.writeJson,
    budget,
  );

  await suricata.start();

  const recordDns = async (
    resolution: Resolution,
    confirmation: ResolutionReceipt | null,
  ) => {
    await buffer.appendDns(dnsObservation(resolution, confirmation));
  };

  const enforcement = await confirmEnforcementConfiguration(config);

  const denials = new DnsDenialSampler();

  const lostDenials = new LostDenialReporter(denials, (details) =>
    buffer.append([{ ...emptyEvent(), details }]),
  );

  // Every DNS listener's receive buffer; a cap below the configured size stays in status until a
  // restart receives the full size.
  const receiveBuffers = dnsReceiveBuffers(config.dnsReceiveBufferBytes);

  const stopDns = await startDnsGate(
    config,
    recordDns,
    (clientIp, question) => policyOwner.admitDns(clientIp, question),
    async (denial) => {
      const event = denials.sample(denial);

      if (!event) return;

      try {
        await buffer.appendDns(event);
      } catch (error) {
        denials.forget(event);
        throw error;
      }
    },
    undefined,
    undefined,
    receiveBuffers.configure,
  );

  const denialTimer = setInterval(() => {
    lostDenials.report().catch((error) => console.error(error));
  }, 10000);

  const [ca, cert, key] = await Promise.all([
    readFile(config.tls.ca),
    readFile(config.tls.certificate),
    readFile(config.tls.key),
  ]);

  const machineWork = new PendingWork();

  const machine = createMachineServer(
    {
      ca,
      cert,
      key,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: "TLSv1.3",
    },
    (request, response) => {
      // oxlint-disable-next-line anti-slop/no-unknown-parameters -- The HTTP serializer writes endpoint-specific results already constructed or parsed by each handler.
      const respond = (status: number, value: unknown) => {
        if (response.destroyed) return;
        response.writeHead(status, {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        });
        response.end(JSON.stringify(value));
      };

      machineWork.track(
        (async () => {
          if (!(request.socket instanceof TLSSocket))
            throw new ServiceError(
              403,
              "unauthorized_identity",
              "Machine connection requires TLS",
            );
          const peer = request.socket.getPeerCertificate();

          if (peer.subject?.CN !== config.controllerIdentity)
            throw new ServiceError(
              403,
              "unauthorized_identity",
              "Machine identity is not authorized",
            );

          if (request.method === "GET" && request.url === "/v1/services") {
            respond(200, await readServiceStatus("gateway"));

            return;
          }

          if (request.method === "GET" && request.url === "/v1/status") {
            const status = await policyOwner.health();
            respond(200, {
              ...status,
              ...(gatewayAddresses && {
                endpoint: { ...enforcement, addresses: gatewayAddresses },
              }),
              collector: buffer.status(),
              condition,
              dnsCondition: receiveBuffers.condition,
              suricataCondition: await (async () => {
                try {
                  const capture = JSON.parse(
                    await readFile(
                      join(
                        dirname(config.suricataFile),
                        "capture-storage.json",
                      ),
                      "utf8",
                    ),
                  );

                  if (
                    !capture.at ||
                    Date.now() - Date.parse(capture.at) > 15000
                  )
                    return "Suricata status has not been updated";

                  if (!capture.running && !capture.paused)
                    return "Suricata capture is not running";

                  return capture.paused
                    ? String(capture.reason)
                    : suricata.condition;
                } catch (error) {
                  if (!hasErrorCode(error, "ENOENT")) throw error;

                  return suricata.condition;
                }
              })(),
              storage: budget.status(),
            });

            return;
          }

          if (request.method === "PUT" && request.url === "/v1/policy") {
            const policy = policyTransportSchema.parse(await readBody(request));
            const receipt = await policyOwner.apply(policy);
            await policyOwner.health();
            condition = null;
            respond(200, receipt);

            return;
          }

          throw new ServiceError(
            404,
            "not_found",
            "Machine endpoint does not exist",
          );
        })().catch((error) =>
          respond(
            error instanceof ServiceError
              ? error.status
              : error instanceof z.ZodError
                ? 400
                : 503,
            {
              code:
                error instanceof ServiceError
                  ? error.code
                  : "gateway_unavailable",
              message: error.message,
            },
          ),
        ),
      );
    },
  );

  const server = machine.server;
  server.maxConnections = 32;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.machinePort, config.listenAddress, resolve);
  });

  const collect = async () => {
    try {
      await collection.retry();

      // Capture lost before this start is recorded once and marked recovered, since capture is
      // running again; the notice clears only after both events are appended.
      const notice = buffer.interruptionNotice();

      if (notice) {
        const lost = emptyEvent();
        lost.details = {
          code: "collector_coverage",
          message: notice,
          recovered: false,
        };

        const resumed = emptyEvent();
        resumed.details = {
          code: "collector_coverage",
          message: "Collector capture resumed",
          recovered: true,
        };

        await collection.write([lost, resumed], () =>
          buffer.clearInterruptionNotice(notice),
        );
      }

      // Collection needs the last confirmed policy for ownership/provenance.
      await policyOwner.collection();

      for (let batch = 0; batch < 8; batch++) {
        const collected = await enforcementRequest(config.enforcementSocket, {
          operation: "events",
          epoch: cursor.epoch,
          after: cursor.sequence,
        });

        const events: GatewayEvent[] = [];

        const nextAccounting = collected.reset
          ? new TrafficAccounting()
          : accounting.fork();

        const kernelCondition =
          collected.condition ??
          (collected.gap || (collected.reset && cursor.epoch !== null)
            ? "Kernel observations were lost or their collection restarted"
            : null);

        if (kernelCondition) nextAccounting.partial = true;

        if (kernelCondition !== cursor.condition) {
          nextAccounting.partial = true;
          const event = emptyEvent();
          event.details = {
            code: "kernel_collection_gap",
            message: kernelCondition ?? "Kernel observation stream recovered",
            recovered: kernelCondition === null,
            epoch: collected.epoch,
          };
          events.push(event);
        }

        for (const record of collected.events) {
          if (record.kind === "gap") continue;

          if (record.kind === "trace") {
            const event = blockedObservation(record);

            if (event) events.push(event);
          } else {
            const connection = parseConnections(
              "<conntrack>" + record.record + "</conntrack>",
            )[0];

            if (!connection) continue;

            if (record.kind === "new")
              nextAccounting.newConnection(
                connection,
                {
                  instances: record.instances,
                  gatewayAddresses: collected.gatewayAddresses,
                },
                record.observedAt,
              );
            else
              events.push(
                ...nextAccounting.observe(
                  connection,
                  {
                    instances: record.instances,
                    gatewayAddresses: collected.gatewayAddresses,
                  },
                  record.observedAt,
                  true,
                  record.id,
                ),
              );
          }
        }

        const nextCursor = {
          epoch: collected.epoch,
          sequence: collected.sequence,
          condition: kernelCondition,
        };

        await collection.write(events, async () => {
          await atomicJson(cursorPath, nextCursor);
          cursor = nextCursor;
          accounting = nextAccounting;
        });

        if (collected.events.length < 128) break;
      }

      await collectBlockedCounts();

      const snapshot = await enforcementRequest(config.enforcementSocket, {
        operation: "connections",
      });

      gatewayAddresses = snapshot.gatewayAddresses;
      suricataGateway.clear();

      for (const address of [...listeners, ...gatewayAddresses])
        suricataGateway.add(address);

      const nextAccounting = accounting.fork();

      if (snapshot.bootId !== previousBoot) nextAccounting.partial = true;

      const events = parseConnections(snapshot.xml).flatMap((connection) =>
        nextAccounting.observe(connection, snapshot, snapshot.observedAt),
      );

      const nextCondition = nextAccounting.takePartial()
        ? "Some connection traffic was not counted: connections open before counting started, missing counters, or lost kernel events"
        : null;

      if (condition !== nextCondition) {
        const event = emptyEvent();
        event.details = {
          code: "traffic_coverage_partial",
          message: nextCondition ?? "Connection collection recovered",
          recovered: nextCondition === null,
        };
        events.push(event);
      }

      await collection.write(events, async () => {
        accounting = nextAccounting;
        previousBoot = snapshot.bootId;
        condition = nextCondition;
      });
    } catch (error) {
      condition =
        error instanceof Error ? error.message : "Traffic collection failed";
    }
  };

  const sample = () => {
    if (sampling || stopping) return;
    sampling = collect().finally(() => {
      sampling = null;
    });
  };

  const timer = setInterval(() => {
    void sample();
  }, 5000);

  void sample();

  const shutdown = () => {
    if (stopping) return;
    stopping = true;
    clearInterval(timer);
    clearInterval(denialTimer);
    void finishShutdown([
      [stopDns, machine.close, () => machineWork.drain()],
      [
        async () => {
          await sampling;
        },
        () => lostDenials.close(),
      ],
      [
        async () => {
          await suricata.close();
        },
      ],
      [() => buffer.close()],
      [() => closeEnforcementConnections(config.enforcementSocket)],
    ])
      .then(() => process.exit(0))
      .catch((error) => {
        console.error(error);
        process.exit(1);
      });
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
  console.log(
    JSON.stringify({
      service: "gateway",
      ready: true,
      gatewayId: config.gatewayId,
    }),
  );
}

if (process.argv[1]?.endsWith("gateway.mjs")) {
  const config = process.argv[2];

  if (!config) throw new Error("Gateway configuration path is required");
  await startGateway(config);
}
