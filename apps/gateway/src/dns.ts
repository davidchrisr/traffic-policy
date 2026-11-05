import { createSocket, type Socket as DatagramSocket } from "node:dgram";
import { createServer, createConnection, type Server } from "node:net";
import { randomInt } from "node:crypto";
import dnsPacket from "dns-packet";
import {
  canonicalIp,
  canonicalName,
  resolutionSchema,
} from "@traffic-policy/contracts";
import type { Resolution, ResolutionReceipt } from "@traffic-policy/contracts";
import type { DnsAdmission } from "@traffic-policy/contracts/enforcement";
import type { GatewayConfig } from "./config.ts";
import { enforcementRequest } from "./enforcement-client.ts";
import { ServiceError } from "@traffic-policy/core/io";
import {
  DnsFailureDiagnostics,
  type DnsFailureStage,
} from "./dns-diagnostics.ts";
import { finishShutdown, PendingWork } from "./shutdown.ts";
import { UpstreamUdp } from "./dns-upstream.ts";

type Packet = ReturnType<typeof dnsPacket.decode>;

export interface DnsDenial {
  observedAt: string;
  clientIp: string;
  question: string;
  queryType: string;
  decision: DnsAdmission;
}

// Null means the client is not an enrolled instance.
export type AdmitDns = (
  clientIp: string,
  question: string,
) => DnsAdmission | null;

const UPSTREAM_TIMEOUT_MS = 2000;

const DNS_QUERY_LIMIT = 4096;

export const DNS_RECEIVE_BUFFER_BYTES = 8 * 1024 * 1024;

export function configureDnsReceiveBuffer(
  socket: DatagramSocket,
  requestedBytes = DNS_RECEIVE_BUFFER_BYTES,
) {
  socket.setRecvBufferSize(requestedBytes);
  const actual = socket.getRecvBufferSize();

  // The Linux gateway reports twice SO_RCVBUF's requested value.
  if (actual < requestedBytes * 2)
    throw new ServiceError(
      503,
      "dns_receive_buffer_clamped",
      `DNS receive buffer is ${actual} bytes; expected at least ${requestedBytes * 2}. Raise net.core.rmem_max to ${requestedBytes}.`,
    );
}

function dnsRefused(query: Packet): Buffer {
  return dnsPacket.encode({
    type: "response",
    id: query.id,
    flags:
      ((query.flags ?? 0) & dnsPacket.RECURSION_DESIRED) |
      dnsPacket.RECURSION_AVAILABLE |
      5,
    questions: query.questions ?? [],
  });
}

function dnsFailure(query: Packet): Buffer {
  return dnsPacket.encode({
    type: "response",
    id: query.id,
    flags: (query.flags ?? 0) | dnsPacket.RECURSION_AVAILABLE | 2,
    questions: query.questions ?? [],
  });
}

function upstreamTcp(config: GatewayConfig, query: Packet): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const id = randomInt(65536);

    const connection = createConnection({
      host: config.upstreamDns.address,
      port: config.upstreamDns.port,
    });

    let settled = false;

    const timer = setTimeout(
      () =>
        connection.destroy(
          new ServiceError(
            504,
            "upstream_dns_timeout",
            "Upstream DNS timed out",
          ),
        ),
      UPSTREAM_TIMEOUT_MS,
    );

    connection.on("close", () => {
      clearTimeout(timer);

      if (!settled) {
        settled = true;
        reject(new Error("Upstream DNS closed before a complete response"));
      }
    });
    let buffer = Buffer.alloc(0);
    connection.on("error", (error) => {
      clearTimeout(timer);
      settled = true;
      reject(error);
    });
    connection.on("connect", () => {
      const bytes = dnsPacket.encode({ ...query, id });
      const length = Buffer.alloc(2);
      length.writeUInt16BE(bytes.length);
      connection.write(Buffer.concat([length, bytes]));
    });
    connection.on("data", (bytes) => {
      buffer = Buffer.concat([buffer, bytes]);

      if (buffer.length > 65537) {
        connection.destroy(new Error("Upstream DNS response is too large"));

        return;
      }

      if (buffer.length < 2 || buffer.length < buffer.readUInt16BE(0) + 2)
        return;

      try {
        const reply = dnsPacket.decode(
          buffer.subarray(2, buffer.readUInt16BE(0) + 2),
        );

        if (reply.type !== "response" || reply.id !== id)
          throw new Error("Upstream DNS transaction mismatch");
        reply.id = query.id;
        settled = true;
        clearTimeout(timer);
        connection.destroy();
        resolve(dnsPacket.encode(reply));
      } catch (error) {
        connection.destroy();
        reject(error);
      }
    });
  });
}

export async function startDnsGate(
  config: GatewayConfig,
  record: (
    resolution: Resolution,
    confirmation: ResolutionReceipt | null,
  ) => Promise<void>,
  admit: AdmitDns,
  recordDenied: (denial: DnsDenial) => Promise<void>,
  diagnostics = new DnsFailureDiagnostics(),
  observations = new DnsFailureDiagnostics(
    undefined,
    undefined,
    "resolver-observation",
  ),
  configureReceiveBuffer: (
    socket: DatagramSocket,
  ) => void = configureDnsReceiveBuffer,
) {
  let active = 0;
  let stopped = false;
  let drain: Promise<void> | null = null;
  const work = new PendingWork();
  // Retention bounds idle descriptors, not admitted query concurrency.
  const upstream = new UpstreamUdp(config.upstreamDns, 4096);

  const observe = (
    resolution: Resolution,
    confirmation: ResolutionReceipt | null,
  ) => {
    const started = performance.now();
    work.track(
      record(resolution, confirmation).catch((error) =>
        observations.report({
          code:
            error instanceof ServiceError
              ? error.code
              : "observation_persistence_failed",
          stage: "observation",
          totalMs: Math.round(performance.now() - started),
          upstreamMs: null,
          enforcementMs: null,
          responseAgeMs: null,
        }),
      ),
    );
  };

  const deny = (query: Packet, denial: Omit<DnsDenial, "observedAt">) => {
    work.track(
      recordDenied({ observedAt: new Date().toISOString(), ...denial }).catch(
        (error) =>
          observations.report({
            code:
              error instanceof ServiceError
                ? error.code
                : "observation_persistence_failed",
            stage: "observation",
            totalMs: 0,
            upstreamMs: null,
            enforcementMs: null,
            responseAgeMs: null,
          }),
      ),
    );

    return dnsRefused(query);
  };

  const admitted = (clientIp: string, question: string) => {
    const decision = admit(clientIp, question);

    if (!decision)
      throw new ServiceError(
        403,
        "dns_client_not_enrolled",
        "DNS client is not an enrolled instance",
      );

    return decision;
  };

  const handle = async (
    bytes: Buffer,
    clientIp: string,
    transport: "udp" | "tcp",
  ): Promise<Buffer> => {
    const query = dnsPacket.decode(bytes);

    if (
      query.type !== "query" ||
      query.questions?.length !== 1 ||
      bytes.length > 65535 ||
      (query.questions[0]?.class && query.questions[0]?.class !== "IN")
    )
      throw new Error("Invalid DNS query");

    const client = canonicalIp(clientIp);

    const refusal = stopped
      ? "dns_stopped"
      : active >= DNS_QUERY_LIMIT
        ? "dns_query_capacity"
        : null;

    if (refusal) {
      diagnostics.report({
        code: refusal,
        stage: "admission",
        upstreamMs: null,
        enforcementMs: null,
        totalMs: 0,
        responseAgeMs: null,
      });

      return dnsFailure(query);
    }

    const question = query.questions[0]!;
    let name = ".";

    if (question.name && question.name !== ".")
      try {
        name = canonicalName(question.name);

        // The original query goes upstream, so it must ask for the name admission decides. Letter
        // case and a trailing dot do not change a DNS name; UTF-8 labels and spaces do.
        if (name !== question.name.toLowerCase().replace(/\.$/, ""))
          throw new Error("Non-canonical DNS name");
      } catch {
        // A name canonicalName rejects, or one sent in another form, is refused like a denied
        // lookup, without recording a request.
        diagnostics.report({
          code: "dns_invalid_name",
          stage: "admission",
          upstreamMs: null,
          enforcementMs: null,
          totalMs: 0,
          responseAgeMs: null,
        });

        return dnsRefused(query);
      }

    active++;
    let resolution: Resolution | null = null;
    const started = performance.now();
    let stage: DnsFailureStage = "admission";
    let upstreamMs: number | null = null;
    let enforcementStarted: number | null = null;

    try {
      const input = { clientIp: client, question: name };

      const admission = admitted(input.clientIp, input.question);

      if (!admission.allowed)
        return deny(query, {
          ...input,
          queryType: question.type,
          decision: admission,
        });
      stage = "upstream";

      const answerBytes =
        transport === "udp"
          ? await upstream.exchange(query)
          : await upstreamTcp(config, query);

      upstreamMs = Math.round(performance.now() - started);
      stage = "validation";
      const answer = dnsPacket.decode(answerBytes);

      if (
        answer.questions?.length !== 1 ||
        answer.questions[0]!.name.toLowerCase().replace(/\.$/, "") !==
          question.name.toLowerCase().replace(/\.$/, "") ||
        answer.questions[0]!.type !== question.type ||
        (answer.questions[0]!.class ?? "IN") !== (question.class ?? "IN")
      )
        throw new Error("Upstream DNS question mismatch");

      if (
        (answer.flags ?? 0) & (dnsPacket.TRUNCATED_RESPONSE | 15) ||
        !["A", "AAAA"].includes(question.type)
      ) {
        stage = "admission";
        const decision = admitted(input.clientIp, input.question);

        if (!decision.allowed)
          return deny(query, { ...input, queryType: question.type, decision });

        return answerBytes;
      }

      resolution = resolutionSchema.parse({
        clientIp: client,
        question: name,
        responseAt: new Date().toISOString(),
        answers: (answer.answers ?? []).flatMap((entry) => {
          if (
            entry.type === "A" ||
            entry.type === "AAAA" ||
            entry.type === "CNAME"
          ) {
            return [
              {
                owner: entry.name,
                type: entry.type,
                value: String(entry.data),
                ttl: entry.ttl,
              },
            ];
          }

          return [];
        }),
      });

      stage = "enforcement";
      enforcementStarted = performance.now();

      const confirmation = await enforcementRequest(config.enforcementSocket, {
        operation: "resolve",
        resolution,
      });

      // The enforcement service's policy denied the lookup: it may already hold a policy the gateway has not
      // recorded, or a scheduled Block took effect.
      if ("allowed" in confirmation)
        return deny(query, {
          ...input,
          queryType: question.type,
          decision: confirmation,
        });

      observe(resolution, confirmation);

      return answerBytes;
    } catch (error) {
      const finished = performance.now();
      diagnostics.report({
        code: error instanceof ServiceError ? error.code : `${stage}_failure`,
        stage,
        upstreamMs:
          upstreamMs ??
          (stage === "upstream" ? Math.round(finished - started) : null),
        enforcementMs:
          enforcementStarted === null
            ? null
            : Math.round(finished - enforcementStarted),
        totalMs: Math.round(finished - started),
        responseAgeMs: resolution
          ? Date.now() - Date.parse(resolution.responseAt)
          : null,
      });

      if (resolution) observe(resolution, null);

      return dnsFailure(query);
    } finally {
      active--;
    }
  };

  const udpServers: DatagramSocket[] = [];
  const tcpServers: Server[] = [];
  const tcpStops = new Set<() => void>();

  const stop = () => {
    if (drain) return drain;
    stopped = true;

    tcpStops.forEach((stopClient) => stopClient());
    drain = finishShutdown([
      [
        ...tcpServers.map(
          (server) => () =>
            new Promise<void>((resolve, reject) =>
              server.close((error) => (error ? reject(error) : resolve())),
            ),
        ),
        () => work.drain(),
      ],
      [() => diagnostics.close(), () => observations.close()],
      [() => upstream.close()],
      udpServers.map(
        (server) => () => new Promise<void>((resolve) => server.close(resolve)),
      ),
    ]);

    return drain;
  };

  try {
    for (const address of config.dnsListenAddresses) {
      const udp = createSocket(address.includes(":") ? "udp6" : "udp4");
      udp.on("message", (bytes, peer) => {
        if (stopped) return;
        work.track(
          handle(bytes, peer.address, "udp")
            .then(
              (reply) =>
                new Promise<void>((resolve, reject) =>
                  udp.send(reply, peer.port, peer.address, (error) =>
                    error ? reject(error) : resolve(),
                  ),
                ),
            )
            .catch(() => {}),
        );
      });
      udp.on("error", (error) =>
        console.error(
          JSON.stringify({ service: "resolver-gate", error: error.message }),
        ),
      );
      await new Promise<void>((resolve, reject) => {
        udp.once("error", reject);
        udp.bind(config.dnsPort, address, () => {
          udp.off("error", reject);
          resolve();
        });
      });
      udpServers.push(udp);
      configureReceiveBuffer(udp);

      const tcp = createServer((socket) => {
        if (stopped) {
          socket.destroy();

          return;
        }

        socket.setTimeout(5000, () => socket.destroy());

        let buffer = Buffer.alloc(0),
          pending = Promise.resolve(),
          queued = 0;

        const finish = () => socket.end(() => socket.destroy());

        const stop = () => {
          socket.pause();

          if (!queued) finish();
        };

        tcpStops.add(stop);
        socket.once("close", () => tcpStops.delete(stop));

        socket.on("data", (bytes) => {
          if (stopped) return;
          buffer = Buffer.concat([buffer, bytes]);

          if (buffer.length > 131074) {
            socket.destroy();

            return;
          }

          while (
            buffer.length >= 2 &&
            buffer.length >= buffer.readUInt16BE(0) + 2
          ) {
            if (queued >= 8 || buffer.readUInt16BE(0) === 0) {
              socket.destroy();

              return;
            }

            const packet = buffer.subarray(2, buffer.readUInt16BE(0) + 2);
            buffer = buffer.subarray(packet.length + 2);
            queued++;
            socket.setTimeout(0);
            pending = pending
              .then(async () => {
                if (stopped || socket.destroyed) return;

                const reply = await handle(
                  packet,
                  socket.remoteAddress!,
                  "tcp",
                );

                const length = Buffer.alloc(2);
                length.writeUInt16BE(reply.length);
                socket.write(Buffer.concat([length, reply]));
              })
              .catch(() => {
                socket.destroy();
              })
              .finally(() => {
                queued--;

                if (stopped && !queued) finish();
                else if (!queued) socket.setTimeout(5000);
              });
            work.track(pending);
          }
        });
        socket.on("error", () => {});
      });

      tcp.maxConnections = DNS_QUERY_LIMIT;
      await new Promise<void>((resolve, reject) => {
        tcp.once("error", reject);
        tcp.listen(
          { port: config.dnsPort, host: address, backlog: DNS_QUERY_LIMIT },
          () => {
            tcp.off("error", reject);
            resolve();
          },
        );
      });
      tcpServers.push(tcp);
    }

    await upstream.warm();
  } catch (error) {
    await stop();
    throw error;
  }

  return stop;
}
