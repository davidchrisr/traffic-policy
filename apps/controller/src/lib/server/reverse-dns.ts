import { createSocket } from "node:dgram";
import { randomInt, randomUUID } from "node:crypto";
import dnsPacket from "dns-packet";
import ipaddr from "ipaddr.js";
import { canonicalName, canonicalIp } from "@traffic-policy/contracts";
import { ServiceError } from "@traffic-policy/core/io";
import { requireAdmin, store } from "./services.ts";

let active = 0;

export async function reverseLookup(
  actor: string | null,
  instanceId: string,
  address: string,
) {
  requireAdmin(actor);

  const policy = store().desired(),
    resolver = policy.settings.reverseDnsResolver;

  if (!resolver)
    throw new ServiceError(
      409,
      "resolver_not_configured",
      "Configure a reverse DNS resolver in Settings first",
    );
  const instance = policy.instances.find((value) => value.id === instanceId);

  if (!instance?.addresses.includes(address))
    throw new ServiceError(
      400,
      "address_not_registered",
      "Choose an address registered to this instance",
    );

  if (active >= 4)
    throw new ServiceError(
      429,
      "lookup_busy",
      "Reverse DNS lookups are busy. Try again shortly.",
    );
  active++;
  const parsed = ipaddr.process(address);

  const question =
    parsed.kind() === "ipv4"
      ? parsed.toByteArray().reverse().join(".") + ".in-addr.arpa"
      : parsed
          .toByteArray()
          .map((byte) => byte.toString(16).padStart(2, "0"))
          .join("")
          .split("")
          .reverse()
          .join(".") + ".ip6.arpa";

  const id = randomInt(65536),
    at = new Date().toISOString();

  let status = "unavailable",
    hostname: string | null = null,
    expiresAt: string | null = null;

  try {
    const response = await new Promise<ReturnType<typeof dnsPacket.decode>>(
      (resolve, reject) => {
        const socket = createSocket(resolver.includes(":") ? "udp6" : "udp4");
        let settled = false;

        const finish = (
          error?: Error,
          answer?: ReturnType<typeof dnsPacket.decode>,
        ) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          socket.close();

          if (error) reject(error);
          else resolve(answer!);
        };

        const timer = setTimeout(
          () => finish(new Error("Reverse lookup timed out")),
          2000,
        );

        socket.on("error", (error) => finish(error));
        socket.on("message", (bytes, peer) => {
          if (canonicalIp(peer.address) !== resolver || peer.port !== 53)
            return;

          try {
            const answer = dnsPacket.decode(bytes);

            if (answer.id !== id) return;

            if (
              answer.type !== "response" ||
              answer.questions?.length !== 1 ||
              canonicalName(answer.questions[0]!.name) !== question ||
              answer.questions[0]!.type !== "PTR"
            )
              throw new Error(
                "Reverse lookup response does not match its question",
              );

            if ((answer.flags ?? 0) & dnsPacket.TRUNCATED_RESPONSE)
              throw new Error("Reverse lookup response was truncated");
            finish(undefined, answer);
          } catch (error) {
            finish(
              error instanceof Error
                ? error
                : new Error("Reverse lookup response is invalid", {
                    cause: error,
                  }),
            );
          }
        });
        socket.send(
          dnsPacket.encode({
            type: "query",
            id,
            flags: dnsPacket.RECURSION_DESIRED,
            questions: [{ name: question, type: "PTR", class: "IN" }],
          }),
          53,
          resolver,
          (error) => {
            if (error) finish(error);
          },
        );
      },
    );

    const answers = (response.answers ?? []).flatMap((answer) =>
      answer.type === "PTR" &&
      canonicalName(answer.name) === question &&
      "data" in answer &&
      "ttl" in answer
        ? [{ value: canonicalName(String(answer.data)), ttl: answer.ttl ?? 0 }]
        : [],
    );

    const names = [...new Set(answers.map((answer) => answer.value))];

    if ((response.flags ?? 0) & 15 || names.length === 0) status = "not-found";
    else if (names.length > 1) status = "ambiguous";
    else {
      status = "resolved";
      hostname = names[0]!;
      expiresAt = new Date(
        Date.now() + Math.min(...answers.map((answer) => answer.ttl)) * 1000,
      ).toISOString();
    }
  } catch {
    status = "unavailable";
    hostname = null;
    expiresAt = null;
  } finally {
    active--;
  }

  const event = {
    id: randomUUID(),
    observedAt: at,
    type: "metadata" as const,
    source: "gateway" as const,
    instanceId,
    direction: null,
    peerIp: address,
    protocol: 17,
    port: 53,
    sentBytes: "0",
    receivedBytes: "0",
    ruleId: null,
    question,
    details: {
      reverseLookup: true,
      resolver,
      address,
      status,
      hostname,
      expiresAt,
      authoritative: false,
    },
  };

  store().recordLocalObservation(event);

  return { address, status, hostname, expiresAt };
}
