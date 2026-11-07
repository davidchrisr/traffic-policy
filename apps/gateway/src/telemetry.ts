import { randomUUID, createHash } from "node:crypto";
import { eventSchema } from "@traffic-policy/contracts";
import { InstanceOwners } from "@traffic-policy/core";
import type {
  GatewayEvent,
  Resolution,
  ResolutionReceipt,
} from "@traffic-policy/contracts";
import type {
  EnforcementResult,
  ObservedInstance,
} from "@traffic-policy/contracts/enforcement";
import type { DnsDenial } from "./dns.ts";
import type { ConnectionSnapshot } from "./connections.ts";
import type { KernelEvent } from "./kernel-events.ts";

type Ownership = Pick<
  EnforcementResult<"connections">,
  "instances" | "gatewayAddresses"
>;

interface Owners {
  find(address: string): ObservedInstance | undefined;
  gateway: ReadonlySet<string>;
}

// One ownership table per connections snapshot, shared by all of its connections. The gateway's own
// addresses belong to no instance, even inside a subnet instance's network.
const snapshotOwners = new WeakMap<Ownership, Owners>();

function ownerMap(policy: Ownership): Owners {
  let owners = snapshotOwners.get(policy);

  if (!owners) {
    const instances = new InstanceOwners(policy.instances);
    const gateway = new Set(policy.gatewayAddresses);

    owners = {
      gateway,
      find: (address) =>
        gateway.has(address) ? undefined : instances.find(address),
    };
    snapshotOwners.set(policy, owners);
  }

  return owners;
}

const blank = (at: string): GatewayEvent => ({
  id: randomUUID(),
  observedAt: at,
  type: "traffic",
  instanceId: null,
  direction: null,
  peerIp: null,
  protocol: null,
  port: null,
  sentBytes: "0",
  receivedBytes: "0",
  ruleId: null,
  question: null,
  source: "conntrack",
  details: {},
});

const uuid = (value: string) =>
  `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;

export function dnsObservation(
  resolution: Resolution,
  confirmation: ResolutionReceipt | null,
): GatewayEvent {
  const details: GatewayEvent["details"] = {
    outcome: confirmation ? "confirmed" : "failed",
    clientIp: resolution.clientIp,
    addresses: resolution.answers
      .filter((answer) => answer.type !== "CNAME")
      .map((answer) => answer.value)
      .join(", "),
    responseAt: resolution.responseAt,
  };

  if (confirmation) {
    details.appliedRevision = confirmation.revision;
    details.policyHash = confirmation.policyHash;
  }

  return {
    ...blank(new Date().toISOString()),
    type: "dns",
    source: "resolver-gate",
    question: resolution.question,
    instanceId: confirmation?.instanceId ?? null,
    details,
  };
}

// dns-packet names types it does not know `UNKNOWN_<n>`. SVCB and HTTPS (RFC 9460) are common
// browser lookups; other unnamed types use the RFC 3597 `TYPE<n>` form.
const unnamedQueryTypes = new Map([
  ["64", "SVCB"],
  ["65", "HTTPS"],
]);

export function queryTypeName(type: string): string {
  const number = /^UNKNOWN_(\d+)$/.exec(type)?.[1];

  return number === undefined
    ? type
    : (unnamedQueryTypes.get(number) ?? `TYPE${number}`);
}

export function dnsDeniedObservation(denial: DnsDenial): GatewayEvent {
  const details: GatewayEvent["details"] = {
    outcome: "policy-denied",
    queryType: queryTypeName(denial.queryType),
    clientIp: denial.clientIp,
    catchall: denial.decision.catchAll,
    appliedRevision: denial.decision.revision,
    policyHash: denial.decision.policyHash,
  };

  return {
    ...blank(denial.observedAt),
    type: "dns",
    source: "resolver-gate",
    instanceId: denial.decision.instanceId,
    question: denial.question,
    ruleId: denial.decision.ruleId,
    details,
  };
}

class TokenBucket {
  private tokens: number;
  private refilled: number;

  constructor(
    private readonly perSecond: number,
    private readonly burst: number,
    now: number,
  ) {
    this.tokens = burst;
    this.refilled = now;
  }
  available(now: number) {
    this.tokens = Math.min(
      this.burst,
      this.tokens + ((now - this.refilled) / 1000) * this.perSecond,
    );
    this.refilled = now;

    return this.tokens >= 1;
  }
  // Unused long enough to hold a whole burst again.
  full(now: number) {
    this.available(now);

    return this.tokens >= this.burst;
  }
  take() {
    this.tokens--;
  }
}

// A recorded name is not recorded again for 60 seconds while the same decision denies it.
const DENIAL_WINDOW_MS = 60_000;

// The most names the rate limits let through in one window: 100 per second plus a burst of 200,
// for catch-all and explicit-Block denials each.
const MAX_RECORDED_NAMES = 12400;

// Rules cannot select a query type, so the lookups of one name share a record. Each client is
// recorded, so a Request lists every host in a subnet that asked.
const denialKey = (instanceId: string, clientIp: string, question: string) =>
  JSON.stringify([instanceId, clientIp, question]);

// Records each client's denied name once per window, so repeated lookups cannot crowd out new
// names. New
// names are limited to 10 per second per instance, bursts of 20, and 100 per second in total,
// bursts of 200, so a client looking up many names cannot fill the delivery buffer or the
// controller's request pool. Catch-all and explicit-Block denials have separate limits, so Blocks
// cannot use up the budget for names that become Requests. A denial under a different decision
// (policy, rule, or catch-all) is a new name. Repeats are dropped; new names the limits leave out
// are counted in `lost`.
export class DnsDenialSampler {
  // Denials of new names the limits left out since the last report.
  lost = 0;
  private readonly totals: Record<"catchAll" | "block", TokenBucket>;
  private readonly buckets = new Map<string, TokenBucket>();
  // Oldest record first.
  private readonly recorded = new Map<
    string,
    { at: number; decision: string; eventId: string }
  >();

  constructor(private readonly now: () => number = () => performance.now()) {
    this.totals = {
      catchAll: new TokenBucket(100, 200, now()),
      block: new TokenBucket(100, 200, now()),
    };
  }
  // The event to record for this denial, or null when it is a repeat or left out.
  sample(denial: DnsDenial): GatewayEvent | null {
    const now = this.now();
    const { instanceId } = denial.decision;

    this.expire(now);

    const key = denialKey(instanceId, denial.clientIp, denial.question);

    const decision = JSON.stringify([
      denial.decision.revision,
      denial.decision.policyHash,
      denial.decision.ruleId,
      denial.decision.catchAll,
    ]);

    if (this.recorded.get(key)?.decision === decision) return null;
    const budget = denial.decision.catchAll ? "catchAll" : "block";
    const total = this.totals[budget];
    const bucketKey = `${budget} ${instanceId}`;
    let bucket = this.buckets.get(bucketKey);

    if (!bucket) {
      bucket = new TokenBucket(10, 20, now);
      this.buckets.set(bucketKey, bucket);
    }

    // Both buckets refill before either is spent, so a full total budget does not drain an
    // instance's share.
    const allowed = bucket.available(now);

    if (!total.available(now) || !allowed) {
      this.lost++;

      return null;
    }

    bucket.take();
    total.take();
    const event = dnsDeniedObservation(denial);

    this.recorded.delete(key);
    this.recorded.set(key, { at: now, decision, eventId: event.id });

    if (this.recorded.size > MAX_RECORDED_NAMES)
      this.recorded.delete(this.recorded.keys().next().value!);

    return event;
  }
  // A recorded denial whose append failed is forgotten, so the name's next denial is recorded.
  forget(event: GatewayEvent) {
    const key = denialKey(
      event.instanceId ?? "",
      String(event.details.clientIp ?? ""),
      event.question ?? "",
    );

    if (this.recorded.get(key)?.eventId === event.id) this.recorded.delete(key);
  }
  // Drops expired names and the buckets of instances idle long enough to hold a whole burst.
  prune() {
    const now = this.now();

    this.expire(now);

    for (const [id, bucket] of this.buckets)
      if (bucket.full(now)) this.buckets.delete(id);
  }
  private expire(now: number) {
    for (const [key, entry] of this.recorded) {
      if (now - entry.at < DENIAL_WINDOW_MS) break;
      this.recorded.delete(key);
    }
  }
}

// The names unregistered clients looked up, which Suricata sees before their packets are
// dropped. Each client's name is kept once per window, and new names have the denial limits: 10 per
// second per client, bursts of 20, and 100 per second in total, bursts of 200. They only label the
// client's registration Request, so names past the limits are dropped uncounted.
export class UnregisteredNameSampler {
  private readonly total: TokenBucket;
  private readonly buckets = new Map<string, TokenBucket>();
  // Oldest record first.
  private readonly recorded = new Map<string, number>();

  constructor(private readonly now: () => number = () => performance.now()) {
    this.total = new TokenBucket(100, 200, now());
  }
  admit(clientIp: string, question: string): boolean {
    const now = this.now();

    for (const [key, at] of this.recorded) {
      if (now - at < DENIAL_WINDOW_MS) break;
      this.recorded.delete(key);
    }

    const key = JSON.stringify([clientIp, question]);

    if (this.recorded.has(key)) return false;
    let bucket = this.buckets.get(clientIp);

    if (!bucket) {
      // Clients idle long enough to hold a whole burst have nothing to remember.
      if (this.buckets.size >= MAX_RECORDED_NAMES / 2)
        for (const [id, value] of this.buckets)
          if (value.full(now)) this.buckets.delete(id);
      bucket = new TokenBucket(10, 20, now);
      this.buckets.set(clientIp, bucket);
    }

    const allowed = bucket.available(now);

    if (!this.total.available(now) || !allowed) return false;
    bucket.take();
    this.total.take();
    this.recorded.set(key, now);

    if (this.recorded.size > MAX_RECORDED_NAMES / 2)
      this.recorded.delete(this.recorded.keys().next().value!);

    return true;
  }
}

// A gateway condition event; callers fill in `details`.
export const emptyEvent = (): GatewayEvent => ({
  id: randomUUID(),
  observedAt: new Date().toISOString(),
  type: "condition",
  instanceId: null,
  direction: null,
  peerIp: null,
  protocol: null,
  port: null,
  sentBytes: "0",
  receivedBytes: "0",
  ruleId: null,
  question: null,
  source: "gateway",
  details: {},
});

// Reports the denials the rate limits left out as one momentary condition. The count is taken off
// only once the event is stored, so a failed append is reported with the next one. A report asked
// for while another is in progress shares it.
export class LostDenialReporter {
  private reporting: Promise<void> | null = null;

  constructor(
    private readonly sampler: DnsDenialSampler,
    private readonly append: (
      details: GatewayEvent["details"],
    ) => Promise<void>,
  ) {}
  report(): Promise<void> {
    return (this.reporting ??= this.send().finally(() => {
      this.reporting = null;
    }));
  }
  // After a report in progress settles, a last one counts what remains.
  async close() {
    await this.reporting?.catch(() => undefined);
    await this.report();
  }
  private async send() {
    this.sampler.prune();
    const count = this.sampler.lost;

    if (!count) return;
    await this.append({
      code: "dns_denials_omitted",
      message:
        "Denied DNS lookups of new names exceeded the recording rate and were not recorded; a name is recorded when a later lookup fits the rate.",
      occurrences: count,
      recovered: true,
    });
    this.sampler.lost -= count;
  }
}

// A traced drop: a Block rule's, attributed to its instance, or an unregistered connection's,
// attributed to the address that started it.
export function blockedObservation(event: KernelEvent): GatewayEvent | null {
  const line = event.record.split("\n")[0]!;

  const header = line.match(
    /^trace id [a-f0-9]+ inet traffic_policy b([46])_([oi])_([a-f0-9]{32})_([a-f0-9]{32})_([0-9]+)_([ct]) packet: (.*)$/,
  );

  const unregistered = header
    ? null
    : line.match(
        /^trace id [a-f0-9]+ inet traffic_policy u_([cu]) packet: (.*)$/,
      );

  if (!header && !unregistered) return null;

  const [, family, side, instanceId, ruleId, revision, catchall] = header ?? [];
  const packet = header?.[7] ?? unregistered![2]!;
  const ip = family === "4" || / ip saddr /.test(` ${packet}`) ? "ip" : "ip6";
  const source = packet.match(new RegExp(`${ip} saddr ([^ ]+)`))?.[1];
  const destination = packet.match(new RegExp(`${ip} daddr ([^ ]+)`))?.[1];

  if (!source || !destination) return null;

  const protocolText = packet.match(
    new RegExp(`${ip} (?:protocol|nexthdr) ([^ ]+)`),
  )?.[1];

  const protocols = new Map<string, number>(
    Object.entries({
      tcp: 6,
      udp: 17,
      icmp: 1,
      "ipv6-icmp": 58,
      icmpv6: 58,
    }),
  );

  const protocol = protocols.get(protocolText ?? "") ?? Number(protocolText);

  if (!Number.isInteger(protocol)) return null;

  if (unregistered) {
    const port = packet.match(/(?:tcp|udp) dport ([0-9]+)/)?.[1];

    return eventSchema.parse({
      ...blank(event.observedAt),
      id: event.id,
      type: "blocked",
      source: "nftables",
      peerIp: destination,
      protocol,
      port: port === undefined ? null : Number(port),
      details: {
        clientIp: source,
        unregistered: unregistered[1] === "c" ? "client" : "upstream",
        sampled: true,
        coverage: "Rate-limited packet traces of unregistered drops",
      },
    });
  }

  const direction = side === "o" ? "outgoing" : "incoming";
  const translated = event.record.split("\ntranslated:")[1];

  const destinationPacket =
    direction === "incoming" ? (translated ?? packet) : packet;

  const port = destinationPacket.match(/(?:tcp|udp) dport ([0-9]+)/)?.[1];

  // The managed end: the initiator of outgoing traffic, or the responder after translation.
  const clientIp =
    direction === "outgoing"
      ? source
      : (destinationPacket.match(new RegExp(`${ip} daddr ([^ ]+)`))?.[1] ??
        destination);

  return eventSchema.parse({
    ...blank(event.observedAt),
    id: event.id,
    type: "blocked",
    source: "nftables",
    instanceId: uuid(instanceId!),
    direction,
    peerIp: direction === "outgoing" ? destination : source,
    protocol,
    port: port === undefined ? null : Number(port),
    ruleId: uuid(ruleId!),
    details: {
      clientIp,
      appliedRevision: revision!,
      catchall: catchall === "c",
      sampled: true,
      coverage: "Rate-limited original-direction packet traces",
    },
  });
}

export class TrafficAccounting {
  private counters = new Map<
    string,
    {
      sent: bigint;
      received: bigint;
      at: number;
      owners: (string | null)[];
    }
  >();
  private completed = new Map<string, number>();
  partial = false;
  fork(): TrafficAccounting {
    const copy = new TrafficAccounting();
    copy.counters = new Map(this.counters);
    copy.completed = new Map(this.completed);
    copy.partial = this.partial;

    return copy;
  }
  // Whether traffic went uncounted since the last call. A loss is reported for the collection cycle
  // it happened in, so the next clean cycle reports recovery.
  takePartial(): boolean {
    const partial = this.partial;

    this.partial = false;

    return partial;
  }
  newConnection(connection: ConnectionSnapshot, policy: Ownership, at: string) {
    const previous = this.counters.get(connection.id);

    if (previous && previous.at >= Date.parse(at)) return;
    this.counters.set(connection.id, {
      sent: 0n,
      received: 0n,
      at: Date.parse(at),
      owners: this.owners(connection, policy).map(
        (instance) => instance?.ownershipId ?? null,
      ),
    });

    if (this.counters.size > 100000) {
      this.counters.delete(this.counters.keys().next().value!);
      this.partial = true;
    }
  }
  observe(
    connection: ConnectionSnapshot,
    policy: Ownership,
    at: string,
    terminal = false,
    recordId?: string,
  ): GatewayEvent[] {
    const owners = this.owners(connection, policy);

    if (!owners.some((instance) => instance !== undefined)) return [];
    const now = Date.parse(at);

    // A connection to the gateway itself has the gateway as its peer, on the port it serves, even
    // when NAT redirected it there.
    const toGateway = ownerMap(policy).gateway.has(connection.flow.responderIp);

    for (const [key, value] of this.completed)
      if (now - value > 10000) this.completed.delete(key);

    if (this.completed.has(connection.id)) return [];

    if (connection.sentBytes === null || connection.receivedBytes === null) {
      this.partial = true;

      return [];
    }

    const sent = BigInt(connection.sentBytes),
      received = BigInt(connection.receivedBytes),
      previous = this.counters.get(connection.id);

    if (terminal) {
      this.counters.delete(connection.id);
      this.completed.set(connection.id, now);
    } else
      this.counters.set(connection.id, {
        sent,
        received,
        at: now,
        owners: owners.map((instance) => instance?.ownershipId ?? null),
      });

    if (this.counters.size > 100000) {
      this.counters.delete(this.counters.keys().next().value!);
      this.partial = true;
    }

    if (!previous || sent < previous.sent || received < previous.received) {
      this.partial = true;

      return [];
    }

    const events: GatewayEvent[] = [];

    for (const direction of ["outgoing", "incoming"] as const) {
      const side = direction === "outgoing" ? 0 : 1;
      const instance = owners[side];

      if (!instance) continue;

      if (previous.owners[side] !== instance.ownershipId) {
        this.partial = true;
        continue;
      }

      const outgoing = sent - previous.sent,
        incoming = received - previous.received;

      if (outgoing === 0n && incoming === 0n) continue;

      const identity = recordId
        ? createHash("sha256")
            .update(`${recordId}|${instance.id}|${direction}`)
            .digest("hex")
            .slice(0, 32)
            .split("")
        : null;

      if (identity) {
        identity[12] = "4";
        identity[16] = "8";
      }

      const base = blank(at);

      if (identity) base.id = uuid(identity.join(""));
      events.push({
        ...base,
        instanceId: instance.id,
        direction,
        protocol: connection.flow.protocol,
        peerIp:
          direction === "outgoing"
            ? toGateway
              ? connection.flow.responderIp
              : connection.flow.originalDestinationIp
            : connection.flow.initiatorIp,
        port:
          direction === "outgoing" && !toGateway
            ? connection.flow.originalServicePort
            : connection.flow.responderServicePort,
        sentBytes: (direction === "outgoing" ? outgoing : incoming).toString(),
        receivedBytes: (direction === "outgoing"
          ? incoming
          : outgoing
        ).toString(),
        details: {
          connectionId: connection.id,
          terminal,
          coverage: "Conntrack snapshots and lifecycle events",
          sampleSeconds: Math.max(0, (now - previous.at) / 1000),
        },
      });
    }

    return events;
  }
  private owners(connection: ConnectionSnapshot, policy: Ownership) {
    const addresses = [
      connection.flow.initiatorIp,
      connection.flow.responderIp,
    ];

    const owners = ownerMap(policy);

    return addresses.map((address) => owners.find(address));
  }
}
