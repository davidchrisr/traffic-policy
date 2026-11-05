import { randomUUID } from "node:crypto";
import { z } from "zod";
import { uint64Schema, type GatewayEvent } from "@traffic-policy/contracts";
import type { EnforcementResult } from "@traffic-policy/contracts/enforcement";
import {
  parseBlockCounter,
  parseUnregisteredCounter,
} from "@traffic-policy/core/nftables";

export const blockedCountStateSchema = z
  .object({
    version: z.literal(1),
    counters: z.record(z.string(), uint64Schema).nullable(),
    condition: z.string().nullable(),
  })
  .strict();

// Counters is null until the first reading, which only sets the baseline because its values
// include packets dropped before counting started.
export type BlockedCountState = z.infer<typeof blockedCountStateSchema>;

export const freshBlockedCountState = (): BlockedCountState => ({
  version: 1,
  counters: null,
  condition: null,
});

// All pages of one enforcement counter reading.
export type BlockCounterReading = Pick<
  EnforcementResult<"counters">,
  "observedAt" | "boot" | "counters"
>;

// Turns a counter reading into blocked_count events: the increase since the previous reading, or
// the whole value of a counter that appeared since then. A counter is identified by boot, table
// handle, and name, so a rebuilt table's counters are new ones. The enforcement service includes the final
// values of a replaced table once, and leaves out zero counters.
export function blockedCounts(
  previous: BlockedCountState["counters"],
  reading: BlockCounterReading,
) {
  const counters: Record<string, string> = {};
  const events: GatewayEvent[] = [];

  for (const counter of reading.counters) {
    const scope = parseBlockCounter(counter.name);
    const unregistered = scope ? null : parseUnregisteredCounter(counter.name);

    if (!scope && !unregistered) continue;
    const identity = `${reading.boot}:${counter.table}:${counter.name}`;

    // A replaced table's final values come before its current ones, and a failed apply leaves the
    // same counter listed twice, so each value counts from the one before it in this reading.
    const before = counters[identity] ?? previous?.[identity];
    counters[identity] = counter.packets;

    if (!previous) continue;
    const packets = BigInt(counter.packets);

    const increase =
      before === undefined || BigInt(before) > packets
        ? packets
        : packets - BigInt(before);

    if (increase === 0n) continue;

    events.push({
      id: randomUUID(),
      observedAt: reading.observedAt,
      type: "blocked_count",
      instanceId: scope?.instanceId ?? null,
      direction: scope?.direction ?? null,
      peerIp: null,
      protocol: null,
      port: null,
      sentBytes: "0",
      receivedBytes: "0",
      ruleId: scope?.ruleId ?? null,
      question: null,
      source: "nftables",
      details: unregistered
        ? { packets: Number(increase), unregistered }
        : { packets: Number(increase) },
    });
  }

  return { events, counters };
}
