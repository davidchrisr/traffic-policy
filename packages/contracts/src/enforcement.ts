import { z } from "zod";
import {
  policyTransportSchema,
  resolutionSchema,
  gatewayReceiptSchema,
  resolutionReceiptSchema,
  instanceSchema,
  instantSchema,
  uint64Schema,
  dnsDecisionSchema,
  ipSchema,
} from "./index.ts";

const identity = { id: z.string().uuid() };

// Counter entries per enforcement response; 4,096 entries stay well inside one machine frame.
export const COUNTER_PAGE_SIZE = 4096;

export const enforcementCommandSchema = z.discriminatedUnion("operation", [
  z
    .object({
      ...identity,
      operation: z.literal("apply"),
      policy: policyTransportSchema,
    })
    .strict(),
  z
    .object({
      ...identity,
      operation: z.literal("prepare"),
      policy: policyTransportSchema,
    })
    .strict(),
  z
    .object({
      ...identity,
      operation: z.literal("resolve"),
      resolution: resolutionSchema,
    })
    .strict(),
  z.object({ ...identity, operation: z.literal("status") }).strict(),
  z.object({ ...identity, operation: z.literal("collection") }).strict(),
  z.object({ ...identity, operation: z.literal("configuration") }).strict(),
  z.object({ ...identity, operation: z.literal("connections") }).strict(),
  z
    .object({
      ...identity,
      operation: z.literal("counters"),
      // Null starts a new reading; later pages of the same reading follow its next offset.
      page: z
        .object({
          reading: z.string().uuid(),
          offset: z.number().int().positive(),
        })
        .strict()
        .nullable(),
    })
    .strict(),
  z
    .object({
      ...identity,
      operation: z.literal("events"),
      epoch: z.string().uuid().nullable(),
      after: uint64Schema,
    })
    .strict(),
]);

const policyState = z
  .object({
    policy: policyTransportSchema,
    receipt: gatewayReceiptSchema,
    permissions: z.number().int().nonnegative(),
    resolutions: z.number().int().nonnegative(),
  })
  .strict();

export const observedInstanceSchema = instanceSchema.safeExtend({
  ownershipId: z.string().uuid(),
});

export type ObservedInstance = z.infer<typeof observedInstanceSchema>;

// A DNS admission decision under one applied policy.
export const dnsAdmissionSchema = dnsDecisionSchema.extend({
  instanceId: z.string().uuid(),
  revision: uint64Schema,
  policyHash: z.string().regex(/^[a-f0-9]{64}$/),
});

export type DnsAdmission = z.infer<typeof dnsAdmissionSchema>;

export const enforcementResultSchemas = {
  prepare: z
    .object({
      revision: uint64Schema,
      policyHash: z.string().regex(/^[a-f0-9]{64}$/),
    })
    .strict(),
  apply: gatewayReceiptSchema,
  // A lookup that the enforcement service's policy denies returns that decision instead of a receipt.
  resolve: z.union([
    resolutionReceiptSchema,
    dnsAdmissionSchema.extend({ allowed: z.literal(false) }),
  ]),
  status: policyState,
  collection: policyState,
  configuration: z
    .object({
      dnsPort: z.number().int().min(1024).max(65535),
      machinePort: z.number().int().min(1024).max(65535),
      controllerPort: z.number().int().min(1).max(65535),
      controllerAddresses: z.array(ipSchema).min(1).max(8),
      upstreamDns: z
        .object({
          address: ipSchema,
          port: z.number().int().min(1).max(65535),
        })
        .strict(),
    })
    .strict(),
  connections: z.object({
    bootId: z.string().uuid(),
    revision: uint64Schema,
    policyHash: z.string().regex(/^[a-f0-9]{64}$/),
    instances: z.array(observedInstanceSchema),
    // The gateway's own addresses when observed; no instance owns them.
    gatewayAddresses: z.array(ipSchema).max(1024),
    observedAt: instantSchema,
    xml: z.string(),
  }),
  // One page of the non-zero Block rule counters, including the final values of counters that
  // a policy apply removed since the previous reading. The boot and table handle identify one run
  // of a counter from zero. uncounted explains drops that could not be read before an apply.
  counters: z
    .object({
      reading: z.string().uuid(),
      observedAt: instantSchema,
      boot: z.string().min(1).max(64),
      counters: z
        .array(
          z
            .object({
              table: z.string().regex(/^[0-9]{1,20}$/),
              name: z.string().min(1).max(128),
              packets: uint64Schema,
            })
            .strict(),
        )
        .max(COUNTER_PAGE_SIZE),
      next: z.number().int().positive().nullable(),
      uncounted: z.string().max(1024).nullable(),
    })
    .strict(),
  events: z.object({
    epoch: z.string().uuid(),
    sequence: uint64Schema,
    events: z.array(
      z.object({
        id: z.string().uuid(),
        sequence: uint64Schema,
        observedAt: instantSchema,
        kind: z.enum(["new", "destroy", "trace", "gap"]),
        record: z.string(),
        instances: z.array(observedInstanceSchema),
      }),
    ),
    reset: z.boolean(),
    gap: z.boolean(),
    condition: z.string().nullable(),
    // The gateway's own addresses when read; no instance owns them.
    gatewayAddresses: z.array(ipSchema).max(1024),
  }),
};

export const enforcementResponseSchema = z.discriminatedUnion("ok", [
  z.object({ ...identity, ok: z.literal(true), value: z.unknown() }).strict(),
  z
    .object({
      ...identity,
      ok: z.literal(false),
      status: z.number().int().min(400).max(599),
      code: z.string().min(1).max(64),
      message: z.string(),
    })
    .strict(),
]);

export type EnforcementCommand = z.infer<typeof enforcementCommandSchema>;

export type EnforcementOperation = EnforcementCommand["operation"];

export type EnforcementRequest = {
  [O in EnforcementOperation]: Omit<
    Extract<EnforcementCommand, { operation: O }>,
    "id"
  >;
}[EnforcementOperation];

export type EnforcementResult<
  O extends EnforcementOperation = EnforcementOperation,
> = z.output<(typeof enforcementResultSchemas)[O]>;

export type EnforcementHealth = EnforcementResult<"status">;

export type EnforcementCollection = EnforcementResult<"collection">;

export function parseEnforcementResult<O extends EnforcementOperation>(
  operation: O,
  // oxlint-disable-next-line anti-slop/no-unknown-parameters -- Operation-specific schemas validate raw JSON returned across the enforcement service process boundary.
  value: unknown,
): EnforcementResult<O> {
  // SAFETY: This exact operation's schema validated the value; the assertion retains the operation/output correlation lost by generic indexed access.
  return enforcementResultSchemas[operation].parse(
    value,
  ) as EnforcementResult<O>;
}
