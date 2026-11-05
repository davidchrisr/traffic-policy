import { z } from "zod";
import { instantSchema, uint64Schema } from "./index.ts";

export const serviceIds = {
  controller: ["controller", "machine"],
  gateway: ["gateway", "enforcement", "suricata", "suricata-rotate"],
} as const;

export const serviceScopeSchema = z.enum(["controller", "gateway"]);

const unitStateSchema = z
  .object({
    loadState: z.string().min(1).max(64),
    activeState: z.string().min(1).max(64),
    subState: z.string().min(1).max(64),
    result: z.string().max(64).nullable(),
    exitStatus: z.number().int().min(0).max(255).nullable(),
    restarts: uint64Schema.nullable(),
  })
  .strict();

export const serviceStateSchema = unitStateSchema.extend({
  id: z.enum([
    "controller",
    "machine",
    "gateway",
    "enforcement",
    "suricata",
    "suricata-rotate",
  ]),
});

export type ServiceState = z.infer<typeof serviceStateSchema>;

export type ServiceId = z.infer<typeof serviceStateSchema>["id"];

export type ServiceScope = z.infer<typeof serviceScopeSchema>;

export const serviceSnapshotSchema = z
  .object({
    scope: serviceScopeSchema,
    checkedAt: instantSchema,
    services: z.array(serviceStateSchema).min(1).max(4),
  })
  .strict()
  .superRefine((value, context) => {
    const expected = new Set<ServiceId>(serviceIds[value.scope]);
    const observed = new Set(value.services.map((service) => service.id));

    if (
      observed.size !== value.services.length ||
      observed.size !== expected.size ||
      value.services.some((service) => !expected.has(service.id))
    )
      context.addIssue({
        code: "custom",
        path: ["services"],
        message: "Service identities do not match the reporting host",
      });
  });

const sourceSchema = z.discriminatedUnion("available", [
  z
    .object({ available: z.literal(true), snapshot: serviceSnapshotSchema })
    .strict(),
  z
    .object({
      available: z.literal(false),
      message: z.string().min(1).max(1024),
    })
    .strict(),
]);

export const servicesSnapshotSchema = z
  .object({
    checkedAt: instantSchema,
    controller: sourceSchema,
    gateway: sourceSchema,
  })
  .strict()
  .superRefine((value, context) => {
    for (const scope of ["controller", "gateway"] as const) {
      const source = value[scope];

      if (source.available && source.snapshot.scope !== scope)
        context.addIssue({
          code: "custom",
          path: [scope],
          message: "Service status belongs to another host",
        });
    }
  });

export type ServiceSnapshot = z.infer<typeof serviceSnapshotSchema>;

export type ServicesSnapshot = z.infer<typeof servicesSnapshotSchema>;
