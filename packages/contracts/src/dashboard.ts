import { z } from "zod";
import {
  cidrSchema,
  eventSchema,
  gatewayReceiptSchema,
  instanceSchema,
  instantSchema,
  ipSchema,
  ruleSchema,
  ruleInputSchema,
  nameSchema,
  dnsQuestionNameSchema,
  settingsSchema,
} from "./index.ts";

// Aggregated counters can exceed one Suricata event's uint64 range.
export const counterSchema = z.string().regex(/^(0|[1-9][0-9]*)$/);

export const conditionSchema = z
  .object({
    code: z.string(),
    message: z.string(),
    firstAt: instantSchema,
    lastAt: instantSchema,
    occurrences: counterSchema,
    recoveredAt: instantSchema.nullable(),
  })
  .strict();

export const storageSnapshotSchema = z
  .object({
    allocatedBytes: counterSchema,
    logicalBytes: counterSchema,
    limitBytes: counterSchema,
    reserveBytes: counterSchema,
  })
  .strict();

// The gateway's addresses and the services its fixed accepts admit before any rule: the DNS gate,
// the machine link with the controller, and its own lookups to the upstream resolver.
export const gatewayEndpointSchema = z
  .object({
    addresses: z.array(ipSchema).max(1024),
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
  .strict();

export type GatewayEndpoint = z.infer<typeof gatewayEndpointSchema>;

export const gatewayHealthSchema = z.object({
  receipt: gatewayReceiptSchema,
  endpoint: gatewayEndpointSchema.optional(),
  condition: z.string().nullable().optional(),
  suricataCondition: z.string().nullable().optional(),
  dnsCondition: z.string().nullable().optional(),
  storage: storageSnapshotSchema.optional(),
  collector: z
    .object({
      lostBatches: counterSchema,
      firstLossAt: instantSchema.nullable(),
      lastLossAt: instantSchema.nullable(),
      deliveryError: z.string().nullable().optional(),
      persistenceError: z.string().nullable().optional(),
      coverageCondition: z.string().nullable().optional(),
      committedAt: instantSchema.optional(),
      pendingDnsRecords: z.number().int().min(0).max(16384).optional(),
      pendingDnsBytes: counterSchema.optional(),
      pendingWrites: z.number().int().min(0).optional(),
      writePending: z.boolean().optional(),
      rejectedRecords: counterSchema.optional(),
      firstRejectedAt: instantSchema.nullable().optional(),
      lastRejectedAt: instantSchema.nullable().optional(),
      rejectionCheckpointPending: z.boolean().optional(),
    })
    .optional(),
});

export const dashboardStatusSchema = z
  .object({
    desiredRevision: counterSchema,
    appliedRevision: counterSchema.nullable(),
    pending: z.boolean(),
    lastError: z.string().nullable(),
    lastSeen: instantSchema.nullable(),
    receipt: gatewayReceiptSchema.nullable(),
    conditions: z.array(conditionSchema),
    // Requests waiting for review, counted for the navigation badge.
    needsReview: z.number().int().nonnegative(),
    // Null until the gateway first reports it.
    gateway: gatewayEndpointSchema.nullable(),
  })
  .strict();

export const monitorSelectionSchema = z
  .object({
    instanceId: z.string().uuid().optional(),
    peerIp: ipSchema.optional(),
    domain: nameSchema.optional(),
    hostname: nameSchema.optional(),
    protocol: z.number().int().min(0).max(255).optional(),
    port: z.number().int().min(0).max(65535).nullable().optional(),
    direction: z.enum(["outgoing", "incoming"]).optional(),
  })
  .strict()
  .superRefine((selection, context) => {
    if ((selection.domain || selection.hostname) && !selection.instanceId)
      context.addIssue({
        code: "custom",
        path: ["instanceId"],
        message: "Name scopes require an instance",
      });
  });

export const monitorServiceSchema = z
  .object({
    key: z.string(),
    instanceId: z.string().uuid(),
    direction: z.enum(["outgoing", "incoming"]),
    peerIp: ipSchema,
    protocol: z.number().int().min(0).max(255),
    port: z.number().int().min(0).max(65535).nullable(),
    sentBytes: counterSchema,
    receivedBytes: counterSchema,
  })
  .strict();

// Retained events for the selected period, grouped by kind, direction, service, and recorded rule.
export const monitorEventGroupSchema = z
  .object({
    type: z.enum(["traffic", "dns", "blocked", "metadata"]),
    direction: z.enum(["outgoing", "incoming"]).nullable(),
    protocol: z.number().int().min(0).max(255).nullable(),
    port: z.number().int().min(0).max(65535).nullable(),
    ruleId: z.string().uuid().nullable(),
    count: counterSchema,
    lastAt: instantSchema,
  })
  .strict();

// Packets each Block rule dropped for the selected instance, from the rule counters, beside the
// samples recorded for the same rule over the same window. More packets than samples means the
// rule's destination rows are incomplete.
export const monitorBlockedTotalSchema = z
  .object({
    ruleId: z.string().uuid(),
    direction: z.enum(["outgoing", "incoming"]),
    packets: counterSchema,
    samples: counterSchema,
  })
  .strict();

export const monitorReviewSchema = z
  .object({
    instanceId: z.string().uuid(),
    direction: z.enum(["outgoing", "incoming"]),
    peerIp: ipSchema,
    protocol: z.number().int().min(0).max(255),
    port: z.number().int().min(0).max(65535).nullable(),
  })
  .strict();

export const monitorSnapshotSchema = z
  .object({
    from: instantSchema,
    to: instantSchema,
    resolutionSeconds: z.number().int().positive(),
    sentBytes: counterSchema,
    receivedBytes: counterSchema,
    services: z.array(monitorServiceSchema),
    servicesTruncated: z.boolean(),
    timeline: z.array(
      z
        .object({
          at: instantSchema,
          sentBytes: counterSchema,
          receivedBytes: counterSchema,
        })
        .strict(),
    ),
    instances: z.array(instanceSchema),
    status: dashboardStatusSchema,
    coverage: z.string(),
    names: z.array(
      z
        .object({
          instanceId: z.string().uuid(),
          peerIp: ipSchema,
          hostname: z.string(),
          domain: z.string().nullable(),
          source: z.string(),
          observedAt: instantSchema,
          protocol: z.number().int().min(0).max(255).nullable(),
          port: z.number().int().min(0).max(65535).nullable(),
          direction: z.enum(["outgoing", "incoming"]).nullable(),
        })
        .strict(),
    ),
    namesTruncated: z.boolean(),
    // Null unless requested with a selected instance. Events are grouped from the newest 5,000
    // matching events; eventsLimited is set when more matched. A recent summary reads at most the
    // newest 100,000 events of the period; scannedFrom is the oldest time it read when that stopped
    // it first, and null when the summary covers the whole period. Counter buckets round the
    // blockedTotals window start down to the bucket size: one minute within the last day, one
    // hour before.
    eventSummary: z
      .object({
        events: z.array(monitorEventGroupSchema),
        eventsTruncated: z.boolean(),
        eventsLimited: z.boolean(),
        scannedFrom: instantSchema.nullable(),
        blockedTotals: z.array(monitorBlockedTotalSchema),
      })
      .strict()
      .nullable(),
    reviews: z.array(monitorReviewSchema),
    rules: z.array(ruleSchema),
    // Settings localNetworks, which hostname and domain rules refuse as DNS answers.
    localNetworks: z.array(cidrSchema),
    // Drops of connections with no instance on either end in the period: packet counts by the side
    // they arrived on, and the newest sampled drops grouped by side, client, destination, and
    // service, newest first. `gateway` is set for a destination on the gateway, with the fixed
    // services of the gateway its protocol and port are, such as "DNS", or none. Client-side drops
    // also become host Requests; `request` is set while the client has one. A client's drops to the
    // gateway's DNS list up to eight names it looked up from a minute before their first sample to
    // their last. dropsTruncated is set when older groups were left out, and samplesLimited when the
    // groups were read from only the newest samples.
    unregistered: z
      .object({
        clientPackets: counterSchema,
        upstreamPackets: counterSchema,
        drops: z
          .array(
            z
              .object({
                side: z.enum(["client", "upstream"]),
                clientIp: ipSchema,
                peerIp: ipSchema,
                protocol: z.number().int().min(0).max(255).nullable(),
                port: z.number().int().min(0).max(65535).nullable(),
                samples: z.number().int().min(1),
                firstAt: instantSchema,
                lastAt: instantSchema,
                gateway: z
                  .object({ services: z.array(z.string()).max(4) })
                  .strict()
                  .nullable(),
                request: z.boolean(),
                names: z
                  .array(
                    z.object({ name: z.string(), at: instantSchema }).strict(),
                  )
                  .max(8),
              })
              .strict(),
          )
          .max(50),
        dropsTruncated: z.boolean(),
        samplesLimited: z.boolean(),
      })
      .strict(),
  })
  .strict();

// A recent value and when it was last seen, newest first.
const recentAddressesSchema = z
  .array(z.object({ address: ipSchema, at: instantSchema }).strict())
  .max(8);

const requestFields = {
  id: z.string(),
  instanceId: z.string().uuid(),
  attempts: counterSchema,
  firstAt: instantSchema,
  lastAt: instantSchema,
  state: z.enum(["needs-review", "applying", "failed", "resolved"]),
  // The most recent distinct clients the Request was denied for; the first decides its state.
  clients: recentAddressesSchema,
};

export const reviewRequestSchema = z.discriminatedUnion("kind", [
  z
    .object({
      ...requestFields,
      kind: z.literal("connection"),
      direction: z.enum(["outgoing", "incoming"]),
      peerIp: ipSchema,
      protocol: z.number().int().min(0).max(255),
      port: z.number().int().min(0).max(65535).nullable(),
      ruleId: z.string().uuid(),
    })
    .strict(),
  z
    .object({
      ...requestFields,
      kind: z.literal("dns"),
      question: dnsQuestionNameSchema,
      queryType: z.string().min(1).max(32),
      ruleId: z.string().uuid().nullable(),
    })
    .strict(),
  // A host no instance covers whose drops arrived on a client interface. Registering it resolves
  // the Request.
  z
    .object({
      id: z.string(),
      kind: z.literal("host"),
      clientIp: ipSchema,
      attempts: counterSchema,
      firstAt: instantSchema,
      lastAt: instantSchema,
      state: z.enum(["needs-review", "dismissed"]),
      destinations: recentAddressesSchema,
      // Names Suricata saw the host look up before its packets were dropped.
      names: z
        .array(z.object({ name: nameSchema, at: instantSchema }).strict())
        .max(8),
    })
    .strict(),
]);

// Names the request's instance looked up or connected to at the request's address, newest first.
// A shared address can serve several names, so they do not prove what the blocked attempt was for.
export const requestNamesSchema = z
  .object({
    names: z
      .array(
        z
          .object({
            hostname: nameSchema,
            source: z.enum(["dns", "tls", "http"]),
            lastSeenAt: instantSchema,
          })
          .strict(),
      )
      .max(20),
  })
  .strict();

export type RequestNames = z.infer<typeof requestNamesSchema>;

// The main list of Requests, or dismissed hosts only.
export const requestsViewSchema = z.enum(["main", "dismissed"]);

export type RequestsView = z.infer<typeof requestsViewSchema>;

export const requestsSnapshotSchema = z
  .object({
    view: requestsViewSchema,
    requests: z.array(reviewRequestSchema),
    // Current rules, so the rule editor can warn when another rule overrides a new one.
    rules: z.array(ruleSchema),
    retention: z
      .object({
        pending: z.number().int().min(0),
        limit: z.number().int().positive(),
        discarded: counterSchema,
        lastDiscardedAt: instantSchema.nullable(),
        // Denied lookups the gateway counted without recording each one, during floods.
        dnsOmitted: counterSchema,
        lastDnsOmittedAt: instantSchema.nullable(),
      })
      .strict(),
    instances: z.array(instanceSchema),
    status: dashboardStatusSchema,
    // Settings localNetworks, which hostname and domain rules refuse as DNS answers.
    localNetworks: z.array(cidrSchema),
  })
  .strict();

// What one admin change did to a rule, an instance, or the settings. A created object has only
// after values and a deleted one only before values, both complete. An update keeps the fields
// that changed, and every service field when any of them changed.
export const auditChangeSchema = z
  .object({
    subject: z.enum(["rule", "instance", "settings"]),
    id: z.string().uuid().nullable(),
    before: z.record(z.string(), z.json()).nullable(),
    after: z.record(z.string(), z.json()).nullable(),
  })
  .strict();

export type AuditChange = z.infer<typeof auditChangeSchema>;

export const historySnapshotSchema = z
  .object({
    audit: z.array(
      z
        .object({
          id: z.string(),
          at: instantSchema,
          actor: z.string(),
          action: z.string(),
          subject: z.string(),
          details: z.string(),
          subjectLabel: z.string().nullable(),
          subjectRule: ruleSchema.nullable(),
          // Recorded with browser changes; Admin setup has none.
          client: z
            .object({ address: z.string(), browser: z.string().nullable() })
            .strict()
            .nullable(),
          revisions: z
            .object({ before: counterSchema, after: counterSchema })
            .strict()
            .nullable(),
          // Empty when the entry is not a policy change.
          changes: z.array(auditChangeSchema),
        })
        .strict(),
    ),
    events: z.array(eventSchema),
    instances: z.array(instanceSchema),
    rules: z.array(ruleSchema),
    earliestAuditAt: instantSchema.nullable(),
    conditions: z.array(conditionSchema),
    status: dashboardStatusSchema,
  })
  .strict();

export type DashboardStatus = z.infer<typeof dashboardStatusSchema>;

export type MonitorSelection = z.infer<typeof monitorSelectionSchema>;

export type MonitorService = z.infer<typeof monitorServiceSchema>;

export type MonitorSnapshot = z.infer<typeof monitorSnapshotSchema>;

export type HistorySnapshot = z.infer<typeof historySnapshotSchema>;

export const rulesSnapshotSchema = z
  .object({
    revision: counterSchema,
    instances: z.array(instanceSchema),
    rules: z.array(
      ruleSchema.safeExtend({
        state: z.enum(["active", "disabled", "expired", "scheduled"]),
        description: z.string(),
        // Block rules only: packets dropped in the last 24 hours across instances, and the
        // oldest retained sample.
        blocked: z
          .object({
            packets: counterSchema,
            samplesSince: instantSchema.nullable(),
          })
          .strict()
          .nullable(),
      }),
    ),
    status: dashboardStatusSchema,
  })
  .strict();

export type RulesSnapshot = z.infer<typeof rulesSnapshotSchema>;

export const instancesSnapshotSchema = z
  .object({
    revision: counterSchema,
    instances: z.array(instanceSchema),
    rules: z.array(ruleSchema),
  })
  .strict();

export const settingsSnapshotSchema = z
  .object({
    settings: settingsSchema,
    // Null when no permanent catch-all covers the direction.
    catchAll: z
      .object({
        outgoing: z.enum(["allow", "block"]).nullable(),
        incoming: z.enum(["allow", "block"]).nullable(),
      })
      .strict(),
    revision: counterSchema,
    names: z.array(
      z
        .object({
          instanceId: z.string().uuid(),
          address: ipSchema,
          status: z.string(),
          hostname: z.string().nullable(),
          expiresAt: instantSchema.nullable(),
        })
        .strict(),
    ),
    databaseBytes: counterSchema,
    historyUsedBytes: z
      .object({
        traffic: counterSchema,
        dns: counterSchema,
        blocked: counterSchema,
        other: counterSchema,
      })
      .strict(),
    auditUsedBytes: counterSchema,
    requestsUsedBytes: counterSchema,
    requestsLimitBytes: counterSchema,
    status: dashboardStatusSchema,
    storage: storageSnapshotSchema,
    gatewayStorage: storageSnapshotSchema
      .extend({ at: instantSchema })
      .nullable(),
  })
  .strict();

export type RuleDraft = z.input<typeof ruleInputSchema>;
