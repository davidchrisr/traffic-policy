import { z } from "zod";
import ipaddr from "ipaddr.js";
import { ScopeTree } from "./scopes.ts";

export {
  ScopeTree,
  addressInteger,
  integerAddress,
  networkRange,
  type ScopeEntry,
} from "./scopes.ts";

export const MAX_MACHINE_FRAME_BYTES = 2 * 1024 * 1024;

// Policy-bearing commands and status responses share the frame allocation.
export const MAX_POLICY_BYTES = MAX_MACHINE_FRAME_BYTES - 64 * 1024;

export function canonicalIp(value: string): string {
  const address = ipaddr.process(value);

  if (address instanceof ipaddr.IPv6 && address.zoneId !== undefined)
    throw new Error("Scoped IPv6 addresses require an interface binding");

  return address.toString();
}

export function canonicalCidr(value: string): string {
  if (value.includes("%")) throw new Error("Scoped networks are not supported");
  let [address, prefix] = ipaddr.parseCIDR(value);

  if (
    address instanceof ipaddr.IPv6 &&
    address.isIPv4MappedAddress() &&
    prefix >= 96
  ) {
    address = address.toIPv4Address();
    prefix -= 96;
  }

  const bytes = address.toByteArray();

  for (let index = 0; index < bytes.length; index++) {
    const remaining = Math.max(0, Math.min(8, prefix - index * 8));
    bytes[index] =
      bytes[index]! & (remaining === 0 ? 0 : 256 - 2 ** (8 - remaining));
  }

  return `${ipaddr.fromByteArray(bytes).toString()}/${prefix}`;
}

// A DNS name as lowercase ASCII labels of letters, digits, hyphens, and underscores (real A/AAAA
// owners and CNAME targets use underscores). An internationalized name becomes its ASCII form
// (IDNA), as DNS queries carry it. Anything else, including whitespace, wildcards, URLs, and
// characters IDNA refuses, is rejected, so a name shown for review reads as what it matches.
export function canonicalName(value: string): string {
  const text = value.trim().toLowerCase().replace(/\.$/, "");

  if (!text || /[\s/@:#?\\]/.test(text)) throw new Error("Invalid DNS name");

  const name = /^[\x00-\x7f]+$/.test(text)
    ? text
    : new URL(`http://${text}`).hostname;

  if (
    name.length > 253 ||
    !name
      .split(".")
      .every(
        (label) =>
          label.length <= 63 &&
          /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/.test(label),
      )
  )
    throw new Error("Invalid DNS name");

  return name;
}

function validIp(value: string): boolean {
  try {
    canonicalIp(value);

    return true;
  } catch {
    return false;
  }
}

function validCidr(value: string): boolean {
  try {
    canonicalCidr(value);

    return true;
  } catch {
    return false;
  }
}

function validName(value: string): boolean {
  try {
    canonicalName(value);

    return true;
  } catch {
    return false;
  }
}

export const ipSchema = z
  .string()
  .max(64)
  .refine(validIp, "Invalid IP address")
  .transform(canonicalIp);

export const cidrSchema = z
  .string()
  .max(72)
  .refine(validCidr, "Invalid network")
  .transform(canonicalCidr);

// Validates and normalizes in one pass.
export const nameSchema = z
  .string()
  .max(253)
  .transform((value, context) => {
    try {
      return canonicalName(value);
    } catch {
      context.addIssue({ code: "custom", message: "Invalid DNS name" });

      return z.NEVER;
    }
  });

export const uint64Schema = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/)
  .refine(
    (value) => BigInt(value) <= 18446744073709551615n,
    "Value exceeds uint64",
  );

export const instantSchema = z.string().datetime({ offset: true });

const deadlineSchema = instantSchema.refine(
  (value) => Date.parse(value) % 1000 === 0,
  "Rule deadlines must have whole-second precision",
);

export const peerSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("any") }).strict(),
  // The gateway itself, at any of its addresses: connections it receives from or starts to the
  // subject, never traffic it forwards.
  z.object({ kind: z.literal("gateway") }).strict(),
  z.object({ kind: z.literal("ip"), value: ipSchema }).strict(),
  z.object({ kind: z.literal("cidr"), value: cidrSchema }).strict(),
  z.object({ kind: z.literal("hostname"), value: nameSchema }).strict(),
  z.object({ kind: z.literal("domain"), value: nameSchema }).strict(),
]);

// A host address or a network. A full-length prefix is the host address itself, so each range has
// one canonical form.
export function canonicalAddress(value: string): string {
  if (!value.includes("/")) return canonicalIp(value);
  const network = canonicalCidr(value);
  const [address, prefix] = network.split("/");

  return Number(prefix) === (address!.includes(":") ? 128 : 32)
    ? address!
    : network;
}

function validAddress(value: string): boolean {
  try {
    canonicalAddress(value);

    return true;
  } catch {
    return false;
  }
}

export const instanceAddressSchema = z
  .string()
  .max(72)
  .refine(validAddress, "Invalid address or network")
  .transform(canonicalAddress);

// Who a rule applies to: every instance, one instance with every network nested in its
// addresses, or an address range inside an instance.
export const subjectSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("global") }).strict(),
  z
    .object({ kind: z.literal("instance"), instanceId: z.string().uuid() })
    .strict(),
  z
    .object({ kind: z.literal("address"), value: instanceAddressSchema })
    .strict(),
]);

export type Subject = z.infer<typeof subjectSchema>;

// The scope a subject names: an instance ID or an address range; null for global rules.
export function subjectScope(subject: Subject): string | null {
  return subject.kind === "global"
    ? null
    : subject.kind === "instance"
      ? subject.instanceId
      : subject.value;
}

// A `ScopeTree.pathKey`: an address family, then each scope from the root with its prefix length.
// Keys are derived from a validated policy and never parsed from input.
export const pathKeySchema = z.string();

export const instanceSchema = z
  .object({
    id: z.string().uuid(),
    name: z.string().trim().min(1).max(128),
    addresses: z.array(instanceAddressSchema).min(1).max(32),
  })
  .strict()
  .refine(
    (instance) =>
      new Set(instance.addresses).size === instance.addresses.length,
    "Instance addresses must be unique",
  );

// A rule lists at most this many ports and port ranges.
export const MAX_RULE_PORTS = 64;

export type PortRange = { start: number; end: number };

const portNumberSchema = z.number().int().min(1).max(65535);

// Port ranges in canonical form: sorted, each start at most its end, and no two overlapping or
// adjacent, so equal port sets compare equal.
export const portsSchema = z
  .array(z.object({ start: portNumberSchema, end: portNumberSchema }).strict())
  .min(1)
  .max(MAX_RULE_PORTS)
  .refine(
    (ranges) =>
      ranges.every(
        (range, index) =>
          range.start <= range.end &&
          (index === 0 || ranges[index - 1]!.end + 1 < range.start),
      ),
    "Port ranges must be sorted, not reversed, and neither overlapping nor adjacent",
  );

function portNumber(digits: string): number {
  const port = Number(digits);

  if (port < 1 || port > 65535)
    throw new Error(`Port ${digits} is outside 1–65535`);

  return port;
}

// Ports typed as comma-separated ports and inclusive ranges, such as "443-1000, 321", in canonical
// form; null when blank, meaning any port. Overlapping and adjacent entries merge.
export function parsePorts(text: string): PortRange[] | null {
  if (text.trim() === "") return null;

  const ranges = text.split(",").map((entry) => {
    const match = /^(\d+)(?:\s*-\s*(\d+))?$/.exec(entry.trim());

    if (!match)
      throw new Error(
        entry.trim() === ""
          ? "Remove the empty entry between commas"
          : `"${entry.trim()}" is not a port or a port range`,
      );

    const start = portNumber(match[1]!);
    const end = match[2] === undefined ? start : portNumber(match[2]);

    if (start > end)
      throw new Error(
        `Range ${start}-${end} is reversed; write it as ${end}-${start}`,
      );

    return { start, end };
  });

  const merged: PortRange[] = [];

  for (const range of ranges.sort((a, b) => a.start - b.start)) {
    const last = merged.at(-1);

    if (last && range.start <= last.end + 1)
      last.end = Math.max(last.end, range.end);
    else merged.push({ ...range });
  }

  if (merged.length > MAX_RULE_PORTS)
    throw new Error(`Enter at most ${MAX_RULE_PORTS} ports or port ranges`);

  return merged;
}

// Port ranges as parsePorts reads them, such as "321, 443-1000".
export function formatPorts(ranges: PortRange[], dash = "-"): string {
  return ranges
    .map(({ start, end }) =>
      start === end ? `${start}` : `${start}${dash}${end}`,
    )
    .join(", ");
}

const ruleObject = z
  .object({
    id: z.string().uuid(),
    subject: subjectSchema,
    direction: z.enum(["outgoing", "incoming", "both"]),
    peer: peerSchema,
    protocol: z.number().int().min(0).max(255).nullable(),
    ports: portsSchema.nullable(),
    icmpType: z.number().int().min(0).max(255).nullable(),
    icmpCode: z.number().int().min(0).max(255).nullable(),
    action: z.enum(["allow", "block"]),
    priority: z.enum(["normal", "high"]),
    enabled: z.boolean(),
    notBefore: deadlineSchema.nullable(),
    expiresAt: deadlineSchema.nullable(),
    dnsDestinations: z.array(cidrSchema).min(1).max(64).nullable(),
    createdAt: instantSchema,
    modifiedAt: instantSchema,
    reason: z.string().max(1024),
  })
  .strict();

export const ruleSchema = ruleObject.superRefine((rule, context) => {
  const fail = (message: string, path: string) =>
    context.addIssue({ code: "custom", message, path: [path] });

  if (
    (rule.peer.kind === "hostname" || rule.peer.kind === "domain") &&
    rule.direction !== "outgoing"
  ) {
    fail("DNS selectors require outgoing direction", "direction");
  }

  if (
    rule.dnsDestinations !== null &&
    !["hostname", "domain"].includes(rule.peer.kind)
  )
    fail(
      "DNS destination networks require a hostname or domain selector",
      "dnsDestinations",
    );

  if (
    rule.ports !== null &&
    rule.protocol !== null &&
    ![6, 17].includes(rule.protocol)
  ) {
    fail("Ports require TCP, UDP, or any transport", "protocol");
  }

  if (
    (rule.icmpType !== null || rule.icmpCode !== null) &&
    ![1, 58].includes(rule.protocol ?? -1)
  ) {
    fail("ICMP selectors require an ICMP protocol", "protocol");
  }

  if (rule.icmpCode !== null && rule.icmpType === null)
    fail("ICMP code requires a type", "icmpType");

  if (
    rule.expiresAt &&
    rule.notBefore &&
    Date.parse(rule.expiresAt) <= Date.parse(rule.notBefore)
  ) {
    fail("Expiry must follow activation", "expiresAt");
  }
});

export const ruleInputSchema = ruleObject
  .omit({ id: true, createdAt: true, modifiedAt: true })
  .strict();

// Each kind of observation history is trimmed to its own limit; together they bound history.
export function historyLimitBytes(
  settings: Pick<
    Settings,
    | "trafficHistoryBytes"
    | "dnsHistoryBytes"
    | "blockedHistoryBytes"
    | "otherHistoryBytes"
  >,
): bigint {
  return (
    BigInt(settings.trafficHistoryBytes) +
    BigInt(settings.dnsHistoryBytes) +
    BigInt(settings.blockedHistoryBytes) +
    BigInt(settings.otherHistoryBytes)
  );
}

export const settingsSchema = z
  .object({
    dnsGraceSeconds: z.number().int().min(0).max(604800),
    permissionLimit: z.number().int().min(1).max(100000),
    trafficHistoryBytes: uint64Schema,
    dnsHistoryBytes: uint64Schema,
    blockedHistoryBytes: uint64Schema,
    otherHistoryBytes: uint64Schema,
    auditBytes: uint64Schema,
    collectorBytes: uint64Schema,
    gatewayDiskBytes: uint64Schema,
    controllerDiskBytes: uint64Schema,
    historyMaxAgeDays: z.number().int().min(1).max(3650).nullable(),
    auditMaxAgeDays: z.number().int().min(1).max(3650).nullable(),
    localNetworks: z.array(cidrSchema).max(128),
    reverseDnsResolver: ipSchema.nullable(),
  })
  .strict()
  .superRefine((settings, context) => {
    if (
      ![
        settings.gatewayDiskBytes,
        settings.controllerDiskBytes,
        settings.collectorBytes,
        settings.trafficHistoryBytes,
        settings.dnsHistoryBytes,
        settings.blockedHistoryBytes,
        settings.otherHistoryBytes,
        settings.auditBytes,
      ].every((value) => /^(0|[1-9][0-9]*)$/.test(value))
    )
      return;

    if (
      BigInt(settings.gatewayDiskBytes) <
      BigInt(settings.collectorBytes) + 268435456n
    )
      context.addIssue({
        code: "custom",
        path: ["gatewayDiskBytes"],
        message:
          "Gateway storage must include the delivery buffer and 256 MiB recovery reserve",
      });

    if (
      BigInt(settings.controllerDiskBytes) <
      2n * (historyLimitBytes(settings) + BigInt(settings.auditBytes)) +
        67108864n
    )
      context.addIssue({
        code: "custom",
        path: ["controllerDiskBytes"],
        message:
          "Controller storage must include history, change history, and database recovery overhead",
      });
  });

export const policySchema = z
  .object({
    protocolVersion: z.literal(1),
    revision: uint64Schema,
    generatedAt: instantSchema,
    instances: z.array(instanceSchema).max(4096),
    rules: z.array(ruleSchema).max(4096),
    settings: settingsSchema,
  })
  .strict()
  .superRefine((policy, context) => {
    const fail = (message: string) =>
      context.addIssue({ code: "custom", message });

    const identities = new Set(policy.instances.map((instance) => instance.id));

    if (identities.size !== policy.instances.length)
      fail("Duplicate instance identity");

    if (
      new Set(policy.rules.map((rule) => rule.id)).size !== policy.rules.length
    )
      fail("Duplicate rule identity");

    const tree = new ScopeTree(
      policy.instances,
      policy.rules.flatMap((rule) =>
        rule.subject.kind === "address" ? [rule.subject.value] : [],
      ),
    );

    for (const problem of tree.problems) fail(problem);

    for (const rule of policy.rules) {
      if (
        rule.subject.kind === "instance" &&
        !identities.has(rule.subject.instanceId)
      )
        fail("Rule references an unknown instance");
    }

    if (compiledRuleCount(policy, tree) > 50000)
      fail("Policy exceeds its compilation budget");

    for (const direction of ["incoming", "outgoing"] as const) {
      if (
        !policy.rules.some(
          (rule) =>
            rule.subject.kind === "global" &&
            rule.peer.kind === "any" &&
            rule.protocol === null &&
            rule.ports === null &&
            rule.icmpType === null &&
            rule.enabled &&
            rule.notBefore === null &&
            rule.expiresAt === null &&
            (rule.direction === direction || rule.direction === "both"),
        )
      ) {
        fail(`A permanent global catch-all is required for ${direction}`);
      }
    }
  });

// The rule entries the enforcement chains hold: each distinct path of scopes gets its own chains,
// holding the global rules and the rules of every scope on the path.
function compiledRuleCount(
  policy: Pick<Policy, "rules">,
  tree: ScopeTree,
): number {
  const counts = new Map<string | null, number>();

  for (const rule of policy.rules) {
    const scope = subjectScope(rule.subject);

    counts.set(scope, (counts.get(scope) ?? 0) + 1);
  }

  const global = counts.get(null) ?? 0;
  const paths = new Map<string, number>();

  for (const entry of tree.entries)
    paths.set(
      ScopeTree.pathKey(entry),
      ScopeTree.path(entry).reduce(
        (sum, value) => sum + (counts.get(value.scope) ?? 0),
        global,
      ),
    );

  let total = 0;

  for (const count of paths.values()) total += count;

  return total;
}

export const policyTransportSchema = policySchema.superRefine(
  (policy, context) => {
    if (
      new TextEncoder().encode(JSON.stringify(policy)).byteLength >
      MAX_POLICY_BYTES
    )
      context.addIssue({
        code: "custom",
        message:
          "Policy exceeds its transport allocation. Shorten rule reasons or reduce policy entries before saving.",
      });
  },
);

// A DNS-derived permission is held by the chains of `path`, so it opens the address only for
// addresses with that path. `leasePath` identifies the lease it came from: the same path when the
// address has the client's family, otherwise the client's.
export const permissionSchema = z
  .object({
    path: pathKeySchema,
    leasePath: pathKeySchema,
    ruleId: z.string().uuid(),
    address: ipSchema,
    question: nameSchema,
    responseAt: instantSchema,
    ttlSeconds: z.number().int().min(0).max(4294967295),
    expiresAt: instantSchema,
  })
  .strict();

// `path` is the client's scope path when the answer arrived.
export const addressLeaseSchema = z
  .object({
    path: pathKeySchema,
    clientIp: ipSchema,
    address: ipSchema,
    question: nameSchema,
    responseAt: instantSchema,
    ttlSeconds: z.number().int().min(0).max(4294967295),
    expiresAt: instantSchema,
  })
  .strict();

const MAX_DNS_ANSWERS = 256;

const MAX_DNS_ANSWER_LENGTH = 253;

const MAX_DNS_ADDRESS_DETAILS_LENGTH =
  MAX_DNS_ANSWERS * (MAX_DNS_ANSWER_LENGTH + 2) - 2;

export const dnsAnswerSchema = z
  .object({
    owner: nameSchema,
    type: z.enum(["A", "AAAA", "CNAME"]),
    value: z.string().max(MAX_DNS_ANSWER_LENGTH),
    ttl: z.number().int().min(0).max(4294967295),
  })
  .strict()
  .superRefine((answer, context) => {
    if (
      answer.type === "CNAME"
        ? !validName(answer.value)
        : !validIp(answer.value)
    ) {
      context.addIssue({ code: "custom", message: "Invalid DNS answer data" });
    } else if (
      answer.type !== "CNAME" &&
      ipaddr.process(answer.value).kind() !==
        (answer.type === "A" ? "ipv4" : "ipv6")
    ) {
      context.addIssue({
        code: "custom",
        message: "DNS answer family does not match its type",
      });
    }
  });

export const dnsQuestionNameSchema = z.union([z.literal("."), nameSchema]);

export const dnsDecisionSchema = z
  .object({
    allowed: z.boolean(),
    ruleId: z.string().uuid().nullable(),
    catchAll: z.boolean(),
  })
  .strict();

export type DnsDecision = z.infer<typeof dnsDecisionSchema>;

export const resolutionSchema = z
  .object({
    clientIp: ipSchema,
    question: dnsQuestionNameSchema,
    responseAt: instantSchema,
    answers: z.array(dnsAnswerSchema).max(MAX_DNS_ANSWERS),
  })
  .strict();

export const flowSchema = z
  .object({
    initiatorIp: ipSchema,
    responderIp: ipSchema,
    originalDestinationIp: ipSchema,
    protocol: z.number().int().min(0).max(255),
    originalServicePort: z.number().int().min(0).max(65535).nullable(),
    responderServicePort: z.number().int().min(0).max(65535).nullable(),
    icmpType: z.number().int().min(0).max(255).nullable(),
    icmpCode: z.number().int().min(0).max(255).nullable(),
  })
  .strict();

export const gatewayReceiptSchema = z
  .object({
    protocolVersion: z.literal(1),
    revision: uint64Schema,
    policyHash: z.string().regex(/^[a-f0-9]{64}$/),
    bootId: z.string().uuid(),
    appliedAt: instantSchema,
    permissions: z.number().int().min(0),
  })
  .strict();

export const resolutionReceiptSchema = gatewayReceiptSchema.extend({
  instanceId: z.string().uuid(),
});

// The details a denied DNS lookup must carry; other detail fields stay allowed.
const deniedDetailsSchema = z.looseObject({
  queryType: z.string().min(1).max(32),
  clientIp: ipSchema,
  catchall: z.boolean(),
  appliedRevision: uint64Schema,
  policyHash: z.string().regex(/^[a-f0-9]{64}$/),
});

export const eventSchema = z
  .object({
    id: z.string().uuid(),
    observedAt: instantSchema,
    // blocked_count carries the packets a Block rule dropped since the previous read.
    type: z.enum([
      "traffic",
      "dns",
      "blocked",
      "blocked_count",
      "condition",
      "metadata",
    ]),
    instanceId: z.string().uuid().nullable(),
    direction: z.enum(["outgoing", "incoming"]).nullable(),
    peerIp: ipSchema.nullable(),
    protocol: z.number().int().min(0).max(255).nullable(),
    port: z.number().int().min(0).max(65535).nullable(),
    sentBytes: uint64Schema,
    receivedBytes: uint64Schema,
    ruleId: z.string().uuid().nullable(),
    question: z.string().max(253).nullable(),
    source: z.enum([
      "conntrack",
      "nftables",
      "resolver-gate",
      "suricata",
      "gateway",
    ]),
    details: z.record(
      z.string().max(128),
      z.union([
        z.string().max(MAX_DNS_ADDRESS_DETAILS_LENGTH),
        z.number().finite(),
        z.boolean(),
        z.null(),
      ]),
    ),
  })
  .strict()
  .superRefine((event, context) => {
    if (
      event.type === "dns" &&
      event.details.outcome === "policy-denied" &&
      (event.source !== "resolver-gate" ||
        event.instanceId === null ||
        !dnsQuestionNameSchema.safeParse(event.question).success ||
        !deniedDetailsSchema.safeParse(event.details).success)
    )
      context.addIssue({
        code: "custom",
        message:
          "A denied DNS lookup needs its question, query type, instance, and applied policy decision",
      });

    // A condition with `occurrences` happened that many times; with `recovered` it is already over.
    if (
      event.type === "condition" &&
      event.details.occurrences !== undefined &&
      (!Number.isSafeInteger(event.details.occurrences) ||
        Number(event.details.occurrences) < 1)
    )
      context.addIssue({
        code: "custom",
        path: ["details", "occurrences"],
        message: "Condition occurrences must be a positive integer",
      });

    // A count of unregistered drops names the side the packets arrived on instead of a rule.
    const unregistered = ["client", "upstream"].includes(
      String(event.details.unregistered),
    );

    if (
      event.type === "blocked_count" &&
      ((unregistered
        ? event.instanceId !== null ||
          event.direction !== null ||
          event.ruleId !== null
        : event.instanceId === null ||
          event.direction === null ||
          event.ruleId === null) ||
        !Number.isSafeInteger(event.details.packets) ||
        Number(event.details.packets) < 1)
    )
      context.addIssue({
        code: "custom",
        path: ["details", "packets"],
        message:
          "A blocked count needs an instance, direction, and rule, or an unregistered side, and a positive packet count",
      });

    // DNS answer addresses are indexed by their canonical form, so each must be an IP address.
    if (
      event.type === "dns" &&
      event.details.addresses !== undefined &&
      event.details.addresses !== "" &&
      !String(event.details.addresses).split(", ").every(validIp)
    )
      context.addIssue({
        code: "custom",
        path: ["details", "addresses"],
        message:
          "DNS answer addresses must be IP addresses separated by commas",
      });

    for (const [key, value] of Object.entries(event.details)) {
      // oxlint-disable-next-line anti-slop/no-runtime-typeof -- The validated detail union needs narrowing before applying its field-specific string bound.
      if (typeof value !== "string") continue;

      const limit =
        event.type === "dns" &&
        event.source === "resolver-gate" &&
        key === "addresses"
          ? MAX_DNS_ADDRESS_DETAILS_LENGTH
          : 4096;

      if (value.length > limit)
        context.addIssue({
          code: "custom",
          path: ["details", key],
          message: `Observation detail exceeds ${limit} characters`,
        });
    }
  });

export const MAX_OBSERVATION_BATCH_RECORDS = 4096;

export const eventBatchSchema = z
  .object({
    protocolVersion: z.literal(1),
    epoch: z.string().uuid(),
    sequence: uint64Schema,
    events: z.array(eventSchema).max(MAX_OBSERVATION_BATCH_RECORDS),
  })
  .strict();

export type Peer = z.infer<typeof peerSchema>;

export type Rule = z.infer<typeof ruleSchema>;

export type Instance = z.infer<typeof instanceSchema>;

export type Settings = z.infer<typeof settingsSchema>;

export type Policy = z.infer<typeof policySchema>;

export type Permission = z.infer<typeof permissionSchema>;

export type AddressLease = z.infer<typeof addressLeaseSchema>;

export type Resolution = z.infer<typeof resolutionSchema>;

export type Flow = z.infer<typeof flowSchema>;

export type GatewayReceipt = z.infer<typeof gatewayReceiptSchema>;

export type ResolutionReceipt = z.infer<typeof resolutionReceiptSchema>;

export type GatewayEvent = z.infer<typeof eventSchema>;

export type EventBatch = z.infer<typeof eventBatchSchema>;
