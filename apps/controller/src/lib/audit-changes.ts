import { z } from "zod";
import {
  peerSchema,
  portsSchema,
  ruleSchema,
  settingsSchema,
  subjectSchema,
  type Instance,
  type Rule,
} from "@traffic-policy/contracts";
import type { AuditChange } from "@traffic-policy/contracts/dashboard";
import {
  describeRule,
  directionLabels,
  ruleServiceLabel,
  subjectLabel,
} from "@traffic-policy/core";
import { formatByteSize } from "./byte-size.ts";
import { formatFullInstant } from "./format-time.ts";

type Fields = NonNullable<AuditChange["after"]>;

type Value = Fields[string];

// An unrestricted instance, peer, or service, and the gateway peer, which History shows boxed.
export const anyValue = Symbol("Any");

export const gatewayValue = Symbol("Gateway");

export type ChangeValue = string | typeof anyValue | typeof gatewayValue;

export interface ChangeLine {
  label: string;
  // Null on the side where the object did not exist.
  before: ChangeValue | null;
  after: ChangeValue | null;
}

export interface ChangeView {
  title: string;
  lines: ChangeLine[];
}

interface Field {
  label: string;
  format: (value: Value | undefined, instances: Instance[]) => ChangeValue;
}

const optionalText = z.string().nullable();

const deadline = (empty: string) => (value: Value | undefined) => {
  const at = optionalText.parse(value);

  return at === null ? empty : formatFullInstant(at);
};

const ruleFields = {
  subject: {
    label: "Instance",
    format: (value, instances) => {
      const subject = subjectSchema.parse(value);

      if (subject.kind === "global") return anyValue;

      return subject.kind === "instance" &&
        !instances.some((instance) => instance.id === subject.instanceId)
        ? "Removed instance"
        : subjectLabel(subject, instances);
    },
  },
  direction: {
    label: "Direction",
    format: (value) =>
      directionLabels[z.enum(["outgoing", "incoming", "both"]).parse(value)],
  },
  peer: {
    label: "Peer",
    format: (value) => {
      const peer = peerSchema.parse(value);

      return peer.kind === "any"
        ? anyValue
        : peer.kind === "gateway"
          ? gatewayValue
          : peer.value;
    },
  },
  action: {
    label: "Action",
    format: (value) =>
      z.enum(["allow", "block"]).parse(value) === "allow" ? "Allow" : "Block",
  },
  priority: {
    label: "Priority",
    format: (value) =>
      z.enum(["normal", "high"]).parse(value) === "high" ? "High" : "Normal",
  },
  enabled: {
    label: "State",
    format: (value) => (z.boolean().parse(value) ? "Enabled" : "Disabled"),
  },
  notBefore: { label: "Starts", format: deadline("Immediately") },
  expiresAt: { label: "Expires", format: deadline("Never") },
  dnsDestinations: {
    label: "DNS destinations",
    format: (value) =>
      z.array(z.string()).nullable().parse(value)?.join(", ") ?? "Any",
  },
  reason: {
    label: "Reason",
    format: (value) => z.string().parse(value) || "None",
  },
} satisfies Record<string, Field>;

const port = z.number().int().nullable();

// Protocol, ports, and ICMP type and code read as one service.
function service(fields: Fields): ChangeValue {
  return (
    ruleServiceLabel({
      protocol: port.parse(fields.protocol),
      ports: portsSchema.nullable().parse(fields.ports),
      icmpType: port.parse(fields.icmpType),
      icmpCode: port.parse(fields.icmpCode),
    }) ?? anyValue
  );
}

const instanceFields = {
  name: { label: "Name", format: (value) => z.string().parse(value) },
  addresses: {
    label: "Addresses",
    format: (value) => z.array(z.string()).parse(value).join(", "),
  },
} satisfies Record<string, Field>;

const bytes: Field["format"] = (value) =>
  formatByteSize(z.string().parse(value));

const days: Field["format"] = (value) => {
  const count = z.number().nullable().parse(value);

  return count === null ? "No limit" : `${count} days`;
};

const settingsFields = {
  dnsReleaseMode: {
    label: "DNS release mode",
    format: (value) =>
      settingsSchema.shape.dnsReleaseMode.parse(value) === "before-approval"
        ? "Before approval"
        : "After an Allow rule",
  },
  dnsGraceSeconds: {
    label: "DNS grace period",
    format: (value) => `${z.number().parse(value)} seconds`,
  },
  permissionLimit: {
    label: "Active permission limit",
    format: (value) => String(z.number().parse(value)),
  },
  trafficHistoryBytes: { label: "Traffic history limit", format: bytes },
  dnsHistoryBytes: { label: "DNS history limit", format: bytes },
  blockedHistoryBytes: { label: "Blocked packets limit", format: bytes },
  otherHistoryBytes: { label: "Other history limit", format: bytes },
  auditBytes: { label: "Change history limit", format: bytes },
  collectorBytes: { label: "Gateway delivery buffer limit", format: bytes },
  gatewayDiskBytes: { label: "Gateway runtime disk limit", format: bytes },
  controllerDiskBytes: {
    label: "Controller runtime disk limit",
    format: bytes,
  },
  historyMaxAgeDays: { label: "History age limit", format: days },
  auditMaxAgeDays: { label: "Change history age limit", format: days },
  localNetworks: {
    label: "Local networks",
    format: (value) => z.array(z.string()).parse(value).join(", ") || "None",
  },
  reverseDnsResolver: {
    label: "Reverse DNS resolver",
    format: (value) => optionalText.parse(value) ?? "None",
  },
} satisfies Record<string, Field>;

// Rule fields in the editor's order; protocol stands for the whole service.
const RULE_ORDER = [
  "subject",
  "direction",
  "peer",
  "protocol",
  "action",
  "priority",
  "enabled",
  "notBefore",
  "expiresAt",
  "dnsDestinations",
  "reason",
];

// Rule fields a created or deleted rule lists beside its description, when not the default.
const RULE_EXTRAS = {
  priority: "normal",
  enabled: true,
  notBefore: null,
  expiresAt: null,
  dnsDestinations: null,
  reason: "",
} satisfies Record<string, Value>;

function lines(
  change: AuditChange,
  fields: Record<string, Field>,
  instances: Instance[],
  keys: string[],
): ChangeLine[] {
  const side = (values: Fields | null, key: string, format: Field["format"]) =>
    values ? format(values[key], instances) : null;

  return keys.flatMap((key) => {
    if (key === "protocol")
      return [
        {
          label: "Service",
          before: change.before && service(change.before),
          after: change.after && service(change.after),
        },
      ];

    const field = fields[key];

    if (!field) return [];

    return [
      {
        label: field.label,
        before: side(change.before, key, field.format),
        after: side(change.after, key, field.format),
      },
    ];
  });
}

function ruleView(
  change: AuditChange,
  instances: Instance[],
  rules: Rule[],
): ChangeView {
  const whole =
    change.before && change.after ? null : (change.before ?? change.after);

  if (whole) {
    const rule = ruleSchema.safeParse(whole);
    const action = whole.action === "allow" ? "Allow" : "Block";

    return {
      title: `${change.before ? "Deleted" : "Added"} ${action} rule: ${rule.success ? describeRule(rule.data, instances) : change.id}`,
      lines: lines(
        change,
        ruleFields,
        instances,
        Object.entries(RULE_EXTRAS)
          .filter(
            ([key, value]) =>
              JSON.stringify(whole[key]) !== JSON.stringify(value),
          )
          .map(([key]) => key),
      ),
    };
  }

  const current = rules.find((rule) => rule.id === change.id);

  return {
    title: current
      ? `Changed rule: ${describeRule(current, instances)}`
      : "Changed rule",
    lines: lines(
      change,
      ruleFields,
      instances,
      RULE_ORDER.filter((key) => change.after && key in change.after),
    ),
  };
}

function instanceView(change: AuditChange): ChangeView {
  const name = z
    .string()
    .optional()
    .parse((change.after ?? change.before)?.name);

  const verb = !change.before ? "Added" : !change.after ? "Removed" : "Changed";

  return {
    title: `${verb} instance${name ? `: ${name}` : ""}`,
    lines: lines(
      change,
      instanceFields,
      [],
      change.before && change.after ? Object.keys(change.after) : ["addresses"],
    ),
  };
}

// Readable titles and before and after values for the changes of one History entry.
export function describeChanges(
  changes: AuditChange[],
  instances: Instance[],
  rules: Rule[],
): ChangeView[] {
  return changes.map((change) => {
    if (change.subject === "rule") return ruleView(change, instances, rules);

    if (change.subject === "instance") return instanceView(change);

    return {
      title: "Changed settings",
      lines: lines(
        change,
        settingsFields,
        instances,
        Object.keys(change.after ?? {}),
      ),
    };
  });
}
