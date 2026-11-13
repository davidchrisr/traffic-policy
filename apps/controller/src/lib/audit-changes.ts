import { z } from "zod";
import {
  peerSchema,
  portsSchema,
  ruleSchema,
  ruleSetMembersSchema,
  settingsSchema,
  subjectSchema,
  type Instance,
  type Rule,
  type RuleSet,
} from "@traffic-policy/contracts";
import type { AuditChange } from "@traffic-policy/contracts/dashboard";
import {
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
  // The rule the title names, shown after it.
  rule?: Rule;
  lines: ChangeLine[];
}

// The instances and rule sets that turn the identities in a change into names.
interface Names {
  instances: Instance[];
  ruleSets: RuleSet[];
}

interface Field {
  label: string;
  format: (value: Value | undefined, names: Names) => ChangeValue;
}

const optionalText = z.string().nullable();

const deadline = (empty: string) => (value: Value | undefined) => {
  const at = optionalText.parse(value);

  return at === null ? empty : formatFullInstant(at);
};

const ruleFields = {
  subject: {
    label: "Applies to",
    format: (value, { instances, ruleSets }) => {
      const subject = subjectSchema.parse(value);

      if (subject.kind === "global") return anyValue;

      if (
        subject.kind === "instance" &&
        !instances.some((instance) => instance.id === subject.instanceId)
      )
        return "Removed instance";

      return subject.kind === "ruleSet" &&
        !ruleSets.some((ruleSet) => ruleSet.id === subject.ruleSetId)
        ? "Deleted rule set"
        : subjectLabel(subject, instances, ruleSets);
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
    label: "High priority",
    format: (value) =>
      z.enum(["normal", "high"]).parse(value) === "high" ? "Yes" : "No",
  },
  enabled: {
    label: "State",
    format: (value) => (z.boolean().parse(value) ? "Enabled" : "Disabled"),
  },
  notBefore: { label: "Starts", format: deadline("Immediately") },
  expiresAt: { label: "Ends", format: deadline("No end") },
  dnsDestinations: {
    label: "Networks",
    format: (value) =>
      z.array(z.string()).nullable().parse(value)?.join(", ") ?? "Not limited",
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

const ruleSetFields = {
  name: { label: "Name", format: (value) => z.string().parse(value) },
  members: {
    label: "Attached to",
    format: (value, { instances }) => {
      const members = ruleSetMembersSchema.parse(value);

      if (members.kind === "global") return anyValue;

      return (
        members.instanceIds
          .map(
            (id) =>
              instances.find((instance) => instance.id === id)?.name ??
              "Removed instance",
          )
          .join(", ") || "None"
      );
    },
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

// Rule fields in History's order; protocol stands for the whole service.
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
  names: Names,
  keys: string[],
): ChangeLine[] {
  const side = (values: Fields | null, key: string, format: Field["format"]) =>
    values ? format(values[key], names) : null;

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
  names: Names,
  rules: Rule[],
): ChangeView {
  const whole =
    change.before && change.after ? null : (change.before ?? change.after);

  if (whole) {
    const rule = ruleSchema.safeParse(whole);
    const action = whole.action === "allow" ? "Allow" : "Block";

    const title = `${change.before ? "Deleted" : "Added"} ${action} rule`;

    return {
      ...(rule.success
        ? { title, rule: rule.data }
        : { title: `${title}: ${change.id}` }),
      lines: lines(
        change,
        ruleFields,
        names,
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
    title: "Changed rule",
    ...(current && { rule: current }),
    lines: lines(
      change,
      ruleFields,
      names,
      RULE_ORDER.filter((key) => change.after && key in change.after),
    ),
  };
}

// A named object's change: every changed field of an update, and `whole` for one added or removed.
function namedView(
  change: AuditChange,
  kind: string,
  removed: string,
  fields: Record<string, Field>,
  names: Names,
  whole: string[],
): ChangeView {
  const name = z
    .string()
    .optional()
    .parse((change.after ?? change.before)?.name);

  const verb = !change.before ? "Added" : !change.after ? removed : "Changed";

  return {
    title: `${verb} ${kind}${name ? `: ${name}` : ""}`,
    lines: lines(
      change,
      fields,
      names,
      change.before && change.after ? Object.keys(change.after) : whole,
    ),
  };
}

// Readable titles and before and after values for the changes of one History entry.
export function describeChanges(
  changes: AuditChange[],
  instances: Instance[],
  ruleSets: RuleSet[],
  rules: Rule[],
): ChangeView[] {
  const names = { instances, ruleSets };

  return changes.map((change) => {
    if (change.subject === "rule") return ruleView(change, names, rules);

    if (change.subject === "instance")
      return namedView(change, "instance", "Removed", instanceFields, names, [
        "addresses",
      ]);

    if (change.subject === "ruleSet")
      return namedView(change, "rule set", "Deleted", ruleSetFields, names, [
        "members",
      ]);

    return {
      title: "Changed settings",
      lines: lines(
        change,
        settingsFields,
        names,
        Object.keys(change.after ?? {}),
      ),
    };
  });
}
