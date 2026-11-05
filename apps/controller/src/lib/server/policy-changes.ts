import type { Policy } from "@traffic-policy/contracts";
import type { AuditChange } from "@traffic-policy/contracts/dashboard";

type Fields = NonNullable<AuditChange["after"]>;

// Service fields are shown as one value, so an update keeps all of them.
const SERVICE_FIELDS = [
  "protocol",
  "portStart",
  "portEnd",
  "icmpType",
  "icmpCode",
];

// Bookkeeping that changes with every save.
const RULE_BOOKKEEPING = new Set(["id", "createdAt", "modifiedAt"]);

function updated(
  before: Fields,
  after: Fields,
  ignored = new Set<string>(),
): { before: Fields; after: Fields } | null {
  const changed = new Set(
    [...new Set([...Object.keys(before), ...Object.keys(after)])].filter(
      (key) =>
        !ignored.has(key) &&
        JSON.stringify(before[key]) !== JSON.stringify(after[key]),
    ),
  );

  if (SERVICE_FIELDS.some((key) => changed.has(key)))
    for (const key of SERVICE_FIELDS) changed.add(key);

  if (!changed.size) return null;

  const pick = (fields: Fields) =>
    Object.fromEntries([...changed].map((key) => [key, fields[key] ?? null]));

  return { before: pick(before), after: pick(after) };
}

function objectChanges(
  subject: "rule" | "instance",
  before: (Fields & { id: string })[],
  after: (Fields & { id: string })[],
  ignored?: Set<string>,
): AuditChange[] {
  const previous = new Map(before.map((value) => [value.id, value]));
  const next = new Map(after.map((value) => [value.id, value]));

  return [...new Set([...previous.keys(), ...next.keys()])].flatMap(
    (id): AuditChange[] => {
      const old = previous.get(id) ?? null;
      const current = next.get(id) ?? null;

      if (!old || !current)
        return [{ subject, id, before: old, after: current }];

      const fields = updated(old, current, ignored);

      return fields ? [{ subject, id, ...fields }] : [];
    },
  );
}

// The instances, rules, and settings that differ between two policy revisions.
export function policyChanges(before: Policy, after: Policy): AuditChange[] {
  const settings = updated(before.settings, after.settings);

  return [
    ...objectChanges("instance", before.instances, after.instances),
    ...objectChanges("rule", before.rules, after.rules, RULE_BOOKKEEPING),
    ...(settings
      ? [{ subject: "settings" as const, id: null, ...settings }]
      : []),
  ];
}
