import {
  ruleSetFileSchema,
  type Rule,
  type RuleSetFile,
  type RuleSetMembers,
} from "@traffic-policy/contracts";

// The rules that belong to a rule set.
export function ruleSetRules<T extends Pick<Rule, "subject">>(
  rules: T[],
  ruleSetId: string,
): T[] {
  return rules.filter(
    (rule) =>
      rule.subject.kind === "ruleSet" && rule.subject.ruleSetId === ruleSetId,
  );
}

// Whether a rule set applies to the instance, or with null to every instance.
export function isAttached(
  members: RuleSetMembers,
  instanceId: string | null,
): boolean {
  return members.kind === "global"
    ? instanceId === null
    : instanceId !== null && members.instanceIds.includes(instanceId);
}

// Members with the instance attached; null attaches every instance, which replaces the list.
export function attach(
  members: RuleSetMembers,
  instanceId: string | null,
): RuleSetMembers {
  if (instanceId === null || members.kind === "global")
    return { kind: "global" };

  return {
    kind: "instances",
    instanceIds: [...new Set([...members.instanceIds, instanceId])],
  };
}

// Members without the instance; null detaches a set attached to every instance from all of them.
export function detach(
  members: RuleSetMembers,
  instanceId: string | null,
): RuleSetMembers {
  if (members.kind === "global")
    return instanceId === null
      ? { kind: "instances", instanceIds: [] }
      : members;

  return {
    kind: "instances",
    instanceIds: members.instanceIds.filter((id) => id !== instanceId),
  };
}

// A rule set as a file another controller can import: its name and rules, without identities,
// attachments, or bookkeeping.
export function ruleSetFile(name: string, rules: Rule[]): RuleSetFile {
  return ruleSetFileSchema.parse({
    format: "traffic-policy-rule-set",
    version: 1,
    name,
    rules: rules.map((rule) => ({
      direction: rule.direction,
      peer: rule.peer,
      protocol: rule.protocol,
      ports: rule.ports,
      icmpType: rule.icmpType,
      icmpCode: rule.icmpCode,
      action: rule.action,
      priority: rule.priority,
      enabled: rule.enabled,
      notBefore: rule.notBefore,
      expiresAt: rule.expiresAt,
      dnsDestinations: rule.dnsDestinations,
      reason: rule.reason,
    })),
  });
}

// The rule set in an exported file's text, or null when the text is not one.
export function readRuleSetFile(text: string): RuleSetFile | null {
  try {
    return ruleSetFileSchema.safeParse(JSON.parse(text)).data ?? null;
  } catch {
    return null;
  }
}

export function ruleSetFileName(name: string): string {
  return `${name.replace(/[^\w.-]+/g, "-").replace(/^-+|-+$/g, "") || "rule-set"}.rule-set.json`;
}
