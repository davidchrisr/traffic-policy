import { randomUUID } from "node:crypto";
import { z } from "zod";
import { ruleSchema, type Policy, type Rule } from "@traffic-policy/contracts";
import { catchAllActions, isSettingsCatchAll } from "@traffic-policy/core";
import { ServiceError } from "@traffic-policy/core/io";

export const catchAllInputSchema = z
  .object({
    outgoing: z.enum(["allow", "block"]),
    incoming: z.enum(["allow", "block"]),
  })
  .strict();

export type CatchAllInput = z.infer<typeof catchAllInputSchema>;

// Settings owns the permanent catch-all, so the rule endpoints refuse to create, change, or
// remove one.
export function assertNotSettingsCatchAll(rule: Rule | undefined) {
  if (rule && isSettingsCatchAll(rule))
    throw new ServiceError(
      400,
      "catch_all_in_settings",
      "The permanent catch-all is set in Settings. Choose an instance, peer, or protocol, set an end time, or use High priority.",
    );
}

// Writes one catch-all for both directions when they agree and one per direction otherwise.
// Existing catch-all IDs are reused so earlier blocked samples keep naming their rule.
export function replaceCatchAll(
  policy: Policy,
  input: CatchAllInput,
  now: string,
): Policy {
  const current = catchAllActions(policy.rules);

  if (
    current.outgoing === input.outgoing &&
    current.incoming === input.incoming
  )
    return policy;
  const previous = policy.rules.filter(isSettingsCatchAll);

  const wanted =
    input.outgoing === input.incoming
      ? [{ direction: "both" as const, action: input.outgoing }]
      : [
          { direction: "outgoing" as const, action: input.outgoing },
          { direction: "incoming" as const, action: input.incoming },
        ];

  const unused = [...previous];

  const rules = wanted.map(({ direction, action }) => {
    const reuse =
      unused.find((rule) => rule.direction === direction) ?? unused[0];

    if (reuse) unused.splice(unused.indexOf(reuse), 1);

    return ruleSchema.parse({
      id: reuse?.id ?? randomUUID(),
      subject: { kind: "global" },
      direction,
      peer: { kind: "any" },
      protocol: null,
      portStart: null,
      portEnd: null,
      icmpType: null,
      icmpCode: null,
      action,
      priority: "normal",
      enabled: true,
      notBefore: null,
      expiresAt: null,
      dnsDestinations: null,
      createdAt: reuse?.createdAt ?? now,
      modifiedAt: now,
      reason: reuse?.reason ?? "Catch-all",
    });
  });

  return {
    ...policy,
    rules: [
      ...policy.rules.filter((rule) => !isSettingsCatchAll(rule)),
      ...rules,
    ],
  };
}
