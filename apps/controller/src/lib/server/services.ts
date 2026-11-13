import { randomUUID } from "node:crypto";
import { z } from "zod";
import {
  instanceInputSchema,
  ipSchema,
  ruleInputSchema,
  ruleSchema,
  ruleSetFileSchema,
  ruleSetInputSchema,
  settingsSchema,
  uint64Schema,
  type Instance,
  type Policy,
} from "@traffic-policy/contracts";
import { ControllerStore, type AuditClient } from "./store.ts";
import { controllerConfig } from "./config.ts";
import { ServiceError } from "@traffic-policy/core/io";
import {
  assertNotSettingsCatchAll,
  catchAllInputSchema,
  replaceCatchAll,
} from "./catch-all.ts";

let singleton: ControllerStore | null = null;

export function store(): ControllerStore {
  if (!singleton) singleton = new ControllerStore(controllerConfig().database);

  return singleton;
}

export function requireAdmin(actor: string | null | undefined) {
  if (actor !== "Admin")
    throw new ServiceError(
      401,
      "authentication_required",
      "Sign in to continue",
    );
}

// The signed-in actor and the client recorded with the change.
export interface Requester {
  actor: string | null;
  client: AuditClient | null;
}

export const ruleMutationSchema = z
  .object({ expectedRevision: uint64Schema, rule: ruleInputSchema })
  .strict();

export const expectedRevisionSchema = z
  .object({ expectedRevision: uint64Schema })
  .strict();

export const instanceMutationSchema = z
  .object({ expectedRevision: uint64Schema, instance: instanceInputSchema })
  .strict();

export const settingsMutationSchema = z
  .object({
    expectedRevision: uint64Schema,
    settings: settingsSchema,
    catchAll: catchAllInputSchema,
  })
  .strict();

export const ruleSetMutationSchema = z
  .object({ expectedRevision: uint64Schema, ruleSet: ruleSetInputSchema })
  .strict();

export const ruleSetCreationSchema = z
  .object({
    expectedRevision: uint64Schema,
    ruleSet: ruleSetInputSchema,
    // Rules to create in the set, as an exported file lists them.
    rules: ruleSetFileSchema.shape.rules,
    // Existing rules that move into the set.
    move: z.array(z.string().uuid()).max(4096),
  })
  .strict();

// oxlint-disable-next-line anti-slop/no-unknown-parameters -- This authorized service validates raw request input with its mutation schema.
export function saveRule(requester: Requester, raw: unknown, id?: string) {
  requireAdmin(requester.actor);
  const input = ruleMutationSchema.parse(raw);
  const identity = id ? z.string().uuid().parse(id) : randomUUID();

  return store().mutation(
    input.expectedRevision,
    id ? "rule-updated" : "rule-created",
    identity,
    (policy) => {
      const existing = policy.rules.find((rule) => rule.id === identity);

      if (id && !existing)
        throw new ServiceError(404, "rule_not_found", "Rule no longer exists");
      assertNotSettingsCatchAll(existing);
      const now = new Date().toISOString();

      const rule = ruleSchema.parse({
        ...input.rule,
        id: identity,
        createdAt: existing?.createdAt ?? now,
        modifiedAt: now,
      });

      assertNotSettingsCatchAll(rule);

      policy.rules = [
        ...policy.rules.filter((candidate) => candidate.id !== identity),
        rule,
      ];

      return policy;
    },
    requester.client,
  );
}

// oxlint-disable-next-line anti-slop/no-unknown-parameters -- This authorized service validates raw request input with its mutation schema.
export function deleteRule(requester: Requester, id: string, raw: unknown) {
  requireAdmin(requester.actor);
  const input = expectedRevisionSchema.parse(raw);

  return store().mutation(
    input.expectedRevision,
    "rule-deleted",
    z.string().uuid().parse(id),
    (policy) => {
      const existing = policy.rules.find((rule) => rule.id === id);

      if (!existing)
        throw new ServiceError(404, "rule_not_found", "Rule no longer exists");
      assertNotSettingsCatchAll(existing);
      policy.rules = policy.rules.filter((rule) => rule.id !== id);

      return policy;
    },
    requester.client,
  );
}

// Creates a rule set from new rules, from existing rules that move into it, or both. Moved rules
// keep their identity, so History and blocked samples keep naming them.
// oxlint-disable-next-line anti-slop/no-unknown-parameters -- This authorized service validates raw request input with its mutation schema.
export function createRuleSet(requester: Requester, raw: unknown) {
  requireAdmin(requester.actor);
  const input = ruleSetCreationSchema.parse(raw);
  const id = randomUUID();

  const policy = store().mutation(
    input.expectedRevision,
    "rule-set-created",
    id,
    (policy) => {
      const now = new Date().toISOString();
      const subject = { kind: "ruleSet" as const, ruleSetId: id };
      const existing = new Map(policy.rules.map((rule) => [rule.id, rule]));
      const moved = new Set(input.move);

      for (const identity of moved) {
        const rule = existing.get(identity);

        if (!rule)
          throw new ServiceError(
            404,
            "rule_not_found",
            "Rule no longer exists",
          );
        assertNotSettingsCatchAll(rule);
      }

      policy.ruleSets = [...policy.ruleSets, { id, ...input.ruleSet }];

      policy.rules = [
        ...policy.rules.map((rule) =>
          moved.has(rule.id) ? { ...rule, subject, modifiedAt: now } : rule,
        ),
        ...input.rules.map((rule) =>
          ruleSchema.parse({
            ...rule,
            id: randomUUID(),
            subject,
            createdAt: now,
            modifiedAt: now,
          }),
        ),
      ];

      return policy;
    },
    requester.client,
  );

  return { id, policy };
}

// Renames a rule set or changes the instances it is attached to.
// oxlint-disable-next-line anti-slop/no-unknown-parameters -- This authorized service validates raw request input with its mutation schema.
export function saveRuleSet(requester: Requester, id: string, raw: unknown) {
  requireAdmin(requester.actor);
  const input = ruleSetMutationSchema.parse(raw);
  const identity = z.string().uuid().parse(id);

  return store().mutation(
    input.expectedRevision,
    "rule-set-updated",
    identity,
    (policy) => {
      if (!policy.ruleSets.some((value) => value.id === identity))
        throw new ServiceError(
          404,
          "rule_set_not_found",
          "Rule set no longer exists",
        );

      policy.ruleSets = policy.ruleSets.map((value) =>
        value.id === identity ? { id: identity, ...input.ruleSet } : value,
      );

      return policy;
    },
    requester.client,
  );
}

// Removes a rule set with its rules.
// oxlint-disable-next-line anti-slop/no-unknown-parameters -- This authorized service validates raw request input with its mutation schema.
export function deleteRuleSet(requester: Requester, id: string, raw: unknown) {
  requireAdmin(requester.actor);
  const input = expectedRevisionSchema.parse(raw);
  const identity = z.string().uuid().parse(id);

  return store().mutation(
    input.expectedRevision,
    "rule-set-deleted",
    identity,
    (policy) => {
      if (!policy.ruleSets.some((value) => value.id === identity))
        throw new ServiceError(
          404,
          "rule_set_not_found",
          "Rule set no longer exists",
        );

      policy.ruleSets = policy.ruleSets.filter(
        (value) => value.id !== identity,
      );

      policy.rules = policy.rules.filter(
        (rule) =>
          rule.subject.kind !== "ruleSet" ||
          rule.subject.ruleSetId !== identity,
      );

      return policy;
    },
    requester.client,
  );
}

// Adds or replaces an instance. Registering an address as an instance of its own promotes the rules
// written for exactly that address to the instance, so editing the instance's address later
// carries them. Rules for one of several addresses stay, and validation refuses them, so
// registration never widens a rule to other addresses.
export function withInstance(
  policy: Policy,
  instance: Instance,
  now: string,
): Policy {
  const only = instance.addresses.length === 1 ? instance.addresses[0] : null;

  return {
    ...policy,
    instances: [
      ...policy.instances.filter((value) => value.id !== instance.id),
      instance,
    ],
    rules: policy.rules.map((rule) =>
      rule.subject.kind === "address" && rule.subject.value === only
        ? {
            ...rule,
            subject: { kind: "instance", instanceId: instance.id },
            modifiedAt: now,
          }
        : rule,
    ),
  };
}

// oxlint-disable-next-line anti-slop/no-unknown-parameters -- This authorized service validates raw request input with its mutation schema.
export function saveInstance(requester: Requester, raw: unknown, id?: string) {
  requireAdmin(requester.actor);
  const input = instanceMutationSchema.parse(raw);
  const identity = id ? z.string().uuid().parse(id) : randomUUID();

  return store().mutation(
    input.expectedRevision,
    id ? "instance-updated" : "instance-created",
    identity,
    (policy) => {
      if (id && !policy.instances.some((instance) => instance.id === identity))
        throw new ServiceError(
          404,
          "instance_not_found",
          "Instance no longer exists",
        );

      return withInstance(
        policy,
        { id: identity, ...input.instance },
        new Date().toISOString(),
      );
    },
    requester.client,
  );
}

// oxlint-disable-next-line anti-slop/no-unknown-parameters -- This authorized service validates raw request input with its mutation schema.
export function saveSettings(requester: Requester, raw: unknown) {
  requireAdmin(requester.actor);
  const input = settingsMutationSchema.parse(raw);

  return store().mutation(
    input.expectedRevision,
    "settings-updated",
    "Settings",
    (policy) =>
      replaceCatchAll(
        { ...policy, settings: input.settings },
        input.catchAll,
        new Date().toISOString(),
      ),
    requester.client,
  );
}

export function dismissHostRequest(requester: Requester, address: string) {
  requireAdmin(requester.actor);
  store().dismissHostRequest(ipSchema.parse(address), requester.client);
}

export function restoreHostRequest(requester: Requester, address: string) {
  requireAdmin(requester.actor);
  store().restoreHostRequest(ipSchema.parse(address), requester.client);
}

// oxlint-disable-next-line anti-slop/no-unknown-parameters -- This authorized service validates raw request input with its mutation schema.
export function removeInstance(requester: Requester, id: string, raw: unknown) {
  requireAdmin(requester.actor);
  const input = expectedRevisionSchema.parse(raw);

  return store().removeInstance(
    input.expectedRevision,
    z.string().uuid().parse(id),
    requester.client,
  );
}
