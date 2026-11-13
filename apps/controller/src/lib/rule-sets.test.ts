import { describe, expect, it } from "vitest";
import { ruleSchema, type Rule } from "@traffic-policy/contracts";
import {
  attach,
  detach,
  isAttached,
  readRuleSetFile,
  ruleSetFile,
  ruleSetFileName,
  ruleSetRules,
} from "./rule-sets.ts";

const first = "11111111-1111-4111-8111-111111111111";

const second = "22222222-2222-4222-8222-222222222222";

const ruleSetId = "33333333-3333-4333-8333-333333333333";

const at = "2026-11-03T00:00:00.000Z";

const rule = (partial: Partial<Rule> = {}): Rule =>
  ruleSchema.parse({
    id: "44444444-4444-4444-8444-444444444444",
    subject: { kind: "ruleSet", ruleSetId },
    direction: "outgoing",
    peer: { kind: "hostname", value: "api.example.com" },
    protocol: 6,
    ports: [{ start: 443, end: 443 }],
    icmpType: null,
    icmpCode: null,
    action: "allow",
    priority: "normal",
    enabled: true,
    notBefore: null,
    expiresAt: null,
    dnsDestinations: null,
    createdAt: at,
    modifiedAt: at,
    reason: "Package registry",
    ...partial,
  });

const none = { kind: "instances" as const, instanceIds: [] };

describe("rule set attachments", () => {
  it("attaches and detaches one instance at a time", () => {
    const one = attach(none, first);

    expect(one).toEqual({ kind: "instances", instanceIds: [first] });
    expect(attach(one, first)).toEqual(one);
    expect(isAttached(one, first)).toBe(true);
    expect(isAttached(one, second)).toBe(false);
    expect(isAttached(one, null)).toBe(false);
    expect(detach(attach(one, second), first)).toEqual({
      kind: "instances",
      instanceIds: [second],
    });
    expect(detach(one, second)).toEqual(one);
  });

  it("treats every instance as one attachment that replaces the list", () => {
    const all = attach(attach(none, first), null);

    expect(all).toEqual({ kind: "global" });
    expect(isAttached(all, null)).toBe(true);
    // The instance has no attachment of its own to remove.
    expect(isAttached(all, first)).toBe(false);
    expect(detach(all, first)).toEqual(all);
    expect(attach(all, first)).toEqual(all);
    expect(detach(all, null)).toEqual(none);
  });

  it("lists the rules that belong to a set", () => {
    const own = rule({ subject: { kind: "instance", instanceId: first } });
    const member = rule();

    expect(ruleSetRules([own, member], ruleSetId)).toEqual([member]);
    expect(ruleSetRules([own, member], second)).toEqual([]);
  });
});

describe("rule set files", () => {
  it("exports a set's name and rules without identities, attachments, or bookkeeping", () => {
    const file = ruleSetFile("Build access", [rule()]);

    expect(file).toEqual({
      format: "traffic-policy-rule-set",
      version: 1,
      name: "Build access",
      rules: [
        {
          direction: "outgoing",
          peer: { kind: "hostname", value: "api.example.com" },
          protocol: 6,
          ports: [{ start: 443, end: 443 }],
          icmpType: null,
          icmpCode: null,
          action: "allow",
          priority: "normal",
          enabled: true,
          notBefore: null,
          expiresAt: null,
          dnsDestinations: null,
          reason: "Package registry",
        },
      ],
    });
    expect(readRuleSetFile(JSON.stringify(file))).toEqual(file);
  });

  it("reads nothing from text that is not a rule set export", () => {
    const file = ruleSetFile("Build access", [rule()]);

    expect(readRuleSetFile("not json")).toBeNull();
    expect(readRuleSetFile(JSON.stringify({ ...file, version: 2 }))).toBeNull();
    expect(
      readRuleSetFile(JSON.stringify({ ...file, rules: [rule()] })),
    ).toBeNull();
    expect(
      readRuleSetFile(
        JSON.stringify({
          ...file,
          rules: [{ ...file.rules[0], ports: [{ start: 443, end: 80 }] }],
        }),
      ),
    ).toBeNull();
  });

  it("names the file after the set", () => {
    expect(ruleSetFileName("Build access")).toBe("Build-access.rule-set.json");
    expect(ruleSetFileName("../etc")).toBe("..-etc.rule-set.json");
    expect(ruleSetFileName("//")).toBe("rule-set.rule-set.json");
  });
});
