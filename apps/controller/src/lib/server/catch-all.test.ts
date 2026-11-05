import { describe, expect, it } from "vitest";
import {
  policySchema,
  type Policy,
  type Rule,
} from "@traffic-policy/contracts";
import { catchAllActions } from "@traffic-policy/core";
import { assertNotSettingsCatchAll, replaceCatchAll } from "./catch-all.ts";

const created = "2026-10-01T00:00:00.000Z";

const now = "2026-10-26T00:00:00.000Z";

const rule = (fields: Partial<Rule>): Rule => ({
  id: "00000000-0000-4000-8000-000000000001",
  subject: { kind: "global" },
  direction: "both",
  peer: { kind: "any" },
  protocol: null,
  portStart: null,
  portEnd: null,
  icmpType: null,
  icmpCode: null,
  action: "block",
  priority: "normal",
  enabled: true,
  notBefore: null,
  expiresAt: null,
  dnsDestinations: null,
  createdAt: created,
  modifiedAt: created,
  reason: "Initial global catch-all",
  ...fields,
});

const policy = (rules: Rule[]): Policy =>
  policySchema.parse({
    protocolVersion: 1,
    revision: "7",
    generatedAt: created,
    instances: [],
    rules,
    settings: {
      dnsGraceSeconds: 300,
      permissionLimit: 1000,
      trafficHistoryBytes: "536870912",
      dnsHistoryBytes: "268435456",
      blockedHistoryBytes: "213909504",
      otherHistoryBytes: "54525952",
      auditBytes: "1073741824",
      collectorBytes: "1073741824",
      controllerDiskBytes: "8589934592",
      gatewayDiskBytes: "8589934592",
      historyMaxAgeDays: null,
      auditMaxAgeDays: null,
      localNetworks: [],
      reverseDnsResolver: null,
    },
  });

const temporaryAllow = rule({
  id: "00000000-0000-4000-8000-000000000009",
  action: "allow",
  expiresAt: "2026-11-01T00:00:00.000Z",
});

describe("Settings catch-all", () => {
  it("splits a shared catch-all per direction and keeps its ID for the matching one", () => {
    const next = replaceCatchAll(
      policy([rule({}), temporaryAllow]),
      { outgoing: "allow", incoming: "block" },
      now,
    );

    expect(catchAllActions(next.rules)).toEqual({
      outgoing: "allow",
      incoming: "block",
    });
    expect(next.rules).toContainEqual(temporaryAllow);

    const outgoing = next.rules.find((value) => value.direction === "outgoing");

    expect(outgoing).toMatchObject({
      id: "00000000-0000-4000-8000-000000000001",
      createdAt: created,
      modifiedAt: now,
    });
    expect(policySchema.parse(next)).toEqual(next);
  });

  it("joins agreeing directions into one rule and leaves an unchanged policy alone", () => {
    const split = policy([
      rule({ direction: "outgoing", action: "allow" }),
      rule({
        id: "00000000-0000-4000-8000-000000000002",
        direction: "incoming",
      }),
    ]);

    const joined = replaceCatchAll(
      split,
      { outgoing: "block", incoming: "block" },
      now,
    );

    expect(joined.rules).toHaveLength(1);
    expect(joined.rules[0]).toMatchObject({
      direction: "both",
      action: "block",
    });
    expect(
      replaceCatchAll(split, { outgoing: "allow", incoming: "block" }, now),
    ).toBe(split);
  });

  it("refuses rule edits that would create, change, or remove the Settings catch-all", () => {
    expect(() => assertNotSettingsCatchAll(rule({}))).toThrow(/Settings/u);
    expect(() =>
      assertNotSettingsCatchAll(rule({ priority: "high" })),
    ).not.toThrow();
    expect(() => assertNotSettingsCatchAll(temporaryAllow)).not.toThrow();
    expect(() =>
      assertNotSettingsCatchAll(rule({ enabled: false })),
    ).not.toThrow();
    expect(() => assertNotSettingsCatchAll(undefined)).not.toThrow();
  });
});
