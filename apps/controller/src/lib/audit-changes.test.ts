import { describe, expect, it } from "vitest";
import {
  policySchema,
  type Policy,
  type Rule,
} from "@traffic-policy/contracts";
import { anyValue, describeChanges, gatewayValue } from "./audit-changes.ts";
import { policyChanges } from "./server/policy-changes.ts";

const instanceId = "11111111-1111-4111-8111-111111111111";

const ruleId = "22222222-2222-4222-8222-222222222222";

const at = "2026-10-26T00:00:00.000Z";

const rule: Rule = {
  id: ruleId,
  subject: { kind: "instance", instanceId },
  direction: "outgoing",
  peer: { kind: "ip", value: "10.22.242.99" },
  protocol: 17,
  ports: [{ start: 18099, end: 18099 }],
  icmpType: null,
  icmpCode: null,
  action: "allow",
  priority: "normal",
  enabled: true,
  notBefore: null,
  expiresAt: "2026-10-27T10:00:00.000Z",
  dnsDestinations: null,
  createdAt: at,
  modifiedAt: at,
  reason: "",
};

const catchAll: Rule = {
  ...rule,
  id: "33333333-3333-4333-8333-333333333333",
  subject: { kind: "global" },
  direction: "both",
  peer: { kind: "any" },
  protocol: null,
  ports: null,
  action: "block",
  expiresAt: null,
};

const policy = (rules: Rule[], dnsGraceSeconds = 7200): Policy =>
  policySchema.parse({
    protocolVersion: 1,
    revision: "1",
    generatedAt: at,
    instances: [
      { id: instanceId, name: "Client", addresses: ["10.22.241.10"] },
    ],
    rules: [...rules, catchAll],
    settings: {
      dnsReleaseMode: "require-allow",
      dnsGraceSeconds,
      permissionLimit: 4096,
      trafficHistoryBytes: "268435456",
      dnsHistoryBytes: "134217728",
      blockedHistoryBytes: "106954752",
      otherHistoryBytes: "27262976",
      auditBytes: "16777216",
      collectorBytes: "67108864",
      gatewayDiskBytes: "2147483648",
      controllerDiskBytes: "2147483648",
      historyMaxAgeDays: null,
      auditMaxAgeDays: null,
      localNetworks: [],
      reverseDnsResolver: null,
    },
  });

describe("policy change details", () => {
  it("keeps changed fields, every service field, and no save bookkeeping", () => {
    const changed = {
      ...rule,
      ports: [{ start: 18100, end: 18100 }],
      expiresAt: "2026-10-27T18:00:00.000Z",
      modifiedAt: "2026-10-26T01:00:00.000Z",
    };

    const changes = policyChanges(policy([rule]), policy([changed], 60));

    expect(changes).toEqual([
      {
        subject: "rule",
        id: ruleId,
        before: {
          protocol: 17,
          ports: [{ start: 18099, end: 18099 }],
          icmpType: null,
          icmpCode: null,
          expiresAt: "2026-10-27T10:00:00.000Z",
        },
        after: {
          protocol: 17,
          ports: [{ start: 18100, end: 18100 }],
          icmpType: null,
          icmpCode: null,
          expiresAt: "2026-10-27T18:00:00.000Z",
        },
      },
      {
        subject: "settings",
        id: null,
        before: { dnsGraceSeconds: 7200 },
        after: { dnsGraceSeconds: 60 },
      },
    ]);

    const [update, settings] = describeChanges(changes, policy([]).instances, [
      changed,
    ]);

    expect(update!.title).toBe(
      "Changed rule: Client · Outgoing · 10.22.242.99 · UDP 18100",
    );
    expect(
      update!.lines.map((line) => [line.label, line.before, line.after]),
    ).toEqual([
      ["Service", "UDP 18099", "UDP 18100"],
      [
        "Ends",
        expect.stringContaining("2026"),
        expect.stringContaining("2026"),
      ],
    ]);
    expect(settings).toEqual({
      title: "Changed settings",
      lines: [
        {
          label: "DNS grace period",
          before: "7200 seconds",
          after: "60 seconds",
        },
      ],
    });
  });

  it("describes a deleted rule completely and lists only its non-default fields", () => {
    const [deleted] = describeChanges(
      policyChanges(policy([rule]), policy([])),
      policy([]).instances,
      [],
    );

    expect(deleted!.title).toBe(
      "Deleted Allow rule: Client · Outgoing · 10.22.242.99 · UDP 18099",
    );
    expect(deleted!.lines).toEqual([
      {
        label: "Ends",
        before: expect.stringContaining("2026"),
        after: null,
      },
    ]);
  });

  it("shows a rule's scope before and after, including an address rule promoted to its instance", () => {
    const address = {
      ...rule,
      subject: { kind: "address", value: "10.22.241.10" },
    } satisfies Rule;

    const global = { ...rule, subject: { kind: "global" } } satisfies Rule;

    // A subnet instance, so the address rule sits inside it.
    const subnet = (rules: Rule[]) =>
      policySchema.parse({
        ...policy([]),
        instances: [
          { id: instanceId, name: "Client", addresses: ["10.22.241.0/24"] },
        ],
        rules: [...rules, catchAll],
      });

    const scope = (before: Rule, after: Rule) =>
      describeChanges(
        policyChanges(subnet([before]), subnet([after])),
        subnet([]).instances,
        [after],
      )[0]!.lines.map((line) => [line.label, line.before, line.after]);

    expect(scope(address, rule)).toEqual([
      ["Instance", "10.22.241.10", "Client"],
    ]);
    expect(scope(rule, global)).toEqual([["Instance", "Client", anyValue]]);
    expect(
      scope(rule, { ...rule, peer: { kind: "gateway" } as const }),
    ).toEqual([["Peer", "10.22.242.99", gatewayValue]]);
  });

  it("records nothing when only bookkeeping changed", () => {
    expect(
      policyChanges(
        policy([rule]),
        policy([{ ...rule, modifiedAt: "2026-10-26T02:00:00.000Z" }]),
      ),
    ).toEqual([]);
  });
});
