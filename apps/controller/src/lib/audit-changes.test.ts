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
    ruleSets: [],
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

    const [update, settings] = describeChanges(
      changes,
      policy([]).instances,
      [],
      [changed],
    );

    expect(update!.title).toBe("Changed rule");
    expect(update!.rule).toEqual(changed);
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
      [],
    );

    expect(deleted!.title).toBe("Deleted Allow rule");
    expect(deleted!.rule).toEqual(rule);
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
        [],
        [after],
      )[0]!.lines.map((line) => [line.label, line.before, line.after]);

    expect(scope(address, rule)).toEqual([
      ["Applies to", "10.22.241.10", "Client"],
    ]);
    expect(scope(rule, global)).toEqual([["Applies to", "Client", anyValue]]);
    expect(
      scope(rule, { ...rule, peer: { kind: "gateway" } as const }),
    ).toEqual([["Peer", "10.22.242.99", gatewayValue]]);
  });

  it("describes rule set changes and names the set a rule belongs to", () => {
    const ruleSetId = "44444444-4444-4444-8444-444444444444";

    const withSets = (
      rules: Rule[],
      ruleSets: Policy["ruleSets"],
      instances = policy([]).instances,
    ) =>
      policySchema.parse({
        ...policy([]),
        rules: [...rules, catchAll],
        instances,
        ruleSets,
      });

    const unattached = {
      id: ruleSetId,
      name: "Web",
      members: { kind: "instances" as const, instanceIds: [] },
    };

    const attached = {
      ...unattached,
      name: "Web access",
      members: { kind: "instances" as const, instanceIds: [instanceId] },
    };

    const moved = {
      ...rule,
      subject: { kind: "ruleSet", ruleSetId },
    } satisfies Rule;

    const describe = (before: Policy, after: Policy) =>
      describeChanges(
        policyChanges(before, after),
        after.instances,
        after.ruleSets,
        after.rules,
      ).map((view) => [
        view.title,
        view.lines.map((line) => [line.label, line.before, line.after]),
      ]);

    // Saving an instance's rule as a set adds the set and moves the rule.
    expect(
      describe(withSets([rule], []), withSets([moved], [attached])),
    ).toEqual([
      ["Added rule set: Web access", [["Attached to", null, "Client"]]],
      ["Changed rule", [["Applies to", "Client", "Web access"]]],
    ]);
    expect(
      describe(withSets([], [unattached]), withSets([], [attached])),
    ).toEqual([
      [
        "Changed rule set: Web access",
        [
          ["Name", "Web", "Web access"],
          ["Attached to", "None", "Client"],
        ],
      ],
    ]);
    expect(
      describe(
        withSets([], [attached]),
        withSets([], [{ ...attached, members: { kind: "global" } }]),
      ),
    ).toEqual([
      // An update records its changed fields only; the entry itself names the set.
      ["Changed rule set", [["Attached to", "Client", anyValue]]],
    ]);

    // Deleting a set deletes its rules; removing an instance detaches it.
    expect(
      describe(withSets([moved], [attached]), withSets([], [])).map(
        ([title]) => title,
      ),
    ).toEqual(["Deleted rule set: Web access", "Deleted Allow rule"]);
    expect(
      describe(
        withSets([], [attached]),
        withSets([], [{ ...attached, members: unattached.members }], []),
      ),
    ).toEqual([
      ["Removed instance: Client", [["Addresses", "10.22.241.10", null]]],
      ["Changed rule set", [["Attached to", "Removed instance", "None"]]],
    ]);
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
