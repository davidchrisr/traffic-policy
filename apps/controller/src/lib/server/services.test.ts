import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ServiceError } from "@traffic-policy/core/io";
import type { Settings } from "@traffic-policy/contracts";
import { ControllerStore } from "./store.ts";
import {
  createRuleSet,
  deleteRuleSet,
  removeInstance,
  saveInstance,
  saveRule,
  saveRuleSet,
  store,
} from "./services.ts";

const admin = { actor: "Admin", client: null };

const settings: Settings = {
  dnsReleaseMode: "require-allow",
  dnsGraceSeconds: 7200,
  permissionLimit: 4096,
  trafficHistoryBytes: "268435456",
  dnsHistoryBytes: "134217728",
  blockedHistoryBytes: "106954752",
  otherHistoryBytes: "27262976",
  auditBytes: "134217728",
  collectorBytes: "134217728",
  gatewayDiskBytes: "4294967296",
  controllerDiskBytes: "8589934592",
  historyMaxAgeDays: null,
  auditMaxAgeDays: null,
  localNetworks: [],
  reverseDnsResolver: null,
};

let directory = "";

// The services open the store named by the controller config, as they do in the service.
beforeAll(async () => {
  mkdirSync(join(process.cwd(), ".local/tmp/tests"), { recursive: true });
  directory = mkdtempSync(
    join(process.cwd(), ".local/tmp/tests/services-test-"),
  );

  const database = join(directory, "controller.sqlite3");
  const config = join(directory, "controller.json");

  writeFileSync(
    config,
    JSON.stringify({
      database,
      listenAddress: "127.0.0.1",
      browserPort: 9444,
      machinePort: 9445,
      browserTransport: "http-local-test",
      publicOrigin: "http://localhost:9444",
      gatewayUrl: "https://gateway.example.test:9443",
      gatewayIdentity: "traffic-policy-gateway",
      tls: {
        ca: "/unused/ca.crt",
        certificate: "/unused/c.crt",
        key: "/unused/c.key",
      },
    }),
  );
  process.env.TP_CONTROLLER_CONFIG = config;

  const setup = new ControllerStore(database, true);
  await setup.setup("fixture-only-password-long-enough", settings);
  setup.close();
});

afterAll(() => {
  store().close();
  delete process.env.TP_CONTROLLER_CONFIG;
  rmSync(directory, { recursive: true });
});

describe("instance mutations", () => {
  it("assigns a created instance's identity and refuses a replayed create", () => {
    const revision = store().desired().revision;

    const input = {
      expectedRevision: revision,
      instance: { name: "Client", addresses: ["10.22.241.10"] },
    };

    const created = saveInstance(admin, input);

    expect(created.instances).toHaveLength(1);
    expect(created.instances[0]).toMatchObject({
      id: expect.stringMatching(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
      name: "Client",
    });

    // A retry after a lost response carries the revision the create already advanced.
    expect(() => saveInstance(admin, input)).toThrow(
      expect.objectContaining({ status: 409 }),
    );
    expect(store().desired().instances).toHaveLength(1);
  });

  it("updates an instance by identity and keeps that identity", () => {
    const [existing] = store().desired().instances;

    const updated = saveInstance(
      admin,
      {
        expectedRevision: store().desired().revision,
        instance: {
          name: "Client",
          addresses: ["10.22.241.10", "10.22.241.11"],
        },
      },
      existing!.id,
    );

    expect(updated.instances).toEqual([
      {
        id: existing!.id,
        name: "Client",
        addresses: ["10.22.241.10", "10.22.241.11"],
      },
    ]);
  });

  it("refuses identity in input and updates of a removed instance", () => {
    const expectedRevision = store().desired().revision;

    expect(() =>
      saveInstance(admin, {
        expectedRevision,
        instance: {
          id: "11111111-1111-4111-8111-111111111111",
          name: "Client",
          addresses: ["10.22.241.12"],
        },
      }),
    ).toThrow();

    let failure: unknown;

    try {
      saveInstance(
        admin,
        {
          expectedRevision,
          instance: { name: "Gone", addresses: ["10.22.241.13"] },
        },
        "22222222-2222-4222-8222-222222222222",
      );
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(ServiceError);
    expect(failure).toMatchObject({ status: 404, code: "instance_not_found" });
    expect(store().desired().revision).toBe(expectedRevision);
  });
});

describe("rule set mutations", () => {
  const revision = () => store().desired().revision;

  const web = {
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
    reason: "",
  };

  const unattached = { kind: "instances", instanceIds: [] };

  const inSet = (id: string) =>
    store()
      .desired()
      .rules.filter(
        (rule) =>
          rule.subject.kind === "ruleSet" && rule.subject.ruleSetId === id,
      );

  const audit = (action: string) =>
    store()
      .history()
      .audit.find((event) => event.action === action);

  // The service error a refused mutation throws, or null when it throws none.
  const refusal = (run: () => void): ServiceError | null => {
    try {
      run();
    } catch (error) {
      if (error instanceof ServiceError) return error;
    }

    return null;
  };

  let imported = "";

  it("creates an unattached set from a file's rules and assigns every identity", () => {
    const before = store().desired().rules.length;

    const { id, policy } = createRuleSet(admin, {
      expectedRevision: revision(),
      ruleSet: { name: " Web access ", members: unattached },
      rules: [web, { ...web, peer: { kind: "ip", value: "192.0.2.10" } }],
      move: [],
    });

    imported = id;
    expect(policy.ruleSets).toEqual([
      { id, name: "Web access", members: unattached },
    ]);
    expect(policy.rules).toHaveLength(before + 2);
    expect(inSet(id).map((rule) => rule.peer)).toEqual([
      { kind: "hostname", value: "api.example.com" },
      { kind: "ip", value: "192.0.2.10" },
    ]);
    expect(new Set(inSet(id).map((rule) => rule.id)).size).toBe(2);
    expect(
      audit("rule-set-created")?.changes.map((change) => [
        change.subject,
        change.before === null,
      ]),
    ).toEqual([
      ["ruleSet", true],
      ["rule", true],
      ["rule", true],
    ]);
  });

  it("moves an instance's rules into a new set attached to it and keeps their identities", () => {
    const [instance] = store().desired().instances;

    const created = saveRule(admin, {
      expectedRevision: revision(),
      rule: {
        ...web,
        subject: { kind: "instance", instanceId: instance!.id },
        reason: "Kept across the move",
      },
    });

    const rule = created.rules.find(
      (value) => value.reason === "Kept across the move",
    )!;

    const members = { kind: "instances", instanceIds: [instance!.id] };

    const { id, policy } = createRuleSet(admin, {
      expectedRevision: revision(),
      ruleSet: { name: "Client rules", members },
      rules: [],
      move: [rule.id],
    });

    expect(policy.ruleSets.find((value) => value.id === id)?.members).toEqual(
      members,
    );
    expect(inSet(id)).toEqual([
      {
        ...rule,
        subject: { kind: "ruleSet", ruleSetId: id },
        modifiedAt: expect.any(String),
      },
    ]);
    expect(
      audit("rule-set-created")?.changes.map((change) => [
        change.subject,
        change.id,
        change.after,
      ]),
    ).toEqual([
      ["ruleSet", id, { id, name: "Client rules", members }],
      ["rule", rule.id, { subject: { kind: "ruleSet", ruleSetId: id } }],
    ]);
  });

  it("refuses to move a missing rule or the Settings catch-all, and changes nothing", () => {
    const expectedRevision = revision();
    const ruleSet = { name: "Refused", members: unattached };

    const catchAll = store()
      .desired()
      .rules.find(
        (rule) => rule.subject.kind === "global" && rule.peer.kind === "any",
      )!;

    expect(
      refusal(() =>
        createRuleSet(admin, {
          expectedRevision,
          ruleSet,
          rules: [],
          move: ["33333333-3333-4333-8333-333333333333"],
        }),
      ),
    ).toMatchObject({ status: 404, code: "rule_not_found" });
    expect(
      refusal(() =>
        createRuleSet(admin, {
          expectedRevision,
          ruleSet,
          rules: [],
          move: [catchAll.id],
        }),
      ),
    ).toMatchObject({ status: 400, code: "catch_all_in_settings" });
    // A rule in a file carries no identity or subject of its own.
    expect(() =>
      createRuleSet(admin, {
        expectedRevision,
        ruleSet,
        rules: [{ ...web, subject: { kind: "global" } }],
        move: [],
      }),
    ).toThrow();
    expect(revision()).toBe(expectedRevision);
    expect(store().desired().ruleSets).toHaveLength(2);
  });

  it("renames a set and changes its attachments without touching its rules", () => {
    const [instance] = store().desired().instances;
    const rules = inSet(imported);

    const renamed = saveRuleSet(admin, imported, {
      expectedRevision: revision(),
      ruleSet: {
        name: "Web",
        members: { kind: "instances", instanceIds: [instance!.id] },
      },
    });

    expect(renamed.ruleSets.find((value) => value.id === imported)).toEqual({
      id: imported,
      name: "Web",
      members: { kind: "instances", instanceIds: [instance!.id] },
    });
    expect(inSet(imported)).toEqual(rules);

    const everywhere = saveRuleSet(admin, imported, {
      expectedRevision: revision(),
      ruleSet: { name: "Web", members: { kind: "global" } },
    });

    expect(
      everywhere.ruleSets.find((value) => value.id === imported)?.members,
    ).toEqual({ kind: "global" });
    expect(audit("rule-set-updated")?.changes).toEqual([
      {
        subject: "ruleSet",
        id: imported,
        before: {
          members: { kind: "instances", instanceIds: [instance!.id] },
        },
        after: { members: { kind: "global" } },
      },
    ]);

    const expectedRevision = revision();

    expect(
      refusal(() =>
        saveRuleSet(admin, "33333333-3333-4333-8333-333333333333", {
          expectedRevision,
          ruleSet: { name: "Gone", members: unattached },
        }),
      ),
    ).toMatchObject({ status: 404, code: "rule_set_not_found" });
    // An attachment names an instance of this policy.
    expect(() =>
      saveRuleSet(admin, imported, {
        expectedRevision,
        ruleSet: {
          name: "Web",
          members: {
            kind: "instances",
            instanceIds: ["33333333-3333-4333-8333-333333333333"],
          },
        },
      }),
    ).toThrow();
    expect(revision()).toBe(expectedRevision);
  });

  it("detaches a removed instance from its sets and keeps the sets and their rules", () => {
    const added = saveInstance(admin, {
      expectedRevision: revision(),
      instance: { name: "Disposable", addresses: ["10.22.241.40"] },
    });

    const disposable = added.instances.find(
      (instance) => instance.name === "Disposable",
    )!;

    const kept = added.instances.find(
      (instance) => instance.name === "Client",
    )!;

    saveRuleSet(admin, imported, {
      expectedRevision: revision(),
      ruleSet: {
        name: "Web",
        members: { kind: "instances", instanceIds: [kept.id, disposable.id] },
      },
    });

    const rules = inSet(imported);

    removeInstance(admin, disposable.id, { expectedRevision: revision() });

    expect(
      store()
        .desired()
        .ruleSets.find((value) => value.id === imported)?.members,
    ).toEqual({ kind: "instances", instanceIds: [kept.id] });
    expect(inSet(imported)).toEqual(rules);
    expect(
      audit("instance-removed")?.changes.map((change) => change.subject),
    ).toEqual(["instance", "ruleSet"]);
  });

  it("deletes a set with its rules and leaves every other rule", () => {
    const members = new Set(inSet(imported).map((rule) => rule.id));

    const others = store()
      .desired()
      .rules.filter((rule) => !members.has(rule.id))
      .map((rule) => rule.id);

    const deleted = deleteRuleSet(admin, imported, {
      expectedRevision: revision(),
    });

    expect(deleted.ruleSets.map((value) => value.name)).toEqual([
      "Client rules",
    ]);
    expect(deleted.rules.map((rule) => rule.id)).toEqual(others);
    expect(
      audit("rule-set-deleted")?.changes.map((change) => [
        change.subject,
        change.after,
      ]),
    ).toEqual([
      ["ruleSet", null],
      ["rule", null],
      ["rule", null],
    ]);
    expect(
      refusal(() =>
        deleteRuleSet(admin, imported, { expectedRevision: revision() }),
      ),
    ).toMatchObject({ status: 404, code: "rule_set_not_found" });
  });

  it("requires Admin", () => {
    expect(
      refusal(() =>
        createRuleSet(
          { actor: null, client: null },
          {
            expectedRevision: revision(),
            ruleSet: { name: "Anonymous", members: unattached },
            rules: [],
            move: [],
          },
        ),
      ),
    ).toMatchObject({ status: 401 });
  });
});
