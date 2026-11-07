import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ServiceError } from "@traffic-policy/core/io";
import type { Settings } from "@traffic-policy/contracts";
import { ControllerStore } from "./store.ts";
import { saveInstance, store } from "./services.ts";

const admin = { actor: "Admin", client: null };

const settings: Settings = {
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
  mkdirSync(join(process.cwd(), ".tmp/tests"), { recursive: true });
  directory = mkdtempSync(join(process.cwd(), ".tmp/tests/services-test-"));

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
