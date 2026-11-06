import { afterEach, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import {
  policySchema,
  type Policy,
  type Settings,
  type GatewayReceipt,
} from "@traffic-policy/contracts";
import type { requestJson } from "@traffic-policy/core/io";
import type { gatewayHealthSchema } from "@traffic-policy/contracts/dashboard";
import { hashDocument, ServiceError } from "@traffic-policy/core/io";
import { DatabaseSync } from "node:sqlite";
import { ControllerStore } from "./store.ts";
import { deliverPolicy, exclusive } from "./machine.ts";

const directories: string[] = [];

const settings: Settings = {
  dnsGraceSeconds: 0,
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

const config = {
  gatewayUrl: "https://gateway.example.test:9443",
  tls: {
    ca: "/fixture/ca.pem",
    certificate: "/fixture/cert.pem",
    key: "/fixture/key.pem",
  },
};

afterEach(() => {
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true });
});

async function controller() {
  const directory = mkdtempSync(
    join(process.cwd(), ".tmp/tests/machine-test-"),
  );

  directories.push(directory);

  const store = new ControllerStore(
    join(directory, "controller.sqlite3"),
    true,
  );

  await store.setup("fixture-only-password-long-enough", settings);

  return store;
}

const receipt = (policy: Policy): GatewayReceipt => ({
  protocolVersion: 1,
  revision: policy.revision,
  policyHash: hashDocument(policy),
  bootId: randomUUID(),
  appliedAt: new Date().toISOString(),
  permissions: 0,
});

// Answers a PUT with the submitted policy's receipt and a status read with `status`.
function gateway(status?: () => ReturnType<typeof gatewayHealthSchema.parse>) {
  return vi.fn<typeof requestJson>(
    async (url, _tls, method = "GET", body, _timeout, onResponse) => {
      onResponse?.();

      if (method === "PUT") return receipt(policySchema.parse(body));
      expect(url.pathname).toBe("/v1/status");

      if (!status) throw new Error("Unexpected gateway status request");

      return status();
    },
  );
}

it.each(["not_initialized", "enforcement_restore_failed"])(
  "sends the desired policy again when the gateway reports %s",
  async (code) => {
    const store = await controller();
    await deliverPolicy(store, config, gateway());
    expect(store.status().pending).toBe(false);

    const request = gateway(() => {
      throw new ServiceError(503, code, "No policy is confirmed");
    });

    await deliverPolicy(store, config, request);
    expect(request.mock.calls.map((call) => call[2] ?? "GET")).toEqual([
      "GET",
      "PUT",
    ]);
    expect(store.status()).toMatchObject({ pending: false, lastError: null });
  },
);

it("sends the desired policy again when the gateway restored another revision", async () => {
  const store = await controller();
  const first = store.desired();
  await deliverPolicy(store, config, gateway());

  const second = store.mutation(
    first.revision,
    "settings-updated",
    "Settings",
    (value) => value,
  );

  await deliverPolicy(store, config, gateway());
  expect(store.status().appliedRevision).toBe(second.revision);

  const request = gateway(() => ({ receipt: receipt(first) }));

  await deliverPolicy(store, config, request);
  expect(request).toHaveBeenLastCalledWith(
    expect.any(URL),
    config.tls,
    "PUT",
    second,
    undefined,
    expect.any(Function),
  );
  expect(store.status().appliedRevision).toBe(second.revision);
});

it.each(["health", "policy"])(
  "records authenticated %s replies separately from policy success and connection failures",
  async (operation) => {
    const store = await controller();
    await deliverPolicy(store, config, gateway());

    const healthy = gateway(() => ({ receipt: receipt(store.desired()) }));
    await deliverPolicy(store, config, healthy);
    expect(healthy).toHaveBeenCalledTimes(1);

    if (operation === "policy")
      store.mutation(
        store.desired().revision,
        "settings-updated",
        "Settings",
        (value) => value,
      );

    const oldContact = "2026-01-01T00:00:00.000Z";
    const sql = new DatabaseSync(store.path);
    sql.prepare("UPDATE policy SET last_seen=?").run(oldContact);
    sql.close();

    const refused = vi.fn<typeof requestJson>(
      async (_url, _tls, _method, _body, _timeout, onResponse) => {
        onResponse?.();
        throw new ServiceError(
          503,
          "kernel_operation_failed",
          "nft rejected rules",
        );
      },
    );

    await expect(deliverPolicy(store, config, refused)).rejects.toThrow(
      "nft rejected rules",
    );
    expect(refused.mock.calls[0]![0].pathname).toBe(
      operation === "health" ? "/v1/status" : "/v1/policy",
    );
    const repliedAt = store.status().lastSeen;

    expect(repliedAt).not.toBeNull();
    expect(repliedAt).not.toBe(oldContact);
    expect(store.status()).toMatchObject({
      pending: operation === "policy",
      lastError: "nft rejected rules",
    });

    const unavailable = vi.fn<typeof requestJson>(async () => {
      throw new Error("Gateway is down");
    });

    await expect(deliverPolicy(store, config, unavailable)).rejects.toThrow(
      "Gateway is down",
    );
    expect(unavailable).toHaveBeenCalledTimes(1);
    expect(store.status().lastError).toBe("Gateway is down");
    expect(store.status().lastSeen).toBe(repliedAt);
  },
);

// The browser process saves a newer revision while the machine process waits on the gateway; the
// older delivery's outcome must leave the newer revision's requests applying.
it.each(["confirmed", "failed"])(
  "leaves a newer revision's requests applying when the older delivery is %s",
  async (outcome) => {
    const web = await controller();
    const machine = new ControllerStore(web.path);
    const first = web.desired();

    const request = vi.fn<typeof requestJson>(
      async (_url, _tls, _method, body) => {
        web.mutation(
          first.revision,
          "settings-updated",
          "Settings",
          (value) => value,
        );

        const sql = new DatabaseSync(web.path);
        const at = new Date().toISOString();

        sql
          .prepare(
            "INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?,json_array(json_object('value','10.22.241.10','at','2026-01-01T00:00:00.000Z')))",
          )
          .run(
            "newer",
            randomUUID(),
            "outgoing",
            "203.0.113.10",
            6,
            443,
            "1",
            at,
            at,
            first.rules[0]!.id,
            "applying",
          );
        sql.close();

        if (outcome === "failed") throw new Error("Gateway is down");

        return receipt(policySchema.parse(body));
      },
    );

    try {
      const delivery = deliverPolicy(machine, config, request);

      if (outcome === "failed")
        await expect(delivery).rejects.toThrow("Gateway is down");
      else await delivery;

      expect(machine.status()).toMatchObject(
        outcome === "failed"
          ? { lastError: "Gateway is down" }
          : { appliedRevision: first.revision, pending: true },
      );
      expect(machine.requests().requests.map((value) => value.state)).toEqual([
        "applying",
      ]);
    } finally {
      machine.close();
    }
  },
);

it("fails the requests of the revision whose delivery failed", async () => {
  const store = await controller();
  const sql = new DatabaseSync(store.path);
  const at = new Date().toISOString();

  sql
    .prepare(
      "INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?,json_array(json_object('value','10.22.241.10','at','2026-01-01T00:00:00.000Z')))",
    )
    .run(
      "current",
      randomUUID(),
      "outgoing",
      "203.0.113.10",
      6,
      443,
      "1",
      at,
      at,
      store.desired().rules[0]!.id,
      "applying",
    );
  sql.close();

  await expect(
    deliverPolicy(
      store,
      config,
      vi.fn<typeof requestJson>(async () => {
        throw new Error("Gateway is down");
      }),
    ),
  ).rejects.toThrow("Gateway is down");
  expect(store.requests().requests.map((value) => value.state)).toEqual([
    "failed",
  ]);
});

it("runs work again after a run that finished without awaiting, and once while a run is in flight", async () => {
  let calls = 0;

  const immediate = exclusive(() => {
    calls++;
  });

  await immediate.run();
  await immediate.run();
  expect(calls).toBe(2);
  expect(immediate.running).toBeNull();

  let release!: () => void;

  const slow = exclusive(
    () =>
      new Promise<void>((resolve) => {
        calls++;
        release = resolve;
      }),
  );

  const first = slow.run();

  expect(slow.run()).toBe(first);
  await Promise.resolve();
  release();
  await first;
  expect(calls).toBe(3);
  expect(slow.running).toBeNull();
});
