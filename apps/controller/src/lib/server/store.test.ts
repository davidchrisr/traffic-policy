import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import {
  ControllerStore,
  MAX_CONNECTION_REQUESTS,
  MAX_DISMISSED_HOSTS,
  MAX_DNS_REQUESTS,
  MAX_HOST_REQUESTS,
  MAX_INSTANCE_DNS_REQUESTS,
  MAX_PENDING_REQUESTS,
} from "./store.ts";
import { withInstance } from "./services.ts";
import { DatabaseSync } from "node:sqlite";
import type {
  EventBatch,
  GatewayEvent,
  Settings,
} from "@traffic-policy/contracts";
import { hashDocument, ServiceError } from "@traffic-policy/core/io";
import { StorageBudget } from "@traffic-policy/core/storage";
import { eventBatchSchema } from "@traffic-policy/contracts";
import {
  settingsSnapshotSchema,
  instancesSnapshotSchema,
} from "@traffic-policy/contracts/dashboard";

const directories: string[] = [];

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

const retentionEvent = (): GatewayEvent => ({
  id: randomUUID(),
  observedAt: new Date().toISOString(),
  type: "dns",
  instanceId: null,
  direction: null,
  peerIp: null,
  protocol: null,
  port: null,
  sentBytes: "0",
  receivedBytes: "0",
  ruleId: null,
  question: "retention.example",
  source: "resolver-gate",
  details: { outcome: "confirmed", padding: "x".repeat(64) },
});

afterEach(() => {
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true });
});

async function database() {
  const directory = mkdtempSync(join(process.cwd(), ".tmp/tests/store-test-"));

  directories.push(directory);

  const store = new ControllerStore(
    join(directory, "controller.sqlite3"),
    true,
  );

  await store.setup("fixture-only-password-long-enough", settings);

  return store;
}

describe("controller contracts and persistence", () => {
  it("persists denied DNS scopes, deduplicates replay, and resolves them only after current policy confirmation", async () => {
    const store = await database();
    const instanceId = randomUUID();
    let reopened: ControllerStore | null = null;

    try {
      store.mutation("1", "instance-created", instanceId, (policy) => ({
        ...policy,
        instances: [
          { id: instanceId, name: "Client", addresses: ["10.22.241.10"] },
        ],
      }));

      const denied: GatewayEvent = {
        ...retentionEvent(),
        instanceId,
        question: "api.example.com",
        details: {
          outcome: "policy-denied",
          queryType: "AAAA",
          clientIp: "10.22.241.10",
          catchall: true,
          appliedRevision: "2",
          policyHash: "a".repeat(64),
        },
      };

      const batch: EventBatch = {
        protocolVersion: 1,
        epoch: randomUUID(),
        sequence: "1",
        events: [denied],
      };

      store.ingest(batch);
      store.ingest(batch);
      expect(store.requests().requests).toMatchObject([
        {
          kind: "dns",
          question: denied.question,
          queryType: "AAAA",
          attempts: "1",
          state: "needs-review",
          ruleId: null,
        },
      ]);
      expect(store.requests().requests[0]).not.toHaveProperty("peerIp");
      expect(store.status().needsReview).toBe(1);
      expect(store.resources().requestsUsedBytes).toBe("512");
      // Another query type for the name updates the same Request.
      store.ingest({
        ...batch,
        sequence: "2",
        events: [
          {
            ...denied,
            id: randomUUID(),
            details: { ...denied.details, queryType: "A" },
          },
        ],
      });
      expect(store.requests().requests).toMatchObject([
        { queryType: "A", attempts: "2" },
      ]);
      store.close();
      reopened = new ControllerStore(store.path);
      expect(reopened.requests().requests[0]?.attempts).toBe("2");
      const active = reopened;

      const allow = {
        ...active.desired().rules[0]!,
        id: randomUUID(),
        subject: { kind: "instance" as const, instanceId },
        direction: "outgoing" as const,
        peer: { kind: "hostname" as const, value: "api.example.com" },
        action: "allow" as const,
        protocol: 6,
        ports: [{ start: 443, end: 443 }],
      };

      const policy = active.mutation(
        "2",
        "rule-created",
        allow.id,
        (value) => ({ ...value, rules: [...value.rules, allow] }),
      );

      expect(active.requests().requests[0]?.state).toBe("applying");

      // A denial recorded under the previous policy that arrives after the save stays applying.
      const late = (id = randomUUID()) => ({
        protocolVersion: 1 as const,
        epoch: randomUUID(),
        sequence: "1",
        events: [{ ...denied, id }],
      });

      active.ingest(late());
      expect(active.requests().requests[0]).toMatchObject({
        state: "applying",
        attempts: "3",
      });
      active.deliveryFailed("Controlled delivery failure", policy.revision);
      expect(active.requests().requests[0]?.state).toBe("failed");
      active.confirm(policy, {
        protocolVersion: 1,
        revision: policy.revision,
        policyHash: hashDocument(policy),
        bootId: randomUUID(),
        appliedAt: new Date().toISOString(),
        permissions: 0,
      });
      expect(active.requests().requests).toEqual([]);
      expect(active.resources().requestsUsedBytes).toBe("0");
      active.ingest({
        ...batch,
        sequence: "3",
        events: [
          {
            ...denied,
            id: randomUUID(),
            details: { ...denied.details, catchall: false },
            ruleId: allow.id,
          },
        ],
      });
      expect(active.requests().requests).toEqual([]);

      // Once the Allow is confirmed, a late denial from before it does not reopen the request.
      active.ingest(late());
      expect(active.requests().requests).toEqual([]);
      expect(active.status().needsReview).toBe(0);

      // Denied names the gateway left out are totaled from momentary conditions, which do not stay
      // active.
      expect(active.requests().retention.dnsOmitted).toBe("0");

      for (const occurrences of [7, 5])
        active.ingest({
          ...late(),
          events: [
            {
              ...retentionEvent(),
              type: "condition",
              source: "gateway",
              question: null,
              details: {
                code: "dns_denials_omitted",
                message: "Denied names were not recorded",
                occurrences,
                recovered: true,
              },
            },
          ],
        });
      expect(active.requests().retention).toMatchObject({
        dnsOmitted: "12",
        lastDnsOmittedAt: expect.any(String),
      });
      expect(
        active
          .status()
          .conditions.find(({ code }) => code === "dns_denials_omitted"),
      ).toMatchObject({ occurrences: "12", recoveredAt: expect.any(String) });
    } finally {
      if (reopened) reopened.close();
      else store.close();
    }
  });

  it("keeps connection and DNS requests in separate pools, with a DNS share for each instance", async () => {
    const store = await database();
    const sql = new DatabaseSync(store.path);

    try {
      const ids = Array.from({ length: 11 }, () => randomUUID());

      store.mutation("1", "instance-created", ids[0]!, (policy) => ({
        ...policy,
        instances: ids.map((id, index) => ({
          id,
          name: `Client ${index}`,
          addresses: [`10.22.241.${10 + index}`],
        })),
      }));
      sql
        .prepare(
          "INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?,json_array(json_object('value','10.22.241.10','at','2026-01-01T00:00:00.000Z')))",
        )
        .run(
          "old-connection",
          ids[0]!,
          "outgoing",
          "192.0.2.1",
          6,
          443,
          "1",
          "2026-01-01T00:00:00.000Z",
          "2026-01-01T00:00:00.000Z",
          store.desired().rules[0]!.id,
          "needs-review",
        );
      sql.exec("BEGIN IMMEDIATE");

      const insert = sql.prepare(
        "INSERT INTO dns_requests VALUES(?,?,?,?,?,?,?,?,?,json_array(json_object('value','10.22.241.10','at','2026-01-01T00:00:00.000Z')))",
      );

      const lookup = (id: string, instanceId: string, minute: number) => {
        const at = new Date(
          Date.UTC(2026, 9, 1) + minute * 60000,
        ).toISOString();

        insert.run(
          id,
          instanceId,
          `${id}.example`,
          "A",
          "1",
          at,
          at,
          null,
          "needs-review",
        );
      };

      // The first instance looks up 100 names beyond its share, all older than the others' lookups.
      for (let i = 0; i < MAX_INSTANCE_DNS_REQUESTS + 100; i++)
        lookup(`first-${i}`, ids[0]!, i);

      for (const [n, id] of ids.slice(1).entries())
        for (let i = 0; i < MAX_INSTANCE_DNS_REQUESTS; i++)
          lookup(`other-${n}-${i}`, id, 1000 * (n + 1) + i);
      sql.exec("COMMIT");
      store.ingest({
        protocolVersion: 1,
        epoch: randomUUID(),
        sequence: "1",
        events: [],
      });

      const count = (sql_: string) => Number(sql.prepare(sql_).get()!.count);

      // 100 of the first instance's oldest leave its share; the DNS pool then holds 5,500, and its
      // 500 oldest, the first instance's remainder, leave too. The connection request stays.
      expect(count("SELECT COUNT(*) AS count FROM requests")).toBe(1);
      expect(count("SELECT COUNT(*) AS count FROM dns_requests")).toBe(
        MAX_DNS_REQUESTS,
      );
      expect(
        count(
          `SELECT COUNT(*) AS count FROM dns_requests WHERE instance_id='${ids[0]}'`,
        ),
      ).toBe(0);
      expect(store.requests().retention).toMatchObject({
        pending: MAX_DNS_REQUESTS + 1,
        limit: MAX_PENDING_REQUESTS,
        discarded: "600",
      });
      expect(store.resources().requestsUsedBytes).toBe(
        String((MAX_DNS_REQUESTS + 1) * 512),
      );
      store.removeInstance(store.desired().revision, ids[0]!);
      expect(store.requests().retention.pending).toBe(MAX_DNS_REQUESTS);
    } finally {
      sql.close();
      store.close();
    }
  });
  it("trims exact oldest prefixes across multiple chunks and rolls back a failed retention update", async () => {
    const store = await database();
    const sql = new DatabaseSync(store.path);
    const at = new Date().toISOString();

    const events = Array.from({ length: 300 }, () => ({
      ...retentionEvent(),
      observedAt: at,
    }));

    const bytes = Buffer.byteLength(JSON.stringify(events[0])) + 256;

    const ids = () =>
      sql
        .prepare("SELECT id FROM events ORDER BY rowid")
        .all()
        .map((row) => row.id);

    try {
      store.ingest({
        protocolVersion: 1,
        epoch: randomUUID(),
        sequence: "1",
        events,
      });

      const first = store.mutation(
        store.desired().revision,
        "settings-updated",
        "Settings",
        (policy) => ({
          ...policy,
          settings: {
            ...policy.settings,
            dnsHistoryBytes: String(bytes * 150),
          },
        }),
      );

      expect(ids()).toEqual(events.slice(150).map((event) => event.id));
      expect(
        sql
          .prepare("SELECT bytes FROM storage_usage WHERE name='events:dns'")
          .get()?.bytes,
      ).toBe(bytes * 150);
      sql.exec(
        `CREATE TRIGGER retention_failure BEFORE DELETE ON events WHEN OLD.id='${events[150]!.id}' BEGIN SELECT RAISE(ABORT,'forced history failure'); END;`,
      );
      expect(() =>
        store.mutation(
          first.revision,
          "settings-updated",
          "Settings",
          (policy) => ({
            ...policy,
            settings: {
              ...policy.settings,
              dnsHistoryBytes: String(bytes * 100),
            },
          }),
        ),
      ).toThrow("forced history failure");
      expect(ids()).toEqual(events.slice(150).map((event) => event.id));
      expect(store.desired().revision).toBe(first.revision);
      expect(
        sql
          .prepare("SELECT bytes FROM storage_usage WHERE name='events:dns'")
          .get()?.bytes,
      ).toBe(bytes * 150);
      sql.exec("DROP TRIGGER retention_failure");
      store.mutation(
        first.revision,
        "settings-updated",
        "Settings",
        (policy) => ({
          ...policy,
          settings: {
            ...policy.settings,
            dnsHistoryBytes: String(bytes * 100),
          },
        }),
      );
      expect(ids()).toEqual(events.slice(200).map((event) => event.id));
    } finally {
      sql.close();
      store.close();
    }
  });
  it("trims a large excess in bounded slices, oldest first across traffic events and metrics", async () => {
    const store = await database();
    const sql = new DatabaseSync(store.path);
    const start = Date.now() - 3600000;

    try {
      store.mutation(
        store.desired().revision,
        "settings-updated",
        "Settings",
        (policy) => ({
          ...policy,
          settings: { ...policy.settings, trafficHistoryBytes: "512000" },
        }),
      );

      // Interleaved traffic events and metric rows, each charged 512 bytes, inserted without
      // retention as if a save had just shrunk the allocation under them.
      const event = sql.prepare(
        "INSERT INTO events(id,at,type,instance_id,peer_ip,question,source,details) VALUES(?,?,'traffic',NULL,NULL,NULL,'conntrack',?)",
      );

      const metric = sql.prepare(
        "INSERT INTO metrics VALUES('i','outgoing','203.0.113.1',6,?,5,?,'1','1',1)",
      );

      const details = JSON.stringify({ p: "x".repeat(248) });

      sql.exec("BEGIN");

      for (let index = 0; index < 1200; index++) {
        event.run(
          `event-${index}`,
          new Date(start + index * 2000).toISOString(),
          details,
        );
        metric.run(index, new Date(start + index * 2000 + 1000).toISOString());
      }

      sql.exec("COMMIT");

      // A slice whose time is already up still makes one chunk of progress: 512 events and the
      // 511 metric rows older than the next unread event.
      let calls = 1;

      expect(store.prune(0)).toBe(false);
      expect(
        Number(
          sql
            .prepare(
              "SELECT (SELECT COUNT(*) FROM events)+(SELECT COUNT(*) FROM metrics) AS n",
            )
            .get()!.n,
        ),
      ).toBe(2400 - 1023);

      while (!store.prune(0)) calls++;
      calls++;
      expect(calls).toBe(2);

      const kept = sql
        .prepare(
          "SELECT at FROM events UNION ALL SELECT bucket FROM metrics ORDER BY 1",
        )
        .all()
        .map((row) => String(row.at));

      // The newest 1,000 rows of both kinds remain.
      expect(kept).toHaveLength(1000);
      expect(kept[0]).toBe(new Date(start + 1400 * 1000).toISOString());
      expect(
        sql
          .prepare(
            "SELECT SUM(bytes) AS bytes FROM storage_usage WHERE name IN ('events:traffic','metrics')",
          )
          .get()!.bytes,
      ).toBe(512000);
    } finally {
      sql.close();
      store.close();
    }
  });
  it("preserves shared event and metric retention ordering and exact byte accounting", async () => {
    const store = await database();
    const sql = new DatabaseSync(store.path);
    const start = Math.floor(Date.now() / 5000) * 5000 - 30000;

    const time = (seconds: number) =>
      new Date(start + seconds * 1000).toISOString();

    const events = [5, 5, 15].map((seconds) => ({
      ...retentionEvent(),
      type: "traffic" as const,
      observedAt: time(seconds),
    }));

    const bytes = Buffer.byteLength(JSON.stringify(events[0])) + 256;

    try {
      store.ingest({
        protocolVersion: 1,
        epoch: randomUUID(),
        sequence: "1",
        events,
      });

      const insert = sql.prepare(
        "INSERT INTO metrics VALUES(?,?,?,?,?,?,?,?,?,?)",
      );

      sql.exec("BEGIN IMMEDIATE");

      for (const seconds of [0, 5, 10])
        insert.run(
          "11111111-1111-4111-8111-111111111111",
          "outgoing",
          "10.22.242.20",
          6,
          443,
          5,
          time(seconds),
          "1",
          "2",
          1,
        );
      sql.exec("COMMIT");
      const allocation = bytes + 1024;
      store.mutation(
        store.desired().revision,
        "settings-updated",
        "Settings",
        (policy) => ({
          ...policy,
          settings: {
            ...policy.settings,
            trafficHistoryBytes: String(allocation),
          },
        }),
      );
      expect(
        sql
          .prepare("SELECT id FROM events")
          .all()
          .map((row) => row.id),
      ).toEqual([events[2]!.id]);
      expect(
        sql
          .prepare("SELECT bucket FROM metrics ORDER BY bucket")
          .all()
          .map((row) => row.bucket),
      ).toEqual([time(5), time(10)]);
      expect(
        sql
          .prepare(
            "SELECT SUM(bytes) AS bytes FROM storage_usage WHERE name IN ('events:traffic','metrics')",
          )
          .get()?.bytes,
      ).toBe(allocation);
    } finally {
      if (sql.isTransaction) sql.exec("ROLLBACK");
      sql.close();
      store.close();
    }
  });
  it("reopens committed WAL history while an older reader prevents checkpointing", async () => {
    const original = await database();
    const reader = new DatabaseSync(original.path, { readOnly: true });
    let closed = false;
    let reopened: ControllerStore | null = null;

    const batch = eventBatchSchema.parse({
      protocolVersion: 1,
      epoch: randomUUID(),
      sequence: "1",
      events: Array.from({ length: 1024 }, () => ({
        id: randomUUID(),
        observedAt: new Date().toISOString(),
        type: "dns",
        instanceId: null,
        direction: null,
        peerIp: null,
        protocol: null,
        port: null,
        sentBytes: "0",
        receivedBytes: "0",
        ruleId: null,
        question: "wal.example",
        source: "resolver-gate",
        details: { outcome: "confirmed" },
      })),
    });

    try {
      reader.exec("BEGIN");
      expect(
        reader.prepare("SELECT COUNT(*) AS count FROM events").get()!.count,
      ).toBe(0);
      const receipt = original.ingest(batch);
      expect(statSync(original.path + "-wal").size).toBeGreaterThan(0);
      original.close();
      closed = true;
      reopened = new ControllerStore(original.path);
      expect(reopened.ingest(batch)).toEqual(receipt);
      expect(
        reader.prepare("SELECT COUNT(*) AS count FROM events").get()!.count,
      ).toBe(0);
      const fresh = new DatabaseSync(original.path, { readOnly: true });

      try {
        expect(
          fresh
            .prepare(
              "SELECT COUNT(*) AS count,COUNT(DISTINCT id) AS distinctIds FROM events",
            )
            .get(),
        ).toEqual({ count: 1024, distinctIds: 1024 });
        expect(() =>
          reopened!.ingest({
            ...batch,
            events: [{ ...batch.events[0]!, question: "conflict.example" }],
          }),
        ).toThrow("different observations");

        const guard = vi
          .spyOn(StorageBudget.prototype, "assertRoom")
          .mockImplementationOnce(() => {
            throw new ServiceError(
              507,
              "storage_limit",
              "Pinned WAL fixture budget exhausted",
            );
          });

        try {
          expect(() =>
            reopened!.ingest({
              ...batch,
              sequence: "2",
              events: [{ ...batch.events[0]!, id: randomUUID() }],
            }),
          ).toThrow("Pinned WAL fixture budget exhausted");
          expect(
            fresh.prepare("SELECT COUNT(*) AS count FROM events").get()!.count,
          ).toBe(1024);
        } finally {
          guard.mockRestore();
        }
      } finally {
        fresh.close();
      }
    } finally {
      if (reader.isTransaction) reader.exec("ROLLBACK");
      reader.close();
      reopened?.close();

      if (!closed) original.close();
    }
  });

  it("ingests and replays a large history batch without merging lookup identities", async () => {
    const store = await database();

    const events: GatewayEvent[] = Array.from({ length: 1024 }, () => ({
      id: randomUUID(),
      observedAt: new Date().toISOString(),
      type: "dns",
      instanceId: null,
      direction: null,
      peerIp: null,
      protocol: null,
      port: null,
      sentBytes: "0",
      receivedBytes: "0",
      ruleId: null,
      question: "proof.example",
      source: "resolver-gate",
      details: { outcome: "confirmed" },
    }));

    const batch = eventBatchSchema.parse({
      protocolVersion: 1,
      epoch: randomUUID(),
      sequence: "1",
      events,
    });

    const sql = new DatabaseSync(store.path, { readOnly: true });

    try {
      expect(store.ingest(batch)).toEqual(store.ingest(batch));

      const row = sql
        .prepare(
          "SELECT COUNT(*) AS count, COUNT(DISTINCT id) AS distinctIds FROM events",
        )
        .get()!;

      expect(row.count).toBe(1024);
      expect(row.distinctIds).toBe(1024);
    } finally {
      sql.close();
      store.close();
    }
  });

  it("keeps duplicate events idempotent and rolls back fresh rows before an identity conflict", async () => {
    const store = await database();
    const sql = new DatabaseSync(store.path, { readOnly: true });

    const event: GatewayEvent = {
      id: randomUUID(),
      observedAt: new Date().toISOString(),
      type: "dns",
      instanceId: null,
      direction: null,
      peerIp: null,
      protocol: null,
      port: null,
      sentBytes: "0",
      receivedBytes: "0",
      ruleId: null,
      question: "proof.example",
      source: "resolver-gate",
      details: { outcome: "confirmed" },
    };

    const batch: EventBatch = {
      protocolVersion: 1,
      epoch: randomUUID(),
      sequence: "1",
      events: [event, structuredClone(event)],
    };

    const rows = () =>
      sql.prepare("SELECT id,details FROM events ORDER BY id").all();

    try {
      store.ingest(batch);
      const committed = rows();
      expect(committed).toHaveLength(1);
      store.ingest({ ...batch, sequence: "2", events: [event] });
      expect(rows()).toEqual(committed);
      expect(() =>
        store.ingest({
          ...batch,
          sequence: "3",
          events: [
            { ...event, id: randomUUID() },
            { ...event, question: "conflict.example" },
          ],
        }),
      ).toThrow("different data");
      expect(rows()).toEqual(committed);
      store.ingest({
        ...batch,
        sequence: "3",
        events: [{ ...event, id: randomUUID() }],
      });
      expect(rows()).toHaveLength(2);
      const fresh = { ...event, id: randomUUID() };
      expect(() =>
        store.ingest({
          ...batch,
          sequence: "4",
          events: [fresh, { ...fresh, question: "conflict.example" }],
        }),
      ).toThrow("different data");
      expect(rows()).toHaveLength(2);
    } finally {
      sql.close();
      store.close();
    }
  });

  it("retains every address in a large DNS observation and replays its batch without duplication", async () => {
    const store = await database();

    const addresses = Array.from(
      { length: 256 },
      (_, index) =>
        `1111:2222:3333:4444:5555:6666:7777:${(0x8000 + index).toString(16)}`,
    ).join(", ");

    const event: GatewayEvent = {
      id: randomUUID(),
      observedAt: new Date().toISOString(),
      type: "dns",
      instanceId: null,
      direction: null,
      peerIp: null,
      protocol: null,
      port: null,
      sentBytes: "0",
      receivedBytes: "0",
      ruleId: null,
      question: "large.example",
      source: "resolver-gate",
      details: { outcome: "confirmed", addresses },
    };

    const batch = eventBatchSchema.parse({
      protocolVersion: 1,
      epoch: randomUUID(),
      sequence: "1",
      events: [event],
    });

    try {
      expect(store.ingest(batch)).toEqual(store.ingest(batch));
      expect(store.history().events).toHaveLength(1);
      expect(store.history().events[0]!.id).toBe(event.id);
      expect(store.history().events[0]!.details).toEqual(event.details);
    } finally {
      store.close();
    }
  });
  it("validates real Settings refresh responses and rejects malformed resource counters", async () => {
    const store = await database();

    try {
      const resources = store.resources();
      const policy = store.desired();
      expect(settingsSnapshotSchema.parse(resources).revision).toBe(
        policy.revision,
      );
      expect(resources.catchAll).toEqual({
        outgoing: "block",
        incoming: "block",
      });
      store.mutation(
        policy.revision,
        "policy-reapplied",
        "Gateway",
        (value) => value,
        { address: "192.168.1.10", agent: "Firefox/144.0" },
      );
      expect(
        store
          .history()
          .audit.find((entry) => entry.action === "policy-reapplied")!.client,
      ).toEqual({
        address: "192.168.1.10",
        browser: "Firefox",
      });
      expect(
        instancesSnapshotSchema.parse({
          revision: policy.revision,
          instances: policy.instances,
          rules: policy.rules,
        }).rules,
      ).toEqual(policy.rules);
      expect(() =>
        settingsSnapshotSchema.parse({
          ...resources,
          requestsUsedBytes: "invalid",
        }),
      ).toThrow();
      expect(() =>
        settingsSnapshotSchema.parse({
          ...resources,
          gatewayStorage: { at: new Date().toISOString() },
        }),
      ).toThrow();
    } finally {
      store.close();
    }
  });
  it("resolves a request through a name seen for its address once that name's rule admits it", async () => {
    const store = await database();
    const sql = new DatabaseSync(store.path);
    const instanceId = randomUUID();

    try {
      store.mutation("1", "instance-created", instanceId, (policy) => ({
        ...policy,
        instances: [
          { id: instanceId, name: "Client", addresses: ["10.22.241.10"] },
        ],
      }));

      const at = new Date().toISOString();
      sql
        .prepare(
          "INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?,json_array(json_object('value','10.22.241.10','at','2026-01-01T00:00:00.000Z')))",
        )
        .run(
          "nas",
          instanceId,
          "outgoing",
          "192.168.1.5",
          6,
          445,
          "1",
          at,
          at,
          store.desired().rules[0]!.id,
          "needs-review",
        );
      store.ingest({
        protocolVersion: 1,
        epoch: randomUUID(),
        sequence: "1",
        events: [
          {
            ...retentionEvent(),
            instanceId,
            question: "nas.home",
            details: { outcome: "confirmed", addresses: "192.168.1.5" },
          },
        ],
      });

      const named = {
        ...store.desired().rules[0]!,
        id: randomUUID(),
        direction: "outgoing" as const,
        action: "allow" as const,
        peer: { kind: "hostname" as const, value: "nas.home" },
      };

      const state = () =>
        store.requests().requests.find((request) => request.id === "nas")
          ?.state;

      // Without permitted destination networks the rule refuses the private answer.
      store.mutation(
        store.desired().revision,
        "rule-created",
        named.id,
        (policy) => ({
          ...policy,
          rules: [...policy.rules, named],
        }),
      );
      expect(state()).toBe("needs-review");
      store.mutation(
        store.desired().revision,
        "rule-updated",
        named.id,
        (policy) => ({
          ...policy,
          rules: policy.rules.map((rule) =>
            rule.id === named.id
              ? { ...rule, dnsDestinations: ["192.168.1.5/32"] }
              : rule,
          ),
        }),
      );
      expect(state()).toBe("applying");
    } finally {
      sql.close();
      store.close();
    }
  });
  it("retains newest pending requests, removes resolved rows, accounts storage and reports discards across replay and restart", async () => {
    const store = await database();
    let restored: ControllerStore | null = null;

    const instanceId = randomUUID(),
      ruleId = store.desired().rules[0]!.id;

    store.mutation("1", "instance-created", instanceId, (policy) => ({
      ...policy,
      instances: [
        { id: instanceId, name: "Client", addresses: ["10.22.241.10"] },
      ],
    }));
    const sql = new DatabaseSync(store.path);

    try {
      const insert = sql.prepare(
        "INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?,json_array(json_object('value','10.22.241.10','at','2026-01-01T00:00:00.000Z')))",
      );

      const base = Date.now() - 20000000;
      sql.exec("BEGIN IMMEDIATE");

      for (let i = 0; i < MAX_CONNECTION_REQUESTS + 2; i++) {
        const at = new Date(base + i * 1000).toISOString();
        insert.run(
          `scope-${i}`,
          instanceId,
          "outgoing",
          "10.22.242.20",
          6,
          i,
          "1",
          at,
          at,
          ruleId,
          "needs-review",
        );
      }

      const at = new Date().toISOString();
      insert.run(
        "resolved",
        instanceId,
        "outgoing",
        "10.22.242.20",
        6,
        443,
        "1",
        at,
        at,
        ruleId,
        "resolved",
      );
      sql.exec("COMMIT");

      const batch = {
        protocolVersion: 1 as const,
        epoch: randomUUID(),
        sequence: "1",
        events: [],
      };

      sql.exec(
        "CREATE TRIGGER retention_failure BEFORE DELETE ON requests WHEN OLD.id='scope-0' BEGIN SELECT RAISE(ABORT,'forced retention failure'); END;",
      );
      expect(() => store.ingest(batch)).toThrow("forced retention failure");
      expect(
        sql.prepare("SELECT COUNT(*) AS count FROM requests").get()!.count,
      ).toBe(MAX_CONNECTION_REQUESTS + 3);
      expect(store.requests().retention.discarded).toBe("0");
      sql.exec("DROP TRIGGER retention_failure");
      store.ingest(batch);
      expect(
        sql.prepare("SELECT COUNT(*) AS count FROM requests").get()!.count,
      ).toBe(MAX_CONNECTION_REQUESTS);
      expect(
        sql
          .prepare(
            "SELECT id FROM requests WHERE id IN ('scope-0','scope-1','resolved')",
          )
          .all(),
      ).toEqual([]);
      expect(store.requests().requests[0]!.id).toBe(
        `scope-${MAX_CONNECTION_REQUESTS + 1}`,
      );
      expect(store.requests().retention).toMatchObject({
        pending: MAX_CONNECTION_REQUESTS,
        limit: MAX_PENDING_REQUESTS,
        discarded: "2",
      });
      expect(store.resources().requestsUsedBytes).toBe(
        String(MAX_CONNECTION_REQUESTS * 512),
      );
      store.ingest(batch);
      expect(store.requests().retention.discarded).toBe("2");
      sql.exec(
        "UPDATE requests SET state='resolved' WHERE id IN ('scope-2','scope-3')",
      );
      store.ingest({ ...batch, sequence: "2" });
      expect(store.requests().retention.pending).toBe(
        MAX_CONNECTION_REQUESTS - 2,
      );
      expect(store.resources().requestsUsedBytes).toBe(
        String((MAX_CONNECTION_REQUESTS - 2) * 512),
      );
      store.close();
      restored = new ControllerStore(store.path);
      expect(restored.requests().retention).toMatchObject({
        pending: MAX_CONNECTION_REQUESTS - 2,
        discarded: "2",
      });
      expect(restored.resources().requestsUsedBytes).toBe(
        String((MAX_CONNECTION_REQUESTS - 2) * 512),
      );
    } finally {
      sql.close();

      if (restored) restored.close();
      else store.close();
    }
  });
  it("acknowledges committed replay under failed capacity checks while rejecting changed, stale and new batches", async () => {
    const store = await database();

    const batch: EventBatch = {
      protocolVersion: 1,
      epoch: randomUUID(),
      sequence: "1",
      events: [],
    };

    const expected = store.ingest(batch);

    const capacity = vi
      .spyOn(StorageBudget.prototype, "assertRoom")
      .mockImplementation(() => {
        throw new ServiceError(507, "disk_full", "full");
      });

    try {
      expect(store.ingest(batch)).toEqual(expected);
      expect(capacity).not.toHaveBeenCalled();
      expect(() =>
        store.ingest({
          ...batch,
          events: [{ id: randomUUID() } as GatewayEvent],
        }),
      ).toThrow("different observations");
      expect(() => store.ingest({ ...batch, sequence: "0" })).toThrow(
        "persisted delivery cursor",
      );
      expect(() => store.ingest({ ...batch, sequence: "2" })).toThrow("full");
      expect(capacity).toHaveBeenCalledTimes(1);
    } finally {
      capacity.mockRestore();
      store.close();
    }
  });
  it("rejects an oversized desired policy atomically before advancing its revision", async () => {
    const store = await database();

    try {
      const before = store.desired(),
        auditCount = store.history().audit.length;

      expect(() =>
        store.mutation(
          before.revision,
          "rule-created",
          "fixture",
          (previous) => ({
            ...previous,
            rules: [
              previous.rules[0]!,
              ...Array.from({ length: 2049 }, () => ({
                ...previous.rules[0]!,
                id: randomUUID(),
                direction: "outgoing" as const,
                peer: { kind: "ip" as const, value: "198.51.100.2" },
                protocol: 6,
                reason: "x".repeat(1024),
              })),
            ],
          }),
        ),
      ).toThrow("transport allocation");
      expect(store.desired()).toEqual(before);
      expect(store.history().audit).toHaveLength(auditCount);
    } finally {
      store.close();
    }
  });
  it("reserves concurrent login attempts before verification and expires old identities", async () => {
    const store = await database();
    const connection = new DatabaseSync(store.path);

    try {
      const results = await Promise.allSettled(
        Array.from({ length: 12 }, () => store.login("wrong", "same-client")),
      );

      expect(results.every((result) => result.status === "rejected")).toBe(
        true,
      );
      expect(
        connection.prepare("SELECT attempts FROM login_failures").get()!
          .attempts,
      ).toBe(4);
      await expect(store.login("wrong", "same-client")).rejects.toMatchObject({
        code: "invalid_credentials",
      });
      await expect(store.login("wrong", "same-client")).rejects.toMatchObject({
        code: "login_throttled",
      });
      connection
        .prepare("UPDATE login_failures SET since=?")
        .run(new Date(Date.now() - 61000).toISOString());
      await expect(store.login("wrong", "other-client")).rejects.toMatchObject({
        code: "invalid_credentials",
      });
      expect(
        connection
          .prepare("SELECT count(*) AS count FROM login_failures")
          .get()!.count,
      ).toBe(1);
    } finally {
      connection.close();
      store.close();
    }
  });
  it("throttles IPv6 clients by /64 and IPv4-mapped clients by their IPv4 address", async () => {
    const store = await database();

    try {
      for (let host = 1; host <= 5; host++)
        await expect(
          store.login("wrong", `2001:db8:1:2::${host}`),
        ).rejects.toMatchObject({ code: "invalid_credentials" });

      await expect(
        store.login("wrong", "2001:db8:1:2:ffff::99"),
      ).rejects.toMatchObject({ code: "login_throttled" });
      await expect(
        store.login("wrong", "2001:db8:1:3::1"),
      ).rejects.toMatchObject({ code: "invalid_credentials" });

      for (let attempt = 0; attempt < 5; attempt++)
        await expect(
          store.login("wrong", "::ffff:192.0.2.5"),
        ).rejects.toMatchObject({ code: "invalid_credentials" });

      await expect(store.login("wrong", "192.0.2.5")).rejects.toMatchObject({
        code: "login_throttled",
      });
      await expect(store.login("wrong", "192.0.2.6")).rejects.toMatchObject({
        code: "invalid_credentials",
      });
    } finally {
      store.close();
    }
  });
  it("refuses new failure identities when the throttle table is full without evicting active windows", async () => {
    const store = await database();
    const connection = new DatabaseSync(store.path);

    try {
      const insert = connection.prepare(
        "INSERT INTO login_failures VALUES(?,5,?)",
      );

      connection.exec("BEGIN");

      for (let index = 0; index < 4096; index++)
        insert.run(String(index), new Date().toISOString());
      connection.exec("COMMIT");
      await expect(store.login("wrong", "new-client")).rejects.toMatchObject({
        code: "login_throttled",
      });
      expect(
        connection
          .prepare("SELECT count(*) AS count FROM login_failures")
          .get()!.count,
      ).toBe(4096);
    } finally {
      connection.close();
      store.close();
    }
  });
  it("removes an instance and its scoped rules atomically while preserving shared rules and rejecting stale removal", async () => {
    const store = await database();

    try {
      const id = randomUUID(),
        scoped = randomUUID();

      store.mutation("1", "instance-updated", id, (policy) => ({
        ...policy,
        instances: [
          { id, name: "Disposable instance", addresses: ["10.22.241.10"] },
        ],
      }));
      store.mutation("2", "rule-created", scoped, (policy) => ({
        ...policy,
        rules: [
          ...policy.rules,
          {
            ...policy.rules[0]!,
            id: scoped,
            subject: { kind: "instance", instanceId: id },
          },
        ],
      }));
      expect(() => store.removeInstance("2", id)).toThrow("Policy changed");
      expect(store.desired().instances).toHaveLength(1);
      const next = store.removeInstance("3", id);
      expect(next.instances).toEqual([]);
      expect(next.rules).toHaveLength(1);
      expect(next.rules[0]?.subject).toEqual({ kind: "global" });

      const removal = store
        .history()
        .audit.find((event) => event.action === "instance-removed");

      expect(removal?.revisions).toEqual({ before: "3", after: "4" });
      expect(
        removal?.changes.map((change) => [
          change.subject,
          change.id,
          change.before === null,
          change.after === null,
        ]),
      ).toEqual([
        ["instance", id, false, true],
        ["rule", scoped, false, true],
      ]);
      // The deleted rule is described from its recorded values; its instance is gone too.
      expect(
        store.history().audit.find((event) => event.subject === scoped)
          ?.subjectLabel,
      ).toMatch(/^Instance · /);
      // A denial delivered after the removal does not recreate a Request.
      store.ingest({
        protocolVersion: 1,
        epoch: randomUUID(),
        sequence: "1",
        events: [
          {
            ...retentionEvent(),
            instanceId: id,
            question: "late.example",
            details: {
              outcome: "policy-denied",
              queryType: "A",
              clientIp: "10.22.241.10",
              catchall: true,
              appliedRevision: "3",
              policyHash: "a".repeat(64),
            },
          },
        ],
      });
      expect(store.requests().requests).toEqual([]);
    } finally {
      store.close();
    }
  });
  it("reports retryable storage errors and uncertain coverage separately from confirmed loss", async () => {
    const store = await database();

    try {
      const collector = {
        lostBatches: "0",
        firstLossAt: null,
        lastLossAt: null,
      };

      store.gatewayHealth({
        collector: { ...collector, persistenceError: "No space left" },
      });
      expect(
        store
          .status()
          .conditions.some(
            (condition) =>
              condition.code === "collector_persistence" &&
              condition.recoveredAt === null,
          ),
      ).toBe(true);
      expect(
        store
          .status()
          .conditions.some((condition) => condition.code === "collector_loss"),
      ).toBe(false);
      store.gatewayHealth({
        collector: {
          ...collector,
          persistenceError: null,
          coverageCondition: "Some observations may be missing",
        },
      });
      expect(
        store
          .status()
          .conditions.find(
            (condition) => condition.code === "collector_persistence",
          )?.recoveredAt,
      ).not.toBeNull();
      expect(
        store
          .status()
          .conditions.find(
            (condition) => condition.code === "collector_coverage",
          )?.message,
      ).toBe("Some observations may be missing");
    } finally {
      store.close();
    }
  });
  it("keeps a capped DNS receive buffer active until the gateway reports the full size", async () => {
    const store = await database();

    try {
      store.gatewayHealth({
        dnsCondition: "DNS receive buffer is 4194304 bytes",
      });

      const active = () =>
        store
          .status()
          .conditions.find(
            (condition) => condition.code === "dns_receive_buffer",
          );

      expect(active()).toMatchObject({
        message: "DNS receive buffer is 4194304 bytes",
        recoveredAt: null,
      });
      store.gatewayHealth({ dnsCondition: null });
      expect(active()?.recoveredAt).not.toBeNull();
    } finally {
      store.close();
    }
  });
  it("reports rejected DNS observations without classifying retained batches as lost", async () => {
    const store = await database();

    try {
      store.gatewayHealth({
        collector: {
          lostBatches: "0",
          firstLossAt: null,
          lastLossAt: null,
          rejectedRecords: "17",
          firstRejectedAt: new Date().toISOString(),
          lastRejectedAt: new Date().toISOString(),
          rejectionCheckpointPending: true,
        },
      });
      const conditions = store.status().conditions;
      expect(
        conditions.find((condition) => condition.code === "collector_rejected")
          ?.message,
      ).toContain("17 DNS observations");
      expect(
        conditions.some((condition) => condition.code === "collector_loss"),
      ).toBe(false);
      expect(
        conditions.find(
          (condition) => condition.code === "collector_rejection_checkpoint",
        )?.recoveredAt,
      ).toBeNull();
      store.gatewayHealth({
        collector: {
          lostBatches: "0",
          firstLossAt: null,
          lastLossAt: null,
          rejectedRecords: "17",
          rejectionCheckpointPending: false,
        },
      });
      expect(
        store
          .status()
          .conditions.find(
            (condition) => condition.code === "collector_rejection_checkpoint",
          )?.recoveredAt,
      ).not.toBeNull();
      expect(
        store
          .status()
          .conditions.find(
            (condition) => condition.code === "collector_rejected",
          )?.message,
      ).not.toContain("undefined");
    } finally {
      store.close();
    }
  });
  it("preserves the storage error when SQLite has already rolled back the observation transaction", async () => {
    const store = await database();
    const connection = new DatabaseSync(store.path);

    const event: GatewayEvent = {
      id: randomUUID(),
      observedAt: new Date().toISOString(),
      type: "metadata",
      instanceId: null,
      direction: null,
      peerIp: null,
      protocol: null,
      port: null,
      sentBytes: "0",
      receivedBytes: "0",
      ruleId: null,
      question: null,
      source: "gateway",
      details: {},
    };

    const batch: EventBatch = {
      protocolVersion: 1,
      epoch: randomUUID(),
      sequence: "1",
      events: [event],
    };

    try {
      connection.exec(
        "CREATE TRIGGER fixture_abort BEFORE INSERT ON events BEGIN SELECT RAISE(ROLLBACK, 'storage transaction aborted'); END;",
      );
      expect(() => store.ingest(batch)).toThrow("storage transaction aborted");
      expect(store.history().events).toEqual([]);
      connection.exec("DROP TRIGGER fixture_abort;");
      expect(store.ingest(batch)).toEqual({
        epoch: batch.epoch,
        sequence: "1",
      });
      expect(store.history().events).toHaveLength(1);
    } finally {
      connection.close();
      store.close();
    }
  });
  it("starts a From now window empty and rejects reversed or oversized periods", async () => {
    const store = await database();

    try {
      const at = new Date().toISOString();
      const view = await store.monitor(at, at);
      expect(view.services).toEqual([]);
      expect(view.timeline).toEqual([]);
      expect(view.sentBytes).toBe("0");
      await expect(
        store.monitor(at, new Date(Date.parse(at) - 1).toISOString()),
      ).rejects.toThrow("Select a period");
      await expect(
        store.monitor(
          new Date(Date.parse(at) - 181 * 86400000).toISOString(),
          at,
        ),
      ).rejects.toThrow("Select a period");
    } finally {
      store.close();
    }
  });
  it("labels audit instances by current name and shows each rule as it was after each entry", async () => {
    const store = await database();

    try {
      const instanceId = randomUUID(),
        ruleId = randomUUID();

      store.mutation("1", "instance-updated", instanceId, (policy) => ({
        ...policy,
        instances: [
          {
            id: instanceId,
            name: "Original name",
            addresses: ["10.22.241.10"],
          },
        ],
      }));
      store.mutation("2", "rule-created", ruleId, (policy) => ({
        ...policy,
        rules: [
          ...policy.rules,
          {
            ...policy.rules[0]!,
            id: ruleId,
            subject: { kind: "instance", instanceId },
            action: "allow",
            protocol: 6,
            ports: [{ start: 443, end: 443 }],
          },
        ],
      }));
      expect(
        store.history().audit.find((item) => item.subject === instanceId)
          ?.subjectLabel,
      ).toBe("Original name");
      expect(
        store.history().audit.find((item) => item.subject === ruleId)
          ?.subjectLabel,
      ).toContain("Original name");
      store.mutation("3", "instance-updated", instanceId, (policy) => ({
        ...policy,
        instances: policy.instances.map((instance) => ({
          ...instance,
          name: "Current name",
        })),
      }));
      store.mutation("4", "rule-updated", ruleId, (policy) => ({
        ...policy,
        rules: policy.rules.map((rule) =>
          rule.id === ruleId
            ? { ...rule, ports: [{ start: 8443, end: 8443 }] }
            : rule,
        ),
      }));
      const rows = store.history().audit;
      expect(
        rows
          .filter((item) => item.subject === instanceId)
          .every((item) => item.subjectLabel === "Current name"),
      ).toBe(true);

      const ruleLabels = () =>
        Object.fromEntries(
          store
            .history()
            .audit.filter((item) => item.subject === ruleId)
            .map((item) => [item.action, item.subjectLabel]),
        );

      expect(ruleLabels()).toEqual({
        "rule-updated": "Current name · Both directions · Any peer · TCP:8443",
        "rule-created": "Current name · Both directions · Any peer · TCP:443",
      });
      expect(
        rows.find((item) => item.action === "instance-updated")?.changes,
      ).toEqual([
        {
          subject: "instance",
          id: instanceId,
          before: { name: "Original name" },
          after: { name: "Current name" },
        },
      ]);

      // The clock steps back between the last two saves.
      const now = Date.now();

      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(now + 60_000);
      store.mutation("5", "rule-updated", ruleId, (policy) => ({
        ...policy,
        rules: policy.rules.map((rule) =>
          rule.id === ruleId
            ? { ...rule, ports: [{ start: 9443, end: 9443 }] }
            : rule,
        ),
      }));
      vi.setSystemTime(now + 59_000);
      store.mutation("6", "rule-deleted", ruleId, (policy) => ({
        ...policy,
        rules: policy.rules.filter((rule) => rule.id !== ruleId),
      }));

      // A deleted rule's recorded values describe its deletion; older entries undo each change.
      expect(
        store
          .history()
          .audit.filter((item) => item.subject === ruleId)
          .map((item) => [item.action, item.subjectRule?.ports?.[0]?.start]),
      ).toEqual([
        ["rule-updated", 9443],
        ["rule-deleted", 9443],
        ["rule-updated", 8443],
        ["rule-created", 443],
      ]);
    } finally {
      vi.useRealTimers();
      store.close();
    }
  });
  it("revokes sessions when credentials change", async () => {
    const store = await database();

    try {
      const token = await store.login(
        "fixture-only-password-long-enough",
        "fixture",
      );

      expect(store.authenticated(token)).not.toBeNull();
      await store.setup("changed-fixture-password-long-enough", settings);
      expect(store.authenticated(token)).toBeNull();
    } finally {
      store.close();
    }
  });
  it("accepts any present password up to 1024 bytes", async () => {
    const store = await database();

    try {
      await store.setup("test", settings);
      expect(await store.login("test", "fixture")).toMatch(
        /^[A-Za-z0-9_-]{43}$/,
      );
      await expect(store.setup("", settings)).rejects.toMatchObject({
        code: "invalid_password",
      });
      await expect(
        store.setup("x".repeat(1025), settings),
      ).rejects.toMatchObject({ code: "invalid_password" });
    } finally {
      store.close();
    }
  });
  it("ends browser sessions after 12 hours and renews remembered sessions up to 30 days", async () => {
    const store = await database();
    const hour = 3600000;
    const day = 24 * hour;

    try {
      const start = Date.now();

      const browser = await store.login(
        "fixture-only-password-long-enough",
        "fixture",
      );

      expect(store.authenticated(browser, start)).toEqual({
        remembered: false,
        renewedUntil: null,
      });
      expect(store.authenticated(browser, start + 13 * hour)).toBeNull();

      const remembered = await store.login(
        "fixture-only-password-long-enough",
        "fixture",
        true,
      );

      // Six days left: no renewal yet.
      expect(
        store.authenticated(remembered, start + day)?.renewedUntil,
      ).toBeNull();

      // Four days left: renewed to seven days from use.
      const renewed = store.authenticated(remembered, start + 3 * day);

      expect(Date.parse(renewed!.renewedUntil!)).toBeGreaterThanOrEqual(
        start + 10 * day - hour,
      );

      // Keep using it every three days; renewal stops at 30 days after sign-in.
      for (let at = 6; at <= 27; at += 3)
        store.authenticated(remembered, start + at * day);
      expect(store.authenticated(remembered, start + 29 * day)).not.toBeNull();
      expect(store.authenticated(remembered, start + 31 * day)).toBeNull();
    } finally {
      store.close();
    }
  });
  it("rejects concurrent stale edits and keeps desired changes pending", async () => {
    const store = await database();

    try {
      const before = store.desired();

      const changed = store.mutation(
        before.revision,
        "fixture-change",
        "Settings",
        (policy) => ({
          ...policy,
          settings: { ...policy.settings, dnsGraceSeconds: 60 },
        }),
      );

      expect(changed.revision).toBe("2");
      expect(store.status().pending).toBe(true);
      expect(() =>
        store.mutation(
          before.revision,
          "stale",
          "Settings",
          (policy) => policy,
        ),
      ).toThrow("Policy changed");
      expect(store.desired().settings.dnsGraceSeconds).toBe(60);
    } finally {
      store.close();
    }
  });
  it("binds confirmation to the exact policy and rejects changed duplicate batches", async () => {
    const store = await database();

    try {
      const policy = store.desired();

      const receipt = {
        protocolVersion: 1 as const,
        revision: policy.revision,
        policyHash: hashDocument(policy),
        bootId: randomUUID(),
        appliedAt: new Date().toISOString(),
        permissions: 0,
      };

      expect(() =>
        store.confirm(policy, { ...receipt, policyHash: "0".repeat(64) }),
      ).toThrow();
      store.confirm(policy, receipt);
      expect(store.status().pending).toBe(false);

      const batch: EventBatch = {
        protocolVersion: 1,
        epoch: randomUUID(),
        sequence: "1",
        events: [],
      };

      expect(store.ingest(batch)).toEqual(store.ingest(batch));
      expect(() =>
        store.ingest({
          ...batch,
          events: [{ id: randomUUID() } as GatewayEvent],
        }),
      ).toThrow("different observations");
    } finally {
      store.close();
    }
  });
  it("aggregates byte counters above JavaScript safe integers without rounding", async () => {
    const store = await database();

    try {
      const id = randomUUID();
      store.mutation("1", "instance", id, (policy) => ({
        ...policy,
        instances: [{ id, name: "Fixture", addresses: ["10.22.241.10"] }],
      }));
      const at = new Date(Math.floor(Date.now() / 5000) * 5000).toISOString();

      const event: GatewayEvent = {
        id: randomUUID(),
        observedAt: at,
        type: "traffic",
        instanceId: id,
        direction: "outgoing",
        peerIp: "10.22.242.20",
        protocol: 6,
        port: 443,
        sentBytes: "9007199254740993",
        receivedBytes: "1",
        ruleId: null,
        question: null,
        source: "conntrack",
        details: { sampleSeconds: 5 },
      };

      store.ingest({
        protocolVersion: 1,
        epoch: randomUUID(),
        sequence: "1",
        events: [event, { ...event, id: randomUUID() }],
      });

      const view = await store.monitor(
        new Date(Date.parse(at) - 5000).toISOString(),
        new Date(Date.parse(at) + 5000).toISOString(),
      );

      expect(view.sentBytes).toBe("18014398509481986");
      expect(view.receivedBytes).toBe("2");
      expect(view.timeline[0]?.sentBytes).toBe("18014398509481986");
    } finally {
      store.close();
    }
  });
  it("prunes UTF-8 history and audit by bytes and preserves counters across replay and restart", async () => {
    const store = await database();
    const sql = new DatabaseSync(store.path);
    let restored: ControllerStore | null = null;
    const details = { message: "🛰".repeat(400) };

    const events: GatewayEvent[] = Array.from({ length: 3 }, (_, index) => ({
      id: randomUUID(),
      observedAt: new Date(Date.now() - (3 - index) * 1000).toISOString(),
      type: "dns",
      instanceId: null,
      direction: null,
      peerIp: null,
      protocol: null,
      port: null,
      sentBytes: "0",
      receivedBytes: "0",
      ruleId: null,
      question: "unicode.example",
      source: "resolver-gate",
      details,
    }));

    const historyBytes = Buffer.byteLength(JSON.stringify(events[0])) + 256;
    const auditBytes = Buffer.byteLength(JSON.stringify(details)) + 256;

    const batch: EventBatch = {
      protocolVersion: 1,
      epoch: randomUUID(),
      sequence: "1",
      events,
    };

    try {
      store.mutation("1", "small-budget", "settings", (policy) => ({
        ...policy,
        settings: {
          ...policy.settings,
          dnsHistoryBytes: String(historyBytes * 2 - 1),
          auditBytes: String(auditBytes * 2 - 1),
        },
      }));
      sql.exec("DELETE FROM audit");
      const insert = sql.prepare("INSERT INTO audit VALUES(?,?,?,?,?,?)");

      for (const event of events)
        insert.run(
          event.id,
          event.observedAt,
          "admin",
          "fixture",
          "settings",
          JSON.stringify(details),
        );

      const receipt = store.ingest(batch);
      expect(store.history().events.map((event) => event.id)).toEqual([
        events[2]!.id,
      ]);
      expect(store.history().audit.map((entry) => entry.id)).toEqual([
        events[2]!.id,
      ]);
      expect(store.ingest(batch)).toEqual(receipt);
      expect(store.resources().historyUsedBytes.dns).toBe(String(historyBytes));
      expect(store.resources().auditUsedBytes).toBe(String(auditBytes));

      for (const [table, usage] of [
        ["events", "events:dns"],
        ["audit", "audit"],
      ])
        expect(
          sql
            .prepare("SELECT bytes FROM storage_usage WHERE name=?")
            .get(usage!)!.bytes,
        ).toBe(
          sql
            .prepare(
              `SELECT COALESCE(SUM(length(CAST(details AS BLOB))+256),0) AS bytes FROM ${table}`,
            )
            .get()!.bytes,
        );

      store.close();
      restored = new ControllerStore(store.path);
      expect(restored.ingest(batch)).toEqual(receipt);
      expect(restored.resources().historyUsedBytes.dns).toBe(
        String(historyBytes),
      );
      expect(restored.resources().auditUsedBytes).toBe(String(auditBytes));
    } finally {
      sql.close();

      if (restored) restored.close();
      else store.close();
    }
  });
  it("bounds observation history and metrics together while keeping enforcement policy", async () => {
    const store = await database();

    try {
      const instanceId = randomUUID();
      store.mutation("1", "small-budget", instanceId, (policy) => ({
        ...policy,
        instances: [
          { id: instanceId, name: "Fixture", addresses: ["10.22.241.10"] },
        ],
        settings: { ...policy.settings, trafficHistoryBytes: "4096" },
      }));
      const epoch = randomUUID();

      for (let sequence = 1; sequence <= 8; sequence++) {
        store.ingest({
          protocolVersion: 1,
          epoch,
          sequence: String(sequence),
          events: [
            {
              id: randomUUID(),
              observedAt: new Date().toISOString(),
              type: "traffic",
              instanceId,
              direction: "outgoing",
              peerIp: "10.22.242.20",
              protocol: 17,
              port: 18000 + sequence,
              sentBytes: "10",
              receivedBytes: "20",
              ruleId: null,
              question: null,
              source: "conntrack",
              details: {},
            },
          ],
        });
      }

      expect(
        BigInt(store.resources().historyUsedBytes.traffic),
      ).toBeLessThanOrEqual(4096n);
      expect(store.desired().instances).toHaveLength(1);
      expect(store.desired().rules).toHaveLength(1);
      expect(() =>
        store.ingest({ protocolVersion: 1, epoch, sequence: "1", events: [] }),
      ).toThrow("persisted delivery cursor");
    } finally {
      store.close();
    }
  });
});

describe("late denials", () => {
  it("do not reopen a connection request the confirmed policy decides", async () => {
    const store = await database();
    const instanceId = randomUUID();

    try {
      store.mutation("1", "instance-created", instanceId, (policy) => ({
        ...policy,
        instances: [
          { id: instanceId, name: "Client", addresses: ["10.22.241.10"] },
        ],
      }));

      const denial = (): EventBatch => ({
        protocolVersion: 1,
        epoch: randomUUID(),
        sequence: "1",
        events: [
          {
            ...retentionEvent(),
            type: "blocked",
            source: "nftables",
            question: null,
            instanceId,
            direction: "outgoing",
            peerIp: "10.22.242.99",
            protocol: 17,
            port: 18083,
            ruleId: store.desired().rules[0]!.id,
            details: {
              clientIp: "10.22.241.10",
              catchall: true,
              appliedRevision: "2",
            },
          },
        ],
      });

      store.ingest(denial());
      expect(store.requests().requests).toMatchObject([
        { state: "needs-review" },
      ]);

      const allow = {
        ...store.desired().rules[0]!,
        id: randomUUID(),
        subject: { kind: "instance" as const, instanceId },
        direction: "outgoing" as const,
        peer: { kind: "ip" as const, value: "10.22.242.99" },
        action: "allow" as const,
        protocol: 17,
        ports: [{ start: 18083, end: 18083 }],
      };

      const policy = store.mutation("2", "rule-created", allow.id, (value) => ({
        ...value,
        rules: [...value.rules, allow],
      }));

      store.ingest(denial());
      expect(store.requests().requests).toMatchObject([{ state: "applying" }]);
      store.confirm(policy, {
        protocolVersion: 1,
        revision: policy.revision,
        policyHash: hashDocument(policy),
        bootId: randomUUID(),
        appliedAt: new Date().toISOString(),
        permissions: 0,
      });
      store.ingest(denial());
      expect(store.requests().requests).toEqual([]);
      expect(store.status().needsReview).toBe(0);
    } finally {
      store.close();
    }
  });
});

describe("history limits per kind", () => {
  const instanceA = "11111111-1111-4111-8111-111111111111";
  const instanceB = "44444444-4444-4444-8444-444444444444";
  const otherRule = "33333333-3333-4333-8333-333333333333";

  const blocked = (
    ruleId: string,
    instanceId: string,
    observedAt: string,
  ): GatewayEvent => ({
    ...retentionEvent(),
    type: "blocked",
    source: "nftables",
    question: null,
    instanceId,
    direction: "outgoing",
    peerIp: "10.22.242.99",
    protocol: 17,
    port: 18083,
    ruleId,
    observedAt,
    details: { catchall: false, padding: "x".repeat(64) },
  });

  const second = (offset: number) =>
    new Date(Date.UTC(2026, 9, 26, 0, 0, offset)).toISOString();

  const ids = (sql: DatabaseSync, type: string) =>
    sql
      .prepare("SELECT id FROM events WHERE type=? ORDER BY at")
      .all(type)
      .map((row) => row.id);

  it("trims a blocked flood within its own limit, starting with the rule and instance holding the most", async () => {
    const store = await database();
    const sql = new DatabaseSync(store.path);

    try {
      const catchAll = store.desired().rules[0]!.id;

      const traffic = [0, 1].map((offset) => ({
        ...retentionEvent(),
        type: "traffic" as const,
        observedAt: second(offset),
      }));

      const dns = [0, 1].map((offset) => ({
        ...retentionEvent(),
        observedAt: second(offset),
      }));

      // Instance A floods the catch-all; instance B and another rule each have one older sample.
      const quiet = [
        blocked(catchAll, instanceB, second(2)),
        blocked(otherRule, instanceA, second(2)),
      ];

      const flood = Array.from({ length: 40 }, (_, index) =>
        blocked(catchAll, instanceA, second(3 + index)),
      );

      store.ingest({
        protocolVersion: 1,
        epoch: randomUUID(),
        sequence: "1",
        events: [...traffic, ...dns, ...quiet, ...flood],
      });

      const sample = Buffer.byteLength(JSON.stringify(flood[0])) + 256;

      store.mutation(
        store.desired().revision,
        "settings-updated",
        "Settings",
        (policy) => ({
          ...policy,
          settings: {
            ...policy.settings,
            blockedHistoryBytes: String(sample * 12),
          },
        }),
      );

      expect(ids(sql, "traffic")).toEqual(traffic.map((event) => event.id));
      expect(ids(sql, "dns")).toEqual(dns.map((event) => event.id));
      expect(ids(sql, "blocked")).toEqual([
        ...quiet.map((event) => event.id),
        ...flood.slice(-10).map((event) => event.id),
      ]);
      expect(BigInt(store.resources().historyUsedBytes.blocked)).toBe(
        BigInt(sample * 12),
      );
    } finally {
      sql.close();
      store.close();
    }
  });

  it("aggregates blocked counts per rule without storing them as events", async () => {
    const store = await database();
    const sql = new DatabaseSync(store.path);

    try {
      const catchAll = store.desired().rules[0]!.id;
      const now = new Date().toISOString();

      const count = (packets: number): GatewayEvent => ({
        ...retentionEvent(),
        type: "blocked_count",
        source: "nftables",
        question: null,
        instanceId: instanceA,
        direction: "outgoing",
        ruleId: catchAll,
        observedAt: now,
        details: { packets, family: 4, appliedRevision: "1" },
      });

      const sample = blocked(catchAll, instanceA, now);

      store.ingest({
        protocolVersion: 1,
        epoch: randomUUID(),
        sequence: "1",
        events: [count(30), count(12), sample],
      });

      expect(
        sql.prepare("SELECT COUNT(*) AS count FROM events").get()!.count,
      ).toBe(1);
      expect(store.rules().rules[0]!.blocked).toEqual({
        packets: "42",
        samplesSince: sample.observedAt,
      });
      expect(store.resources().historyUsedBytes.blocked).toBe(
        String(Buffer.byteLength(JSON.stringify(sample)) + 256 + 2 * 256),
      );
    } finally {
      sql.close();
      store.close();
    }
  });

  it("indexes DNS answer addresses in canonical form, charges them to DNS history, and drops them with their event", async () => {
    const store = await database();
    const sql = new DatabaseSync(store.path);

    const addresses = () =>
      sql
        .prepare("SELECT address FROM dns_answers ORDER BY address")
        .all()
        .map((row) => row.address);

    try {
      const answer: GatewayEvent = {
        ...retentionEvent(),
        instanceId: instanceA,
        details: {
          outcome: "confirmed",
          addresses: "192.0.2.10, 2001:DB8:0:0::1",
        },
      };

      // An address that is not an IP is rejected with the batch, before it reaches the index.
      expect(() =>
        eventBatchSchema.parse({
          protocolVersion: 1,
          epoch: randomUUID(),
          sequence: "1",
          events: [
            { ...answer, details: { addresses: "192.0.2.10, not-an-ip" } },
          ],
        }),
      ).toThrow("DNS answer addresses must be IP addresses");

      store.ingest({
        protocolVersion: 1,
        epoch: randomUUID(),
        sequence: "1",
        events: [answer],
      });

      expect(addresses()).toEqual(["192.0.2.10", "2001:db8::1"]);
      expect(store.resources().historyUsedBytes.dns).toBe(
        String(Buffer.byteLength(JSON.stringify(answer)) + 256 + 2 * 256),
      );

      store.mutation(
        store.desired().revision,
        "settings-updated",
        "Settings",
        (policy) => ({
          ...policy,
          settings: { ...policy.settings, dnsHistoryBytes: "0" },
        }),
      );

      expect(addresses()).toEqual([]);
      expect(store.resources().historyUsedBytes.dns).toBe("0");
    } finally {
      sql.close();
      store.close();
    }
  });

  it("trims the oldest blocked counts once no samples remain over the limit", async () => {
    const store = await database();
    const sql = new DatabaseSync(store.path);

    try {
      const catchAll = store.desired().rules[0]!.id;
      const hour = Math.floor(Date.now() / 3600000) * 3600000;

      // Half past each of the last four hours: one minute row and one hour row each.
      const times = [4, 3, 2, 1].map((back) =>
        new Date(hour - back * 3600000 + 1800000).toISOString(),
      );

      store.ingest({
        protocolVersion: 1,
        epoch: randomUUID(),
        sequence: "1",
        events: [
          ...times.map((observedAt) => ({
            ...retentionEvent(),
            type: "blocked_count" as const,
            source: "nftables" as const,
            question: null,
            instanceId: instanceA,
            direction: "outgoing" as const,
            ruleId: catchAll,
            observedAt,
            details: { packets: 5, family: 4, appliedRevision: "1" },
          })),
          blocked(catchAll, instanceA, times[3]!),
        ],
      });

      store.mutation(
        store.desired().revision,
        "settings-updated",
        "Settings",
        (policy) => ({
          ...policy,
          settings: {
            ...policy.settings,
            blockedHistoryBytes: String(5 * 256 + 100),
          },
        }),
      );

      expect(
        sql.prepare("SELECT COUNT(*) AS count FROM events").get()!.count,
      ).toBe(0);
      expect(
        sql
          .prepare(
            "SELECT resolution,bucket FROM blocked_counts ORDER BY bucket,resolution",
          )
          .all()
          .map((row) => [row.resolution, row.bucket]),
      ).toEqual([
        [60, times[1]],
        [3600, new Date(hour - 2 * 3600000).toISOString()],
        [60, times[2]],
        [3600, new Date(hour - 3600000).toISOString()],
        [60, times[3]],
      ]);
      expect(store.resources().historyUsedBytes.blocked).toBe(String(5 * 256));
    } finally {
      sql.close();
      store.close();
    }
  });
});

describe("subnet instances and unregistered hosts", () => {
  const subnet = "11111111-1111-4111-8111-111111111111";

  const batch = (events: GatewayEvent[]): EventBatch => ({
    protocolVersion: 1,
    epoch: randomUUID(),
    sequence: "1",
    events,
  });

  const denied = (clientIp: string, question = "api.example.com") => ({
    ...retentionEvent(),
    instanceId: subnet,
    question,
    details: {
      outcome: "policy-denied",
      queryType: "A",
      clientIp,
      catchall: true,
      appliedRevision: "2",
      policyHash: "a".repeat(64),
    },
  });

  const dropped = (
    clientIp: string,
    side: "client" | "upstream",
    peerIp = "93.184.216.34",
  ): GatewayEvent => ({
    ...retentionEvent(),
    type: "blocked",
    source: "nftables",
    question: null,
    peerIp,
    protocol: 6,
    port: 443,
    details: { clientIp, unregistered: side, sampled: true },
  });

  async function subnetStore() {
    const store = await database();

    store.mutation("1", "instance-created", subnet, (policy) => ({
      ...policy,
      instances: [
        { id: subnet, name: "example-network", addresses: ["10.10.0.0/24"] },
      ],
    }));

    return store;
  }

  it("keeps one Request per instance and name with its recent clients, decided for the latest client", async () => {
    const store = await subnetStore();

    try {
      store.ingest(batch([denied("10.10.0.37"), denied("10.10.0.41")]));

      const [request] = store.requests().requests;

      expect(request).toMatchObject({
        kind: "dns",
        instanceId: subnet,
        state: "needs-review",
        clients: [{ address: "10.10.0.41" }, { address: "10.10.0.37" }],
      });

      // An address rule for the latest client decides the Request.
      store.mutation("2", "rule-created", "address", (policy) => ({
        ...policy,
        rules: [
          ...policy.rules,
          {
            ...policy.rules[0]!,
            id: randomUUID(),
            subject: { kind: "address", value: "10.10.0.41" },
            direction: "outgoing",
            peer: { kind: "hostname", value: "api.example.com" },
            action: "allow",
          },
        ],
      }));
      expect(store.requests().requests[0]?.state).toBe("applying");
    } finally {
      store.close();
    }
  });

  it("asks to register unregistered hosts seen on client networks, and resolves them on registration", async () => {
    const store = await subnetStore();

    const start = Date.now() - 120_000;

    const at = (seconds: number) =>
      new Date(start + seconds * 1000).toISOString();

    const lookup = (
      clientIp: string,
      question: string,
      seconds: number,
    ): GatewayEvent => ({
      ...retentionEvent(),
      observedAt: at(seconds),
      source: "suricata",
      question,
      details: { clientIp, unregistered: "client" },
    });

    const drop = (seconds: number, peerIp?: string): GatewayEvent => ({
      ...dropped("10.20.0.5", "client", peerIp),
      observedAt: at(seconds),
    });

    try {
      // Suricata's lookups arrive before the drops: those from a minute before the first drop on
      // name its Request, even one seen after the drop. Lookups without a drop ask for nothing.
      store.ingest(
        batch([
          lookup("10.20.0.5", "stale.example", -66),
          lookup("10.20.0.5", "edge.example", -61),
          lookup("10.20.0.5", "early.example", -1),
          lookup("10.20.0.5", "after.example", 1),
          lookup("203.0.113.9", "dns.example", 0),
        ]),
      );
      store.ingest(
        batch([
          drop(0),
          drop(2, "93.184.216.35"),
          lookup("10.20.0.5", "wanted.example", 3),
          // A late, older drop widens the minute before the first drop; it and a late lookup move
          // no newer time.
          drop(-5, "93.184.216.35"),
          lookup("10.20.0.5", "wanted.example", -2),
          // Upstream drops and drops from covered or link-local addresses ask for nothing.
          dropped("198.51.100.7", "upstream"),
          dropped("fe80::1234", "client"),
          dropped("10.10.0.9", "client"),
        ]),
      );

      expect(store.requests().requests).toMatchObject([
        {
          kind: "host",
          clientIp: "10.20.0.5",
          attempts: "3",
          firstAt: at(-5),
          lastAt: at(3),
          destinations: [
            { address: "93.184.216.35", at: at(2) },
            { address: "93.184.216.34", at: at(0) },
          ],
          names: [
            { name: "wanted.example", at: at(3) },
            { name: "after.example", at: at(1) },
            { name: "early.example", at: at(-1) },
            { name: "edge.example", at: at(-61) },
          ],
        },
      ]);
      expect(store.status().needsReview).toBe(1);

      // Registering the address moves the rules written for exactly it to the instance.
      const promoted = randomUUID();

      store.mutation("2", "instance-updated", subnet, (policy) =>
        withInstance(
          {
            ...policy,
            rules: [
              ...policy.rules,
              {
                ...policy.rules[0]!,
                id: promoted,
                subject: { kind: "address", value: "10.10.0.70" },
              },
            ],
          },
          { id: subnet, name: "example-network", addresses: ["10.10.0.0/24"] },
          new Date().toISOString(),
        ),
      );

      const host = randomUUID();

      const register = (revision: string, id: string, addresses: string[]) =>
        store.mutation(revision, "instance-created", id, (policy) =>
          withInstance(
            policy,
            { id, name: id.slice(0, 8), addresses },
            new Date().toISOString(),
          ),
        );

      // Among other addresses, the rule would widen to all of them, so the save is refused.
      expect(() => register("3", host, ["10.20.0.5", "10.10.0.70"])).toThrow(
        "names an instance address",
      );

      const next = register("3", host, ["10.10.0.70"]);

      expect(next.rules.find((rule) => rule.id === promoted)?.subject).toEqual({
        kind: "instance",
        instanceId: host,
      });
      expect(store.requests().requests).toHaveLength(1);
      register("4", randomUUID(), ["10.20.0.5"]);
      expect(store.requests().requests).toEqual([]);
    } finally {
      store.close();
    }
  });

  it("dismisses a host Request until it is restored, counting only its later drops", async () => {
    const store = await subnetStore();
    const later = new Date(Date.now() + 60000).toISOString();

    try {
      store.ingest(batch([dropped("10.20.0.5", "client")]));
      expect(store.status().needsReview).toBe(1);
      store.dismissHostRequest("10.20.0.5");
      expect(store.status().needsReview).toBe(0);
      expect(store.requests().retention.pending).toBe(0);

      // A dismissed host leaves the main list for the dismissed view, unless a link names it.
      expect(store.requests().requests).toEqual([]);
      expect(store.requests("10.20.0.5").requests).toMatchObject([
        { state: "dismissed" },
      ]);

      const [before] = store.requests(null, "dismissed").requests;

      // A later drop to another destination and a lookup change only the attempts and last time.
      store.ingest(
        batch([
          {
            ...dropped("10.20.0.5", "client", "198.51.100.9"),
            observedAt: later,
          },
          {
            ...retentionEvent(),
            source: "suricata",
            question: "after-dismissal.example",
            details: { clientIp: "10.20.0.5", unregistered: "client" },
          },
        ]),
      );
      expect(store.requests(null, "dismissed").requests).toEqual([
        { ...before, attempts: "2", lastAt: later },
      ]);
      expect(store.status().needsReview).toBe(0);
      expect(() => store.dismissHostRequest("10.20.0.5")).toThrow(
        "No host Request waits for review",
      );
      store.restoreHostRequest("10.20.0.5");
      expect(store.requests().requests).toMatchObject([
        { kind: "host", state: "needs-review", attempts: "2" },
      ]);
      expect(store.requests(null, "dismissed").requests).toEqual([]);
      expect(store.status().needsReview).toBe(1);
      expect(() => store.restoreHostRequest("10.20.0.5")).toThrow(
        "No dismissed host Request",
      );
      expect(
        store
          .history()
          .audit.slice(0, 2)
          .map(({ action, subject }) => [action, subject]),
      ).toEqual([
        ["host-request-restored", "10.20.0.5"],
        ["host-request-dismissed", "10.20.0.5"],
      ]);
    } finally {
      store.close();
    }
  });

  it("keeps dismissed hosts out of the host pool and refuses dismissal at their limit", async () => {
    const store = await subnetStore();
    const sql = new DatabaseSync(store.path);

    // Hosts fd00::<n>, older than any drop below, dismissed or waiting for review.
    const hosts = (from: number, count: number, dismissed: boolean) =>
      sql
        .prepare(
          "WITH RECURSIVE n(i) AS (SELECT ? UNION ALL SELECT i+1 FROM n WHERE i+1 < ?) INSERT INTO host_requests(client_ip,attempts,first_at,last_at,destinations,names,dismissed_at) SELECT printf('fd00::%x',i),'1','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z','[]','[]',? FROM n",
        )
        .run(from, from + count, dismissed ? "2026-01-01T00:00:00.000Z" : null);

    const count = (where: string) =>
      Number(
        sql
          .prepare(`SELECT COUNT(*) AS count FROM host_requests WHERE ${where}`)
          .get()!.count,
      );

    try {
      hosts(0, MAX_DISMISSED_HOSTS - 1, true);
      hosts(MAX_DISMISSED_HOSTS, MAX_HOST_REQUESTS, false);
      // A new host overfills the host pool, which removes its oldest waiting host, never a
      // dismissed one.
      store.ingest(batch([dropped("10.20.0.5", "client")]));
      expect(count("dismissed_at IS NULL")).toBe(MAX_HOST_REQUESTS);
      expect(count("dismissed_at IS NOT NULL")).toBe(MAX_DISMISSED_HOSTS - 1);
      expect(store.requests().retention).toMatchObject({
        pending: MAX_HOST_REQUESTS,
        discarded: "1",
      });
      store.dismissHostRequest("10.20.0.5");
      expect(() =>
        store.dismissHostRequest(
          `fd00::${(MAX_DISMISSED_HOSTS + 1).toString(16)}`,
        ),
      ).toThrow("Dismissed host limit (10,000) reached");
    } finally {
      sql.close();
      store.close();
    }
  });

  it("refuses to remove an instance that address rules sit in", async () => {
    const store = await subnetStore();

    try {
      store.mutation("2", "rule-created", "address", (policy) => ({
        ...policy,
        rules: [
          ...policy.rules,
          {
            ...policy.rules[0]!,
            id: randomUUID(),
            subject: { kind: "address", value: "10.10.0.70" },
          },
        ],
      }));
      expect(() => store.removeInstance("3", subnet)).toThrow(
        "Address rule 10.10.0.70 is outside every instance",
      );
      expect(store.desired().instances).toHaveLength(1);
    } finally {
      store.close();
    }
  });

  it("shows unregistered drop counts and grouped samples in Monitor", async () => {
    const store = await subnetStore();
    const start = Date.now() - 600_000;

    const at = (seconds: number) =>
      new Date(start + seconds * 1000).toISOString();

    const lookup = (question: string, seconds: number): GatewayEvent => ({
      ...retentionEvent(),
      observedAt: at(seconds),
      source: "suricata",
      question,
      // Sent to another resolver and forwarded to the gateway's listener.
      peerIp: "1.1.1.1",
      details: { clientIp: "10.20.0.5", unregistered: "client" },
    });

    const drop = (
      clientIp: string,
      side: "client" | "upstream",
      seconds: number,
      peerIp?: string,
      port?: number,
    ): GatewayEvent => {
      const event = {
        ...dropped(clientIp, side, peerIp),
        observedAt: at(seconds),
      };

      if (port !== undefined) {
        event.protocol = 17;
        event.port = port;
      }

      return event;
    };

    try {
      store.gatewayHealth({
        endpoint: {
          addresses: ["10.20.0.1"],
          dnsPort: 5353,
          machinePort: 9443,
          controllerPort: 443,
          controllerAddresses: ["10.10.0.2"],
          upstreamDns: { address: "192.0.2.53", port: 53 },
        },
      });
      store.ingest(
        batch([
          {
            ...retentionEvent(),
            type: "blocked_count",
            source: "nftables",
            question: null,
            observedAt: at(0),
            details: { packets: 40, unregistered: "upstream" },
          },
          drop("198.51.100.7", "upstream", 0),
          // Lookups a minute before the DNS drops' first sample on name them; older ones do not.
          lookup("stale.example", -70),
          lookup("wanted.example", -50),
          drop("10.20.0.5", "client", 10, "10.20.0.1", 5353),
          drop("10.20.0.5", "client", 20, "10.20.0.1", 5353),
          lookup("later.example", 20),
          // Drops to another gateway service, here its machine link, carry no names.
          { ...drop("10.20.0.5", "client", 30, "10.20.0.1"), port: 9443 },
        ]),
      );

      const monitor = await store.monitor(
        new Date(start - 3600000).toISOString(),
        new Date(Date.now() + 60000).toISOString(),
      );

      expect(monitor.unregistered).toEqual({
        clientPackets: "0",
        upstreamPackets: "40",
        drops: [
          {
            side: "client",
            clientIp: "10.20.0.5",
            peerIp: "10.20.0.1",
            protocol: 6,
            port: 9443,
            samples: 1,
            firstAt: at(30),
            lastAt: at(30),
            gateway: { services: ["controller link"] },
            request: true,
            names: [],
          },
          {
            side: "client",
            clientIp: "10.20.0.5",
            peerIp: "10.20.0.1",
            protocol: 17,
            port: 5353,
            samples: 2,
            firstAt: at(10),
            lastAt: at(20),
            gateway: { services: ["DNS"] },
            request: true,
            names: [
              { name: "later.example", at: at(20) },
              { name: "wanted.example", at: at(-50) },
            ],
          },
          {
            side: "upstream",
            clientIp: "198.51.100.7",
            peerIp: "93.184.216.34",
            protocol: 6,
            port: 443,
            samples: 1,
            firstAt: at(0),
            lastAt: at(0),
            gateway: null,
            request: false,
            names: [],
          },
        ],
        dropsTruncated: false,
        samplesLimited: false,
      });
    } finally {
      store.close();
    }
  });

  it("marks Monitor's unregistered drop groups as truncated and read from the newest samples", async () => {
    const store = await subnetStore();
    const start = Date.now() - 600_000;

    // 5,001 samples across 51 destinations, more than one read groups and returns.
    const drops = Array.from({ length: 5001 }, (_, index) => ({
      ...dropped("198.51.100.7", "upstream", `203.0.113.${index % 51}`),
      observedAt: new Date(start + index * 100).toISOString(),
    }));

    try {
      store.ingest(batch(drops.slice(0, 4000)));
      store.ingest(batch(drops.slice(4000)));

      const { unregistered } = await store.monitor(
        new Date(start - 60000).toISOString(),
        new Date(Date.now() + 60000).toISOString(),
      );

      expect(unregistered.drops).toHaveLength(50);
      expect(unregistered.dropsTruncated).toBe(true);
      expect(unregistered.samplesLimited).toBe(true);
    } finally {
      store.close();
    }
  });

  it("includes a linked host Request older than the newest Requests", async () => {
    const store = await subnetStore();
    const start = Date.now() - 600_000;

    const drop = (clientIp: string, seconds: number) => ({
      ...dropped(clientIp, "client"),
      observedAt: new Date(start + seconds * 1000).toISOString(),
    });

    try {
      store.ingest(
        batch([
          drop("10.30.0.1", 0),
          ...Array.from({ length: 500 }, (_, index) =>
            drop(`10.31.${Math.floor(index / 256)}.${index % 256}`, index + 1),
          ),
        ]),
      );

      const linked = (host: string | null) =>
        store
          .requests(host)
          .requests.filter((request) => request.id === "10.30.0.1");

      expect(linked(null)).toEqual([]);
      expect(linked("10.30.0.1")).toMatchObject([
        { kind: "host", clientIp: "10.30.0.1", state: "needs-review" },
      ]);
      // A host already among the newest Requests is not listed twice.
      expect(store.requests("10.31.1.243").requests).toHaveLength(500);
    } finally {
      store.close();
    }
  });
});
