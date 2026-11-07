import { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import type { DashboardStatus } from "@traffic-policy/contracts/dashboard";
import { browserName, DashboardReads } from "./dashboard-reads.ts";
import { HISTORY_GROUP } from "./store.ts";

const databases: DatabaseSync[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

const instanceId = "11111111-1111-4111-8111-111111111111",
  ruleId = "22222222-2222-4222-8222-222222222222";

const at = "2026-10-10T00:00:00.000Z";

const policy = {
  instances: [
    { id: instanceId, name: "Current name", addresses: ["10.22.241.10"] },
  ],
  rules: [],
  settings: { localNetworks: [] },
};

const status: DashboardStatus = {
  desiredRevision: "1",
  appliedRevision: null,
  pending: true,
  lastError: null,
  lastSeen: null,
  receipt: null,
  conditions: [],
  needsReview: 0,
  gateway: null,
};

function fixture() {
  const database = new DatabaseSync(":memory:");
  databases.push(database);
  database.aggregate("tp_sum", {
    start: "0",
    step: (previous, value) =>
      (BigInt(String(previous)) + BigInt(String(value))).toString(),
  });
  database.exec(`CREATE TABLE requests(id TEXT,instance_id TEXT,direction TEXT,peer_ip TEXT,protocol INTEGER,port INTEGER,attempts TEXT,first_at TEXT,last_at TEXT,rule_id TEXT,state TEXT,clients TEXT);
 CREATE TABLE dns_requests(id TEXT,instance_id TEXT,question TEXT,query_type TEXT,attempts TEXT,first_at TEXT,last_at TEXT,rule_id TEXT,state TEXT,clients TEXT);
 CREATE TABLE host_requests(client_ip TEXT,attempts TEXT,first_at TEXT,last_at TEXT,destinations TEXT,names TEXT,dismissed_at TEXT);
 CREATE TABLE conditions(code TEXT,message TEXT,first_at TEXT,last_at TEXT,occurrences TEXT,recovered_at TEXT);
 CREATE TABLE audit(id TEXT,at TEXT,actor TEXT,action TEXT,subject TEXT,details TEXT);
 CREATE TABLE events(id TEXT,at TEXT,details TEXT,type TEXT,instance_id TEXT,peer_ip TEXT,question TEXT GENERATED ALWAYS AS (json_extract(details,'$.question')) VIRTUAL,history_group TEXT GENERATED ALWAYS AS (${HISTORY_GROUP}) VIRTUAL);
 CREATE TABLE metrics(instance_id TEXT,direction TEXT,peer_ip TEXT,protocol INTEGER,port INTEGER,resolution INTEGER,bucket TEXT,sent TEXT,received TEXT);
 CREATE TABLE blocked_counts(instance_id TEXT,rule_id TEXT,direction TEXT,resolution INTEGER,bucket TEXT,packets INTEGER);
 CREATE TABLE dns_answers(event_id TEXT,instance_id TEXT,address TEXT,at TEXT);`);

  return { database, reads: new DashboardReads(database) };
}

describe("typed dashboard reads", () => {
  it("lists names seen for a request's address from DNS answers and connections, newest first", () => {
    const { database, reads } = fixture();
    const insert = database.prepare("INSERT INTO events VALUES(?,?,?,?,?,?)");

    const event = (
      observedAt: string,
      type: "dns" | "metadata",
      fields: {
        peerIp?: string;
        question?: string;
        details: Record<string, string>;
      },
    ) => {
      const id = randomUUID();

      insert.run(
        id,
        observedAt,
        JSON.stringify({ id, observedAt, type, instanceId, ...fields }),
        type,
        instanceId,
        fields.peerIp ?? null,
      );

      if (type === "dns")
        for (const address of fields.details.addresses!.split(", "))
          database
            .prepare("INSERT INTO dns_answers VALUES(?,?,?,?)")
            .run(id, instanceId, address, observedAt);
    };

    event("2026-10-10T00:00:01.000Z", "dns", {
      question: "Proof.Example.",
      details: { addresses: "10.22.242.99, 10.22.242.100" },
    });
    // A longer address containing the request's address is not a match.
    event("2026-10-10T00:00:02.000Z", "dns", {
      question: "other.example",
      details: { addresses: "10.22.242.990" },
    });
    event("2026-10-10T00:00:03.000Z", "metadata", {
      peerIp: "10.22.242.99",
      details: { eventType: "tls", hostname: "api.example.co.uk" },
    });
    event("2026-10-10T00:00:04.000Z", "dns", {
      question: "proof.example",
      details: { addresses: "10.22.242.99" },
    });

    expect(reads.requestNames(instanceId, "10.22.242.99")).toEqual({
      names: [
        {
          hostname: "proof.example",
          source: "dns",
          lastSeenAt: "2026-10-10T00:00:04.000Z",
        },
        {
          hostname: "api.example.co.uk",
          source: "tls",
          lastSeenAt: "2026-10-10T00:00:03.000Z",
        },
      ],
    });
  });
  it("groups only unambiguous observed names and filters events to the selected period and service", async () => {
    const { database, reads } = fixture();

    const insert = database.prepare(
      "INSERT INTO metrics VALUES(?,?,?,?,?,?,?,?,?)",
    );

    for (const [ip, sent] of [
      ["10.22.242.20", "10"],
      ["10.22.242.30", "20"],
      ["10.22.242.40", "40"],
    ])
      insert.run(instanceId, "outgoing", ip, 6, 443, 5, at, sent, "0");

    for (const [ip, hostname] of [
      ["10.22.242.20", "api.example.co.uk"],
      ["10.22.242.30", "www.example.co.uk"],
      ["10.22.242.40", "one.example.co.uk"],
      ["10.22.242.40", "other.example.net"],
    ]) {
      const id = randomUUID();

      const event = {
        id,
        observedAt: at,
        type: "metadata",
        instanceId,
        direction: "outgoing",
        peerIp: ip,
        protocol: 6,
        port: 443,
        sentBytes: "0",
        receivedBytes: "0",
        ruleId: null,
        question: null,
        source: "suricata",
        details: { eventType: "tls", hostname },
      };

      database
        .prepare("INSERT INTO events VALUES(?,?,?,?,?,?)")
        .run(id, at, JSON.stringify(event), "metadata", instanceId, ip);
    }

    const to = "2026-10-10T00:01:00.000Z";
    const all = await reads.monitor(at, to, {}, policy, status, Date.parse(to));
    expect(all.sentBytes).toBe("70");

    for (const [from, until] of [
      ["2026-10-10T07:00:00+07:00", "2026-10-10T07:01:00+07:00"],
      ["2026-10-10T00:00:00Z", "2026-10-10T00:01:00Z"],
    ]) {
      const equivalent = await reads.monitor(
        from!,
        until!,
        {},
        policy,
        status,
        Date.parse(to),
      );

      expect(equivalent).toEqual(all);
      expect(
        (
          await reads.monitor(
            from!,
            until!,
            { hostname: "api.example.co.uk" },
            policy,
            status,
            Date.parse(to),
          )
        ).sentBytes,
      ).toBe("10");
    }

    const domain = await reads.monitor(
      at,
      to,
      { instanceId, domain: "example.co.uk" },
      policy,
      status,
      Date.parse(to),
      "recent",
    );

    expect(domain.sentBytes).toBe("30");
    expect(domain.eventSummary!.events).toEqual([
      {
        type: "metadata",
        direction: "outgoing",
        protocol: 6,
        port: 443,
        ruleId: null,
        count: "2",
        lastAt: at,
      },
    ]);

    const host = await reads.monitor(
      at,
      to,
      { instanceId, hostname: "api.example.co.uk" },
      policy,
      status,
      Date.parse(to),
    );

    expect(host.sentBytes).toBe("10");

    const service = await reads.monitor(
      at,
      to,
      { instanceId, peerIp: "10.22.242.20", protocol: 6, port: 443 },
      policy,
      status,
      Date.parse(to),
      "recent",
    );

    expect(service.eventSummary!.events.map((group) => group.count)).toEqual([
      "1",
    ]);
    expect(service.names[0]?.domain).toBe("example.co.uk");
  });
  it("counts blocked samples per recorded rule and returns waiting reviews for listed services", async () => {
    const { database, reads } = fixture();

    database
      .prepare("INSERT INTO metrics VALUES(?,?,?,?,?,?,?,?,?)")
      .run(instanceId, "outgoing", "10.22.242.20", 6, 18080, 5, at, "1", "1");

    const otherRule = "33333333-3333-4333-8333-333333333333";

    for (const [observedAt, rule, direction] of [
      ["2026-10-10T00:00:01.000Z", ruleId, "outgoing"],
      ["2026-10-10T00:00:02.000Z", ruleId, "outgoing"],
      ["2026-10-10T00:00:03.000Z", otherRule, "outgoing"],
      ["2026-10-10T00:00:04.000Z", ruleId, "incoming"],
    ] as const) {
      const id = randomUUID();

      database.prepare("INSERT INTO events VALUES(?,?,?,?,?,?)").run(
        id,
        observedAt,
        JSON.stringify({
          id,
          observedAt,
          type: "blocked",
          instanceId,
          direction,
          peerIp: "10.22.242.20",
          protocol: 6,
          port: 18080,
          sentBytes: "0",
          receivedBytes: "0",
          ruleId: rule,
          question: null,
          source: "nftables",
          details: {},
        }),
        "blocked",
        instanceId,
        "10.22.242.20",
      );
    }

    const request = database.prepare(
      "INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?,json_array(json_object('value','10.22.241.10','at','2026-01-01T00:00:00.000Z')))",
    );

    request.run(
      "listed",
      instanceId,
      "outgoing",
      "10.22.242.20",
      6,
      18080,
      "3",
      at,
      at,
      ruleId,
      "needs-review",
    );
    request.run(
      "unlisted",
      instanceId,
      "outgoing",
      "10.22.242.99",
      6,
      22,
      "1",
      at,
      at,
      ruleId,
      "needs-review",
    );

    const count = database.prepare(
      "INSERT INTO blocked_counts VALUES(?,?,?,?,?,?)",
    );

    count.run(instanceId, ruleId, "outgoing", 60, at, 40);
    count.run(instanceId, otherRule, "outgoing", 60, at, 1);
    count.run(instanceId, ruleId, "incoming", 60, at, 1);
    // Hour buckets and other instances stay out of a recent window's totals.
    count.run(instanceId, ruleId, "outgoing", 3600, at, 40);
    count.run(randomUUID(), ruleId, "outgoing", 60, at, 7);

    const to = "2026-10-10T00:05:00.000Z";

    const snapshot = await reads.monitor(
      at,
      to,
      { instanceId, peerIp: "10.22.242.20" },
      policy,
      status,
      Date.parse(to),
      "recent",
    );

    expect(
      snapshot.eventSummary!.events.map(({ ruleId: rule, count, lastAt }) => ({
        rule,
        count,
        lastAt,
      })),
    ).toEqual([
      { rule: ruleId, count: "1", lastAt: "2026-10-10T00:00:04.000Z" },
      { rule: otherRule, count: "1", lastAt: "2026-10-10T00:00:03.000Z" },
      { rule: ruleId, count: "2", lastAt: "2026-10-10T00:00:02.000Z" },
    ]);
    expect(snapshot.reviews).toEqual([
      {
        instanceId,
        direction: "outgoing",
        peerIp: "10.22.242.20",
        protocol: 6,
        port: 18080,
      },
    ]);
    // The rule counter saw more packets than were sampled in one direction; each direction's
    // samples are counted separately.
    expect(
      [...snapshot.eventSummary!.blockedTotals].sort(
        (left, right) =>
          left.ruleId.localeCompare(right.ruleId) ||
          left.direction.localeCompare(right.direction),
      ),
    ).toEqual([
      { ruleId, direction: "incoming", packets: "1", samples: "1" },
      { ruleId, direction: "outgoing", packets: "40", samples: "2" },
      { ruleId: otherRule, direction: "outgoing", packets: "1", samples: "1" },
    ]);
  });
  it("summarizes events only when requested for an instance, from its newest 5,000", async () => {
    const { database, reads } = fixture();
    const insert = database.prepare("INSERT INTO events VALUES(?,?,?,?,?,?)");

    const event = (observedAt: string, type: "dns" | "traffic") => {
      const id = randomUUID();

      insert.run(
        id,
        observedAt,
        JSON.stringify({
          id,
          observedAt,
          type,
          instanceId,
          direction: "outgoing",
          peerIp: type === "dns" ? null : "10.22.242.20",
          protocol: type === "dns" ? null : 6,
          port: type === "dns" ? null : 443,
        }),
        type,
        instanceId,
        type === "dns" ? null : "10.22.242.20",
      );
    };

    // The oldest event falls outside the newest 5,000.
    database.exec("BEGIN");
    event(at, "dns");

    for (let index = 1; index <= 5000; index++)
      event(new Date(Date.parse(at) + index * 1000).toISOString(), "traffic");
    database.exec("COMMIT");

    const to = "2026-10-11T00:00:00.000Z";

    const summary = async (selection: {
      instanceId?: string;
      peerIp?: string;
    }) =>
      (
        await reads.monitor(
          at,
          to,
          selection,
          policy,
          status,
          Date.parse(to),
          "recent",
        )
      ).eventSummary;

    for (const selection of [
      { instanceId },
      { instanceId, peerIp: "10.22.242.20" },
    ])
      expect(await summary(selection)).toMatchObject({
        events: [{ type: "traffic", count: "5000" }],
        eventsTruncated: false,
        eventsLimited: selection.peerIp === undefined,
      });

    expect(await summary({})).toBeNull();
    expect(
      (
        await reads.monitor(
          at,
          to,
          { instanceId },
          policy,
          status,
          Date.parse(to),
        )
      ).eventSummary,
    ).toBeNull();
  });
  it("reads the newest 100,000 events unless the whole period is scanned, one scan at a time", async () => {
    const { database, reads } = fixture();
    const insert = database.prepare("INSERT INTO events VALUES(?,?,?,?,?,?)");
    const peerIp = "10.22.242.30";
    const other = "33333333-3333-4333-8333-333333333333";

    const second = (index: number) =>
      new Date(Date.parse(at) + index * 1000).toISOString();

    // The selected address's only event is older than the newest 100,000 events, all of another
    // instance.
    database.exec("BEGIN");
    insert.run(
      randomUUID(),
      at,
      JSON.stringify({ direction: "outgoing", protocol: 6, port: 443 }),
      "traffic",
      instanceId,
      peerIp,
    );

    for (let index = 1; index <= 100000; index++)
      insert.run(randomUUID(), second(index), "{}", "traffic", other, peerIp);
    database.exec("COMMIT");

    const to = "2026-10-12T00:00:00.000Z";

    const scan = (events: "recent" | "full", signal?: AbortSignal) =>
      reads.monitor(
        at,
        to,
        { instanceId, peerIp },
        policy,
        status,
        Date.parse(to),
        events,
        signal,
      );

    expect((await scan("recent")).eventSummary).toMatchObject({
      events: [],
      eventsLimited: false,
      scannedFrom: second(1),
    });

    const full = scan("full");

    await expect(scan("full")).rejects.toThrow(
      "Another whole-period scan is running",
    );
    expect((await full).eventSummary).toMatchObject({
      events: [{ type: "traffic", direction: "outgoing", count: "1" }],
      scannedFrom: null,
    });

    const controller = new AbortController();
    const aborted = scan("full", controller.signal);
    controller.abort();
    await expect(aborted).rejects.toThrow();
    expect((await scan("full")).eventSummary?.scannedFrom).toBeNull();
  });
  it("normalizes request columns and unknown ports without changing stored rows", () => {
    const { database, reads } = fixture();
    database
      .prepare(
        "INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?,json_array(json_object('value','10.22.241.10','at','2026-01-01T00:00:00.000Z')))",
      )
      .run(
        "request",
        instanceId,
        "outgoing",
        "10.22.242.20",
        17,
        -1,
        "9007199254740993",
        at,
        at,
        ruleId,
        "needs-review",
      );

    const request = reads.requests(policy, status, 10000, null, "main")
      .requests[0]!;

    expect(request).toMatchObject({
      instanceId,
      peerIp: "10.22.242.20",
      port: null,
      attempts: "9007199254740993",
      firstAt: at,
      ruleId,
    });
    expect(request).not.toHaveProperty("peer_ip");
    expect(database.prepare("SELECT port FROM requests").get()!.port).toBe(-1);
  });
  it("distinguishes an unspecified port filter from explicitly unknown ports and preserves large sums", async () => {
    const { database, reads } = fixture();

    const insert = database.prepare(
      "INSERT INTO metrics VALUES(?,?,?,?,?,?,?,?,?)",
    );

    for (const port of [-1, 443])
      insert.run(
        instanceId,
        "outgoing",
        "10.22.242.20",
        6,
        port,
        5,
        at,
        "18446744073709551615",
        "1",
      );

    const to = "2026-10-10T00:05:00.000Z",
      now = Date.parse(to);

    const all = await reads.monitor(at, to, {}, policy, status, now),
      unknown = await reads.monitor(
        at,
        to,
        { port: null },
        policy,
        status,
        now,
      );

    expect(all.sentBytes).toBe("36893488147419103230");
    expect(unknown.sentBytes).toBe("18446744073709551615");
    expect(unknown.services[0]!.port).toBeNull();
    expect(all.services).toHaveLength(2);
  });
  it("resolves current audit names, leaves deleted identifiers, and types conditions", () => {
    const { database, reads } = fixture();
    const insert = database.prepare("INSERT INTO audit VALUES(?,?,?,?,?,?)");
    insert.run("a", at, "Admin", "instance-updated", instanceId, "{}");
    insert.run("b", at, "Admin", "rule-deleted", ruleId, "{}");
    insert.run(
      "c",
      at,
      "Admin",
      "settings-updated",
      "Settings",
      JSON.stringify({
        client: {
          address: "192.168.1.10",
          agent:
            "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
        },
      }),
    );
    database
      .prepare("INSERT INTO conditions VALUES(?,?,?,?,?,?)")
      .run("test", "Condition", at, at, "3", null);
    const history = reads.history(100, policy, status);
    expect(
      history.audit.find((row) => row.subject === instanceId)!.subjectLabel,
    ).toBe("Current name");
    expect(
      history.audit.find((row) => row.subject === ruleId)!.subjectLabel,
    ).toBeNull();
    expect(history.audit.find((row) => row.id === "c")!.client).toEqual({
      address: "192.168.1.10",
      browser: "Safari",
    });
    expect(history.audit.find((row) => row.id === "a")!.client).toBeNull();
    expect(history.conditions[0]).toMatchObject({
      firstAt: at,
      lastAt: at,
      recoveredAt: null,
      occurrences: "3",
    });
  });
  it("names the browser family that made a change", () => {
    expect(
      browserName(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36",
      ),
    ).toBe("HeadlessChrome");
    expect(
      browserName(
        "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
      ),
    ).toBe("Edge");
    expect(
      browserName(
        "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
      ),
    ).toBe("Firefox");
    expect(
      browserName(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
      ),
    ).toBe("Chrome");
    expect(browserName("curl/8.14.1")).toBeNull();
  });
  it("surfaces invalid stored event data as a server failure", () => {
    const { database, reads } = fixture();
    database
      .prepare("INSERT INTO events(id,at,details) VALUES(?,?,?)")
      .run("broken", at, JSON.stringify({ id: "broken" }));
    expect(() => reads.history(100, policy, status)).toThrow(
      expect.objectContaining({ status: 503, code: "invalid_dashboard_data" }),
    );
  });
});
