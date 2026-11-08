import type { DatabaseSync, SQLOutputValue } from "node:sqlite";
import { setImmediate } from "node:timers/promises";
import { z } from "zod";
import type { Policy, Rule } from "@traffic-policy/contracts";
import {
  auditChangeSchema,
  conditionSchema,
  counterSchema,
  historySnapshotSchema,
  monitorSnapshotSchema,
  requestNamesSchema,
  requestSuggestionsSchema,
  requestsSnapshotSchema,
  type DashboardStatus,
  type MonitorSelection,
  type RequestsView,
} from "@traffic-policy/contracts/dashboard";
import { describeRule } from "@traffic-policy/core";
import { gatewayServices } from "../rule-state.ts";
import { ServiceError } from "@traffic-policy/core/io";
import { registrableDomain } from "@traffic-policy/core/domains";
import {
  eventSchema,
  canonicalIp,
  canonicalName,
  nameSchema,
  ruleSchema,
} from "@traffic-policy/contracts";

// The most matching events grouped for one Monitor event summary.
const EVENT_SUMMARY_LIMIT = 5000;

// The most unregistered drop groups one Monitor read returns.
const UNREGISTERED_DROP_GROUPS = 50;

// The most events, of any instance, read in one slice of an event summary. A recent summary reads
// one slice; a whole-period scan reads slice after slice and lets other requests run between them.
const EVENT_SCAN_SLICE = 100000;

export type EventScan = "recent" | "full";

type DashboardPolicy = Pick<Policy, "instances" | "rules"> & {
  settings: Pick<Policy["settings"], "localNetworks">;
};

export const bucketStart = (at: string, resolution: number) =>
  new Date(
    Math.floor(Date.parse(at) / (resolution * 1000)) * resolution * 1000,
  ).toISOString();

export function parseDashboard<T extends z.ZodType>(
  schema: T,
  // oxlint-disable-next-line anti-slop/no-unknown-parameters -- This parser validates the raw value with its supplied endpoint schema.
  value: unknown,
): z.output<T> {
  try {
    return schema.parse(value);
  } catch (failure) {
    if (!(failure instanceof z.ZodError)) throw failure;
    throw new ServiceError(
      503,
      "invalid_dashboard_data",
      "Dashboard data is unavailable",
    );
  }
}

const auditClientSchema = z.object({
  client: z.object({ address: z.string(), agent: z.string() }),
});

// A Request keeps the most recent distinct clients that hit it, newest first.
export const RECENT_CLIENTS = 8;

// Hostname suggestions read answers from this long before each client's latest attempt, at most
// this many answers per client, and return at most this many names.
export const SUGGESTION_WINDOW_MS = 5 * 60_000;

export const SUGGESTION_SCAN_LIMIT = 10_000;

const MAX_SUGGESTIONS = 20;

// A stored recent list, newest first and distinct, JSON [{ value, at }].
const recentSchema = z
  .array(z.object({ value: z.string(), at: z.string() }).strict())
  .max(RECENT_CLIENTS);

export function readRecent(stored: SQLOutputValue | undefined) {
  return stored === undefined || stored === null
    ? []
    : recentSchema.parse(JSON.parse(String(stored)));
}

// Suricata sees a packet before it is dropped, and the gateway sends a host's repeated name once a
// minute, so an unregistered host's lookups behind its drops are those from this long before them.
export const HOST_LOOKUP_LEAD_MS = 60_000;

// The names an unregistered host looked up from `from` until `to`, or with no end, each at its
// latest time, newest first, up to RECENT_CLIENTS.
export function hostLookups(
  database: DatabaseSync,
  clientIp: string,
  from: string,
  to: string | null,
) {
  // A plain upper bound, so the index range ends at `to`.
  const until = to === null ? "" : " AND at<=?";

  return database
    .prepare(
      `SELECT question,MAX(at) AS latest FROM events WHERE type='dns' AND source='suricata' AND instance_id IS NULL AND json_extract(details,'$.details.clientIp')=? AND at>=?${until} AND question!='' AND json_extract(details,'$.details.unregistered')='client' GROUP BY question ORDER BY latest DESC LIMIT ?`,
    )
    .all(clientIp, from, ...(to === null ? [] : [to]), RECENT_CLIENTS)
    .map((row) => ({ value: String(row.question), at: String(row.latest) }));
}

// The browser family from a User-Agent header, checked in this order because Edge and headless
// Chrome also name Chrome, and Chrome also names Safari.
const browsers = [
  ["HeadlessChrome/", "HeadlessChrome"],
  ["Edg/", "Edge"],
  ["Firefox/", "Firefox"],
  ["Chrome/", "Chrome"],
  ["Version/", "Safari"],
] as const;

export function browserName(agent: string): string | null {
  return browsers.find(([token]) => agent.includes(token))?.[1] ?? null;
}

// Policy changes keep their revisions and what changed; other audit entries have neither.
const auditDetailsSchema = z.object({
  beforeRevision: counterSchema,
  desiredRevision: counterSchema,
  changes: z.array(auditChangeSchema),
});

function auditDetails(details: string) {
  const parsed = auditDetailsSchema.safeParse(JSON.parse(details));

  return parsed.success
    ? {
        revisions: {
          before: parsed.data.beforeRevision,
          after: parsed.data.desiredRevision,
        },
        changes: parsed.data.changes,
      }
    : { revisions: null, changes: [] };
}

function auditClient(details: string) {
  const parsed = auditClientSchema.safeParse(JSON.parse(details));

  return parsed.success
    ? {
        address: parsed.data.client.address,
        browser: browserName(parsed.data.client.agent),
      }
    : null;
}

export class DashboardReads {
  // One whole-period event scan runs at a time.
  private scanning = false;

  constructor(private readonly database: DatabaseSync) {}

  conditions() {
    return this.database
      .prepare("SELECT * FROM conditions ORDER BY first_at DESC LIMIT 100")
      .all()
      .map((row) =>
        parseDashboard(conditionSchema, {
          code: String(row.code),
          message: String(row.message),
          firstAt: String(row.first_at),
          lastAt: String(row.last_at),
          occurrences: String(row.occurrences),
          recoveredAt:
            row.recovered_at === null ? null : String(row.recovered_at),
        }),
      );
  }
  // One view of the Requests: the newest 500 of every kind except dismissed hosts, or the newest
  // 500 dismissed hosts, which are kept apart so they never displace Requests. Either view adds
  // the host Request at `host` when it is not among them.
  requests(
    policy: DashboardPolicy,
    status: DashboardStatus,
    limit: number,
    host: string | null,
    view: RequestsView,
  ) {
    const hosts = (where: string) =>
      this.database.prepare(
        `SELECT client_ip AS id,'host' AS kind,client_ip AS peer_ip,attempts,first_at,last_at,CASE WHEN dismissed_at IS NULL THEN 'needs-review' ELSE 'dismissed' END AS state,destinations,names FROM host_requests WHERE ${where}`,
      );

    const rows =
      view === "dismissed"
        ? hosts(
            "dismissed_at IS NOT NULL ORDER BY julianday(last_at) DESC,client_ip DESC LIMIT 500",
          ).all()
        : this.database
            .prepare(
              "SELECT id,'connection' AS kind,instance_id,direction,peer_ip,protocol,port,NULL AS question,NULL AS query_type,attempts,first_at,last_at,rule_id,state,clients,NULL AS destinations,NULL AS names,julianday(last_at) AS time FROM requests WHERE state != ? UNION ALL SELECT id,'dns' AS kind,instance_id,NULL,NULL,NULL,NULL,question,query_type,attempts,first_at,last_at,rule_id,state,clients,NULL,NULL,julianday(last_at) AS time FROM dns_requests WHERE state != ? UNION ALL SELECT client_ip,'host' AS kind,NULL,NULL,client_ip,NULL,NULL,NULL,NULL,attempts,first_at,last_at,NULL,CASE WHEN dismissed_at IS NULL THEN 'needs-review' ELSE 'dismissed' END,NULL,destinations,names,julianday(last_at) AS time FROM host_requests WHERE dismissed_at IS NULL ORDER BY time DESC,id DESC LIMIT 500",
            )
            .all("resolved", "resolved");

    if (
      host !== null &&
      !rows.some((row) => row.kind === "host" && row.id === host)
    )
      rows.push(...hosts("client_ip=?").all(host));

    const count = this.database
      .prepare(
        "SELECT (SELECT COUNT(*) FROM requests WHERE state != 'resolved') + (SELECT COUNT(*) FROM dns_requests WHERE state != 'resolved') + (SELECT COUNT(*) FROM host_requests WHERE dismissed_at IS NULL) AS count",
      )
      .get()!;

    const recent = (stored: SQLOutputValue) =>
      readRecent(stored).map(({ value, at }) => ({ address: value, at }));

    const condition = this.database.prepare(
      "SELECT occurrences,last_at FROM conditions WHERE code=?",
    );

    const overflow = condition.get("requests_overflow");
    const omitted = condition.get("dns_denials_omitted");

    return parseDashboard(requestsSnapshotSchema, {
      view,
      retention: {
        pending: Number(count.count),
        limit,
        discarded: String(overflow?.occurrences ?? "0"),
        lastDiscardedAt: overflow ? String(overflow.last_at) : null,
        dnsOmitted: String(omitted?.occurrences ?? "0"),
        lastDnsOmittedAt: omitted ? String(omitted.last_at) : null,
      },
      requests: rows.map((row) =>
        row.kind === "host"
          ? {
              id: String(row.id),
              kind: "host",
              clientIp: String(row.peer_ip),
              attempts: String(row.attempts),
              firstAt: String(row.first_at),
              lastAt: String(row.last_at),
              state: String(row.state),
              destinations: recent(row.destinations),
              names: readRecent(row.names).map(({ value, at }) => ({
                name: value,
                at,
              })),
            }
          : {
              id: String(row.id),
              instanceId: String(row.instance_id),
              clients: recent(row.clients),
              ...(row.kind === "dns"
                ? {
                    kind: "dns",
                    question: String(row.question),
                    queryType: String(row.query_type),
                    ruleId: row.rule_id === null ? null : String(row.rule_id),
                  }
                : {
                    kind: "connection",
                    direction: row.direction,
                    peerIp: String(row.peer_ip),
                    protocol: Number(row.protocol),
                    port: row.port === -1 ? null : Number(row.port),
                    ruleId: String(row.rule_id),
                  }),
              attempts: String(row.attempts),
              firstAt: String(row.first_at),
              lastAt: String(row.last_at),
              state: row.state,
            },
      ),
      instances: policy.instances,
      rules: policy.rules,
      status,
      localNetworks: policy.settings.localNetworks,
    });
  }
  // Names for one instance and address: DNS answers the instance received that contained the
  // address, and TLS or HTTP names seen on its connections to it. Scans stop after 500 matches.
  requestNames(instanceId: string, peerIp: string) {
    const names = new Map<
      string,
      { hostname: string; source: "dns" | "tls" | "http"; lastSeenAt: string }
    >();

    const add = (
      hostname: string,
      source: "dns" | "tls" | "http",
      at: string,
    ) => {
      const name = nameSchema.safeParse(hostname);

      if (name.success && (names.get(name.data)?.lastSeenAt ?? "") < at)
        names.set(name.data, {
          hostname: name.data,
          source,
          lastSeenAt: at,
        });
    };

    const answers = this.database
      .prepare(
        "SELECT dns_answers.at,question FROM dns_answers JOIN events ON events.id=dns_answers.event_id WHERE dns_answers.instance_id=? AND address=? ORDER BY dns_answers.at DESC LIMIT 500",
      )
      .all(instanceId, peerIp);

    for (const row of answers)
      if (row.question) add(String(row.question), "dns", String(row.at));

    const observed = this.database
      .prepare(
        "SELECT at,json_extract(details,'$.details.hostname') AS hostname,json_extract(details,'$.details.eventType') AS source FROM events WHERE type='metadata' AND instance_id=? AND peer_ip=? ORDER BY at DESC LIMIT 500",
      )
      .all(instanceId, peerIp);

    for (const row of observed)
      if (row.hostname && (row.source === "tls" || row.source === "http"))
        add(String(row.hostname), row.source, String(row.at));

    return parseDashboard(requestNamesSchema, {
      names: [...names.values()]
        .sort((a, b) => b.lastSeenAt.localeCompare(a.lastSeenAt))
        .slice(0, 20),
    });
  }
  // Hostnames from confirmed resolver-gate answers that resolved each client's lookups to the
  // address. Only the client's indexed answers are read, up to the scan limit, before their events
  // are joined and grouped by name.
  requestSuggestions(
    instanceId: string,
    peerIp: string,
    clients: { address: string; at: string }[],
  ) {
    const statement = this.database.prepare(
      `WITH matched AS MATERIALIZED (SELECT event_id,at FROM dns_answers WHERE instance_id=? AND address=? AND suggestion_client_ip=? AND at>=? AND at<=? ORDER BY at DESC LIMIT ${SUGGESTION_SCAN_LIMIT + 1}) SELECT events.question AS question,MAX(matched.at) AS at,(SELECT COUNT(*) FROM matched) AS scanned FROM matched JOIN events ON events.id=matched.event_id GROUP BY events.question ORDER BY at DESC LIMIT ${MAX_SUGGESTIONS + 1}`,
    );

    const latest = new Map<string, string>();
    let complete = true;

    for (const client of clients) {
      const earliest = new Date(
        Date.parse(client.at) - SUGGESTION_WINDOW_MS,
      ).toISOString();

      const rows = statement.all(
        instanceId,
        peerIp,
        client.address,
        earliest,
        client.at,
      );

      if (
        rows.length > MAX_SUGGESTIONS ||
        Number(rows[0]?.scanned ?? 0) > SUGGESTION_SCAN_LIMIT
      )
        complete = false;

      for (const row of rows) {
        const name = nameSchema.safeParse(row.question);
        const at = String(row.at);

        if (name.success && (latest.get(name.data) ?? "") < at)
          latest.set(name.data, at);
      }
    }

    const hostnames = [...latest]
      .sort((a, b) => b[1].localeCompare(a[1]))
      .map(([name]) => name);

    return parseDashboard(requestSuggestionsSchema, {
      hostnames: hostnames.slice(0, MAX_SUGGESTIONS),
      complete: complete && hostnames.length <= MAX_SUGGESTIONS,
    });
  }
  history(limit: number, policy: DashboardPolicy, status: DashboardStatus) {
    const names = new Map(
      policy.instances.map((instance) => [instance.id, instance.name]),
    );

    const rows = this.database
      .prepare("SELECT * FROM audit ORDER BY at DESC LIMIT ?")
      .all(limit);

    const events = this.database
      .prepare("SELECT details FROM events ORDER BY at DESC LIMIT ?")
      .all(limit);

    const oldest = this.database
      .prepare("SELECT MIN(at) AS at FROM audit")
      .get()!;

    const entries = rows.map((row) => ({
      row,
      details: auditDetails(String(row.details)),
    }));

    // Each entry shows its rule as it was right after the entry. From the newest entry back, each
    // rule starts as it is now and every change is undone in turn: a deletion brings back the
    // recorded rule, an update restores the fields it changed, and a creation removes the rule.
    // Entries are loaded newest first, so every change newer than a loaded entry is loaded too.
    // Changes are undone by revision, since timestamps can tie or step back.
    const known = new Map(policy.rules.map((rule) => [rule.id, rule]));
    const asOf = new Map<string, Rule>();

    const changed = entries
      .filter(({ details }) => details.revisions)
      .map((entry) => ({
        ...entry,
        revision: BigInt(entry.details.revisions!.after),
      }))
      .sort((a, b) =>
        a.revision < b.revision ? 1 : a.revision > b.revision ? -1 : 0,
      );

    for (const { row, details } of changed) {
      const changes = details.changes.filter(
        (change) => change.subject === "rule" && change.id,
      );

      const deletion = changes.find(
        (change) => change.id === row.subject && !change.after,
      );

      const rule = deletion
        ? ruleSchema.safeParse(deletion.before).data
        : known.get(String(row.subject));

      if (rule) asOf.set(String(row.id), rule);

      for (const { id, before, after } of changes) {
        const previous = known.get(id!);

        const restored = !before
          ? undefined
          : ruleSchema.safeParse(after ? { ...previous, ...before } : before)
              .data;

        if (restored) known.set(id!, restored);
        else known.delete(id!);
      }
    }

    return parseDashboard(historySnapshotSchema, {
      audit: entries.map(({ row, details }) => {
        const subject = String(row.subject);

        const rule = asOf.get(String(row.id)) ?? null;

        return {
          id: String(row.id),
          at: String(row.at),
          actor: String(row.actor),
          action: String(row.action),
          subject,
          details: String(row.details),
          subjectLabel: rule
            ? describeRule(rule, policy.instances)
            : (names.get(subject) ?? null),
          subjectRule: rule,
          client: auditClient(String(row.details)),
          ...details,
        };
      }),
      events: events.map((row) => JSON.parse(String(row.details))),
      instances: policy.instances,
      rules: policy.rules,
      earliestAuditAt: oldest.at === null ? null : String(oldest.at),
      conditions: this.conditions(),
      status,
    });
  }
  // Drops of connections with no instance on either end: counted packets by side over the counter
  // buckets of the period, and the newest sampled drops, which share one history group, grouped by
  // side, client, destination, and service. Grouping reads at most EVENT_SUMMARY_LIMIT samples and
  // returns the newest UNREGISTERED_DROP_GROUPS groups. A client's drops to the gateway's DNS
  // listener, which it reaches directly or through forwarding the operator configured, carry the
  // names it looked up over their span.
  private unregistered(
    from: string,
    to: string,
    now: number,
    gateway: DashboardStatus["gateway"],
  ) {
    const resolution = Date.parse(from) >= now - 86400000 ? 60 : 3600;

    const packets = (side: "client" | "upstream") =>
      String(
        this.database
          .prepare(
            "SELECT COALESCE(SUM(packets),0) AS packets FROM blocked_counts WHERE instance_id='' AND rule_id=? AND direction='' AND resolution=? AND bucket>=? AND bucket<?",
          )
          .get(
            `unregistered:${side}`,
            resolution,
            bucketStart(from, resolution),
            to,
          )!.packets,
      );

    const samples = this.database
      .prepare(
        "SELECT at,peer_ip,json_extract(details,'$.details.unregistered') AS side,json_extract(details,'$.details.clientIp') AS client,json_extract(details,'$.protocol') AS protocol,json_extract(details,'$.port') AS port FROM events WHERE history_group='blocked:::' AND at>=? AND at<? ORDER BY at DESC LIMIT ?",
      )
      .all(from, to, EVENT_SUMMARY_LIMIT + 1);

    const groups = new Map<
      string,
      {
        side: string;
        clientIp: string;
        peerIp: string;
        protocol: number | null;
        port: number | null;
        samples: number;
        firstAt: string;
        lastAt: string;
      }
    >();

    // Samples come newest first, so a group's first sample sets its last time.
    for (const row of samples.slice(0, EVENT_SUMMARY_LIMIT)) {
      const drop = {
        side: String(row.side),
        clientIp: canonicalIp(String(row.client)),
        peerIp: String(row.peer_ip),
        protocol: row.protocol === null ? null : Number(row.protocol),
        port: row.port === null ? null : Number(row.port),
      };

      const key = JSON.stringify(Object.values(drop));
      const group = groups.get(key);

      if (group) {
        group.samples++;
        group.firstAt = String(row.at);
      } else
        groups.set(key, {
          ...drop,
          samples: 1,
          firstAt: String(row.at),
          lastAt: String(row.at),
        });
    }

    const requested = this.database.prepare(
      "SELECT 1 FROM host_requests WHERE client_ip=?",
    );

    return {
      clientPackets: packets("client"),
      upstreamPackets: packets("upstream"),
      drops: [...groups.values()]
        .slice(0, UNREGISTERED_DROP_GROUPS)
        .map((group) => {
          const client = group.side === "client";

          // A drop reaches the gateway as a connection to its service, whichever side it came from.
          const services =
            gateway && gateway.addresses.includes(group.peerIp)
              ? gatewayServices(gateway, "outgoing", group.protocol, group.port)
              : null;

          return {
            ...group,
            gateway: services && { services: services.map(({ name }) => name) },
            request: client && requested.get(group.clientIp) !== undefined,
            names:
              client && services?.some(({ name }) => name === "DNS")
                ? hostLookups(
                    this.database,
                    group.clientIp,
                    new Date(
                      Date.parse(group.firstAt) - HOST_LOOKUP_LEAD_MS,
                    ).toISOString(),
                    group.lastAt,
                  ).map(({ value, at }) => ({ name: value, at }))
                : [],
          };
        }),
      dropsTruncated: groups.size > UNREGISTERED_DROP_GROUPS,
      samplesLimited: samples.length > EVENT_SUMMARY_LIMIT,
    };
  }
  // Counted packets per Block rule and direction for one instance, beside the samples recorded
  // over the same window, which starts at the counter bucket containing `from`.
  private blockedTotals(
    instanceId: string,
    from: string,
    to: string,
    now: number,
  ) {
    const resolution = Date.parse(from) >= now - 86400000 ? 60 : 3600;
    const start = bucketStart(from, resolution);

    const counts = this.database
      .prepare(
        "SELECT rule_id,direction,SUM(packets) AS packets FROM blocked_counts WHERE instance_id=? AND resolution=? AND bucket>=? AND bucket<? GROUP BY 1,2",
      )
      .all(instanceId, resolution, start, to);

    // Each rule, instance, and direction has its own history group, so its samples are counted
    // from the group index alone.
    const sampled = this.database.prepare(
      "SELECT COUNT(*) AS count FROM events WHERE history_group=? AND at>=? AND at<?",
    );

    return counts.map((row) => ({
      ruleId: String(row.rule_id),
      direction: String(row.direction),
      packets: String(row.packets),
      samples: String(
        sampled.get(
          `blocked:${row.rule_id}:${instanceId}:${row.direction}`,
          start,
          to,
        )!.count,
      ),
    }));
  }
  // Groups the newest events of one instance, or of its listed peer addresses, by type, direction,
  // protocol, port, and the rule recorded on blocked samples. Reading stops at EVENT_SUMMARY_LIMIT
  // matching events, so a long period on a busy instance is summarized from its recent events. A
  // recent scan also stops after one slice of EVENT_SCAN_SLICE events and reports how far back it
  // read; a full scan reads the whole period.
  private async eventSummary(
    instanceId: string,
    peers: string[] | null,
    selection: MonitorSelection,
    from: string,
    to: string,
    now: number,
    scan: EventScan,
    signal?: AbortSignal,
  ) {
    // The unary pluses keep the read on the time index, newest first, so it stops at the limit.
    const filters = [
      "+instance_id=?",
      ...(peers ? [`+peer_ip IN (${peers.map(() => "?").join(",")})`] : []),
      "at>=?",
      "at<?",
      "type!='condition'",
    ];

    const values: (string | number)[] = [];

    for (const [field, value] of [
      ["direction", selection.direction],
      ["protocol", selection.protocol],
      ["port", selection.port],
    ] as const) {
      if (value !== undefined) {
        filters.push(
          `json_extract(details,'$.${field}') ${value === null ? "IS NULL" : "=?"}`,
        );

        if (value !== null) values.push(value);
      }
    }

    const newest = this.database.prepare(
      `SELECT type,at,json_extract(details,'$.direction') AS direction,json_extract(details,'$.protocol') AS protocol,json_extract(details,'$.port') AS port,CASE WHEN type='blocked' THEN json_extract(details,'$.ruleId') END AS rule_id FROM events WHERE ${filters.join(" AND ")} ORDER BY at DESC LIMIT ?`,
    );

    // The oldest time within the next slice, read from the time index alone.
    const sliceStart = this.database.prepare(
      `SELECT at FROM events WHERE at>=? AND at<? ORDER BY at DESC LIMIT 1 OFFSET ${EVENT_SCAN_SLICE - 1}`,
    );

    const rows: ReturnType<typeof newest.all> = [];
    let end = to;
    let scannedFrom: string | null = null;

    // A name selection without matching addresses has no events to read.
    while (!peers || peers.length) {
      // A full scan lets other requests run before each slice, including the first, which would
      // otherwise follow the Monitor's own reads without a break.
      if (scan === "full") {
        await setImmediate();
        signal?.throwIfAborted();
      }

      const start = sliceStart.get(from, end)?.at;

      rows.push(
        ...newest.all(
          instanceId,
          ...(peers ?? []),
          start === undefined ? from : String(start),
          end,
          ...values,
          EVENT_SUMMARY_LIMIT + 1 - rows.length,
        ),
      );

      if (start === undefined || rows.length > EVENT_SUMMARY_LIMIT) break;

      if (scan === "recent") {
        scannedFrom = String(start);
        break;
      }

      end = String(start);
    }

    // The snapshot schema validates the group fields when the snapshot is parsed.
    const groups = new Map<
      string,
      {
        type: string;
        direction: string | null;
        protocol: number | null;
        port: number | null;
        ruleId: string | null;
        lastAt: string;
      }
    >();

    const counts = new Map<string, number>();

    for (const row of rows.slice(0, EVENT_SUMMARY_LIMIT)) {
      const key = JSON.stringify([
        row.type,
        row.direction,
        row.protocol,
        row.port,
        row.rule_id,
      ]);

      counts.set(key, (counts.get(key) ?? 0) + 1);

      // Rows are newest first, so a group's first row is its last time.
      if (!groups.has(key))
        groups.set(key, {
          type: String(row.type),
          direction: row.direction === null ? null : String(row.direction),
          protocol: row.protocol === null ? null : Number(row.protocol),
          port: row.port === null ? null : Number(row.port),
          ruleId: row.rule_id === null ? null : String(row.rule_id),
          lastAt: String(row.at),
        });
    }

    // Newest groups first, with blocked samples leading.
    const sorted = [...groups]
      .map(([key, group]) => ({ ...group, count: String(counts.get(key)) }))
      .sort(
        (left, right) =>
          Number(right.type === "blocked") - Number(left.type === "blocked"),
      );

    return {
      events: sorted.slice(0, 100),
      eventsTruncated: sorted.length > 100,
      eventsLimited: rows.length > EVENT_SUMMARY_LIMIT,
      scannedFrom,
      blockedTotals: this.blockedTotals(instanceId, from, to, now),
    };
  }
  async monitor(
    from: string,
    to: string,
    selection: MonitorSelection,
    policy: DashboardPolicy,
    status: DashboardStatus,
    now = Date.now(),
    events?: EventScan,
    signal?: AbortSignal,
  ) {
    from = new Date(from).toISOString();
    to = new Date(to).toISOString();
    const duration = Date.parse(to) - Date.parse(from);

    if (duration < 0 || duration > 180 * 86400000)
      throw new ServiceError(
        400,
        "invalid_period",
        "Select a period within the retained 180 days",
      );

    const resolution =
      Date.parse(from) >= now - 86400000 && duration <= 3600000
        ? 5
        : Date.parse(from) >= now - 30 * 86400000 && duration <= 86400000
          ? 60
          : 3600;

    const filters = ["resolution=?", "bucket>=?", "bucket<?"];
    const args: (string | number)[] = [resolution, from, to];
    const active = policy.instances.map((instance) => instance.id);

    const activeWhere = active.length
      ? `instance_id IN (${active.map(() => "?").join(",")})`
      : "0";

    filters.push(activeWhere);
    args.push(...active);

    // The unary plus keeps this read on the time index, newest first, so it stops after 5,001
    // names instead of reading and sorting every name of the active instances.
    const observed = this.database
      .prepare(
        `SELECT details FROM events WHERE type='metadata' AND at>=? AND at<? AND +${activeWhere} ORDER BY at DESC LIMIT 5001`,
      )
      .all(from, to, ...active);

    if ((selection.domain || selection.hostname) && observed.length > 5000)
      throw new ServiceError(
        503,
        "name_scope_limit",
        "Too many name observations for this period. Select a shorter period.",
      );

    const labels = new Map<
      string,
      {
        instanceId: string;
        peerIp: string;
        hostname: string;
        domain: string | null;
        source: string;
        observedAt: string;
        protocol: number | null;
        port: number | null;
        direction: "outgoing" | "incoming" | null;
      }
    >();

    for (const row of observed.slice(0, 5000)) {
      const event = parseDashboard(
        eventSchema,
        JSON.parse(String(row.details)),
      );

      const rawHostname = event.details.hostname;

      if (
        !event.instanceId ||
        !event.peerIp ||
        // oxlint-disable-next-line anti-slop/no-runtime-typeof -- eventSchema validates metadata as a primitive union; this selects its string member.
        typeof rawHostname !== "string" ||
        !["http", "tls"].includes(String(event.details.eventType))
      )
        continue;
      const hostname = canonicalName(rawHostname);
      const key = JSON.stringify([event.instanceId, event.peerIp, hostname]);

      if (!labels.has(key))
        labels.set(key, {
          instanceId: event.instanceId,
          peerIp: event.peerIp,
          hostname,
          domain: registrableDomain(hostname),
          source: String(event.details.eventType),
          observedAt: event.observedAt,
          protocol: event.protocol,
          port: event.port,
          direction: event.direction,
        });
    }

    const names = [...labels.values()];
    let nameIps: string[] | null = null;

    if (selection.domain || selection.hostname) {
      const aliases = new Map<string, typeof names>();

      for (const name of names) {
        if (selection.instanceId && name.instanceId !== selection.instanceId)
          continue;
        const key = JSON.stringify([name.instanceId, name.peerIp]);
        aliases.set(key, [...(aliases.get(key) ?? []), name]);
      }

      const ips = [...aliases.values()].flatMap((values) =>
        values.length === 1 &&
        (!selection.domain ||
          (values[0]!.domain ?? values[0]!.hostname) === selection.domain) &&
        (!selection.hostname || values[0]!.hostname === selection.hostname)
          ? [values[0]!.peerIp]
          : [],
      );

      nameIps = ips;
      filters.push(
        ips.length ? `peer_ip IN (${ips.map(() => "?").join(",")})` : "0",
      );
      args.push(...ips);
    }

    for (const [column, value] of [
      ["instance_id", selection.instanceId],
      ["peer_ip", selection.peerIp],
      ["protocol", selection.protocol],
      ["port", selection.port],
      ["direction", selection.direction],
    ] as const) {
      if (value !== undefined) {
        filters.push(`${column}=?`);
        args.push(value === null ? -1 : value);
      }
    }

    const where = filters.join(" AND ");

    const totals = this.database
      .prepare(
        `SELECT tp_sum(sent) AS sent,tp_sum(received) AS received FROM metrics WHERE ${where}`,
      )
      .get(...args)!;

    const rows = this.database
      .prepare(
        `SELECT instance_id,direction,peer_ip,protocol,port,tp_sum(sent) AS sent,tp_sum(received) AS received FROM metrics WHERE ${where} GROUP BY instance_id,direction,peer_ip,protocol,port ORDER BY instance_id,peer_ip,protocol,port LIMIT 1001`,
      )
      .all(...args);

    const services = rows.slice(0, 1000).map((row) => {
      const scope = {
        instanceId: String(row.instance_id),
        direction: String(row.direction),
        peerIp: String(row.peer_ip),
        protocol: Number(row.protocol),
        port: row.port === -1 ? null : Number(row.port),
      };

      return {
        ...scope,
        key: JSON.stringify([
          scope.instanceId,
          scope.direction,
          scope.peerIp,
          scope.protocol,
          scope.port,
        ]),
        sentBytes: String(row.sent),
        receivedBytes: String(row.received),
      };
    });

    const timeline = this.database
      .prepare(
        `SELECT bucket,tp_sum(sent) AS sent,tp_sum(received) AS received FROM metrics WHERE ${where} GROUP BY bucket ORDER BY bucket`,
      )
      .all(...args)
      .map((row) => ({
        at: String(row.bucket),
        sentBytes: String(row.sent),
        receivedBytes: String(row.received),
      }));

    const peers =
      selection.peerIp === undefined
        ? nameIps
        : nameIps === null || nameIps.includes(selection.peerIp)
          ? [selection.peerIp]
          : [];

    let eventSummary = null;

    if (
      events !== undefined &&
      selection.instanceId !== undefined &&
      active.includes(selection.instanceId)
    ) {
      if (events === "full") {
        if (this.scanning)
          throw new ServiceError(
            409,
            "event_scan_busy",
            "Another whole-period scan is running. Try again when it finishes.",
          );
        this.scanning = true;
      }

      try {
        eventSummary = await this.eventSummary(
          selection.instanceId,
          peers,
          selection,
          from,
          to,
          now,
          events,
          signal,
        );
      } finally {
        if (events === "full") this.scanning = false;
      }
    }

    const serviceKeys = new Set(services.map((service) => service.key));

    const reviews = this.database
      .prepare(
        `SELECT instance_id,direction,peer_ip,protocol,port FROM requests WHERE state='needs-review' AND ${activeWhere}`,
      )
      .all(...active)
      .map((row) => ({
        instanceId: String(row.instance_id),
        direction: String(row.direction),
        peerIp: String(row.peer_ip),
        protocol: Number(row.protocol),
        port: row.port === -1 ? null : Number(row.port),
      }))
      .filter((review) =>
        serviceKeys.has(
          JSON.stringify([
            review.instanceId,
            review.direction,
            review.peerIp,
            review.protocol,
            review.port,
          ]),
        ),
      );

    return parseDashboard(monitorSnapshotSchema, {
      from,
      to,
      resolutionSeconds: resolution,
      sentBytes: String(totals.sent),
      receivedBytes: String(totals.received),
      services,
      servicesTruncated: rows.length > 1000,
      timeline,
      instances: policy.instances,
      status,
      coverage: "Routed conntrack measurements; missing buckets are unmeasured",
      names: names.filter(
        (name) =>
          (!selection.instanceId || name.instanceId === selection.instanceId) &&
          (!selection.peerIp || name.peerIp === selection.peerIp) &&
          (nameIps === null || nameIps.includes(name.peerIp)),
      ),
      namesTruncated: observed.length > 5000,
      eventSummary,
      reviews,
      rules: policy.rules,
      localNetworks: policy.settings.localNetworks,
      unregistered: this.unregistered(from, to, now, status.gateway),
    });
  }
}
