import { DatabaseSync, type SQLOutputValue } from "node:sqlite";
import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import ipaddr from "ipaddr.js";
import {
  StorageBudget,
  CONTROLLER_RESERVE,
} from "@traffic-policy/core/storage";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { hash, verify } from "@node-rs/argon2";
import {
  bucketStart,
  DashboardReads,
  parseDashboard,
  readRecent,
  HOST_LOOKUP_LEAD_MS,
  RECENT_CLIENTS,
  hostLookups,
  type EventScan,
} from "./dashboard-reads.ts";
import { policyChanges } from "./policy-changes.ts";
import {
  type AuditChange,
  dashboardStatusSchema,
  type GatewayEndpoint,
  gatewayEndpointSchema,
  type MonitorSelection,
  type RequestsView,
  type RulesSnapshot,
  rulesSnapshotSchema,
  storageSnapshotSchema,
} from "@traffic-policy/contracts/dashboard";
import {
  canonicalCidr,
  canonicalIp,
  historyLimitBytes,
  policySchema,
  policyTransportSchema,
  ruleSchema,
  eventSchema,
  gatewayReceiptSchema,
  ipSchema,
} from "@traffic-policy/contracts";
import type {
  EventBatch,
  GatewayEvent,
  GatewayReceipt,
  Policy,
  ScopeTree,
  Settings,
} from "@traffic-policy/contracts";
import {
  catchAllActions,
  compareRules,
  decideTraffic,
  decideDns,
  describeRule,
  isCatchAll,
  ruleState,
  scopeTree,
  subjectContext,
  type ObservedTraffic,
  type SubjectContext,
  type TrafficDecision,
} from "@traffic-policy/core";
import { hashDocument, ServiceError } from "@traffic-policy/core/io";

const tokenHash = (value: string) =>
  createHash("sha256").update(value).digest("hex");

const instant = () => new Date().toISOString();

// An IPv6 client usually controls its whole /64, so throttle the prefix.
function loginIdentity(address: string): string {
  try {
    const canonical = canonicalIp(address);

    return canonical.includes(":")
      ? canonicalCidr(`${canonical}/64`)
      : canonical;
  } catch {
    return address;
  }
}

const APPLICATION_ID = 0x54504e46;

const HOUR = 3600000;

// A browser session lasts 12 hours. A remembered session lasts 7 days, renews to 7 days when used
// with less than 5 days left, and ends 30 days after sign-in.
export const SESSION_MS = 12 * HOUR;

export const REMEMBERED_MS = 7 * 24 * HOUR;

const RENEW_BELOW_MS = 5 * 24 * HOUR;

const REMEMBERED_LIMIT_MS = 30 * 24 * HOUR;

export interface Session {
  remembered: boolean;
  // Set when this request renewed a remembered session.
  renewedUntil: string | null;
}

// Pending requests are kept in separate pools: connections, and DNS lookups with a share per
// instance.
export const MAX_CONNECTION_REQUESTS = 5000;

export const MAX_DNS_REQUESTS = 5000;

export const MAX_INSTANCE_DNS_REQUESTS = 500;

// Hosts outside every instance whose drops arrived on a client interface, waiting for
// registration.
export const MAX_HOST_REQUESTS = 10000;

// Dismissed hosts are kept apart and never removed for space, so a dismissal never lapses; at the
// limit, dismissing is refused.
export const MAX_DISMISSED_HOSTS = 10000;

export const MAX_PENDING_REQUESTS =
  MAX_CONNECTION_REQUESTS + MAX_DNS_REQUESTS + MAX_HOST_REQUESTS;

// Adds a value to a recent list stored as JSON [{ value, at }], newest first and distinct.
export function recentValues(
  stored: SQLOutputValue | undefined,
  value: string,
  at: string,
): string {
  return JSON.stringify(
    [
      { value, at },
      ...readRecent(stored).filter((entry) => entry.value !== value),
    ].slice(0, RECENT_CLIENTS),
  );
}

// Merges values into a recent list by time, keeping each value's latest, so an event that arrives
// late cannot displace newer ones.
export function latestValues(
  stored: SQLOutputValue | undefined,
  entries: { value: string; at: string }[],
): string {
  const latest = new Map<string, string>();

  for (const { value, at } of [...readRecent(stored), ...entries]) {
    const seen = latest.get(value);

    if (seen === undefined || at > seen) latest.set(value, at);
  }

  return JSON.stringify(
    [...latest]
      .map(([value, at]) => ({ value, at }))
      .sort((a, b) => (a.at < b.at ? 1 : -1))
      .slice(0, RECENT_CLIENTS),
  );
}

const REQUEST_ROW_BYTES = 512n;

const BLOCKED_COUNT_ROW_BYTES = 256;

// One indexed address of a DNS answer, charged to DNS history. A row with its suggestion index
// entry measured about 400 bytes.
const DNS_ANSWER_ROW_BYTES = 512;

// Retention trims at most this long in one write transaction, and deletes this many rows per
// statement.
export const PRUNE_SLICE_MS = 100;

const PRUNE_CHUNK = 512;

// Minute buckets cover the last day and hour buckets the last 180 days, like traffic metrics.
const BLOCKED_COUNT_RESOLUTIONS = [60, 3600] as const;

// The retention group of an event. Blocked samples are grouped by rule, instance, and direction
// so one instance's flood only displaces its own older samples, and each group's samples can be
// counted from the group index.
export const HISTORY_GROUP = `CASE type WHEN 'traffic' THEN 'traffic' WHEN 'dns' THEN 'dns' WHEN 'blocked' THEN 'blocked:'||COALESCE(json_extract(details,'$.ruleId'),'')||':'||COALESCE(instance_id,'')||':'||COALESCE(json_extract(details,'$.direction'),'') ELSE 'other' END`;

// Where an admin change came from, kept in its audit details.
export interface AuditClient {
  address: string;
  agent: string;
}

interface MutationAudit {
  beforeRevision: string;
  desiredRevision: string;
  changes: AuditChange[];
  client?: AuditClient;
}

// Source ranges that do not identify a host to register: link-local addresses repeat on every
// link, and the others are not unicast hosts.
const UNREGISTRABLE = new Set([
  "unspecified",
  "broadcast",
  "multicast",
  "linkLocal",
  "loopback",
]);

export class ControllerStore {
  private database: DatabaseSync;
  private reads: DashboardReads;
  private verifying = 0;
  private physicalBudget(): StorageBudget {
    return new StorageBudget(
      [dirname(this.path)],
      BigInt(this.desired().settings.controllerDiskBytes),
      CONTROLLER_RESERVE,
    );
  }
  constructor(
    readonly path: string,
    create = false,
  ) {
    if (!existsSync(path) && !create)
      throw new ServiceError(
        503,
        "not_initialized",
        "Controller storage has not been initialized",
      );

    if (create) mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.database = new DatabaseSync(path);
    this.database.aggregate("tp_sum", {
      start: "0",
      step: (previous, value) =>
        (BigInt(String(previous)) + BigInt(String(value))).toString(),
    });
    // The wait comes first: the browser and gateway link processes start together, and one may be
    // recovering the WAL when the other first reads.
    this.database.exec(
      "PRAGMA busy_timeout=2000; PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
    );

    if (create) this.initialize();
    const identity = this.database.prepare("PRAGMA application_id").get()!;
    const version = this.database.prepare("PRAGMA user_version").get()!;

    if (
      identity.application_id !== APPLICATION_ID ||
      version.user_version !== 1
    )
      throw new Error("Storage is not a compatible Traffic Policy database");

    if (this.database.prepare("PRAGMA quick_check").get()!.quick_check !== "ok")
      throw new Error("Controller storage integrity check failed");
    this.database.exec(
      "PRAGMA wal_autocheckpoint=256; PRAGMA journal_size_limit=4194304;",
    );
    this.reads = new DashboardReads(this.database);

    if (this.database.prepare("SELECT 1 FROM policy WHERE id=1").get())
      this.pruneRequests();
  }
  // Creates the schema in one transaction, so the browser and machine processes never see part of
  // it. Running processes only open initialized storage.
  private initialize() {
    this.transaction(() => this.createSchema());
  }
  private createSchema() {
    const identity = this.database.prepare("PRAGMA application_id").get()!
      .application_id;

    if (identity !== 0 && identity !== APPLICATION_ID)
      throw new Error("Refusing to initialize another application database");

    if (
      identity === 0 &&
      this.database
        .prepare(
          "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 1",
        )
        .get()
    ) {
      throw new Error(
        "Refusing to initialize a database containing unrelated tables",
      );
    }

    const version = this.database.prepare("PRAGMA user_version").get()!
      .user_version;

    if (identity === APPLICATION_ID && version !== 1)
      throw new Error("Refusing to overwrite an unsupported storage version");
    this.database.exec(`
      PRAGMA application_id=${APPLICATION_ID}; PRAGMA user_version=1;
      CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK(id=1), password_hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, expires_at TEXT NOT NULL, remembered INTEGER NOT NULL, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS login_failures (identity TEXT PRIMARY KEY, attempts INTEGER NOT NULL, since TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS policy (id INTEGER PRIMARY KEY CHECK(id=1), desired TEXT NOT NULL, applied TEXT, receipt TEXT, last_error TEXT, last_seen TEXT);
      CREATE TABLE IF NOT EXISTS audit (id TEXT PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL, details TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS audit_time ON audit(at);
      CREATE TABLE IF NOT EXISTS batches (epoch TEXT NOT NULL, sequence TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(epoch,sequence));
      CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, at TEXT NOT NULL, type TEXT NOT NULL, instance_id TEXT, peer_ip TEXT, question TEXT, source TEXT NOT NULL, details TEXT NOT NULL,
        history_group TEXT GENERATED ALWAYS AS (${HISTORY_GROUP}) VIRTUAL);
      CREATE INDEX IF NOT EXISTS event_time ON events(at);
      CREATE TABLE IF NOT EXISTS metrics (instance_id TEXT NOT NULL, direction TEXT NOT NULL, peer_ip TEXT NOT NULL, protocol INTEGER NOT NULL, port INTEGER NOT NULL,
        resolution INTEGER NOT NULL, bucket TEXT NOT NULL, sent TEXT NOT NULL, received TEXT NOT NULL, samples INTEGER NOT NULL,
        PRIMARY KEY(instance_id,direction,peer_ip,protocol,port,resolution,bucket));
      CREATE INDEX IF NOT EXISTS metric_time ON metrics(resolution,bucket);
      CREATE INDEX IF NOT EXISTS metric_age ON metrics(bucket,resolution);
      CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, direction TEXT NOT NULL, peer_ip TEXT NOT NULL, protocol INTEGER NOT NULL, port INTEGER NOT NULL,
        attempts TEXT NOT NULL, first_at TEXT NOT NULL, last_at TEXT NOT NULL, rule_id TEXT NOT NULL, state TEXT NOT NULL, clients TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS conditions (code TEXT PRIMARY KEY, message TEXT NOT NULL, first_at TEXT NOT NULL, last_at TEXT NOT NULL, occurrences TEXT NOT NULL, recovered_at TEXT);
    `);
    // Event usage is kept per history group: traffic, dns, other, and
    // blocked:<rule>:<instance>:<direction>.
    this.database.exec(`
      CREATE INDEX IF NOT EXISTS event_group_time ON events(history_group,at);
      CREATE TABLE IF NOT EXISTS blocked_counts (instance_id TEXT NOT NULL, rule_id TEXT NOT NULL, direction TEXT NOT NULL, resolution INTEGER NOT NULL, bucket TEXT NOT NULL, packets INTEGER NOT NULL,
        PRIMARY KEY(instance_id,rule_id,direction,resolution,bucket));
      CREATE INDEX IF NOT EXISTS blocked_count_time ON blocked_counts(resolution,bucket);
      CREATE INDEX IF NOT EXISTS blocked_count_age ON blocked_counts(bucket,resolution);
      CREATE TABLE IF NOT EXISTS dns_answers (event_id TEXT NOT NULL, instance_id TEXT NOT NULL, address TEXT NOT NULL, at TEXT NOT NULL, suggestion_client_ip TEXT, UNIQUE(event_id,address));
      CREATE INDEX IF NOT EXISTS dns_answer_lookup ON dns_answers(instance_id,address,at);
      CREATE INDEX IF NOT EXISTS dns_answer_suggestion ON dns_answers(instance_id,address,suggestion_client_ip,at) WHERE suggestion_client_ip IS NOT NULL;
      CREATE INDEX IF NOT EXISTS event_metadata_peer_time ON events(instance_id,peer_ip,at) WHERE type='metadata';
      CREATE INDEX IF NOT EXISTS event_host_lookup_time ON events(json_extract(details,'$.details.clientIp'),at) WHERE type='dns' AND source='suricata' AND instance_id IS NULL;
      CREATE TABLE IF NOT EXISTS gateway_resources (id INTEGER PRIMARY KEY CHECK(id=1),at TEXT NOT NULL,details TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS gateway_endpoint (id INTEGER PRIMARY KEY CHECK(id=1),details TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS storage_usage (name TEXT PRIMARY KEY,bytes INTEGER NOT NULL);
      INSERT OR IGNORE INTO storage_usage SELECT 'audit',COALESCE(SUM(length(CAST(details AS BLOB))+256),0) FROM audit;
      INSERT OR IGNORE INTO storage_usage SELECT 'metrics',COUNT(*)*512 FROM metrics;
      INSERT OR IGNORE INTO storage_usage SELECT 'requests',COUNT(*)*512 FROM requests;
      INSERT OR IGNORE INTO storage_usage SELECT 'events:'||history_group,SUM(length(CAST(details AS BLOB))+256) FROM events GROUP BY history_group;
      INSERT OR IGNORE INTO storage_usage SELECT 'blocked_counts',COUNT(*)*${BLOCKED_COUNT_ROW_BYTES} FROM blocked_counts;
      INSERT OR IGNORE INTO storage_usage SELECT 'dns_answers',COUNT(*)*${DNS_ANSWER_ROW_BYTES} FROM dns_answers;
      CREATE INDEX IF NOT EXISTS request_retention_time ON requests(julianday(last_at),id);
      CREATE TRIGGER IF NOT EXISTS usage_audit_insert AFTER INSERT ON audit BEGIN UPDATE storage_usage SET bytes=bytes+length(CAST(NEW.details AS BLOB))+256 WHERE name='audit'; END;
      CREATE TRIGGER IF NOT EXISTS usage_audit_delete AFTER DELETE ON audit BEGIN UPDATE storage_usage SET bytes=bytes-length(CAST(OLD.details AS BLOB))-256 WHERE name='audit'; END;
      CREATE TRIGGER IF NOT EXISTS usage_metric_insert AFTER INSERT ON metrics BEGIN UPDATE storage_usage SET bytes=bytes+512 WHERE name='metrics'; END;
      CREATE TRIGGER IF NOT EXISTS usage_metric_delete AFTER DELETE ON metrics BEGIN UPDATE storage_usage SET bytes=bytes-512 WHERE name='metrics'; END;
      CREATE TRIGGER IF NOT EXISTS usage_request_insert AFTER INSERT ON requests BEGIN UPDATE storage_usage SET bytes=bytes+512 WHERE name='requests'; END;
      CREATE TRIGGER IF NOT EXISTS usage_request_delete AFTER DELETE ON requests BEGIN UPDATE storage_usage SET bytes=bytes-512 WHERE name='requests'; END;
      CREATE TRIGGER IF NOT EXISTS usage_group_insert AFTER INSERT ON events BEGIN INSERT INTO storage_usage VALUES('events:'||NEW.history_group,length(CAST(NEW.details AS BLOB))+256) ON CONFLICT(name) DO UPDATE SET bytes=bytes+excluded.bytes; END;
      CREATE TRIGGER IF NOT EXISTS usage_group_delete AFTER DELETE ON events BEGIN
        UPDATE storage_usage SET bytes=bytes-length(CAST(OLD.details AS BLOB))-256 WHERE name='events:'||OLD.history_group;
        DELETE FROM storage_usage WHERE name='events:'||OLD.history_group AND bytes<=0;
      END;
      CREATE TRIGGER IF NOT EXISTS usage_blocked_count_insert AFTER INSERT ON blocked_counts BEGIN UPDATE storage_usage SET bytes=bytes+${BLOCKED_COUNT_ROW_BYTES} WHERE name='blocked_counts'; END;
      CREATE TRIGGER IF NOT EXISTS usage_blocked_count_delete AFTER DELETE ON blocked_counts BEGIN UPDATE storage_usage SET bytes=bytes-${BLOCKED_COUNT_ROW_BYTES} WHERE name='blocked_counts'; END;
      CREATE TRIGGER IF NOT EXISTS usage_dns_answer_insert AFTER INSERT ON dns_answers BEGIN UPDATE storage_usage SET bytes=bytes+${DNS_ANSWER_ROW_BYTES} WHERE name='dns_answers'; END;
      CREATE TRIGGER IF NOT EXISTS usage_dns_answer_delete AFTER DELETE ON dns_answers BEGIN UPDATE storage_usage SET bytes=bytes-${DNS_ANSWER_ROW_BYTES} WHERE name='dns_answers'; END;
      CREATE TRIGGER IF NOT EXISTS dns_answer_event_delete AFTER DELETE ON events WHEN OLD.type='dns' BEGIN DELETE FROM dns_answers WHERE event_id=OLD.id; END;
      CREATE TABLE IF NOT EXISTS dns_requests (id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, question TEXT NOT NULL, query_type TEXT NOT NULL,
        attempts TEXT NOT NULL, first_at TEXT NOT NULL, last_at TEXT NOT NULL, rule_id TEXT, state TEXT NOT NULL, clients TEXT NOT NULL);
      INSERT OR IGNORE INTO storage_usage SELECT 'dns_requests',COUNT(*)*512 FROM dns_requests;
      CREATE INDEX IF NOT EXISTS dns_request_retention_time ON dns_requests(julianday(last_at),id);
      CREATE TRIGGER IF NOT EXISTS usage_dns_request_insert AFTER INSERT ON dns_requests BEGIN UPDATE storage_usage SET bytes=bytes+512 WHERE name='dns_requests'; END;
      CREATE TRIGGER IF NOT EXISTS usage_dns_request_delete AFTER DELETE ON dns_requests BEGIN UPDATE storage_usage SET bytes=bytes-512 WHERE name='dns_requests'; END;
      CREATE TABLE IF NOT EXISTS host_requests (client_ip TEXT PRIMARY KEY, attempts TEXT NOT NULL, first_at TEXT NOT NULL, last_at TEXT NOT NULL,
        destinations TEXT NOT NULL, names TEXT NOT NULL, dismissed_at TEXT);
      INSERT OR IGNORE INTO storage_usage SELECT 'host_requests',COUNT(*)*512 FROM host_requests;
      CREATE INDEX IF NOT EXISTS host_request_retention_time ON host_requests(julianday(last_at),client_ip);
      CREATE TRIGGER IF NOT EXISTS usage_host_request_insert AFTER INSERT ON host_requests BEGIN UPDATE storage_usage SET bytes=bytes+512 WHERE name='host_requests'; END;
      CREATE TRIGGER IF NOT EXISTS usage_host_request_delete AFTER DELETE ON host_requests BEGIN UPDATE storage_usage SET bytes=bytes-512 WHERE name='host_requests'; END;
    `);
  }
  close() {
    this.database.close();
  }
  // Runs work in one write transaction, or inside the caller's. The browser and machine processes
  // share the database, so a read-then-write must not interleave with the other's writes.
  private transaction<T>(work: () => T): T {
    if (this.database.isTransaction) return work();
    this.database.exec("BEGIN IMMEDIATE");

    try {
      const result = work();

      this.database.exec("COMMIT");

      return result;
    } catch (error) {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      throw error;
    }
  }
  private groupUsage(pattern: string): bigint {
    return BigInt(
      String(
        this.database
          .prepare(
            "SELECT COALESCE(SUM(bytes),0) AS bytes FROM storage_usage WHERE name GLOB ?",
          )
          .get(pattern)!.bytes,
      ),
    );
  }
  private historyUsage() {
    return {
      traffic: this.groupUsage("events:traffic") + this.usage("metrics"),
      dns: this.groupUsage("events:dns") + this.usage("dns_answers"),
      blocked:
        this.groupUsage("events:blocked:*") + this.usage("blocked_counts"),
      other: this.groupUsage("events:other"),
    };
  }
  private usage(name: string): bigint {
    return BigInt(
      String(
        this.database
          .prepare("SELECT bytes FROM storage_usage WHERE name=?")
          .get(name)!.bytes,
      ),
    );
  }

  async setup(password: string, settings: Settings): Promise<void> {
    if (!password || Buffer.byteLength(password) > 1024)
      throw new ServiceError(
        400,
        "invalid_password",
        "Password must be present and at most 1024 bytes",
      );

    const passwordHash = await hash(password, {
      algorithm: 2,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
      outputLen: 32,
    });

    this.database.exec("BEGIN IMMEDIATE");

    try {
      this.database
        .prepare(
          "INSERT INTO admin(id,password_hash) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET password_hash=excluded.password_hash",
        )
        .run(passwordHash);
      this.database.prepare("DELETE FROM sessions").run();

      if (!this.database.prepare("SELECT id FROM policy WHERE id=1").get()) {
        const now = instant();

        const catchall = ruleSchema.parse({
          id: randomUUID(),
          subject: { kind: "global" },
          direction: "both",
          peer: { kind: "any" },
          protocol: null,
          ports: null,
          icmpType: null,
          icmpCode: null,
          action: "block",
          priority: "normal",
          enabled: true,
          notBefore: null,
          expiresAt: null,
          dnsDestinations: null,
          createdAt: now,
          modifiedAt: now,
          reason: "Initial global catch-all",
        });

        const policy = policyTransportSchema.parse({
          protocolVersion: 1,
          revision: "1",
          generatedAt: now,
          instances: [],
          rules: [catchall],
          settings,
        });

        this.database
          .prepare("INSERT INTO policy(id,desired) VALUES(1,?)")
          .run(JSON.stringify(policy));
      }

      this.audit("Admin", "authentication-configured", "Admin", {});
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  async login(
    password: string,
    identity: string,
    remembered = false,
  ): Promise<string> {
    const key = tokenHash(loginIdentity(identity));
    const now = instant();
    this.database
      .prepare("DELETE FROM login_failures WHERE since <= ?")
      .run(new Date(Date.now() - 60000).toISOString());

    const failures = this.database
      .prepare("SELECT * FROM login_failures WHERE identity=?")
      .get(key);

    if (
      failures &&
      Date.now() - Date.parse(String(failures.since)) < 60000 &&
      Number(failures.attempts) >= 5
    ) {
      throw new ServiceError(
        429,
        "login_throttled",
        "Too many login attempts. Try again shortly.",
      );
    }

    if (
      this.verifying >= 4 ||
      (!failures &&
        Number(
          this.database
            .prepare("SELECT count(*) AS count FROM login_failures")
            .get()!.count,
        ) >= 4096)
    )
      throw new ServiceError(
        429,
        "login_throttled",
        "Too many login attempts. Try again shortly.",
      );

    const admin = this.database
      .prepare("SELECT password_hash FROM admin WHERE id=1")
      .get();

    if (!admin)
      throw new ServiceError(
        503,
        "admin_not_configured",
        "Admin authentication has not been configured",
      );

    if (
      !/^\$argon2id\$v=19\$m=65536,t=3,p=4\$/.test(String(admin.password_hash))
    )
      throw new Error("Stored password parameters are invalid");
    this.database
      .prepare(
        "INSERT INTO login_failures VALUES(?,1,?) ON CONFLICT(identity) DO UPDATE SET attempts=attempts+1",
      )
      .run(key, now);
    this.verifying++;
    let valid: boolean;

    try {
      valid =
        Buffer.byteLength(password) <= 1024 &&
        (await verify(String(admin.password_hash), password));
    } finally {
      this.verifying--;
    }

    if (!valid) {
      throw new ServiceError(
        401,
        "invalid_credentials",
        "Password is incorrect",
      );
    }

    this.database
      .prepare("DELETE FROM login_failures WHERE identity=?")
      .run(key);

    if (
      this.database.prepare("SELECT password_hash FROM admin WHERE id=1").get()!
        .password_hash !== admin.password_hash
    ) {
      throw new ServiceError(
        401,
        "credentials_changed",
        "Credentials changed. Sign in again.",
      );
    }

    const token = randomBytes(32).toString("base64url");
    const created = Date.now();
    this.database
      .prepare("INSERT INTO sessions VALUES(?,?,?,?)")
      .run(
        tokenHash(token),
        new Date(
          created + (remembered ? REMEMBERED_MS : SESSION_MS),
        ).toISOString(),
        remembered ? 1 : 0,
        new Date(created).toISOString(),
      );

    return token;
  }
  authenticated(token: string | undefined, now = Date.now()): Session | null {
    if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;

    const hashed = tokenHash(token);

    const row = this.database
      .prepare(
        "SELECT expires_at, remembered, created_at FROM sessions WHERE token_hash=?",
      )
      .get(hashed);

    if (!row) return null;

    const expires = Date.parse(String(row.expires_at));

    if (expires <= now) return null;

    if (!row.remembered) return { remembered: false, renewedUntil: null };

    const limit = Date.parse(String(row.created_at)) + REMEMBERED_LIMIT_MS;
    const renewed = Math.min(now + REMEMBERED_MS, limit);

    if (expires - now >= RENEW_BELOW_MS || renewed <= expires)
      return { remembered: true, renewedUntil: null };

    const renewedUntil = new Date(renewed).toISOString();
    this.database
      .prepare("UPDATE sessions SET expires_at=? WHERE token_hash=?")
      .run(renewedUntil, hashed);

    return { remembered: true, renewedUntil };
  }
  logout(token: string | undefined) {
    if (token)
      this.database
        .prepare("DELETE FROM sessions WHERE token_hash=?")
        .run(tokenHash(token));
  }

  desired(): Policy {
    const row = this.database
      .prepare("SELECT desired FROM policy WHERE id=1")
      .get();

    if (!row)
      throw new ServiceError(
        503,
        "not_initialized",
        "Controller policy has not been initialized",
      );

    return policySchema.parse(JSON.parse(String(row.desired)));
  }
  // The gateway's last reported addresses and DNS gate port; null until it reports them.
  gatewayEndpoint(): GatewayEndpoint | null {
    const row = this.database
      .prepare("SELECT details FROM gateway_endpoint WHERE id=1")
      .get();

    return row
      ? gatewayEndpointSchema.parse(JSON.parse(String(row.details)))
      : null;
  }
  status() {
    const row = this.database.prepare("SELECT * FROM policy WHERE id=1").get();

    if (!row)
      throw new ServiceError(
        503,
        "not_initialized",
        "Controller policy has not been initialized",
      );
    const desired = policySchema.parse(JSON.parse(String(row.desired)));

    const receipt = row.receipt
      ? gatewayReceiptSchema.parse(JSON.parse(String(row.receipt)))
      : null;

    return parseDashboard(dashboardStatusSchema, {
      desiredRevision: desired.revision,
      appliedRevision: receipt?.revision ?? null,
      pending: receipt?.revision !== desired.revision,
      lastError: row.last_error,
      lastSeen: row.last_seen,
      receipt,
      conditions: this.reads.conditions(),
      needsReview: Number(
        this.database
          .prepare(
            "SELECT (SELECT COUNT(*) FROM requests WHERE state='needs-review') + (SELECT COUNT(*) FROM dns_requests WHERE state='needs-review') + (SELECT COUNT(*) FROM host_requests WHERE dismissed_at IS NULL) AS count",
          )
          .get()!.count,
      ),
      gateway: this.gatewayEndpoint(),
    });
  }
  mutation(
    expectedRevision: string,
    action: string,
    subject: string,
    change: (policy: Policy) => Policy,
    client: AuditClient | null = null,
  ): Policy {
    this.database.exec("BEGIN IMMEDIATE");

    try {
      const previous = this.desired();

      if (previous.revision !== expectedRevision)
        throw new ServiceError(
          409,
          "revision_conflict",
          "Policy changed. Review the current values before saving again.",
        );

      const candidate = policyTransportSchema.parse({
        ...change(structuredClone(previous)),
        revision: (BigInt(previous.revision) + 1n).toString(),
        generatedAt: instant(),
      });

      new StorageBudget(
        [dirname(this.path)],
        BigInt(candidate.settings.controllerDiskBytes),
        CONTROLLER_RESERVE,
      ).assertRoom(
        BigInt(Buffer.byteLength(JSON.stringify(candidate))) * 8n + 1048576n,
        true,
      );
      this.database
        .prepare("UPDATE policy SET desired=?,last_error=NULL WHERE id=1")
        .run(JSON.stringify(candidate));

      const details: MutationAudit = {
        beforeRevision: previous.revision,
        desiredRevision: candidate.revision,
        changes: policyChanges(previous, candidate),
      };

      if (client) details.client = client;
      this.audit("Admin", action, subject, details);
      this.resolveRequests(candidate);
      this.prune();
      this.database.exec("COMMIT");

      return candidate;
    } catch (error) {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      throw error;
    }
  }
  confirm(policy: Policy, receipt: GatewayReceipt) {
    if (
      receipt.revision !== policy.revision ||
      receipt.policyHash !== hashDocument(policy)
    )
      throw new ServiceError(
        503,
        "policy_drift",
        "Gateway receipt does not identify the submitted policy",
      );
    // An older receipt is recorded but leaves the requests of a newer desired revision pending.
    this.transaction(() => {
      this.database
        .prepare(
          "UPDATE policy SET applied=?,receipt=?,last_error=NULL,last_seen=? WHERE id=1",
        )
        .run(JSON.stringify(policy), JSON.stringify(receipt), instant());
      this.recoverCondition("gateway_delivery");

      if (this.desired().revision === policy.revision) {
        this.resolveRequests(policy);
        this.database
          .prepare("UPDATE requests SET state=? WHERE state=?")
          .run("resolved", "applying");
        this.database
          .prepare("UPDATE dns_requests SET state=? WHERE state=?")
          .run("resolved", "applying");
        this.pruneRequests();
      }
    });
  }
  // Fails applying requests only while the revision that failed is still desired; a newer revision
  // has its own delivery ahead.
  deliveryFailed(message: string, revision: string) {
    this.transaction(() => {
      this.database
        .prepare("UPDATE policy SET last_error=? WHERE id=1")
        .run(message.slice(0, 1024));
      this.condition("gateway_delivery", message.slice(0, 1024));

      if (this.desired().revision === revision) {
        this.database
          .prepare("UPDATE requests SET state=? WHERE state=?")
          .run("failed", "applying");
        this.database
          .prepare("UPDATE dns_requests SET state=? WHERE state=?")
          .run("failed", "applying");
      }
    });
  }
  seen() {
    this.database
      .prepare("UPDATE policy SET last_seen=? WHERE id=1")
      .run(instant());
  }

  private audit(
    actor: "Admin",
    action: string,
    subject: string,
    // oxlint-disable-next-line anti-slop/no-unknown-parameters -- The audit serializer stores JSON details for several distinct operation types.
    details: unknown,
  ) {
    this.database
      .prepare("INSERT INTO audit VALUES(?,?,?,?,?,?)")
      .run(
        randomUUID(),
        instant(),
        actor,
        action,
        subject,
        JSON.stringify(details),
      );
  }
  condition(code: string, message: string, occurrences = 1n) {
    const previous = this.database
      .prepare("SELECT occurrences,first_at FROM conditions WHERE code=?")
      .get(code);

    this.database
      .prepare(
        "INSERT INTO conditions VALUES(?,?,?,?,?,NULL) ON CONFLICT(code) DO UPDATE SET message=excluded.message,last_at=excluded.last_at,occurrences=excluded.occurrences,recovered_at=NULL",
      )
      .run(
        code,
        message,
        previous?.first_at ?? instant(),
        instant(),
        (BigInt(String(previous?.occurrences ?? "0")) + occurrences).toString(),
      );
  }
  private recoverCondition(code: string) {
    this.database
      .prepare(
        "UPDATE conditions SET recovered_at=? WHERE code=? AND recovered_at IS NULL",
      )
      .run(instant(), code);
  }
  gatewayHealth(value: {
    endpoint?: GatewayEndpoint;
    condition?: string | null;
    suricataCondition?: string | null;
    dnsCondition?: string | null;
    storage?: {
      allocatedBytes: string;
      logicalBytes: string;
      limitBytes: string;
      reserveBytes: string;
    };
    collector?: {
      lostBatches: string;
      firstLossAt: string | null;
      lastLossAt: string | null;
      deliveryError?: string | null;
      persistenceError?: string | null;
      coverageCondition?: string | null;
      rejectedRecords?: string;
      firstRejectedAt?: string | null;
      lastRejectedAt?: string | null;
      rejectionCheckpointPending?: boolean;
    };
  }) {
    if (value.endpoint)
      this.database
        .prepare(
          "INSERT INTO gateway_endpoint VALUES(1,?) ON CONFLICT(id) DO UPDATE SET details=excluded.details",
        )
        .run(JSON.stringify(gatewayEndpointSchema.parse(value.endpoint)));

    if (value.storage)
      this.database
        .prepare(
          "INSERT INTO gateway_resources VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET at=excluded.at,details=excluded.details",
        )
        .run(
          instant(),
          JSON.stringify(storageSnapshotSchema.parse(value.storage)),
        );

    const update = (code: string, message: string | null) => {
      if (!message) {
        this.recoverCondition(code);

        return;
      }

      const current = this.database
        .prepare("SELECT message,recovered_at FROM conditions WHERE code=?")
        .get(code);

      if (current?.message !== message || current.recovered_at !== null)
        this.condition(code, message.slice(0, 1024));
    };

    update("gateway_coverage", value.condition ?? null);
    update("suricata_collection", value.suricataCondition ?? null);
    update("dns_receive_buffer", value.dnsCondition ?? null);
    update("collector_delivery", value.collector?.deliveryError ?? null);
    update("collector_persistence", value.collector?.persistenceError ?? null);
    update("collector_coverage", value.collector?.coverageCondition ?? null);

    if (value.collector?.rejectedRecords !== undefined) {
      const period =
        value.collector.firstRejectedAt && value.collector.lastRejectedAt
          ? ` between ${value.collector.firstRejectedAt} and ${value.collector.lastRejectedAt}`
          : "";

      update(
        "collector_rejected",
        BigInt(value.collector.rejectedRecords) > 0n
          ? `${value.collector.rejectedRecords} DNS observations could not be recorded${period}`
          : null,
      );
      update(
        "collector_rejection_checkpoint",
        value.collector.rejectionCheckpointPending
          ? "Observation rejection counts have not yet been saved; a restart may lose some counts"
          : null,
      );
    }

    if (value.collector && BigInt(value.collector.lostBatches) > 0n) {
      update(
        "collector_loss",
        `${value.collector.lostBatches} observation batches were lost between ${value.collector.firstLossAt} and ${value.collector.lastLossAt}`,
      );
    }
  }

  private isBatchReplay(batch: EventBatch, identity: string): boolean {
    const previous = this.database
      .prepare(
        "SELECT hash,sequence FROM batches WHERE epoch=? ORDER BY length(sequence) DESC,sequence DESC LIMIT 1",
      )
      .get(batch.epoch);

    if (previous && BigInt(batch.sequence) < BigInt(String(previous.sequence)))
      throw new ServiceError(
        409,
        "stale_batch",
        "Observation batch precedes the persisted delivery cursor",
      );

    if (previous?.sequence !== batch.sequence) return false;

    if (previous.hash !== identity)
      throw new ServiceError(
        409,
        "batch_identity_conflict",
        "Batch identity cannot contain different observations",
      );

    return true;
  }
  ingest(batch: EventBatch): Pick<EventBatch, "epoch" | "sequence"> {
    const identity = hashDocument(batch);

    if (this.isBatchReplay(batch, identity))
      return { epoch: batch.epoch, sequence: batch.sequence };
    this.database.exec("PRAGMA wal_checkpoint(PASSIVE)");
    // Ingest trims one chunk per step, enough for a batch's own excess; the gateway link's trim
    // loop does larger trims, so ingest holds the writer briefly while one runs.
    this.prune(0);
    this.physicalBudget().assertRoom(
      BigInt(Buffer.byteLength(JSON.stringify(batch))) * 8n + 1048576n,
    );
    this.database.exec("BEGIN IMMEDIATE");

    try {
      if (this.isBatchReplay(batch, identity)) {
        this.database.exec("COMMIT");

        return { epoch: batch.epoch, sequence: batch.sequence };
      }

      const findEvent = this.database.prepare(
        "SELECT details FROM events WHERE id=?",
      );

      const insertEvent = this.database.prepare(
        "INSERT OR IGNORE INTO events(id,at,type,instance_id,peer_ip,question,source,details) VALUES(?,?,?,?,?,?,?,?)",
      );

      const addAnswer = this.database.prepare(
        "INSERT OR IGNORE INTO dns_answers VALUES(?,?,?,?,?)",
      );

      const addCount = this.database.prepare(
        "INSERT INTO blocked_counts VALUES(?,?,?,?,?,?) ON CONFLICT(instance_id,rule_id,direction,resolution,bucket) DO UPDATE SET packets=packets+excluded.packets",
      );

      // Denials can arrive after the policy that decides their scope. A denied scope the current
      // policy decides is applying until the gateway confirms that policy, and a denial arriving
      // after confirmation predates it. A Request belongs to the client's current instance and is
      // decided for that client; a denial from an address no instance covers now is not a Request.
      let current: {
        policy: Policy;
        applied: boolean;
        tree: ScopeTree;
      } | null = null;

      const policyNow = () => {
        if (!current) {
          const policy = this.desired();

          current = {
            policy,
            applied: this.status().appliedRevision === policy.revision,
            tree: scopeTree(policy),
          };
        }

        return current;
      };

      const clientContext = (clientIp: string) =>
        subjectContext(policyNow().tree, clientIp);

      const deniedState = (
        decided: boolean,
        previous: SQLOutputValue | undefined,
      ) => {
        if (decided) return policyNow().applied ? null : "applying";

        return previous === "applying" ? "applying" : "needs-review";
      };

      for (const event of batch.events) {
        // Counts are aggregated only. The batch sequence keeps them from being added twice. An
        // unregistered count has no instance or rule; it is kept under its side.
        if (event.type === "blocked_count") {
          for (const resolution of BLOCKED_COUNT_RESOLUTIONS)
            addCount.run(
              event.instanceId ?? "",
              event.ruleId ??
                `unregistered:${String(event.details.unregistered)}`,
              event.direction ?? "",
              resolution,
              bucketStart(event.observedAt, resolution),
              Number(event.details.packets),
            );
          continue;
        }

        const priorEvent = findEvent.get(event.id);

        if (
          priorEvent &&
          hashDocument(JSON.parse(String(priorEvent.details))) !==
            hashDocument(event)
        ) {
          throw new ServiceError(
            409,
            "event_identity_conflict",
            "Observation identity cannot contain different data",
          );
        }

        const inserted = insertEvent.run(
          event.id,
          new Date(event.observedAt).toISOString(),
          event.type,
          event.instanceId,
          event.peerIp,
          event.question,
          event.source,
          JSON.stringify(event),
        );

        if (Number(inserted.changes) === 0) continue;
        const client = ipSchema.safeParse(event.details.clientIp);
        const at = new Date(event.observedAt).toISOString();

        // A drop that arrived on a client interface from an address no instance covers asks for
        // the host's registration; lookups Suricata saw from it add their names. Upstream drops
        // stay in history only, and Suricata alone asks for nothing, since it also sees allowed
        // traffic such as upstream queries to a DNS server on an instance. Sources that are not a
        // registrable host ask for nothing either.
        if (
          event.instanceId === null &&
          event.details.unregistered === "client" &&
          client.success &&
          !UNREGISTRABLE.has(ipaddr.process(client.data).range()) &&
          !clientContext(client.data)
        ) {
          const old = this.database
            .prepare(
              "SELECT attempts,first_at,last_at,destinations,names,dismissed_at FROM host_requests WHERE client_ip=?",
            )
            .get(client.data);

          const blocked = event.type === "blocked";

          // A dismissed host keeps only how often and how recently it was dropped; its lookups and
          // destinations stay as they were when it was dismissed.
          if (old && old.dismissed_at !== null) {
            if (blocked)
              this.database
                .prepare(
                  "UPDATE host_requests SET attempts=?,last_at=MAX(last_at,?) WHERE client_ip=?",
                )
                .run(
                  (BigInt(String(old.attempts)) + 1n).toString(),
                  at,
                  client.data,
                );
          } else {
            // The Request starts at its first drop, which can arrive after later ones.
            const firstDrop = blocked && (!old || at < String(old.first_at));
            const first = firstDrop || !old ? at : String(old.first_at);

            // A new first drop takes the lookups that may have arrived before the Request: stored
            // ones from the lead before the drop on, including any seen after the drop but sent
            // first.
            const names =
              event.type === "dns" && event.question
                ? [{ value: event.question, at }]
                : firstDrop
                  ? hostLookups(
                      this.database,
                      client.data,
                      new Date(
                        Date.parse(at) - HOST_LOOKUP_LEAD_MS,
                      ).toISOString(),
                      null,
                    )
                  : [];

            const last = [
              at,
              ...names.map((name) => name.at),
              String(old?.last_at ?? at),
            ].reduce((a, b) => (a > b ? a : b));

            if (blocked || old)
              this.database
                .prepare(
                  "INSERT INTO host_requests(client_ip,attempts,first_at,last_at,destinations,names) VALUES(?,?,?,?,?,?) ON CONFLICT(client_ip) DO UPDATE SET attempts=excluded.attempts,first_at=excluded.first_at,last_at=excluded.last_at,destinations=excluded.destinations,names=excluded.names",
                )
                .run(
                  client.data,
                  (
                    BigInt(String(old?.attempts ?? "0")) + (blocked ? 1n : 0n)
                  ).toString(),
                  first,
                  last,
                  blocked && event.peerIp
                    ? latestValues(old?.destinations, [
                        { value: event.peerIp, at },
                      ])
                    : String(old?.destinations ?? "[]"),
                  latestValues(old?.names, names),
                );
          }
        }

        // Answer addresses are indexed in canonical form, matching request addresses, so the names
        // seen for an address are found without a scan. Confirmed resolver-gate answers also index
        // their client, so a client's suggestions read only its own answers.
        if (event.type === "dns" && event.instanceId) {
          const suggestionClient =
            event.source === "resolver-gate" &&
            event.details.outcome === "confirmed" &&
            client.success
              ? client.data
              : null;

          for (const address of String(event.details.addresses ?? "").split(
            ", ",
          ))
            if (address)
              addAnswer.run(
                event.id,
                event.instanceId,
                canonicalIp(address),
                new Date(event.observedAt).toISOString(),
                suggestionClient,
              );
        }

        if (
          event.type === "traffic" &&
          event.instanceId &&
          event.direction &&
          event.peerIp &&
          event.protocol !== null
        ) {
          for (const resolution of [5, 60, 3600]) {
            const bucket = bucketStart(event.observedAt, resolution);

            const key = [
              event.instanceId,
              event.direction,
              event.peerIp,
              event.protocol,
              event.port ?? -1,
              resolution,
              bucket,
            ] as const;

            const row = this.database
              .prepare(
                "SELECT sent,received,samples FROM metrics WHERE instance_id=? AND direction=? AND peer_ip=? AND protocol=? AND port=? AND resolution=? AND bucket=?",
              )
              .get(...key);

            this.database
              .prepare(
                "INSERT INTO metrics VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(instance_id,direction,peer_ip,protocol,port,resolution,bucket) DO UPDATE SET sent=excluded.sent,received=excluded.received,samples=excluded.samples",
              )
              .run(
                ...key,
                (
                  BigInt(String(row?.sent ?? "0")) + BigInt(event.sentBytes)
                ).toString(),
                (
                  BigInt(String(row?.received ?? "0")) +
                  BigInt(event.receivedBytes)
                ).toString(),
                Number(row?.samples ?? 0) + 1,
              );
          }
        }

        const context =
          event.instanceId && client.success
            ? clientContext(client.data)
            : null;

        if (
          event.type === "blocked" &&
          context &&
          event.peerIp &&
          event.direction &&
          event.protocol !== null &&
          event.ruleId
        ) {
          const catchall =
            event.details.catchall === true &&
            // oxlint-disable-next-line anti-slop/no-runtime-typeof -- eventSchema validates metadata as a primitive union; this selects its string member.
            typeof event.details.appliedRevision === "string";

          if (catchall) {
            const key = hashDocument([
              context.instanceId,
              event.direction,
              event.peerIp,
              event.protocol,
              event.port,
            ]);

            const old = this.database
              .prepare(
                "SELECT attempts,first_at,state,clients FROM requests WHERE id=?",
              )
              .get(key);

            const traffic = {
              direction: event.direction,
              peerIp: event.peerIp,
              protocol: event.protocol,
              port: event.port,
            };

            const peerIp = event.peerIp;
            const clients = recentValues(old?.clients, context.address, at);

            const state = deniedState(
              this.trafficTargeted(policyNow().policy, context, traffic, () =>
                this.requestHostnames(context.instanceId, peerIp, clients),
              ),
              old?.state,
            );

            if (state)
              this.database
                .prepare(
                  "INSERT INTO requests(id,instance_id,direction,peer_ip,protocol,port,attempts,first_at,last_at,rule_id,state,clients) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET attempts=excluded.attempts,last_at=excluded.last_at,rule_id=excluded.rule_id,state=excluded.state,clients=excluded.clients",
                )
                .run(
                  key,
                  context.instanceId,
                  event.direction,
                  event.peerIp,
                  event.protocol,
                  event.port ?? -1,
                  (BigInt(String(old?.attempts ?? "0")) + 1n).toString(),
                  old?.first_at ?? at,
                  at,
                  event.ruleId,
                  state,
                  clients,
                );
          }
        }

        if (
          event.type === "dns" &&
          context &&
          event.question &&
          event.details.outcome === "policy-denied" &&
          event.details.catchall === true &&
          // oxlint-disable-next-line anti-slop/no-runtime-typeof -- eventSchema validates denial details; this narrows the metadata union for SQL.
          typeof event.details.appliedRevision === "string" &&
          // oxlint-disable-next-line anti-slop/no-runtime-typeof -- eventSchema validates denial details; this selects the query type's string member.
          typeof event.details.queryType === "string"
        ) {
          // One Request per name: rules cannot select a query type. It shows the latest type.
          const key = hashDocument(["dns", context.instanceId, event.question]);

          const old = this.database
            .prepare(
              "SELECT attempts,first_at,state,clients FROM dns_requests WHERE id=?",
            )
            .get(key);

          const state = deniedState(
            this.dnsTargeted(policyNow().policy, context, event.question),
            old?.state,
          );

          if (state)
            this.database
              .prepare(
                "INSERT INTO dns_requests(id,instance_id,question,query_type,attempts,first_at,last_at,rule_id,state,clients) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET query_type=excluded.query_type,attempts=excluded.attempts,last_at=excluded.last_at,rule_id=excluded.rule_id,state=excluded.state,clients=excluded.clients",
              )
              .run(
                key,
                context.instanceId,
                event.question,
                event.details.queryType,
                (BigInt(String(old?.attempts ?? "0")) + 1n).toString(),
                old?.first_at ?? at,
                at,
                event.ruleId,
                state,
                recentValues(old?.clients, context.address, at),
              );
        }

        // A condition counts its occurrences, 1 unless given. A momentary one carries both
        // `occurrences` and `recovered`: it is counted, then recovered at once.
        if (event.type === "condition") {
          const code = String(event.details.code ?? "gateway_condition");

          if (
            event.details.recovered !== true ||
            event.details.occurrences !== undefined
          )
            this.condition(
              code,
              String(event.details.message ?? "Gateway reported a condition"),
              BigInt(Number(event.details.occurrences ?? 1)),
            );

          if (event.details.recovered === true) this.recoverCondition(code);
        }
      }

      this.database
        .prepare("INSERT INTO batches VALUES(?,?,?)")
        .run(batch.epoch, batch.sequence, identity);
      this.database
        .prepare("DELETE FROM batches WHERE epoch=? AND sequence!=?")
        .run(batch.epoch, batch.sequence);
      this.prune(0);
      this.database.exec("COMMIT");

      return { epoch: batch.epoch, sequence: batch.sequence };
    } catch (error) {
      if (this.database.isTransaction) this.database.exec("ROLLBACK");
      throw error;
    }
  }

  recordLocalObservation(event: GatewayEvent) {
    const identity = hashDocument(["controller-local-observations", this.path])
      .slice(0, 32)
      .split("");

    identity[12] = "4";
    identity[16] = "8";

    const value = identity.join(""),
      epoch = `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;

    const previous = this.database
      .prepare(
        "SELECT sequence FROM batches WHERE epoch=? ORDER BY length(sequence) DESC,sequence DESC LIMIT 1",
      )
      .get(epoch);

    this.ingest({
      protocolVersion: 1,
      epoch,
      sequence: (BigInt(String(previous?.sequence ?? "0")) + 1n).toString(),
      events: [event],
    });
  }

  names() {
    const policy = this.desired(),
      names: {
        instanceId: string;
        address: string;
        status: string;
        hostname: string | null;
        expiresAt: string | null;
      }[] = [];

    const seen = new Set<string>();

    for (const row of this.database
      .prepare(
        "SELECT details FROM events WHERE type='metadata' ORDER BY at DESC LIMIT 500",
      )
      .all()) {
      const event = eventSchema.parse(JSON.parse(String(row.details)));

      if (
        event.details.reverseLookup !== true ||
        event.details.resolver !== policy.settings.reverseDnsResolver ||
        !event.instanceId
      )
        continue;

      const address = String(event.details.address),
        key = `${event.instanceId}|${address}`;

      if (seen.has(key)) continue;
      seen.add(key);

      const expiresAt =
        // oxlint-disable-next-line anti-slop/no-runtime-typeof -- eventSchema validates metadata as a primitive union; this selects its string member.
        typeof event.details.expiresAt === "string"
          ? event.details.expiresAt
          : null;

      const expired = expiresAt !== null && Date.parse(expiresAt) <= Date.now();
      names.push({
        instanceId: event.instanceId,
        address,
        status: expired ? "expired" : String(event.details.status),
        hostname: expired
          ? null
          : // oxlint-disable-next-line anti-slop/no-runtime-typeof -- eventSchema validates metadata as a primitive union; this selects its string member.
            typeof event.details.hostname === "string"
            ? event.details.hostname
            : null,
        expiresAt,
      });
    }

    return names;
  }

  // A DNS request is decided once a rule other than the catch-all decides its question for the
  // client.
  private dnsTargeted(
    policy: Policy,
    context: SubjectContext,
    question: string,
  ) {
    if (policy.settings.dnsReleaseMode === "before-approval") return true;

    const decision = decideDns(policy.rules, context, question);

    return decision.allowed || !decision.catchAll;
  }
  // A connection request is decided once a rule other than the catch-all decides it. A hostname or
  // domain rule that may admit the address decides it when one of the names seen for the address
  // matches; `seen` reads them only then.
  // Names that can decide a Request: those seen for its address, and those its clients' lookups
  // resolved to it, which the Requests page suggests even once newer answers displace them. Each
  // client is read alone, as a draft for its address is, so another client's names cannot crowd
  // out its own.
  private requestHostnames(
    instanceId: string,
    peerIp: string,
    clients: SQLOutputValue | undefined,
  ) {
    const recent = readRecent(clients).map(({ value, at }) => ({
      address: value,
      at,
    }));

    return [
      ...new Set([
        ...this.reads
          .requestNames(instanceId, peerIp)
          .names.map(({ hostname }) => hostname),
        ...recent.flatMap(
          (client) =>
            this.reads.requestSuggestions(instanceId, peerIp, [client])
              .hostnames,
        ),
      ]),
    ];
  }
  private trafficTargeted(
    policy: Policy,
    context: SubjectContext,
    traffic: ObservedTraffic,
    seen: () => string[],
  ) {
    const gateway =
      this.gatewayEndpoint()?.addresses.includes(traffic.peerIp) ?? false;

    const decide = (name?: string) =>
      decideTraffic(
        policy.rules,
        context,
        { ...traffic, gateway },
        policy.settings.localNetworks,
        Date.now(),
        name,
      );

    const targets = ({ winner, dns }: TrafficDecision) =>
      winner !== null && !dns.length && !isCatchAll(winner);

    const decision = decide();

    return (
      targets(decision) ||
      (decision.dns.length > 0 &&
        seen().some((hostname) => targets(decide(hostname))))
    );
  }
  private resolveRequests(policy: Policy) {
    const tree = scopeTree(policy);

    // A Request is decided for its latest client; one no instance covers now waits for its next
    // denial.
    const latest = (clients: SQLOutputValue | undefined) => {
      const [client] = readRecent(clients);

      return client ? subjectContext(tree, client.value) : null;
    };

    for (const row of this.database
      .prepare("SELECT * FROM dns_requests WHERE state != 'resolved'")
      .all()) {
      const context = latest(row.clients);

      if (!context) continue;

      const targeted = this.dnsTargeted(policy, context, String(row.question));

      if (targeted || row.state === "applying")
        this.database
          .prepare("UPDATE dns_requests SET state=? WHERE id=?")
          .run(targeted ? "applying" : "needs-review", row.id!);
    }

    // Requests for other services of the same address and clients share their names.
    const names = new Map<string, string[]>();

    for (const row of this.database
      .prepare("SELECT * FROM requests WHERE state != ?")
      .all("resolved")) {
      const context = latest(row.clients);

      if (!context) continue;

      const traffic = {
        direction:
          row.direction === "incoming"
            ? ("incoming" as const)
            : ("outgoing" as const),
        peerIp: String(row.peer_ip),
        protocol: Number(row.protocol),
        port: row.port === -1 ? null : Number(row.port),
      };

      const seen = () => {
        const key = `${String(row.instance_id)} ${traffic.peerIp} ${String(row.clients)}`;

        if (!names.has(key))
          names.set(
            key,
            this.requestHostnames(
              String(row.instance_id),
              traffic.peerIp,
              row.clients,
            ),
          );

        return names.get(key)!;
      };

      if (this.trafficTargeted(policy, context, traffic, seen))
        this.database
          .prepare("UPDATE requests SET state=? WHERE id=?")
          .run("applying", row.id!);
      else if (row.state === "applying")
        this.database
          .prepare("UPDATE requests SET state=? WHERE id=?")
          .run("needs-review", row.id!);
    }

    // Registering a host resolves its request.
    for (const row of this.database
      .prepare("SELECT client_ip FROM host_requests")
      .all())
      if (tree.find(String(row.client_ip)))
        this.database
          .prepare("DELETE FROM host_requests WHERE client_ip=?")
          .run(row.client_ip!);
  }

  // Keeps the newest pending requests within separate pools, so lookups for many names cannot
  // displace connection requests, and one instance cannot fill the DNS pool.
  private pruneRequests() {
    this.transaction(() => {
      this.database
        .prepare("DELETE FROM requests WHERE state='resolved'")
        .run();
      this.database
        .prepare("DELETE FROM dns_requests WHERE state='resolved'")
        .run();

      const count = (sql: string, ...values: string[]) =>
        Number(this.database.prepare(sql).get(...values)!.count);

      // `instanceId` limits DNS Requests to one instance; host Requests exclude dismissed hosts.
      const removeOldest = (
        table: "requests" | "dns_requests" | "host_requests",
        excess: number,
        instanceId?: string,
      ) => {
        if (excess <= 0) return 0;
        const id = table === "host_requests" ? "client_ip" : "id";

        const where =
          table === "host_requests"
            ? " WHERE dismissed_at IS NULL"
            : instanceId === undefined
              ? ""
              : " WHERE instance_id=?";

        this.database
          .prepare(
            `DELETE FROM ${table} WHERE ${id} IN (SELECT ${id} FROM ${table}${where} ORDER BY julianday(last_at),${id} LIMIT ?)`,
          )
          .run(...(instanceId === undefined ? [] : [instanceId]), excess);

        return excess;
      };

      let discarded = removeOldest(
        "requests",
        count("SELECT COUNT(*) AS count FROM requests") -
          MAX_CONNECTION_REQUESTS,
      );

      for (const row of this.database
        .prepare(
          "SELECT instance_id,COUNT(*) AS count FROM dns_requests GROUP BY instance_id HAVING COUNT(*) > ?",
        )
        .all(MAX_INSTANCE_DNS_REQUESTS))
        discarded += removeOldest(
          "dns_requests",
          Number(row.count) - MAX_INSTANCE_DNS_REQUESTS,
          String(row.instance_id),
        );

      discarded += removeOldest(
        "dns_requests",
        count("SELECT COUNT(*) AS count FROM dns_requests") - MAX_DNS_REQUESTS,
      );
      discarded += removeOldest(
        "host_requests",
        count(
          "SELECT COUNT(*) AS count FROM host_requests WHERE dismissed_at IS NULL",
        ) - MAX_HOST_REQUESTS,
      );

      if (discarded > 0)
        this.condition(
          "requests_overflow",
          "Request queue limit reached. Older pending scopes were removed; newest scopes were retained.",
          BigInt(discarded),
        );
      else if (
        count("SELECT COUNT(*) AS count FROM requests") <
          MAX_CONNECTION_REQUESTS &&
        count("SELECT COUNT(*) AS count FROM dns_requests") <
          MAX_DNS_REQUESTS &&
        count(
          "SELECT COUNT(*) AS count FROM host_requests WHERE dismissed_at IS NULL",
        ) < MAX_HOST_REQUESTS &&
        !this.database
          .prepare(
            "SELECT 1 FROM dns_requests GROUP BY instance_id HAVING COUNT(*) >= ? LIMIT 1",
          )
          .get(MAX_INSTANCE_DNS_REQUESTS)
      )
        this.recoverCondition("requests_overflow");
    });
  }

  // Deletes the oldest rows `select` lists, PRUNE_CHUNK at a time, until at least `excess` bytes
  // are gone, no rows remain, or the slice ends. `select` returns each row's rowid as `row` and its
  // accounted `bytes`, oldest first.
  private trimOldest(
    table: "events" | "audit",
    select: string,
    excess: bigint,
    due: () => boolean,
    ...params: string[]
  ) {
    const oldest = this.database.prepare(`${select} LIMIT ${PRUNE_CHUNK}`);

    const remove = this.database.prepare(
      `DELETE FROM ${table} WHERE rowid IN (SELECT value FROM json_each(?))`,
    );

    let removed = 0n;

    while (removed < excess) {
      const rows: number[] = [];

      for (const row of oldest.all(...params)) {
        if (removed >= excess) break;
        rows.push(Number(row.row));
        removed += BigInt(String(row.bytes));
      }

      if (!rows.length) return { removed, done: true };
      remove.run(JSON.stringify(rows));

      if (removed < excess && due()) return { removed, done: false };
    }

    return { removed, done: true };
  }
  private trimGroup(group: string, excess: bigint, due: () => boolean) {
    return this.trimOldest(
      "events",
      `SELECT rowid AS row,length(CAST(details AS BLOB))+256+(SELECT COUNT(*) FROM dns_answers WHERE event_id=events.id)*${DNS_ANSWER_ROW_BYTES} AS bytes FROM events WHERE history_group=? ORDER BY at`,
      excess,
      due,
      group,
    );
  }
  // Deletes the rows matching `where`, `chunk` at a time, until none remain or the slice ends,
  // and reports whether none remain.
  private drain(
    table: "events" | "audit" | "metrics" | "blocked_counts",
    where: string,
    due: () => boolean,
    chunk: number,
    ...params: (string | number)[]
  ) {
    const remove = this.database.prepare(
      `DELETE FROM ${table} WHERE rowid IN (SELECT rowid FROM ${table} WHERE ${where} LIMIT ?)`,
    );

    while (Number(remove.run(...params, chunk).changes) === chunk)
      if (due()) return false;

    return true;
  }

  // Trims history and audit to their ages and allocations, oldest first, for at most
  // PRUNE_SLICE_MS, and reports whether it finished. Each step resumes where an earlier slice
  // stopped, so a large trim, such as after a save that shrinks an allocation, finishes over later
  // slices of the gateway link process while the browser process writes between them. Runs in one
  // write transaction, which the caller may already hold.
  prune(deadline = performance.now() + PRUNE_SLICE_MS): boolean {
    return this.transaction(() => {
      this.pruneRequests();
      const settings = this.desired().settings;
      const due = () => performance.now() >= deadline;

      const ago = (days: number) =>
        new Date(Date.now() - days * 86400000).toISOString();

      const pages = Number(
        this.database.prepare("PRAGMA page_size").get()!.page_size,
      );

      const limit =
        (historyLimitBytes(settings) + BigInt(settings.auditBytes)) * 2n +
        67108864n;

      this.database.exec(
        `PRAGMA max_page_count=${Number(limit / BigInt(pages) > 4294967294n ? 4294967294n : limit / BigInt(pages))};`,
      );
      this.database
        .prepare("DELETE FROM sessions WHERE expires_at < ?")
        .run(instant());
      this.database
        .prepare("DELETE FROM login_failures WHERE since <= ?")
        .run(new Date(Date.now() - 60000).toISOString());

      if (
        settings.historyMaxAgeDays !== null &&
        !this.drain(
          "events",
          "at < ?",
          due,
          PRUNE_CHUNK,
          ago(settings.historyMaxAgeDays),
        )
      )
        return false;

      if (
        settings.auditMaxAgeDays !== null &&
        !this.drain(
          "audit",
          "at < ?",
          due,
          PRUNE_CHUNK,
          ago(settings.auditMaxAgeDays),
        )
      )
        return false;

      if (
        !this.trimOldest(
          "audit",
          "SELECT rowid AS row,length(CAST(details AS BLOB))+256 AS bytes FROM audit ORDER BY at",
          this.usage("audit") - BigInt(settings.auditBytes),
          due,
        ).done
      )
        return false;

      for (const [table, resolution, days] of [
        ["metrics", 5, 1],
        ["metrics", 60, 30],
        ["metrics", 3600, 180],
        ["blocked_counts", 60, 1],
        ["blocked_counts", 3600, 180],
      ] as const) {
        if (
          !this.drain(
            table,
            "resolution=? AND bucket < ?",
            due,
            PRUNE_CHUNK * 8,
            resolution,
            ago(days),
          )
        )
          return false;
      }

      if (
        !this.trimGroup(
          "dns",
          this.historyUsage().dns - BigInt(settings.dnsHistoryBytes),
          due,
        ).done ||
        !this.trimGroup(
          "other",
          this.groupUsage("events:other") - BigInt(settings.otherHistoryBytes),
          due,
        ).done
      )
        return false;

      // Blocked samples leave the rule, instance, and direction with the most samples first, in
      // steps that bring it down toward the next largest. Counts leave for space only once no samples remain.
      let blocked =
        this.historyUsage().blocked - BigInt(settings.blockedHistoryBytes);

      while (blocked > 0n) {
        const [largest, next] = this.database
          .prepare(
            "SELECT name,bytes FROM storage_usage WHERE name GLOB 'events:blocked:*' ORDER BY bytes DESC LIMIT 2",
          )
          .all();

        if (!largest) break;

        const lead =
          BigInt(String(largest.bytes)) - BigInt(String(next?.bytes ?? 0));

        const { removed, done } = this.trimGroup(
          String(largest.name).slice("events:".length),
          // Steps of at least 64 KiB toward the next largest, never more than the excess.
          lead > 65536n
            ? blocked < lead
              ? blocked
              : lead
            : blocked < 65536n
              ? blocked
              : 65536n,
          due,
        );

        if (!removed) break;
        blocked -= removed;

        if (!done || (blocked > 0n && due())) return false;
      }

      // Every count row is charged the same size, so the oldest needed rows go in a few statements.
      let counts =
        blocked > 0n
          ? (blocked + BigInt(BLOCKED_COUNT_ROW_BYTES - 1)) /
            BigInt(BLOCKED_COUNT_ROW_BYTES)
          : 0n;

      const oldestCounts = this.database.prepare(
        "DELETE FROM blocked_counts WHERE rowid IN (SELECT rowid FROM blocked_counts ORDER BY bucket,resolution LIMIT ?)",
      );

      while (counts > 0n) {
        const chunk =
          counts < BigInt(PRUNE_CHUNK * 8) ? counts : BigInt(PRUNE_CHUNK * 8);

        const removed = BigInt(oldestCounts.run(Number(chunk)).changes);

        counts -= removed;

        if (removed < chunk) break;

        if (counts > 0n && due()) return false;
      }

      // Traffic events and metric rows share one allocation and leave oldest first across both.
      let traffic =
        this.groupUsage("events:traffic") +
        this.usage("metrics") -
        BigInt(settings.trafficHistoryBytes);

      const oldestEvents = this.database.prepare(
        `SELECT rowid AS row,at,length(CAST(details AS BLOB))+256 AS bytes FROM events WHERE history_group='traffic' ORDER BY at LIMIT ${PRUNE_CHUNK}`,
      );

      const oldestMetrics = this.database.prepare(
        `SELECT rowid AS row,bucket FROM metrics ORDER BY bucket,resolution LIMIT ${PRUNE_CHUNK}`,
      );

      const removeEvents = this.database.prepare(
        "DELETE FROM events WHERE rowid IN (SELECT value FROM json_each(?))",
      );

      const removeMetrics = this.database.prepare(
        "DELETE FROM metrics WHERE rowid IN (SELECT value FROM json_each(?))",
      );

      while (traffic > 0n) {
        const events = oldestEvents.all(),
          metrics = oldestMetrics.all(),
          doomedEvents: number[] = [],
          doomedMetrics: number[] = [];

        if (!events.length && !metrics.length) break;

        let event = 0,
          metric = 0;

        // A fully read chunk may have older rows behind it than the other list's next row, so the
        // walk stops there and reads again.
        while (
          traffic > 0n &&
          (event < events.length || metric < metrics.length) &&
          !(event === events.length && events.length === PRUNE_CHUNK) &&
          !(metric === metrics.length && metrics.length === PRUNE_CHUNK)
        ) {
          if (
            metric === metrics.length ||
            (event < events.length &&
              String(events[event]!.at) <= String(metrics[metric]!.bucket))
          ) {
            doomedEvents.push(Number(events[event]!.row));
            traffic -= BigInt(String(events[event]!.bytes));
            event++;
          } else {
            doomedMetrics.push(Number(metrics[metric]!.row));
            traffic -= 512n;
            metric++;
          }
        }

        removeEvents.run(JSON.stringify(doomedEvents));
        removeMetrics.run(JSON.stringify(doomedMetrics));

        if (traffic > 0n && due()) return false;
      }

      return true;
    });
  }

  rules(): RulesSnapshot {
    const policy = this.desired();

    const packets = new Map(
      this.database
        .prepare(
          "SELECT rule_id,SUM(packets) AS packets FROM blocked_counts WHERE resolution=60 AND bucket>=? GROUP BY rule_id",
        )
        .all(new Date(Date.now() - 86400000).toISOString())
        .map((row) => [String(row.rule_id), String(row.packets)]),
    );

    // One indexed lookup per rule, instance, and direction that has samples.
    const samplesSince = new Map<string, string>();

    for (const row of this.database
      .prepare(
        "SELECT substr(name,8) AS name FROM storage_usage WHERE name GLOB 'events:blocked:*'",
      )
      .all()) {
      const oldest = this.database
        .prepare("SELECT MIN(at) AS at FROM events WHERE history_group=?")
        .get(row.name!)?.at;

      const ruleId = String(row.name).split(":")[1]!;
      const current = samplesSince.get(ruleId);

      if (oldest && (!current || String(oldest) < current))
        samplesSince.set(ruleId, String(oldest));
    }

    return parseDashboard(rulesSnapshotSchema, {
      revision: policy.revision,
      instances: policy.instances,
      rules: [...policy.rules].sort(compareRules).map((rule) => ({
        ...rule,
        state: ruleState(rule),
        description: describeRule(rule, policy.instances),
        blocked:
          rule.action === "block"
            ? {
                packets: packets.get(rule.id) ?? "0",
                samplesSince: samplesSince.get(rule.id) ?? null,
              }
            : null,
      })),
      status: this.status(),
    });
  }
  history(limit = 100) {
    return this.reads.history(limit, this.desired(), this.status());
  }
  requestNames(id: string) {
    const request = this.database
      .prepare("SELECT instance_id,peer_ip FROM requests WHERE id=?")
      .get(id);

    if (!request)
      throw new ServiceError(
        404,
        "request_not_found",
        "Request no longer exists",
      );

    return this.reads.requestNames(
      String(request.instance_id),
      String(request.peer_ip),
    );
  }
  // Suggestions for the Request's clients, or for one of them, each up to its own latest attempt.
  requestSuggestions(id: string, client: string | null = null) {
    const request = this.database
      .prepare("SELECT instance_id,peer_ip,clients FROM requests WHERE id=?")
      .get(id);

    if (!request)
      throw new ServiceError(
        404,
        "request_not_found",
        "Request no longer exists",
      );

    const clients = readRecent(request.clients).map((value) => ({
      address: value.value,
      at: value.at,
    }));

    const selected =
      client === null
        ? clients
        : clients.filter((value) => value.address === client);

    if (client !== null && !selected.length)
      throw new ServiceError(
        409,
        "request_changed",
        "This client no longer appears in the Request",
      );

    return this.reads.requestSuggestions(
      String(request.instance_id),
      String(request.peer_ip),
      selected,
    );
  }
  requests(host: string | null = null, view: RequestsView = "main") {
    return this.reads.requests(
      this.desired(),
      this.status(),
      MAX_PENDING_REQUESTS,
      host,
      view,
    );
  }
  // A dismissed host Request stops asking for review until it is restored; the host's later drops
  // still count, and registering the host resolves it.
  dismissHostRequest(clientIp: string, client: AuditClient | null = null) {
    this.transaction(() => {
      const held = this.database
        .prepare(
          "SELECT COUNT(*) AS count FROM host_requests WHERE dismissed_at IS NOT NULL",
        )
        .get()!;

      if (Number(held.count) >= MAX_DISMISSED_HOSTS)
        throw new ServiceError(
          409,
          "dismissed_hosts_full",
          `Dismissed host limit (${MAX_DISMISSED_HOSTS.toLocaleString("en-US")}) reached. Restore or register dismissed hosts, or register the network they come from.`,
        );

      const dismissed = this.database
        .prepare(
          "UPDATE host_requests SET dismissed_at=? WHERE client_ip=? AND dismissed_at IS NULL",
        )
        .run(instant(), clientIp);

      if (Number(dismissed.changes) === 0)
        throw new ServiceError(
          404,
          "request_not_found",
          "No host Request waits for review at this address",
        );
      this.audit(
        "Admin",
        "host-request-dismissed",
        clientIp,
        client ? { client } : {},
      );
    });
  }
  // A restored host Request asks for review again.
  restoreHostRequest(clientIp: string, client: AuditClient | null = null) {
    this.transaction(() => {
      const restored = this.database
        .prepare(
          "UPDATE host_requests SET dismissed_at=NULL WHERE client_ip=? AND dismissed_at IS NOT NULL",
        )
        .run(clientIp);

      if (Number(restored.changes) === 0)
        throw new ServiceError(
          404,
          "request_not_found",
          "No dismissed host Request at this address",
        );
      this.audit(
        "Admin",
        "host-request-restored",
        clientIp,
        client ? { client } : {},
      );
    });
  }
  monitor(
    from: string,
    to: string,
    selection: MonitorSelection = {},
    events?: EventScan,
    signal?: AbortSignal,
  ) {
    return this.reads.monitor(
      from,
      to,
      selection,
      this.desired(),
      this.status(),
      Date.now(),
      events,
      signal,
    );
  }
  resources() {
    const storage = this.database.prepare("PRAGMA page_count").get()!;
    const size = this.database.prepare("PRAGMA page_size").get()!;
    const history = this.historyUsage();

    return {
      settings: this.desired().settings,
      catchAll: catchAllActions(this.desired().rules),
      revision: this.desired().revision,
      names: this.names(),
      databaseBytes: (
        BigInt(String(storage.page_count)) * BigInt(String(size.page_size))
      ).toString(),
      historyUsedBytes: {
        traffic: history.traffic.toString(),
        dns: history.dns.toString(),
        blocked: history.blocked.toString(),
        other: history.other.toString(),
      },
      auditUsedBytes: this.usage("audit").toString(),
      requestsUsedBytes: (
        this.usage("requests") +
        this.usage("dns_requests") +
        this.usage("host_requests")
      ).toString(),
      requestsLimitBytes: (
        BigInt(MAX_PENDING_REQUESTS + MAX_DISMISSED_HOSTS) * REQUEST_ROW_BYTES
      ).toString(),
      status: this.status(),
      storage: this.physicalBudget().status(),
      gatewayStorage: (() => {
        const row = this.database
          .prepare("SELECT at,details FROM gateway_resources WHERE id=1")
          .get();

        return row
          ? {
              ...storageSnapshotSchema.parse(JSON.parse(String(row.details))),
              at: String(row.at),
            }
          : null;
      })(),
    };
  }
  removeInstance(
    expectedRevision: string,
    id: string,
    client: AuditClient | null = null,
  ) {
    const next = this.mutation(
      expectedRevision,
      "instance-removed",
      id,
      (policy) => {
        if (!policy.instances.some((instance) => instance.id === id))
          throw new ServiceError(
            404,
            "instance_not_found",
            "Instance no longer exists",
          );
        policy.instances = policy.instances.filter(
          (instance) => instance.id !== id,
        );
        // Address rules inside the instance stay; validation refuses the removal while one
        // would be outside every instance.
        policy.rules = policy.rules.filter(
          (rule) =>
            rule.subject.kind !== "instance" || rule.subject.instanceId !== id,
        );
        this.database
          .prepare("DELETE FROM requests WHERE instance_id=?")
          .run(id);
        this.database
          .prepare("DELETE FROM dns_requests WHERE instance_id=?")
          .run(id);

        return policy;
      },
      client,
    );

    return next;
  }
}
