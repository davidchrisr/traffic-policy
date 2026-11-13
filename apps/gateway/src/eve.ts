import { hasErrorCode } from "@traffic-policy/core/io";
import { createHash, randomUUID } from "node:crypto";
import {
  open,
  readFile,
  stat,
  readdir,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { join, dirname, basename } from "node:path";
import { z } from "zod";
import {
  canonicalName,
  eventSchema,
  ipSchema,
  instantSchema,
  uint64Schema,
} from "@traffic-policy/contracts";
import type { GatewayEvent, Policy } from "@traffic-policy/contracts";
import type { DnsRuleIndex } from "@traffic-policy/core";
import { atomicJson } from "@traffic-policy/core/io";
import { CollectionCommit } from "./collection.ts";
import { UnregisteredNameSampler } from "./telemetry.ts";
import type { StorageBudget } from "@traffic-policy/core/storage";

const inputSchema = z
  .object({
    timestamp: z.string(),
    event_type: z.string(),
    src_ip: ipSchema.optional(),
    dest_ip: ipSchema.optional(),
    src_port: z.number().int().min(0).max(65535).optional(),
    dest_port: z.number().int().min(0).max(65535).optional(),
    proto: z.string().optional(),
    flow_id: uint64Schema.optional(),
    http: z
      .object({ hostname: z.string().optional() })
      .passthrough()
      .optional(),
    tls: z.object({ sni: z.string().optional() }).passthrough().optional(),
    dns: z
      .object({
        type: z.string().optional(),
        rrname: z.string().optional(),
        queries: z
          .array(z.object({ rrname: z.string() }).passthrough())
          .optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough();

// A confirmed policy and its index, shared without copying. Readers must not mutate either.
export interface PolicyView {
  policy: Policy;
  index: DnsRuleIndex;
}

// `gatewayAddresses` are the gateway's own; their events are no client's.
export function eveObservation(
  line: string,
  gatewayId: string,
  index: DnsRuleIndex,
  gatewayAddresses: ReadonlySet<string> = new Set(),
): GatewayEvent | null {
  const input = inputSchema.parse(
    JSON.parse(
      line,
      // oxlint-disable-next-line anti-slop/no-unknown-parameters -- The JSON reviver receives raw tokens before inputSchema validates the Suricata event.
      (key: string, value: unknown, context?: { source?: string }) => {
        // oxlint-disable-next-line anti-slop/no-runtime-typeof -- The JSON token kind determines whether the lossless numeric source must be preserved.
        if (key === "flow_id" && typeof value === "number") {
          if (!context?.source || !/^(0|[1-9][0-9]*)$/.test(context.source))
            throw new z.ZodError([
              {
                code: "custom",
                path: ["flow_id"],
                message: "Suricata flow identity is not lossless",
              },
            ]);

          return context.source;
        }

        return value;
      },
    ),
  );

  if (
    !["dns", "http", "tls", "alert"].includes(input.event_type) ||
    !input.src_ip ||
    !input.dest_ip
  )
    return null;
  const response = input.event_type === "dns" && input.dns?.type === "answer";

  const clientIp = input.src_ip,
    peerIp = input.dest_ip;

  // The gateway's own events are no client's, even where a subnet instance contains its address.
  const instanceId = gatewayAddresses.has(clientIp)
    ? null
    : (index.context(clientIp)?.instanceId ?? null);

  // An unregistered client's packets are dropped, so only its lookups say what it wanted.
  if (
    !instanceId &&
    (input.event_type !== "dns" || response || gatewayAddresses.has(clientIp))
  )
    return null;

  const timestamp = instantSchema.parse(
    input.timestamp.replace(/([+-][0-9]{2})([0-9]{2})$/, "$1:$2"),
  );

  const name =
    input.http?.hostname ??
    input.tls?.sni ??
    input.dns?.rrname ??
    input.dns?.queries?.[0]?.rrname;

  let hostname: string | null = null;

  if (name) {
    try {
      hostname = canonicalName(name);
    } catch {
      hostname = null;
    }
  }

  if (!instanceId && !hostname) return null;

  const identity = createHash("sha256")
    .update(`${gatewayId}|${line}`)
    .digest("hex")
    .slice(0, 32)
    .split("");

  identity[12] = "4";
  identity[16] = "8";
  const id = identity.join("");

  const details: GatewayEvent["details"] = {
    eventType: input.event_type,
    hostname,
    clientIp,
    flowId: input.flow_id ?? null,
    dnsResponse: response,
    authoritative: false,
  };

  // Suricata captures a client interface, so an unregistered client is a registration candidate.
  if (!instanceId) details.unregistered = "client";

  return eventSchema.parse({
    id: `${id.slice(0, 8)}-${id.slice(8, 12)}-${id.slice(12, 16)}-${id.slice(16, 20)}-${id.slice(20)}`,
    observedAt: timestamp,
    type: input.event_type === "dns" ? "dns" : "metadata",
    source: "suricata",
    instanceId,
    direction: "outgoing",
    peerIp,
    protocol: input.proto === "TCP" ? 6 : input.proto === "UDP" ? 17 : null,
    port: input.dest_port ?? null,
    sentBytes: "0",
    receivedBytes: "0",
    ruleId: null,
    question: input.event_type === "dns" ? hostname : null,
    details,
  });
}

const normalizationFailureSchema = z
  .object({
    at: instantSchema,
    code: z.string().max(64),
    path: z.array(z.string().max(128)).max(16),
    message: z.string().max(256),
    sourceInode: z.string().max(128),
    sourceOffset: uint64Schema,
    digest: z.string().regex(/^[a-f0-9]{64}$/),
    recordsInRead: z.number().int().positive().max(262144),
  })
  .strict();

const normalizationCoverage =
  "Earlier Suricata records could not be processed; historical coverage is incomplete";

const missingSourceCoverage =
  "The saved Suricata source is missing; collection resumed where the newest source ended when the miss began, and unread records in retained sources are missing";

// A Suricata source's identity. Rotation archives a source by renaming it, which keeps it on the
// same filesystem, so the inode alone identifies one; a filesystem's device number can change
// when it is mounted again, as ZFS datasets do.
const inodeOf = (stats: { ino: bigint }) => String(stats.ino);

// A file's first `length` bytes, or null when the file is shorter.
async function readStart(file: FileHandle, length: number) {
  const buffer = Buffer.alloc(length);

  for (let filled = 0; filled < length;) {
    const { bytesRead } = await file.read(
      buffer,
      filled,
      length - filled,
      filled,
    );

    if (!bytesRead) return null;
    filled += bytesRead;
  }

  return buffer;
}

const sha256 = (bytes: Buffer) =>
  createHash("sha256").update(bytes).digest("hex");

// A source's head: the SHA-256 of its first bytes, up to 1 KiB, and their count. A file's first
// bytes never change, so the head identifies the source by content: a copy still matches after a
// restore or migration changes its inode, and another file given a reused inode does not. Every
// record starts alike, so a head counts only once it holds the first complete record, whose
// timestamp and flow ID are its own, or 1 KiB of it; until then it has none.
async function headOf(file: FileHandle) {
  const size = (await file.stat({ bigint: true })).size;
  const bytes = await readStart(file, Number(size < 1024n ? size : 1024n));

  if (bytes === null) throw new Error("Suricata source changed while reading");

  return bytes.length === 1024 || bytes.includes(10)
    ? { head: sha256(bytes), headBytes: bytes.length }
    : { head: sha256(Buffer.alloc(0)), headBytes: 0 };
}

// `condition` is a coverage loss not yet recorded. The next job records it as a condition event
// followed by its recovery, since later records are processed again. `head` and `headBytes` are
// the source's `headOf`, which grows with the source up to 1 KiB.
const cursorSchema = z
  .object({
    inode: z.string(),
    offset: uint64Schema,
    head: z.string().regex(/^[a-f0-9]{64}$/),
    headBytes: z.number().int().min(0).max(1024),
    condition: z.string().nullable(),
    lastNormalizationFailure: normalizationFailureSchema.nullable(),
  })
  .strict();

const jobSchema = z
  .object({
    key: z.string().max(256),
    before: cursorSchema,
    next: cursorSchema,
    events: z.array(eventSchema).max(4096),
    chunkRecords: z.union([z.literal(256), z.literal(1024)]),
    offset: z.number().int().nonnegative(),
  })
  .strict()
  .refine(
    (job) =>
      job.offset <= job.events.length &&
      (job.offset % job.chunkRecords === 0 || job.offset === job.events.length),
    "Suricata job progress is invalid",
  )
  .refine((job) => {
    const bytes = BigInt(job.next.offset) - BigInt(job.before.offset);

    const key = `eve:${job.before.inode}:${job.before.offset}:${bytes}`;

    // A job without source bytes only records the cursor's coverage notice. Its key adds the
    // notice's own ID, since a later notice can start at the same source offset.
    return (
      job.next.inode === job.before.inode &&
      (bytes > 0n ||
        (job.before.condition !== null && job.next.condition === null)) &&
      bytes <= 262144n &&
      (bytes > 0n
        ? job.key === key
        : job.key.startsWith(`${key}:`) &&
          z
            .string()
            .uuid()
            .safeParse(job.key.slice(key.length + 1)).success)
    );
  }, "Suricata job source identity is invalid");

type EveJob = z.infer<typeof jobSchema>;

function coverageEvents(notice: string): GatewayEvent[] {
  const event = (message: string, recovered: boolean) =>
    eventSchema.parse({
      id: randomUUID(),
      observedAt: new Date().toISOString(),
      type: "condition",
      source: "suricata",
      instanceId: null,
      direction: null,
      peerIp: null,
      protocol: null,
      port: null,
      sentBytes: "0",
      receivedBytes: "0",
      ruleId: null,
      question: null,
      details: { code: "suricata_coverage", message, recovered },
    });

  return [
    event(notice, false),
    event("Suricata records are processed again", true),
  ];
}

export class EveReader {
  private file: FileHandle | null = null;
  private cursor: z.infer<typeof cursorSchema> | null = null;
  private pending: Promise<void> | null = null;
  private stopped = false;
  private shutdown = new AbortController();
  private timer: NodeJS.Timeout | null = null;
  private job: EveJob | null = null;
  private jobDurable = false;
  private collection: CollectionCommit;
  // When the saved source was first found missing, on the monotonic clock, and where the newest
  // source's last record ended then.
  private missingSince: number | null = null;
  private missingResume: { inode: string; offset: string } | null = null;
  // The current read failure, cleared by the next successful read.
  condition: string | null = null;
  constructor(
    private path: string,
    private stateDirectory: string,
    private gatewayId: string,
    private policy: () => PolicyView | null,
    private record: (
      events: GatewayEvent[],
      key: string,
      signal: AbortSignal,
    ) => Promise<void>,
    private gatewayAddresses: ReadonlySet<string>,
    private persist: typeof atomicJson = atomicJson,
    private budget?: StorageBudget,
    private unregistered = new UnregisteredNameSampler(),
  ) {
    this.collection = new CollectionCommit(async (events, offset) => {
      const job = this.job!;
      await this.record(events, `${job.key}:${offset}`, this.shutdown.signal);

      const next = {
        ...job,
        offset: offset + events.length,
      };

      // The source cursor fences the final chunk. Until it commits, the keyed
      // buffer receipt makes replay of that chunk idempotent after restart.
      if (next.offset < job.events.length)
        await this.persist(this.jobPath, next);
      this.job = next;
    });
  }
  private get jobPath() {
    return join(this.stateDirectory, "eve-job.json");
  }
  async start() {
    try {
      this.cursor = cursorSchema.parse(
        JSON.parse(
          await readFile(join(this.stateDirectory, "eve-cursor.json"), "utf8"),
        ),
      );
    } catch (error) {
      if (!hasErrorCode(error, "ENOENT")) throw error;
    }

    try {
      this.job = jobSchema.parse(
        JSON.parse(await readFile(this.jobPath, "utf8")),
      );

      const same = (
        left: z.infer<typeof cursorSchema>,
        right: z.infer<typeof cursorSchema>,
      ) =>
        left.inode === right.inode &&
        left.offset === right.offset &&
        left.condition === right.condition;

      if (
        this.cursor &&
        !same(this.cursor, this.job.before) &&
        !same(this.cursor, this.job.next)
      )
        throw new Error("Suricata job conflicts with its saved source cursor");

      if (this.cursor && same(this.cursor, this.job.next))
        this.job.offset = this.job.events.length;
      this.cursor ??= this.job.before;
      this.jobDurable = true;
    } catch (error) {
      if (!hasErrorCode(error, "ENOENT")) throw error;
    }

    this.scheduleRead(1000);
  }
  private scheduleRead(waitMs: number) {
    if (this.stopped) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      const before = this.cursor;
      void this.read()
        .then(() => {
          this.condition = null;
          // Yield between durable jobs, but do not idle while the source advances.
          this.scheduleRead(this.cursor !== before ? 0 : 1000);
        })
        .catch((error: Error) => {
          if (this.stopped) return;
          this.condition = error.message;
          this.scheduleRead(1000);
        });
    }, waitMs);
    this.timer.unref();
  }
  read(): Promise<void> {
    if (this.stopped) return Promise.resolve();

    if (this.pending) return this.pending;
    const view = this.job ? null : this.policy();

    if (!this.job && !view) return Promise.resolve();
    const task = this.collect(view);
    this.pending = task;
    void task
      .finally(() => {
        if (this.pending === task) this.pending = null;
      })
      .catch(() => {});

    return task;
  }
  private async sources() {
    const prefix = basename(this.path) + ".";

    const names = (await readdir(dirname(this.path)))
      .filter(
        (name) =>
          name.startsWith(prefix) &&
          /^\d{13}-[a-f0-9-]+\.(closed|rotating)$/.test(
            name.slice(prefix.length),
          ),
      )
      .sort();

    const sources = [];

    for (const path of [
      ...names.map((name) => join(dirname(this.path), name)),
      this.path,
    ]) {
      try {
        const current = await stat(path, { bigint: true });

        if (!current.isFile())
          throw new Error("Suricata source is not a regular file");
        sources.push({
          path,
          inode: inodeOf(current),
          closed: path.endsWith(".closed"),
        });
      } catch (error) {
        if (!hasErrorCode(error, "ENOENT")) throw error;
      }
    }

    return sources;
  }
  // Where a source's last record ends; Suricata may be writing the next one.
  private async lastRecordEnd(source: { path: string; inode: string }) {
    const file = await open(source.path, "r");

    try {
      const actual = await file.stat({ bigint: true });

      if (inodeOf(actual) !== source.inode)
        throw new Error("Suricata source changed while opening");
      const buffer = Buffer.alloc(65536);

      let end = actual.size,
        offset = 0n;

      while (end > 0n) {
        const start = end > 65536n ? end - 65536n : 0n;

        const length = Number(end - start);

        // A read can return fewer bytes than asked, so the window is filled before it is searched.
        for (let filled = 0; filled < length;) {
          const { bytesRead } = await file.read(
            buffer,
            filled,
            length - filled,
            Number(start) + filled,
          );

          if (!bytesRead)
            throw new Error("Suricata source changed while reading");
          filled += bytesRead;
        }

        const index = buffer.subarray(0, length).lastIndexOf(10);

        if (index >= 0) {
          offset = start + BigInt(index) + 1n;
          break;
        }

        end = start;
      }

      return { inode: source.inode, offset: String(offset) };
    } finally {
      await file.close();
    }
  }
  // Opens a listed source, checking that it is still the one listed.
  private async openSource(source: { path: string; inode: string }) {
    const file = await open(source.path, "r");

    if (inodeOf(await file.stat({ bigint: true })) !== source.inode) {
      await file.close();
      throw new Error("Suricata source changed while opening");
    }

    return file;
  }
  private async headOfSource(source: { path: string; inode: string }) {
    const file = await this.openSource(source);

    return headOf(file).finally(() => file.close());
  }
  // Whether a file holds the cursor's source: the same first bytes, and at least its offset. Until
  // the source holds a complete record, the cursor has no head and relies on the inode alone.
  private async continues(file: FileHandle) {
    const cursor = this.cursor!;

    if (BigInt(cursor.offset) > (await file.stat({ bigint: true })).size)
      return false;

    if (!cursor.headBytes) return true;
    const bytes = await readStart(file, cursor.headBytes);

    return bytes !== null && sha256(bytes) === cursor.head;
  }
  // Opens the cursor's source: the source with its inode when its content matches, or else the
  // only source whose first bytes match, as after a restore or migration copies the files and
  // changes their inodes. Returns whether one was found.
  private async reopen(sources: { path: string; inode: string }[]) {
    const cursor = this.cursor!,
      byInode = sources.find((value) => value.inode === cursor.inode);

    if (byInode) {
      const file = await this.openSource(byInode);

      let found = false;

      try {
        found = await this.continues(file);
      } finally {
        if (!found) await file.close();
      }

      if (found) {
        this.file = file;

        return true;
      }
    }

    // A cursor without a head has no content to match.
    if (!cursor.headBytes) return false;
    const matches: { inode: string; file: FileHandle }[] = [];

    try {
      for (const source of sources) {
        if (source === byInode) continue;
        const file = await this.openSource(source);

        let found = false;

        try {
          found = await this.continues(file);
        } finally {
          if (found) matches.push({ inode: source.inode, file });
          else await file.close();
        }
      }

      if (matches.length !== 1) return false;
      await this.checkpoint({ ...cursor, inode: matches[0]!.inode });
      this.file = matches.pop()!.file;

      return true;
    } finally {
      for (const match of matches) await match.file.close();
    }
  }
  // The head to save with a cursor in the open source.
  private async nextHead() {
    const { head, headBytes } = this.cursor!;

    return headBytes === 1024 ? { head, headBytes } : headOf(this.file!);
  }
  private async checkpoint(next: z.infer<typeof cursorSchema>) {
    const committed = { ...next };

    await this.persist(join(this.stateDirectory, "eve-cursor.json"), committed);
    this.cursor = committed;
  }
  private async resumeJob() {
    const job = this.job!;

    if (!this.jobDurable) {
      await this.persist(this.jobPath, job);
      this.jobDurable = true;
    }

    if (await this.collection.retry()) return;
    await this.collection.write(
      job.events,
      async () => {
        await this.checkpoint(job.next);

        try {
          await unlink(this.jobPath);
        } catch (error) {
          if (!hasErrorCode(error, "ENOENT")) throw error;
        }

        const directory = await open(this.stateDirectory, "r");

        try {
          await directory.sync();
        } finally {
          await directory.close();
        }

        this.job = null;
        this.jobDurable = false;
      },
      job.offset,
      job.chunkRecords,
    );
  }
  private async collect(view: PolicyView | null) {
    if (this.job) {
      await this.resumeJob();

      return;
    }

    if (!view) return;

    const sources = await this.sources();

    // An open source is missing only once it is deleted; its cursor then looks for a copy.
    if (
      this.file &&
      !sources.some((value) => value.inode === this.cursor!.inode) &&
      (await this.file.stat({ bigint: true })).nlink === 0n
    ) {
      await this.file.close();
      this.file = null;
    }

    // A source that stays missing with no copy resumes collection after the newest source's last
    // record with a coverage condition. Reading retained records again would normalize them under
    // the current policy, which can change the data behind an event ID. Rotation renames a source
    // twice, and either rename can drop it from one listing, so the miss must last a minute.
    if (!this.file && this.cursor && !(await this.reopen(sources))) {
      // Collection resumes where the newest source ended when the miss began, which keeps the
      // records Suricata writes during the wait.
      if (this.missingSince === null) {
        this.missingResume = sources.length
          ? await this.lastRecordEnd(sources.at(-1)!)
          : null;
        this.missingSince = performance.now();
      }

      if (!sources.length || performance.now() - this.missingSince < 60000)
        throw new Error("Suricata source is missing");
      const remembered = this.missingResume;

      // Rotation may have archived that source since, which keeps its place; once it is gone,
      // collection resumes after the newest source's last record.
      const resume =
        remembered && sources.some((value) => value.inode === remembered.inode)
          ? remembered
          : await this.lastRecordEnd(sources.at(-1)!);

      await this.checkpoint({
        ...resume,
        ...(await this.headOfSource(
          sources.find((value) => value.inode === resume.inode)!,
        )),
        condition: this.cursor.condition
          ? `${this.cursor.condition}; ${missingSourceCoverage}`
          : missingSourceCoverage,
        lastNormalizationFailure: this.cursor.lastNormalizationFailure,
      });
      this.missingSince = null;
      this.missingResume = null;

      if (!(await this.reopen(sources)))
        throw new Error("Suricata source is missing");
    } else {
      this.missingSince = null;
      this.missingResume = null;
    }

    if (!this.file) {
      const source = sources[0];

      if (!source) throw new Error("Suricata source is missing");
      this.file = await this.openSource(source);
      this.cursor ??= {
        inode: source.inode,
        offset: "0",
        ...(await headOf(this.file)),
        condition: null,
        lastNormalizationFailure: null,
      };
    }

    if (this.cursor!.condition) {
      const cursor = this.cursor!;

      this.job = jobSchema.parse({
        key: `eve:${cursor.inode}:${cursor.offset}:0:${randomUUID()}`,
        before: cursor,
        next: { ...cursor, condition: null },
        events: coverageEvents(cursor.condition!),
        chunkRecords: 256,
        offset: 0,
      });
      await this.resumeJob();

      return;
    }

    let sourceIndex = sources.findIndex(
      (source) => source.inode === this.cursor!.inode,
    );

    if (sourceIndex < 0) throw new Error("Suricata source is missing");

    // Earlier closed files have been durably spooled. Keep the current source
    // until its descriptor and cursor have moved to the next file.
    for (const source of sources.slice(0, sourceIndex))
      if (source.closed) await unlink(source.path);

    if (
      this.budget &&
      BigInt(this.budget.status().allocatedBytes) >
        this.budget.limit - this.budget.reserve - 67108864n
    ) {
      const source = sources[sourceIndex]!,
        next = sources[sourceIndex + 1];

      if (source.closed && next) {
        const size = (await this.file.stat({ bigint: true })).size;
        const unread = size - BigInt(this.cursor!.offset);

        const condition =
          unread > 0n
            ? `Suricata observations were discarded at the storage limit; ${unread} unread source bytes are missing`
            : null;

        await this.checkpoint({
          inode: next.inode,
          offset: "0",
          ...(await this.headOfSource(next)),
          condition,
          lastNormalizationFailure: this.cursor!.lastNormalizationFailure,
        });
        await this.file.close();
        this.file = null;
        await unlink(source.path);
        const directory = await open(dirname(this.path), "r");

        try {
          await directory.sync();
        } finally {
          await directory.close();
        }

        return;
      }
    }

    const cursor = this.cursor!;
    const saved = await this.file.stat({ bigint: true });

    if (BigInt(cursor.offset) > saved.size)
      throw new Error(
        "Suricata source was truncated before collection completed",
      );

    if (BigInt(cursor.offset) > BigInt(Number.MAX_SAFE_INTEGER))
      throw new Error("Suricata file offset exceeds the reader limit");
    const buffer = Buffer.alloc(256 * 1024);

    const { bytesRead } = await this.file.read(
      buffer,
      0,
      buffer.length,
      Number(cursor.offset),
    );

    sourceIndex = sources.findIndex((source) => source.inode === cursor.inode);
    const closed = sourceIndex >= 0 && sources[sourceIndex]!.closed;

    if (!bytesRead && closed) {
      const next = sources[sourceIndex + 1];

      if (!next) return;
      const file = await this.openSource(next);

      try {
        await this.checkpoint({
          inode: next.inode,
          offset: "0",
          ...(await headOf(file)),
          condition: null,
          lastNormalizationFailure: cursor.lastNormalizationFailure,
        });
      } catch (error) {
        await file.close();
        throw error;
      }

      await this.file.close();
      this.file = file;

      return;
    }

    const bytes = buffer.subarray(0, bytesRead),
      end = bytes.lastIndexOf(10);

    if (end < 0) {
      // One record beyond the framing limit must not stall collection; skip
      // it once complete and report the gap like other unreadable records.
      const recordEnd =
        bytesRead === buffer.length
          ? await this.newlineAfter(BigInt(cursor.offset) + BigInt(bytesRead))
          : null;

      if (recordEnd !== null) {
        const failure = {
          at: new Date().toISOString(),
          code: "record_too_large",
          path: [],
          message: "Suricata record exceeds the 256 KiB framing limit",
          sourceInode: cursor.inode,
          sourceOffset: cursor.offset,
          digest: createHash("sha256").update(bytes).digest("hex"),
          recordsInRead: 1,
        };

        await this.checkpoint({
          ...cursor,
          offset: (recordEnd + 1n).toString(),
          ...(await this.nextHead()),
          condition: normalizationCoverage,
          lastNormalizationFailure: failure,
        });

        return;
      }

      if (bytesRead && closed) {
        await this.checkpoint({
          ...cursor,
          offset: saved.size.toString(),
          ...(await this.nextHead()),
          condition:
            "Closed Suricata source ended with an incomplete record; coverage is partial",
        });
      }

      return;
    }

    const events: GatewayEvent[] = [];
    const lines = bytes.subarray(0, end).toString("utf8").split("\n");
    let failure: z.infer<typeof normalizationFailureSchema> | null = null;
    let failedRecords = 0;

    for (let index = 0; index < lines.length; index++) {
      const line = lines[index]!;

      if (!line) continue;

      try {
        const event = eveObservation(
          line,
          this.gatewayId,
          view.index,
          this.gatewayAddresses,
        );

        if (
          event &&
          (event.instanceId ||
            this.unregistered.admit(
              String(event.details.clientIp),
              event.question!,
            ))
        )
          events.push(event);
      } catch (error) {
        if (!(error instanceof SyntaxError) && !(error instanceof z.ZodError))
          throw error;
        failedRecords++;

        if (!failure) {
          let localOffset = 0;

          for (let prior = 0; prior < index; prior++)
            localOffset = bytes.indexOf(10, localOffset) + 1;

          const issue =
            error instanceof z.ZodError ? error.issues[0] : undefined;

          failure = {
            at: new Date().toISOString(),
            code:
              issue?.code ??
              (error instanceof SyntaxError
                ? "invalid_json"
                : "normalization_error"),
            path:
              issue?.path
                .slice(0, 16)
                .map((part) => String(part).slice(0, 128)) ?? [],
            message: (
              issue?.message ??
              (error instanceof Error
                ? error.message
                : "Suricata normalization failed")
            ).slice(0, 256),
            sourceInode: cursor.inode,
            sourceOffset: (
              BigInt(cursor.offset) + BigInt(localOffset)
            ).toString(),
            digest: createHash("sha256")
              .update(
                bytes.subarray(localOffset, bytes.indexOf(10, localOffset)),
              )
              .digest("hex"),
            recordsInRead: 1,
          };
        }
      }
    }

    if (failure) failure.recordsInRead = failedRecords;

    const eventBytes = Buffer.byteLength(JSON.stringify(events));
    this.budget?.assertRoom(BigInt(eventBytes) * 2n + 16384n);

    const chunkRecords =
      eventBytes + 256 <= 1048576 &&
      BigInt(eventBytes + 256) <= BigInt(view.policy.settings.collectorBytes)
        ? 1024
        : 256;

    this.job = jobSchema.parse({
      key: `eve:${cursor.inode}:${cursor.offset}:${end + 1}`,
      before: cursor,
      next: {
        ...cursor,
        offset: (BigInt(cursor.offset) + BigInt(end + 1)).toString(),
        ...(await this.nextHead()),
        condition: failure ? normalizationCoverage : null,
        lastNormalizationFailure: failure ?? cursor.lastNormalizationFailure,
      },
      events,
      chunkRecords,
      offset: 0,
    });
    await this.resumeJob();
  }
  // Absolute offset of the next newline at or after `from`, or null at EOF.
  private async newlineAfter(from: bigint): Promise<bigint | null> {
    const chunk = Buffer.alloc(256 * 1024);

    for (let position = from; ;) {
      const { bytesRead } = await this.file!.read(
        chunk,
        0,
        chunk.length,
        Number(position),
      );

      if (!bytesRead) return null;
      const newline = chunk.subarray(0, bytesRead).indexOf(10);

      if (newline >= 0) return position + BigInt(newline);
      position += BigInt(bytesRead);
    }
  }
  async close() {
    this.stopped = true;
    this.shutdown.abort();

    if (this.timer) clearTimeout(this.timer);
    await this.pending?.catch((error: Error) => {
      if (error === this.shutdown.signal.reason) return;
      this.condition = error.message;
    });
    await this.file?.close();
    this.file = null;
  }
}
