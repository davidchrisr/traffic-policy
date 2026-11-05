import { hasErrorCode } from "@traffic-policy/core/io";
import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  mkdir,
  readdir,
  readFile,
  unlink,
  stat,
  open,
} from "node:fs/promises";
import { basename, join } from "node:path";
import { z } from "zod";
import { setTimeout as delay } from "node:timers/promises";
import {
  eventBatchSchema,
  uint64Schema,
  instantSchema,
  eventSchema,
  MAX_OBSERVATION_BATCH_RECORDS,
} from "@traffic-policy/contracts";
import type { EventBatch, GatewayEvent } from "@traffic-policy/contracts";
import {
  atomicJson,
  requestJson,
  hashDocument,
  stableJson,
  ServiceError,
} from "@traffic-policy/core/io";
import type { GatewayConfig } from "./config.ts";
import type { StorageBudget } from "@traffic-policy/core/storage";

const stateSchema = z
  .object({
    epoch: z.string().uuid(),
    sequence: uint64Schema,
    lost: uint64Schema,
    firstLossAt: instantSchema.nullable(),
    lastLossAt: instantSchema.nullable(),
    pending: z
      .union([
        uint64Schema,
        z
          .object({
            batch: eventBatchSchema,
            key: z.string().max(256).nullable(),
          })
          .strict(),
      ])
      .nullable(),
    sourceCommit: z
      .object({ key: z.string().max(256), hash: z.string() })
      .strict()
      .nullable(),
    lastCommitHash: z.string().nullable(),
    coverageCondition: z.string().nullable(),
    rejectedRecords: uint64Schema,
    firstRejectedAt: instantSchema.nullable(),
    lastRejectedAt: instantSchema.nullable(),
    sessionOpen: z.boolean(),
    evicting: z
      .object({
        sequence: uint64Schema,
        lost: uint64Schema,
        firstLossAt: instantSchema,
        lastLossAt: instantSchema,
      })
      .strict()
      .nullable(),
    dnsCommit: z
      .array(z.object({ id: z.string().uuid(), hash: z.string() }).strict())
      .max(MAX_OBSERVATION_BATCH_RECORDS),
  })
  .strict();

type BufferState = z.infer<typeof stateSchema>;

type Segment = { path: string; bytes: number };

type DnsGroup = {
  events: GatewayEvent[];
  bytes: number;
  openedAt: number;
  reserved: boolean;
  callers: { accept: () => void; reject: (error: Error) => void }[];
  hashes: Map<string, string>;
  batchHash: string;
};

const DNS_PENDING_RECORDS = 16384;

const DNS_PENDING_BYTES = 64 * 1024 * 1024;

const DNS_BATCH_BYTES = 1024 * 1024;

const DNS_BATCH_WAIT_MS = 50;

// Delivery reads back segments this buffer wrote from events it validated when they were appended,
// and the controller validates every event again at ingest. Delivery checks only batch identity.
const deliveryBatchSchema = eventBatchSchema.extend({
  events: z.array(z.custom<GatewayEvent>()),
});

type SendBatch = (
  batch: EventBatch,
) => Promise<{ epoch: string; sequence: string }>;

export class EventBuffer {
  private state!: BufferState;
  private tail: Promise<unknown> = Promise.resolve();
  private queued = 0;
  private delivery: Promise<void> | null = null;
  private pinned: Segment | null = null;
  private acknowledgement: Segment | null = null;
  private inventory = new Map<string, Segment>();
  private inventoryBytes = 0n;
  private pendingCompletion: string | null = null;
  private committed: {
    bytes: string;
    allocationBytes: string;
    batches: number;
    lostBatches: string;
    firstLossAt: string | null;
    lastLossAt: string | null;
    coverageCondition: string | null;
    committedAt: string;
  } | null = null;
  private dnsGroup: DnsGroup | null = null;
  private pendingRecords = 0;
  private pendingBytes = 0;
  private rejectedRecords = 0n;
  private firstRejectedAt: string | null = null;
  private lastRejectedAt: string | null = null;
  private rejectionTimer: NodeJS.Timeout | null = null;
  private rejectionFlush: Promise<void> | null = null;
  private closing: Promise<void> | null = null;
  private stopped = false;
  private timer: NodeJS.Timeout | null = null;
  private deliveryError: string | null = null;
  private loggedDeliveryError: string | null = null;
  private persistenceError: string | null = null;
  private sourceWaiters = new Set<() => void>();
  private allocationBytes: bigint;
  constructor(
    private config: GatewayConfig,
    private send: SendBatch = async (batch) =>
      z
        .object({ epoch: z.string().uuid(), sequence: uint64Schema })
        .strict()
        .parse(
          await requestJson(
            new URL("/v1/observations", config.controllerUrl),
            config.tls,
            "POST",
            batch,
          ),
        ),
    private persist: typeof atomicJson = atomicJson,
    private syncSegments: () => Promise<void> = () => this.syncDirectory(),
    private budget?: StorageBudget,
    private persistenceLifecycle: {
      close: () => Promise<void>;
      readonly error: Error | null;
    } = { close: async () => {}, error: null },
  ) {
    this.allocationBytes = BigInt(config.collectorBytes);
  }
  get directory() {
    return join(this.config.stateDirectory, "segments");
  }
  get statePath() {
    return join(this.config.stateDirectory, "buffer.json");
  }
  private filename(sequence: string) {
    return join(this.directory, sequence.padStart(20, "0") + ".json");
  }
  private async syncDirectory() {
    const directory = await open(this.directory, "r");

    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  }
  private serialize<T>(
    operation: () => Promise<T>,
    kind: "producer" | "maintenance" = "producer",
  ): Promise<T> {
    if (kind === "producer") this.dnsGroup = null;

    if (kind === "producer" && this.queued >= 64)
      return Promise.reject(new Error("Observation persistence queue is full"));
    this.queued++;

    const task = this.tail
      .then(async () => {
        await this.finishEviction();

        if (this.acknowledgement) await this.finishAcknowledgement();

        return operation();
      })
      .finally(() => {
        this.queued--;
      });

    this.tail = task.catch(() => {});

    return task;
  }
  private remember(segment: Segment) {
    const previous = this.inventory.get(segment.path);
    this.inventoryBytes += BigInt(segment.bytes - (previous?.bytes ?? 0));
    this.inventory.set(segment.path, segment);
  }
  private forget(path: string) {
    const previous = this.inventory.get(path);

    if (previous) this.inventoryBytes -= BigInt(previous.bytes);
    this.inventory.delete(path);
  }
  private publish() {
    this.committed = {
      bytes: this.inventoryBytes.toString(),
      allocationBytes: this.allocationBytes.toString(),
      batches: this.inventory.size,
      lostBatches: this.state.lost,
      firstLossAt: this.state.firstLossAt,
      lastLossAt: this.state.lastLossAt,
      coverageCondition: this.state.coverageCondition,
      committedAt: new Date().toISOString(),
    };
    this.wakeSources();
  }
  private sourceReady() {
    return (
      this.pendingRecords === 0 &&
      (this.inventory.size === 0 ||
        (this.inventory.size === 1 &&
          this.pinned !== null &&
          this.inventory.has(this.pinned.path)))
    );
  }
  private wakeSources() {
    for (const wake of this.sourceWaiters) wake();
  }
  private async waitForSource(signal: AbortSignal) {
    for (;;) {
      signal.throwIfAborted();

      if (this.stopped) throw new Error("Observation persistence is stopped");

      if (this.sourceReady()) return;
      await new Promise<void>((resolve, reject) => {
        const cleanup = () => {
          this.sourceWaiters.delete(wake);
          signal.removeEventListener("abort", abort);
        };

        const wake = () => {
          cleanup();
          resolve();
        };

        const abort = () => {
          cleanup();
          reject(signal.reason);
        };

        this.sourceWaiters.add(wake);
        signal.addEventListener("abort", abort, { once: true });
      });
    }
  }
  private async checkpoint(state: BufferState) {
    const next = {
      ...state,
      rejectedRecords: this.rejectedRecords.toString(),
      firstRejectedAt: this.firstRejectedAt,
      lastRejectedAt: this.lastRejectedAt,
    };

    await this.persist(this.statePath, next);
    this.state = next;
    this.pendingCompletion = null;
  }
  private rejectRecords(count: number) {
    if (!count) return;
    const at = new Date().toISOString();
    this.rejectedRecords += BigInt(count);
    this.firstRejectedAt ??= at;
    this.lastRejectedAt = at;

    if (!this.rejectionTimer && !this.rejectionFlush && !this.stopped) {
      this.rejectionTimer = setTimeout(() => {
        this.rejectionTimer = null;
        this.rejectionFlush = this.serialize(async () => {
          if (this.state.rejectedRecords === this.rejectedRecords.toString())
            return;
          await this.checkpoint(this.state);
          this.publish();
        }, "maintenance")
          .catch(() => {
            this.persistenceError =
              "Collector rejection metadata could not be saved";
          })
          .finally(() => {
            this.rejectionFlush = null;
          });
      }, 50);
      this.rejectionTimer.unref();
    }
  }
  private lossState() {
    const at = new Date().toISOString();

    return {
      ...this.state,
      lost: (BigInt(this.state.lost) + 1n).toString(),
      firstLossAt: this.state.firstLossAt ?? at,
      lastLossAt: at,
    };
  }
  private async finishEviction() {
    const eviction = this.state.evicting;

    if (!eviction) return;
    const path = this.filename(eviction.sequence);

    // Re-establish intent if its preceding checkpoint failed after rename.
    await this.checkpoint(this.state);

    try {
      await unlink(path);
    } catch (error) {
      // This exact owned eviction may already have unlinked the segment.
      if (!hasErrorCode(error, "ENOENT")) throw error;
    }

    await this.syncSegments();
    await this.checkpoint({
      ...this.state,
      lost: eviction.lost,
      firstLossAt: eviction.firstLossAt,
      lastLossAt: eviction.lastLossAt,
      evicting: null,
    });
    this.forget(path);
    this.publish();
  }
  async start(): Promise<void> {
    await mkdir(this.directory, { recursive: true });
    // The unit's UMask=0077 would leave a new directory 0700. The enforcement service's storage budget reads it
    // through the traffic-policy group and has no capability to bypass file permissions.
    await chmod(this.directory, 0o750);

    try {
      this.state = stateSchema.parse(
        JSON.parse(await readFile(this.statePath, "utf8")),
      );
    } catch (error) {
      if (!hasErrorCode(error, "ENOENT")) throw error;

      if ((await this.scanSegments()).length)
        throw new Error(
          "Collector checkpoint is missing for retained observations",
        );
      this.state = stateSchema.parse({
        epoch: randomUUID(),
        sequence: "0",
        lost: "0",
        firstLossAt: null,
        lastLossAt: null,
        pending: null,
        sourceCommit: null,
        lastCommitHash: null,
        coverageCondition: null,
        rejectedRecords: "0",
        firstRejectedAt: null,
        lastRejectedAt: null,
        sessionOpen: false,
        evicting: null,
        dnsCommit: [],
      });
      await this.persist(this.statePath, this.state);
    }

    this.rejectedRecords = BigInt(this.state.rejectedRecords);
    this.firstRejectedAt = this.state.firstRejectedAt;
    this.lastRejectedAt = this.state.lastRejectedAt;
    const interrupted = this.state.sessionOpen;
    let greatest = BigInt(this.state.sequence);
    let tail: EventBatch | undefined;

    for (const segment of await this.scanSegments()) {
      const batch = eventBatchSchema.parse(
        JSON.parse(await readFile(segment.path, "utf8")),
      );

      if (
        batch.epoch !== this.state.epoch ||
        this.filename(batch.sequence) !== segment.path
      )
        throw new Error("Collector segment identity is invalid");

      if (BigInt(batch.sequence) > greatest) {
        greatest = BigInt(batch.sequence);
        tail = batch;
      }

      this.remember(segment);
    }

    await this.finishEviction();
    await this.recoverReservation(greatest.toString(), tail);
    await this.checkpoint({
      ...this.state,
      sessionOpen: true,
      coverageCondition: interrupted
        ? "Collector capture ended without a clean shutdown; some observations may be missing"
        : this.state.coverageCondition,
    });
    this.publish();
    this.timer = setInterval(() => {
      void this.deliver().catch((error: Error) => {
        if (this.loggedDeliveryError !== error.message)
          console.error(
            JSON.stringify({
              service: "collector-delivery",
              error: error.message,
            }),
          );
        this.loggedDeliveryError = error.message;
        this.deliveryError = error.message;
      });
    }, 1000);
    this.timer.unref();
  }
  // A notice about capture lost before this start, kept until its condition events are recorded.
  interruptionNotice(): string | null {
    return this.state.coverageCondition;
  }
  // Clears the notice once its condition events are appended, unless a newer notice replaced it.
  clearInterruptionNotice(notice: string): Promise<void> {
    return this.serialize(async () => {
      if (this.state.coverageCondition !== notice) return;
      await this.checkpoint({ ...this.state, coverageCondition: null });
      this.publish();
    }, "maintenance");
  }
  async allocation(bytes: string) {
    await this.coordinateAllocation(bytes, async () => undefined);
  }
  async coordinateAllocation<T>(
    bytes: string,
    commit: () => Promise<T>,
    budget = this.budget,
  ): Promise<T> {
    return this.serialize(async () => {
      await this.recoverReservation();
      const allocation = BigInt(uint64Schema.parse(bytes));
      const segments = await this.segments();

      const used = segments.reduce(
        (total, segment) => total + BigInt(segment.bytes),
        0n,
      );

      if (this.pinned && BigInt(this.pinned.bytes) > allocation)
        throw new ServiceError(
          507,
          "collector_delivery_pinned",
          "Wait for the in-flight observation delivery before reducing this allocation",
        );

      if (used > allocation)
        budget?.assertRoom(
          BigInt(Buffer.byteLength(JSON.stringify(this.lossState()))) * 2n +
            32768n,
          true,
        );
      const result = await commit();
      this.allocationBytes = allocation;
      await this.trim(0n);
      this.publish();

      return result;
    });
  }
  private async recoverReservation(
    sequence = this.state.sequence,
    tail?: EventBatch,
  ) {
    if (!this.state.pending) {
      if (sequence !== this.state.sequence) {
        const next = tail
          ? this.commitMetadata({ ...this.state, sequence }, tail, null)
          : { ...this.state, sequence };

        // Standalone DNS segments can be newer than the checkpoint. Fence
        // their directory before advancing durable sequence/deduplication state.
        await this.syncSegments();
        await this.checkpoint(next);
      }

      return;
    }

    const pending = this.state.pending;

    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- stateSchema already validated pending as a sequence string or an inline batch.
    if (typeof pending !== "string" && pending.batch.epoch !== this.state.epoch)
      throw new Error("Collector pending segment epoch is invalid");

    const reserved =
      // oxlint-disable-next-line anti-slop/no-runtime-typeof -- stateSchema already validated pending as a sequence string or an inline batch.
      typeof pending === "string" ? pending : pending.batch.sequence;

    let next: BufferState = {
      ...this.state,
      sequence: BigInt(sequence) > BigInt(reserved) ? sequence : reserved,
      pending: null,
    };

    let recovered: EventBatch | null = null;

    try {
      const batch = eventBatchSchema.parse(
        JSON.parse(await readFile(this.filename(reserved), "utf8")),
      );

      if (
        batch.epoch !== this.state.epoch ||
        batch.sequence !== reserved ||
        // oxlint-disable-next-line anti-slop/no-runtime-typeof -- stateSchema already validated pending as a sequence string or an inline batch.
        (typeof pending !== "string" &&
          hashDocument(batch) !== hashDocument(pending.batch))
      )
        throw new Error("Collector pending segment identity is invalid");
      recovered = batch;
    } catch (error) {
      if (!hasErrorCode(error, "ENOENT")) throw error;

      // oxlint-disable-next-line anti-slop/no-runtime-typeof -- stateSchema already validated pending as a sequence string or an inline batch.
      if (typeof pending === "string") {
        next.coverageCondition =
          "Collector restarted before a write completed; some observations may be missing";
      } else {
        // Re-establish the reservation before recovering a write whose initial
        // checkpoint may itself have failed after rename.
        await this.persist(this.statePath, this.state);
        await this.trim(
          BigInt(Buffer.byteLength(JSON.stringify(pending.batch)) + 1),
        );
        await this.persist(this.filename(reserved), pending.batch);
        recovered = pending.batch;
        next.lost = this.state.lost;
        next.firstLossAt = this.state.firstLossAt;
        next.lastLossAt = this.state.lastLossAt;
      }
    }

    await this.syncSegments();

    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- stateSchema already validated pending as a sequence string or an inline batch.
    if (typeof pending !== "string") {
      next = this.commitMetadata(next, pending.batch, pending.key);
    }

    if (tail && BigInt(tail.sequence) > BigInt(reserved))
      next = this.commitMetadata(next, tail, null);

    await this.checkpoint(next);

    if (recovered)
      this.remember({
        path: this.filename(reserved),
        bytes: Buffer.byteLength(JSON.stringify(recovered)) + 1,
      });
    this.persistenceError = null;
    this.publish();
  }
  private segments() {
    return [...this.inventory.values()].sort((a, b) =>
      a.path.localeCompare(b.path),
    );
  }
  private async scanSegments() {
    const names = (await readdir(this.directory))
      .filter((name) => /^[0-9]{20}\.json$/.test(name))
      .sort();

    return Promise.all(
      names.map(async (name) => {
        const path = join(this.directory, name);

        return { path, bytes: (await stat(path)).size };
      }),
    );
  }
  private async trim(incoming: bigint) {
    const segments = await this.segments();

    if (
      this.pinned &&
      BigInt(this.pinned.bytes) + incoming > this.allocationBytes
    )
      throw new ServiceError(
        507,
        "collector_delivery_pinned",
        "Collector allocation is occupied by an in-flight delivery",
      );

    let used = segments.reduce(
      (total, segment) => total + BigInt(segment.bytes),
      0n,
    );

    for (const segment of segments) {
      if (used + incoming <= this.allocationBytes) break;

      if (segment.path === this.pinned?.path) continue;
      const loss = this.lossState();
      this.state = {
        ...this.state,
        evicting: {
          sequence: BigInt(basename(segment.path, ".json")).toString(),
          lost: loss.lost,
          firstLossAt: loss.firstLossAt,
          lastLossAt: loss.lastLossAt,
        },
      };
      await this.finishEviction();
      used -= BigInt(segment.bytes);
    }

    if (used + incoming > this.allocationBytes)
      throw new ServiceError(
        507,
        "collector_delivery_pinned",
        "Collector allocation is occupied by an in-flight delivery",
      );
  }
  append(events: GatewayEvent[], key: string | null = null): Promise<void> {
    if (this.stopped)
      return Promise.reject(new Error("Observation persistence is stopped"));

    return this.serialize(() => this.commitAppend(events, key)).catch(
      (error: Error) => {
        this.persistenceError = error.message;
        throw error;
      },
    );
  }
  async appendSource(
    events: GatewayEvent[],
    key: string,
    signal: AbortSignal,
  ): Promise<void> {
    for (;;) {
      signal.throwIfAborted();

      if (this.stopped) throw new Error("Observation persistence is stopped");

      try {
        await this.serialize(() => {
          signal.throwIfAborted();

          return this.commitAppend(events, key, undefined, true);
        });

        return;
      } catch (error) {
        if (signal.aborted && error === signal.reason) throw error;

        if (
          !(error instanceof ServiceError) ||
          error.code !== "collector_source_wait"
        ) {
          this.persistenceError =
            error instanceof Error ? error.message : String(error);
          throw error;
        }
      }

      await this.waitForSource(signal);
    }
  }
  appendDns(event: GatewayEvent): Promise<void> {
    if (this.stopped)
      return Promise.reject(new Error("Observation persistence is stopped"));
    const parsed = eventSchema.safeParse(event);

    if (
      !parsed.success ||
      parsed.data.type !== "dns" ||
      parsed.data.source !== "resolver-gate"
    ) {
      this.rejectRecords(1);

      return Promise.reject(
        new ServiceError(
          400,
          "invalid_dns_observation",
          "DNS observation is invalid",
        ),
      );
    }

    const owned = parsed.data;
    const bytes = Buffer.byteLength(JSON.stringify(owned)) + 1;

    if (
      bytes + 256 > DNS_BATCH_BYTES ||
      this.pendingRecords === DNS_PENDING_RECORDS ||
      this.pendingBytes + bytes > DNS_PENDING_BYTES
    ) {
      this.rejectRecords(1);

      return Promise.reject(
        new ServiceError(
          429,
          "collector_queue_capacity",
          "DNS observation queue is full",
        ),
      );
    }

    this.pendingRecords++;
    this.pendingBytes += bytes;

    return new Promise<void>((accept, reject) => {
      let group = this.dnsGroup;

      if (
        !group ||
        group.events.length === MAX_OBSERVATION_BATCH_RECORDS ||
        group.bytes + bytes > DNS_BATCH_BYTES
      ) {
        group = {
          events: [],
          bytes: 256,
          openedAt: performance.now(),
          reserved: false,
          callers: [],
          hashes: new Map(),
          batchHash: "",
        };
        const queued = group;
        void this.serialize(async () => {
          const remaining =
            DNS_BATCH_WAIT_MS - (performance.now() - queued.openedAt);

          if (remaining > 0) await delay(remaining);

          if (this.dnsGroup === queued) this.dnsGroup = null;
          await this.recoverReservation();

          const previous = new Map(
            this.state.dnsCommit.map((value) => [value.id, value.hash]),
          );

          const unique = new Map<string, GatewayEvent>();
          const batchHash = createHash("sha256").update("[");

          for (const event of queued.events) {
            const canonical = stableJson(event);

            const hash = createHash("sha256").update(canonical).digest("hex"),
              saved = previous.get(event.id);

            if (saved && saved !== hash)
              throw new Error(
                "DNS observation identity conflicts with its committed event",
              );
            const duplicate = unique.get(event.id);

            if (duplicate && queued.hashes.get(event.id) !== hash)
              throw new Error(
                "DNS observation identity conflicts within its batch",
              );

            if (!saved && !duplicate) {
              if (unique.size) batchHash.update(",");
              batchHash.update(canonical);
              unique.set(event.id, event);
              queued.hashes.set(event.id, hash);
            }
          }

          queued.batchHash = batchHash.update("]").digest("hex");
          await this.commitAppend([...unique.values()], null, queued);
        }).then(
          () => {
            for (const caller of queued.callers) caller.accept();
          },
          (error: Error) => {
            // A refused queue admission never runs the operation that detaches
            // this group. Later callers must not join an already rejected batch.
            if (this.dnsGroup === queued) this.dnsGroup = null;
            this.persistenceError = error.message;

            if (!queued.reserved) this.rejectRecords(queued.events.length);

            for (const caller of queued.callers) caller.reject(error);
          },
        );
        this.dnsGroup = group;
      }

      group.events.push(owned);
      group.bytes += bytes;
      group.callers.push({ accept, reject });
    }).finally(() => {
      this.pendingRecords--;
      this.pendingBytes -= bytes;

      if (this.pendingRecords === 0) this.wakeSources();
    });
  }
  private async commitAppend(
    events: GatewayEvent[],
    key: string | null,
    group?: DnsGroup,
    sourceAdmission = false,
  ): Promise<void> {
    if (!events.length) return;
    // An earlier write may have failed after its segment became durable.
    // Resolve that reservation before replacing its checkpoint.
    await this.recoverReservation();
    // appendDns already owns schema-validated events and bounds its group. Parsing copies
    // other callers' events.
    const owned = group ? events : eventBatchSchema.shape.events.parse(events);
    const hash = group ? group.batchHash : hashDocument(owned);

    if (key !== null && this.state.sourceCommit?.key === key) {
      if (this.state.sourceCommit.hash !== hash)
        throw new Error(
          "Collector source commit identity conflicts with its observations",
        );

      return;
    }

    if (key === null && this.state.lastCommitHash === hash) return;

    if (sourceAdmission && !this.sourceReady())
      throw new ServiceError(
        429,
        "collector_source_wait",
        "Suricata observations are waiting for history delivery",
      );

    const sequence = uint64Schema.parse(
      (BigInt(this.state.sequence) + 1n).toString(),
    );

    const batch: EventBatch = {
      protocolVersion: 1,
      epoch: this.state.epoch,
      sequence,
      events: owned,
    };

    const serializedBytes = Buffer.byteLength(JSON.stringify(batch)) + 1;
    const bytes = BigInt(serializedBytes);
    this.budget?.assertRoom(bytes * 3n + 32768n, key !== null);

    if (bytes > this.allocationBytes) {
      throw new Error("Observation batch exceeds the collector allocation");
    }

    await this.trim(bytes);
    this.state = { ...this.state, sequence, pending: { batch, key } };

    if (group) group.reserved = true;

    // A DNS group's synchronized segment is its durable record. Keyed sources
    // retain their payload intent so source progress can recover independently.
    if (!group) await this.checkpoint(this.state);
    await this.persist(this.filename(sequence), batch);
    // Successful persistence already synchronized the segment and its directory.
    // Read and validate it again only when recovering an interrupted write.
    this.finishReservation(batch, key, hash, serializedBytes, group?.hashes);
    this.persistenceError = null;
  }
  private finishReservation(
    batch: EventBatch,
    key: string | null,
    hash: string,
    bytes: number,
    hashes?: ReadonlyMap<string, string>,
  ) {
    this.state = this.commitMetadata(
      { ...this.state, sequence: batch.sequence, pending: null },
      batch,
      key,
      hash,
      hashes,
    );
    // The segment is durable. Metadata is fenced before acknowledgement
    // deletion, by the next keyed reservation, or by clean shutdown.
    this.pendingCompletion = batch.sequence;
    this.remember({ path: this.filename(batch.sequence), bytes });
    this.publish();
  }
  private commitMetadata(
    state: BufferState,
    batch: EventBatch,
    key: string | null,
    hash = hashDocument(batch.events),
    hashes?: ReadonlyMap<string, string>,
  ): BufferState {
    const next: BufferState = { ...state, lastCommitHash: hash };

    if (key !== null) next.sourceCommit = { key, hash };

    if (
      batch.events.every(
        (event) => event.type === "dns" && event.source === "resolver-gate",
      )
    )
      next.dnsCommit = batch.events.map((event) => ({
        id: event.id,
        hash: hashes?.get(event.id) ?? hashDocument(event),
      }));

    return next;
  }
  deliver(): Promise<void> {
    if (this.delivery) return this.delivery;

    if (this.stopped) return Promise.resolve();
    this.delivery = this.deliverLoop()
      .catch((error: Error) => {
        this.deliveryError = error.message;
        throw error;
      })
      .finally(() => {
        this.delivery = null;
      });

    return this.delivery;
  }
  private async deliverLoop(): Promise<void> {
    try {
      for (let delivery = 0; delivery < 32 && !this.stopped; delivery++) {
        const selected = await this.serialize(async () => {
          await this.recoverReservation();
          const segment = (await this.segments())[0];

          if (!segment) return null;

          const batch = deliveryBatchSchema.parse(
            JSON.parse(await readFile(segment.path, "utf8")),
          );

          if (
            batch.epoch !== this.state.epoch ||
            this.filename(batch.sequence) !== segment.path
          )
            throw new Error("Collector delivery segment identity is invalid");
          this.pinned = segment;
          this.wakeSources();

          return { segment, batch };
        }, "maintenance");

        if (!selected) break;
        const response = await this.send(selected.batch);

        if (
          response.epoch !== selected.batch.epoch ||
          response.sequence !== selected.batch.sequence
        )
          throw new Error("Collector acknowledgement identity mismatch");
        this.acknowledgement = selected.segment;
        await this.serialize(async () => {
          await this.finishAcknowledgement();
        }, "maintenance");
      }
    } finally {
      await this.serialize(async () => {
        this.pinned = null;
        this.wakeSources();
      }, "maintenance");
    }
  }
  private async finishAcknowledgement() {
    const segment = this.acknowledgement;

    if (!segment) return;

    // A retained keyed intent can precede newer standalone DNS segments. Fence
    // all completed metadata before deleting any acknowledged recovery source.
    if (this.pendingCompletion !== null) await this.checkpoint(this.state);

    try {
      await unlink(segment.path);
    } catch (error) {
      // A preceding acknowledgement may have unlinked this exact owned segment
      // before its directory synchronization failed.
      if (!hasErrorCode(error, "ENOENT")) throw error;
    }

    this.forget(segment.path);
    await this.syncSegments();
    this.acknowledgement = null;
    this.pinned = null;
    this.deliveryError = null;
    this.loggedDeliveryError = null;
    this.publish();
  }
  status() {
    if (!this.committed)
      throw new ServiceError(
        503,
        "collector_not_ready",
        "Collector status is not initialized",
      );

    return {
      ...this.committed,
      deliveryError: this.deliveryError,
      persistenceError:
        this.persistenceLifecycle.error?.message ?? this.persistenceError,
      pendingDnsRecords: this.pendingRecords,
      pendingDnsBytes: this.pendingBytes.toString(),
      pendingWrites: this.queued,
      writePending: this.state.pending !== null || this.state.evicting !== null,
      rejectedRecords: this.rejectedRecords.toString(),
      firstRejectedAt: this.firstRejectedAt,
      lastRejectedAt: this.lastRejectedAt,
      rejectionCheckpointPending:
        this.state.rejectedRecords !== this.rejectedRecords.toString(),
    };
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.stopped = true;
    this.wakeSources();
    this.dnsGroup = null;

    if (this.timer) clearInterval(this.timer);

    if (this.rejectionTimer) clearTimeout(this.rejectionTimer);
    this.closing = (async () => {
      try {
        if (this.delivery) await Promise.allSettled([this.delivery]);
        await this.tail;

        if (!this.committed) return;
        await this.serialize(async () => {
          await this.checkpoint({ ...this.state, sessionOpen: false });
          this.publish();
        }, "maintenance");
      } finally {
        await this.persistenceLifecycle.close();
      }
    })();

    return this.closing;
  }
}
