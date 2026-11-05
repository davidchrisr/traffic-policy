import { Worker } from "node:worker_threads";
import { z } from "zod";
import { ServiceError, type atomicJson } from "@traffic-policy/core/io";
import type { StorageBudget } from "@traffic-policy/core/storage";

export type CollectorCommand =
  | {
      kind: "write";
      id: number;
      path: string;
      bytes: Uint8Array;
      mode: number | undefined;
    }
  | { kind: "close" };

const replySchema = z.discriminatedUnion("kind", [
  z
    .object({ kind: z.literal("written"), id: z.number().int().nonnegative() })
    .strict(),
  z
    .object({
      kind: z.literal("failed"),
      id: z.number().int().nonnegative(),
      message: z.string(),
      code: z.string().nullable(),
    })
    .strict(),
]);

export type CollectorReply = z.infer<typeof replySchema>;

export const collectorWorkerUrl = new URL(
  import.meta.url.endsWith(".ts")
    ? "./collector-worker.ts"
    : "./collector-worker.mjs",
  import.meta.url,
);

type PendingWrite = {
  id: number;
  promise: Promise<void>;
  accept: () => void;
  reject: (error: Error) => void;
};

/** One in-flight write; EventBuffer owns commit ordering and queue admission. */
export class CollectorWriter {
  private pending: PendingWrite | null = null;
  private nextId = 0;
  private failure: Error | null = null;
  private closing: Promise<void> | null = null;
  private accepting = true;
  private exited = false;
  private finishExit!: () => void;
  private readonly exit = new Promise<void>((resolve) => {
    this.finishExit = resolve;
  });

  constructor(
    private readonly budget: StorageBudget,
    private readonly worker = new Worker(collectorWorkerUrl),
  ) {
    // oxlint-disable-next-line anti-slop/no-unknown-parameters -- Worker replies are validated before any write acknowledgement is accepted.
    worker.on("message", (raw: unknown) => {
      const parsed = replySchema.safeParse(raw);
      const pending = this.pending;

      if (!parsed.success || !pending || parsed.data.id !== pending.id) {
        this.fail(
          new Error("Collector writer acknowledgement identity is invalid"),
        );

        return;
      }

      this.pending = null;

      if (parsed.data.kind === "written") pending.accept();
      else
        pending.reject(
          Object.assign(
            new Error(parsed.data.message),
            parsed.data.code === null ? {} : { code: parsed.data.code },
          ),
        );
    });
    worker.on("error", (error: Error) => this.fail(error));
    worker.once("exit", (code) => {
      this.exited = true;

      if (this.accepting || this.pending || code !== 0)
        this.fail(new Error(`Collector writer exited unexpectedly (${code})`));
      this.finishExit();
    });
  }

  private fail(error: Error) {
    this.failure ??= error;
    const pending = this.pending;
    this.pending = null;
    pending?.reject(this.failure);

    if (!this.exited) void this.worker.terminate();
  }

  get error(): Error | null {
    return this.failure;
  }

  writeJson: typeof atomicJson = async (path, value, mode) => {
    if (this.failure) throw this.failure;

    if (!this.accepting)
      throw new ServiceError(
        503,
        "collector_writer_closed",
        "Collector persistence is closed",
      );

    if (this.pending)
      throw new ServiceError(
        429,
        "collector_writer_busy",
        "Collector persistence already has an active write",
      );
    const json = JSON.stringify(value);
    this.budget.assertRoom(BigInt(Buffer.byteLength(json)) + 8192n, true);
    const bytes = new TextEncoder().encode(`${json}\n`);
    const id = ++this.nextId;
    let accept!: () => void, reject!: (error: Error) => void;

    const promise = new Promise<void>((resolve, fail) => {
      accept = resolve;
      reject = fail;
    });

    this.pending = { id, promise, accept, reject };

    try {
      this.worker.postMessage(
        {
          kind: "write",
          id,
          path,
          bytes,
          mode,
        } satisfies CollectorCommand,
        [bytes.buffer],
      );
    } catch (error) {
      this.pending = null;
      reject(error instanceof Error ? error : new Error(String(error)));
    }

    await promise;
  };

  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.accepting = false;
    this.closing = (async () => {
      if (this.pending) await Promise.allSettled([this.pending.promise]);

      if (!this.exited && !this.failure)
        this.worker.postMessage({ kind: "close" } satisfies CollectorCommand);
      await this.exit;
    })();

    return this.closing;
  }
}
