import { randomUUID } from "node:crypto";
import {
  COUNTER_PAGE_SIZE,
  type EnforcementCommand,
  type EnforcementResult,
} from "@traffic-policy/contracts/enforcement";
import { ServiceError } from "@traffic-policy/core/io";
import { listBlockCounters, type BlockCounter } from "./native-access.ts";

// Final values kept for replaced tables until the gateway reads them. Drops past this bound are
// reported as uncounted instead of growing enforcement service memory while the gateway is away.
const RETIRED_LIMIT = 65536;

type CounterPage = Extract<
  EnforcementCommand,
  { operation: "counters" }
>["page"];

interface Reading {
  id: string;
  observedAt: string;
  counters: BlockCounter[];
  uncounted: string | null;
}

// Reads Block rule counters for the gateway in pages, and saves the final values of a table that a
// policy apply is about to replace, so drops between the last reading and the apply still count.
// Readings and applies run one at a time, so a table handle always belongs to the counters listed
// with it.
export class BlockCounters {
  #queue: Promise<void> = Promise.resolve();
  #retired: BlockCounter[] = [];
  #uncounted: string | null = null;
  #reading: Reading | null = null;

  constructor(
    private readonly boot: string,
    private readonly list: () => Promise<BlockCounter[]> = listBlockCounters,
  ) {}

  // The apply goes ahead when the counters cannot be read; the next reading reports the loss.
  replace<T>(rebuild: () => Promise<T>): Promise<T> {
    return this.#exclusive(async () => {
      try {
        const final = await this.list();

        if (this.#retired.length + final.length > RETIRED_LIMIT)
          this.#uncounted =
            "Counters of replaced policies were not read in time and are not counted";
        else this.#retired.push(...final);
      } catch (error) {
        this.#uncounted = `Counters could not be read before a policy apply: ${error instanceof Error ? error.message : "unknown failure"}`;
      }

      return rebuild();
    });
  }

  read(page: CounterPage): Promise<EnforcementResult<"counters">> {
    return this.#exclusive(async () => {
      if (page === null) {
        const current = await this.list();

        this.#reading = {
          id: randomUUID(),
          observedAt: new Date().toISOString(),
          counters: [...this.#retired, ...current],
          uncounted: this.#uncounted?.slice(0, 1024) ?? null,
        };
        this.#retired = [];
        this.#uncounted = null;
      }

      const reading = this.#reading;

      if (!reading || (page && reading.id !== page.reading))
        throw new ServiceError(
          409,
          "counter_reading_expired",
          "Counter reading is no longer available; start a new reading",
        );

      const offset = page?.offset ?? 0;
      const end = offset + COUNTER_PAGE_SIZE;
      const next = end < reading.counters.length ? end : null;

      if (next === null) this.#reading = null;

      return {
        reading: reading.id,
        observedAt: reading.observedAt,
        boot: this.boot,
        counters: reading.counters.slice(offset, end),
        next,
        uncounted: page === null ? reading.uncounted : null,
      };
    });
  }

  #exclusive<T>(action: () => Promise<T>): Promise<T> {
    const result = this.#queue.then(action);

    this.#queue = result.then(
      () => undefined,
      () => undefined,
    );

    return result;
  }
}
