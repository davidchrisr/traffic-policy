import { join } from "node:path";
import { z } from "zod";
import type { Policy } from "@traffic-policy/contracts";
import {
  atomicJson,
  hasErrorCode,
  readJson,
  ServiceError,
} from "@traffic-policy/core/io";
import {
  CONNECTION_MARK_MASK,
  connectionMarkScopes,
  type MarkAssignments,
} from "@traffic-policy/core/nftables";

const stateSchema = z
  .object({
    version: z.literal(1),
    next: z
      .number()
      .int()
      .min(1)
      .max(CONNECTION_MARK_MASK + 1),
    marks: z.record(
      z.string(),
      z.number().int().min(1).max(CONNECTION_MARK_MASK),
    ),
  })
  .strict();

type MarkState = z.infer<typeof stateSchema>;

export interface MarkStore {
  // Null when no state was saved.
  read(): Promise<MarkState | null>;
  write(state: MarkState): Promise<void>;
}

export function fileMarkStore(directory: string): MarkStore {
  const path = join(directory, "connection-marks.json");

  return {
    read: async () => {
      try {
        return await readJson(path, stateSchema);
      } catch (error) {
        if (hasErrorCode(error, "ENOENT")) return null;

        throw new Error(
          `Connection mark state ${path} could not be read: ${error instanceof Error ? error.message : "unknown failure"}`,
          { cause: error },
        );
      }
    },
    write: (state) => atomicJson(path, state),
  };
}

// Gives each DNS Allow rule and instance a connection mark that is never given to another. A mark
// is saved before any installed rule sets it, and the next mark only grows, so a connection still
// carrying an old mark can never match a different rule.
export class ConnectionMarks {
  #state: MarkState | null = null;

  constructor(private readonly store: MarkStore) {}

  // Marks of the candidate policy. Marks of the installed policy are kept as well, so preparing or
  // failing to install a candidate does not renumber the installed rules.
  async assign(
    candidate: Policy,
    installed: Policy | null,
  ): Promise<MarkAssignments> {
    const state = this.#state ??
      (await this.store.read()) ?? { version: 1, next: 1, marks: {} };

    const scopes = connectionMarkScopes(candidate);

    const kept = new Set([
      ...scopes,
      ...(installed ? connectionMarkScopes(installed) : []),
    ]);

    const marks = Object.fromEntries(
      Object.entries(state.marks).filter(([scope]) => kept.has(scope)),
    );

    let next = state.next;

    for (const scope of scopes) {
      if (marks[scope] !== undefined) continue;

      if (next > CONNECTION_MARK_MASK)
        throw new ServiceError(
          507,
          "connection_marks_exhausted",
          "Every connection mark has been used.",
        );
      marks[scope] = next++;
    }

    const updated: MarkState = { version: 1, next, marks };

    if (
      next !== state.next ||
      Object.keys(marks).length !== Object.keys(state.marks).length
    )
      await this.store.write(updated);
    this.#state = updated;

    return new Map(scopes.map((scope) => [scope, marks[scope]!]));
  }
}
