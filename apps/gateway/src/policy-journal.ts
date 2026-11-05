import { hasErrorCode } from "@traffic-policy/core/io";
import { open, unlink } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { gatewayReceiptSchema, policySchema } from "@traffic-policy/contracts";
import { atomicJson, readJson } from "@traffic-policy/core/io";

export const policyCheckpointSchema = z
  .object({
    version: z.literal(1),
    policy: policySchema,
    receipt: gatewayReceiptSchema.nullable(),
  })
  .strict();

export type PolicyCheckpoint = z.infer<typeof policyCheckpointSchema>;

export type Checkpoints = {
  "full-pending": PolicyCheckpoint;
  "full-applied": PolicyCheckpoint;
};

export type CheckpointKind = keyof Checkpoints;

export interface PolicyJournal {
  read<K extends CheckpointKind>(kind: K): Promise<Checkpoints[K] | null>;
  replace<K extends CheckpointKind>(
    kind: K,
    value: Checkpoints[K],
  ): Promise<void>;
  removeDurably(...kinds: CheckpointKind[]): Promise<void>;
}

const names = {
  "full-pending": "pending.json",
  "full-applied": "applied.json",
} as const;

// oxlint-disable-next-line anti-slop/no-known-value-widening -- The correlated map preserves the checkpoint-key/output relationship when indexed generically.
const schema: { [K in CheckpointKind]: z.ZodType<Checkpoints[K]> } = {
  "full-pending": policyCheckpointSchema,
  "full-applied": policyCheckpointSchema,
};

export class FilePolicyJournal implements PolicyJournal {
  constructor(
    private directory: string,
    private persist: typeof atomicJson = atomicJson,
  ) {}
  async read<K extends CheckpointKind>(
    kind: K,
  ): Promise<Checkpoints[K] | null> {
    try {
      return await readJson(join(this.directory, names[kind]), schema[kind]);
    } catch (error) {
      if (hasErrorCode(error, "ENOENT")) return null;
      throw error;
    }
  }
  async replace<K extends CheckpointKind>(
    kind: K,
    value: Checkpoints[K],
  ): Promise<void> {
    await this.persist(join(this.directory, names[kind]), value);
  }
  async removeDurably(...kinds: CheckpointKind[]) {
    for (const kind of kinds)
      try {
        await unlink(join(this.directory, names[kind]));
      } catch (error) {
        if (!hasErrorCode(error, "ENOENT")) throw error;
      }

    const directory = await open(this.directory, "r");

    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  }
}
