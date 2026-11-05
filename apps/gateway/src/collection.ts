import type { GatewayEvent } from "@traffic-policy/contracts";

/** Keeps one collection job intact until its batches and checkpoint commit. */
export class CollectionCommit {
  private pending: (() => Promise<void>) | null = null;
  constructor(
    private append: (events: GatewayEvent[], offset: number) => Promise<void>,
  ) {}
  async retry() {
    if (!this.pending) return false;
    await this.pending();
    this.pending = null;

    return true;
  }
  async write(
    events: GatewayEvent[],
    commit: () => Promise<void>,
    offset = 0,
    chunkRecords: 256 | 1024 = 256,
  ) {
    if (this.pending)
      throw new Error("A collection job is awaiting persistence");
    this.pending = async () => {
      while (offset < events.length) {
        await this.append(events.slice(offset, offset + chunkRecords), offset);
        offset += chunkRecords;
      }

      await commit();
    };

    await this.retry();
  }
}
