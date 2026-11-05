export type ShutdownTask = () => void | Promise<void>;

export class PendingWork {
  private readonly tasks = new Set<Promise<void>>();
  track(task: Promise<void>) {
    this.tasks.add(task);
    void task.then(
      () => this.tasks.delete(task),
      () => this.tasks.delete(task),
    );
  }
  async drain() {
    while (this.tasks.size) await Promise.allSettled([...this.tasks]);
  }
}

export async function finishShutdown(
  phases: readonly (readonly ShutdownTask[])[],
) {
  const errors: unknown[] = [];

  for (const phase of phases) {
    const results = await Promise.allSettled(
      phase.map((task) => Promise.resolve().then(task)),
    );

    for (const result of results)
      if (result.status === "rejected") errors.push(result.reason);
  }

  if (errors.length)
    throw new AggregateError(errors, "Shutdown cleanup failed");
}
