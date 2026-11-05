interface RefreshCallbacks<T> {
  onValue: (value: T) => void;
  onError: (cause: unknown) => void;
  onBusy: (busy: boolean) => void;
}

// One current refresh batch. Polls skip busy batches; user changes supersede them.
export class RefreshRunner<T> {
  private active: AbortController | null = null;
  private disposed = false;

  constructor(
    private readonly callbacks: RefreshCallbacks<T>,
    private readonly timeoutMs = 10_000,
  ) {}

  async run(
    work: (signal: AbortSignal) => Promise<T>,
    supersede = true,
  ): Promise<void> {
    if (this.disposed || (this.active && !supersede)) return;
    this.active?.abort(new DOMException("Refresh superseded", "AbortError"));
    const controller = new AbortController();
    this.active = controller;
    this.callbacks.onBusy(true);

    const timeout = setTimeout(
      () =>
        controller.abort(new DOMException("Refresh timed out", "TimeoutError")),
      this.timeoutMs,
    );

    let onAbort: () => void;

    const aborted = new Promise<never>((_resolve, reject) => {
      onAbort = () => reject(controller.signal.reason);
      controller.signal.addEventListener("abort", onAbort, { once: true });
    });

    try {
      const operation = Promise.resolve().then(() => {
        if (controller.signal.aborted) throw controller.signal.reason;

        return work(controller.signal);
      });

      const value = await Promise.race([operation, aborted]);

      if (
        this.active === controller &&
        !this.disposed &&
        !controller.signal.aborted
      ) {
        this.callbacks.onValue(value);
      }
    } catch (failure) {
      if (
        this.active === controller &&
        !this.disposed &&
        (!controller.signal.aborted ||
          controller.signal.reason?.name === "TimeoutError")
      ) {
        this.callbacks.onError(
          controller.signal.aborted ? controller.signal.reason : failure,
        );
      }
    } finally {
      clearTimeout(timeout);
      controller.signal.removeEventListener("abort", onAbort!);
      // Stop sibling fetches when one member of a batch fails.
      controller.abort(new DOMException("Refresh complete", "AbortError"));

      if (this.active === controller) {
        this.active = null;
        this.callbacks.onBusy(false);
      }
    }
  }

  cancel(): void {
    this.active?.abort(new DOMException("Refresh superseded", "AbortError"));
  }

  dispose(): void {
    this.disposed = true;
    this.active?.abort(new DOMException("View closed", "AbortError"));
    this.active = null;
  }
}
