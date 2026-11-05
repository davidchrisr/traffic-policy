import { afterEach, describe, expect, it, vi } from "vitest";
import { RefreshRunner } from "./refresh-runner.ts";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (cause: unknown) => void;

  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });

  return { promise, resolve, reject };
}

function fixture() {
  const onValue = vi.fn(),
    onError = vi.fn(),
    onBusy = vi.fn();

  return {
    runner: new RefreshRunner<string>({ onValue, onError, onBusy }),
    onValue,
    onError,
    onBusy,
  };
}

afterEach(() => vi.useRealTimers());

describe("Monitor refresh lifecycle", () => {
  it("cancels a channel without permanently disposing it", async () => {
    const { runner, onValue, onError } = fixture();
    let signal!: AbortSignal;

    const request = runner.run((next) => {
      signal = next;

      return new Promise<string>(() => {});
    });

    await Promise.resolve();
    runner.cancel();
    await request;
    expect(signal.aborted).toBe(true);
    expect(onError).not.toHaveBeenCalled();
    await runner.run(async () => "new snapshot");
    expect(onValue).toHaveBeenCalledExactlyOnceWith("new snapshot");
  });
  it("propagates caller-required failures while still completing cleanup", async () => {
    const onBusy = vi.fn(),
      failure = new Error("resource snapshot failed");

    const runner = new RefreshRunner<string>({
      onValue: vi.fn(),
      onBusy,
      onError: (error) => {
        throw error;
      },
    });

    await expect(
      runner.run(async () => {
        throw failure;
      }),
    ).rejects.toBe(failure);
    expect(onBusy.mock.calls).toEqual([[true], [false]]);
    runner.dispose();
  });
  it("skips polling while a refresh is running", async () => {
    const { runner, onValue, onBusy } = fixture(),
      pending = deferred<string>();

    const first = runner.run(() => pending.promise);
    const poll = vi.fn(async () => "poll");
    await runner.run(poll, false);
    expect(poll).not.toHaveBeenCalled();
    pending.resolve("first");
    await first;
    expect(onValue).toHaveBeenCalledExactlyOnceWith("first");
    expect(onBusy.mock.calls).toEqual([[true], [false]]);
    await runner.run(poll, false);
    expect(onValue).toHaveBeenLastCalledWith("poll");
  });

  it("aborts superseded requests and ignores their late response", async () => {
    const { runner, onValue, onError, onBusy } = fixture(),
      pending = deferred<string>();

    let previousSignal!: AbortSignal;

    const first = runner.run((signal) => {
      previousSignal = signal;

      return pending.promise;
    });

    await Promise.resolve();
    await runner.run(async () => "new scope");
    expect(previousSignal.aborted).toBe(true);
    pending.resolve("old scope");
    await first;
    expect(onValue).toHaveBeenCalledExactlyOnceWith("new scope");
    expect(onError).not.toHaveBeenCalled();
    expect(onBusy.mock.calls).toEqual([[true], [true], [false]]);
  });

  it("bounds a stalled request even when its operation ignores cancellation", async () => {
    vi.useFakeTimers();

    const { runner, onValue, onError, onBusy } = fixture(),
      pending = deferred<string>();

    let signal!: AbortSignal;

    const request = runner.run((next) => {
      signal = next;

      return pending.promise;
    });

    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(10_000);
    await request;
    expect(signal.aborted).toBe(true);
    expect(onError.mock.calls[0]![0]).toMatchObject({ name: "TimeoutError" });
    expect(onBusy).toHaveBeenLastCalledWith(false);
    pending.resolve("too late");
    await Promise.resolve();
    expect(onValue).not.toHaveBeenCalled();
    await runner.run(async () => "recovered", false);
    expect(onValue).toHaveBeenCalledExactlyOnceWith("recovered");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("aborts on disposal without updating an unmounted page", async () => {
    const { runner, onValue, onError, onBusy } = fixture(),
      pending = deferred<string>();

    let signal!: AbortSignal;

    const request = runner.run((next) => {
      signal = next;

      return pending.promise;
    });

    await Promise.resolve();
    runner.dispose();
    await request;
    expect(signal.aborted).toBe(true);
    pending.resolve("closed");
    await runner.run(async () => "after close");
    expect(onValue).not.toHaveBeenCalled();
    expect(onError).not.toHaveBeenCalled();
    expect(onBusy.mock.calls).toEqual([[true]]);
  });

  it("cancels the batch's remaining work after failure", async () => {
    const { runner, onError } = fixture();
    let signal!: AbortSignal;
    const failure = new Error("network failure");
    await runner.run(async (next) => {
      signal = next;
      throw failure;
    });
    expect(onError).toHaveBeenCalledExactlyOnceWith(failure);
    expect(signal.aborted).toBe(true);
  });
});
