import { afterEach, expect, it, vi } from "vitest";
import { ChildProcess } from "node:child_process";
import { PassThrough } from "node:stream";
import { runNativeCommand, type NativeSpawn } from "./native-access.ts";

const mocks = { spawn: vi.fn<NativeSpawn>() };

class FixtureProcess extends ChildProcess {
  override stdin = new PassThrough();
  override stdout = new PassThrough();
  override stderr = new PassThrough();
  override stdio: [PassThrough, PassThrough, PassThrough, null, null] = [
    this.stdin,
    this.stdout,
    this.stderr,
    null,
    null,
  ];
  override kill = vi.fn<ChildProcess["kill"]>();
}

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
});

function processFixture() {
  const child = new FixtureProcess();
  mocks.spawn.mockReturnValue(child);

  return child;
}

it("confirms actual nft application only after successful process completion", async () => {
  const child = processFixture(),
    result = runNativeCommand(
      "/usr/sbin/nft",
      ["--file", "-"],
      "fixture program",
      mocks.spawn,
    );

  expect(mocks.spawn).toHaveBeenCalledWith(
    "/usr/sbin/nft",
    ["--file", "-"],
    expect.objectContaining({ stdio: "pipe" }),
  );
  child.emit("close", 0);
  await expect(result).resolves.toBe("");
});

it("preserves command errors as failed application", async () => {
  const child = processFixture(),
    result = runNativeCommand(
      "/usr/sbin/nft",
      ["--file", "-"],
      "invalid program",
      mocks.spawn,
    );

  child.stderr.write("syntax error");
  child.emit("close", 1);
  await expect(result).rejects.toMatchObject({
    code: "kernel_operation_failed",
    message: expect.stringContaining("syntax error"),
  });
});

it("handles interrupted command input without an unhandled stream error", async () => {
  const child = processFixture();
  child.kill.mockImplementation(() => {
    child.emit("close", null);

    return true;
  });

  const result = runNativeCommand(
    "/usr/sbin/nft",
    ["--file", "-"],
    "fixture",
    mocks.spawn,
  );

  child.stdin.emit("error", new Error("input closed"));
  await expect(result).rejects.toMatchObject({
    code: "kernel_operation_uncertain",
  });
});

it.each([null, 0])(
  "reports uncertain completion after the deadline, even with exit %s",
  async (code) => {
    vi.useFakeTimers();
    const child = processFixture();
    child.kill.mockImplementation(() => {
      child.emit("close", code);

      return true;
    });

    const result = runNativeCommand(
      "/usr/sbin/nft",
      ["--file", "-"],
      "slow fixture",
      mocks.spawn,
    );

    const rejected = expect(result).rejects.toMatchObject({
      code: "kernel_operation_uncertain",
    });

    await vi.advanceTimersByTimeAsync(10000);
    await rejected;
    expect(child.kill).toHaveBeenCalledWith("SIGKILL");
  },
);
