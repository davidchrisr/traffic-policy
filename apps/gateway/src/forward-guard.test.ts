import { expect, it, vi } from "vitest";
import { startProtectedForwarding } from "./forward-guard.ts";
import { withInstallationLock } from "./enforcement-owner.ts";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";

const lock = <T>(action: () => Promise<T>) => action();

it("keeps forwarding disabled when guard installation fails", async () => {
  const enable = vi.fn(async () => {});
  await expect(
    startProtectedForwarding(
      {
        disable: async () => {},
        protected: async () => false,
        install: async () => {
          throw new Error("Guard installation failed");
        },
        enable,
      },
      lock,
    ),
  ).rejects.toThrow("Guard installation failed");
  expect(enable).not.toHaveBeenCalled();
});

it("installs protection before enabling forwarding", async () => {
  const calls: string[] = [];
  await startProtectedForwarding(
    {
      disable: async () => {
        calls.push("disabled");
      },
      protected: async () => false,
      install: async () => {
        calls.push("guard");
      },
      enable: async () => {
        calls.push("forwarding");
      },
    },
    lock,
  );
  expect(calls).toEqual(["disabled", "guard", "forwarding"]);
});

it("enables forwarding without replacing an existing managed policy", async () => {
  const install = vi.fn(async () => {}),
    enable = vi.fn(async () => {});

  await startProtectedForwarding(
    {
      disable: async () => {},
      protected: async () => true,
      install,
      enable,
    },
    lock,
  );
  expect(install).not.toHaveBeenCalled();
  expect(enable).toHaveBeenCalledOnce();
});

it("does not enable forwarding when policy presence cannot be checked", async () => {
  const install = vi.fn(async () => {}),
    enable = vi.fn(async () => {});

  await expect(
    startProtectedForwarding(
      {
        disable: async () => {},
        protected: async () => {
          throw new Error("nft unavailable");
        },
        install,
        enable,
      },
      lock,
    ),
  ).rejects.toThrow("nft unavailable");
  expect(install).not.toHaveBeenCalled();
  expect(enable).not.toHaveBeenCalled();
});

it("prevents a paused guard check from installing after the enforcement service replaces policy", async () => {
  const path = await mkdtemp(join(process.cwd(), ".tmp/tests/guard-race-"));

  const installation = <T>(action: () => Promise<T>) =>
    withInstallationLock(action, path);

  let checked!: () => void;
  let release!: () => void;

  const entered = new Promise<void>((resolve) => {
    checked = resolve;
  });

  const held = new Promise<void>((resolve) => {
    release = resolve;
  });

  let managed = false,
    guarded = false,
    enabled = false;

  const guard = startProtectedForwarding(
    {
      disable: async () => {
        enabled = false;
      },
      protected: async () => {
        const present = managed;
        checked();
        await held;

        return present;
      },
      install: async () => {
        guarded = true;
      },
      enable: async () => {
        enabled = true;
      },
    },
    installation,
  );

  await entered;

  const policy = installation(async () => {
    managed = true;
    guarded = false;
  });

  try {
    await new Promise<void>((resolve) => setTimeout(resolve, 30));
    expect(managed).toBe(false);
  } finally {
    release();
    await Promise.all([guard, policy]);
    await rm(path, { recursive: true });
  }

  expect(managed).toBe(true);
  expect(guarded).toBe(false);
  expect(enabled).toBe(true);
});
