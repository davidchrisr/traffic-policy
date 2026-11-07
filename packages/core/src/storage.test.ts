import { afterEach, expect, it } from "vitest";
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  linkSync,
  symlinkSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { StorageBudget, storageUsage } from "./storage.server.ts";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true });
});

it("counts unique allocated inodes and protects the recovery reserve", () => {
  const root = mkdtempSync(join(process.cwd(), ".local/tmp/tests/storage-"));

  roots.push(root);
  writeFileSync(join(root, "data"), randomBytes(8192));
  const initial = storageUsage([join(root, "data")]);
  linkSync(join(root, "data"), join(root, "alias"));
  expect(storageUsage([join(root, "data"), join(root, "alias")])).toEqual(
    initial,
  );
  const used = BigInt(storageUsage([root]).allocatedBytes);
  const budget = new StorageBudget([root], used + 1000n, 500n);
  expect(() => budget.assertRoom(600n)).toThrow("Storage limit reached");
  expect(() => budget.assertRoom(600n, true)).not.toThrow();
  symlinkSync(join(root, "data"), join(root, "link"));
  expect(() => budget.status()).toThrow("symbolic links");
});
