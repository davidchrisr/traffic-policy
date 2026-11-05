import { afterEach, expect, it } from "vitest";
import { mkdir, mkdtemp, readdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { atomicJson, hasErrorCode } from "./io.server.ts";

it("narrows an errno without assuming arbitrary thrown values are errors", () => {
  expect(
    hasErrorCode(
      Object.assign(new Error("missing"), { code: "ENOENT" }),
      "ENOENT",
    ),
  ).toBe(true);

  for (const cause of [
    null,
    undefined,
    "ENOENT",
    {},
    { code: "ENOENT" },
    new Error("missing"),
  ])
    expect(hasErrorCode(cause, "ENOENT")).toBe(false);
  expect(
    hasErrorCode(
      Object.assign(new Error("denied"), { code: "EACCES" }),
      "ENOENT",
    ),
  ).toBe(false);
});

const roots: string[] = [];

afterEach(async () => {
  for (const root of roots.splice(0)) await rm(root, { recursive: true });
});

it("removes its temporary write when the destination rename fails", async () => {
  const root = await mkdtemp(join(process.cwd(), ".tmp/tests/io-test-"));

  roots.push(root);
  const path = join(root, "destination");
  await mkdir(path);
  await expect(atomicJson(path, { fixture: true })).rejects.toThrow();
  expect(await readdir(root)).toEqual(["destination"]);
});
