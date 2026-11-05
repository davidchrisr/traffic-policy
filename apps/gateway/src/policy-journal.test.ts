import { afterEach, expect, it } from "vitest";
import {
  mkdtemp,
  mkdir,
  readFile,
  writeFile,
  rmdir,
  rm,
} from "node:fs/promises";
import { join } from "node:path";
import { FilePolicyJournal } from "./policy-journal.ts";

const directories: string[] = [];

afterEach(async () => {
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
});

it("distinguishes missing checkpoints from malformed and schema-invalid saved state", async () => {
  const directory = await mkdtemp(join(process.cwd(), ".tmp/tests/journal-"));

  directories.push(directory);

  const journal = new FilePolicyJournal(directory);
  expect(await journal.read("full-pending")).toBeNull();
  await writeFile(join(directory, "pending.json"), "broken JSON");
  await expect(journal.read("full-pending")).rejects.toThrow();
  await writeFile(
    join(directory, "pending.json"),
    JSON.stringify({ version: 1 }),
  );
  await expect(journal.read("full-pending")).rejects.toThrow();
});

it("repeats durable removal after a partial unlink failure without adopting missing state", async () => {
  const directory = await mkdtemp(join(process.cwd(), ".tmp/tests/journal-"));

  directories.push(directory);

  const journal = new FilePolicyJournal(directory);
  await writeFile(join(directory, "pending.json"), "owned pending fixture");
  await mkdir(join(directory, "applied.json"));
  await expect(
    journal.removeDurably("full-pending", "full-applied"),
  ).rejects.toThrow();
  await expect(readFile(join(directory, "pending.json"))).rejects.toMatchObject(
    { code: "ENOENT" },
  );
  await rmdir(join(directory, "applied.json"));
  await journal.removeDurably("full-pending", "full-applied");
  expect(await journal.read("full-applied")).toBeNull();
});
