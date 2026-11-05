import { readFile } from "node:fs/promises";
import { settingsSchema } from "../packages/contracts/src/index.ts";
import { ControllerStore } from "../apps/controller/src/lib/server/store.ts";

const args = process.argv.slice(2);

const value = (name: string) => {
  const index = args.indexOf(name);

  return index >= 0 ? args[index + 1] : undefined;
};

const database = value("--database"),
  passwordFile = value("--password-file"),
  settingsFile = value("--settings-file");

if (!database || !passwordFile || !settingsFile)
  throw new Error(
    "Use --database PATH --password-file PATH --settings-file PATH",
  );

const password = (await readFile(passwordFile, "utf8")).replace(/\r?\n$/, "");

const settings = settingsSchema.parse(
  JSON.parse(await readFile(settingsFile, "utf8")),
);

const store = new ControllerStore(database, args.includes("--initialize"));

try {
  await store.setup(password, settings);
  console.log("Admin configured; previous sessions revoked.");
} finally {
  store.close();
}
