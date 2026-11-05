import { mkdir } from "node:fs/promises";
import { join } from "node:path";

await mkdir(join(process.cwd(), ".tmp/tests"), { recursive: true });
