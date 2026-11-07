import { mkdir } from "node:fs/promises";
import { join } from "node:path";

await mkdir(join(process.cwd(), ".local/tmp/tests"), { recursive: true });
