import { build } from "esbuild";
import { cp, mkdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import { requireBuildOrigin } from "../apps/controller/build-origin.ts";

const origin = requireBuildOrigin(process.env.TP_PUBLIC_ORIGIN);

await mkdir("dist", { recursive: true });

for (const [name, entry] of [
  ["enforcement", "apps/gateway/src/enforcement-service.ts"],
  ["gateway", "apps/gateway/src/server.ts"],
  ["collector-worker", "apps/gateway/src/collector-worker.ts"],
  ["controller-runtime", "tools/controller-runtime.ts"],
  ["controller-machine", "tools/controller-machine.ts"],
  ["setup-admin", "tools/setup-admin.ts"],
  ["suricata-rotate", "tools/suricata-rotate.ts"],
  ["forward-guard", "tools/forward-guard.ts"],
]) {
  await build({
    entryPoints: [entry!],
    outfile: `dist/${name}.mjs`,
    bundle: true,
    platform: "node",
    target: "es2023",
    format: "esm",
    external: ["@node-rs/argon2"],
    banner: {
      js: "import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);",
    },
  });
}

const child = spawn(
  process.execPath,
  ["--bun", "run", "--cwd", "apps/controller", "build"],
  { stdio: "inherit", env: { ...process.env, TP_PUBLIC_ORIGIN: origin } },
);

await new Promise<void>((resolve, reject) => {
  child.on("error", reject);
  child.on("close", (code) =>
    code === 0 ? resolve() : reject(new Error("Controller build failed")),
  );
});

// Ship the licensed source dataset alongside the bundled server code.
const licenseDirectory = "apps/controller/build/LICENSES/public-suffix-list";

await mkdir(licenseDirectory, { recursive: true });

for (const file of ["LICENSE", "public_suffix_list.dat", "README.md"])
  await cp(`packages/core/data/${file}`, `${licenseDirectory}/${file}`);
