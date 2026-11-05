import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    setupFiles: ["./tools/test-setup.ts"],
    include: ["packages/*/src/**/*.test.ts", "apps/*/src/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/.svelte-kit/**", "**/build/**"],
    pool: "forks",
    maxWorkers: 2,
  },
});
