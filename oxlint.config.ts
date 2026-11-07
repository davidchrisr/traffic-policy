import { defineConfig } from "oxlint";

// Policy and boundary exceptions are documented in docs/LINTING.md.
export default defineConfig({
  categories: { correctness: "off" },
  plugins: ["oxc"],
  jsPlugins: [
    { name: "anti-slop", specifier: "./tools/oxlint/anti-slop/index.ts" },
  ],
  ignorePatterns: [
    "**/node_modules/**",
    "**/.svelte-kit/**",
    "**/build/**",
    "dist/**",
    ".local/**",
    ".agents/**",
    "tools/oxlint/anti-slop/**",
  ],
  rules: {
    "oxc/no-accumulating-spread": "error",
    "anti-slop/no-array-filter-map": "error",
    "anti-slop/no-reduce-accumulator-copy": "error",
    "anti-slop/no-chained-type-assertions": "error",
    "anti-slop/no-conditional-empty-object-spread": "error",
    "anti-slop/no-known-value-widening": "error",
    "anti-slop/no-module-mocking": "error",
    "anti-slop/no-object-parameters": "error",
    "anti-slop/no-reflect-apply": "error",
    "anti-slop/no-reflect-get": "error",
    "anti-slop/no-runtime-typeof": ["error", { allowInTypeGuards: true }],
    "anti-slop/no-shape-in-symbol-names": "error",
    "anti-slop/no-unknown-parameters": "error",
    "anti-slop/no-unknown-returns": "error",
    "anti-slop/no-unknown-type-aliases": "error",
    "anti-slop/no-unsafe-dictionary-type": "error",
    "anti-slop/no-widen-then-assert": "error",
    "anti-slop/require-readable-spacing": "error",
    "anti-slop/require-safety-comment-for-type-assertion": "error",
  },
  overrides: [
    {
      files: ["**/*.test.ts"],
      rules: {
        // Invalid and partial fixtures deliberately cross type boundaries.
        "anti-slop/require-safety-comment-for-type-assertion": "off",
      },
    },
    {
      files: [
        "apps/gateway/src/startup.test.ts",
        "apps/gateway/src/kernel-events.test.ts",
        "packages/core/src/machine-request.test.ts",
      ],
      rules: {
        // These test native I/O and entrypoint wiring, including ordering.
        "anti-slop/no-module-mocking": "off",
      },
    },
  ],
});
