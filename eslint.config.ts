import tseslint from "typescript-eslint";
import svelte from "eslint-plugin-svelte";
import { defineConfig } from "eslint/config";

export default defineConfig([
  {
    ignores: [
      "**/node_modules/**",
      "**/.svelte-kit/**",
      "**/build/**",
      "dist/**",
      ".local/**",
      ".tmp/**",
      "tools/oxlint/anti-slop/**",
    ],
  },
  ...tseslint.configs.recommended,
  ...svelte.configs.recommended,
  {
    files: ["**/*.svelte"],
    languageOptions: { parserOptions: { parser: tseslint.parser } },
    rules: { "svelte/block-lang": ["error", { script: "ts" }] },
  },
  {
    files: ["**/*.{js,jsx,mjs,cjs}"],
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector: "Program",
          message:
            "Authored application code, tools and executable configs must use TypeScript.",
        },
      ],
    },
  },
  {
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
]);
