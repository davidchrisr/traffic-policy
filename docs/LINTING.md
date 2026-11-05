# Linting

All JavaScript tool CLIs and test workers run explicitly under Bun. ESLint's
config is `eslint.config.ts`; strict checks include root configs and all tools.
Lint rejects authored JavaScript and requires `lang="ts"` on Svelte scripts.
Generated outputs and `tools/oxlint/anti-slop/` are excluded explicitly.
`bun run format:check` verifies formatting without changing files.

Run `bun run lint` in an isolated development environment. It runs ESLint and
Oxlint. ESLint retains TypeScript and Svelte template checks. Oxlint runs the
vendored anti-slop rules on application code, tests, service tools and its
config, including Svelte script blocks. Prettier remains the formatter.

## Rule decisions

All 18 generic anti-slop rules are enabled as errors in `oxlint.config.ts`,
along with `oxc/no-accumulating-spread`.

`require-readable-spacing` enforces blank lines between declarations and logical
statement groups. Apply Oxlint's spacing fixes, run Prettier, then run lint.
Formatting can expose a newly multiline declaration that needs another spacing
fix; resolve it before completing verification.

`no-runtime-typeof` permits explicit type guards. A type guard is itself a
validation boundary, so forbidding primitive checks there would prevent its
implementation.

The following exceptions are limited to test files:

- Assertion comments are not required in `*.test.ts`. Negative tests and partial
  fixtures intentionally construct values that production contracts reject.
  Chained assertions and loss of known type information remain prohibited.
- Module mocks are permitted only in `startup.test.ts`, `kernel-events.test.ts`
  and `machine-request.test.ts`. These tests verify entrypoint ordering,
  subprocess streams and HTTPS failure handling. Mocking those native
  dependencies avoids starting privileged services or making real network
  requests. Other tests retain the rule.

Source-level exceptions have a reason on each affected line. They permit:

- `unknown` at JSON transport, schema parser, error and serialization
  boundaries. Successful transport results remain unknown until the caller
  validates them.
- Primitive discrimination of already validated unions, including pending buffer
  state, event metadata and `FormData` values.
- The correlated checkpoint schema map. Its annotation preserves the
  relationship between a checkpoint key and the parser's output when indexed
  generically.

Do not replace boundary `unknown` with `any`, cast a result merely to silence a
rule, or add a `SAFETY:` comment without a checked invariant. For a new
exception, use the narrowest directive and state the concrete reason.

Lint rejects unused suppression comments. Remove a directive when its code no
longer needs the exception.

Effect rules are not loaded because this application does not use Effect. Other
Oxlint rule categories are disabled; ESLint retains the existing general rules.

## Vendored source

The plugin comes from
[dmmulroy/anti-slop](https://github.com/dmmulroy/anti-slop) at commit
`c44ef22ca116d0ba62a3ff663a0bd13a3f3fa40b`. Its `src/` directory and MIT license
are copied to `tools/oxlint/anti-slop/` without local source modifications. The
embedded ESLint Stylistic license and provenance are retained in its vendor
directory. The copied source includes upstream tests; these are excluded from
application checks and are not part of application test coverage.

The downloaded source archive's locally computed SHA-256 is
`afc6aaeb4561561835c51e0a919ac86a1ebd1474667a3bd311e5a0a775f3d3d9`. This records
the downloaded bytes; upstream did not provide a separate archive checksum.

`oxlint` and `@oxlint/plugins` are both pinned to `1.87.0`, published October
5, 2026. Keep these versions equal. Review upstream changes before updating the
plugin, preserve local policy decisions and record the new revision. Oxlint's
JavaScript plugin API is still alpha, so upgrades need a full lint run.
