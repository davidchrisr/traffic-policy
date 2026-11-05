# Third-party material

The root MIT license covers project-authored code. Preserve the following
upstream notices when redistributing copied material:

| Material                 | Location                                                            | License and provenance                                                                                                                                        |
| ------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Anti-slop                | `tools/oxlint/anti-slop/`                                           | MIT; pinned source and update policy in [Linting](LINTING.md). Includes embedded ESLint Stylistic notices. Upstream's installation model is source vendoring. |
| shadcn-svelte components | `apps/controller/src/lib/components/ui/`                            | MIT; upstream copyright and license in that directory. Components are copied into the application for customization.                                          |
| Inter                    | `apps/controller/static/fonts/inter/`                               | SIL Open Font License 1.1; license included with the font files.                                                                                              |
| Public Suffix List       | `packages/core/data/` and `packages/core/src/public-suffix-data.ts` | MPL 2.0; source revision, hash and license in the [dataset notes](../packages/core/data/README.md).                                                           |

Other dependencies are installed through Bun and pinned in `bun.lock`. Their
licenses remain those of their respective packages. Bundling a dependency does
not change its license. Include the applicable dependency notices when
redistributing application binaries.
