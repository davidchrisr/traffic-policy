# Traffic Policy

Network visibility and control for a Linux gateway. Monitor traffic, manage
firewall rules and review connection requests through a self-hosted dashboard.

Handles over **5,000 DNS queries per second during short bursts on a two-vCPU
gateway**, measured with traffic capture and history collection enabled. See
[benchmarks](docs/BENCHMARKS.md) for the workload and results.

## What it does

- Apply global, instance, and address rules for addresses, domains, protocols
  and ports, with priorities and expiration times. Instances can be hosts or
  whole subnets; nested ones inherit their parents' rules.
- Drop traffic from hosts no instance covers and ask to register the ones seen
  on any interface other than upstream ones.
- Authorize DNS-derived destinations before releasing permitted DNS answers.
- Monitor sent and received traffic, group peers by domain and inspect
  connection evidence.
- Review blocked requests and policy changes in the dashboard.
- Collect observations into a bounded durable delivery buffer, with visible
  reporting of capture gaps, rejected observations and retention limits.

The application runs on a routed Linux gateway. It manages network instances,
not per-process permissions on a desktop. Network routing and client DNS
configuration are provisioned separately.

## Architecture

The SvelteKit controller owns the dashboard, authentication, desired policy and
SQLite history. An unprivileged gateway handles DNS authorization and
observation delivery. A restricted privileged enforcement service owns nftables
updates. Suricata supplies passive metadata; observed names do not independently
authorize traffic.

The stack uses strict TypeScript, Bun, Svelte 5, SvelteKit, Zod, shadcn-svelte,
Tailwind, Inter, Lucide and Apache ECharts. Machine APIs use mutual TLS. Learned
DNS permissions are held in memory and renewed by subsequent lookups after an
enforcement service restart.

Read the [architecture](docs/ARCHITECTURE.md) for system and policy behavior,
the [API contract](API_CONTRACT.md) for wire formats, and the
[visual design system](DESIGN.md) for presentation.

## Build and verify

Use Linux with the Bun version pinned in `package.json`. Development checks do
not need a live gateway or root privileges. OpenSSL is required by the TLS
tests. Run these commands inside a tooling container or isolated development
environment:

```sh
bun install --frozen-lockfile
bun run check
bun run test
bun run lint
bun run lint:markdown
bun run format:check
TP_PUBLIC_ORIGIN=https://controller.example.test:9444 bun run build
```

The build origin must exactly match the controller's configured `publicOrigin`.
Build the controller separately for each deployment origin. Development and type
checks can run without this variable; production builds require it.

The [CI workflow](.github/workflows/ci.yml) runs the quality checks and a build
without privileged networking. Native firewall and full network integration
checks require a separate Linux lab. A [development stack](dev/docker/README.md)
runs a controller, gateway and routed client in containers for end-to-end
checks; [Verification](docs/VERIFICATION.md) describes using it. Run
`bun run catalog` to open the component catalog for frontend work.
[Linting](docs/LINTING.md) explains the ESLint, Oxlint and anti-slop policies.

## Run it

Follow the [setup guide](docs/SETUP.md) for configuration, machine identities,
Admin initialization and Linux services. The [example configurations](examples/)
use documentation addresses and contain no credentials. There is no default
Admin password.

The service definitions target Linux x64 with glibc and systemd. Deployment
requires nftables, conntrack, Suricata and a configured routing topology.
Network commissioning is manual; the project does not configure a router
automatically.

## Repository layout

| Path                  | Purpose                                                             |
| --------------------- | ------------------------------------------------------------------- |
| `packages/contracts/` | Validated shared data and wire contracts                            |
| `packages/core/`      | Rule precedence, DNS permissions and native compilation             |
| `apps/gateway/`       | Enforcement service, resolver gate, collection and durable delivery |
| `apps/controller/`    | Dashboard, services, SQLite and gateway link                        |
| `tools/`              | Build, runtime and Admin setup tooling                              |
| `packaging/linux/`    | Linux service units, sysctls and pinned runtime metadata            |
| `examples/`           | Deployment configuration templates                                  |
| `dev/docker/`         | Development stack for end-to-end checks                             |
| `DESIGN.md`           | Visual design and component recipes                                 |
| `docs/`               | Architecture, setup, product behavior and benchmarks                |

## Security

Report vulnerabilities privately as described in the
[security policy](SECURITY.md).

## License

Project-authored code is available under the [MIT license](LICENSE).
[Third-party notices](docs/THIRD_PARTY.md) identify copied source, datasets and
fonts with their own licenses.
