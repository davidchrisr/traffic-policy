# Development stack

A controller, a gateway, and one routed client, built from your checkout with
`nerdctl compose`, rootless included, so several developers or agents can each
test against their own stack instead of a shared instance. It runs on x86-64
hosts, matching the packaged Bun runtime.

It tests application behavior. It does not test the production install: there is
no systemd, and the units' ordering and sandboxing are replaced by the entry
scripts here. Use [Setup](../../docs/SETUP.md) on a host or VM for that.

## Start

Once per host, create the dependency cache that every stack shares:

```sh
nerdctl volume create tp-dev-bun-cache
```

Write Admin's password to a file outside the repository, readable only by you.
Copy `.env.example` to `.env` (or to `.env.<name>` for each extra stack), set
`TP_ADMIN_PASSWORD_FILE` to that file, and run this ordered sequence from this
directory to start or rebuild the stack:

```sh
nerdctl compose --env-file .env down &&
  nerdctl compose --env-file .env build &&
  nerdctl compose --env-file .env run --rm -i=false build &&
  nerdctl compose --env-file .env run --rm -i=false init &&
  nerdctl compose --env-file .env up -d controller gateway client
```

`down` keeps the volumes. Building and initializing must succeed before the
runtime services start; the `&&` chain stops on failure. A plain `up -d` also
starts the build service, which can rewrite the work volume while other services
accept its previous `.built` marker. Use the ordered sequence above with
retained volumes too.

The first start builds the runtime image and application, which takes a few
minutes; later builds reuse caches. Sign in at `TP_ORIGIN` as Admin with that
password.

The stack is ready when the build and init commands returned status 0, the three
runtime services are running, and the gateway's log shows `"ready":true` for
both the enforcement service and the gateway. The one-off build and init
containers are removed after they exit.

## Change code

The source is mounted read-only. Repeat the ordered [Start](#start) sequence
after changing source, entry scripts, the `Dockerfile`, or `systemctl`. It stops
consumers before rebuilding shared outputs, rebuilds the runtime image, and
recreates the runtime containers while keeping their volumes.

## Generate traffic

The client routes through the gateway and resolves through its DNS gate:

```sh
nerdctl compose --env-file .env exec client curl -sI https://example.com
nerdctl compose --env-file .env exec client dig example.com
```

A fresh stack blocks everything, and the client is unregistered, so its first
connections become a host Request. Register `TP_CLIENT_ADDRESS` to apply rules
to it.

## Several stacks

Each stack on a host needs its own `COMPOSE_PROJECT_NAME`, `TP_BROWSER_PORT`,
`TP_ORIGIN`, and subnets (`TP_UPSTREAM_SUBNET`, `TP_CLIENTS_SUBNET`, and the
addresses inside them). Pass that stack's file with `--env-file`.

## Browser on another machine

`http-local-test` accepts only a loopback origin. For a browser elsewhere, use
`http-lan-test` with the host's private IPv4 address as `TP_ORIGIN` and bind
`0.0.0.0`, as `.env.example` shows.

## Stop

```sh
nerdctl compose --env-file .env down -v
```

This removes the stack's containers, networks, and volumes, including its
database. The shared `tp-dev-bun-cache` volume stays. Omit `-v` to keep the
stack's data.

## How it differs from a deployment

- One container runs all gateway processes, started in unit order by
  `gateway.sh` with each unit's account and capabilities, except
  `suricata-rotate`, which keeps the gateway container's capabilities so it can
  restart Suricata.
- `systemctl` in the image is a stand-in that reports process status for the
  service status display and lets `suricata-rotate` control Suricata.
- The gateway container has a writable `/proc/sys`
  (`security_opt: systempaths=unconfined`) so the forward guard can switch
  forwarding, as it does on a host.
- `gateway.sh` adds the NAT a deployment provides itself: clients' DNS
  redirected to the gate, and masquerade for traffic leaving upstream.
- Unprivileged containers cannot raise `net.core.rmem_max`, so the stack
  requests a small DNS receive buffer (`TP_DNS_RECEIVE_BUFFER_BYTES`).
