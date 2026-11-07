# Development stack

A controller, a gateway, and one routed client, built from the checkout with
`nerdctl compose`, rootless included. Each stack has its own runtime data and
networks; the dependency cache is shared. It runs on x86-64 hosts, matching the
packaged Bun runtime.

Entry scripts replace systemd here, so the stack does not exercise installed
units' ordering or sandboxing. Use [Setup](../../docs/SETUP.md) on a host or VM
to verify those.

## Configure a stack

From this directory, copy `.env.example` to an ignored `.env.<name>` file. The
examples use `.env.development`; substitute the filename for your stack. This
command creates a new file without overwriting an existing one:

```sh
stack_env=.env.development
(set -C; cat .env.example >"$stack_env")
```

Set `COMPOSE_PROJECT_NAME`, `TP_BROWSER_PORT`, `TP_UPSTREAM_SUBNET`, and
`TP_CLIENTS_SUBNET` in that file. Independent stacks need distinct project names
and browser ports, and nonoverlapping private subnets that also avoid the host's
routes. The example allocations must be adjusted for the host.

Set `TP_CONTROLLER_ADDRESS` within the upstream subnet and `TP_CLIENT_ADDRESS`
within the clients subnet. Set `TP_ORIGIN` to match the browser address and
port. Use this env file for every operation on the stack; in another shell, set
`stack_env` to the same filename.

## Start

Once per host, create the dependency cache that every stack shares:

```sh
nerdctl volume create tp-dev-bun-cache
```

Write Admin's password to a file outside the repository, readable only by you.
Set `TP_ADMIN_PASSWORD_FILE` in your env file to that file, and run this ordered
sequence from this directory to start or rebuild your stack:

```sh
nerdctl compose --env-file "$stack_env" down &&
  nerdctl compose --env-file "$stack_env" build &&
  nerdctl compose --env-file "$stack_env" run --rm -i=false build &&
  nerdctl compose --env-file "$stack_env" run --rm -i=false init &&
  nerdctl compose --env-file "$stack_env" up -d controller gateway client
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
nerdctl compose --env-file "$stack_env" exec client curl -sI https://example.com
nerdctl compose --env-file "$stack_env" exec client dig example.com
```

A fresh stack blocks everything, and the client is unregistered, so its first
connections become a host Request. Register `TP_CLIENT_ADDRESS` to apply rules
to it.

## Browser on another machine

`http-local-test` accepts only a loopback origin. For a browser elsewhere, use
`http-lan-test` with the host's private IPv4 address as `TP_ORIGIN` and bind
`0.0.0.0`, as `.env.example` shows.

## Stop

```sh
nerdctl compose --env-file "$stack_env" down
```

This removes the stack's containers and networks, keeping its volumes and env
file. Adding `-v` also removes its volumes, including the database. The external
`tp-dev-bun-cache` volume stays.

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
