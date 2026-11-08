# Setup

Traffic Policy requires a Linux gateway with routed client traffic and a
controller reachable by the gateway. They may run on separate hosts. Native
enforcement requires Linux, nftables and privileged networking; ordinary source
checks do not.

This guide describes a source installation using the supplied systemd units. It
does not provision VM networks, client routes, a certificate authority or
Suricata's capture configuration automatically.

## Prepare the hosts

Use Linux x64 with glibc, systemd and the Bun version pinned in
`packaging/linux/runtime.json`. The gateway needs `nft`, `conntrack`, `ip`,
Suricata, `flock` and `systemd-notify` at the paths expected by the units and
native integration. TLS tests and certificate provisioning require OpenSSL. On
Debian, install `nftables`, `conntrack`, `iproute2`, `suricata`, `util-linux`
and `openssl`. The `suricata` package enables its own `suricata.service`; run
`systemctl disable --now suricata`, because `tp-suricata.service` replaces it.

Create a system service account and group named `traffic-policy` on each host.
On the gateway, also create a separate system account and group named
`traffic-policy-suricata` for Suricata. Do not add it to the `traffic-policy`
group; Suricata parses untrusted traffic and must not reach the enforcement
service socket. Install Bun at `/opt/traffic-policy/runtime/bin/bun`. Keep the
application and configuration owned by the administrator, with read access for
that account. The enforcement runs as root with restricted capabilities and
exposes its authorized Unix socket operations to the service account.

Create `/etc/traffic-policy/` and role-specific state directories:

- Controller: `/var/lib/traffic-policy/controller`, owned by `traffic-policy`,
  mode `0700`.
- Gateway: `/var/lib/traffic-policy/gateway`, owned by `traffic-policy`, mode
  `0750`.
- Enforcement service: `/var/lib/traffic-policy/enforcement`, owned by root and
  group `traffic-policy`, mode `0750`.
- Suricata: `/var/lib/traffic-policy/suricata`, owned by
  `traffic-policy-suricata` and group `traffic-policy`, mode `2770`. The setgid
  bit gives Suricata's output the `traffic-policy` group, so the gateway can
  read it.

Provision these directories before initializing controller state or configuring
capture.

## Configure identities and networking

Copy the JSON templates from `examples/` into `/etc/traffic-policy/`:
`controller.json` on the controller, and `gateway.json` and `enforcement.json`
on the gateway. [Initialize Admin](#initialize-admin) covers `settings.json`.
The `192.0.2.0/24` management addresses, `198.51.100.0/24` client-side addresses
and `.example.test` names are documentation placeholders. Replace addresses,
hostnames and interface names for your network.

- Give the controller and gateway stable management addresses. Configure DNS or
  host resolution for the names in their machine API URLs.
- Issue separate controller and gateway certificates from a trusted private CA.
  Both certificates must support server and client authentication and have SANs
  matching their machine API hostnames. Use Common Names
  `traffic-policy-controller` and `traffic-policy-gateway`, matching the peer
  identity fields in the templates. Do not share private keys between hosts.
- Place the CA certificate, role certificate and role key at the template's TLS
  paths. Grant the service account access to its own key only. Trust the
  controller certificate's CA in browsers and include the browser hostname in
  its SANs. Use browser-compatible RSA or ECDSA keys.
- Replace `enforcement.json`'s `groupId` with `id -g traffic-policy` on the
  gateway. Its `upstreamInterfaces` must name every interface facing upstream
  networks, such as WAN links and tunnels: traffic from addresses no instance
  covers is dropped everywhere, drops arriving on these interfaces are only
  recorded, and drops arriving on any other interface become host Requests for
  registration. Add new upstream links here too; an unlisted one turns internet
  scans into host Requests. Set `controllerAddresses` to the controller's
  addresses; policy never filters the machine link with them, so the controller
  can always repair a policy. Other connections with the controller, such as SSH
  from it, need rules like any other host's. Its `dnsPort`, `machinePort`,
  `controllerPort` (the port of `gateway.json`'s `controllerUrl`), and
  `upstreamDns` must match `gateway.json`; the gateway refuses to start
  otherwise.
- Generate a unique gateway UUID for `gatewayId`. The example UUID is a
  placeholder, not a machine credential.
- Set `upstreamDns` to a resolver reachable from the gateway. Set
  `dnsListenAddresses` to gateway addresses on the managed client networks, and
  configure managed clients or router forwarding to use that DNS listener. The
  example uses port 5353; forwarding ordinary port-53 DNS to that listener is a
  separate router configuration step. Managed clients can always reach this port
  on the gateway. DHCP and DHCPv6, ICMPv6 neighbour discovery, router
  solicitations and MLD, and the gateway's lookups to `upstreamDns` always pass,
  so the gateway can serve leases to hosts before they are registered. Policy
  governs every other connection between a managed client and the gateway
  itself, including the global block, and the gateway drops connections started
  by addresses outside every instance. There is no anti-lockout bypass: without
  the instances and Allow rules that [Start and verify](#start-and-verify) adds
  before the gateway starts, the console is the recovery path.
- Configure client routing through the gateway and any required upstream NAT.
  Let `tp-forward-guard.service` enable IPv4 and IPv6 forwarding after
  protection is installed. Remove independent forwarding-enable settings from
  other boot services or sysctl files before commissioning. Review
  `packaging/linux/90-traffic-policy.conf` and install it in `/etc/sysctl.d/`;
  install `traffic-policy-modules.conf` in `/etc/modules-load.d/`. Apply both
  with `systemctl restart systemd-modules-load systemd-sysctl`. Keep management
  access independent of the managed client path.
- Each UDP DNS listener requests `dnsReceiveBufferBytes` (default 8 MiB) in
  `gateway.json`; the packaged `net.core.rmem_max` permits the default. Raise
  both together for higher DNS rates. A host that caps the buffer lower, such as
  an unprivileged container, still runs and reports the `dns_receive_buffer`
  condition with the size it received; lower the setting there to clear it.

Machine ports are 9443 on the gateway and 9445 on the controller. Permit them
between those hosts. The browser uses 9444. Bind addresses must exist on the
corresponding host. Keep the default HTTPS browser transport for deployment.

For capture, copy the distribution's `/etc/suricata/suricata.yaml` to
`/etc/traffic-policy/suricata.yaml`, readable by `traffic-policy-suricata`, and
set `HOME_NET` to the managed client networks. Keep its `eve-log` output named
`eve.json` with the `dns`, `http`, `tls` and `alert` types, which are the events
the gateway reads; the unit's `-l` option places the output in the Suricata
directory. Create `/etc/traffic-policy/suricata.env` containing
`TP_SURICATA_INTERFACE=<capture-interface>`, an interface carrying managed
client traffic. The gateway requires `suricataFile`; Suricata names do not
authorize traffic. Suricata captures before packets are filtered, so it also
names the lookups of hosts no instance covers; the names join the host Request
their dropped traffic raised.

## Build and install the application

Place a source checkout at `/opt/traffic-policy/app` on each role's host, or
build in an isolated Linux environment and transfer the matching source,
installed dependencies and outputs. A bare copy of `dist/` is not a complete
controller installation. This source installation retains `node_modules`
alongside the bundled executables.

From the checkout, run:

```sh
bun install --frozen-lockfile
TP_PUBLIC_ORIGIN=https://controller.example.test:9444 bun run build
cp dist/*.mjs /opt/traffic-policy/app/
cp -R apps/controller/build /opt/traffic-policy/app/controller
```

Replace the example origin with the exact controller `publicOrigin` before
building. Keep the application's `node_modules` and the third-party notices in
`apps/controller/build/LICENSES` and `docs/THIRD_PARTY.md`. The service account
needs read access to the installed source and outputs, not permission to modify
them.

## Initialize Admin

Copy `examples/settings.json` to `/etc/traffic-policy/settings.json` and adjust
the storage budgets. Hostname and domain rules without permitted destination
networks reach only public unicast addresses; private, loopback and other
reserved ranges are always excluded. List in `localNetworks` any additional
ranges, such as public addresses used inside your network, that those rules must
not reach. The template leaves the list empty.

Create a protected `/etc/traffic-policy/admin-password` file containing the
chosen password, accessible only to root and the `traffic-policy` group. There
is no default password.

Run on the controller as its service account:

```sh
runuser -u traffic-policy -- /opt/traffic-policy/runtime/bin/bun --no-install \
  /opt/traffic-policy/app/setup-admin.mjs \
  --database /var/lib/traffic-policy/controller/controller.sqlite3 \
  --password-file /etc/traffic-policy/admin-password \
  --settings-file /etc/traffic-policy/settings.json \
  --initialize
```

Remove the provisioning password file after successful setup. Running this tool
again changes the Admin password and revokes sessions. Back up existing state
before modifying it. Fresh policy begins with a global block rule and no
instances, so once the gateway enforces it, every connection an address other
than the controller starts is dropped until its network is registered.

## Start and verify

Install the role's units from `packaging/linux/` into `/etc/systemd/system/`:

- Controller: `tp-controller.service` and `tp-controller-machine.service`.
- Gateway: `tp-forward-guard.service`, `tp-enforcement.service`,
  `tp-gateway.service`, `tp-suricata.service` and `tp-suricata-rotate.service`.

On the gateway, also install `packaging/linux/forward-guard.nft` as
`/etc/traffic-policy/forward-guard.nft`. Enable `tp-forward-guard.service` for
boot. Its bundled startup command first disables routing, then enables
forwarding only after preserving an existing managed policy or successfully
installing the guard. A failed guard installation leaves forwarding disabled
under the commissioning configuration above. The guard drops forwarded traffic
until the enforcement service installs a policy; management access to the
gateway itself is unaffected. The guard loads after `nftables.service`, so a
host ruleset beginning with `flush ruleset` cannot remove it at boot. A later
whole-ruleset flush, such as reloading or stopping `nftables.service`, removes
the guard and the enforced policy. The enforcement service checks for its table
every five seconds and immediately after a rejected DNS update, then reinstalls
the policy with its live DNS permissions; forwarding is unrestricted until then.
When removing Traffic Policy, stop its services before deleting the
`traffic_policy` and `traffic_policy_guard` nftables tables.

Reload systemd after installation. On the controller, start
`tp-controller.service`; it also starts `tp-controller-machine.service`, the
gateway link that receives observations and delivers policy. Before starting the
gateway, sign in at the configured browser origin, register the management
network and the client networks as instances, and add Allow rules for SSH to the
gateway (peer Gateway, TCP 22) and for the path to the controller dashboard. On
the gateway, start `tp-gateway.service`; its dependencies start the enforcement
service, Suricata and log rotation. After verification, enable boot startup with
`systemctl enable tp-controller.service tp-controller-machine.service` on the
controller and `systemctl enable tp-gateway.service` on the gateway; the gateway
unit's dependencies bring up the rest. The controller sends its desired policy
to the gateway over mTLS; no hand-authored enforcement checkpoint is needed.

The two controller units run independently: restarting or stopping
`tp-controller.service` leaves the gateway link running, and a failed gateway
link leaves the dashboard up and shows the link process under Gateway in its
status. Each unit has its own `MemoryMax=768M`, so the controller may use up to
1.5 GiB.

Check `systemctl status` and `journalctl` for each role. Sign in at the
configured browser origin, check gateway and service status, then add a test
instance and verify a scoped allow/block rule from that client. Confirm DNS,
capture and history delivery before commissioning more clients.

After uncertain or interrupted firewall updates, the enforcement service retries
a full reinstall with one-to-30-second backoff. For persistent failure, check
the enforcement service logs with `journalctl -u tp-enforcement` and submit a
corrected policy. Newer revisions supersede stuck updates. On startup, an
un-restorable pending policy falls back to the last applied policy; if both
fail, the enforcement service keeps retrying them, remains available for repair,
and health reports the failure.

## Upgrades

The project is pre-deployment. Stored formats can change without migrations.
When the controller's stored format changes, recreate the test state or repair
it manually before starting the new build. Gateway recovery does not convert the
controller database.

`dnsReleaseMode` is required in settings and saved policies; a missing mode is
rejected. The example uses `before-approval`; `require-allow` retains DNS
approval before answer release.

Upgrade the gateway while the controller is running and can reach it. Install
the new outputs the same way as above, then restart `tp-enforcement` followed by
`tp-gateway`, or both `tp-controller` and `tp-controller-machine` on the
controller.

If the controller's desired policy is compatible but the enforcement service
cannot restore its saved policy, it reports `enforcement_restore_failed`. The
controller resends its desired policy and enforcement resumes once it applies.
The gateway likewise sets aside a pending application it cannot parse as
`/var/lib/traffic-policy/gateway/policy-apply.json.unreadable-<UTC time>`,
records a recovered `gateway_intent_unreadable` condition, and waits for the
controller instead of finishing that application itself. Each set-aside file is
kept for inspection; remove it once it is no longer needed. Until the controller
delivers:

- After an enforcement service restart, the previously installed firewall table
  keeps enforcing, but new DNS lookups for hostname rules fail.
- After a gateway reboot, the boot guard drops all forwarded traffic.

Both last until the controller can deliver the policy, so do not upgrade the
gateway while the controller is down. Connections that DNS Allow rules already
admitted stay open across an enforcement service restart.

[Architecture](ARCHITECTURE.md) documents restart and overload behavior.
