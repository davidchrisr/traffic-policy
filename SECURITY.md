# Security policy

## Supported versions

Traffic Policy is pre-1.0. Security fixes go to the latest release on `main`.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub. Open the repository's Security
tab and choose Report a vulnerability. Do not open a public issue for a
suspected vulnerability.

Include the affected component, the version or commit, any relevant
configuration and the steps to reproduce the problem.

## Security-sensitive components

- The enforcement service runs as root with `CAP_NET_ADMIN`. It accepts commands
  on a Unix socket restricted to the `traffic-policy` group.
- The DNS gate decides which DNS-derived addresses an instance may reach.
- Suricata parses untrusted client traffic. It runs as its own unprivileged
  account with only `CAP_NET_RAW`.
- The controller handles Admin authentication, sessions and mutation-origin
  checks.
- The controller and gateway authenticate each other with mutual TLS.
- The boot forwarding guard keeps routed traffic blocked until the enforcement
  service installs a policy.

Weaknesses in an operator's own router, network or certificate setup are out of
scope unless the documented setup causes them.
