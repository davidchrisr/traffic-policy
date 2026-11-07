# Native Traffic Policy API

The authoritative policy, observation, enforcement, dashboard, and service
schemas are in `packages/contracts/src/`. Browser mutation envelopes are
validated in `apps/controller/src/lib/server/services.ts`.

## Browser API

The dashboard and `/api/` share the controller origin. Protected endpoints
require the Admin session. Mutations require the configured Origin. Session
cookies are HttpOnly and SameSite Strict; Secure is enabled with browser HTTPS.
`POST /api/auth/login` takes `{ "password": string, "remember"?: boolean }`.
Without `remember`, the cookie ends with the browser and the session expires
after 12 hours. With it, the session lasts 7 days, renews to 7 days when used
with less than 5 days left, and ends 30 days after sign-in. Changing the
password revokes every session. Explicit HTTP test modes omit Secure and
restrict origins to loopback or private IPv4 addresses. Deployment uses HTTPS.

| Endpoint                               | Methods     | Behavior                                   |
| -------------------------------------- | ----------- | ------------------------------------------ |
| `/api/auth/login`                      | POST        | Verify password and create a session       |
| `/api/auth/session`                    | GET         | Current authenticated identity             |
| `/api/auth/logout`                     | POST        | Revoke the current session                 |
| `/api/status`                          | GET         | Desired/applied revision, errors, health   |
| `/api/services`                        | GET         | Read-only controller/gateway service state |
| `/api/policy`                          | GET         | Desired policy                             |
| `/api/policy/reapply`                  | POST        | Advance and redeliver desired policy       |
| `/api/rules`                           | GET, POST   | List or create a rule                      |
| `/api/rules/:id`                       | PUT, DELETE | Edit or remove a rule                      |
| `/api/rules/:id/renew`                 | POST        | Explicit renewed duration                  |
| `/api/instances`                       | GET, PUT    | List or upsert registered instances        |
| `/api/instances/:id`                   | DELETE      | Remove an instance and its scoped rules    |
| `/api/settings`                        | GET, PUT    | Settings and resource usage                |
| `/api/names/lookup`                    | POST        | PTR query for a registered address         |
| `/api/monitor`                         | GET         | Selection/period-scoped service metrics    |
| `/api/requests`                        | GET         | Sampled catch-all denials and review state |
| `/api/requests/:id/names`              | GET         | Names seen for a request's address         |
| `/api/requests/hosts/:address/dismiss` | POST        | Stop a host Request asking for review      |
| `/api/history`                         | GET         | Retained audit, observations, health       |

Rules, instances, and settings mutations require `expectedRevision`. A stale
revision returns 409. Rule input excludes server-owned identity and
creation/modification times. Unknown fields and invalid combinations return 400
with field issues. A rule's `ports` is `null` for any port, or up to 64
`{ start, end }` ranges within 1–65535, sorted, each start at most its end, and
no two overlapping or adjacent. Ports require TCP, UDP, or any transport; with
any transport they match TCP and UDP only. Accepted mutations return 202 and
remain pending until the gateway confirms the new policy hash. Responses include
the new revision except for instance removal, which returns
`{ "accepted": true }`.

Removing an instance also removes its scoped rules and pending request rows;
retained history remains available.

Settings reads include `catchAll`, the outgoing and incoming action of the
permanent catch-all, each `null` when no such rule covers the direction. A
settings write requires `catchAll` with both actions. Rule writes and deletes
that would create, change, or remove that catch-all return 400
`catch_all_in_settings`.

Settings hold one history limit per kind: `trafficHistoryBytes`,
`dnsHistoryBytes`, `blockedHistoryBytes`, and `otherHistoryBytes`. Settings
reads report `historyUsedBytes` as an object with `traffic`, `dns`, `blocked`,
and `other` decimal strings. Rule reads include `blocked` for Block rules:
`packets` counted in the last 24 hours across instances and `samplesSince`, the
oldest retained sample or `null`; it is `null` for Allow rules.

Renewal requires `durationSeconds`, counted from now; expiry never silently
becomes permanent. Requests reads include the current `rules` so the editor can
warn about rules another rule overrides. Each connection or DNS request has
`kind`, `id`, `instanceId`, `attempts`, `firstAt`, `lastAt`, `ruleId`, `state`,
and `clients`, its eight most recent distinct client `address` and `at` values,
newest first; the newest decides its state. `kind: "connection"` adds
`direction`, `peerIp`, `protocol`, and nullable `port`. `kind: "dns"` adds
`question` and `queryType`, the latest denied query type for the name; its
`ruleId` is the denying Block, or null when no Block was attributed. DNS rows
have no destination or service fields. `kind: "host"` is a host no instance
covers whose drops arrived on a client interface, with `id` and `clientIp` (its
address), `attempts`, `firstAt`, `lastAt`, `destinations` (up to eight recent
`address` and `at`), `names` (up to eight recent `name` and `at` from Suricata
DNS queries), and `state` `needs-review` or `dismissed`; registering an address
that covers it removes it. A Suricata query alone raises no host Request; it
adds its name to one a drop raised. Dismissing a host Request removes it from
the review count and audits the dismissal; later drops still update it. It
returns 404 `request_not_found` when no host Request waits for review at the
address. States are `needs-review`, `applying`, `failed`, and `resolved`.
`requests` lists the newest 500 by `lastAt`; an optional `host` address adds the
host Request at that address when it is older, and an invalid one returns 400.
`retention` reports `pending`, the combined `limit` of the connection, DNS, and
host pools, `discarded` and `lastDiscardedAt` for scopes removed at a pool
limit, and `dnsOmitted` and `lastDnsOmittedAt` for denied lookups the gateway
counted without recording each one. Requests and Monitor reads include the
settings' `localNetworks`, so the dashboard evaluates hostname and domain rules
only where they would admit an address as a DNS answer. A request's names list
up to 20 hostnames, newest first, from DNS answers its instance received that
contained the address (`dns`) and TLS or HTTP names on its connections to the
address (`tls`, `http`), each with `lastSeenAt`; an unknown request returns 404.
Every dashboard `status` includes `needsReview`, the number of requests waiting
for review, and `gateway`: the gateway's own `addresses` and the parameters of
its fixed accepts (DNS gate `dnsPort`, machine link `machinePort`,
`controllerPort`, and `controllerAddresses`, and `upstreamDns`) as it last
reported them, or null before its first report. A name lookup requires
`instanceId` and one of its registered addresses. A disabled resolver
returns 409. Lookup results distinguish resolved, not-found, ambiguous, and
unavailable states; retained lookup status also reports expiry.

Monitor filters accept instance, peer IP, domain, hostname, direction, protocol,
service port, and a retained period within 180 days. Totals cover the full
selection; the service list indicates truncation beyond 1,000 entries. Missing
buckets are unmeasured. Transfer totals are decimal strings, not floating-point
JSON. `eventSummary` is null unless the request has an `instanceId` and
`events=recent` or `events=full`. Its `events` groups the newest 5,000 matching
events in the period by type, direction, protocol, port, and the rule recorded
on blocked samples, with a decimal-string count and last time; `eventsLimited`
is set when more events matched. A recent summary reads at most the period's
newest 100,000 events of any instance; when that stops it before the period
start, `scannedFrom` is the oldest time read, otherwise null. A full summary
reads the whole period and returns 409 `event_scan_busy` while another full
summary runs. It returns the newest 100 groups and sets `eventsTruncated` beyond
that. `blockedTotals` lists each Block rule and direction with counted `packets`
and recorded `samples` over the same window, which starts at the minute (within
the last day) or hour containing `from`; more packets than samples means the
rule's destination rows are incomplete. `reviews` lists the scopes of
needs-review requests that match a listed service. `unregistered` reports drops
of connections with no instance on either end in the period: `clientPackets` and
`upstreamPackets` counted by the side they arrived on, over the same counter
buckets as `blockedTotals`, and `drops`, the newest 5,000 sampled drops grouped
by `side`, `clientIp` (the address that started the connection), `peerIp`,
`protocol`, and `port`, newest first. Each group has a `samples` count,
`firstAt`, `lastAt`, `request` (set while the client has a host Request), and
`gateway`, the gateway services its protocol and port match when `peerIp` is a
gateway address, otherwise null. Client-side groups at the gateway's DNS service
list in `names` up to eight names the client looked up from a minute before
`firstAt` to `lastAt`. It returns the newest 50 groups and sets `dropsTruncated`
beyond that; `samplesLimited` is set when more samples matched.

History audit entries include `subjectRule`, the current rule when the subject
is a rule that still exists, otherwise the newest complete rule recorded in the
loaded entries for a deleted rule, and `client`, the address and browser family
of a browser change, `null` for Admin setup. `revisions` holds the `before` and
`after` policy revisions of a policy change, otherwise `null`. `changes` lists
what a policy change did, empty for other entries: each entry names its
`subject` (`rule`, `instance`, or `settings`) and `id`, with `before` and
`after` field values. A created object has only complete `after` values and a
deleted one only complete `before` values; an update keeps the changed fields,
and every service field when any changed. Entries about a deleted rule take
their `subjectLabel` from the newest complete values recorded among the loaded
entries. The snapshot includes `instances` and `rules`.

History accepts a `limit` from 1 to 500, defaulting to 100. The limit applies
separately to audit entries and observations; it is not a paging cursor.

## Machine API

Both listeners require authenticated TLS 1.3 and the configured peer identity.
The gateway serves `GET /v1/status`, `GET /v1/services`, and `PUT /v1/policy`.
The controller accepts `POST /v1/observations`.

Service snapshots use the shared schemas in
`packages/contracts/src/services.ts`. The gateway reports only its gateway,
enforcement service, Suricata and log rotation services; the controller reports
its browser process and its gateway link process. Each report binds the fixed
service identities to its reporting host and includes a check timestamp. Stopped
and failed units remain observations, while unreadable or unreachable sources
are explicitly unavailable. Service state does not imply native policy
confirmation or complete traffic coverage. These endpoints perform no service
mutations and accept no executable or unit-name input.

Policy protocol version is 1. Revisions are canonical uint64 decimal strings. A
receipt binds revision, canonical policy hash, gateway boot identity,
application time, and permission count. Instance `addresses` are host IPs or
networks; a full-length prefix is stored as the host address. A rule's `subject`
is `{ "kind": "global" }`, `{ "kind": "instance", "instanceId" }`, or
`{ "kind": "address", "value" }` with an IP or CIDR inside an instance. A policy
is rejected when an exact address belongs to two instances, an address subject
lies outside every instance or names an instance address, or a rule names an
unknown instance.

Observation batches contain an epoch UUID, sequence string, and at most 4,096
validated records. Gateway DNS batches also retain their one MiB byte ceiling.
The controller acknowledges their exact identity after commit. Delivery is
serialized. Lost acknowledgements can replay the latest batch; a changed latest
identity or older sequence returns 409.

Observation detail strings are limited to 4,096 characters, except
`details.addresses` on `dns` events from `resolver-gate`. That field preserves
all accepted answer values and allows up to 65,278 characters, derived from 256
answers of at most 253 characters separated by a comma and a space.

Observation source, original timestamp, tuple scope, and source record identity
remain explicit. Suricata and PTR observations never authorize traffic. Requests
report rate-limited packet samples and distinguish review, applying, failed, and
resolved states.

## Enforcement service

The Unix socket is restricted to the configured group. Commands are validated
and bounded; policy and DNS mutations execute in order. Operations apply policy,
confirm resolutions, inspect status, read connection snapshots and read kernel
events. Callers cannot choose executables, shell commands, native table names,
or filesystem paths.

Shared schemas cover `prepare`, `apply`, `resolve`, `status`, `collection`,
`configuration`, `connections`, `counters`, and `events`, including their
operation-specific results. `configuration` returns the enforcement service's
`dnsPort`, `machinePort`, `controllerPort`, `controllerAddresses`, and
`upstreamDns`; all but `controllerAddresses` must match the gateway's.
`connections` and `events` also return `gatewayAddresses`, the gateway's own
addresses when read, which no instance owns. `counters` returns Block rule and
unregistered drop counters that are not zero, as table handle, counter name, and
packets, in pages of up to 4,096. A `page` of `null` starts a reading; later
pages pass its `reading` ID and the returned `next` offset, and a page of a
finished or replaced reading returns 409 `counter_reading_expired`. The first
page carries the enforcement service's `boot` and `uncounted`, which explains
drops that could not be read before a policy apply. The enforcement service
client returns a validated result type inferred from the selected schema. A
successful envelope must contain that operation's valid result. Malformed
results return `502 invalid_enforcement_response`; valid enforcement rejection
status, code and message remain unchanged. Status and collection return the last
successfully applied policy and its receipt, with current in-memory counts. Both
bind policy and receipt identity; neither performs kernel rule inspection.
Request IDs, frame limits, UTF-8 decoding and deadlines remain part of the
transport contract.

Connection snapshots include policy revision/hash and captured instance
ownership IDs. Samples spanning policy installation fail explicitly. Lifecycle
records carry the same ownership IDs; `gap` records represent retained
observation-loss markers. Repeating an event cursor repeats its unacknowledged
markers, including when no traffic records exist. Cursor advancement
acknowledges collection.

Commands and responses are newline-delimited JSON frames on persistent Unix
connections. Each frame, including its newline, is at most two MiB. A connection
may carry multiple in-flight commands; responses are correlated by request ID
and may arrive out of order. Duplicate in-flight command IDs, unknown response
IDs, malformed envelopes and incomplete final frames close the connection.
Operation-specific result validation still applies to each response.

DNS names, in questions, answers, rules, and HTTP or TLS hostnames, are
lowercase ASCII labels of 1 to 63 letters, digits, hyphens, and underscores, not
starting or ending with a hyphen, at most 253 characters in total. An
internationalized name is converted to its ASCII form (IDNA) first. The gateway
answers REFUSED to a question with any other name and records no request for it.
The gateway decides admission locally against the last policy the enforcement
service confirmed. `resolve` checks DNS admission against the enforcement
service's applied policy; when that policy denies the question, it returns
`allowed: false`, nullable `ruleId`, `catchAll`, `instanceId`, `revision`, and
`policyHash` from that policy instead of a receipt. `resolve` uses the DNS lane.
Resolver denial events have type `dns`, source `resolver-gate`, the question and
instance, and details `outcome: "policy-denied"`, `queryType`, `clientIp`,
`catchall`, `appliedRevision`, and `policyHash`. Packet destination and service
fields remain null. Condition events (type `condition`, source `gateway`) carry
details `code`, `message`, and `recovered`, and optionally `occurrences`, a
positive integer the controller adds to the condition's count in place of 1. A
momentary condition sends `occurrences` with `recovered: true` in one event: it
is counted and recovered at once. `dns_denials_omitted` reports this way the
denied lookups the gateway's recording limits left out; a name is recorded when
a later lookup fits the limits. `blocked` events from Block rule traces carry
`details.clientIp`, the managed end. An unregistered drop's `blocked` event has
no instance, direction, or rule, and carries `details.clientIp` (the address
that started the connection) and `details.unregistered`, `upstream` when the
packet arrived on one of the enforcement service's upstream interfaces,
otherwise `client`. A `blocked_count` has an instance, direction, and rule, or
none of them and `details.unregistered`. Suricata DNS queries from a client no
instance covers are sent with no instance and `details.unregistered: "client"`.

The client uses separate active DNS and control connections. Request admission
allows 4,096 DNS and 32 control operations. Pending request payloads and partial
response frames share a 64 MiB client allocation. The server accounts each
partial/admitted input frame against its 64 MiB allocation and retains admitted
work until dispatch and its response write settle, even after client disconnect.
Queued response writes have a separate 64 MiB aggregate bound.

Each request retains its total deadline, normally ten seconds, including
connection establishment. A timeout retires that connection from new requests
while healthy peers finish. Expired request IDs remain reserved until their late
reply arrives or the draining connection closes, bounded by request/memory
admission. New requests can establish a fresh connection; failed commands are
never replayed automatically. Idle client sockets are unreferenced, and gateway
shutdown explicitly closes its enforcement connections after producers drain.
Enforcement service shutdown stops admission, drains admitted work and ends
persistent connections. Deploy matching gateway and enforcement service
artifacts together.

The enforcement service owns one nftables table. Configured-policy checkpoints
contain only policy and receipt. Learned DNS leases and permissions are
memory-only; startup installs configured rules with empty DNS sets. DNS
acknowledgements follow successful atomic nft execution. A definite atomic
rejection fails only its DNS batch or policy application and leaves the previous
state enforced and available. Uncertain completion blocks acknowledgements while
a full reinstall of confirmed state retries with backoff from one to 30 seconds.
Only successful installation clears unavailability. Newer configured revisions
can supersede a failed pending revision; equal-revision hash conflicts and older
revisions remain errors. Startup tries the newest saved policy, then the last
applied policy. If restoration fails, status and collection report
`enforcement_restore_failed`, the saved policies retry with the same backoff,
and policy commands remain available. Lookup history remains independently
batched and durable; it never restores enforcement permissions.

Learned mappings are keyed by the client's scope path, requested hostname and
returned address. Their rule contributions remain separate, including
overlapping global and scoped rules. An address in the other family than the
lookup is held on each of the client instance's paths in that family. A unique
grant, keyed by holding path, rule and address, may be supported by several
mappings and uses their latest live deadline. The state ledger tracks exact
serialized bytes and permission allocation incrementally. A batch keeps changes
private, rolls back rejected lookups individually, and publishes only after its
required firewall update succeeds. Status continues to read confirmed state
while a batch is pending. Policy changes re-evaluate still-valid mappings
against the new policy; changing grace does not revive expired mappings.
