# Native Traffic Policy architecture

Traffic Policy uses a Debian/nftables backend, a Bun gateway and a SvelteKit
controller. [Setup](SETUP.md) describes deployment.

## Runtime boundaries

The controller is a SvelteKit application with server loaders, actions, and API
handlers. Shared server modules own validation, policy mutation, persistence,
authentication, and delivery.

The controller runs as two processes that share only the SQLite database. The
browser process (`tp-controller.service`, `controller-runtime.mjs`) serves the
dashboard and API. The gateway link (`tp-controller-machine.service`,
`controller-machine.mjs`) accepts observation batches on the machine port and
delivers the desired policy every two seconds. Dashboard reads and writes
therefore never delay ingest or delivery on the same thread; the processes still
share CPU, disk, and the database's single writer, so a long write in one waits
up to the two-second busy timeout in the other. Every read-then-write runs in
one `BEGIN IMMEDIATE` transaction: mutations, confirmations, delivery failures,
request pruning, and retention pruning before ingest. A confirmation or failure
for an older revision is recorded without resolving or failing the requests of a
newer desired revision. Only `setup-admin --initialize` creates the schema, in
one transaction; the running processes open initialized storage.

Retention trims in slices of at most 100 milliseconds, each one transaction that
deletes up to 512 rows per statement, so neither process holds the writer long
enough for the other to time out. A save runs one slice, and ingest trims one
chunk per step, enough for its own batch; the gateway link checks retention
every two seconds and finishes a larger trim, such as after a save shrinks an
allocation, in further slices with equal pauses between them. History can exceed
its allocation until that trim finishes.

`DashboardReads` owns dashboard SQL queries and maps storage rows to the shared
Zod contracts exported through `@traffic-policy/contracts/dashboard`.
ControllerStore retains the SQLite connection, credentials, mutations, and
transaction boundaries. Loaders and HTTP handlers consume the same query
results. Browser responses use camelCase fields and nullable unknown ports; the
database uses a sentinel for unknown ports. Invalid stored dashboard data is a
server failure, not an empty response. Aggregated counters remain decimal
strings and can exceed an individual Suricata event's uint64 range.

Dashboard pages use one RefreshRunner per independent read channel for
deadlines, cancellation, response ordering, and disposal. Rules and Requests
poll every five seconds; Settings polls status without replacing form drafts;
History refreshes manually. A full Settings refresh cancels stale status work
and requires resource and instance revisions to match.

The plain TypeScript MonitorView owns typed selection, period, query identity,
and matching measurement snapshots. Service keys are opaque display identities;
queries use explicit scope fields. A scope remains valid when its roster is
empty. The Svelte page subscribes to snapshots and retains presentation state
such as search, expansion, and rule-editor drafts.

Monitor refreshes use one batch at a time with a ten-second deadline. Scope,
period and explicit refresh changes cancel the previous batch; navigation
cancels in-flight work. Selection and roster requests share a cancellation
signal, and a failure cancels remaining work. API snapshots use `$state.raw`.
Selecting the same scope preserves an in-flight load; From now changes coalesce
into one refresh. Explicit Settings resource refreshes supersede status polling.

One shared ECharts component owns initialization, resizing, updates, and
disposal. It resolves CSS tokens to concrete canvas colors. Initialization,
update, or resize failure disposes the chart and reports it unavailable, without
replacement measurements or an alternate renderer. Traffic formatting uses
BigInt truncation while raw byte counters remain unchanged. Visible relative
times share a clock refreshed every 15 seconds.

Bun 1.4.2 runs development/build tools, test workers, the controller,
unprivileged gateway, privileged enforcement service and log rotation.
Compatible `node:` APIs execute under Bun. The controller can run on the gateway
or on another host. Both placements use the same authenticated machine
contracts.

The gateway API accepts only its configured controller certificate identity. The
observation API accepts only the configured gateway identity. CA validation and
server-name checks remain enabled. Machine listeners require TLS 1.3 and client
certificates.

Machine HTTPS uses the shared TLS transport in
`packages/core/src/machine-server.server.ts`. It passes the real authenticated
TLS socket to HTTP framing on both server and client, preserving certificate
identity access under Bun. The signature-algorithm list includes Ed25519 and
modern ECDSA/RSA schemes. Both directions enforce TLS 1.3 and CA verification;
the handlers additionally verify the configured certificate identity.

The enforcement service acquires a namespace-specific lifetime lock before
touching the firewall or policy journal. Linux `flock` locks an inherited file
description; Bun retains its descriptor until admitted work and recovery have
drained. Failed startup closes acquired resources and releases ownership. The
lock file remains in place so concurrent starters cannot acquire different
inodes. Guard activation and full policy replacement share a separate,
short-lived installation lock. Guard retries cannot add a blocking table after a
policy installation has removed it. Lock acquisition waits asynchronously with a
bounded deadline.

The enforcement service composes a private `PolicyEnforcer`, a schema-checked
file journal, and a fixed native-executable adapter. It retains the
group-restricted Unix socket, validated wire commands and process/event
lifecycle. The owner holds confirmed memory state, pending configured-policy
application and native command failures. Pure state calculations enforce shared
bounds; callers cannot assign snapshots, install candidates directly or bypass
mutation scheduling. Policies and resolutions are parsed once at the socket and
owned without copying; outward policy views share the confirmed policy and are
read-only by contract, and kernel ownership uses a cached read-only instance
projection. Ownership generations follow successful or uncertain kernel
installations independently of durable policy publication.

The enforcement service bounds pending wire commands; the owner serializes
mutations. Diagnostic reads run outside that workflow. The owner uses successful
atomic nft execution as application confirmation and performs no runtime rule
dumps or fingerprint checks. It owns only the `inet traffic_policy` table.
Full-policy installation checks the candidate transaction, writes a policy-only
pending checkpoint, applies atomically, and persists its receipt.
Table-existence queries select the full replacement program and detect an
external flush; they do not inspect installed rules.

The journal reads configured-policy checkpoints by kind, leaving precedence with
the owner. Startup first tries the newest saved policy, then the last applied
policy if the pending policy cannot restore. If neither restores, the
enforcement service keeps its management socket available but reports
`enforcement_restore_failed` and accepts a corrected policy. It retries the
saved policies, newest first, with the recovery backoff. Restore attempts never
rewrite or remove a newer saved policy, so it survives another restart. The boot
guard remains until a native policy transaction succeeds. Owner tests model
native effects independently of journals and exercise command failure, uncertain
completion, publication and durability boundaries.

Collection refreshes every five seconds through a read-only confirmed-state
operation. Status and collection supply last successfully applied policy
ownership/provenance and live memory counts. Neither reads nft rules. The
controller polls health every two seconds without overlapping requests; pending
configured-rule changes are delivered instead. A gateway that reports no
restorable policy, or a receipt for another revision, receives the desired
policy again. The enforcement service protocol uses bounded newline frames,
incremental UTF-8 decoding, a total deadline and explicit premature-close
errors.

Shared enforcement contracts define each command and operation result in
`packages/contracts/src/enforcement.ts`. The enforcement service validates
incoming commands and outgoing payloads with those schemas. The client validates
the correlated reply envelope and operation payload before returning its
inferred type. Complete health and collection payloads bind the receipt
revision/hash to the policy. Missing or malformed successful values fail as
`invalid_enforcement_response`; raw JSON remains inside the transport boundary.
Callers retain application-specific identity and business checks.

Full policy changes use `pending.json` and `applied.json`, containing only
configured policy and receipt. `connection-marks.json` holds the connection mark
of each DNS Allow rule on each scope path. Learned DNS leases, permissions and
DNS work stay in memory. DNS commits perform no checkpoint writes, disk-capacity
scans or kernel readback. Startup replaces the owned table using configured
policy with empty DNS sets. A client retaining a cached address may need a fresh
DNS lookup before its connection is allowed. A boot guard table loads after the
distribution ruleset and drops all forwarded traffic before networking starts.
Its startup command disables routing, then enables IPv4 and IPv6 forwarding only
after a guard is installed or an existing managed table is found. Commissioning
excludes independent forwarding activation; management repair remains available
if guard startup fails. Every full installation removes it in the same
transaction, so forwarding stays blocked until a policy is installed, including
when the enforcement service cannot restore one.

Configured-policy retries and automatic recovery share the enforcement service
mutation lock. DNS admission and full installation share the deduplicated
permission count. While the enforcement service keeps running, an accepted limit
reduction preserves existing live grants without extending their deadlines or
permitting growth. Restart discards those grants and uses the configured limit
with an empty allocation. Supporting leases and expanded permissions have a
fixed memory record/byte bound. A definite atomic DNS-update rejection leaves
memory unchanged and fails only that batch. A definite rejection of a full
installation withdraws its pending checkpoint and keeps the previous policy
enforced and available. Uncertain completion, including a failed checkpoint
write after the kernel accepted a full installation, blocks further DNS
acknowledgements and reports enforcement unavailable. The enforcement service
retries a full installation of its configured policy and confirmed live leases
after one second, doubling the delay on failure up to 30 seconds. It never
publishes the failed batch or extends lease deadlines. Success clears the
condition; a successful manual policy application also cancels recovery.
Shutdown cancels the timer and drains admitted work. Polling does not perform
kernel drift detection. The enforcement service only checks every five seconds,
and after a definite DNS-update rejection, that its table exists. A missing
table, such as after an external ruleset flush, reports enforcement unavailable
and starts the same full reinstallation. Expired eligible DNS answers fail
confirmation even when deadline filtering produces no native grants. Incoming
enforcement commands preserve split UTF-8 characters and bound received bytes
before decoding.

Gateway revision application holds the collector mutation lock through capacity
preflight, enforcement preparation, native application and allocation
completion. `policy-apply.json` records native-started and native-committed
phases. Failures before preparation leave enforcement and collector retention
unchanged. After a native request starts, recovery retains that revision until
completion or a newer revision supersedes it. Equal revisions with different
hashes and older revisions are rejected. An identical revision checks confirmed
policy identity and returns its receipt without reinstallation or kernel
inspection. Collector trimming happens after native confirmation. External
filesystem failures can leave a revision pending until recovery completes; the
gateway does not acknowledge it early. A `policy-apply.json` that is not valid
JSON or does not match the current format, such as after a release changes it,
is renamed with an `.unreadable-<UTC time>` suffix and recorded once as a
recovered `gateway_intent_unreadable` condition. The gateway then has no pending
application: enforcement keeps its own journal, the next status read restores
the confirmed policy, quotas and collector allocation, and the controller
resends when enforcement's receipt differs from its desired policy. This
requires compatible controller state; it does not migrate the controller
database. Stored-format changes before deployment can require manually repairing
or recreating test state. Other read failures still fail the request.

`GatewayPolicy` owns application recovery, enforcement-confirmed policy,
disk-budget transitions and collector-allocation synchronization. Bootstrap
validates enforcement collection state and loads confirmed limits before buffer
construction and reservation recovery. Explicit enforcement states for initial
setup or incomplete policy application permit startup so the management API can
receive a policy. Startup then uses the last enforcement-confirmed collector and
disk limits from `confirmed-limits.json`, or configuration defaults before any
confirmation, so an outage cannot shrink retained observations. No instances are
enrolled until an enforcement-confirmed policy is available, and application
failure remains visible through health reads. Malformed responses and transport
failures stop bootstrap.

Application, recovery and adoption of observed policy share one mutation queue.
Enforcement service health and collection reads run outside that queue and
return their own validated results. Adoption rechecks revision eligibility after
earlier work finishes; older responses cannot change shared policy or
allocations. Policy and receipt identity must match, equal-revision conflicts
fail explicitly, and health/collection validation flags remain distinct. Lock
acquisition runs from the policy owner into the collector, with no callbacks
into queued owner methods.

A validated native receipt advances the enforcement-confirmed policy and the
same shared disk-budget object's limit for both increases and decreases. DNS
enrollment and newly normalized EVE jobs use that policy; an EVE job takes one
detached snapshot and retains its normalized identities across retries. Native
confirmation remains distinct from completed gateway application. Collector
synchronization and durable intent removal must finish before application
acknowledgement. A later failure retains the pending obligation and confirmed
quota; required recovery failures keep gateway health explicitly unavailable.

## Service monitoring and startup

Service monitoring uses bounded, unprivileged `systemctl show` reads for a fixed
unit catalog. The gateway machine listener provides `/v1/services` without
querying the enforcement service, while the authenticated controller combines
that report with its own service state. Host-scoped identities are validated
through shared contracts. In-flight reads coalesce; failed sources remain
unavailable rather than being replaced with cached observations. Gateway host
state cannot be read through this endpoint when the gateway process itself is
unreachable.

Starting `tp-gateway.service` requires its enforcement service and also starts
Suricata and log rotation. Suricata failure remains an observable capture
failure without blocking enforcement startup. The dependency graph provides
startup ordering and activation; monitoring adds no service-control endpoint or
privileged management process.

## Rule semantics

Instances have stable UUIDs and addresses that are host IPs or networks. An
instance can represent a container, VM, physical client, or a whole subnet such
as a bridge for dynamically created instances; enforcement follows routed
traffic, not desktop processes. Instance-wide permissions and global defaults
are ordinary broad rules. Their grouping in the dashboard does not change
precedence. Network commissioning and DHCP are separate from application policy.

A rule's subject is every instance, one instance, or an address range (an IP or
CIDR) inside an instance. Instance addresses and address subjects form a tree:
CIDRs either nest or are disjoint, an exact network belongs to one instance, and
an address subject must lie inside an instance without naming one of its exact
addresses. An address receives the rules of every range that contains it, so a
nested instance or address subject adds rules to its parents' instead of
replacing them. A host's most specific instance names it in observations and
Requests. Registering an address as an instance of its own moves the rules
written for exactly that address to the instance, which keeps the host's
effective policy; adding it to an instance with other addresses is refused while
such rules exist, so registration never widens a rule. Removing an instance or a
range is refused while an address subject would fall outside every instance.

Active matching rules compare lexicographically by priority, peer, port presence
and the number of ports covered, ICMP type, ICMP code, protocol, subject, and
direction. Block wins an otherwise equal tie; UUID breaks remaining ties. High
priority outranks Normal. Peer order is exact IP, host-length CIDR, or the
gateway, then exact hostname, domain, CIDR, then any peer. Deeper domains and
longer CIDRs win within their kind. DNS-derived permissions retain their
selector's rank. The subject key is the prefix length of the subject's range
that covers the address, above global rules, so a nested scope overrides its
parent only on an otherwise equal tie. More-specific global and parent rules can
outrank broad nested rules.

Direction describes who initiates relative to an instance. Outgoing downloads
still receive bytes on an outgoing connection. The service port is the remote
responder port for outgoing policy and the instance's local responder port for
incoming policy. A rule's ports are a list of ports and inclusive ranges; the
editor merges overlapping and adjacent entries, and the ruleset matches several
as one anonymous set. Between managed instances, both endpoint policies must
allow the connection. A broad instance Block is subject to the same precedence
as other rules.

The Gateway peer is the gateway itself at any of its addresses. It matches only
connections the gateway receives from or starts to the subject, which the kernel
recognizes by the gateway's local addresses (`fib ... type local`), so it needs
no address list. It never matches forwarded traffic: the forward hook first
drops any packet whose source is a gateway address, since the gateway sends only
through output. The kernel already drops such IPv4 packets as martians but
forwards IPv6 ones. Its service port is the port the gateway serves, after any
redirect to it, such as the DNS gate's port for redirected lookups.

Manual enablement, scheduling, and expiry remain independent. Expiry does not
delete a rule or change its enabled flag. Renew requires a new duration or
deadline; enabling an expired rule does not make it permanent. Linux time
synchronization supplies the clock, without an application NTP startup gate. An
incorrect platform clock can change when deadlines take effect.

## Policy and DNS

The gateway's local resolver gate validates and records DNS answers for
registered clients. `dnsReleaseMode` selects whether connection rules can
withhold those answers. The example settings use `require-allow`, which requires
approval before release, using the existing rules without a separate DNS
allowlist or Technitium policy mirror. `before-approval` releases answers before
connection approval and exposes queried names upstream, including names whose
connections are blocked. Packet rules still decide every connection. Technitium
can be the configured upstream resolver. Unregistered clients remain refused.

In `require-allow` mode, a lookup is allowed when at least one outgoing service
remains allowed for the question under current rule precedence, scope, and time
conditions. A hostname or domain Allow with no protocol or ports allows lookup
and leaves services unrestricted except where a winning rule blocks them. A
TCP:443 Allow also permits lookup, while packet enforcement retains its service
restriction. A TCP:22 Block cannot suppress DNS needed by an effective TCP:443
Allow. Higher-ranked Blocks can collectively cover every allowed service and
deny lookup. Any-destination Allows, including TCP:80/443, permit DNS for any
name. Incoming rules and IP/CIDR selectors cannot authorize a question before
its address is known. The original question controls name matching across
CNAMEs.

The release mode applies to every query type over UDP and TCP, including TXT,
HTTPS/SVCB, and the root question. In `require-allow` mode, unapproved queries
receive REFUSED with no upstream exchange. The gateway decides admission against
the last policy the enforcement service confirmed, so a lookup needs no
enforcement round trip; the gate decides again before returning an upstream
response that installs nothing. A policy takes effect for admission when the
gateway records the enforcement service's apply reply. A/AAAA responses also
require successful permission installation and local enforcement confirmation.
The enforcement service checks admission against its own policy before it
installs and again at confirmation, and it adopts a new policy just before it
replies, so A/AAAA answers can follow that policy slightly before other answers
do. An enforcement service denial returns its decision, which the gateway
records as the denial, and the client receives REFUSED. Answers that install
nothing are released under the gateway's copy even while the enforcement service
reports enforcement unavailable. Other answers create no address permissions.
Policy denial is distinct from infrastructure or enforcement failure, which
returns SERVFAIL. In `before-approval` mode, A/AAAA answers are retained as
leases even when no connection rule grants a permission. Saving a hostname or
domain rule can bind those unexpired leases without another query, so a broad
Domain rule can need more grants than `permissionLimit` allows; its apply then
fails with `permission_capacity`. Address restrictions, scope isolation, expiry,
and local confirmation still apply. Existing cached addresses remain subject to
packet rules.

Hostname and domain rules admit public unicast addresses by default, excluding
configured local networks. Listing permitted destination networks replaces that
default. Learning an IP does not authorize every service or prove which hostname
a later connection uses; shared IPs cannot enforce hostname isolation. Fresh
successful resolutions renew returned addresses. Old answers retain their
deadlines when answers change; traffic and restarts cannot renew them. Rule
disablement, deletion, and hard expiry override DNS grace.

Gateway and enforcement service RPCs use persistent Unix connections with
newline-delimited JSON frames and request-ID correlation. DNS and control use
separate active connections, each allowing multiple in-flight operations within
the 4,096/32 admission allocations. Expired requests retire a connection from
new work while healthy peers drain; known late replies release their
reservations. Transport failures are not replayed. Client request payloads and
partial replies share a 64 MiB bound. Server input frames and queued response
writes have separate 64 MiB bounds. Enforcement service work remains admitted
after socket loss until it settles. A settled command releases its admission
slot before its response write callback, since the client can receive that
response first. Response bytes, identities and shutdown work remain tracked
until the write finishes. Gateway and enforcement service shutdown drains
producers and closes idle connections.

Question admission ranks only the any-destination rules and the question's
hostname and domain rules that are global or scoped to an instance or address
rule on the client's scope path. The same index maps client addresses to their
paths and instances; the gateway builds one for each confirmed policy.
Address-permission derivation uses exact-hostname and domain-suffix indexes,
each partitioned by subject scope, and binds each answer address on the paths
described under the firewall below. The enforcement service reuses one index for
each owned immutable policy snapshot. CIDRs are parsed once during index
construction; a lookup normalizes its name once, retrieves only matching
name/scope candidates, parses its address once, and preserves all matching rules
in policy order. Prepared policies have separate indexes and cannot change the
active snapshot. Configured policy changes construct a new index and compile a
full firewall replacement.

DNS batches use an in-memory ledger of leases keyed by the client's scope path,
requested hostname and returned address. Each rule contribution is retained
separately; unique grants are keyed by the path that holds them, rule and
address and track supporting contributions and their maximum deadline. Global
rules share their matcher, while learned grants remain specific to each holding
path. Indexed expiry queues replace/delete entries on refresh, and batch cursors
inspect confirmed expiry without mutating it. Each instance holds at most 10,000
leases over its addresses' scope paths, whether or not a rule grants them,
within the shared 100,000-lease bound. A lookup that would add more fails with
`dns_instance_capacity` for that instance only; refreshing a held lease adds
none.

Each batch stages only changed records. A rejected lookup restores its own
changes while preserving earlier staged answers. Lease/contribution counts,
unique grant allocation and exact serialized-state bytes are maintained
incrementally, including JSON array separators and serialization overhead.
Changed native groups are derived only when effective address deadlines change.
The enforcement service merges staged state after successful atomic nft
execution. Failed execution blocks cached acknowledgement; status reads
confirmed counts throughout an in-flight transaction. Configured-policy
operations may still materialize and rebuild the full state.

Each incoming DNS UDP listener requests `dnsReceiveBufferBytes`, 8 MiB by
default; Linux reports twice that per socket after bookkeeping. Configuring both
IPv4 and IPv6 uses two UDP listeners. The packaged gateway sysctls permit the
default. Startup binds both UDP/TCP listeners and reads back the granted size
before it reports readiness. A buffer the kernel caps lower, as
`net.core.rmem_max` does in unprivileged containers, is kept: the gateway logs
the requested and granted sizes and reports the `dns_receive_buffer` condition
in its status until a restart receives the full size. The default for unrelated
sockets is unchanged. DNS admission remains bounded at 4096 active queries
across all listeners; buffer capacity absorbs bursts before admission. The
enforcement service reserves 32 separate control slots and allows 4160
connections for admitted work and incoming frames, with a 64 MiB aggregate frame
budget. The application requests TCP DNS and enforcement Unix-socket listen
backlogs matching their connection limits; effective backlogs also depend on Bun
and kernel caps. Gateway and enforcement service file-descriptor limits
are 16384. The five-second response-freshness check applies to queued DNS work.

Each DNS gate owns its upstream UDP sockets. It retains up to 4,096 ports and
assigns one active query per socket; temporary sockets handle additional
admitted queries, so the retention size does not reduce DNS admission. Each
socket connects once to the configured peer; subsequent sends reuse its default
destination and kernel route. Warming waits for connection readiness and rejects
if shutdown closes the socket first. Idle selection and transaction IDs are
random. A port never reuses a transaction ID during its lifetime. Expiry is
staggered over 15-30 seconds; ports also retire after 2,048 uses, timeout or
transport failure. Startup prepares the retained ports before listener readiness
without sending queries. Active queries finish before their port is retired.
Replies must match the configured peer, ID, question name, class and type.
Failures are not replayed. Shutdown drains admitted queries before closing the
pool. TCP upstream queries use a separate connection per query.

The enforcement service streams conntrack snapshots through a managed-endpoint
filter before RPC framing. Original initiator and translated responder addresses
determine scope, matching traffic accounting. Unmanaged gateway-owned upstream
DNS connections are excluded. Malformed records and snapshots exceeding the
transport allocation produce explicit errors rather than truncated or partial
snapshots. Snapshot sizing includes the encoded ownership map and response
envelope; capacity errors leave other requests on the shared connection intact.

Connection snapshots carry the captured policy identity and immutable instance
ownership IDs. A policy installation during the native query rejects the sample
without holding the DNS mutation queue. Lifecycle events capture the same
ownership IDs; lifecycle records arriving during full installation become loss
markers rather than receiving an uncertain owner. Counter baselines retain
endpoint ownership; reassignment resets the affected baseline and reports
partial coverage instead of assigning the transition interval to either owner.
Names and unrelated rule changes preserve ownership IDs. Loss warnings are
retained sequenced markers in the bounded kernel stream; reads do not consume
them. The gateway acknowledges them by advancing its cursor only after
observation and cursor persistence succeed.

The default profile allows 4,096 concurrent queries. Persistent enforcement
connections avoid opening a new connection for each lookup. The profile includes
16,384 pending DNS history records, a 64 MiB pending-history allocation, and
16,384 gateway and enforcement service file descriptors. The separate DNS TCP
accept backlog is unchanged; passing ordinary TCP checks is not a
4,096-connection TCP burst guarantee.

Rules use deterministic field precedence and separate manual enablement from
time eligibility. A permanent global catch-all is required in each direction.
Settings owns the enabled, normal-priority permanent catch-all: saving Settings
writes one rule for both directions when they agree and one per direction
otherwise, reusing existing catch-all IDs. The rule endpoints refuse to create,
change, or delete it. Temporary, disabled, and High-priority catch-alls remain
ordinary rules. Incoming DNS selectors are rejected.

Managed policy runs in input, output, and forwarding hooks on every packet,
except managed clients' TCP and UDP traffic to the gateway's DNS port, which
hostname rules depend on. An Allow returns to the remaining endpoint checks. An
established connection does not bypass current policy. The original
initiator/destination identify outgoing scope; the actual responder identifies
incoming scope under NAT. Blocking or expiry does not require deleting conntrack
state.

A DNS Allow rule's live permission sets the rule's connection mark on the
connections it admits, in the low 24 bits of the conntrack mark; the high 8 bits
stay with other tools. Right before its DNS permission check, the rule allows an
established connection that carries its mark, under the rule's own time
conditions. A disabled, deleted, or expired rule loses that check, so its
connections stop at their next packet. The mark identifies the instance, rule,
peer, and service, so an edit to the peer or service gives the rule a new mark.
The enforcement service numbers marks from a counter that only grows and saves
them in `connection-marks.json` before installing a policy that uses them, so a
number is never given to another rule.

The resolver gate validates its upstream transaction and question. The
controller is outside the A/AAAA authorization path. Authoritative address
leases retain the original question, response time, CNAME minimum TTL, and
deadline. A grace change can alter eligible live deadlines without reviving
expired leases. Native timeout sets and absolute UTC time predicates enforce
expiry while services are stopped. The nft CLI accepts epoch seconds, not kernel
nanoseconds. DNS permission deadlines round down to whole seconds, shortening
their lifetime by less than one second without extending the original TTL.
Scheduled rule deadlines already require whole-second precision. The resolver
returns a failure when a permission expires before installation is confirmed.

Each endpoint chain calls dedicated DNS admission chains in rule order. A live
Allow sets its connection mark and a packet-local admission flag before
returning. The endpoint chain checks that flag before returning to the remaining
endpoint checks; a miss continues with the next ordered rule. Entry wrappers
restore the borrowed packet-mark bit on allowed traffic. Connection marks are
never cleared to communicate a miss: related ICMP errors can share an
established flow's conntrack entry. Inherited marks on separate related
connections do not prove fresh admission. Chain depth stays constant as DNS
rules are added. The transaction replaces only changed DNS chains and timeout
sets. Command completion precedes memory publication and acknowledgement;
unchanged grants use memory. Older concurrent replies cannot overwrite a newer
authoritative response. Permission counts deduplicate shared address/rule pairs.

The controller retries health reads after transient failures. Only an
unconfirmed desired revision triggers full policy delivery, avoiding
reinstallation on ordinary connection or diagnostic errors.

Infrastructure access is represented through ordinary rules, including SSH to
the gateway (a Gateway peer rule) and the path to the controller dashboard;
there is no anti-lockout bypass. Fixed network, management, anti-spoofing,
routing, and offload configuration belongs to Linux network commissioning.
Traffic bypassing the gateway is outside coverage.

### Enforcement chains and unregistered traffic

The enforcement service compiles one chain pair per distinct path of scopes in
each family, holding the global rules and the rules of every scope on the path
in precedence order and ending with the missing-winner drop. Interval verdict
maps keyed by the connection's original and reply source addresses dispatch each
packet to its path's chains; their elements are each range minus its nested
ranges, so they never overlap. Allow verdicts return to the hook, so both
managed endpoints' chains run. In `input` and `output` the gateway is one end,
so only the other is dispatched: the initiator of a connection the gateway
receives, or the responder of one it starts. A hostname rule keeps a set of
learned addresses per path, filled by lookups of clients on that path, so only
clients that inherit the same rules share what one of them learned. An answer
address in the other family than the lookup, such as an AAAA answer to a lookup
over IPv4, fills the sets of every path of the client's instance in that family
that some address has, since nothing tells which of those addresses the client
uses; each path binds it only to the rules that apply there, so its own
precedence still decides. Learned addresses and the connections they admitted
end when no address has their path any more, such as when an address rule is
added above the only client on it.

A connection with no instance on either end is unregistered. `forward` drops it
after both dispatches, and `input` drops connections unregistered addresses
start, before the DNS gate. Replies and errors of the gateway's own connections
pass. Before those drops, `input` and `output` accept loopback, DHCP and DHCPv6
in both roles between the protocols' client and server ports, ICMPv6 neighbour
discovery, router solicitations and MLD, the machine link with the enforcement
service's configured controller addresses (their connections to `machinePort`
and the gateway's to `controllerPort`), and the gateway's lookups to its
upstream resolver, so policy can always be repaired and the gateway can
configure its links and resolve. Router advertisements reach the gateway only on
upstream interfaces, and no host may redirect it; the gateway itself may send
both. Unregistered drops trace themselves at 10 packets per second, bursts of
20, and count every packet; a drop that arrived on one of the enforcement
service's upstream interfaces (such as a scan) is reported as history only, any
other is reported for registration.

## Collection and storage

Conntrack snapshots and NEW/DESTROY events contribute counter deltas. Tuple
identity preserves original and translated service ports. Counters remain
decimal strings on the wire and use BigInt internally. Missing counters, startup
baselines, stream loss, and resets leave visible partial coverage: a collection
cycle that lost traffic records a `traffic_coverage_partial` condition, and the
next clean cycle records its recovery. Dropped kernel records, such as conntrack
buffer overruns, are reported once as a gap; a stopped event stream restarts
with backoff and reports a condition until it runs again. An older NEW event
cannot replace a newer sampled baseline. Resolver observations retain the
instance identity and policy revision returned by enforcement; failed
resolutions have no inferred instance owner.

The gateway is not an instance, even where a subnet instance contains its
address. The enforcement service reads the gateway's addresses from the
operating system with each snapshot and event batch, and telemetry attributes no
connection end to an instance at one of them, so a client's connection to the
gateway is counted once, as the client's, with the gateway as its peer on the
port the gateway serves. The gateway reports its addresses and the parameters of
its fixed accepts to the controller, which shows the addresses as the Gateway in
Monitor and decides those services by Gateway peer rules or by the fixed accepts
that precede policy. The DNS gate accept covers a whole service. The others
(DHCP, the machine link, and the gateway's upstream lookups; see Enforcement
chains and unregistered traffic) match only some ports or addresses, and Monitor
records neither source ports nor which of an instance's addresses was the end,
so where rules would not allow such a service it shows it as varying, allowed
for those packets by the accept and otherwise decided by rules.

Each Block rule counts every packet it drops before sampling in one named
counter per instance and direction, shared by its IPv4 and IPv6 trace chains.
The gateway reads the counters once a minute, matching the one-minute storage
buckets, through the enforcement service (`nft -j list counters`, which lists
only counter objects), in pages that keep each enforcement frame small, and
appends the increase per counter as a `blocked_count` event. A counter is
identified by boot, table handle, and name. Every policy apply rebuilds the
table and restarts its counters, so the enforcement service reads them just
before the rebuild, in the same sequence as counter readings, and returns those
final values once with the next reading. Packets dropped between that read and
the rebuild are lost, and so are final values in a reading that does not reach
the gateway. A rejected apply keeps the table, so a reading can list a counter
twice; each value counts from the one before it. If that read fails, the apply
goes ahead and the next reading reports the drops as uncounted. The first
reading after the counter state file is created only sets the baseline. The
state is saved before the counts are appended, so a crash in between loses those
counts instead of reporting them twice. Read failures emit a
`blocked_count_collection` condition. The controller adds counts into per-rule,
instance, and direction buckets and does not store them as events. Unregistered
drop counters carry the side the packets arrived on instead of an instance and
rule, and are kept in buckets of their own.

Rate-limited nftables traces populate blocked activity and connection Requests.
Pre-NAT packet identity is retained; samples without the original tuple are
omitted rather than assigned a guessed peer. Requests count sampled packets, not
all connection attempts. Captured kernel revision and winning catch-all metadata
identify the original denial independently of the controller's desired policy.
Block traces and resolver policy denials record the managed client's address.
Resolver policy denials record the actual question and query type, the client's
most specific instance, and the applied decision's revision, hash, and rule.
They contain no destination IP or packet service. Catch-all denials enter DNS
Requests grouped by instance and question, showing the latest query type; rules
cannot select a query type. Each Request keeps its eight most recent distinct
clients, and is decided for the newest; a Request belongs to the client's
current most specific instance. Explicit Blocks do not repeatedly enter review.
A denial is attributed to the Block that completes the coverage of the
highest-ranked losing Allow, the Block without which that Allow would keep a
service; with no Allow, to the first Block covering every service. The gateway
records each denied instance, client, and question once per 60 seconds while the
same decision (policy, rule, and catch-all) denies it, so repeated lookups
cannot crowd out new names; a denial under a different decision is recorded at
once. New names are recorded at most 10 per second per instance, bursts of 20,
and 100 per second in total, bursts of 200, with separate limits for catch-all
and explicit-Block denials. Repeats are dropped. Lookups of new names the limits
leave out are counted and reported every 10 seconds as one momentary
`dns_denials_omitted` condition; such a name is recorded when a later lookup
fits the limits. A name whose record fails to append is recorded on its next
denial. DNS request attempts therefore count recorded windows, roughly the
minutes a name was denied; connection counts represent sampled packets. A denial
arriving after the policy that decides its scope was saved leaves the request
Applying, and one arriving after that policy is confirmed is not recorded as a
request. Telemetry delivery is asynchronous and cannot release a denied answer.
The enforcement service checks DNS admission before it installs an answer's
permissions and again when they are confirmed, so in `require-allow` mode a
Block scheduled to start during the install withholds the answer.
`before-approval` releases it, and packet rules decide its connections.

An unregistered drop that arrived on a client interface creates a host Request
for the dropping address, with its eight most recent destinations; DNS queries
Suricata saw from it, which arrive before its packets are dropped, add up to
eight names. A new Request takes the stored queries from the minute before its
first drop on, so its first names can be missing only when history retention has
already removed them; queries alone create no Request. Each client's name is
kept once per 60 seconds within the denial limits. Registering an address that
covers the host resolves the Request, and its later denials become ordinary
Requests. Upstream drops create no Request; Monitor shows their counts beside
client-side ones, and groups the newest 5,000 sampled drops of either side by
source, destination, and service, showing the 50 newest groups with sample
counts, first and last times, and a link to the host's Request. A host's drops
at the gateway's DNS listener, which it reaches directly or through forwarding
the operator configured, list up to eight names it looked up from a minute
before their first sample to their last; these are the host's lookups in that
span, not a pairing of names with drops. The Requests page loads a linked host's
Request even when it is older than the newest 500 Requests it lists.

The controller retains pending requests in separate pools: 5,000 connection
scopes, 5,000 DNS scopes, at most 500 of them per instance, and 10,000 host
scopes, so lookups for many names cannot displace connection requests. Dismissed
hosts are kept apart, up to 10,000, and are never removed for space, so a
dismissal lasts until the host is restored or registered; at the limit,
dismissing is refused. A dismissed host's drops update only its attempt count
and last time. Resolved rows are removed. Overflow retains the newest scopes of
each pool by last observed time, with a stable identity tie-break, and records
the discarded-scope count in the same SQLite transaction as removal. Request
rows have separate logical accounting at 512 bytes per row; the runtime disk
budget includes their actual database and index storage. Requests exposes
retained and discarded counts, including after replay or restart.

Lifecycle records pin their endpoint instance mappings before entering the
enforcement queue. Trace normalization uses the captured instance identity,
without requiring it to remain in the current policy. Kernel conditions emit
transition events; the source cursor durably retains the last condition so an
unchanged error does not generate history on every poll.

Suricata EVE and configured PTR lookups supply labels and protocol metadata.
They never create admissions. Original timestamps and lossless source identity
are retained. PTR results expire and preserve manually configured instance
names.

The gateway persists closed observation batches before delivery. Acknowledged
batches are removed only after the controller's transaction commits. Epoch and
sequence identify serialized delivery. The latest batch can replay after a lost
acknowledgement; older sequences are rejected. At allocation exhaustion, an
eviction intent durably identifies the selected unread batch and its target loss
count before deletion. Deletion and directory synchronization complete before
the loss count is finalized. Startup and subsequent operations finish an
interrupted eviction exactly once before delivering newer sequences.

DNS telemetry keeps each lookup's event identity and timestamp while grouping up
to 4,096 events or one MiB into a durable write. Its collection window is 50 ms;
pending DNS work is bounded by 16,384 records and 64 MiB. Source checkpoint
operations close the open DNS group. Append acknowledgements follow durable
commitment, and telemetry remains asynchronous relative to the DNS reply.
DNS-only batches use their synchronized segment as the durable record, without
duplicating the payload in a preceding buffer checkpoint. Keyed sources retain
their payload reservation so source progress can recover independently. Startup
fences the segment directory and rebuilds sequence and DNS deduplication
metadata from the newest retained batch beyond the checkpoint, including when an
older keyed intent still needs recovery. Individual DNS event hashes are shared
between deduplication and checkpoint metadata. Any acknowledgement deletion
first fences uncheckpointed completion metadata; clean shutdown also flushes it.
Accepted DNS history remains durable through its segment before metadata is
checkpointed. Resolver DNS address details retain all accepted answers in one
string, bounded by the resolution's 256-answer and 253-character value limits.
Other observation detail strings remain limited to 4,096 characters.

Owned DNS groups reuse admission-time schema validation. Each canonical event
encoding feeds its per-event hash and the ordered batch hash, preserving the
SHA-256 identities without re-sorting the same event for the batch. Other
sources retain commit-time validation. Delivery rereads only a segment's batch
identity; startup recovery and controller ingest validate every event.

A dedicated collector worker runs atomic JSON writes for segment files and
buffer metadata on its own JavaScript event loop. Each write transfers owned
UTF-8 bytes. The current storage budget is checked before persistence
submission. Both paths share the same atomic-file primitive. The buffer keeps
its ordered commit queue and permits only one worker write in flight; reply
identities must match that write. Acknowledgement follows the same file and
directory synchronization. Filesystem errors preserve their codes. Unexpected
worker exit or invalid replies fail pending and subsequent writes and appear
immediately in collector status, without worker restart or main-thread
persistence fallback. Shutdown drains writes and the final metadata checkpoint
before closing the worker; failed initialization also releases it. Builds ship
`collector-worker.mjs` alongside `gateway.mjs`.

Delivery pins one committed segment and releases the writer during the
controller request. Acknowledgement deletion and directory synchronization
finish through the writer before a newer sequence is sent. Retention cannot
evict the pinned segment. An append that cannot fit beside the pin rejects
before evicting other unread segments. Status reads use the owner's published
committed inventory and expose its timestamp, live pending counts and errors
without entering the write queue. Known rejected DNS records are separate from
lost durable batches and retryable writes. Uncheckpointed rejection counters are
identified explicitly; an unclean capture session reports potentially missing
volatile records or counts. That notice is written once as a condition event
followed by a recovered event, because capture is running again; the stored
notice clears only after both events are appended.

The controller acknowledges an identical latest committed batch before write
maintenance or insertion-capacity checks. Changed hashes and older sequences
remain errors, and new batches still require available storage.

SQLite stores desired and confirmed policy separately. Mutation checks the
expected revision and advances it atomically; confirmation checks its exact
policy hash. Observation history has one logical allocation per kind, each
trimmed oldest first: traffic (traffic events and metric rows), DNS (events and
the answer addresses indexed for request names), blocked packets (samples and
counts), and other (Suricata metadata and conditions), so a flood of one kind
cannot displace another. Blocked samples are grouped by rule, instance, and
direction, and the group with the most is trimmed first, so one instance
scanning into the catch-all only displaces its own older samples in that
direction. Blocked counts leave by age, minute buckets after one day and hour
buckets after 180 days, and oldest first only when the blocked allocation is
still exceeded after its samples are trimmed. Audit has a separate allocation.
Admin changes record the client address and User-Agent in their audit details;
History shows the address and browser family. Policy changes also record their
revisions and what changed, computed from the previous and new policy while
saving: complete values for created and deleted rules and instances, and before
and after values of the changed fields otherwise. SQLite page and journal limits
reserve overhead independently of enforcement state.

Collection jobs retain their event identities and chunk progress until batch
persistence and the source checkpoint succeed. Accounting uses a staged copy;
failed writes do not advance the committed baseline. Process restarts still lose
in-memory connection baselines and report partial traffic coverage.

EVE persists a normalized read job before emitting its chunks. The job pins
instance identity and source range across policy changes and process restart.
Shared collection commits retain chunk progress; the buffer retains the latest
keyed EVE receipt so an acknowledged chunk can retry its progress checkpoint
without allocating another segment. The EVE job is removed after its cursor
commits. One reader owns this keyed receipt.

A Suricata coverage loss (unreadable records, an oversized or incomplete record,
or unread data discarded at the storage limit) is saved in the source cursor.
The next job records it as a `suricata_coverage` condition event followed by a
recovered event, since later records are processed again, and its cursor commit
clears the notice. The reader's status condition covers only the current read
failure and clears after the next successful read.

New EVE jobs retain a 1,024-record chunk size when the entire normalized read,
including transport headroom, fits both 1 MiB and the collector allocation.
Other jobs retain 256-record chunks. The chunk size is journaled before append;
older saved jobs keep their original 256-record boundaries. Progress advances by
the number of events durably appended. The reader yields between completed jobs
and immediately continues while its cursor advances; the one-second poll delay
applies at end of input or after an error. Shutdown cancels polling and awaits
the active read. Source read size, job limits and durable write ordering remain
unchanged.

Suricata append waits outside the collector mutation queue while DNS writes are
pending or delivery has queued batches beyond its current in-flight batch. One
Suricata batch can be prepared while that final batch is sending. Delivery and
DNS completion wake the waiter; no polling delay is added to this capacity wait.
Unread Suricata files and the normalized job retain the backlog. Shutdown aborts
the wait before awaiting the reader, without advancing source progress or
reporting a persistence failure. Actual filesystem and delivery failures retain
their error handling.

Intermediate chunks checkpoint job progress. The final chunk proceeds directly
to the source cursor checkpoint instead of rewriting the whole job first. If
that cursor fails, the same normalized final chunk may be replayed against its
keyed buffer receipt, including after its segment was acknowledged and deleted.

Persisted keyed buffer reservations include their batch payload. Startup and
runtime use one recovery path to recreate missing reserved segments, sync their
directory, and commit reservation completion together. Normal DNS batches
recover from their synchronized segments; a failed live DNS write retains its
in-memory reservation for retry or a clean-shutdown checkpoint. Old reservations
without a payload report uncertain coverage, not confirmed loss. Retryable
persistence errors are separate from durable eviction loss; a successfully
recovered write adds no lost-batch count.

Suricata runs as its own account with only `CAP_NET_RAW`, outside the service
group, so a compromised Suricata process cannot reach the enforcement service
socket, gateway configuration or nftables. The root log rotation service is
limited to reading Suricata's process descriptors and handing it a placeholder
output. A fast loop checks output sizes every 250 ms, renames files at 8 MiB and
requests Suricata's log reopen. A slow loop handles storage pressure, capture
state and the status heartbeat every second, publishes a `.closed` archive once
the writer's descriptors show it has let go, and then syncs the directory.
Directory syncs can stall for seconds under heavy Suricata output, and only the
slow loop waits for them, so they cannot delay a rename. Suricata reopens on its
next write, which an idle Suricata process delays until its stats interval, so a
held archive waits for a later pass. An archive still held after a minute is
logged once. Rotation starts once the enforcement service has an applied policy,
whose settings carry the disk budget. Under storage pressure, every non-empty
output is archived. The unprivileged EVE reader waits for that marker, resumes
the saved inode among retained archives after restart, and waits for active
reads on shutdown. A missing saved source stops collection with a visible error.
The reader removes closed sources after their data is durably spooled. Under
pressure it records the unread byte count in a durable coverage condition before
discarding a closed source. Active writers are never reclaimed.

The focused checks cover lost acknowledgements, committed SQLite recovery after
SIGKILL, backlog replay, reservation failures, and real full-filesystem writes.
They do not establish complete accounting continuity under crash/load. Raw
Suricata files, archives, pending payload checkpoints, and EVE jobs have
separate logical allocations inside a combined physical budget. Defaults are 4
GiB on the gateway and 8 GiB on the controller. Allocated filesystem blocks
count once per inode, including raw logs, enforcement snapshots, pending jobs,
delivery segments, SQLite/WAL and runtime diagnostics. Symbolic links are
rejected. Admission checks protect 256 MiB on the gateway and 64 MiB on the
controller for recovery and policy changes. Capture pauses before the gateway
reserve and resumes after reclamation. Suricata has a 64 MiB per-file process
limit; closed diagnostic logs are removed.

These are cooperating application limits, not filesystem quotas. OS journals,
operator backups and unrelated writers require host-level limits. Existing files
over budget remain visible; the app does not delete unknown files to make room.

## Dashboard and access

One Admin account uses Argon2id and revocable opaque sessions. The controller
imposes no password strength policy; setup requires a password of at most 1024
bytes. Browser sessions expire after 12 hours. Remembered sessions last 7 days,
renew in the server hook when used with less than 5 days left, and end 30 days
after sign-in. Server hooks authenticate protected routes and enforce mutation
origins; application services authorize operations. Loaders call shared services
directly. Bodies, timeouts, connection counts, and queues are bounded.

Login reserves each attempt before asynchronous password verification. At most
four verifications run concurrently and 4,096 live throttle identities are
retained. An identity is an IPv4 address or an IPv6 /64 prefix; IPv4-mapped IPv6
clients use their IPv4 address. Expired one-minute windows are removed on login
and pruning; active identities are not evicted to admit another client. Machine
HTTPS operations have an elapsed-time deadline in addition to response-size
bounds.

Machine frames share a 2 MiB allocation. New policy documents must fit that
allocation with 64 KiB reserved for command and status metadata. The controller
validates encoded bytes before advancing a desired revision; gateway and
enforcement service commands enforce the same policy ceiling. Saved documents
retain their ordinary schema so existing state remains readable for correction.

Browser deployment requires HTTPS and Secure session cookies. Machine transport
always requires authenticated HTTPS.

Production controller builds require a validated `TP_PUBLIC_ORIGIN`, which sets
SvelteKit's `paths.origin` for form CSRF checks. The root build validates it
before writing artifacts; direct Vite builds enforce the same contract. Each
controller artifact must match its deployment's configured public origin.
Application mutation-origin checks, transport validation and cookie flags remain
independent of this build setting.

Production views read configured data. The component catalog is a separate
development page in `apps/controller/catalog/`, started with `bun run catalog`
on port 4174. The production build excludes it. [DESIGN.md](../DESIGN.md)
defines the visual contract; this document owns system and product behavior, and
[API_CONTRACT.md](../API_CONTRACT.md) owns wire formats.

Monitor groups HTTP/TLS labels by registrable domain, hostname, IP and service.
The server bundles a pinned Public Suffix List with its license. Labels belong
to the selected period. Only an IP with one observed hostname joins a named
group; other IPs appear under an IP addresses node so aliases cannot duplicate
byte totals. DNS questions do not label the resolver as the queried site. Names
never grant access.

The inspector summarizes retained events only for a selected instance, and only
when the request asks for it: on a scope, period, or explicit refresh change,
and otherwise at most every 15 seconds of polling, with the last summary kept in
between. It walks the event time index newest first, without a peer index that
would slow every ingest, and keeps the newest 5,000 events of the instance or
its selected peer addresses in the period and scope. It stops after reading the
period's newest 100,000 events of any instance and reports the oldest time it
read, so a rarely seen address does not cost a scan of the whole period on each
refresh. The user can request one whole-period scan, which reads 100,000 events
at a time and lets other requests run between slices; it runs one at a time, and
the browser keeps its result for that view until the view changes or the user
rescans. Events are grouped by kind, direction, protocol, port, and the rule
recorded on blocked samples, and the newest 100 groups are returned. Every limit
is reported, so a long period on a busy instance is labeled as covering only its
recent events. The summary also returns each Block rule's counted packets beside
the samples recorded over the same window, which starts at the counter bucket
containing the period start; samples are counted from each rule, instance, and
direction's history group index. The instance view also lists rules that counted
packets without sample rows in the summary. Destination, service, and name views
list only rules with sample rows, because counters are per instance; when the
summary hit a limit and the instance counted blocked packets, they say that
matching samples may be outside the checked events and link to the instance.
Current rules are shown separately from past events. Monitor row decisions are
evaluated in the browser from the desired rules with the shared core evaluator,
without DNS-derived permissions; the snapshot lists open review requests for its
listed services. Indexed timestamps normalize to UTC while source event JSON
retains the exact Suricata timestamp. Removing an instance atomically removes
its scoped rules and pending Requests after a revision check; shared rules and
retained historical observations remain.

### Dashboard decisions and editing

Monitor offers Show all, 30 days, a week, 3 days, 24 hours, 5 hours, an hour, 10
minutes, 5 minutes, and 2 minutes. Last 5 minutes is the default. Show all
covers the retained 180-day window. From now fixes the start while polling
advances the end; selecting it again resets the start. Changing periods
preserves scope. An initial zero-duration window is empty.

Settings storage fields accept bytes, decimal KB/MB/GB/TB, or binary
KiB/MiB/GiB/TiB, case-insensitively with an optional space. Fractions must
resolve to whole bytes. Bare K/M/G suffixes are invalid.

Monitor selections narrow totals, timeline, and inspector together. Selecting
the same entry preserves the current view and in-flight work. Group decisions
agree only when every measured service agrees. IP decisions vary when a name
rule could outrank them through DNS; a named row evaluates its own name. Rules
that refuse a destination address do not count as effective permissions. The
inspector distinguishes current desired decisions from historical evidence.

A rule has no effect when an active opposite-action rule covers its entire scope
and outranks it by High priority or Block's exact tie. Saving remains available
because the winner may expire. The editor identifies that winner and offers an
explicit High priority choice when it would change the result. Monitor actions
edit an exactly matching scope; otherwise they create a draft. Instance actions
use both directions, name actions use outgoing, and destination actions follow
measured services. A child action cannot silently edit a broad parent rule.

Requests use the same editor. Connection requests retain the recorded instance,
direction, protocol, and service port. For outgoing connection requests,
confirmed DNS answers that resolved a client's lookups to the address within
five minutes before that client's latest attempt supply hostname suggestions;
incoming and both-direction requests keep the IP, since hostname rules apply
only to outgoing traffic. One name is preselected; several, or a list the read
limits cut short, require a choice, with the IP available explicitly. Without a
matching name the IP is prefilled, as it is for an address a hostname rule
without permitted destination networks cannot admit. The editor warns when a
hostname or domain draft would not admit the request's address and offers to add
it to the permitted destination networks; it does not add it by itself. A
hostname or domain draft whose address subject has no scope of its own notes
that it takes effect after those addresses look the name up again: saving gives
them a new scope path, and the answers they already hold stay with the previous
one. Lookups count only from the Request's own client addresses, so a dual-stack
host that resolves over one family and connects over the other gets the IP
draft. Only confirmed resolver-gate answers index their client, and each
client's read covers only those answers. Historical inspector names are not
suggestions. The suggestions read has a 10-second deadline, and a failure is
shown without opening a draft. DNS requests in `require-allow` mode prefill the
exact hostname, instance, and outgoing direction with no service conditions. The
root DNS question requires an Any peer selector, shown in the editor. Scope,
action, priority, activation, and lifetime remain editable. Saving never raises
priority automatically. Available lifetimes are Permanent, 15 minutes, 1 hour, 8
hours, 24 hours, and Until a deadline.

Connection inspectors load observed DNS, TLS, and HTTP names for the actual
address. A shared address does not identify a blocked connection's hostname.
When a name Allow would win but refuses the address, Allow through opens that
rule with the exact address added to its permitted networks, unsaved for review.
Listing a network replaces the public-address default. DNS inspectors show the
actual requested name directly.

Saving a targeted decision moves matching Requests to Applying. DNS requests use
the shared DNS evaluator; connection requests consider their observed names and
hostname suggestions when relevant. Only confirmation of the current desired
revision resolves Applying requests. Failed delivery moves them to Failed; an
older receipt or failure cannot resolve or fail newer work. Requests represent
observed attempts; permission takes effect on a later lookup or connection.

History reads up to 500 audit entries and 500 observations, newest first. It
resolves names and rule descriptions from current policy. For deleted rules, it
uses the newest complete creation or deletion values. Search matches current
labels and recorded identifiers. Retention follows configured budgets, and the
earliest retained audit timestamp describes available change coverage.
