# Local transport and durable state

These packages implement the helper boundary, not an installed firewall service.
The reader command submits fresh directory data to a checked root-helper socket;
no current command starts the helper or directly updates nftables. The private guarded
backend is exercised in isolated test fixtures, not an installed service. The
remaining runtime and packet tests are listed in [the activation gates](architecture.md#implementation-gates).

## Socket contract

`internal/ipc` accepts a Unix stream listener created by a trusted supervisor.
A future systemd socket unit must create a root-owned path in a trusted,
non-writable directory, with mode `0660` for the reader group. The helper checks
the socket metadata and Linux `SO_PEERCRED` before reading any request. Only the
configured reader UID reaches the processor. The client checks the helper's UID
before sending its snapshot. Production wiring must choose distinct helper and
non-root reader identities; transport tests can use the test runner's identity.

Each connection carries one four-byte, big-endian length followed by one JSON
request. The maximum request is 16 MiB, checked before allocating its body.
Version 1 accepts only `schema_version` and `directory`; directory fields are
`observed_at`, `complete`, `groups` and `devices`. Group and device keys must
match exactly. Duplicate keys, case variants, null required fields, trailing
JSON, commands, raw firewall programs, bindings, helper clocks and reset
operations reject. Collection limits are 8,192 groups and 4,096 devices; the
compiler applies the remaining policy quotas and freshness checks.

The processor receives typed directory data and a deadline. `internal/agent`
provides that processor: it owns an immutable compiler, uses helper-owned state
and time, and reads qualified bindings through a separate trusted dependency.
The transport does not turn an arbitrary callback into a policy validator.
Requests are serial, with a configured deadline capped at ten seconds. Processor implementations must
honor cancellation; the transport alone cannot interrupt an arbitrary callback.
Cancellation interrupts socket I/O and joins the interruption callback.

In enforce mode, startup clears application permits before reading existing state;
missing or unsafe state never triggers initialization. Each complete directory
observation's watermark and managed cohort are saved before collecting bindings.
A newer denial therefore cannot be replaced by an older allow if binding
collection fails. After fresh binding validation, the helper derives native
and available NAT device classifiers against its own geometry and saves that
deny-only history before compilation. This includes inactive, removed and
zero-grant managed devices with current qualified Untrusted bindings; unrelated
or unqualified bindings contribute no addresses. Compilation saves immutable
expiry/alias anchors before
calling the backend. On failure, enforce mode attempts permit removal with an
independent two-second deadline. Cleanup can outlive a canceled request by that
bounded interval; failed cleanup requires a new successful closed startup.
Shadow mode rejects firewall dependencies and never calls them.
Repeating a snapshot cannot restart its directory lease.

The engine also keeps a process-local monotonic age anchor independent of UTC
snapshot timestamps. Between readings, authorization time advances by at least
the elapsed monotonic interval; a forward UTC correction can advance it further.
A UTC lag of at most 250 ms is clamped to that lower bound, never added to a lease.
A larger backward discrepancy rejects and attempts permit removal. Failed samples
and another `Start` on the same engine do not reset that age anchor. Evidence is
also checked against actual UTC so the clamp cannot admit future timestamps.

After startup, directory observations must be at least as recent as startup and
strictly newer than any persisted directory watermark. Binding snapshot,
association and address observations must also be collected afresh after startup.
The collector must revalidate actual association/ownership, not stamp a cache
with the current time. Losing process-local timing on restart therefore cannot
make a persisted directory observation or old ownership evidence fresh again.

The apply callback receives `policy.Authorization`, not an editable candidate.
The helper captures its age anchor before collecting compile-time UTC. The
compiler owns the resulting grants; diagnostic/state snapshots are deep copies.
`Remaining` clips each original grant by UTC expiry and elapsed age since that
sample. Sampling, compilation, durable saves and backend queueing all consume
the same lifetime. Copying a result does not reset its anchor. Both the anchor
and authorization reject JSON serialization/deserialization; boot must obtain
new evidence, never restore one of these process-local values.

The enforce-mode callbacks are a contract for a trusted, restricted backend,
not proof of production packet revocation. The private guarded backend implements
the apply/seal operations below, but no executable wires it into these callbacks.
Qualified binding collection, protected packet-path integration, translation
coordination and packaging remain unfinished.

The private `guardedService` composes the real backend, engine and IPC server.
It copies the catalog from the backend's paired profile, rejects a differing
compiler hash and uses the backend's same clock. Configuration supplies only
normal persistence, independently qualified binding collection, a non-root
reader UID and a request timeout within the ten-second cap. Construction does
not load state, read bindings, sample time or touch nftables.

Serving requires root and adopts a supervisor-created listener exactly once.
The service runs closed startup before the IPC server can accept a request;
failed startup never silently initializes or repairs state. Concurrent or
repeated calls reject without adopting their listeners. On every adopted exit,
including canceled startup, an independent two-second stop attempts to remove
permits and retains any cleanup error. The supervisor's socket path is not
unlinked; the caller must keep backend and store resources open until cleanup
finishes. A failed seal is an error, not evidence that packets were revoked.
The signed boot path must still keep forwarding closed before this service
starts. No current command enables it.

`make kernel-service` exercises this composition with a root-owned persistent
store, a real UID-65534 client and the actual nftables backend. Native UDP
packets verify both IPv4/IPv6 initiation directions, correlated replies,
account-disable revocation and shutdown. Startup restores stored classifiers
without permits, and missing/corrupt state rejects while existing kernel
history is retained. The fixture's extra `SETUID` capability switches only the
test client's identity; it is not a production helper requirement. The bindings
remain synthetic and do not establish actual association or address ownership.

Both callbacks receive independently owned `state.Classification` slices for
MACs, IPv4 and IPv6. `Seal` must clear only owned permits and union these
classifiers into the existing guard; an empty startup/stop handoff must not
flush historical classification. Startup passes all validated persisted
classifiers before accepting requests. A failed restore prevents startup.
Failure cleanup also supplies newly observed classifiers if their durable
write failed, including failure after rename. Fixed guarded preparation can
restore this history and clear all lease mirrors; the current executable cannot
apply those transactions. The signed boot path must still prevent traffic before
restoration. Helper tests prove the handoff and ordering; isolated kernel tests
exercise the restore transactions, not production cold-boot packet protection.

Directory responses contain only schema, shadow/applied/rejected status, a fixed error
code, baseline hash, compilation time and grant/denial counts. The maximum
response is 64 KiB. Backend error text never becomes a response. A `shadow`
receipt is not permission and does not prove a kernel transaction occurred.

### Read-only operator status

The status server uses a separate supervisor-owned Unix socket and a distinct
non-root operator UID. The guarded service rejects root and its directory-reader
UID for that role. Both sides verify filesystem ownership and `SO_PEERCRED`.
Socket-group membership does not grant either UID's authority. The supervisor
must cancel and join the status server before closing backend/store resources.

Its only request is `{"schema_version":1,"operation":"status"}`, bounded to
512 bytes. A directory submission, reset, extra field or other operation cannot
reach either processor. Responses are bounded to 64 KiB and contain no raw
directory attributes, device IDs/MACs/addresses, policy reasons, file paths or
backend error text. Contributor group/rule IDs are limited to 128 distinct
pairs with explicit truncation; fixed denial codes are deduplicated. Those IDs
are operator diagnostics and must remain in private operational logs.

The engine copies cached successful-decision diagnostics under its transaction
gate. Querying status does not load/save state, read bindings, advance its clock,
seal or apply. Countdown calculation clips UTC expiry by the original elapsed
lifetime. Expired grants disappear from the remaining count without pretending
that a new application occurred. A rollback/missing clock reports `unverified`
and no countdown. `usable` describes this local check, not synchronized-UTC
qualification. Successful sealing clears local countdowns; failed sealing says
`unknown`, never claims that permits were removed, and preserves the last
successful decision for diagnosis. Shadow status never claims an actual apply.

The backend separately acquires the existing writer fence and reads the complete
ruleset through its checked executor. A matching ready generation and exact
paired contract produce `matches_pinned_contract`, a writer sequence and the
observed logical lease-set tuple count. Closed/changed generations, drift or
inspection failure produce `unverified` with no kernel count/sequence. This
query never repairs a floor, changes metadata or revokes/renews a permit.
Engine diagnostics and kernel inspection are separate observations, not an
atomic authorization view; a later writer may invalidate them. Matching objects
do not establish P01–P10 semantics or translated forwarding.

`router-policy-status` is the read-only Linux CLI for this protocol. It requires
an explicit clean absolute socket path, pins the expected helper UID, has one
bounded attempt and prints validated JSON. Exit 0 means a valid report, even
when unhealthy; 1 is query/output failure and 2 is invalid usage. No current
executable enables either service socket. Isolated tests qualify real operator
and writer UIDs, rejection of writes, expiry/rollback and actual backend queries
without modifying state or the drifted external floor.

## State contract

`internal/state` stores only the managed MAC cohort, historical device-address
classifiers, temporary-rule first-seen
times, alias ownership anchors, known network-group IDs, validated clock and
last complete directory timestamp/digest. It does not store credentials, raw
directory records or renewable grants.

The deployment must supply an encrypted persistent filesystem. The store
checks an owner-only directory and private regular files; it does not encrypt
the filesystem or prove its encryption. Directory ancestors must have trusted
owners and no untrusted write access. Symlinks, hard links, special files,
unsafe modes and files over 16 MiB reject. An exclusive process lock prevents
two helpers from owning the same state. Updates use an unpredictable temporary
file, file sync, atomic rename and directory sync. A failed sync never authorizes
a new grant, even if the rename advanced state.

Missing state returns an initialization error. Corrupt or unsafe state cannot
be silently initialized over. First installation needs an explicit initialization
operation; runtime startup must not use it as recovery. Normal updates cannot
erase cohort members, known classifications, first-seen times or alias anchors.
An older directory snapshot cannot restore a permit after a newer denial;
conflicting content at the same observation time also rejects. Repeating an
identical snapshot retains its original observation time and lease.

State schema 2 requires explicit `classified_ipv4` and `classified_ipv6` arrays.
All classifiers are canonical, sorted and unique, bounded to 4,096 MACs and
16,384 addresses per family. Addresses cannot exist without a managed cohort.
Normal updates cannot shrink either family's history; capacity exhaustion
rejects instead of evicting old guards. The helper stores deny-only history,
not address-to-MAC ownership claims. IP reuse needs independently fresh
ownership before a new managed occupant can receive a permit; an unmanaged
occupant cannot use saved history as authorization. Retiring old classifiers
requires a separate reviewed recovery operation, not a reader request.

Schema 1 is rejected. It cannot recover missing historical addresses and is
not automatically converted to empty arrays. Its presence is an unsafe-state
error, not the missing-state initialization condition; installation cannot
silently overwrite it. A future upgrade/recovery workflow must reconstruct and
verify classification while traffic remains closed, retaining original state
and authorization anchors. No runtime upgrade tool is supplied yet.

This durable history still needs a qualified kernel backend and boot ordering.
It does not protect incoming traffic or IP reuse by itself. The helper must
install closed classification before accepting traffic and must persist anchors
before permitting a new candidate. In particular, bindings with no application
grant must remain closed rather than becoming unmanaged after restart.

## Restricted nftables primitives

`internal/firewall` opens a checked, root-owned ELF executable and invokes its
pinned descriptor with fixed arguments and a minimal environment. It never
opens a shell. Output is bounded and drained; raw nftables diagnostics do not
become errors or IPC receipts. Execution has a two-second deadline and bounded
pipe cleanup. The owning signed image still has to authenticate the executable
and its libraries; ownership checks are not release verification.
The executor pins the creating OS thread until the bounded child wait completes:
Linux's parent-death signal follows that thread, which can terminate before its
process ([Go SysProcAttr documentation](https://pkg.go.dev/syscall#SysProcAttr)).

The private renderer takes the helper's immutable authorization and rechecks
its baseline, Untrusted geometry, protected floor, complete endpoint variants and contributor
deadlines. This check does not authenticate directory input or address ownership.
Reader IPC still accepts raw directory snapshots, never candidate grants.

Only eight fixed lease sets in `inet router_policy_agent` can be replaced. The
permanent `managed_macs` set can receive new canonical identities, never a flush
or removal. A transaction cannot change tables, chains, rules, hooks, maps,
routes or includes. Missing objects fail the complete transaction. The renderer's
existing-cohort input is not itself a kernel observation.

Before a prepared mutation, the executor reads and strictly verifies the complete
set-only table. It requires the selected library/schema, positive distinct set
handles, fixed datatypes/capacities and timeout-only lease sets. Permanent cohort
elements cannot carry a timeout. Unknown objects/fields, missing or duplicate
sets, malformed or excessive leases, and grants outside the permanent cohort
reject the observation without returning partial classification. A replacement
can use an existing classified identity or append it in the same atomic update;
the combined permanent cohort must still fit the fixed capacity.

Inspection and mutation share the executor's local gate. This does not fence
another privileged writer or verify immutable rules, hooks and protected paths.
This verifier rejects chains in the set-only table. The private guarded backend
uses a separate fixed chain/rule schema and complete reviewed-ruleset comparison;
it does not relax this verifier to allow arbitrary objects. Library metadata
checks establish format compatibility, not release authenticity. The owning
signed image and packet-path auditor remain required.

Each tuple contains interface, MAC, device address, peer address and destination
port. Direction, family and TCP/UDP protocol select the fixed set. The selected
nftables 1.1.3 build misrepresented the first datatype of a six-field tuple, so
protocol is separated into immutable set identity. Future matching rules must
explicitly check the corresponding protocol before lookup; names alone are not
an enforcement mechanism.

Rendering retains every compatible native/NAT counterpart and unions overlapping
tuple deadlines. Each remaining lifetime comes from the original authorization,
not a UTC-only snapshot or a fresh age anchor. Timeout values use JSON seconds,
rounded down after subtracting two seconds for preparation and 2.25 seconds for
execution/cleanup. A batch must
start inside that preparation window, checked after queueing, inspection and
validation. A private monotonic reading captured before rendering bounds elapsed
preparation independently of UTC metadata; the wall-clock window is also checked.
UTC conversion strips Go's monotonic reading, so UTC metadata alone is not that
elapsed-time fence ([Go time documentation](https://pkg.go.dev/time#hdr-Monotonic_Clocks)).
Expired preparations or backward clocks reject; insufficient remaining lifetime
rejects the entire replacement. A 90-second fresh grant therefore gets at most
85 seconds in this renderer. The deployed kernel's timeout resolution and maximum
transaction latency still need qualification before activation.

The authorization anchor and preparation fence cover different delays. The
former follows the compiler result into rendering; the latter bounds the
rendered batch's queueing and execution reserve. Neither qualifies UTC
synchronization or suspend/resume behavior on the selected router. The private
guarded backend uses this handoff and has native packet expiry tests; the final
installed packet path still requires qualification.
A UTC timestamp alone cannot establish elapsed authorization age.

`make kernel` runs real set operations in an isolated container. Tests verify
typed compiler output, actual empty/populated schema inspection, element expiry
with permanent cohort retention, schema-drift rejection before prepared mutation,
delayed handoff expiry by the original ownership deadline, failed transaction
rollback and unchanged unrelated objects. These are not packet tests: the fixture
installs no forwarding hooks. Existing-flow cutoff, both
directions, guarded return traffic, binding loss/IP reuse, baseline drift and
translator mapping changes remain activation gates.

## Cooperative writer fence

`hostfs.Fence` pins a private, ownership-checked directory and its empty `.lock`
file. Each operation acquires both a local gate and an exclusive Linux advisory
lock. Queueing and the callback share the caller's deadline, capped at two
seconds; the trusted callback must honor cancellation. The fence rechecks file
metadata and directory/lock identity before and after the callback. Replacement
invalidates that fence rather than following a different lock inode. Closing
does not remove the shared lock file. Integration tests prove separate-process
exclusion and lock release after the holder is killed.

The privileged generation gate reads only `generation.json` in that checked
directory. Its bounded, strict schema requires a version, positive sequence,
canonical floor/mapping hashes and explicit readiness. It checks an exact ready
generation before and after its callback. Missing, unsafe, closed or mismatched
metadata prevents the callback from starting. A changed generation cannot renew
the original authorization or reset a prepared batch's elapsed-time fence.

The owning-writer coordinator holds that same fence for the entire transition:

1. Check the exact previous record, reserve two increasing sequences, and
   atomically publish a closed record with the previous hashes.
2. Revoke old application permits before the owned update callback can change
   a mapping or protected path. Keep historical deny classification intact.
3. Run the independent audit callback, check its observed hashes against the
   reviewed target, and publish a new ready record at the second sequence.

Each publication writes an owner-only temporary file, syncs it, renames only
the fixed record, then syncs the pinned directory. The coordinator rechecks its
closed vector between callbacks. Invalid, missing, stale or exhausted state
cannot start callbacks or be initialized automatically. Normal transitions
require ready state. Explicit recovery from an existing closed record repeats
revocation, the idempotent owned update and audit with new sequences; it never
restores an older vector or application leases. Hashes are coordination data,
not permission or proof that the named protected paths exist.

A publication error after rename, or a final fence-check failure, has an
indeterminate outcome: the replacement may already be visible. The coordinator
returns an error and no successful vector; it cannot roll back external state
or promise that every failure leaves a closed record. Owning adapters must keep
permits sealed and independently re-audit before granting again. Tests cover
stage failures, cancellation, drift and explicit recovery after reopening the
gate. An isolated native IPv4/IPv6 fixture uses test-only nftables adapters to
prove that old traffic is blocked before the update callback, readiness does not
restore permits, and classification and unrelated objects remain intact. It
does not retarget a translator or qualify the full protected floor.

The private guarded backend uses the fence and generation checks during
application. An advisory lock cannot restrain a nonparticipating privileged
writer, and a generation record cannot attest kernel rules or translator state.
Actual owning adapters, failure sealing, boot ordering, every privileged writer and independent checks
of protected paths must be integrated and qualified before guarded writes
activate. Deployment paths, hashes and records remain private configuration.

## Reviewed ruleset comparison

`reviewedRuleset` holds a private, independently prepared artifact with exactly
`schema_version: 1` and an `objects` array. This is not the native `nftables`
listing envelope. Artifacts cannot contain runtime handles, counter statistics
or helper-owned objects. The decoder limits input to 4 MiB and 8,192 objects;
it neither loads a file nor authenticates who supplied those bytes. The paired
[profile loader](#pinned-router-profile-loading) checks ownership and an
independently supplied digest; release/pin provenance remains required. Reader IPC
must never carry this artifact. There is no command for learning an expected
contract from the live router.

The executor uses the checked executable descriptor and the fixed read-only
arguments `--json list ruleset`. One listing supplies the surrounding program
and both helper tables. The verifier requires the selected library metadata,
positive unique object handles within each table and a complete inventory. It
checks helper tables using their fixed schema and compares every other table,
chain, set, data map, named counter and rule against the reviewed artifact.
Comments and expression data remain part of that comparison. Unknown objects,
fields or statements, flow offload, verdict maps and unqualified dynamic
collections reject. Empty static sets remain part of the contract; their
contents cannot disappear into an ignored runtime field.

Declaration and static element order are normalized. Rule order within each
chain is preserved. Only actual table/object handles and validated unsigned
packet/byte counter statistics are omitted from policy identity; a field with
the same name elsewhere in an expression is not discarded. Numeric values stay
exact rather than passing through floating-point conversion. Jump/goto targets
must be declared regular chains, with no cycle and a maximum depth of 16.
Standalone input, forward and output drop hooks are required, but do not by
themselves prove a protected floor. Same-priority hooks with overlapping address
families reject, including a reviewed hook competing with the helper's hook.

Successful comparison returns the hash of the observed normalized program and
verified helper inventory. Failure returns no partial observation and makes no
firewall change. This is a point-in-time observation, not authorization or an
automatic sealing operation. Production reads and later mutations must still
hold the shared writer fence, enforce the original lease deadlines and seal
permits on failure. Other privileged writers must participate in that protocol.
Updates to reviewed root-owned sets/maps need independently prepared expected
data coordinated with their owning generation; an observed replacement must
not become its own expectation.

The isolated fixture verifies drift detection and lack of mutation. It is not
the deployment's P01–P10 projection or packet qualification. Release/pin
provenance, independent protection/caller-path checks, writer adapters,
executable/backend integration and actual translator-state verification remain required.

## Pinned router profile loading

`loadRouterProfile` is privileged library plumbing, not an activated service.
It reads only `profile.json` from a clean absolute, root-owned private directory.
The file must be a root-owned regular file with one link and mode `0600` or
`0400`. Symlinks, hard links, special files, unsafe ancestors/permissions and
oversized files reject before decoding. Read size is capped at 8 MiB, metadata
is checked again after reading, and every descriptor closes before return.
Cancellation or any failure returns no partial profile. Printable diagnostics
omit private paths and payloads; trusted callers can still inspect error causes.

The exact bundle schema has `schema_version: 1`, `baseline` and
`reviewed_ruleset`. Nested schemas keep their own tighter limits. Duplicate,
unknown, case-variant or null fields reject. One validated baseline constructs
the immutable compiler/renderer and guard layout; the paired reviewed artifact
supplies the surrounding object contract. Profile inspection uses only those
paired components and the existing fixed read-only executable operation.

| Identity | What it binds |
| --- | --- |
| Image-owned profile pin | Exact serialized bundle bytes, including the catalog and object contract |
| Compiler baseline hash | Validated normalized compiler configuration |
| Observed ruleset hash | Verified normalized surrounding nftables program; helper inventory is checked separately |

The caller must obtain the canonical SHA-256 pin independently from the
verified owning release. Ownership and a checksum supplied beside mutable
profile bytes do not authenticate that release. The loader does not verify
image signatures, learn pins from live state, accept a self-declared digest,
or treat a generation record as provenance. Even equivalent JSON formatting
requires the correct independently supplied pin.

Isolated tests load a root-owned synthetic bundle, inspect real nftables
objects, reject another bundle's guard layout and detect early-accept drift
without changing the firewall. They do not prove that the catalog matches
every P01–P10 packet path. Private projection generation, release/pin
distribution, semantic/packet review, shared writer fencing, translator-state
verification and actual runtime wiring remain required. Production bundles,
pins, endpoint catalogs and evidence stay outside this public repository.

## Packet-field qualification

A separate test-only fixture routes raw UDP packets between two virtual links
inside the empty container namespace. Only the router ends have IP addresses;
endpoint packet taps observe delivery before fixture-only ingress drops prevent
recirculation. All identities and networks are synthetic. Cleanup deletes only
the fixture's tables and links. No production executable can call its helpers.

Both IPv4 and IPv6 tests cover peer/device initiation and correlated replies.
Counters prove that inbound `inet forward` sees the ingress router MAC, not the
device's destination MAC. Final `netdev egress` sees that device MAC. Forward-hook
connection direction, state and original destination port are available, and a
packet mark reaches egress. The selected build rejected direct egress conntrack
queries during qualification; a guarded backend must not depend on them.

After an earlier forward accept, an egress MAC drop blocks an existing flow, a
new flow and an unqualified address on the same device. This does not establish
lease-based authorization, protected-floor ordering, spoof resistance, mapping
coordination or translated return identity. The fixture's broad accepts and
marks are observations, not deployable policy. The final backend still needs
independently checked mark ownership/reset and atomic guard/lease updates.

## Guard layout and atomic mirrors

`guardLayout` generates fixed image-owned rules from a validated, copied router
baseline. It defines an early forward guard, a late `guard_confirm` base chain,
a regular `permit_flow` chain and final Ethernet egress guards on the reviewed
role interfaces. Runtime updates
cannot select rules, hooks, priorities or marks. No current executable installs
this layout or accepts its rule program from the reader.

One logical lease produces three named representations:

| Object | Tuple key | Lifetime |
| --- | --- | --- |
| Forward lease | Interface, MAC, device IP, peer IP, listener port | Bounded lease |
| Incoming projection | Interface, device IP, peer IP, listener port | Bounded lease |
| Final egress mirror | Interface, actual destination MAC, device IP, peer IP, listener port | Bounded lease |
| Managed MAC sets in both tables | Canonical MAC | No timeout or runtime removal |
| Classified IPv4/IPv6 sets | Independently qualified historical device representation | No timeout or runtime removal |

The forward guard checks the initiation direction, protocol, connection state
and original destination listener against a current lease. It checks outgoing
MAC identity directly. Incoming lookup projects the IP tuple because the device
MAC is not visible there; final egress checks that actual MAC against the full
mirror. A projected permit that reaches a different MAC drops, even when that
new MAC is not managed. Unknown addresses on a managed MAC also drop. Historical
classified addresses remain closed rather than falling through a legacy permit.

Per-packet mark bits `0xff00ffff` carry direction and listener to final egress;
the other bits are preserved. The early guard clears its bits on every packet.
The selected build needs two assignments to combine the 16-bit conntrack port
with a 32-bit direction tag. Egress uses the 32-bit `mark` datatype for that
bounded port value; it does not query conntrack. This reservation still needs an
independent audit against every image-owned mark user and privileged writer.

The separate router table cannot jump to a helper-table regular chain. The
image owner instead places the four fixed `guardBridgeRules` provisional tag
accepts after its protected checks and before ordinary application default
deny. The router keeps its default-drop policy. An early guard return alone
does not override that drop ([Netfilter chain ordering](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)).

`guard_confirm`, at forward priority 150, calls `permit_flow` within the helper
table. This rechecks the current lease, protocol, direction, original listener,
interfaces and endpoint tuple after the router's provisional accept. A failed
lookup drops every provisional tag, even if another hook changed the tuple to
an otherwise unclassified address. Untagged managed MACs and historical
addresses also remain closed. The late guard does not clear the provisional tag
before this check: losing it would let a changed, unclassified tuple fall
through. Successful lookup stamps the direction/listener again for final MAC
verification. Unrelated traffic remains subject to the router's own policy.

The image must independently qualify the priority -150 early guard, the
protected paths and provisional bridge between the guards, the priority 150
confirmation and final egress mirrors. These helpers neither install rules in
the router table nor authenticate its protected policy. Other base-chain drops
remain authoritative. Changes after confirmation and userspace translation
need separate qualification; this layout does not prove the complete router
chain graph or reserve marks against every other writer.

`prepareGuards` retains the logical renderer's original preparation fence and
derives all 24 lease sets as one transaction. MAC additions are mirrored into
both permanent cohort sets; observed device representations append to permanent
address classification. Projection duplicates retain the longest valid lease;
final mirrors keep each exact MAC and its own deadline. `validateGuardBatch`
reconstructs these mirrors and rejects missing or changed counterparts, altered
timeouts, extra operations and permanent-set removal. All compiler-derived
native/NAT representations remain in the transaction; retaining them is not
proof of their translated packet path.

The native fixture compiles fresh synthetic directory/binding input, renders
the immutable authorization and applies its validated mirrors. It routes real
IPv4/IPv6 TCP handshakes and UDP datagrams through a separate router table.
With its stateful shortcut disabled, counters prove all four direction tags
use the bridge; removing the bridge blocks new traffic despite a current lease.
An independent protected endpoint/port drop blocks previously working UDP
flows before the router's established shortcut. Neighboring TCP/UDP listeners
receive no inherited permit. Explicit revocation blocks existing
TCP/UDP traffic in both initiation directions before the fixture's established
accept; UDP kernel expiry also blocks a previously working flow. Separate cases
check reverse-initiation denial, unknown addresses behind a legacy permit,
changed destination MACs with and without a live lease, and an unrelated legacy
flow that still works. Test-only fault rules delete the queried lease between
the early and late hooks while leaving final mirrors live. Counters prove all
four directions reach that fault and none passes confirmation. This deliberately
inconsistent fixture tests revalidation; production updates still require
atomic replacement of every mirror and do not mutate leases from packets.

A further fixture rewrites the device address after the bridge while retaining
the provisional tag. Counters distinguish late-guard rejection from final MAC
or checksum handling. Linux restricts payload writes in user namespaces
([kernel payload implementation](https://github.com/torvalds/linux/blob/master/net/netfilter/nft_payload.c));
that fixture reports a skip in a rootless runner. CI sets
`ROUTER_POLICY_REQUIRE_HEADER_TEST=1`, passed through `make kernel`, so inability
to exercise the header-changing case fails the job. No host networking or
additional container capabilities are permitted for it. These are synthetic
ownership records, not a qualified NAS or address collector.

Permanent kernel sets survive lease replacement and expiry, not reboot by
themselves. Restoring saved classifiers is tested separately below. Closed boot
ordering, actual owning-writer integration and executable/backend wiring are
still required.
Related ICMP/PMTU and other required control traffic need explicit reviewed
paths; they must not be enabled by a broad bypass. P01–P10 ordering, all-role
Security tests, synchronized UTC/suspend behavior, DSR and native/translated
return correlation remain activation gates. No production deployment is
authorized by these fixtures.

### Historical restoration and sealing

`prepareClassifiedGuards` accepts the helper-owned `state.Classification` handoff
and retains an independently owned, validated copy. Every rendered leased MAC
and device address must already be in that saved history. Restoring classifiers
cannot manufacture a lease, change its deadline or reset the renderer's original
preparation fence. The reader still cannot submit this state through IPC.

`prepareGuardSeal` atomically flushes all 24 owned lease mirrors and appends the
saved MAC cohort to both tables and saved IPv4/IPv6 addresses to their permanent
sets. It works with zero grants. An explicit empty handoff clears leases without
removing any existing classifier. Neither operation can change rules, tables,
hooks, marks, routes or maps, or expire/delete a permanent identity.

The prepared validator regenerates the entire fixed transaction against its
retained state. Extra addresses, omitted classifiers, timeout-bearing history
and changed mirrors reject. Raw guarded validation does not gain permission to
restore independently supplied history. Inventory checks bound the union of
existing kernel classifiers and saved additions; capacity exhaustion rejects
rather than dropping old protection.

Isolated kernel tests cover zero-grant restore, repeated idempotent additions,
compiler-expanded counterpart retention, clearing live leases, restoration
after recreating only the owned tables and unchanged unrelated objects. A native
packet fixture reassigns a historical IPv4/IPv6 address to an unmanaged MAC:
restored classification denies both initiation directions before a legacy
permit, while a never-classified address on that same MAC remains unaffected.
These fixtures do not prove translated packet correlation, storage-to-boot
traffic ordering or the production protected floor. The private guarded backend
uses these transactions; no current command can activate them.

### Owned guard inspection

`guardLayout.inspect` verifies both tables against fixed code-owned schemas
derived from the validated root interface geometry. It checks every set type,
capacity and timeout flag, chain hook/device/priority/policy, ordered rule
expression, mark mask, conntrack direction/listener and verdict. Chain, set and
rule handles must be positive and unique within their table; table handles have
a separate namespace. Unexpected objects
and extra, missing or reordered rules reject the whole observation.

Inspection reconstructs projections and final-egress mirrors from the full
tuples. Their keys and configured lifetimes must match; remaining expiry seconds
can differ between separately observed tables. Every live tuple needs permanent
MAC/address classification and an approved Untrusted interface. Historical
addresses may remain after grants disappear. Replacement checks retain those
classifications and enforce cumulative MAC/address capacity before admitting
additional identities or representations.

`process.inspectGuards` uses the pinned executable, two fixed read-only argument
vectors, bounded output and the existing local command gate. Actual kernel tests
cover empty/populated tables, compiler-derived counterparts, revocation with
classification retention, missing mirrors and extra rules. Counterparts in a
listing are not proof of translated forwarding.

These reads are not an atomic kernel-generation snapshot. A lease expiring
between them can cause a mirror mismatch; inspection fails closed and may be
retried without renewing authorization. Nor does this schema attest the
surrounding protected chain graph or coordinate other privileged writers.
The private guarded backend instead obtains one complete listing under the
shared writer fence. These separate diagnostic reads cannot authorize updates.

### Guarded backend

The private Linux backend requires a paired pinned profile, checked executor,
shared writer fence, root-owned expected generation and helper-owned clock.
The expected ready generation must name the independently reviewed floor hash;
neither a live listing nor a reader request can supply that expectation.
Construction does not authenticate release provenance, qualify P01–P10, verify
actual translator state or establish that other privileged writers participate.

Application holds the writer fence and executor gate while reading and checking
the complete ruleset, rendering the immutable authorization with its original
age, checking cumulative classification capacity and committing every mirror.
It captures the complete post-commit listing before releasing both gates, then
fully validates those owned bytes before reporting success. This receipt is
evidence at that fenced point, not a reusable permit. A cooperating later writer
must revoke before changing its owned floor or mappings. No deadline is extended
to accommodate inspection, queueing or validation.

Every application failure attempts sealing with an independent two-second
cleanup deadline, including canceled requests and changed generation metadata.
Cleanup failure remains part of the returned error; callers cannot report an
applied policy or reopen readiness. Sealing still needs the shared fence and
exact fixed guard rules/objects, but does not require a ready generation or an
unchanged external floor. Inconsistent or expired lease mirrors cannot prevent
their removal. Both permanent MAC mirrors and saved address history are retained
as a validated, capacity-bounded union. Cleanup cannot repair external tables,
delete historical classification, create guards or open boot forwarding.

Only privately prepared transactions reach the two fixed guarded operations.
The raw executor cannot submit them. A sealing transaction has no authorization
clock and can contain only mirror flushes and permanent deny-only additions;
it cannot add or renew a lease. Commands still use the pinned executable, fixed
argument vectors, restricted environment and bounded output.

An independently authored native router fixture exercises this actual backend,
not a test-only mutation adapter. Packet tests cover IPv4/IPv6 initiation and
replies, retained classification, cancellation, invalid authorization, closed
generation, external floor drift and expiry during continuous traffic. Existing
flows stop before the stateful shortcut; external drift is left untouched.
The fixture's bridge is not the production protected-policy projection. Actual
writer cooperation, authenticated collectors, boot ordering, UTC/suspend and
translator identity remain unqualified, and executable wiring is still absent.

## Checked helper configuration and ownership

Private helper wiring reads exactly `helper.json` from an explicitly selected
root-owned private directory. The file must be a bounded regular file, have one
hard link, and use mode `0400` or `0600`; symlinks, FIFOs and unsafe metadata
reject. Its schema is strict, including nested objects, required fields, nulls
and duplicate keys. Nothing is learned from a live listing or an adjacent file.

All configuration fields are required:

| Field | Contract |
| --- | --- |
| `schema_version` | Exactly `1` |
| `profile.directory`, `profile.sha256` | Private profile directory and independently supplied canonical SHA-256 pin |
| `generation_directory` | Private root for the cooperative writer fence/record |
| `expected_generation` | Exact schema-1 ready vector: sequence, reviewed floor hash and mapping hash |
| `state_directory` | Private, encrypted persistent state provisioned by the deployment owner |
| `nft_executable` | Clean absolute path opened through the checked ELF descriptor loader |
| `reader_uid`, `operator_uid` | Distinct non-root identities, separately authenticated through kernel peer credentials |
| `request_timeout_ms` | Integer from `1` through `10000`; no default or timeout extension |
| `request_socket`, `status_socket` | Distinct clean absolute Unix-stream paths, each at most 107 bytes |

Private resource directories cannot overlap one another or contain either
socket. Paths cannot contain control characters. File ownership does not
authenticate an owning release or prove storage encryption; deployment must
qualify those properties separately. The expected vector is trusted input, not
a declaration that the current writer record or translator state is ready.

Resource opening retains the checked executable, writer fence and exclusive
state lock without executing commands, sampling time, reading bindings or
initializing state.
Partial failure closes previously opened resources. Configuration contains no
clock override, state-reset option, binding fixture, firewall program or hook
selection. A separate qualified binding producer remains mandatory.

The configured runner adopts two supervisor-created listeners only when their
paths match its configuration. Closed startup restores durable classification
before either server accepts a request. Each server has its own authorized UID;
failure of either cancels the other. The runner joins both servers, performs
bounded sealing, closes both descriptors without unlinking their paths, then
releases its state lock and backend resources. It never creates sockets or
initializes missing history.

Isolated tests run this configuration-to-backend path with real non-root reader
and operator clients. Native IPv4/IPv6 initiation/reply traffic is permitted
after a fresh transaction and revoked when the status listener fails, without
parent cancellation. State remains deny-only and the exclusive lock is released.
The lower-level test assembler supplies a controlled clock projection; these
packet tests neither change nor depend on the host's synchronization state.
These fixtures do not qualify real bindings, release/pin provenance, encrypted
storage, boot ordering, synchronized time or translated forwarding. No installed
helper executable or production configuration is supplied yet.

## Denial-only recovery

`router-policy-recover -config-directory PATH` performs one fixed root-only
operation: seal all existing agent-owned application lease mirrors and restore
validated deny-only classification. Build it with `make build`; there is no
installed configuration or guard layout supplied for a real router yet.

Stop the owning helper through the deployment's approved service procedure
before recovery. The command acquires the same exclusive state lock and refuses
an existing owner. It never stops a service, adopts/unlinks sockets, reads LDAP
or bindings, refreshes grants, changes routes/maps, or flushes conntrack. Its
scope is all helper-owned application grants, not a per-device rollback or
restoration of legacy permits.

Recovery uses the checked profile, ELF descriptor and shared writer fence.
It revokes current leases before loading history, then restores saved MAC and
both-family address classifiers without granting access. Existing kernel
classifiers are retained in the union. The durable file, temporary deadlines,
alias anchors and observation watermarks are not written. Neither a ready
generation record nor a usable clock is required to revoke; drift in external
tables is left untouched. This is not repair or verification of that floor.

Missing or corrupt history makes recovery fail even if existing leases were
successfully sealed. It is never initialized, overwritten or reconstructed.
Missing/damaged guard schemas, an unavailable state lock/fence or failed nftables
inspection also return failure; immediate sealing cannot be assumed. Keep
enforcement stopped and use the separately reviewed recovery procedure. The
command cannot repair unsafe/missing resources, restore lost history, authorize
a canary rollback or qualify signed A/B image recovery.

`-timeout` defaults to five seconds and accepts durations greater than zero and
at most ten seconds. Cancellation/failure after resources open triggers a
separate two-second sealing attempt, followed by separately bounded resource
closure. JSON goes to stdout only on verified owned sealing with valid history;
`floor_state` remains `unverified`. Exit codes are 0 for that scoped result, 1
for unsuccessful/unverified recovery or output failure, and 2 for invalid
arguments. Fixed stderr messages exclude private paths and upstream diagnostics.

The isolated test builds and invokes the real CLI, denies an unprivileged
caller, refuses a live store owner and respects a deliberately stalled writer
fence. Native IPv4/IPv6 initiation and correlated replies stop after recovery;
an unrelated established flow still passes. Tests retain exact durable bytes,
restore recorded classifiers, seal despite floor/generation drift, leave broken
history intact and reject guard-schema drift without claiming recovery. They
do not qualify production boot, translation or release provenance.

## Linux synchronization check

The configured entry point fixes its clock source to a fresh Linux `adjtimex`
query with all adjustment fields zero. It never changes clock parameters or
requests `CAP_SYS_TIME`. No configuration, environment variable or reader input
can replace this source. See the [Linux API contract](https://man7.org/linux/man-pages/man2/adjtimex.2.html).

Only `TIME_OK` with no unsynchronized, hardware-fault or pending-leap status
flags supplies a usable UTC sample. Syscall errors and other states return an
invalid clock. Timestamp fields are range-checked before conversion, including
the kernel's microsecond/nanosecond resolution flag; invalid fractions are not
normalized into another second. The engine and renderer reject the invalid
sample through their existing clock checks.

An unsafe startup sample leaves grants sealed and closes both adopted
listeners. An unsafe sample during a directory transaction rejects that
transaction and attempts bounded sealing, retaining deny-only classification.
Native IPv4/IPv6 packet tests exercise that request-triggered revocation through
an actual non-root reader. Separate integration tests exercise the real
read-only kernel query without requiring a synchronized test host.

This is not continuous clock monitoring. A status query stays read-only, and a
clock failure without another transaction does not immediately remove existing
permits; their original kernel deadlines still apply. Kernel synchronization
flags do not identify or authenticate the time reference, establish UTC accuracy,
or qualify suspend/resume and cold-boot packet ordering. Those checks remain
activation gates; status reports do not claim they passed.

## Verification

`make integration` exercises actual Unix sockets and, in an isolated root runner,
a subprocess running as an unprivileged UID. It checks wrong-reader/wrong-helper
identity, malformed schemas, backend-error redaction and cancellation. State
tests cover exclusive ownership, restart, clock/directory rollback, loss of an
account, immutable anchors and unsafe filesystem objects. Fuzz tests cover
request framing, schema decoding and state round trips.

Engine tests cover transaction ordering, persisted observation before binding
failure, replay, non-renewable leases, canceled requests, startup/restart and
partial backend failures. Deterministic elapsed-time tests reproduce and reject
cross-request clock rollback, require fresh directory/ownership evidence after
restart, and check recovery and future-evidence rejection. Clock fuzzing checks
that accepted time never understates UTC or monotonic age. Handoff tests cover
sampling/persistence/queueing delays, deceptive UTC, shorter ownership deadlines,
overlapping contributors, non-restorable anchors and independent snapshots.
Compiler cancellation tests discard whole candidates;
the capacity test exercises 4,096 synthetic identities and the 65,536-entry
ledger without copying that ledger for each device. These are model and library
tests, not native packet tests of an enforcement backend.

All fixtures are synthetic. Deployment addresses, device identifiers, secrets,
private inventories and operational captures must stay outside this repository.
