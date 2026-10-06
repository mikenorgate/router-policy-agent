# Local transport and durable state

These packages implement the helper boundary, not a working firewall service.
No current command starts the transport or updates nftables. Guard layouts are
exercised only by isolated test fixtures, not a production backend. The remaining
runtime and packet tests are listed in [the activation gates](architecture.md#implementation-gates).

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
collection fails. Compilation saves immutable expiry/alias anchors before
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
not proof of packet revocation. Restricted nftables primitives exist separately;
the callbacks do not yet wire them into a guarded backend. No executable
currently wires these components together; qualified binding collection,
kernel enforcement, translation coordination and packaging remain unfinished.

Responses contain only schema, shadow/applied/rejected status, a fixed error
code, baseline hash, compilation time and grant/denial counts. The maximum
response is 64 KiB. Backend error text never becomes a response. A `shadow`
receipt is not permission and does not prove a kernel transaction occurred.

## State contract

`internal/state` stores only the managed MAC cohort, temporary-rule first-seen
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

This durable MAC list still needs a kernel guard and qualified address ownership.
It does not protect incoming traffic or IP reuse by itself. The helper must
install closed classification before accepting traffic and must persist anchors
before permitting a new candidate.

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
The current verifier rejects chains in this set-only table: the final guarded
table needs a separately reviewed chain/rule schema, not an exception allowing
arbitrary objects. Library metadata checks establish format compatibility, not
release authenticity. The owning signed image and packet-path auditor remain
required.

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
synchronization or suspend/resume behavior on the selected router. The final
guarded backend must use this handoff and pass end-to-end packet expiry tests.
A UTC timestamp alone cannot establish elapsed authorization age.

`make kernel` runs real set operations in an isolated container. Tests verify
typed compiler output, actual empty/populated schema inspection, element expiry
with permanent cohort retention, schema-drift rejection before prepared mutation,
delayed handoff expiry by the original ownership deadline, failed transaction
rollback and unchanged unrelated objects. These are not packet tests: the fixture
installs no forwarding hooks. Existing-flow cutoff, both
directions, guarded return traffic, binding loss/IP reuse, baseline drift and
translator mapping changes remain activation gates.

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
baseline. It defines an early forward guard, a regular `permit_flow` chain and
final Ethernet egress guards on the reviewed role interfaces. Runtime updates
cannot select rules, hooks, priorities or marks. No current executable installs
this layout or accepts its rule program from the reader.

One logical lease produces three named representations:

| Object | Tuple key | Lifetime |
| --- | --- | --- |
| Forward lease | Interface, MAC, device IP, peer IP, listener port | Bounded lease |
| Incoming projection | Interface, device IP, peer IP, listener port | Bounded lease |
| Final egress mirror | Interface, actual destination MAC, device IP, peer IP, listener port | Bounded lease |
| Managed MAC sets in both tables | Canonical MAC | No timeout or runtime removal |
| Classified IPv4/IPv6 sets | Previously permitted device representation | No timeout or runtime removal |

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

The later permit chain rechecks the lease instead of treating a cached mark as
authorization. The image must call it in the same table after protected checks
and before ordinary application default deny. Other base-chain drops remain
authoritative. This project has not yet integrated or independently verified
that complete router chain graph.

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
IPv4/IPv6 TCP handshakes and UDP datagrams. Explicit revocation blocks existing
TCP/UDP traffic in both initiation directions before the fixture's established
accept; UDP kernel expiry also blocks a previously working flow. Separate cases
check reverse-initiation denial, unknown addresses behind a legacy permit,
changed destination MACs with and without a live lease, and an unrelated legacy
flow that still works. These are synthetic ownership records, not a qualified
NAS or address collector.

Permanent here means surviving lease replacement and expiry, not reboot.
Durable address restoration and closed boot ordering are still required, as
are the guarded-table schema verifier, writer fencing and executor wiring.
Related ICMP/PMTU and other required control traffic need explicit reviewed
paths; they must not be enabled by a broad bypass. P01–P10 ordering, all-role
Security tests, synchronized UTC/suspend behavior, DSR and native/translated
return correlation remain activation gates. No production deployment is
authorized by these fixtures.

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
