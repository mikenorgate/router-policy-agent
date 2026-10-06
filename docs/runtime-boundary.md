# Local transport and durable state

These packages implement the helper boundary, not a working firewall service.
No current command starts the transport or updates nftables. The remaining
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

The enforce-mode callbacks are a contract for a trusted, restricted backend,
not an implementation of nftables or proof of kernel revocation. No executable
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

## Verification

`make integration` exercises actual Unix sockets and, in an isolated root runner,
a subprocess running as an unprivileged UID. It checks wrong-reader/wrong-helper
identity, malformed schemas, backend-error redaction and cancellation. State
tests cover exclusive ownership, restart, clock/directory rollback, loss of an
account, immutable anchors and unsafe filesystem objects. Fuzz tests cover
request framing, schema decoding and state round trips.

Engine tests cover transaction ordering, persisted observation before binding
failure, replay, non-renewable leases, canceled requests, startup/restart and
partial backend failures. Compiler cancellation tests discard whole candidates;
the capacity test exercises 4,096 synthetic identities and the 65,536-entry
ledger without copying that ledger for each device. These are model and library
tests, not native packet tests of an enforcement backend.

All fixtures are synthetic. Deployment addresses, device identifiers, secrets,
private inventories and operational captures must stay outside this repository.
