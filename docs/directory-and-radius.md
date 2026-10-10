# Directory collection and RADIUS evidence

These are separate trust boundaries. Authentik supplies active identities,
original groups and group policy. RADIUS supplies the agent's network-session
evidence. Neither source can grant control over the router-owned protected
floor, and a directory read cannot establish network ownership.

## Directory collection

`internal/directory` provides the read-only collector used by the Linux reader
command. It does not install a service. `New` accepts private connection
configuration and a cancellable credential callback. `Collect` opens a new
connection and obtains credentials
again on each call; it caches neither credentials nor directory entries.
Concurrent calls use separate connections. A shared credential callback must
itself be safe for concurrent use and honor its context.

By default, only explicit `ldaps://host:port` endpoints are accepted. TLS verifies both the
certificate chain and hostname, using system roots or a cloned deployment CA
pool, with TLS 1.2 as the minimum. There is no disabled-verification option,
plaintext fallback, referral following or StartTLS implementation. Connection, bind and
all searches share a deadline of at most ten seconds. Cancellation closes the
socket and joins LDAP cleanup. Errors expose a fixed collection failure and,
where applicable, cancellation, not server diagnostics or private endpoints.

A deployment may explicitly set `PlaintextUntil` for a temporary LDAP test.
This accepts only `ldap://` with a private or loopback literal IP, no IPv6 zone
or mapped address, no custom CA, and an expiry within 24 hours of startup.
It is not selected after a TLS failure. Expiry is checked before credentials,
caps the connection deadline, and is checked again before returning a snapshot.
Credentials and directory data are unencrypted on this path. Expiry stops new
collection; previously accepted grants keep their normal, independently bounded
lease deadlines. This exception does not qualify production TLS or source authority.

The collector performs one-level paged searches below `ou=groups` and
`ou=users` in one configured provider base. Each group remains an individual
entry; the collector never uses merged user attributes as group policy. It
uses Authentik's `uid`, `cn`, object classes, `ak-active`, `member` and
`memberOf` fields, and the group's `network_policy_v1` attribute. These fields
are described in the [Authentik LDAP provider documentation](https://docs.goauthentik.io/add-secure-apps/providers/ldap/).

The collection contract is strict:

- Paging is critical. Every successful page must carry exactly one paging
  response control. Missing controls, referrals, repeated/oversized cookies,
  duplicate entries or any LDAP error reject the entire collection, including
  entries returned alongside a size-limit error.
- Device subjects are accounts whose names parse as canonical Ethernet MACs.
  Other account names are not device subjects. Device status must be exactly
  `true` or `false`; inactive devices remain inputs for the compiler's denial.
- Stable IDs must be unique within their namespace. MAC subjects must be
  unique. Names must match entry DNs in the expected namespace. Duplicate or
  multi-valued identity/status/policy attributes reject collection.
- Direct memberships must agree in both directions between the user and the
  original group. Missing references and inconsistent nested-group edges reject
  collection. Parent policy is not flattened into device policy. A device's
  own virtual group is ignored, never used as a policy contribution.
- Malformed group-policy JSON is retained for the compiler's device denial;
  it is not silently discarded to authorize from the remaining groups. Names
  beginning `vlan-`, `trusted-`, `guest-`, `untrusted-`, `infrastructure-`,
  `security-` or `assessment-` mark a group as network-related when its
  attribute is missing. These case-sensitive reserved prefixes grant nothing;
  policy still uses stable group IDs.

Configuration caps groups at 8,192, accounts at 4,096 and page size at 256.
The account quota counts non-device accounts too. BER responses are limited
to 2 MiB per message and 32 MiB per connection, with local depth/node limits
checked before the dependency parses them, including BER embedded in paging
controls. Limits also cap aggregate nodes across the connection. Unsupported
controls reject collection. Entry attribute data is limited to
1 MiB, each attribute value to 16 KiB, and the typed snapshot to 16 MiB.
Exceeding a limit returns no snapshot rather than a permitted subset.

`ObservedAt` is sampled before credential retrieval and dialing, so the time
spent collecting consumes authorization lifetime. Successful paging means
all requested reads finished; it is not an LDAP database transaction or proof
that no account changed during collection. Membership consistency checks catch
some concurrent changes, not every concurrent policy edit. Normal bounded
refresh/revocation requirements still apply.

### Qualification before integration

The loopback tests prove the client behavior, not the installed provider's
authority or freshness. Before connecting this library to enforcement:

1. Verify the existing scoped identity can read the complete intended account
   and original-group namespace without directory administration privileges.
   A restricted partial view cannot be accepted as a complete policy source.
2. Verify the provider uses fresh direct searches. A stale outpost cache read
   cannot be stamped as a new authorization observation.
3. Independently review effective group/user attribute-write permissions.
   Authentik permits custom attributes to overwrite built-in LDAP attributes;
   client-side shape checks cannot prove that a well-formed `uid`, active flag
   or membership came from an authoritative field. Reserved identity/status/
   membership overrides must be excluded upstream. Verify nested-group and
   virtual-group behavior against the direct-membership contract.
4. Test account disablement, group/rule removal, absent policy, certificate and
   credential rotation, partial reads and outages through the final runtime.
   Collection failure must not refresh an old permit.

Provider configuration, credentials, CA material and these operational records
remain private. This library does not change provider settings or permissions.

## Reader command

Build `cmd/router-policy-reader` with `make build`, then run it under the
separately provisioned non-root reader identity:

```sh
router-policy-reader -config-directory /run/router-policy-agent-reader
```

This command requires a separately installed helper. It does not create a socket,
start a helper, reset state or install firewall rules. The helper, not the reader,
selects shadow/enforce mode and obtains bindings and protected configuration.
Deployment and source qualification are still required before enabling grants.

The private directory must belong to the reader UID, have no group/other access,
and have trusted non-writable ancestors. The process refuses root or differing
real/effective UIDs. Files must be single-link regular files owned by the same
reader UID with mode `0400` or `0600`; symlinks, special files and executable or
shared-readable files are rejected. A deployment supervisor must provision this
directory rather than granting the process access to privileged configuration.

`reader.json` accepts exactly these required fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Must be `1`. |
| `directory_url` | Explicit verified `ldaps://host:port`, with no credentials, path, query or fallback. |
| `base_dn` | The separately authorized provider namespace. |
| `helper_socket` | Clean absolute request-socket path, at most 107 bytes. Its filesystem ownership and root peer UID are checked before sending. |
| `custom_ca` | If true, use only the checked `ca.pem` in this directory; otherwise use system roots. |

The optional `plaintext_until` field must be a UTC RFC3339 timestamp ending in
`Z`. A nonempty value enables only the bounded private-literal-IP exception
above and requires `custom_ca: false`. Omission or an empty string keeps the
verified-LDAPS default. Null, malformed, expired and overlong exceptions reject.

The file is capped at 16 KiB. Unknown, duplicate, case-variant, missing and null
fields reject startup. There are no environment overrides or command-line secret,
binding, time, mode or protection switches. `ca.pem` is capped at 64 KiB and 32
certificate authorities; non-certificate content rejects rather than being
silently ignored. Configuration and CA trust are loaded once; restart the reader
after an approved change. The directory descriptor stays pinned for its lifetime.

The supervisor supplies `credentials.json` with exactly `bind_dn` and `password`
string fields, capped at 8 KiB. The reader reopens this fixed file for each
collection. Rotate it by replacing the file atomically inside the pinned
directory, not by replacing the directory or introducing a symlink. Project
secrets from the platform's credential mechanism or protected encrypted private
storage; never commit them or bake them into an image. Clearing the input byte
buffer is not a guarantee that the Go/LDAP runtime erases all secret copies.

The first poll starts immediately. Subsequent polls target 30 seconds from the
previous attempt's start, without overlap or catch-up bursts. Collection and
submission share one ten-second deadline. Search caps remain 256 entries per
page, 4,096 accounts and 8,192 groups. The helper independently rechecks the
snapshot, original observation age, authoritative bindings and protected floor.
The reader never caches a snapshot, resets its observation time, retries a lost
receipt or submits a partial collection. A failed poll grants nothing new; old
permits expire under the helper's independently enforced lease.

Runtime stdout is unused. Stderr receives one JSON outcome per completed
attempt: `collection_failed`, `submission_failed`, `rejected`, `shadow` or
`applied`, with bounded grant/denial counts. Shadow is not application access;
applied is a transaction receipt, not independent protected-floor acceptance.
No identities, addresses, policies, credentials or raw backend errors enter these
diagnostics. A diagnostic-write failure stops the reader. SIGINT/SIGTERM cancel
and join in-flight collection/submission. Exit 0 means help/version or orderly
cancellation, 1 means startup/runtime failure, and 2 means invalid arguments.

Tests cover bounded file parsing, atomic credential rotation, shared deadlines,
failed-read/lost-receipt recovery, fixed diagnostics and cancellation. An isolated
root test runner also launches the configured command as UID 65534 against an
in-memory synthetic TLS directory and a root-owned UID-checked helper socket.
That fixture verifies original group/inactive identity delivery, TLS rejection
before submission and helper rejection without leaking errors. It does not
qualify a production directory, a binding producer or the final firewall path.

The reader protects two boundaries: credential-bearing directory transport and
directory data crossing to the root helper. Verified TLS, checked private files,
fresh single-use submissions and kernel peer identity checks address substitution,
replay and diagnostic disclosure. Directory authority and privileged-helper
enforcement remain separate qualification gates; this command cannot prove them.

## RADIUS-only network evidence

Access points connect to the existing RADIUS service. The policy agent has no
UniFi/controller client and needs no controller account, API token or inventory
lookup. NAS identity, current session, actual VLAN and qualified IP ownership
must reach the agent through a router-trusted RADIUS-side integration. This
document specifies that integration; it does not claim a producer exists yet.

An Access-Accept is an authorization/placement reply, not proof that the NAS
applied the VLAN or that the device currently owns an address. A plain `radutmp`
or accounting-log reread is not a fresh observation either. The RADIUS-side
producer must preserve the original evidence times and expiry bounds rather
than renew them when exporting a snapshot.

[RADIUS accounting](https://www.rfc-editor.org/rfc/rfc2866.html) provides session
identifiers and Start/Stop records. Qualify fresh Interim-Update reporting and
the actual NAS attributes before relying on it. The integration must:

- Authenticate and authorize the NAS source at RADIUS, then authenticate the
  local export to the agent's privileged binding consumer. A directory writer
  cannot forge network evidence.
- Tie the canonical MAC, NAS and unique session identity to a current actual
  VLAN observation, not only a requested placement attribute.
- Handle Start, fresh Interim-Update, Stop, roaming, NAS restart, lost/delayed
  messages and session-ID reuse conservatively. Stop or conflicting evidence
  withdraws authorization; a replay cannot create a fresh lease.
- Deliver address ownership with source, original observation time, ownership
  identity and validity deadline. Verify the NAS reports the required address
  data rather than assuming that accounting includes it.
- Qualify native IPv4 and every permitted native IPv6 address, including
  address changes. [RFC 6911](https://www.rfc-editor.org/rfc/rfc6911.html) defines
  additional IPv6 RADIUS attributes; their presence in a standard does not
  establish AP support or complete reporting of SLAAC/privacy addresses.
  Prefix delegation or an NDP observation alone does not identify one device's
  current host address.
- Reject unknown address ownership, duplicate owners, conflicting sessions,
  unavailable VLAN evidence and expired observations. NAT counterparts come
  from reviewed translation maps, not independent fabricated ownership.

If accounting lacks a required field, source qualification remains incomplete.
Do not substitute controller access, inferred VLANs or guessed IPv6 ownership.
Any additional corroboration must be qualified on the RADIUS side and exposed
through that same trusted interface; it must not quietly add another agent
integration. NAS authentication also does not make a spoofable MAC into a
cryptographic device identity. Access-layer anti-spoofing remains a separate
router-owned requirement.

Enabling live accounting, choosing export credentials/identities and changing
NAS or router configuration require a separate reviewed deployment step. The
current implementation and tests do not enable them.

### Current DHCPv4 lease query

`internal/kea.ReadIPv4` is a prepared component for the trusted RADIUS-side
producer. It queries a local Kea daemon with `lease4-get-by-hw-address`; it is
not wired into either running command and does not produce `binding.Snapshot`.
There is no new controller API, service, dependency or network control agent.

The client checks the Unix socket's owner, permissions and ancestors, then
checks the connected daemon's kernel peer UID before sending the fixed query.
Trusted local options pin that UID, the subnet ID and IPv4 prefix. A query is
limited to ten seconds, 256 KiB and sixteen returned leases. Malformed,
duplicate, mismatched-owner or wrong-subnet evidence rejects the whole result;
absent, expired, declined or reclaimed leases yield no active addresses. An
unavailable socket never falls back to a CSV or cached result.

Each successful query records its start time as the conservative ownership
observation. Kea's original `cltt` and `cltt + valid-lft` remain the renewal and
expiry times. Requerying cannot extend that lease. Queries for different
devices are not one transaction: the producer must still reject ownership
conflicts and clip grants to both session freshness and original lease expiry.

The isolated Kea 2.6.3 fixture checks the real response format, unchanged expiry
on reread, and IP reuse by a different MAC. It starts without DHCP interfaces
and uses a synthetic, non-persistent database. Socket tests cover peer
substitution, unsafe permissions, cancellation, incomplete responses and source
loss. These checks do not qualify live VLAN placement or MAC anti-spoofing.

Deployment still needs the lease-commands hook and a protected local control
socket. The client is read-only; **Kea's socket is not**. Keep administrative
socket access away from the directory reader and device-policy editors. Kea
2.6.3 restricts its control-socket directory and requires `0750` permissions;
the fixture uses its documented `KEA_CONTROL_SOCKET_DIR` override to avoid
installed paths. See the [Kea DHCPv4 management API](https://kea.readthedocs.io/en/kea-2.6.3/arm/dhcp4-srv.html#management-api-for-the-dhcpv4-server)
and [lease commands](https://kea.readthedocs.io/en/kea-2.6.3/arm/hooks.html#the-lease4-get-by-lease6-get-by-commands).

### Accounting replay and IPv4 correlation

`internal/radius.Replay` checks the current-boot accounting history's JSON
schema, local service UID, service/tag, NAS source scope, timestamps and order.
The caller must obtain that history from an authenticated journal source. A
JSON document claiming those fields is not authenticated evidence, and a
truncated capture can omit a Stop even if its remaining entries look valid.
The installed source adapter must collect complete history, not a tail or an
active-session list. Replay rejects incomplete lines and bounded-input limits;
it cannot detect deliberate removal of complete entries by an untrusted caller.

Start anchors each session's duration. Fresh Interim-Update observations keep
their original event time, adjusted conservatively for accounting delay. Exact
duplicates and rereads do not refresh it; a Stop tombstone never reopens within
the same boot/NAS/session identity. Missing Starts, ID reuse and conflicting
current sessions withhold candidates. A fresh roaming overlap remains withheld
until the old session stops or expires. Malformed or wrong-source input rejects
the whole observation, without returning partial sessions.

`internal/radius.MatchIPv4` joins one fresh session with one current Kea lease
whose canonical MAC, reported IPv4, subnet and prefix agree. Multiple leases,
reassignment, absent ownership and stale queries produce no candidate. The
result retains the original DHCP renewal and expiry, and its lifetime ends at
the earlier of DHCP expiry or the ninety-second session-evidence deadline.
Session and ownership identities are opaque hashes, not raw accounting IDs.
A reread can observe a still-valid lease but cannot renew that lease or turn an
old accounting event into a heartbeat.

The result is `IPv4Candidate`, deliberately **not** `binding.Record` or
`binding.Snapshot`. A reported VLAN is only corroboration. No physical VLAN,
anti-spoofing or native IPv6 qualification is manufactured from these matches.
Tests cover Stop/replay, delayed and duplicate records, roaming, identity reuse,
lease reassignment and original expiry bounds, using synthetic data only.

### Local collection and shadow export

`internal/radius.CollectIPv4` now obtains accounting history from the local
system journal. It pins the root-owned `journalctl` executable, uses the actual
kernel boot ID and exact service, tag and numeric UID matches, and passes a
fixed environment and argument list without a shell. It reads oldest first,
without tailing, following or choosing an alternate journal source. Nonzero
exit, cancellation, stderr (including exit-zero warnings), oversized output or
invalid replay rejects the collection. See the [systemd journalctl manual
source](https://raw.githubusercontent.com/systemd/systemd/v257/man/journalctl.xml)
for field-match, output and ordering semantics.

The collector brackets two serial Kea lease passes with three journal reads.
JSON object field order and whitespace are normalized because `journalctl`
assembles fields from an unordered map; see its [JSON output implementation](https://github.com/systemd/systemd/blob/v257/src/shared/logs-show.c#L1165).
All fields, values, cursors and entry ordering are retained. Each normalized
history must extend the preceding one without changing its existing records,
provenance or current session cohort. Ownership, renewal and expiry
must agree across both lease passes. A Stop, roaming conflict, heartbeat change,
lease renewal or reassignment observed during collection rejects the result;
the next attempt starts from the sources again. Original session and first-query
lease times are retained. Clock conflicts, duplicate IP owners and expired
evidence also reject without partial candidates.

This detects observed races; it is not an atomic transaction across RADIUS and
DHCP. Changes after an observation remain possible. The journal is retained
current-boot history, not a durable session database or proof that no historical
record was lost. Missing Starts deny candidates. Rotation, NAS/service restart
and live source identity still need qualification. Bounds are 16 MiB of journal
output, 16,384 events, 4,096 replayed sessions and at most 256 candidate devices;
exceeding them fails closed rather than falling back to a tail or cache. Overall
collection is capped at thirty seconds, with each source read capped at ten.

`internal/radius.PublishIPv4` uses an existing root-private directory dedicated
to the collector on encrypted local storage. An exclusive file lock prevents
overlapping publishers. Before querying either source, it atomically replaces
`radius-shadow.json` with an incomplete, empty report. A collection failure
therefore cannot leave the preceding report marked complete. Successful reports
remain `mode: shadow` and `enforcement_ready: false`. The exporter rejects unsafe
existing files and writes through a private temporary file, file sync, rename
and directory sync. A failed filesystem operation returns an error; readers
must not treat a file's mere presence as a successful or current collection.

This is a distinct report schema, not `binding.Snapshot`; even renaming it to
`bindings.json` does not make the helper accept it. The standalone
`router-policy-collector` command invokes the collector, but neither the reader
nor helper consumes this report. Independent actual-VLAN/source qualification,
native IPv6 ownership and the installed shadow canary remain deployment gates.

Synthetic tests cover source loss, Stop/roaming during collection, journal
rewrites, lease reassignment, original expiry bounds, clock conflict, export
invalidation, unsafe output files and concurrent publishers. Run the pinned-ELF
subprocess fixture with `go test -race -tags integration ./internal/radius`
**without `-cover`**: a coverage-instrumented child emits a runtime warning when
its deliberately fixed production environment excludes `GOCOVERDIR`. The
collector correctly rejects that warning. Other tests can run with coverage;
the subprocess fixture explicitly skips that mode rather than accepting stderr
or inheriting test-only environment variables.

Before building an installable binary, use a patched supported Go toolchain.
The cached Go 1.26.7 test image predates the Go 1.26.9 security release; see the
[Go release history](https://go.dev/doc/devel/release).

### Running the shadow collector

Build `./cmd/router-policy-collector` on Linux with a patched supported Go
toolchain and `CGO_ENABLED=0`. Static local-account lookup avoids depending on
an NSS directory service. The command runs once and exits; a deployment may
schedule it without overlapping runs.

```sh
router-policy-collector -config-directory /run/router-policy-collector
```

The existing configuration directory must be root-owned and private, with a
regular, single-link, root-owned `collector.json` readable only by root. Its
complete schema is illustrated below with documentation-only addresses:

```json
{
  "schema_version": 1,
  "mode": "shadow",
  "radius_user": "freerad",
  "nas_prefixes": ["198.51.100.0/24"],
  "kea_user": "_kea",
  "kea_socket": "/run/kea/kea4-ctrl-socket",
  "subnet_id": 22,
  "ipv4_prefix": "192.0.2.0/24",
  "vlan": 22,
  "maximum_devices": 16,
  "output_directory": "/var/lib/router-policy-collector"
}
```

Service names resolve to non-root local accounts; numeric IDs are not portable
between installations. NAS prefixes describe authenticated RADIUS senders, not
device networks. The subnet, prefix and VLAN must match the one observed scope.
Unknown or duplicate keys, extra command arguments, noncanonical prefixes and
an enforcement mode are rejected. Configuration takes no credentials,
environment overrides, executable paths or helper connection.

The output directory must already exist, root-owned and mode 0700, on encrypted
local storage. The command writes only its private shadow report and prints
counts, never device identities or upstream diagnostics. Exit codes are 0 for
success, help or version, 1 for runtime/output failure, and 2 for invalid use.
Its fixed deadline is thirty seconds, with five-second source-read deadlines.

A capability-free root service can connect to a Kea-owned socket with mode
0660 and the local Kea supplementary group; the socket parent must remain
Kea-owned and not writable by that group or others. Do not grant this group to
the unprivileged directory reader: the Kea socket is an administrative API even
though this client issues only the fixed read-only lease query. The collector
needs filesystem access to that socket and the local system journal, but no
IP network listener, Internet access or firewall capability.

The command and its tests are source implementation, not proof of an installed
service. A deployment still needs an authenticated release artifact, reviewed
service isolation, journal retention/restart qualification and a live shadow
comparison. Shadow output never satisfies the enforcement binding contract.

### Optional host IPv4 placement checks

The collector accepts an optional root-owned `host_placement` object in
`collector.json`. Omission preserves the existing collection and report shape.
For example, a deployment with a VLAN link named `edge22` on `edge0` can add:

```json
"host_placement": {"interface": "edge22", "parent": "edge0"}
```

Only these two fields are accepted; the VLAN comes from the existing collector
scope. Both links must be Ethernet links with UP and LOWER_UP flags. The child
must be operationally UP, use 802.1Q with the configured VLAN ID, and name the
pinned parent. Bridged/VRF-enslaved and cross-namespace links reject. Child and
parent indices are checked across reads; changed geometry rejects collection.

The capability-free observer pins the root-owned `/usr/bin/ip` ELF descriptor
and runs only fixed JSON link/IPv4-neighbour `show` operations. Reads are bounded
by three seconds and four MiB, with limits of 256 links and 4,096 neighbours.
Warnings, malformed/duplicate JSON, conflicting identities or source failure
return no observation. No shell, active probes, neighbour writes, additional
daemon, controller API or new dependency is involved.

Only REACHABLE neighbours with a matching current MAC/IP can propose a binding.
The observer subtracts kernel confirmation age, plus one second for rounding,
from query start. It does not treat `used`, a cache reread or DHCP renewal as
new neighbour confirmation. The age fields are seconds in
[iproute2's neighbour formatter](https://github.com/iproute2/iproute2/blob/main/ip/ipneigh.c).
Confirmation must follow the current session Start. Stale, missing, permanent,
proxy and externally managed/offloaded entries provide no binding. An idle
device can therefore lose its proposal until ordinary permitted traffic
refreshes reachability; this implementation adds no permit or probe to do so.
Live idle-device availability remains a qualification item before enforcement.

Placement is read twice around the lease recheck. A proposal requires matching
placement in both reads and keeps the earliest original session, DHCP and
neighbour-confirmation deadline. The report adds `placement_checked`,
`placement_withheld` and `proposed_bindings`, but retains its distinct shadow
schema and `enforcement_ready: false`. The binding loader rejects the report
even if renamed to `bindings.json`; there is no authoritative-export switch.

The observer needs the host network namespace and AF_NETLINK in addition to
the collector's existing Unix-socket access. A private-network/AF_UNIX-only
unit cannot use this option. Service isolation and an authenticated release
must be reviewed before deployment; retain the empty capability bounding set,
deny IP socket families and keep the directory reader away from these sources.
Synthetic native tests read an actual Debian VLAN/neighbour table after the
fixture drops all effective and bounding capabilities. They do not qualify a
live NAS, journal retention, first-hop controls or the installed firewall.

MAC and ARP remain spoofable. Deployments using this model must explicitly
accept that device-identity limitation or supply stronger access-layer controls.
Agreement among RADIUS, DHCP and neighbours is not cryptographic authentication.
