# Architecture and activation gates

## Ownership

The runtime is a Go application on the router, started by systemd. FreeRADIUS continues to authenticate NAS requests and return Wi-Fi placement attributes. This project is neither a RADIUS replacement nor a Kubernetes controller.

Small internal packages use ordinary constructors. No dependency-injection framework is needed.

| Component | Authority | Must not do |
| --- | --- | --- |
| Directory reader | Read active accounts, individual groups and their policy attributes | Obtain directory administration privileges, merge user attributes as group policy, cache a failed lookup into a new Wi-Fi acceptance |
| Binding collector | Supply fresh, independently authenticated actual VLAN/address ownership | Treat Access-Accept or NDP alone as ownership, inherit grants across IP reuse |
| Compiler | Produce bounded shadow decisions against reviewed router configuration | Turn placement into role-wide access, grant Security permissions, reinterpret a forbidden alias as Internet |
| Privileged applier | Recompile inputs against its own floor and update named owned dynamic objects | Accept raw nftables/shell text, replace the baseline, create NAT maps/routes/listeners, update Security rules |
| Router/image configuration | Own the protected floor, Security rules and their counterparts, hooks and translator coordination | Leave a managed cohort able to fall through legacy permits after evidence disappears |

The reader-to-applier request carries raw typed directory data, not an authoritative rendered firewall program. The applier reloads its own qualified bindings, immutable baseline and durable ledger. Local peer credentials must identify the permitted reader UID; file ownership and permissions are part of the trust boundary.

## Compiler behavior

Compilation starts leases at collection time. An incomplete, stale, future-dated or oversized snapshot rejects the candidate. An inactive account, malformed network group, missing membership, conflicting placement or unqualified device binding gives that device no dynamic grants. Router-wide expanded-tuple overflow rejects the entire candidate rather than applying a partial subset.

Group membership is an additive union only after every network group is valid. Grants retain logical endpoints and contributors. The effective expiry is the latest still-valid contributor, each clipped by directory, association, address and temporary-rule deadlines. Removing the final contributor must withdraw every representation atomically.

The applier-owned ledger records first-validation times, recognized alias/real-peer anchors, known network group IDs and the last validated clock. It does not persist renewable grants. Restoring old permits after reboot, shifting an alias to a new peer, losing a known group's attribute, or moving a clock backward cannot create new permission.

Durable state also records the managed MAC cohort, historical native/NAT device-address classifiers and the last complete directory snapshot's timestamp/digest. Normal updates cannot shrink the cohort or either address family, or erase expiry/alias anchors. Fresh qualified Untrusted bindings supply deny-only classifiers even when an inactive, removed or zero-grant device receives no application permission. Startup hands the entire history to the backend before accepting requests; saved addresses are not current ownership or permission. Older snapshots and conflicting data at the same timestamp reject, including after restart. Schema 1 fails closed instead of inventing missing address history. The filesystem, UID-checked IPC and helper engine are described in [the runtime boundary contract](runtime-boundary.md); a qualified firewall backend, boot packet ordering and executable wiring are still missing.

The helper measures elapsed authorization age independently of UTC. Small sampling/slew lag is clamped without extending deadlines; larger backward discrepancy rejects. Restart requires fresh directory, association and address observations rather than reuse of persisted or cached evidence. Its backend handoff carries an immutable, process-local age anchor: compilation, persistence and queueing consume the original lifetime. These library and set-expiry checks do not qualify UTC synchronization, suspend/resume or the final packet-enforcement path.

Address expansion includes both endpoints. NAT64 supports installed `/96` prefixes with an explicit global or private scope. NAT46 needs a ready reviewed map in a reserved alias pool. The same semantic rule covers available representations; the kernel backend still needs proof of original, translated and return identity. A userspace translator does not promise to preserve conntrack marks. A whole translator pool is never a peer substitute.

## Protected floor

The private deployment must project and independently audit these boundaries from its reviewed router profile:

| ID | Non-overridable boundary |
| --- | --- |
| P01 | Out-of-band and isolated recovery links |
| P02 | Exact router, node, switch, AP and administration endpoint/port tuples |
| P03 | Transit/control/service-plane and integration source/identity restrictions |
| P04 | Actual VLAN/interface, canonical identity and fresh unambiguous address ownership |
| P05 | Packet safety, anti-spoofing and narrowly reviewed bootstrap/ICMPv6 handling |
| P06 | Router DNS/NTP forcing and resolver policy; no claim to block all encrypted DNS |
| P07 | Untrusted default deny with exact editable grants; both Security directions router-only; Assessment isolated and Guest Internet-only |
| P08 | Reviewed retained global, role, network and device blocks, including their applicable encodings |
| P09 | Decoded translator scope, non-global well-known-prefix denial, ready-map ownership and no unsolicited WAN publishing |
| P10 | Fixed privileged objects, quotas, transport/authentication settings and independent application/network authorization |

The compiler directly checks the logical policy restrictions. Packet safety, bootstrap handling, access-layer controls and static router-only policies require independently audited router integration. An inventory/catalog being present in JSON is not proof that all enforcement paths exist.

## Implementation gates

Current source implements the strict parser, cancellable compiler, contributor union, temporary-rule/alias ledger, bounded binding envelope, offline checker, durable state, credential-checked IPC, helper transaction engine and restricted nftables transaction primitives. Guard layouts and atomic mirrors have isolated native packet tests, including real TCP handshakes and revocation before a stateful shortcut. Fixed preparation can restore helper-owned historical classifiers without grants and seal all mirrors; isolated tests cover recreated owned tables and native IP reuse.

The private guarded backend now pairs complete ruleset inspection with the cooperative writer fence and original authorization age. It replaces all mirrors atomically, retains deny-only history, seals on failure and verifies a post-commit listing captured under the fence. Actual backend packet tests cover native IPv4/IPv6 initiation and replies, cancellation, invalid authorization, closed generation, external floor drift and expiry despite continuous traffic. The raw set-only executor still cannot accept guarded transactions.

The durable owning-writer coordinator closes readiness, revokes, updates, checks audit hashes and publishes a new sequence; its separate native fixture proves permits are withdrawn before the update callback and are not restored by readiness. These tests do not establish actual writer cooperation or the installed protected floor. Executable/backend integration, actual owning-writer adapters, independent protected-floor verification, closed boot ordering and translated forwarding remain unfinished. The following gates remain before this project can be called a completed runtime:

1. Add verified LDAPS/StartTLS collection with individual group reads, exact active identity, complete bounded paging and collision-safe membership interpretation. There must be no plaintext production fallback.
2. Qualify an authenticated binding source with actual NAS/VLAN association, DHCP and both-family ownership. Demonstrate roaming, disconnect, unknown privacy addresses, spoof/ambiguity and IP reuse. The JSON fixture is not such a source.
3. Wire the transport, state, engine and private guarded backend into the helper executable with distinct production identities and checked configuration. Complete independent verification of immutable enforcement paths and their final chain/rule objects, coordinate every privileged firewall writer, and implement closed boot restoration of persistent classification. Boot and failure start with empty application permits while classification remains closed; synthetic guard tests and a persisted MAC list do not prove production packet classification.
4. Integrate kernel-expiring tuples before every relevant established, DSR and translator shortcut. The native fixture now proves a provisional bridge through a separate default-drop router table and current-lease rechecking afterward. Independently qualify its placement after every protected path, mark ownership and all remaining shortcuts; these synthetic tables are not the production projection.
5. Coordinate mapping generations and original/translated/return identity with the translation owner. Removing or retargeting a map must withdraw the old variants before another endpoint can use them. Do not assume userspace translation preserves conntrack marks.
6. Run isolated native packet/namespace tests: both families and directions, existing connection expiry, denied aliases, Security ownership, quota/apply failures, reader/helper crashes, boot/clock events and unaffected unrelated flows. Qualify synchronized UTC, suspend/resume and end-to-end expiry on the final packet path; library clock and kernel set tests are not that evidence.
7. Package pinned, verified release artifacts and hardened systemd services. Integrate the router template, independent policy auditor and hardening/health checks together. Keep environment data in private configuration.

Only after those gates pass should an operator approve shadow deployment, one canary and then small cohort cutovers. Do not remove an existing router rule until equivalent permitting and denial/revocation evidence exists. Production directory TLS/credential rotation, actual controller peer addresses and access-layer source controls are deployment prerequisites, not defaults supplied by this public project.

## Reviewed ruleset drift checks

The read-only executor can compare one complete native listing against an
independently prepared object contract, while checking both helper tables
against their code-owned schema. It checks ordered rule expressions, declared
hooks and priorities, jump targets, static set/map contents and object inventory.
Unexpected tables are not silently ignored. Isolated kernel tests install an
independently authored fixture and prove that changes to early accepts, rule
order, protected sets, mappings and hooks reject without changing any objects.

This comparison does not establish that the contract implements P01–P10. The
image-policy owner must derive and authenticate the private projection, map
every protection to its enforcing paths and qualify those paths with packets.
The root-owned profile loader binds the compiler catalog and object contract
to one independently supplied image pin. It keeps guard inspection paired
with that catalog; it does not authenticate the owning release or establish
P01–P10 semantics. Neither a complete listing nor a matching hash may bootstrap
that expected policy. Actual writers, the generation fence, permitting paths,
translator identity and boot restoration are still integration gates. See the
[comparison contract and limits](runtime-boundary.md#reviewed-ruleset-comparison).
