# Directory collection and RADIUS evidence

These are separate trust boundaries. Authentik supplies active identities,
original groups and group policy. RADIUS supplies the agent's network-session
evidence. Neither source can grant control over the router-owned protected
floor, and a directory read cannot establish network ownership.

## Directory collection

`internal/directory` provides a read-only library, not an installed service or
command. `New` accepts private connection configuration and a cancellable
credential callback. `Collect` opens a new connection and obtains credentials
again on each call; it caches neither credentials nor directory entries.
Concurrent calls use separate connections. A shared credential callback must
itself be safe for concurrent use and honor its context.

Only explicit `ldaps://host:port` endpoints are accepted. TLS verifies both the
certificate chain and hostname, using system roots or a cloned deployment CA
pool, with TLS 1.2 as the minimum. There is no insecure option, plaintext
fallback, referral following or StartTLS implementation. Connection, bind and
all searches share a deadline of at most ten seconds. Cancellation closes the
socket and joins LDAP cleanup. Errors expose a fixed collection failure and,
where applicable, cancellation, not server diagnostics or private endpoints.

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
