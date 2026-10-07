# Router Policy Agent

[![Go version](https://img.shields.io/github/go-mod/go-version/mikenorgate/router-policy-agent)](https://go.dev/)
[![License](https://img.shields.io/github/license/mikenorgate/router-policy-agent)](LICENSE)
[![Checks](https://github.com/mikenorgate/router-policy-agent/actions/workflows/check.yml/badge.svg)](https://github.com/mikenorgate/router-policy-agent/actions/workflows/check.yml)

Router-side policy compilation for directory-managed devices. One placement group selects a reviewed VLAN role; access groups contribute exact application permissions without granting control over the router's protected policy.

**Development status:** the compiler, offline checker, UID-checked local transport, durable revocation state, helper transaction engine and restricted nftables update primitives are implemented. A private guarded backend combines pinned profile inspection, the cooperative writer fence, original authorization deadlines and atomic lease replacement/sealing. A single-use service pairs that backend with the durable engine and IPC, restoring deny-only history before accepting requests and sealing on exit. Isolated kernel tests exercise native IPv4/IPv6 permits, failure revocation and expiry during continuous traffic; a separate fixture tests the service through a real non-root client. The durable revoke-before-update coordinator is also tested. This is not yet a deployable firewall agent. Installed helper activation, directory-source integration, independently qualified bindings, release/pin provenance and independently qualified protected-policy projection, actual owning-writer integration and boot restoration, protected packet-path integration and translation tests remain required. See [the implementation gates](docs/architecture.md#implementation-gates).

A read-only LDAPS collector obtains original Authentik group entries and
direct device memberships with verified certificates, bounded paging and
redacted failures. Loopback wire tests exercise TLS rejection, partial-result
rejection, cancellation and credential rotation. The Linux `router-policy-reader`
command now connects fresh collection to the checked root-helper socket, with a
serial 30-second poll and one ten-second collection/submission budget. Isolated
cross-UID tests exercise the configured command. Production source qualification,
helper activation and installed service packaging remain outstanding. See
[directory collection and reader configuration](docs/directory-and-radius.md).

Configured helper wiring now rejects kernel-reported unsafe synchronization
through a read-only Linux clock query. Request-triggered clock-loss revocation
has native packet tests; the actual time reference, accuracy and suspend/resume
behavior remain unqualified. See [clock checks](docs/runtime-boundary.md#linux-synchronization-check).

## Getting started

Use Go 1.26 or newer. No external services or root privileges are needed for the compiler tests.

```sh
make check
make build
./bin/router-policy-check \
  -baseline examples/baseline.json \
  -directory examples/directory.json \
  -bindings examples/bindings.json \
  -at 2026-01-01T12:00:00Z
```

The synthetic example produces one TCP/6053 permission from a Trusted controller to an Untrusted device. The `-at` option is for offline fixtures only; it does not authorize changing a production clock. The checker prints JSON to stdout, diagnostics to stderr, and never changes networking or router state. Exit codes are 0 for a completed compilation (including device denials), 1 for an invalid snapshot/runtime failure, and 2 for incorrect arguments.

`router-policy-reader` is a Linux-only, non-root long-running command. It needs
`-config-directory` naming its private reader-owned runtime configuration and
credentials. It connects only over verified LDAPS and submits fresh snapshots
to a separately installed root helper; it cannot select enforcement mode, supply
bindings or modify the protected baseline. Runtime diagnostics are fixed JSON
outcomes on stderr, without directory dumps or upstream errors. It does not
install or start a helper. See [the reader command contract](docs/directory-and-radius.md#reader-command).

`router-policy-status` is a Linux-only, read-only client for a separately
authorized helper socket. `-socket` is required; `-server-uid` defaults to root
and is verified through kernel peer credentials. `-timeout` defaults to two
seconds and cannot exceed ten seconds. `-help` lists these options. No installed
helper/socket is supplied yet, so the client is currently qualified in isolated
tests rather than a production deployment. It does not start a helper, request
sudo, submit directory data or refresh authorization.

Status separates the last successful decision, conservative lease countdowns
and a fresh fenced kernel inspection. Failed inspection reports `unverified`;
`matches_pinned_contract` means the observed objects match the paired contract,
not that its protected-policy semantics or translated paths are qualified.
JSON goes to stdout and fixed diagnostics to stderr. Exit 0 means a valid report,
including unhealthy/unverified state; it is not a firewall health verdict.

`router-policy-recover` is a Linux-only, root-only command that revokes existing
agent-owned application grants. Stop the owning helper separately first; its
exclusive state lock prevents recovery from racing it. `-config-directory` is
required and loads the same checked private `helper.json`; `-timeout` defaults
to five seconds and is capped at ten. State is never initialized or reset.
Exit 0 confirms owned sealing and retained history, not baseline health or
permission to restart enforcement. See [recovery scope and failures](docs/runtime-boundary.md#denial-only-recovery).

Private helper wiring now loads checked root-owned configuration and supervises
the separate reader/operator listeners. Both start after closed restoration and
stop before backend resources are released. No installed helper or real binding
producer is supplied yet. See [configuration and ownership](docs/runtime-boundary.md#checked-helper-configuration-and-ownership).

Source installation is also available:

```sh
go install github.com/mikenorgate/router-policy-agent/cmd/router-policy-check@latest
```

Prebuilt runtime packages will be published after the enforcement gates pass. There are no production packages yet.

## Policy specification

The group-only `network_policy_v1` attribute carries a JSON string. Policy uses group IDs, not a switch on group names. Each device must have exactly one placement group. Up to 16 network groups may contribute compatible permissions; duplicate permissions retain every contributor so removing one group does not erase another group's valid grant.

```json
{
  "schema_version": 1,
  "kind": "access",
  "vlan_role": "untrusted",
  "temporary": false,
  "rules": [{
    "id": "controller-api",
    "direction": "to_device",
    "peer": {"addresses": ["fdca:1a2b::10/128"]},
    "protocol": "tcp",
    "destination_ports": [6053],
    "reason": "Synthetic controller API"
  }]
}
```

Version 1 accepts TCP/UDP with explicit destination ports and canonical `/32` or `/128` hosts. It rejects duplicate or unknown keys, subnet peers, names, mapped IPv6 addresses, multicast, loopback, link-local and documentation addresses. A temporary group sets `temporary: true` and supplies UTC `expires_at` on every rule. Its seven-day maximum starts at first validation and cannot slide through refresh or restart.

Only Untrusted access groups are supported. Authentik cannot grant either direction of a Security flow, including through NAT aliases. Guest and Assessment isolation, protected administration/service endpoints, retained blocks and router DNS/NTP policy remain independent restrictions. The router owns the baseline; directory attributes cannot modify its hooks, paths, quotas, translators or lifecycle. Application authentication and other network policies still apply.

Recognized NAT64/NAT46 addresses resolve to the real host before protection checks. The compiler includes installed, eligible NAT64 encodings and ready approved NAT46 counterparts. Private targets never gain a well-known-prefix encoding. Reserved unready/unmapped aliases deny, and a changed alias cannot transfer an unchanged rule's permission to another host. Expansion does not create a map, route, listener or DNS record. A compiled representation alone is not proof that its translated packet path can be enforced.

The agent's network-evidence interface is RADIUS, not an AP/controller API.
Bindings require a current actual NAS association and independently qualified
address ownership delivered through that interface. Access-Accept and NDP alone
are insufficient. The example binding record is a fixture, not evidence that a
real collector exists. Directory and binding freshness limit permissions to 90
seconds or less; map events cannot renew directory leases. The privileged
runtime must enforce those deadlines in the kernel before stateful/translator
fast paths. See [RADIUS source requirements](docs/directory-and-radius.md#radius-only-network-evidence).

See [architecture and remaining gates](docs/architecture.md) and [security responsibilities](SECURITY.md). Network-specific endpoints, protected catalogs, accounts, credentials and operational evidence belong in private deployment configuration, not this repository.

## Contributing

Run `make check` and `make fuzz`. Keep tests synthetic and do not add deployment addresses or credentials. Changes affecting policy boundaries need rejection and revocation tests as well as successful-flow tests.

`make integration` adds Linux Unix-socket and checked-executable tests. The real cross-UID and root-owned executable cases require an isolated root test runner; they are skipped for an ordinary user. CI runs them in a pinned Go container. These tests do not change a firewall.

`make kernel` builds a test image and runs nftables tests with `NET_ADMIN` and `NET_RAW` inside a disposable, empty network namespace. Forwarding is enabled only in that namespace. It mounts this source tree read-only. The build context admits only the test recipe and public module manifests through `.dockerignore`; dependencies are downloaded and verified during image creation, before the network-disabled tests run. No deployment configuration enters the image. Do not add host networking, host namespace mounts or `--privileged`. Tests require an explicit acknowledgement and initially only loopback; missing isolation or capability fails rather than skips. Synthetic packet fixtures qualify MAC visibility, mark handoff, native TCP/UDP permits and replies, existing-flow revocation, UDP expiry, directionality, unknown addresses, IP reuse and unaffected unrelated traffic. Protected-floor integration, clock/suspend behavior and translated paths remain unqualified. See [guard layout and test scope](docs/runtime-boundary.md#guard-layout-and-atomic-mirrors).

`make kernel-service` uses the same isolated image and adds test-only `SETUID`
to launch a client with UID 65534. It tests real IPC, durable history restoration,
the guarded backend, native IPv4/IPv6 UDP initiation and replies, account-disable
revocation, shutdown sealing and failed startup. The helper rejects a root client
even though it can connect to the socket. Missing or corrupt state is never
initialized automatically. Bindings are synthetic; this does not qualify a NAS
collector, production identities or the installed router's packet paths.

Repository maintainers should require passing checks and reviewed pull requests in [branch protection](https://github.com/mikenorgate/router-policy-agent/settings/branches), set read-only default tokens and outside-contributor approval in [Actions settings](https://github.com/mikenorgate/router-policy-agent/settings/actions), and keep any future release credentials in [Actions secrets](https://github.com/mikenorgate/router-policy-agent/settings/secrets/actions) behind a reviewed [release environment](https://github.com/mikenorgate/router-policy-agent/settings/environments). The current check workflow requests only `contents: read`; it does not publish releases or need deployment secrets. Workflow files do not configure these repository settings.

The native fixture uses a separate default-drop router table and a late lease
recheck. Tests cover the missing-bridge deny, an independent protected endpoint,
and withdrawal between hooks in all four flow directions. This fixture skips
the packet-header-changing case in a rootless runner; CI requires it with
`ROUTER_POLICY_REQUIRE_HEADER_TEST=1`. See the [handoff contract](docs/runtime-boundary.md#guard-layout-and-atomic-mirrors)
for the mark reservation, hook ordering and remaining production gates.

## License

[MIT](LICENSE), matching the standalone companion-project release model.
