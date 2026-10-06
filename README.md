# Router Policy Agent

[![Go version](https://img.shields.io/github/go-mod/go-version/mikenorgate/router-policy-agent)](https://go.dev/)
[![License](https://img.shields.io/github/license/mikenorgate/router-policy-agent)](LICENSE)
[![Checks](https://github.com/mikenorgate/router-policy-agent/actions/workflows/check.yml/badge.svg)](https://github.com/mikenorgate/router-policy-agent/actions/workflows/check.yml)

Router-side policy compilation for directory-managed devices. One placement group selects a reviewed VLAN role; access groups contribute exact application permissions without granting control over the router's protected policy.

**Development status:** the compiler, offline checker, UID-checked local transport, durable revocation state, helper transaction engine and restricted nftables update primitives are implemented. Guard layouts, atomic lease mirrors and exact owned-object inspection have isolated kernel tests. Cooperative writer-fence and generation-check primitives are tested but not wired into production enforcement. This is not yet a deployable firewall agent. Executable wiring, LDAP collection, independently qualified bindings, owning-writer coordination and boot restoration, protected packet-path integration and translation tests remain required. See [the implementation gates](docs/architecture.md#implementation-gates).

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

Bindings require an actual NAS association and independently qualified DHCP/IPv6 ownership. Access-Accept and NDP alone are insufficient. The example binding record is a fixture, not evidence that a real collector exists. Directory and binding freshness limit permissions to 90 seconds or less; map events cannot renew directory leases. The privileged runtime must enforce those deadlines in the kernel before stateful/translator fast paths.

See [architecture and remaining gates](docs/architecture.md) and [security responsibilities](SECURITY.md). Network-specific endpoints, protected catalogs, accounts, credentials and operational evidence belong in private deployment configuration, not this repository.

## Contributing

Run `make check` and `make fuzz`. Keep tests synthetic and do not add deployment addresses or credentials. Changes affecting policy boundaries need rejection and revocation tests as well as successful-flow tests.

`make integration` adds Linux Unix-socket and checked-executable tests. The real cross-UID and root-owned executable cases require an isolated root test runner; they are skipped for an ordinary user. CI runs them in a pinned Go container. These tests do not change a firewall.

`make kernel` builds a test image and runs nftables tests with `NET_ADMIN` and `NET_RAW` inside a disposable, empty network namespace. Forwarding is enabled only in that namespace. It mounts this source tree read-only and builds from `packaging`, not deployment configuration. Do not add host networking, host namespace mounts or `--privileged`. Tests require an explicit acknowledgement and initially only loopback; missing isolation or capability fails rather than skips. Synthetic packet fixtures qualify MAC visibility, mark handoff, native TCP/UDP permits and replies, existing-flow revocation, UDP expiry, directionality, unknown addresses, IP reuse and unaffected unrelated traffic. Protected-floor integration, clock/suspend behavior and translated paths remain unqualified. See [guard layout and test scope](docs/runtime-boundary.md#guard-layout-and-atomic-mirrors).

Repository maintainers should require passing checks and reviewed pull requests in [branch protection](https://github.com/mikenorgate/router-policy-agent/settings/branches), set read-only default tokens and outside-contributor approval in [Actions settings](https://github.com/mikenorgate/router-policy-agent/settings/actions), and keep any future release credentials in [Actions secrets](https://github.com/mikenorgate/router-policy-agent/settings/secrets/actions) behind a reviewed [release environment](https://github.com/mikenorgate/router-policy-agent/settings/environments). The current check workflow requests only `contents: read`; it does not publish releases or need deployment secrets. Workflow files do not configure these repository settings.

## License

[MIT](LICENSE), matching the standalone companion-project release model.
