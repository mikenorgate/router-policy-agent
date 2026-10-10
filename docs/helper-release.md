# Inert helper prerelease

The helper Debian package contains one static Linux/amd64 executable,
`/usr/bin/router-policy-helper`, and its MIT license. It contains no service,
socket unit, configuration, credentials or maintainer scripts. Installing the
package does not start the helper or change the firewall.

Build from a clean Git revision using the same patched Go toolchain and
govulncheck version as the [collector release](collector-release.md):

```sh
python3 packaging/build-collector.py --command router-policy-helper --version 0.1.0-shadow.4 --output /tmp/helper-release
```

The builder rejects dirty source and existing output directories, verifies
module checksums, scans command source and binary, and records their exact
revision and digests in `helper-release.json` and `helper-security.txt`. A
successful build is not publication or deployment approval.

The helper binary supports explicit root-owned mode selection. Its manifest
therefore records `mode: explicit_configuration`, not a claim that the binary
is incapable of enforcement. For collector proposals, configuration must select
both `mode: shadow` and `binding_source: radius_shadow`; an enforcing helper
rejects that source. Shadow construction has no firewall write callbacks.

Deployment owns the private pinned policy profile, separate non-root reader
and operator identities, two supervisor-created Unix sockets, writer-generation
resources and encrypted durable state. First-install state initialization is a
separate operation and refuses existing history. The package supplies none of
these inputs and must not invent their pins from a live ruleset.

The helper package does not include the directory reader executable. Package
and qualify that reader separately before claiming end-to-end directory
integration. Keep deployment addresses, policy catalogs and credentials out of
public release assets. See [the runtime contract](runtime-boundary.md#checked-helper-configuration-and-ownership).
