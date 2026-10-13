# Runtime package contract

The runtime has three Linux/amd64 packages: `router-policy-collector`,
`router-policy-reader` and `router-policy-helper`. Each contains only its static
executable and MIT license. There are no service units, accounts, credentials,
site configuration, maintainer scripts or automatic firewall changes.

## v0.3.0 compatibility

Internet permissions now use expiring device/listener entries and shared,
image-owned public-address eligibility and exclusion sets. An all-port rule
needs at most two TCP or three UDP listener spans per bound address, rather
than a copy of every allowed public subnet. Internal GUA, special-use ranges,
protected destinations and translated counterparts remain excluded. Conditional
retained blocks still apply to the specified device and role.

This changes the generated guard-object contract. Re-render the guards with
the v0.3.0 helper, rebuild and independently audit the pinned router profile,
and deploy the helper with that matching image. Replacing only the executable
in an older image will fail guard inspection. Preserve durable deny history;
the upgrade must not reset it or restore old permissions. Roll back the helper
and image contract together.

Directory policy schemas and helper request formats are unchanged. Read-only
observations add optional `internet`, `peer_network`, `peer_network_variants`
and `port_end` fields so consumers can distinguish selectors and listener
intervals from exact hosts. Broad internal CIDR permissions still use bounded
protected-service cutouts; this release does not remove those restrictions.

Shared-group parsing, NAT46 counterpart resolution, disjoint CIDR union and
JSON validation avoid repeated work. Scoped quotas count the final union, with
a separate bound on intermediate work. The changes add no dependencies and
do not increase request, preparation or permission-lifetime limits.

## Building the packages

Build all three from the same clean commit, version and patched toolchain:

```sh
python3 packaging/build-collector.py --version 0.3.0 --command router-policy-collector --output /tmp/policy-collector-release
python3 packaging/build-collector.py --version 0.3.0 --command router-policy-reader --output /tmp/policy-reader-release
python3 packaging/build-collector.py --version 0.3.0 --command router-policy-helper --output /tmp/policy-helper-release
```

The builder requires Go 1.26.9+ or 1.27.2+, govulncheck v1.8.0, Python 3 and
dpkg-deb. It scans source and each resulting binary. Manifests bind the source
commit, toolchain, package, executable and scan report. A deployment must pin
those identities in its reviewed configuration, rather than trust metadata
downloaded alongside an otherwise untrusted package.

Non-shadow packages use the manifest mode `explicit_configuration`. This is
not an activation instruction. The root-owned helper configuration must choose
`enforce`; the reader cannot select a mode or change the protected baseline.
The native collector export additionally requires `-publish-bindings` and
explicitly enrolled guarded-DHCP configuration. Failed collection invalidates
the export rather than reusing a previous success.

The guarded backend includes native controller initiation and reviewed
translation-path support. It does not install translator maps or learn a
protected floor from the running firewall. Controller identity, early/late/final
guards, bootstrap traffic, closed boot restoration, writer coordination and
the complete protected-policy projection still belong to the router integrator.

Installing these packages alone is not a production deployment. Follow the
[implementation gates](architecture.md#implementation-gates) before activation;
do not replace missing readiness evidence with a generated hash or fixture.

For offline image assembly, `router-policy-helper -render-image-guards -baseline
FILE` prints the code-owned guard program to stdout. It accepts no runtime
operation, does not invoke nftables, and does not initialize history or writer
state. The image owner must independently audit and install the guards alongside
its protected floor; rendering is not activation or readiness evidence.

The baseline's optional `bootstrap_paths` supplies fixed router-owned service
geometry for managed Untrusted interfaces. DNS is TCP/UDP 53; NTP is UDP 123.
Requests must use the declared service interface and protected server address.
Replies require an established conntrack reply and retain their narrow egress
exception after reverse NAT. No directory grant is needed for these services.
ARP, DHCPv4 and IPv6 neighbour/router control exceptions are limited to the
declared gateway addresses. This does not allow arbitrary traffic to the
service plane or unsolicited packets with a DNS/NTP source port. An integrator
must include its required bootstrap paths before enrolling devices; omitting
them does not infer or learn exceptions from the running router.

For closed boot restoration, `router-policy-helper -config-directory PATH
-restore-deny-state` runs the existing denial-only recovery operation. Stop the
helper first. Recovery withdraws application permits and restores retained
classifications from existing durable history; it does not initialize state,
install guards, mark a writer generation ready or restart enforcement. Keep
forwarding closed until guards and restored classifications are in place.
