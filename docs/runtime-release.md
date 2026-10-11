# Runtime package contract

The runtime has three Linux/amd64 packages: `router-policy-collector`,
`router-policy-reader` and `router-policy-helper`. Each contains only its static
executable and MIT license. There are no service units, accounts, credentials,
site configuration, maintainer scripts or automatic firewall changes.

Build all three from the same clean commit, version and patched toolchain:

```sh
python3 packaging/build-collector.py --version 0.1.0 --command router-policy-collector --output /tmp/policy-collector-release
python3 packaging/build-collector.py --version 0.1.0 --command router-policy-reader --output /tmp/policy-reader-release
python3 packaging/build-collector.py --version 0.1.0 --command router-policy-helper --output /tmp/policy-helper-release
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
