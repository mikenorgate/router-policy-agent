# Collector-only shadow release

The prerelease Debian package contains one static Linux/amd64 executable,
`/usr/bin/router-policy-collector`, and its MIT license. It contains no service,
site configuration, credentials or firewall helper. Installing it does not
start anything or change application access.

Build from a clean Git revision with patched Go 1.26.9+ or 1.27.2+,
govulncheck v1.8.0, Python 3 and dpkg-deb:

```sh
python3 packaging/build-collector.py --version 0.1.0-shadow.1 --output /tmp/collector-release
```

The output directory must not already exist. The builder embeds the version,
records the exact commit, verifies module checksums, scans the command source
and binary, and creates a root-owned Debian archive without maintainer scripts.
Both scans must report no vulnerabilities. Release metadata binds the package,
binary and scan-report SHA-256 digests; deployment must pin and verify these
values rather than download an unqualified latest release.

Run the collector as root with `-config-directory PATH`. The private root-owned
directory must contain a mode-0600 `collector.json` with all these fields:

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

These are documentation addresses, not deployment defaults. Configure the
actual local service accounts, authenticated NAS prefixes and one DHCP scope.
Create the encrypted output directory root-owned with mode 0700. The collector
prints only counts and writes a mode-0600 `radius-shadow.json`; it never writes
`bindings.json` or contacts the firewall helper. Exit codes are 0 for success,
help or version, 1 for runtime/output failure and 2 for invalid use.

A capability-free service may connect to the Kea-owned local socket with mode
0660 and the local Kea supplementary group. Do not give that group to the
directory reader: Kea's socket is an administrative API, although the collector
issues only its fixed lease query. No IP networking or credentials are needed.

Session observations retain their original ninety-second freshness bounds and
DHCP expiry. Reassignment or source failure invalidates the export; a RADIUS
Stop removes the session. These observations are not enforcement bindings.
Actual VLAN/source ownership, journal retention/restarts, native IPv6 and
installed packet paths still require deployment qualification.
