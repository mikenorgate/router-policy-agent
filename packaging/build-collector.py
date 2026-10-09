#!/usr/bin/env python3
"""Build and scan a collector-only Debian package from a clean Git revision."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'https://github.com/mikenorgate/router-policy-agent'


def run(*arguments, env=None):
    result = subprocess.run(arguments, cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
    if result.returncode:
        raise SystemExit(result.stderr + result.stdout or 'collector build command failed')
    return result.stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--output', required=True, type=Path)
    options = parser.parse_args()
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-shadow\.[1-9][0-9]*', options.version):
        parser.error('expected a version such as 0.1.0-shadow.1')
    destination = options.output.resolve()
    if destination == ROOT or ROOT in destination.parents or destination.exists():
        parser.error('output must be a new directory outside the source tree')
    if run('git', 'status', '--porcelain').strip():
        parser.error('source revision must be clean, including untracked files')
    source = run('git', 'rev-parse', 'HEAD').strip()
    epoch = int(run('git', 'show', '-s', '--format=%ct', 'HEAD').strip())
    go_version = run('go', 'env', 'GOVERSION').strip()
    match = re.fullmatch(r'go1\.(26|27)\.([0-9]+)', go_version)
    if not match or int(match[2]) < (9 if match[1] == '26' else 2):
        parser.error('use patched Go 1.26.9+ or 1.27.2+')
    scanner = run('govulncheck', '-version')
    if 'v1.8.0' not in scanner:
        parser.error('govulncheck v1.8.0 is required')
    environment = {**os.environ, 'CGO_ENABLED': '0', 'GOOS': 'linux', 'GOARCH': 'amd64',
                   'GOTOOLCHAIN': 'local', 'SOURCE_DATE_EPOCH': str(epoch)}
    run('go', 'mod', 'verify', env=environment)
    destination.mkdir(mode=0o755)
    binary = destination / 'router-policy-collector'
    run('go', 'build', '-trimpath', '-buildvcs=false', '-ldflags',
        '-X github.com/mikenorgate/router-policy-agent/internal/cli.Version=' + options.version,
        '-o', str(binary), './cmd/router-policy-collector', env=environment)
    if run(str(binary), '-version').strip() != options.version:
        raise SystemExit('collector version embedding failed')
    source_scan = run('govulncheck', './cmd/router-policy-collector', env=environment)
    binary_scan = run('govulncheck', '-mode=binary', str(binary), env=environment)
    if 'No vulnerabilities found.' not in source_scan or 'No vulnerabilities found.' not in binary_scan:
        raise SystemExit('both vulnerability scans must report no vulnerabilities')
    report = destination / 'collector-security.txt'
    report.write_text('source_commit: ' + source + '\ngo_version: ' + go_version + '\n' + scanner +
                      '\n$ govulncheck@v1.8.0 ./cmd/router-policy-collector\n' + source_scan +
                      '\n$ govulncheck@v1.8.0 -mode=binary router-policy-collector\n' + binary_scan)
    debian_version = options.version.replace('-', '~', 1)
    filename = 'router-policy-collector_' + debian_version + '_amd64.deb'
    package = destination / filename
    with tempfile.TemporaryDirectory(prefix='collector-package.') as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        (root / 'DEBIAN').mkdir()
        (root / 'usr/bin').mkdir(parents=True)
        (root / 'usr/share/doc/router-policy-collector').mkdir(parents=True)
        (root / 'DEBIAN/control').write_text(
            'Package: router-policy-collector\nVersion: ' + debian_version + '\n'
            'Architecture: amd64\nMaintainer: Router Policy Agent maintainers\n'
            'Section: net\nPriority: optional\n'
            'Homepage: ' + REPOSITORY + '\n'
            'Description: Root-private RADIUS and DHCP ownership observer\n'
            ' Shadow reports only. No firewall enforcement, service activation or site configuration.\n')
        shutil.copyfile(binary, root / 'usr/bin/router-policy-collector')
        shutil.copyfile(ROOT / 'LICENSE', root / 'usr/share/doc/router-policy-collector/copyright')
        for path in sorted(root.rglob('*'), reverse=True):
            path.chmod(0o755 if path.is_dir() or path.name == 'router-policy-collector' else 0o644)
            os.utime(path, (epoch, epoch), follow_symlinks=False)
        os.utime(root, (epoch, epoch))
        run('dpkg-deb', '--root-owner-group', '-Zxz', '-z9', '--build', str(root), str(package), env=environment)
    manifest = {
        'schema': 1, 'version': options.version, 'debian_version': debian_version,
        'tag': 'v' + options.version, 'source_repository': REPOSITORY, 'source_commit': source,
        'source_date_epoch': epoch, 'go_version': go_version, 'cgo_enabled': False,
        'command': 'router-policy-collector', 'mode': 'shadow', 'architecture': 'amd64',
        'binary_sha256': digest(binary), 'package_filename': filename, 'package_sha256': digest(package),
        'scanner': 'govulncheck-v1.8.0', 'security_sha256': digest(report),
    }
    (destination / 'collector-release.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print(json.dumps(manifest, sort_keys=True))


if __name__ == '__main__':
    main()
