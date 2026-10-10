"""Check release rejection paths and inspect the generated Debian archive."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('builder', Path(__file__).with_name('build-collector.py'))
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class CollectorPackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / 'release'
        self.dirty = ''
        self.go = 'go1.26.9'
        self.scan = 'No vulnerabilities found.\n'
        self.builds = 0
        self.command = 'router-policy-collector'

    def run_command(self, *arguments, env=None):
        if arguments == ('git', 'status', '--porcelain'):
            return self.dirty
        if arguments == ('git', 'rev-parse', 'HEAD'):
            return 'a' * 40
        if arguments == ('git', 'show', '-s', '--format=%ct', 'HEAD'):
            return '1750000000'
        if arguments == ('go', 'env', 'GOVERSION'):
            return self.go
        if arguments == ('govulncheck', '-version'):
            return 'govulncheck: v1.8.0\n'
        if arguments[:2] == ('go', 'mod'):
            return 'all modules verified\n'
        if arguments[:2] == ('go', 'build'):
            self.builds += 1
            self.assertEqual(env['CGO_ENABLED'], '0')
            self.assertEqual(env['GOTOOLCHAIN'], 'local')
            Path(arguments[arguments.index('-o') + 1]).write_bytes(b'test collector binary')
            return ''
        if arguments == (str(self.output / self.command), '-version'):
            return '0.1.0-shadow.1\n'
        if arguments[0] == 'govulncheck':
            return self.scan
        if arguments[0] == 'dpkg-deb':
            return subprocess.run(arguments, env=env, check=True, capture_output=True, text=True).stdout
        self.fail('unexpected build command: ' + repr(arguments))

    def build(self):
        with patch.object(BUILDER, 'run', self.run_command), patch('sys.argv', [
                'build-collector.py', '--version', '0.1.0-shadow.1', '--output', str(self.output),
                '--command', self.command]):
            BUILDER.main()

    def test_package_is_inert_and_root_owned(self):
        self.build()
        manifest = json.loads((self.output / 'collector-release.json').read_text())
        package = self.output / manifest['package_filename']
        listing = subprocess.run(['dpkg-deb', '--contents', str(package)],
                                 capture_output=True, text=True, check=True).stdout
        self.assertTrue(all('root/root' in line for line in listing.splitlines()))
        self.assertTrue(listing.splitlines()[0].startswith('drwxr-xr-x'))
        self.assertNotIn('systemd', listing)
        self.assertNotIn('/etc/', listing)
        with tempfile.TemporaryDirectory() as extracted:
            subprocess.run(['dpkg-deb', '--control', str(package), extracted], check=True)
            self.assertEqual([item.name for item in Path(extracted).iterdir()], ['control'])
        self.assertEqual(BUILDER.digest(package), manifest['package_sha256'])
        self.assertEqual(manifest['mode'], 'shadow')

    def test_dirty_source_is_rejected_before_build(self):
        self.dirty = '?? unfinished-helper.go\n'
        with self.assertRaises(SystemExit):
            self.build()
        self.assertEqual(self.builds, 0)

    def test_helper_package_contains_only_executable_and_license(self):
        self.command = 'router-policy-helper'
        self.build()
        manifest = json.loads((self.output / 'helper-release.json').read_text())
        package = self.output / manifest['package_filename']
        self.assertEqual(manifest['command'], self.command)
        self.assertEqual(manifest['mode'], 'explicit_configuration')
        self.assertTrue((self.output / 'helper-security.txt').is_file())
        self.assertFalse((self.output / 'collector-release.json').exists())
        with tempfile.TemporaryDirectory() as extracted:
            root = Path(extracted)
            subprocess.run(['dpkg-deb', '--extract', str(package), extracted], check=True)
            self.assertEqual(sorted(str(path.relative_to(root)) for path in root.rglob('*') if path.is_file()),
                             ['usr/bin/router-policy-helper', 'usr/share/doc/router-policy-helper/copyright'])
            self.assertEqual((root / 'usr/bin/router-policy-helper').stat().st_mode & 0o7777, 0o755)
        with tempfile.TemporaryDirectory() as controls:
            subprocess.run(['dpkg-deb', '--control', str(package), controls], check=True)
            self.assertEqual([path.name for path in Path(controls).iterdir()], ['control'])
        self.assertEqual(BUILDER.digest(package), manifest['package_sha256'])

    def test_arbitrary_commands_are_rejected(self):
        self.command = '../../unexpected-command'
        with self.assertRaises(SystemExit):
            self.build()
        self.assertEqual(self.builds, 0)

    def test_unpatched_toolchains_are_rejected(self):
        for version in ('go1.26.8', 'go1.27.1', 'go1.25.9', 'devel go1.28'):
            with self.subTest(version=version):
                self.go = version
                with self.assertRaises(SystemExit):
                    self.build()
                self.assertEqual(self.builds, 0)

    def test_existing_output_is_preserved(self):
        self.output.mkdir()
        sentinel = self.output / 'keep'
        sentinel.write_text('keep')
        with self.assertRaises(SystemExit):
            self.build()
        self.assertEqual(sentinel.read_text(), 'keep')
        self.assertEqual(self.builds, 0)

    def test_unclean_vulnerability_scan_cannot_create_package(self):
        self.scan = 'Vulnerability reported\n'
        with self.assertRaises(SystemExit):
            self.build()
        self.assertFalse(list(self.output.glob('*.deb')))
        self.assertFalse((self.output / 'collector-release.json').exists())


if __name__ == '__main__':
    unittest.main()
