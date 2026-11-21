"""Offline .MTREE tests. No package manager, installation or fake root needed."""
import gzip
import hashlib
import os
import importlib.util
from decimal import Decimal
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('backend_package', Path(__file__).with_name('backend-package.py'))
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)


class MtreeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='rwr-mtree-test-')
        self.stage = Path(self.directory.name)
        (self.stage / 'usr').mkdir(mode=0o755)
        (self.stage / '.PKGINFO').write_text('pkgname = test\n')
        (self.stage / 'usr/payload').write_bytes(b'real file bytes\n')
        for name in ['.PKGINFO', 'usr/payload']:
            (self.stage / name).chmod(0o644)
        # Like build(): whole-second timestamps before .MTREE generation.
        for name in ['.PKGINFO', 'usr/payload', 'usr']:
            os.utime(self.stage / name, (1700000000, 1700000000))
        backend.generate_mtree(self.stage)
        self.actual = {}
        for name in ['.PKGINFO', 'usr', 'usr/payload']:
            path = self.stage / name
            stat = path.stat()
            attrs = dict(type='dir' if path.is_dir() else 'file', uid='0', gid='0',
                         mode=format(stat.st_mode & 0o7777, 'o'),
                         time=str(Decimal(stat.st_mtime_ns) / Decimal(1000000000)))
            if path.is_file():
                attrs.update(size=str(stat.st_size), sha256digest=hashlib.sha256(path.read_bytes()).hexdigest())
            self.actual[name] = attrs
        self.compressed = (self.stage / '.MTREE').read_bytes()

    def tearDown(self):
        self.directory.cleanup()

    def test_real_mtree_matches_bytes_and_root_metadata(self):
        backend.verify_mtree(self.compressed, self.actual)

    def test_normalized_epoch_is_preserved(self):
        for name in self.actual:
            os.utime(self.stage / name, (0, 0))
            self.actual[name]['time'] = '0'
        backend.generate_mtree(self.stage)
        backend.verify_mtree((self.stage / '.MTREE').read_bytes(), self.actual)

    def test_missing_mtree_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Missing .MTREE'):
            backend.verify_mtree(None, self.actual)

    def test_changed_file_bytes_are_rejected(self):
        self.actual['usr/payload']['sha256digest'] = hashlib.sha256(b'tampered').hexdigest()
        with self.assertRaisesRegex(RuntimeError, 'sha256digest'):
            backend.verify_mtree(self.compressed, self.actual)

    def test_wrong_owner_mode_size_and_time_are_rejected(self):
        for key, changed in [('uid', '1000'), ('mode', '777'), ('size', '9999'), ('time', '1')]:
            original = self.actual['usr/payload'][key]
            self.actual['usr/payload'][key] = changed
            with self.assertRaisesRegex(RuntimeError, key):
                backend.verify_mtree(self.compressed, self.actual)
            self.actual['usr/payload'][key] = original

    def test_missing_and_duplicate_entries_are_rejected(self):
        text = gzip.decompress(self.compressed).decode()
        lines = text.splitlines()
        for bad in ['\n'.join(lines[:-1]) + '\n', text + lines[-1] + '\n']:
            with self.assertRaises(RuntimeError):
                backend.verify_mtree(gzip.compress(bad.encode(), mtime=0), self.actual)

    def test_sub_second_mtime_is_refused(self):
        os.utime(self.stage / 'usr/payload', ns=(1700000000_005000000, 1700000000_005000000))
        with self.assertRaisesRegex(RuntimeError, 'Non-integer mtime'):
            backend.generate_mtree(self.stage)

    def test_invalid_compression_is_rejected(self):
        with self.assertRaises((RuntimeError, OSError)):
            backend.verify_mtree(b'not gzip', self.actual)


class RuntimeGateTests(unittest.TestCase):
    """Packaging checks for the runtime execution gate. Synthetic trees only:
    no policy is created anywhere outside a private temporary directory."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='rwr-gate-test-')
        self.root = Path(self.directory.name)
        for name, needles in backend.GATE_WIRING.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('\n'.join(needles) + '\n')
        self.stage = self.root / 'stage'
        for unit in ['system', 'user']:
            (self.stage / 'usr/lib/systemd' / unit).mkdir(parents=True)
            (self.stage / 'usr/lib/systemd' / unit / 'x.service').write_text('[Service]\nNoNewPrivileges=yes\n')

    def tearDown(self):
        self.directory.cleanup()

    def append(self, name, text):
        with (self.root / name).open('a') as file:
            file.write(text)

    def test_complete_wiring_passes(self):
        backend.check_source_gate(self.root)
        backend.check_payload_default_deny(self.stage)

    def test_missing_production_commit_code_is_rejected(self):
        (self.root / 'src/libalpm_ffi.rs').write_text('// no alpm_trans_commit\n')
        with self.assertRaisesRegex(RuntimeError, 'production code missing'):
            backend.check_source_gate(self.root)

    def test_participant_without_runtime_gate_is_rejected(self):
        (self.root / 'src/bin/rwr-update-helper.rs').write_text('fn real_execution_enabled() -> bool { true }\n')
        with self.assertRaisesRegex(RuntimeError, 'Runtime gate'):
            backend.check_source_gate(self.root)

    def test_policy_parser_weakening_is_rejected(self):
        text = (self.root / 'src/supervisor_trust.rs').read_text().replace('value["allow_system_upgrade"] != true', '')
        (self.root / 'src/supervisor_trust.rs').write_text(text)
        with self.assertRaises(RuntimeError):
            backend.check_source_gate(self.root)

    def test_legacy_real_denial_must_remain(self):
        (self.root / 'src/authorization_gate.rs').write_text('AuthorizationMode::Real => AuthorizationDecision::Allowed\n')
        with self.assertRaises(RuntimeError):
            backend.check_source_gate(self.root)

    def test_compile_time_unlock_is_rejected(self):
        self.append('src/bin/rwr-transaction-supervisor.rs', 'const REAL_EXECUTION_ENABLED: bool = true;\n')
        with self.assertRaisesRegex(RuntimeError, 'Compile-time execution switch'):
            backend.check_source_gate(self.root)

    def test_environment_unlock_is_rejected(self):
        self.append('src/update_launcher.rs', 'let _ = std::env::var("RWR_ALLOW_REAL_MODE");\n')
        with self.assertRaisesRegex(RuntimeError, 'Environment override'):
            backend.check_source_gate(self.root)

    def test_second_policy_path_is_rejected(self):
        self.append('src/production_ipc.rs', 'const P: &str = "/tmp/execution-policy.json";\n')
        with self.assertRaisesRegex(RuntimeError, 'Second execution policy path'):
            backend.check_source_gate(self.root)

    def test_shipped_policy_is_rejected(self):
        policy = self.stage / 'etc/rwr-package-intelligence/execution-policy.json'
        policy.parent.mkdir(parents=True)
        policy.write_text('{"schema":1,"allow_system_upgrade":true}')
        with self.assertRaisesRegex(RuntimeError, '/etc'):
            backend.check_payload_default_deny(self.stage)

    def test_unit_provisioning_policy_is_rejected(self):
        for line in ['ExecStartPre=/bin/sh -c "echo > /etc/rwr-package-intelligence/execution-policy.json"',
                     'Environment=RWR_ALLOW_SYSTEM_UPGRADE=1', 'ConfigurationDirectory=rwr-package-intelligence']:
            (self.stage / 'usr/lib/systemd/system/x.service').write_text(f'[Service]\n{line}\n')
            with self.assertRaisesRegex(RuntimeError, 'Unit may provision'):
                backend.check_payload_default_deny(self.stage)

    def test_binary_markers(self):
        good = b'\x7fELF..' + backend.EXECUTION_POLICY.encode() + b'..REAL MODE locked: x'
        backend.binary_gate_markers(good, 'helper')
        for bad in [b'\x7fELF REAL MODE locked', b'\x7fELF ' + backend.EXECUTION_POLICY.encode()]:
            with self.assertRaises(RuntimeError):
                backend.binary_gate_markers(bad, 'helper')


class AdminToolGateTests(unittest.TestCase):
    """The shipped admin tool is checked as packaged text (no execution)."""
    TOOL = Path(__file__).resolve().parents[1] / 'admin/rwr-package-intelligence-admin'

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='rwr-admin-gate-test-')
        self.stage = Path(self.directory.name)
        self.target = self.stage / f'usr/bin/{backend.NAME}-admin'
        self.target.parent.mkdir(parents=True)
        self.source = self.TOOL.read_text()

    def tearDown(self):
        self.directory.cleanup()

    def check(self, text):
        self.target.write_text(text)
        backend.check_admin_tool(self.stage)

    def test_shipped_tool_passes(self):
        self.check(self.source)

    def test_admin_tool_is_in_manifest_as_executable(self):
        self.assertEqual(backend.FILES[f'usr/bin/{backend.NAME}-admin'], 0o755)

    def test_missing_root_requirement_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'require_root enable'):
            self.check(self.source.replace('require_root enable', 'true'))

    def test_libalpm_pin_cannot_be_dropped(self):
        with self.assertRaisesRegex(RuntimeError, 'REQUIRED_ALPM'):
            self.check(self.source.replace('REQUIRED_ALPM=16.0.1', 'REQUIRED_ALPM=16'))

    def test_supervisor_confirmation_cannot_be_dropped(self):
        with self.assertRaisesRegex(RuntimeError, '--status'):
            self.check(self.source.replace('"$SUPERVISOR" --status', 'true'))

    def test_dangerous_operations_are_rejected(self):
        for extra in ['pkexec true', 'pacman -Syu', 'rm -f /var/lib/pacman/db.lck',
                      'systemctl enable rwr-package-intelligence-system.socket',
                      'cp x /etc/polkit-1/rules.d/49-rwr.rules', 'reboot']:
            with self.subTest(extra=extra), self.assertRaisesRegex(RuntimeError, 'must not use'):
                self.check(self.source + extra + '\n')


if __name__ == '__main__':
    unittest.main()
