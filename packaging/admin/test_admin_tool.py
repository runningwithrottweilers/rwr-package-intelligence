#!/usr/bin/env python3
"""Isolated tests for rwr-package-intelligence-admin.

Every scenario runs in a fresh bwrap sandbox with a private user namespace
(uid 0 maps to the invoking user), a tmpfs root, private /etc and /run and no
network. pacman and systemctl are stubs; the host package database, pacman
locks, systemd and Polkit are never contacted. The policy written by the tool
is judged by the REAL supervisor binary built from this tree (`--status`),
i.e. by the production trust checks, not by a reimplementation.

    python3 packaging/admin/test_admin_tool.py --supervisor target/release/rwr-transaction-supervisor
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / 'packaging/admin/rwr-package-intelligence-admin'
NAME = 'rwr-package-intelligence'
LIB = f'/usr/lib/{NAME}'
SUPERVISOR = None

PACMAN_STUB = r'''#!/bin/bash
case "$1" in
  -V) printf ' .--.  Pacman v7.1.0 - libalpm v%s\n' "${STUB_ALPM:-16.0.1}" ;;
  -Q) [[ ${STUB_INSTALLED:-1} == 1 ]] && echo "rwr-package-intelligence 0.1.0-16" || exit 1 ;;
  -Qkk) echo "rwr-package-intelligence: 43 total files, ${STUB_ALTERED:-0} altered files" ;;
  *) echo "pacman stub: unexpected $*" >&2; echo "UNEXPECTED pacman $*" >> /tmp/calls.log; exit 99 ;;
esac
'''
SYSTEMCTL_STUB = r'''#!/bin/bash
echo "systemctl $*" >> /tmp/calls.log
case "$1" in
  add-wants) mkdir -p /etc/systemd/system/sockets.target.wants
             ln -s "/usr/lib/systemd/system/$3" "/etc/systemd/system/sockets.target.wants/$3" ;;
  start) touch /run/socket-active ;;
  stop) rm -f /run/socket-active ;;
  is-active) shift; [[ $1 == --quiet ]] && shift; test -e /run/socket-active ;;
  daemon-reload) ;;
  *) echo "UNEXPECTED systemctl $*" >> /tmp/calls.log; exit 99 ;;
esac
'''


class AdminToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='rwr-admin-test-')
        base = Path(self.tmp.name)
        for name, text in [('pacman', PACMAN_STUB), ('systemctl', SYSTEMCTL_STUB)]:
            (base / name).write_text(text)
            (base / name).chmod(0o755)
        self.base = base

    def tearDown(self):
        self.tmp.cleanup()

    def sandbox(self, script, uid=0, env=None):
        b = self.base
        command = [
            'bwrap', '--unshare-all', '--unshare-user', '--uid', str(uid), '--gid', str(uid),
            '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr',
            '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/bin', '/sbin',
            '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib', '/lib64',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--dir', '/run',
            '--dir', '/etc', '--dir', '/etc/systemd/system',
            # Package payload paths: tool from this tree, supervisor from this build.
            '--dir', '/opt/bin', '--ro-bind', str(TOOL), f'/opt/bin/{NAME}-admin',
            '--ro-bind', str(SUPERVISOR), f'{LIB}/rwr-transaction-supervisor',
            '--ro-bind', str(b / 'pacman'), '/usr/bin/pacman',
            '--ro-bind', str(b / 'systemctl'), '/usr/bin/systemctl',
            '--setenv', 'PATH', '/opt/bin:/usr/bin', '--setenv', 'USER', 'root' if uid == 0 else 'user',
        ]
        for key, value in (env or {}).items():
            command += ['--setenv', key, value]
        command += ['bash', '-c', 'touch /tmp/calls.log; ' + script + '; rc=$?; echo "--- calls"; cat /tmp/calls.log; exit $rc']
        return subprocess.run(command, capture_output=True, text=True, timeout=60)

    GATE = f'{LIB}/rwr-transaction-supervisor --status'
    POLICY = f'/etc/{NAME}/execution-policy.json'

    def test_00_payload_paths_exist_on_host(self):
        # The sandbox reuses /usr: these must exist so bwrap can bind over them.
        for path in [f'{LIB}/rwr-transaction-supervisor', f'{LIB}/rwr-update-helper',
                     f'/usr/lib/systemd/system/{NAME}-system.socket',
                     '/usr/share/polkit-1/actions/io.github.runningwithrottweilers.rwr-package-intelligence.policy']:
            self.assertTrue(Path(path).exists(), f'bind target missing on host: {path}')

    def test_status_default_deny(self):
        r = self.sandbox(f'{NAME}-admin status; echo "rc=$?"; {self.GATE}')
        self.assertIn('policy:         missing (default-deny)', r.stdout)
        self.assertIn('backend gate:   LOCKED', r.stdout)
        self.assertIn('rc=3', r.stdout)
        self.assertIn('"real_execution_enabled":false', r.stdout)

    def test_enable_requires_root(self):
        r = self.sandbox(f'{NAME}-admin enable; echo "rc=$?"; ls /etc', uid=1000)
        self.assertIn('requires administrator rights', r.stderr)
        self.assertIn('rc=1', r.stdout)
        self.assertNotIn('add-wants', r.stdout)

    def test_enable_refuses_unsupported_libalpm(self):
        r = self.sandbox(f'{NAME}-admin enable; echo "rc=$?"; test -e {self.POLICY} && echo POLICY-WRITTEN; {self.GATE}',
                         env={'STUB_ALPM': '16.1.0'})
        self.assertIn('libalpm 16.1.0 is not supported', r.stderr)
        self.assertIn('rc=1', r.stdout)
        self.assertNotIn('POLICY-WRITTEN', r.stdout)
        self.assertNotIn('add-wants', r.stdout)
        self.assertIn('"real_execution_enabled":false', r.stdout)

    def test_enable_refuses_altered_installation(self):
        r = self.sandbox(f'{NAME}-admin enable; echo "rc=$?"; test -e {self.POLICY} && echo POLICY-WRITTEN',
                         env={'STUB_ALTERED': '1'})
        self.assertIn('installed files differ from the package', r.stderr)
        self.assertNotIn('POLICY-WRITTEN', r.stdout)

    def test_enable_refuses_uninstalled_package(self):
        r = self.sandbox(f'{NAME}-admin enable; echo "rc=$?"', env={'STUB_INSTALLED': '0'})
        self.assertIn('not installed through pacman', r.stderr)
        self.assertIn('rc=1', r.stdout)

    def test_enable_opens_gate_exactly_like_reference_deployment(self):
        r = self.sandbox(
            f'{NAME}-admin enable; echo "rc=$?"; '
            f'stat -c "%u:%g %a %h" {self.POLICY} /etc/{NAME}; cat {self.POLICY}; '
            f'readlink /etc/systemd/system/sockets.target.wants/{NAME}-system.socket; '
            f'ls -A /etc/{NAME}; {self.GATE}; {NAME}-admin status; echo "status-rc=$?"')
        out = r.stdout
        self.assertIn('REAL MODE enabled.', out, r.stderr)
        self.assertIn('rc=0', out)
        self.assertIn('0:0 644 1', out)                       # policy root:root 0644, one link
        self.assertIn('0:0 755 ', out)                        # policy directory
        self.assertIn('{"schema":1,"allow_system_upgrade":true}\n', out)
        self.assertIn(f'/usr/lib/systemd/system/{NAME}-system.socket', out)
        self.assertIn(f'systemctl add-wants sockets.target {NAME}-system.socket', out)
        self.assertIn(f'systemctl start {NAME}-system.socket', out)
        self.assertIn('"real_execution_enabled":true', out)  # production trust check agrees
        self.assertNotIn('.execution-policy.', out)          # no temporary file left
        self.assertIn('READY: REAL MODE enabled', out)
        self.assertIn('status-rc=0', out)
        self.assertNotIn('UNEXPECTED', out)

    def test_enable_is_idempotent_and_replaces_untrusted_file_atomically(self):
        r = self.sandbox(
            f'mkdir -m 755 /etc/{NAME}; echo junk > {self.POLICY}; chmod 666 {self.POLICY}; {self.GATE}; '
            f'{NAME}-admin enable >/dev/null && {NAME}-admin enable; echo "rc=$?"; '
            f'stat -c "%a %h" {self.POLICY}; {self.GATE}')
        self.assertIn('"real_execution_enabled":false', r.stdout.split('rc=')[0])
        self.assertIn('rc=0', r.stdout, r.stderr)
        self.assertIn('644 1', r.stdout)
        self.assertEqual(r.stdout.count('systemctl add-wants'), 1)
        self.assertTrue(r.stdout.rstrip().split('--- calls')[0].strip().endswith('"real_execution_enabled":true,"service_integration_ready":false,"transaction_supervision_ready":false}'))

    def test_enable_refuses_symlinked_policy_directory(self):
        r = self.sandbox(f'mkdir /tmp/evil; ln -s /tmp/evil /etc/{NAME}; {NAME}-admin enable; echo "rc=$?"; ls -A /tmp/evil')
        self.assertIn('not a symlink', r.stderr)
        self.assertIn('rc=1', r.stdout)
        self.assertNotIn('execution-policy', r.stdout.split('rc=1')[1].split('--- calls')[0])

    def test_enable_refuses_group_writable_policy_directory(self):
        r = self.sandbox(f'mkdir -m 775 /etc/{NAME}; {NAME}-admin enable; echo "rc=$?"')
        self.assertIn('without group/other write', r.stderr)
        self.assertIn('rc=1', r.stdout)

    def test_disable_refused_while_transaction_runs(self):
        r = self.sandbox(
            f'{NAME}-admin enable >/dev/null; '
            f'(exec -a "{LIB}/rwr-update-helper --supervised-upgrade" sleep 20) & sleep 0.5; '
            f'{NAME}-admin disable; echo "rc=$?"; cat {self.POLICY}; {self.GATE}; kill %1')
        self.assertIn('an update transaction is running', r.stderr)
        self.assertIn('rc=1', r.stdout)
        self.assertIn('"allow_system_upgrade":true', r.stdout)
        self.assertIn('"real_execution_enabled":true', r.stdout)
        self.assertNotIn('systemctl stop', r.stdout)

    def test_disable_locks_and_removes_activation(self):
        r = self.sandbox(
            f'{NAME}-admin enable >/dev/null; {NAME}-admin disable; echo "rc=$?"; cat {self.POLICY}; '
            f'test -L /etc/systemd/system/sockets.target.wants/{NAME}-system.socket && echo LINK-LEFT; '
            f'{self.GATE}; {NAME}-admin status; echo "status-rc=$?"')
        out = r.stdout
        self.assertIn('REAL MODE locked.', out, r.stderr)
        self.assertIn('rc=0', out)
        self.assertIn('{"schema":1,"allow_system_upgrade":false}', out)
        self.assertNotIn('LINK-LEFT', out)
        self.assertIn(f'systemctl stop {NAME}-system.socket {NAME}-system.service', out)
        self.assertIn('systemctl daemon-reload', out)
        self.assertIn('"real_execution_enabled":false', out)
        self.assertIn('status-rc=3', out)

    def test_unknown_command(self):
        r = self.sandbox(f'{NAME}-admin upgrade; echo "rc=$?"')
        self.assertIn('usage:', r.stdout)
        self.assertIn('rc=2', r.stdout)
        self.assertNotIn('systemctl', r.stdout.split('--- calls')[1])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--supervisor', required=True, type=Path)
    args, rest = parser.parse_known_args()
    SUPERVISOR = args.supervisor.resolve()
    if not os.access(SUPERVISOR, os.X_OK):
        sys.exit(f'supervisor binary not executable: {SUPERVISOR}')
    unittest.main(argv=[sys.argv[0], *rest], verbosity=2)
