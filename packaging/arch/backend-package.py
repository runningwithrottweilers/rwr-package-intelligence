#!/usr/bin/env python3
"""Local offline packaging checks. Never installs packages or activates services.

Build/package functions come from the real PKGBUILD. makepkg is deliberately not
invoked: even a dependency-skipping run can query the host package database via
an external package manager. The local archive has honest minimal .PKGINFO;
no synthetic .BUILDINFO and no claim of a signed/reproducible makepkg release.
"""
import argparse
import configparser
import gzip
from decimal import Decimal
import hashlib
import io
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
ARCH = ROOT / 'packaging/arch'
PKGBUILD = ARCH / 'PKGBUILD'
NAME = 'rwr-package-intelligence'
ACTION = 'io.github.runningwithrottweilers.rwr-package-intelligence.update'
POLICY = 'io.github.runningwithrottweilers.rwr-package-intelligence.policy'
LIB = f'usr/lib/{NAME}'
SYS = f'{NAME}-system'
FILES = {
    f'usr/bin/{NAME}': 0o755,
    f'{LIB}/rwr-update-helper': 0o755,
    f'{LIB}/rwr-transaction-supervisor': 0o755,
    f'usr/lib/systemd/system/{SYS}.service': 0o644,
    f'usr/lib/systemd/system/{SYS}.socket': 0o644,
    f'usr/lib/systemd/user/{NAME}.service': 0o644,
    f'usr/lib/systemd/user/{NAME}.socket': 0o644,
    f'usr/share/polkit-1/actions/{POLICY}': 0o644,
    'usr/share/applications/io.github.runningwithrottweilers.PackageIntelligence.desktop': 0o644,
    f'usr/share/licenses/{NAME}/LICENSE': 0o644,
    f'usr/share/licenses/{NAME}/ASSETS-LICENSE.md': 0o644,
    f'usr/share/doc/{NAME}/README.md': 0o644,
    f'usr/share/doc/{NAME}/BACKEND-DEPLOYMENT.md': 0o644,
}
for size in [48, 64, 128, 256]:
    FILES[f'usr/share/icons/hicolor/{size}x{size}/apps/io.github.runningwithrottweilers.PackageIntelligence.png'] = 0o644


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def metadata():
    # Sourcing defines variables/functions only. Never invokes build/package.
    script = '''source "$1"
for key in pkgname pkgver pkgrel pkgdesc arch depends source sha256sums; do
    declare -n values="$key"
    printf '%s\\0' "$key" "${values[@]}" END
 done'''
    raw = subprocess.check_output(['bash', '--noprofile', '--norc', '-c', script, '_', str(PKGBUILD)])
    parts = raw.decode().split('\0')
    result = {}
    while parts and parts[0]:
        key = parts.pop(0)
        end = parts.index('END')
        result[key] = parts[:end]
        parts = parts[end + 1:]
    require(result['pkgname'] == [NAME], 'Unexpected package name')
    require(result['arch'] == ['x86_64'], 'Unexpected architecture')
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare():
    meta = metadata()
    require(not (ARCH / f'{NAME}-{meta["pkgver"][0]}-{meta["pkgrel"][0]}-x86_64.pkg.tar.zst').exists(), 'Bump pkgrel before changing a built release candidate')
    prefix = f'{NAME}-{meta["pkgver"][0]}'
    archive = ARCH / meta['source'][0]
    # Explicit source allowlist excludes PKGBUILD itself (no circular checksum),
    # old source/package archives, build output, backups and private dotfiles.
    entries = ['Cargo.toml', 'Cargo.lock', '.cargo/config.toml', 'LICENSE',
               'ASSETS-LICENSE.md', 'README.md', 'assets/style.css',
               'assets/rwr-package-banner.png', 'packaging/systemd', 'packaging/polkit',
               'packaging/arch/release-rustc.sh', 'packaging/arch/backend-package.py',
               'packaging/arch/BACKEND-DEPLOYMENT.md',
               'packaging/arch/io.github.runningwithrottweilers.PackageIntelligence.desktop',
               'src/bin/rwr-transaction-supervisor.rs', 'src/bin/rwr-update-helper.rs']
    entries += [str(p.relative_to(ROOT)) for p in (ROOT / 'src').glob('*.rs')]
    entries += [f'assets/icons/rwr-package-intelligence-{size}.png' for size in (48, 64, 128, 256)]
    with archive.open('wb') as output, gzip.GzipFile(fileobj=output, mode='wb', mtime=0, filename='') as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as tar:
            paths = set()
            for entry in entries:
                path = ROOT / entry
                paths.add(path)
                if path.is_dir():
                    paths.update(path.rglob('*'))
            for path in sorted(paths):
                rel = path.relative_to(ROOT)
                if any((part.startswith('.') and part != '.cargo') or '.before-' in part or '.backup-' in part
                       or '.broken-' in part or part.endswith(('.tmp', '.orig', '.swp')) for part in rel.parts):
                    continue
                info = tar.gettarinfo(str(path), arcname=f'{prefix}/{rel}')
                require(info.isfile() or info.isdir() or info.issym(), f'Unsafe source file type: {rel}')
                if info.issym():
                    require(not Path(info.linkname).is_absolute() and path.resolve().is_relative_to(ROOT), f'Unsafe source link: {rel}')
                info.uid = info.gid = 0
                info.uname = info.gname = 'root'
                info.mtime = 0
                info.pax_headers = {}
                info.mode = 0o755 if info.isdir() or (info.isfile() and info.mode & 0o111) else 0o644
                if info.isfile():
                    with path.open('rb') as content:
                        tar.addfile(info, content)
                else:
                    tar.addfile(info)
    value = digest(archive)
    text, count = re.subn(r'^sha256sums=.*$', f'sha256sums=("{value}")', PKGBUILD.read_text(), flags=re.M)
    require(count == 1, 'Expected exactly one source checksum')
    PKGBUILD.write_text(text)
    print(f'SOURCE {archive.name} SHA256 {value}')


def ini(path):
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read(path)
    require('Install' not in parser, f'Unexpected automatic enablement: {path}')
    return parser


# Runtime deployment gate (replaces the obsolete compile-time REAL=false checks).
# Production COMMIT code is expected in the optimized helper. Execution must be
# denied by default: only a root-owned policy file, never shipped or created by
# this package, can permit attempting Polkit authorization.
EXECUTION_POLICY = f'/etc/{NAME}/execution-policy.json'
GATE_WIRING = {
    'src/supervisor_trust.rs': [
        f'pub const SYSTEM_EXECUTION_POLICY: &str = "{EXECUTION_POLICY}";',
        'value.as_object().is_none_or(|v| v.len() != 2)',
        'value["schema"] != 1',
        'value["allow_system_upgrade"] != true',
        'libc::O_NOFOLLOW',
        'meta.uid() != 0',
        'meta.nlink() != 1',
        'meta.mode() & 0o7777 != 0o644',
        'meta.mode() & 0o022 != 0',
        'pub fn system_execution_enabled() -> bool {\n    require_system_execution_policy().is_ok()\n}',
    ],
    'src/bin/rwr-update-helper.rs': [
        'fn real_execution_enabled() -> bool {\n    rwr_package_intelligence::supervisor_trust::system_execution_enabled()\n}',
        'execute_authorized_system_upgrade(',
    ],
    'src/bin/rwr-transaction-supervisor.rs': [
        'fn real_execution_enabled() -> bool {\n    rwr_package_intelligence::supervisor_trust::system_execution_enabled()\n}',
        '"commit_authorized":false',
    ],
    'src/production_alpm_flow.rs': [
        'pub use crate::supervisor_trust::system_execution_enabled as real_flow_enabled;',
        'pub fn execute_authorized_system_upgrade(',
    ],
    'src/update_launcher.rs': ['supervisor_trust::require_system_execution_policy()'],
    'src/production_ipc.rs': ['pub const PRODUCTION_BACKEND_AVAILABLE: bool = true;'],
    'src/libalpm_ffi.rs': ['fn alpm_trans_commit(', 'alpm_trans_commit(self.handle'],
    'src/authorization_gate.rs': ['AuthorizationMode::Real => AuthorizationDecision::Denied'],
}
# Booleans allowed to be compile-time true: code availability only, not permission.
ALLOWED_TRUE_CONSTANTS = {'PRODUCTION_BACKEND_AVAILABLE'}
UNIT_FORBIDDEN = ['execution-policy', 'allow_system_upgrade', 'ExecStartPre', 'ExecStartPost',
                  'ConfigurationDirectory', 'BindPaths', 'BindReadOnlyPaths', 'LoadCredential',
                  'SetCredential', 'RWR_ALLOW', 'RWR_REAL', 'RWR_EXECUTION']


def check_source_gate(source):
    """Production code is present, every participant uses the one runtime gate,
    and no compile-time switch, environment variable or other path unlocks it."""
    for name, needles in GATE_WIRING.items():
        text = (source / name).read_text()
        for needle in needles:
            require(needle in text, f'Runtime gate/production code missing in {name}: {needle.splitlines()[0]}')
    for path in sorted((source / 'src').rglob('*.rs')):
        rel = path.relative_to(source).as_posix()
        text = path.read_text()
        for constant in re.findall(r'const ([A-Z0-9_]+): bool = true;', text):
            require(constant in ALLOWED_TRUE_CONSTANTS and rel == 'src/production_ipc.rs',
                    f'Compile-time execution switch: {rel}: {constant}')
        for variable in re.findall(r'env::var(?:_os)?\(\s*"([^"]+)"', text):
            require(not re.search(r'REAL|EXECUT|POLICY|ALLOW|UNLOCK|COMMIT', variable),
                    f'Environment override of execution gate: {rel}: {variable}')
        if rel != 'src/supervisor_trust.rs':
            require('execution-policy' not in text, f'Second execution policy path: {rel}')
    print('PASS source: production COMMIT code present, single runtime policy gate, '
          'no compile-time/env unlock, legacy Real=>Denied kept')


def check_payload_default_deny(stage):
    """The package never ships, creates or binds an execution policy."""
    require(not (stage / 'etc').exists(), 'Package must not ship /etc (execution policy)')
    for path in stage.rglob('*'):
        require('execution-policy' not in path.name, f'Shipped execution policy: {path}')
    for unit in ['system', 'user']:
        for path in (stage / 'usr/lib/systemd' / unit).glob('*'):
            text = path.read_text()
            for forbidden in UNIT_FORBIDDEN:
                require(forbidden not in text, f'Unit may provision/unlock execution: {path.name}: {forbidden}')
    print('PASS default deny: no /etc payload, no policy file, units do not create or bind a policy')


def binary_gate_markers(data, role):
    require(EXECUTION_POLICY.encode() in data, f'{role}: runtime policy path not compiled in')
    require(b'REAL MODE locked' in data, f'{role}: fail-closed refusal message missing')


def check_binary_gate(stage):
    helper = stage / f'{LIB}/rwr-update-helper'
    for role, binary in [('helper', helper), ('supervisor', stage / f'{LIB}/rwr-transaction-supervisor'),
                         ('gui', stage / f'usr/bin/{NAME}')]:
        binary_gate_markers(binary.read_bytes(), role)
    dynamic = subprocess.check_output(['readelf', '--dyn-syms', '-W', str(helper)], text=True)
    require(re.search(r'\bUND\s+alpm_trans_commit\b', dynamic), 'helper: alpm_trans_commit not imported (COMMIT code eliminated)')
    sections = subprocess.check_output(['readelf', '-S', '-W', str(helper)], text=True)
    if '.symtab' in sections:
        symbols = subprocess.check_output(['nm', '-C', str(helper)], text=True)
        require(re.search(r' [Tt] .*execute_authorized_system_upgrade', symbols),
                'helper: execute_authorized_system_upgrade not present in optimized binary')
        detail = 'execute_authorized_system_upgrade symbol'
    else:
        detail = 'symbols stripped, dynamic import only'
    print(f'PASS binaries: policy gate in helper/supervisor/GUI, helper imports alpm_trans_commit, {detail}')


def check_stage(stage, source):
    for name, mode in FILES.items():
        path = stage / name
        require(path.is_file() and not path.is_symlink(), f'Missing/non-regular packaged file: {name}')
        require(stat.S_IMODE(path.stat().st_mode) == mode, f'Wrong mode: {name}')
    for path in stage.rglob('*'):
        require(not path.is_symlink(), f'Unexpected package symlink: {path}')
        if path.is_dir():
            require(stat.S_IMODE(path.stat().st_mode) == 0o755, f'Wrong directory mode: {path}')
        else:
            require(path.relative_to(stage).as_posix() in FILES or path.name in ('.PKGINFO', '.MTREE'), f'Unexpected payload: {path}')
    rust = (source / 'src/supervisor_trust.rs').read_text()
    for key, value in [('SYSTEM_HELPER', f'/{LIB}/rwr-update-helper'),
                       ('SYSTEM_SUPERVISOR', f'/{LIB}/rwr-transaction-supervisor'),
                       ('SYSTEM_SOCKET', f'/run/{NAME}/system.sock')]:
        require(re.search(rf'pub const {key}: &str = "{re.escape(value)}";', rust), f'Rust path mismatch: {key}')
    check_source_gate(source)
    check_payload_default_deny(stage)
    check_binary_gate(stage)
    service = ini(stage / f'usr/lib/systemd/system/{SYS}.service')
    socket = ini(stage / f'usr/lib/systemd/system/{SYS}.socket')
    user = ini(stage / f'usr/lib/systemd/user/{NAME}.service')
    user_socket = ini(stage / f'usr/lib/systemd/user/{NAME}.socket')
    require(service['Service']['ExecStart'] == f'/{LIB}/rwr-transaction-supervisor --serve-system', 'Wrong system ExecStart')
    require(service['Unit']['Requires'] == service['Service']['Sockets'] == f'{SYS}.socket', 'System unit reference mismatch')
    require(socket['Socket']['Service'] == f'{SYS}.service', 'Wrong socket service')
    require(socket['Socket']['ListenStream'] == f'/run/{NAME}/system.sock', 'Wrong system socket path')
    require(socket['Socket']['SocketUser'] == socket['Socket']['SocketGroup'] == 'root', 'Wrong socket ownership')
    require(socket['Socket']['SocketMode'] == '0666', 'Unexpected connect permissions')
    require(socket['Socket']['DirectoryMode'] == '0755', 'Unsafe socket parent permissions')
    for key, value in [('User', 'root'), ('Group', 'root'), ('NoNewPrivileges', 'yes'),
                       ('UMask', '0077'), ('StateDirectoryMode', '0700'),
                       ('RuntimeDirectoryMode', '0755'), ('KillMode', 'process'),
                       ('SendSIGKILL', 'no'), ('TimeoutStopSec', 'infinity')]:
        require(service['Service'][key] == value, f'System hardening/lifecycle mismatch: {key}')
    require(user['Service']['ExecStart'] == f'/{LIB}/rwr-transaction-supervisor', 'User ExecStart is not packaged')
    require(user['Service']['NoNewPrivileges'] == 'yes', 'User NNP changed')
    require(user['Unit']['Requires'] == user['Service']['Sockets'] == f'{NAME}.socket', 'User unit reference mismatch')
    require(user_socket['Socket']['Service'] == f'{NAME}.service', 'Wrong user socket service')
    require(user_socket['Socket']['ListenStream'] == f'%t/{NAME}/supervisor.sock', 'Wrong user socket')
    policy = ET.parse(stage / f'usr/share/polkit-1/actions/{POLICY}').getroot()
    actions = policy.findall('action')
    expected_actions={ACTION,ACTION.removesuffix('.update')+'.inspect'}
    require(len(actions)==2 and {action.get('id') for action in actions}==expected_actions, 'Polkit action mismatch')
    for action in actions:
        for key, value in [('allow_any', 'no'), ('allow_inactive', 'no'), ('allow_active', 'auth_admin')]:
            require(action.findtext(f'defaults/{key}') == value, f'Polkit default changed: {key}')
        require(not action.findall('annotate'), 'Obsolete elevation dispatcher annotation')
    for action in expected_actions:
        require(f'"{action}"' in (source / 'src/production_alpm_flow.rs').read_text(), 'Rust action mismatch')
    for binary in [f'usr/bin/{NAME}', f'{LIB}/rwr-update-helper', f'{LIB}/rwr-transaction-supervisor']:
        require((stage / binary).read_bytes()[:4] == b'\x7fELF', f'Not ELF: {binary}')
    desktop = (stage / 'usr/share/applications/io.github.runningwithrottweilers.PackageIntelligence.desktop').read_text()
    require(f'Exec=/usr/bin/{NAME}\n' in desktop, 'Desktop executable not packaged')
    needed = set()
    for binary in [f'usr/bin/{NAME}', f'{LIB}/rwr-update-helper', f'{LIB}/rwr-transaction-supervisor']:
        output = subprocess.check_output(['readelf', '-d', str(stage / binary)], text=True)
        needed.update(re.findall(r'NEEDED.*\[(.*?)\]', output))
    expected = {'libalpm.so.16', 'libgpgme.so.45', 'libseccomp.so.2', 'libgtk-4.so.1'}
    require(expected <= needed, f'Unexpected release dependencies: {needed}')
    require({'pacman', 'pacman-contrib', 'polkit', 'systemd', 'gnupg', 'gpgme', 'libseccomp', 'gtk4', 'libalpm.so=16-64', 'libgpgme.so=45-64'} <= set(metadata()['depends']), 'Missing runtime dependencies')
    print('PASS payload, modes, ELF/dependencies, Rust paths, unit references, Polkit, '
          'production code present, runtime gate default-deny, no shipped execution policy')


def verify_archive(path):
    # libarchive reads zstd, Python checks every resulting tar entry without
    # extracting it. No dependency on Python's optional zstd module.
    child = subprocess.Popen(['bsdtar', '-cf', '-', '--format=pax', '@' + str(path.resolve())], stdout=subprocess.PIPE)
    found = set()
    pkginfo = None
    mtree = None
    actual = {}
    try:
        with tarfile.open(fileobj=child.stdout, mode='r|') as tar:
            for item in tar:
                name = item.name.removeprefix('./').rstrip('/')
                require(not Path(name).is_absolute() and '..' not in Path(name).parts, f'Unsafe archive path: {name}')
                require(item.uid == item.gid == 0, f'Archive entry not root:root: {name}')
                require(item.isdir() or item.isfile(), f'Unsafe archive entry: {name}')
                attributes = dict(type='dir' if item.isdir() else 'file', uid=str(item.uid), gid=str(item.gid), mode=format(item.mode, 'o'), time=item.pax_headers.get('mtime', str(item.mtime)))
                actual[name] = attributes
                if item.isdir():
                    require(item.mode == 0o755, f'Wrong archive directory mode: {name}')
                    continue
                require(name not in found, f'Duplicate archive file: {name}')
                found.add(name)
                require(item.mode == FILES.get(name, 0o644), f'Wrong archive mode: {name}')
                content = tar.extractfile(item)
                attributes['size'] = str(item.size)
                hasher = hashlib.sha256()
                saved = bytearray()
                while chunk := content.read(65536):
                    hasher.update(chunk)
                    if name in ('.PKGINFO', '.MTREE'):
                        saved.extend(chunk)
                        require(len(saved) <= 1024 * 1024, 'Oversized package metadata')
                attributes['sha256digest'] = hasher.hexdigest()
                if name == '.PKGINFO':
                    pkginfo = saved.decode()
                if name == '.MTREE':
                    mtree = bytes(saved)
        require(child.wait() == 0, 'Cannot read package archive')
    finally:
        child.stdout.close()
        if child.poll() is None:
            child.terminate()
            child.wait()
    require(found == set(FILES) | {'.PKGINFO', '.MTREE'}, f'Archive manifest mismatch: {found ^ (set(FILES) | {".PKGINFO", ".MTREE"})}')
    verify_mtree(mtree, actual)
    meta = metadata()
    require(f'pkgname = {NAME}\n' in pkginfo, 'Wrong .PKGINFO name')
    require(f'pkgver = {meta["pkgver"][0]}-{meta["pkgrel"][0]}\n' in pkginfo, 'Wrong .PKGINFO version')
    for dependency in meta['depends']:
        require(f'depend = {dependency}\n' in pkginfo, f'Missing .PKGINFO dependency: {dependency}')
    print(f'PASS archive root:root ownership, complete manifest, permissions, metadata: {path.name}')


def generate_mtree(stage):
    # libarchive writes mtree nanoseconds without zero padding (5 ms -> ".5000000"),
    # which misstates sub-second times. build() normalizes to whole seconds;
    # refuse anything else instead of recording a wrong timestamp.
    for path in [stage / '.PKGINFO', stage / 'usr', *(stage / 'usr').rglob('*')]:
        require(path.lstat().st_mtime_ns % 1_000_000_000 == 0,
                f'Non-integer mtime before .MTREE generation: {path}')
    data = subprocess.check_output(['bsdtar', '-cf', '-', '--format=mtree',
        '--options=!all,type,uid,gid,mode,time,size,sha256,link',
        '--uid', '0', '--gid', '0', '-C', str(stage), '.PKGINFO', 'usr'])
    (stage / '.MTREE').write_bytes(gzip.compress(data, mtime=0))
    (stage / '.MTREE').chmod(0o644)


def verify_mtree(compressed, actual):
    require(compressed is not None, 'Missing .MTREE')
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        text = stream.read(1024 * 1024 + 1)
    require(len(text) <= 1024 * 1024 and text.startswith(b'#mtree\n'), 'Invalid/oversized .MTREE')
    entries = {}
    for line in text.decode().splitlines():
        if not line or line.startswith('#'):
            continue
        fields = line.split()
        name = fields[0].removeprefix('./')
        require(name not in entries, f'Duplicate .MTREE entry: {name}')
        entries[name] = dict(field.split('=', 1) for field in fields[1:])
    expected = {name: attrs for name, attrs in actual.items() if name != '.MTREE'}
    require(set(entries) == set(expected), '.MTREE entry set differs from payload')
    for name, attrs in expected.items():
        for key, value in attrs.items():
            recorded = entries[name].get(key)
            require(recorded is not None, f'Missing .MTREE {key}: {name}')
            require(Decimal(recorded) == Decimal(value) if key == 'time' else recorded == value,
                    f'.MTREE mismatch {key}: {name}')
    print('PASS .MTREE: gzip, exact entry set, root ownership, mode, size, mtime and SHA256 for every file')


def build():
    require(os.geteuid() != 0, 'Never run the offline packaging helper as root')
    meta = metadata()
    archive = ARCH / meta['source'][0]
    require(digest(archive) == meta['sha256sums'][0], 'Source checksum mismatch; run prepare after intentional source changes')
    work = Path(tempfile.mkdtemp(prefix='rwr-backend-package-'))
    with tarfile.open(archive, 'r:gz') as tar:
        tar.extractall(work / 'src', filter='data')
    source = work / 'src' / f'{NAME}-{meta["pkgver"][0]}'
    require(f'version = "{meta["pkgver"][0]}"' in (source / 'Cargo.toml').read_text(), 'Source version mismatch')
    target = work / 'target'
    environment = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_NET_OFFLINE='true',
                       SOURCE_DATE_EPOCH=os.environ.get('SOURCE_DATE_EPOCH', '1794349181'))
    # package() expects the normal Cargo target path in the extracted snapshot.
    (source / 'target').symlink_to(target, target_is_directory=True)
    for operation in ['build', 'package']:
        script = 'set -euo pipefail; source "$1"; srcdir="$2"; pkgdir="$3"; "$4"'
        run('bash', '--noprofile', '--norc', '-c', script, '_', str(PKGBUILD), str(work / 'src'), str(work / 'pkg'), operation, env=environment)
    stage = work / 'pkg'
    check_stage(stage, source)
    build_epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '1794349181'))
    require(build_epoch >= 0, 'Invalid SOURCE_DATE_EPOCH')
    pkginfo = [f'pkgname = {NAME}', f'pkgbase = {NAME}',
               f'pkgver = {meta["pkgver"][0]}-{meta["pkgrel"][0]}',
               f'pkgdesc = {meta["pkgdesc"][0]}', 'url = https://github.com/runningwithrottweilers',
               'builddate = ' + str(build_epoch),
               'packager = RWR local offline packaging',
               'size = ' + str(sum(p.stat().st_size for p in stage.rglob('*') if p.is_file())),
               'arch = x86_64', 'license = MIT']
    pkginfo += ['depend = ' + dep for dep in meta['depends']]
    (stage / '.PKGINFO').write_text('\n'.join(pkginfo) + '\n')
    (stage / '.PKGINFO').chmod(0o644)
    # Like makepkg, normalize timestamps before .MTREE and archive creation.
    for path in stage.rglob('*'):
        os.utime(path, (build_epoch, build_epoch), follow_symlinks=False)
    generate_mtree(stage)
    os.utime(stage / '.MTREE', (build_epoch, build_epoch))
    output = ARCH / f'{NAME}-{meta["pkgver"][0]}-{meta["pkgrel"][0]}-x86_64.pkg.tar.zst'
    require(not output.exists(), 'Refusing to overwrite an existing package candidate')
    pending = work / output.name
    run('bsdtar', '--zstd', '--uid', '0', '--gid', '0', '--uname', 'root', '--gname', 'root', '-cf', str(pending), '-C', str(stage), '.PKGINFO', '.MTREE', 'usr')
    verify_archive(pending)
    # Only expose a verified candidate, atomically and without overwriting one.
    with tempfile.NamedTemporaryFile(dir=ARCH, prefix='.verified-package-', suffix='.tmp', delete=False) as file:
        temporary = Path(file.name)
        try:
            with pending.open('rb') as content:
                shutil.copyfileobj(content, file)
            file.flush()
            os.fsync(file.fileno())
            os.chmod(temporary, 0o644)
            os.link(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)
    checksum = digest(output)
    output.with_name(output.name + '.sha256').write_text(f'{checksum}  {output.name}\n')
    print(f'PACKAGE SHA256 {checksum}')
    print(f'STAGING {stage}')
    print('NOT installed; NOT signed; no .BUILDINFO claim; REAL MODE locked by default, no execution policy shipped')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['prepare', 'build', 'verify'])
    parser.add_argument('archive', nargs='?', type=Path)
    args = parser.parse_args()
    if args.operation == 'prepare':
        prepare()
    elif args.operation == 'build':
        build()
    else:
        require(args.archive is not None, 'verify requires a package path')
        verify_archive(args.archive)


if __name__ == '__main__':
    main()
