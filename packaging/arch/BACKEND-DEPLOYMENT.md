# Backend package: controlled deployment, execution locked by default

## Enabling REAL MODE (0.1.0-16 and later)

The package installs default-deny. The one supported administrator opt-in is:

    rwr-package-intelligence-admin status          # any user, read-only
    sudo rwr-package-intelligence-admin enable     # writes the policy, enables the socket
    sudo rwr-package-intelligence-admin disable    # policy false, socket stopped and removed

`enable` refuses unless the package is installed unmodified (`pacman -Qkk`), the
system libalpm is exactly 16.0.1 and the policy directory is root-owned and not
writable by group/other or a symlink. It writes `{"schema":1,"allow_system_upgrade":true}`
atomically (root:root 0644, one link), runs
`systemctl add-wants sockets.target rwr-package-intelligence-system.socket`
(the same symlink the reference Dell deployment uses), starts the socket and
confirms with `rwr-transaction-supervisor --status` that the backend's own trust
checks accept the policy. `disable` refuses while a helper transaction runs.
Neither command updates packages, touches pacman locks, adds Polkit rules or
changes NoNewPrivileges. Enabling is not consent to any update: each update still
requires the confirmed plan in the GUI and Polkit `auth_admin` in both the
supervisor and the helper. Run `disable` before removing the package.

This package contains the existing GUI plus the transaction backend. It installs
files only. It has no install script, presets, enable/start hooks, SUID binaries,
file capabilities or automatic service activation. REAL MODE is locked by default (see below).
Installing these files is NOT approval to perform an update or activate services.
The system supervisor intentionally refuses execution while its gates are closed.

## Installed layout

| File | Owner after package extraction | Mode / purpose |
| --- | --- | --- |
| /usr/bin/rwr-package-intelligence | root:root | 0755, existing GUI |
| /usr/bin/rwr-package-intelligence-admin | root:root | 0755, administrator opt-in (status/enable/disable) |
| /usr/lib/rwr-package-intelligence/rwr-update-helper | root:root | 0755, helper |
| /usr/lib/rwr-package-intelligence/rwr-transaction-supervisor | root:root | 0755, supervisor |
| /usr/lib/systemd/system/rwr-package-intelligence-system.service | root:root | 0644, root service |
| /usr/lib/systemd/system/rwr-package-intelligence-system.socket | root:root | 0644, system socket |
| /usr/lib/systemd/user/rwr-package-intelligence.service | root:root | 0644, read-only user service |
| /usr/lib/systemd/user/rwr-package-intelligence.socket | root:root | 0644, user socket |
| /usr/share/polkit-1/actions/io.github.runningwithrottweilers.rwr-package-intelligence.policy | root:root | 0644, dedicated action |

All packaged directories have mode 0755. Persistent state is NOT shipped in the
archive: StateDirectory/helper create it root:root/0700, journals 0600. The system
runtime directory is root:root/0755; its socket has mode 0666 to allow requests.
Connect permission is not authorization. Kernel identity, pinned binaries, Polkit,
exact plan validation and execution gates are still required. The user socket is
0600 inside the user's private runtime directory.

System and user units are different scopes and different names. A check for the
unsuffixed service in the system manager does not check the system backend:
its name has the `-system` suffix. Both user/system service ExecStart values now
reference the installed supervisor; no per-user copy in ~/.local/libexec is needed.

## Authorization and service safety

The Polkit action ID is exactly
`io.github.runningwithrottweilers.rwr-package-intelligence.update`, as in Rust.
Defaults stay: allow_any=no, allow_inactive=no, allow_active=auth_admin.
The root service/helper query CheckAuthorization directly. Obsolete pkexec
exec.path/argv1 annotations are removed; the retired --upgrade GUI-owned route
is not the system service's --supervised-upgrade route.

NoNewPrivileges=yes remains on both service scopes. The user service keeps its
read-only sandbox. The system service already starts as root and does not elevate.
Do not add ProtectSystem=strict or blanket read-only package paths to the actual
installer without testing: they can cause a partially completed transaction.
KillMode=process / SendSIGKILL=no are intentional to preserve a helper in COMMIT;
this lifecycle and shutdown behavior still require actual systemd/Polkit VM tests.
No Install sections are provided, and no enabling symlinks are shipped.

## Offline preparation and inspection

Run from the project directory as an ordinary user, with existing dependencies:

```
python3 packaging/arch/backend-package.py prepare
python3 packaging/arch/backend-package.py build
python3 packaging/arch/backend-package.py verify 019-RWR-PACKAGE-INTELLIGENCE-0.1.0-19-x86_64.pkg.tar.zst
```

`prepare` creates an explicit current-source snapshot, excluding old packages,
backups, private files and PKGBUILD itself, then pins its real SHA256 in PKGBUILD.
There is no circular source checksum and no SKIP checksum. Intentional later
source changes require a new snapshot/checksum. Existing release candidates are
never overwritten. The old 0.1.0-1 package/source are not a backend deployment.

`build` verifies that source hash, extracts it into a private temporary directory,
runs the actual PKGBUILD build()/package() offline with Cargo.lock, then checks the
staged payload. It assembles a real local .pkg.tar.zst with .PKGINFO, gzip-compressed .MTREE and normalized
root:root archive ownership using libarchive. It does not run a package manager.
The source checksum, archive checksum, staging directory and validation result are
printed. SHA256 is integrity evidence only, never transaction authorization.

This is an unsigned local candidate. No .BUILDINFO is fabricated: a canonical
makepkg build was not run because it can invoke the prohibited package manager
even for read-only metadata. No claim of a signed distribution/reproducible release
or an installed-package test is made. If target signature policy requires it,
a separately approved trusted signing step is necessary; do not weaken SigLevel.

The verifier checks the entire archive, not a dummy payload: binaries/modes,
root ownership, exact file manifest, dependencies, Rust constants, unit references,
Polkit defaults, production code presence and the default-deny runtime gate. Dependencies include Polkit/systemd,
GPGME/GnuPG, libseccomp and the actual ALPM/GPGME SONAMEs. The code independently
requires libalpm 16.0.1; verify the target ABI before any separately approved
controlled deployment. This document does not authorize dependency installation.

## Remaining gates

Before deployment: review this artifact/hash, target ABI/dependency compatibility,
backup and rollback/removal of package FILES, and approve installation separately.
This is not a pacman transaction rollback guarantee. No activation or host update
is part of packaging validation.

Before enabling updates: actual Polkit decisions, root-owned path checks after
installation, FD 3/4 handoff, full isolated transaction, lease/restart/reconnect,
hooks/boot/recovery and the Dell checklist must pass. Read-only authorization
must become testable independently of the closed COMMIT gate. The existence of
a complete package does not solve those runtime validation blocks.

The .MTREE covers every payload file and .PKGINFO with real SHA256, mode, owner,
size and timestamp. The verifier compares it against archive bytes, not a fixture.
Version 0.1.0-3 fixes the missing .MTREE in the local 0.1.0-2 candidate.

Version 0.1.0-3 separates `.inspect` (authorized read-only recovery) from `.update`
(execution authorization, still locked). The root service can serve status/ATTACH
with REAL=false; EXECUTE/CANCEL remain explicitly denied by the original gates.
Status is public metadata with commit_authorized=false; journals still require
real Polkit and owner checks. Socket-activation identity uses kernel credentials
of the process sending the handshake, not the PID of systemd's listener creator.
No service is installed or activated by this tooling.

Staged timestamps are normalized to integer SOURCE_DATE_EPOCH/build time before
.MTREE generation, matching archive timestamps. A failed verification stays in
the private work directory; only a verified candidate is exposed atomically.

Version 0.1.0-5 is the first candidate intended for the Dell. It replaces the
installed 0.1.0-3, whose supervisor and GUI speak an older handshake: GUI and
supervisor must always be upgraded together from one package. 0.1.0-3 was built
three times under one name (only SHA256 0c03c2d3…7919 matches the installed
files) and 0.1.0-4 was built from a snapshot that is older than the current
helper source. Never rebuild under an existing pkgrel and never deploy -4.
Direct ELF dependencies glib2, cairo and gdk-pixbuf2 are declared explicitly.
Dell steps: packaging/arch/DELL-DEPLOYMENT-0.1.0-5.md (not part of the payload);
apply them to 0.1.0-6 with the file name and SHA256 of the newer candidate.

## 0.1.0-6: runtime execution gate replaces compile-time REAL constants

The optimized helper now contains production COMMIT code (it imports
`alpm_trans_commit`). Code presence is not permission. GUI, supervisor and helper
consult one root-owned deployment policy at runtime:
`/etc/rwr-package-intelligence/execution-policy.json` (schema 1, exactly
`schema` and `allow_system_upgrade`). Missing, invalid or untrusted policy means
REAL MODE locked; Polkit `.update` and plan confirmation are still required
per transaction. THIS PACKAGE NEVER SHIPS OR CREATES THAT FILE: the verifier
rejects any /etc payload, any policy-named file and any unit that could create,
bind or credential it (ExecStartPre/Post, ConfigurationDirectory, Bind*,
Load/SetCredential, RWR_ALLOW/REAL/EXECUTION environment).

`backend-package.py` checks instead of the old `REAL=false` constants:
single policy path and strict parser/ownership checks in `supervisor_trust.rs`;
runtime gate wiring in helper, supervisor, ALPM flow and GUI launcher; no other
compile-time `bool = true` switch except `PRODUCTION_BACKEND_AVAILABLE`; no
environment variable that names REAL/EXECUTION/POLICY/ALLOW/UNLOCK/COMMIT;
legacy `AuthorizationMode::Real => Denied` retained; policy path and
`REAL MODE locked` compiled into all three binaries; helper imports
`alpm_trans_commit` and defines `execute_authorized_system_upgrade`.
Creating the policy is a separate administrator decision after the VM/Polkit
E2E and Dell checklist; installing this package is not that decision.
