# RWR PACKAGE INTELLIGENCE

A Rust and GTK4 update manager for Arch Linux package repositories. Review available updates and an ALPM transaction plan before authorizing a system upgrade through a separate privileged backend.

**Version: 0.1.0-19 BETA** · [GitHub pre-release v0.1.0-19-beta](https://github.com/runningwithrottweilers/rwr-package-intelligence/releases/tag/v0.1.0-19-beta).

## Scope

The application reads pacman repositories and prepares system upgrades through libalpm. REAL MODE uses a system supervisor, a transaction helper and Polkit authorization. AUR and Flatpak are not supported.

The current package has been tested on one HP CachyOS installation. This does not establish compatibility with every Arch derivative. The release was prepared on Dell Arch Linux; the HP results below were reported by the project owner, not reproduced on the Dell.

## Requirements

- Linux x86_64 with pacman and **libalpm 16.0.1**, with `libalpm.so=16-64`.
- `libgpgme.so=45-64`, GTK4, glibc, gcc-libs, glib2, cairo and gdk-pixbuf2.
- pacman-contrib, Polkit, systemd, gpgme, gnupg and libseccomp.
- A graphical session with a working Polkit authentication agent.

The archive declares these dependencies; pacman is responsible for checking them. Do not bypass dependency or signature checks. Hyprland is not required by the package.

## Safety

Read the installation instructions and limitations below before installing. This is a beta that can change system packages. Have an independent backup and a recovery method available.

REAL MODE is locked until explicitly enabled by an administrator. Enabling it does not perform an update. Each transaction requires review and authorization through Polkit; enter credentials only in the system authentication dialog. The application’s authorization screen is not a password prompt.

CheckSpace passes the configured pacman disk-space check to libalpm. It is not a filesystem snapshot, a backup or a guarantee that an update will succeed. The application does not provide rollback of completed package upgrades.

## Validation and limitations

On HP CachyOS, the owner confirmed installation, REAL MODE readiness, working supervisor and sockets, active CheckSpace, four CachyOS database signatures reporting GOODSIG, and seven repositories read without errors. The GUI scan found **0 updates and 1,528 packages**; ALPM plan preparation succeeded.

A full upgrade succeeded with 0.1.0-18. No updates were available to exercise the full upgrade path in 0.1.0-19. Five earlier GUI tests remain failing. This release is not stable.

## Reporting a bug

Use the project repository’s Issues page. Include the package version, distribution, pacman/libalpm versions, desktop session, steps to reproduce, expected and actual results, and relevant redacted logs. Mention whether REAL MODE was enabled and whether a transaction was running. Remove account names, local paths, credentials and private repository addresses. Never attach authentication secrets or unreviewed system journals.

License: MIT; see the source repository’s LICENSE and ASSETS-LICENSE.md for asset terms.

# Installation and removal — 0.1.0-19 BETA

**BETA pre-release.** The corrected build passed local regression and package checks. It has not been installed on HP; the HP results above belong to the previous artifact. No full upgrade was tested with this corrected build.

## Verify the package

See the requirements above. In the directory containing the package and checksum file:

```sh
sha256sum -c 019-SHA256SUMS
```

Do not proceed if verification fails. Check that pacman and libalpm match the required ABI and that a Polkit authentication agent is running in the graphical session. Do not bypass pacman dependency or trust checks to install this beta. The candidate is not accompanied by a detached package signature.

## Install

Ensure no package transaction is running; close the application before replacing an older version. To install the verified package:

```sh
sudo pacman -U ./019-RWR-PACKAGE-INTELLIGENCE-0.1.0-19-x86_64.pkg.tar.zst
rwr-package-intelligence-admin status
```

The package includes the GUI and privileged backend. Installing it does not enable REAL MODE. Do not use an old AppImage or a separate backend package from a previous release with this candidate.

## Enable REAL MODE (optional)

After reviewing the risks and preparing backups:

```sh
sudo rwr-package-intelligence-admin enable
rwr-package-intelligence-admin status
rwr-package-intelligence
```

The administrative command checks package integrity and libalpm compatibility, writes the execution policy and activates the system socket. It does not upgrade packages. Each update still needs a reviewed plan and Polkit authorization. The supervisor and helper may each request authorization.

The system socket is `/run/rwr-package-intelligence/system.sock`. Access to that socket alone does not authorize a transaction. A user-scoped diagnostic socket is a separate mechanism, not a substitute for REAL MODE.

For an upgrade from an already enabled older backend, use the existing deployment guide to refresh an already running supervisor only after confirming there is no active or unresolved transaction. Do not restart backend processes during a transaction.

## Disable and uninstall

Finish or resolve any active transaction first. Then:

```sh
sudo rwr-package-intelligence-admin disable
sudo pacman -R rwr-package-intelligence
```

The disable command refuses to interrupt an active helper transaction. Do not force it. Keep transaction state and journals for recovery; do not delete them as part of routine removal. Disabling or uninstalling the application does not undo completed system upgrades.

## If something goes wrong

Do not start a second transaction while the outcome of the first is unresolved. Preserve logs, inspect the existing transaction result, and use the established Arch recovery procedure when necessary. Never disable signature verification or remove pacman’s lock file merely to retry an unresolved operation.

## Changes in 0.1.0-19

Optional signature levels retain verification. CachyOS database signatures are refreshed with their databases. The multi-architecture fix from 0.1.0-18 is retained.

## Release files

[Release notes](docs/release-019/019-RELEASE-NOTES.md) · [Installation and removal](docs/release-019/019-INSTALL.md) · [Known issues](docs/release-019/019-KNOWN-ISSUES.md)
