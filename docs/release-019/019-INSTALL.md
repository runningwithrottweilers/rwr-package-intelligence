# Installation and removal — 0.1.0-19 BETA

**BETA pre-release.** Local checks have passed. The corrected package has not been installed on HP. The earlier HP results describe the previous artifact; no installation was performed during release preparation.

## Verify the package

Read 019-README.md for requirements. In the directory containing the package and checksum file:

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
