# RWR Package Intelligence — AppImage

The AppImage contains the GTK4 application. Scanning, package descriptions,
security signals and changelogs work right away. **Real Arch Linux upgrades
additionally need the backend package**, which the administrator installs once
with pacman.

## Why there are two parts

A real upgrade is performed by a transaction supervisor and an update helper
that run as root. For that to be safe they must be root-owned files at fixed
system paths, started by systemd, with a Polkit action installed system-wide.
An AppImage is a user-owned image mounted by the user, so it can never be a
trusted source of code for root. The AppImage therefore never installs or
starts anything privileged itself; it carries the matching backend package so
you can install it with pacman after checking it.

- `RWR-Package-Intelligence-<version>-x86_64.AppImage` — the application.
- `rwr-package-intelligence-backend-<version>-x86_64.pkg.tar.zst` — supervisor,
  helper, systemd units (system and user) and the Polkit action. No install script.

Use the backend with **the same version** as the AppImage. It conflicts with the
full native package `rwr-package-intelligence` (same files): if you already use
the native package, you do not need the AppImage.

## Requirements

Arch Linux x86_64 with `gtk4`, `pacman` (libalpm 16), `pacman-contrib`,
`polkit`, `systemd`, `gpgme`, `gnupg` and a working Polkit authentication agent
in your desktop session. The AppImage uses the system GTK4 and libalpm on
purpose: libalpm must match the pacman that owns your package database.

## Install

```sh
chmod +x RWR-Package-Intelligence-<version>-x86_64.AppImage
./RWR-Package-Intelligence-<version>-x86_64.AppImage --backend-info
./RWR-Package-Intelligence-<version>-x86_64.AppImage --extract-backend ~/rwr-backend
cd ~/rwr-backend
sha256sum -c rwr-package-intelligence-backend-<version>-x86_64.pkg.tar.zst.sha256
sudo pacman -U ./rwr-package-intelligence-backend-<version>-x86_64.pkg.tar.zst
```

The package installs files only. Execution stays locked by default. Socket
activation, the optional execution policy and recovery are described in
`BACKEND-DEPLOYMENT.md` (extracted next to the package).

Installing still requires an explicit deployment policy, separate transaction
confirmation and Polkit authorization for every upgrade. Enter credentials only
in the system Polkit dialog.

## Uninstall

Wait for any running transaction and determine its outcome, stop the sockets as
described in `BACKEND-DEPLOYMENT.md`, then run
`sudo pacman -R rwr-package-intelligence-backend` and delete the AppImage.
Removing RWR does not undo completed system updates.
