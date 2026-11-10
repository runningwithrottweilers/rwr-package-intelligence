# RWR Package Intelligence v0.1.0-beta

RWR is a GTK4 update planner and supervised full-system updater for Arch Linux x86_64. The interface supports Polish and English. It presents the prepared ALPM plan, including versions, dependencies and removals, before asking for approval. The Arch package for this beta candidate is `0.1.0-17`.

## Install on Arch Linux

Use the native Arch package and check its SHA256 against a trusted copy of the checksum. The candidate is unsigned. Follow your package signature policy.

```sh
sha256sum -c rwr-package-intelligence-0.1.0-17-x86_64.pkg.tar.zst.sha256
```

In an administrator shell, install the local application package with `pacman -U ./rwr-package-intelligence-0.1.0-17-x86_64.pkg.tar.zst`. Launch **RWR Package Intelligence** from the application menu or run `/usr/bin/rwr-package-intelligence`. For a Waybar click action use `/usr/bin/rwr-package-intelligence`.

The package declares GTK4, pacman, pacman-contrib (`checkupdates`), systemd, Polkit, curl, tar, GnuPG, GPGME and the native library dependencies in [PKGBUILD](packaging/arch/PKGBUILD). The built package requires the libalpm 16 and libgpgme 45 SONAMEs. Keep a working Polkit authentication agent in your desktop session for authorized operations.

## Scan and update

**Scan** checks for updates using a private temporary package database. **Update** prepares a fresh plan and shows the package changes. Installing requires an explicit deployment policy, separate transaction confirmation and Polkit authorization. If the plan changes, review a fresh plan before proceeding. The supervisor owns the transaction and records its outcome. The FBI status card shows authorization progress. Enter credentials in the system Polkit dialog. After success the application rescans and keeps the outcome visible. For an unresolved session, use **Check result** to request its status before retrying.

The package installs service definitions with execution locked by default. See the [deployment guide](packaging/arch/BACKEND-DEPLOYMENT.md) for socket activation, optional execution policy and recovery.

## Uninstall

Wait for any running transaction and determine its outcome. Stop the USER and SYSTEM sockets and services as described in the deployment guide. In an administrator shell run `pacman -R rwr-package-intelligence`. Keep the transaction journals and user execution references for recovery or auditing. Remove your own Waybar and local desktop overrides separately if you created them. Removing RWR does not undo completed system updates.

## Build and inspect

The source archive contains the production build inputs. The development checkout carries the isolated test fixtures separately. The offline builder uses `Cargo.lock`, a fixed build epoch, normalized paths and archive metadata. Reproduce with the same Rust toolchain, dependency cache, system ABI and packaging tools. The deployment guide lists the build and verification commands. The old read-only AppImage is outside this beta release.

## Po polsku

Zainstaluj pakiet Arch zgodnie z instrukcją powyżej. **Skanuj** sprawdza dostępne aktualizacje. **Aktualizuj** pokazuje świeży plan, wersje, zależności i usunięcia. Instalacja wymaga osobnej zgody i Polkit. Po sukcesie lista odświeża się automatycznie, a wynik transakcji pozostaje widoczny. Przy nieustalonym wyniku wybierz **Sprawdź wynik** przed ponowną próbą. Odinstalowanie RWR nie cofa zmian pakietów systemowych.

## Licenses

Source code is distributed under the [MIT License](LICENSE). Artwork and branding are covered separately in [ASSETS-LICENSE.md](ASSETS-LICENSE.md). Third-party dependencies retain their own licenses.
