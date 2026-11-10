# RWR Package Intelligence

**Know what's changing. Update Arch Linux with confidence.**

Arch Linux moves fast. Keeping up with updates shouldn't mean guessing what will change on your system.

**RWR Package Intelligence** brings package updates into a dark, X-Files-inspired desktop interface. See what's available, review the proposed changes, and decide when to proceed. It's a real Arch Linux updater, not just an update notification or a read-only demo.

Built by **RUNNING WITH ROTTWEILERS** for Arch Linux x86_64, with an interface available in English and Polish.

## What you can do

- **See available updates.** Scan your system and review packages and version changes before making a decision.
- **Review the full update plan.** Check the packages involved, including dependencies and proposed removals, before authorizing a transaction.
- **Stay in control.** Updating requires explicit confirmation and system Polkit authentication. RWR does not silently install updates.
- **Follow the process.** Watch the authorization and transaction status in the FBI-inspired interface.
- **Check what happened.** After a successful update, RWR scans again. If a transaction's result is uncertain, use **Check result** before trying again.

The interface has its own personality: dark panels, green highlights and an FBI authorization theme. Underneath, it uses Arch Linux's package-management mechanisms rather than pretending to update your system.

## Download

**Current beta:** `v0.1.0-beta`
**Arch package:** `rwr-package-intelligence-0.1.0-17-x86_64.pkg.tar.zst`

[**Get the beta release on GitHub**](https://github.com/runningwithrottweilers/rwr-package-intelligence/releases/tag/v0.1.0-beta)

This beta is distributed as a native Arch Linux package. An older read-only AppImage is **not** part of this release.

## Install on Arch Linux

Download the package and its `.sha256` file from the release page into the same directory. Verify the downloaded package against a checksum obtained from a source you trust:

```sh
sha256sum -c rwr-package-intelligence-0.1.0-17-x86_64.pkg.tar.zst.sha256
```

**Important:** The beta package is unsigned. A matching SHA256 detects differences from the published checksum, but does not establish who produced the package. Follow your own package-signature and trust policy.

After reviewing the package and its source, install it in an administrator shell:

```sh
pacman -U ./rwr-package-intelligence-0.1.0-17-x86_64.pkg.tar.zst
```

Launch **RWR Package Intelligence** from your application menu, or run:

```sh
/usr/bin/rwr-package-intelligence
```

You can use the same executable for a Waybar click action.

The package depends on GTK4, pacman, pacman-contrib (`checkupdates`), systemd, Polkit and other libraries listed in [PKGBUILD](packaging/arch/PKGBUILD). This build requires the `libalpm 16` and `libgpgme 45` SONAMEs. A working Polkit authentication agent is required for authorized operations.

## How updating works

1. Select **Scan** to check for available updates using a private temporary package database.
2. Select **Update** to generate a fresh plan. Review version changes, dependencies and any removals.
3. If you choose to continue, approve the transaction separately and authenticate through your system's **Polkit dialog**.
4. Follow the status in RWR. After success, the application scans again and keeps the transaction result visible.

If the plan changes before execution, review the new plan. If a session has an unresolved outcome, select **Check result** before attempting another update.

**Beta setup note:** The installed backend service definitions are locked against execution by default. Real update execution requires the deployment policy described in the [backend deployment guide](packaging/arch/BACKEND-DEPLOYMENT.md). Installing the package alone does not guarantee that the privileged update workflow is enabled.

## Uninstall

First, make sure no update transaction is running and that you know its outcome. Follow the [deployment guide](packaging/arch/BACKEND-DEPLOYMENT.md) to stop the relevant user and system sockets and services. Then, in an administrator shell:

```sh
pacman -R rwr-package-intelligence
```

Keep transaction journals and execution records if you need them for recovery or auditing. Remove any custom Waybar or desktop overrides you added separately. **Uninstalling RWR does not undo completed system updates.**

## Build and inspect

The release source archive contains the production build inputs; the development checkout also contains isolated test fixtures. The offline build process uses `Cargo.lock`, a fixed build epoch and normalized paths and archive metadata.

To reproduce a build, you need matching Rust tools, cached dependencies, system ABI and packaging tools. See the [backend deployment guide](packaging/arch/BACKEND-DEPLOYMENT.md) for build and verification instructions.

## About RUNNING WITH ROTTWEILERS

**Author & Lead Developer:** Artur Maciejewski

**Developed and published by:** RUNNING WITH ROTTWEILERS

RWR Package Intelligence is a project by **RUNNING WITH ROTTWEILERS**: Linux software with a distinct visual identity and a focus on giving users clear choices over what happens on their machines.

[RUNNING WITH ROTTWEILERS website](https://runningwithrottweilers.github.io/) · [GitHub](https://github.com/runningwithrottweilers)

## Licenses

The source code is released under the [MIT License](LICENSE). Artwork and branding are covered separately in [ASSETS-LICENSE.md](ASSETS-LICENSE.md). Third-party components retain their own licenses.
