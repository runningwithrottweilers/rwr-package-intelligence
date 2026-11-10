# Arch beta deployment

The Arch package installs a GTK4 application, a USER supervisor, a privileged SYSTEM supervisor, a helper and Polkit action definitions. Package installation supplies files only. The administrator controls service activation and the execution policy.

## Service setup

For plan validation, start the socket from your desktop user session:

```sh
systemctl --user start rwr-package-intelligence.socket
```

For SYSTEM status, authorized recovery and execution, start the SYSTEM socket from an administrator shell:

```sh
systemctl start rwr-package-intelligence-system.socket
```

These static sockets have no `[Install]` section. To make startup persistent, use `systemctl add-wants sockets.target rwr-package-intelligence-system.socket` as administrator, and `systemctl --user add-wants sockets.target rwr-package-intelligence.socket` as the desktop user. The installed supervisor binaries are pinned by path and identity. The USER socket is private. The SYSTEM socket permits connections and applies independent authorization to protected operations.

## Execution and recovery

The optional administrator policy is `/etc/rwr-package-intelligence/execution-policy.json`. Its parent directories must be root-owned and protected from group and other writes. To explicitly permit the production execution path, an administrator can provision a regular, single-link, root-owned file with mode `0644` and these fields:

```json
{"schema":1,"allow_system_upgrade":true}
```

A missing or invalid policy locks execution. A valid policy still requires a fresh reviewed plan, a separate transaction confirmation and Polkit `.update` authorization. The helper revalidates the plan and package identities and verifies hashes and trusted signatures before COMMIT. The production mirror selection requires HTTPS. For a saved unresolved transaction, **Check result** uses the separate Polkit `.inspect` action.

The SYSTEM service retains `NoNewPrivileges=yes` and supervises the helper independently of the GUI. Keep `/var/lib/rwr-package-intelligence` and the user's saved execution references. A lost connection may leave an unknown outcome. Check the recorded result before starting another update. Completed system changes are not automatically rolled back.

## Removal

After the outcome of any transaction is known, stop the USER socket and service as the desktop user:

```sh
systemctl --user stop rwr-package-intelligence.socket rwr-package-intelligence.service
```

Stop the SYSTEM socket and service in an administrator shell:

```sh
systemctl stop rwr-package-intelligence-system.socket rwr-package-intelligence-system.service
```

If you added persistent socket activation, disable the corresponding socket in each manager before removing the package. Preserve journals and saved references. Review the administrator policy separately if you intend to reinstall later.

## Offline package inspection

Use the release source archive and its matching PKGBUILD from the same build. In a development checkout with the locked Cargo dependencies cached, run:

```sh
python3 packaging/arch/backend-package.py prepare
python3 packaging/arch/backend-package.py build
python3 packaging/arch/backend-package.py verify packaging/arch/rwr-package-intelligence-0.1.0-17-x86_64.pkg.tar.zst
```

The verifier checks the archive manifest, root ownership, modes, `.MTREE`, linked ABI, systemd and Polkit configuration, and execution gates. The archive is unsigned and does not claim makepkg `.BUILDINFO`. Reproduce it using the same locked dependencies, toolchain, native libraries and packaging utilities. The default build epoch is fixed for this candidate. The archive excludes host configuration, fixtures and development artifacts.
