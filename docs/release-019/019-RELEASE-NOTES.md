# RWR PACKAGE INTELLIGENCE 0.1.0-19 BETA

Release: `v0.1.0-19-beta` · **Pre-release**.

This beta fixes ALPM signature-level handling on CachyOS. Optional signatures retain the verification flag, so signed databases are verified when present while unsigned databases remain acceptable where the pacman configuration permits them. Database refresh also downloads the corresponding CachyOS signature files.

It includes the 0.1.0-18 fix that registers each architecture returned by pacman-conf separately, including CachyOS architecture variants.

## Test evidence

The project owner confirmed the following on HP CachyOS: installation succeeded; REAL MODE, the system supervisor and sockets were ready; CheckSpace was active; all four CachyOS database signatures returned GOODSIG; seven repositories were read without errors; GUI scanning found 0 updates and 1,528 packages; ALPM plan preparation succeeded.

A complete upgrade was tested in 0.1.0-18, not in 0.1.0-19: no upgrades were available for the latter. Five earlier GUI tests still fail. These results do not establish support for all Arch derivatives.

## Requirements and limits

x86_64, pacman, libalpm **16.0.1**, libalpm SONAME 16, libgpgme SONAME 45, GTK4, systemd and Polkit are required. See the installation guide for the full dependency list and explicit REAL MODE activation. AUR and Flatpak are not supported.

The package can modify system packages after authorization. CheckSpace is a disk-space check, not backup or transaction rollback. Keep independent backups and a recovery environment.

## Download verification

Asset: `019-RWR-PACKAGE-INTELLIGENCE-0.1.0-19-x86_64.pkg.tar.zst`

SHA256:

```text
a7e050f64729f24ef33b2a18521d7ba84acceadf6fbc6722cb000564570daae1
```

The checksum verifies the downloaded bytes against this value; it does not replace trusted provenance or a package signature. Read [installation and removal](019-INSTALL.md) and [known issues](019-KNOWN-ISSUES.md).

## Corrected build and release status

This candidate was rebuilt once to update the embedded README to 0.1.0-19 and remove private compilation paths. Application code and interface are unchanged. Local checks passed: 31 selected Rust/libalpm regressions, 13 administrative-tool tests and 25 packaging tests. The package retains the same ELF library requirements and default-deny execution policy.

The HP results above belong to the previous 0.1.0-19 artifact. This corrected artifact has not been installed on HP or used for a full system upgrade. This corrected artifact is the one distributed with this pre-release. The previous checksum no longer identifies this corrected build.
