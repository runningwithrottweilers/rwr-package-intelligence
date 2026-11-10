//! Isolated ALPM laboratory filesystem.
//! Never accepts a caller-supplied system root.
//! COMMIT is possible only inside the attested sandbox, on the private
//! laboratory root; no package installation, privilege escalation or
//! system database access.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_LAB_ID: AtomicU64 = AtomicU64::new(0);

pub struct AlpmLab {
    base: PathBuf,
    root: PathBuf,
    db: PathBuf,
    base_device: u64,
    base_inode: u64,
}

impl AlpmLab {
    pub fn create() -> Result<Self, String> {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/alpm-upgrade-lab/local/var/lib/pacman");

        let temp = fs::canonicalize(std::env::temp_dir())
            .map_err(|e| format!("Cannot resolve temporary directory: {e}"))?;

        let id = NEXT_LAB_ID.fetch_add(1, Ordering::Relaxed);

        let base = temp.join(format!("rwr-alpm-lab-{}-{id}", std::process::id()));

        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&base)
            .map_err(|e| format!("Cannot create isolated laboratory: {e}"))?;

        let permissions = fs::metadata(&base)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode()
            & 0o777;

        if permissions != 0o700 {
            return Err("Laboratory directory permissions are not 0700".into());
        }

        let root = base.join("root");
        let db = root.join("var/lib/pacman");

        let result = (|| -> Result<(), String> {
            for name in ["cache", "gnupg", "hooks"] {
                fs::create_dir(base.join(name)).map_err(|e| e.to_string())?;
            }

            let repository = base.join("repository");
            fs::create_dir(&repository).map_err(|e| e.to_string())?;

            let fixture_repository = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/alpm-upgrade-lab/repository");

            for name in [
                "rwr-test.db.tar.gz",
                "rwr-test.files.tar.gz",
                "rwr-test-package-1.1-1-any.pkg.tar.zst",
            ] {
                fs::copy(fixture_repository.join(name), repository.join(name))
                    .map_err(|e| format!("Repository fixture copy failed: {e}"))?;
            }

            // ALPM downloads <repo>.db / <repo>.files, not the archive's
            // storage suffix. Use regular private copies, never host symlinks.
            for (archive, alias) in [
                ("rwr-test.db.tar.gz", "rwr-test.db"),
                ("rwr-test.files.tar.gz", "rwr-test.files"),
            ] {
                fs::copy(repository.join(archive), repository.join(alias))
                    .map_err(|e| format!("Repository fixture alias copy failed: {e}"))?;
            }

            let local = db.join("local/rwr-test-package-1.0-1");

            fs::create_dir_all(&local).map_err(|e| e.to_string())?;

            fs::create_dir_all(db.join("sync")).map_err(|e| e.to_string())?;

            for (source, destination) in [
                ("local/ALPM_DB_VERSION", "local/ALPM_DB_VERSION"),
                (
                    "local/rwr-test-package-1.0-1/desc",
                    "local/rwr-test-package-1.0-1/desc",
                ),
                (
                    "local/rwr-test-package-1.0-1/files",
                    "local/rwr-test-package-1.0-1/files",
                ),
                ("sync/rwr-test.db", "sync/rwr-test.db"),
            ] {
                fs::copy(fixture.join(source), db.join(destination))
                    .map_err(|e| format!("Fixture copy failed: {e}"))?;
            }

            // Restore the installed 1.0-1 fixture into the private lab root.
            // This is a fixed, allowlisted regular file, never a caller path.
            let installed_version = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/alpm-upgrade-lab/packages/build-1.0/pkg/rwr-test-package/usr/share/rwr-alpm-test/version");

            let metadata = fs::symlink_metadata(&installed_version)
                .map_err(|e| format!("Initial package fixture inspection failed: {e}"))?;

            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err("Initial package fixture is not a regular file".into());
            }

            let contents = fs::read_to_string(&installed_version)
                .map_err(|e| format!("Initial package fixture read failed: {e}"))?;

            if contents.trim() != "1.0-1" {
                return Err("Initial laboratory package version mismatch".into());
            }

            let destination = root.join("usr/share/rwr-alpm-test/version");

            fs::create_dir_all(destination.parent().unwrap())
                .map_err(|e| format!("Initial package directory creation failed: {e}"))?;

            fs::write(&destination, contents)
                .map_err(|e| format!("Initial package fixture restore failed: {e}"))?;

            Ok(())
        })();

        if let Err(error) = result {
            let _ = fs::remove_dir_all(&base);
            return Err(error);
        }

        let metadata = fs::symlink_metadata(&base).map_err(|e| e.to_string())?;

        Ok(Self {
            base,
            root,
            db,
            base_device: metadata.dev(),
            base_inode: metadata.ino(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn db(&self) -> &Path {
        &self.db
    }
}

impl AlpmLab {
    pub(crate) fn verify_fixed_upgrade_plan(
        plan: &crate::libalpm_ffi::AlpmTransactionPlan,
    ) -> Result<(), String> {
        if plan.add.len() != 1
            || plan.add[0].name != "rwr-test-package"
            || plan.add[0].version != "1.1-1"
            || !plan.remove.is_empty()
        {
            return Err(
                "Laboratory transaction plan rejected: unexpected package selection".into(),
            );
        }
        Ok(())
    }

    fn prepare_transaction(
        transaction: &mut crate::libalpm_ffi::AlpmTransaction<'_>,
    ) -> Result<(), String> {
        transaction.select_system_upgrade()?;
        let before = transaction.planned_packages()?;
        transaction.prepare()?;
        let after = transaction.planned_packages()?;
        if before != after {
            return Err("ALPM transaction plan changed during PREPARE".into());
        }
        Ok(())
    }

    fn prepare_verified_transaction(
        transaction: &mut crate::libalpm_ffi::AlpmTransaction<'_>,
    ) -> Result<crate::libalpm_ffi::AlpmTransactionPlan, String> {
        Self::prepare_transaction(transaction)?;
        let plan = transaction.planned_packages()?;
        Self::verify_fixed_upgrade_plan(&plan)?;
        Ok(plan)
    }

    fn verify_prepared_commit_boundary(
        &self,
        transaction: &mut crate::libalpm_ffi::AlpmTransaction<'_>,
    ) -> Result<(), String> {
        self.verify_boundary()?;

        let plan = transaction.planned_packages()?;
        Self::verify_fixed_upgrade_plan(&plan)?;

        Err("Laboratory COMMIT refused: verified sandbox authorization not implemented".into())
    }

    pub fn attempt_isolated_commit(&self) -> Result<(), String> {
        use crate::libalpm_ffi::{AlpmHandle, AlpmTransaction};

        let handle = AlpmHandle::new_isolated_lab(self)?;
        handle.set_lab_architecture()?;
        handle.configure_lab_options(self)?;
        self.register_repository(&handle)?;

        let mut transaction = AlpmTransaction::begin(&handle)?;

        Self::prepare_verified_transaction(&mut transaction)?;

        // Same transaction, no second PREPARE or libalpm handle.
        // Authorization remains fail-closed.
        self.verify_prepared_commit_boundary(&mut transaction)
    }

    // O9: controlled COMMIT inside the isolated laboratory root only.
    // Authorization requires a sandbox attestation token, which cannot be
    // constructed outside the attested bwrap/seccomp laboratory. The host
    // pacman database is never touched: the libalpm handle root is the
    // private laboratory root, re-verified before and after the commit.
    pub fn run_isolated_commit_with_events(&self) -> Result<(Vec<i32>, bool, bool, bool), String> {
        use crate::libalpm_ffi::{AlpmHandle, AlpmTransaction};
        use crate::production_alpm_flow::{FlowStage, ProductionAlpmFlow};
        use crate::sandbox_attestation::LabCommitAuthorization;

        // Attestation first: on the host this always fails, so the
        // controlled commit path is unreachable outside the sandbox.
        let authorization = LabCommitAuthorization::attest()?;

        let mut flow = ProductionAlpmFlow::new_isolated_lab();

        self.verify_boundary()?;

        let mut handle = AlpmHandle::new_isolated_lab(self)?;
        handle.set_lab_architecture()?;
        handle.configure_lab_options(self)?;
        let lab_db = self.register_repository(&handle)?;
        handle.register_lab_event_callback()?;

        // Synchronisation stage: libalpm retrieves the repository database
        // into the laboratory dbpath through its own download path. The
        // laboratory db file mtime is the honest evidence of execution.
        let sync_target = self.db.join("sync/rwr-test.db");
        let sync_before = fs::metadata(&sync_target)
            .ok()
            .and_then(|metadata| metadata.modified().ok());

        handle.update_database(lab_db, true)?;

        let sync_executed = fs::metadata(&sync_target)
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .map(|after| match sync_before {
                Some(before) => after != before,
                None => true,
            })
            .unwrap_or(false);

        flow.record_stage_evidence(FlowStage::DatabaseSync, sync_executed);

        if !sync_executed {
            return Err("Laboratory database synchronisation was not executed".into());
        }

        {
            let mut transaction = AlpmTransaction::begin(&handle)?;

            // PREPARE: verified fixed plan becomes the flow's recorded plan.
            let plan = Self::prepare_verified_transaction(&mut transaction)?;
            flow.record_prepared(plan)?;

            self.verify_boundary()?;

            // Download and signature-verification boundaries are ordered by
            // the flow; libalpm performs the retrieval during COMMIT.
            flow.advance()?;
            flow.advance()?;

            self.verify_boundary()?;

            flow.begin_commit_isolated_lab(&authorization)?;
            transaction.commit_isolated_lab_authorized(&authorization)?;

            self.verify_boundary()?;
            transaction.release()?;
        }

        // Verify the isolated result: only the fixed package upgrade is
        // accepted as a committed outcome.
        let version = self
            .root
            .join("usr/share/rwr-alpm-test/version")
            .canonicalize()
            .map_err(|e| format!("Laboratory post-commit read failed: {e}"))?;

        if !version.starts_with(self.root.canonicalize().map_err(|e| e.to_string())?) {
            return Err("Laboratory post-commit path escaped the laboratory".into());
        }

        let contents = fs::read_to_string(&version)
            .map_err(|e| format!("Laboratory post-commit verification failed: {e}"))?;

        if contents.trim() != "1.1-1" {
            return Err(format!(
                "Laboratory COMMIT produced unexpected version: {}",
                contents.trim()
            ));
        }

        // Honest stage evidence: libalpm retrieves the package file into
        // the laboratory cache; the repository is registered with siglevel
        // 0, so signature verification is NOT exercised.
        let download_executed = self
            .base
            .join("cache")
            .join("rwr-test-package-1.1-1-any.pkg.tar.zst")
            .is_file();

        flow.record_stage_evidence(FlowStage::Download, download_executed);
        flow.record_stage_evidence(FlowStage::Signatures, false);

        let events = handle.laboratory_event_sequence();
        if events.is_empty() {
            return Err("Isolated COMMIT delivered no libalpm events".into());
        }

        // The result boundary closes the flow only after a real COMMIT.
        flow.finish()?;

        Ok((events, sync_executed, download_executed, false))
    }

    // O6: isolated PREPARE with actual libalpm callback events.
    // No COMMIT, no caller-selected root or repository.
    pub fn prepare_isolated_transaction_with_events(&self) -> Result<Vec<i32>, String> {
        use crate::libalpm_ffi::{AlpmHandle, AlpmTransaction};

        self.verify_boundary()?;

        let mut handle = AlpmHandle::new_isolated_lab(self)?;
        handle.set_lab_architecture()?;
        handle.configure_lab_options(self)?;
        self.register_repository(&handle)?;
        handle.register_lab_event_callback()?;

        {
            let mut transaction = AlpmTransaction::begin(&handle)?;
            Self::prepare_verified_transaction(&mut transaction)?;
            self.verify_boundary()?;
            transaction.release()?;
        }

        let events = handle.laboratory_event_sequence();
        if events.is_empty() {
            return Err("Isolated PREPARE delivered no libalpm events".into());
        }

        Ok(events)
    }

    pub fn prepare_isolated_transaction(
        &self,
    ) -> Result<crate::libalpm_ffi::AlpmTransactionPlan, String> {
        use crate::libalpm_ffi::{AlpmHandle, AlpmTransaction};

        let handle = AlpmHandle::new_isolated_lab(self)?;
        // The isolated laboratory owns both root and repository selection.
        // No caller-provided filesystem root is accepted.
        handle.set_lab_architecture()?;
        handle.configure_lab_options(self)?;
        self.register_repository(&handle)?;

        let mut transaction = AlpmTransaction::begin(&handle)?;

        let plan = Self::prepare_verified_transaction(&mut transaction)?;

        // PREPARE and the future authorized COMMIT must use
        // the same active libalpm transaction.
        // For now the transaction is deliberately released.
        self.verify_boundary()?;
        transaction.release()?;

        Ok(plan)
    }
}

impl AlpmLab {
    pub(crate) fn verify_boundary(&self) -> Result<(), String> {
        let root = self
            .root
            .canonicalize()
            .map_err(|e| format!("Cannot resolve laboratory root: {e}"))?;

        let db = self
            .db
            .canonicalize()
            .map_err(|e| format!("Cannot resolve laboratory database: {e}"))?;

        let base = self
            .base
            .canonicalize()
            .map_err(|e| format!("Cannot resolve laboratory base: {e}"))?;

        if root != base.join("root") || db != root.join("var/lib/pacman") || !db.starts_with(&base)
        {
            return Err("Laboratory filesystem boundary violated".into());
        }

        for name in ["repository", "cache", "gnupg", "hooks"] {
            let path = self.base.join(name);
            let resolved = path
                .canonicalize()
                .map_err(|e| format!("Cannot resolve laboratory auxiliary directory: {e}"))?;

            if resolved != base.join(name) {
                return Err("Laboratory auxiliary directory boundary violated".into());
            }
        }

        for path in [
            &self.base,
            &self.root,
            &self.root.join("usr"),
            &self.root.join("usr/share"),
            &self.root.join("usr/share/rwr-alpm-test"),
            &self.root.join("var"),
            &self.root.join("var/lib"),
            &self.db,
            &self.base.join("repository"),
            &self.base.join("cache"),
            &self.base.join("gnupg"),
            &self.base.join("hooks"),
        ] {
            let metadata = fs::symlink_metadata(path)
                .map_err(|e| format!("Laboratory path inspection failed: {e}"))?;

            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("Laboratory path is not a real directory".into());
            }
        }

        Ok(())
    }

    fn register_repository(
        &self,
        handle: &crate::libalpm_ffi::AlpmHandle,
    ) -> Result<*mut crate::libalpm_ffi::RawAlpmDb, String> {
        self.verify_boundary()?;
        handle.register_fixed_lab_repository(&self.base.join("repository"))
    }
}

impl Drop for AlpmLab {
    fn drop(&mut self) {
        // Cleanup is limited to the private directory created by this instance.
        let metadata = match fs::symlink_metadata(&self.base) {
            Ok(metadata) => metadata,
            Err(error) => {
                eprintln!("RWR laboratory cleanup refused: {error}");
                return;
            }
        };

        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.dev() != self.base_device
            || metadata.ino() != self.base_inode
        {
            eprintln!("RWR laboratory cleanup refused: directory identity changed");
            return;
        }

        if let Err(error) = fs::remove_dir_all(&self.base) {
            eprintln!("RWR laboratory cleanup failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_lab_plan_accepts_only_fixed_upgrade() {
        use crate::libalpm_ffi::{AlpmPlannedPackage, AlpmTransactionPlan};
        let package = |name: &str, version: &str| AlpmPlannedPackage {
            name: name.into(),
            version: version.into(),
        };
        let mut plan = AlpmTransactionPlan {
            add: vec![package("rwr-test-package", "1.1-1")],
            remove: vec![],
        };
        assert!(AlpmLab::verify_fixed_upgrade_plan(&plan).is_ok());
        plan.add[0].version = "9.9-9".into();
        assert!(AlpmLab::verify_fixed_upgrade_plan(&plan).is_err());
        plan.add[0].version = "1.1-1".into();
        plan.add.push(package("unexpected-package", "1.0-1"));
        assert!(AlpmLab::verify_fixed_upgrade_plan(&plan).is_err());
        plan.add.pop();
        plan.remove.push(package("system-package", "1.0-1"));
        assert!(AlpmLab::verify_fixed_upgrade_plan(&plan).is_err());
    }

    #[test]
    fn cleanup_refuses_replaced_laboratory_directory() {
        let lab = AlpmLab::create().unwrap();
        let original = lab.base.clone();
        let moved = original.with_extension("moved");

        assert!(!moved.exists());
        fs::rename(&original, &moved).unwrap();
        fs::create_dir(&original).unwrap();

        let marker = original.join("replacement-must-survive");
        fs::write(&marker, "protected").unwrap();

        drop(lab);

        assert!(marker.is_file(), "Replacement directory was removed");
        assert_eq!(fs::read_to_string(&marker).unwrap(), "protected");

        fs::remove_dir_all(&original).unwrap();
        fs::remove_dir_all(&moved).unwrap();
    }

    #[test]
    fn laboratory_starts_with_installed_package_1_0() {
        let lab = AlpmLab::create().unwrap();

        let version = lab.root().join("usr/share/rwr-alpm-test/version");

        assert!(version.is_file());
        assert_eq!(std::fs::read_to_string(version).unwrap().trim(), "1.0-1");
        assert!(lab.verify_boundary().is_ok());
    }

    #[test]
    fn laboratory_uses_private_root() {
        let lab = AlpmLab::create().unwrap();

        assert_ne!(lab.root(), Path::new("/"));
        assert_ne!(lab.db(), Path::new("/var/lib/pacman"));
        assert!(lab.root().starts_with(&lab.base));
        assert!(lab.db().starts_with(lab.root()));
        assert!(lab.db().join("local/ALPM_DB_VERSION").is_file());
        assert!(lab.db().join("sync/rwr-test.db").is_file());
    }

    #[test]
    fn laboratory_rejects_symlinked_package_destination() {
        use std::os::unix::fs::symlink;

        let lab = AlpmLab::create().unwrap();
        let destination = lab.root().join("usr/share/rwr-alpm-test");
        let original = lab.base.join("original-package-directory");

        fs::rename(&destination, &original).unwrap();
        symlink(&original, &destination).unwrap();

        let error = lab.verify_boundary().unwrap_err();
        assert!(error.contains("boundary violated") || error.contains("not a real directory"));

        fs::remove_file(&destination).unwrap();
        fs::rename(&original, &destination).unwrap();
    }

    #[test]
    fn laboratory_rejects_symlinked_database() {
        use std::os::unix::fs::symlink;

        let lab = AlpmLab::create().unwrap();

        assert!(lab.verify_boundary().is_ok());

        let original = lab.root.join("var/lib/pacman");
        let relocated = lab.root.join("var/lib/pacman-original");

        std::fs::rename(&original, &relocated).unwrap();
        symlink(&relocated, &original).unwrap();

        let error = lab.verify_boundary().unwrap_err();

        assert!(error.contains("boundary violated") || error.contains("not a real directory"));

        assert!(crate::libalpm_ffi::AlpmHandle::new_isolated_lab(&lab).is_err());
    }

    #[test]
    fn laboratory_rejects_symlinked_cache() {
        use std::os::unix::fs::symlink;

        let lab = AlpmLab::create().unwrap();

        let original = lab.base.join("cache");
        let relocated = lab.base.join("cache-original");

        std::fs::rename(&original, &relocated).unwrap();
        symlink(&relocated, &original).unwrap();

        let error = lab.verify_boundary().unwrap_err();

        assert!(
            error.contains("auxiliary directory boundary violated")
                || error.contains("not a real directory")
        );

        assert!(crate::libalpm_ffi::AlpmHandle::new_isolated_lab(&lab).is_err());
    }

    #[test]
    fn laboratory_removes_its_directory() {
        let base = {
            let lab = AlpmLab::create().unwrap();
            lab.base.clone()
        };

        assert!(!base.exists());
    }

    #[test]
    fn laboratories_have_unique_directories() {
        let first = AlpmLab::create().unwrap();
        let second = AlpmLab::create().unwrap();

        assert_ne!(first.base, second.base);
    }
}

#[cfg(test)]
mod stage_4_3_13_commit_gate_tests {
    use super::*;

    #[test]
    fn prepared_transaction_reaches_authorization_denial() {
        let lab = AlpmLab::create().unwrap();

        let error = lab.attempt_isolated_commit().unwrap_err();

        assert!(
            error.contains("verified sandbox authorization not implemented"),
            "Unexpected error: {error}"
        );
    }

    #[test]
    fn controlled_commit_is_unreachable_outside_sandbox() {
        let lab = AlpmLab::create().unwrap();

        // The attestation cannot pass on the host, so the controlled
        // laboratory COMMIT is refused before any libalpm handle exists.
        let error = lab.run_isolated_commit_with_events().unwrap_err();

        assert!(
            error.contains("Sandbox verification failed") || error.contains("sandbox"),
            "Unexpected host commit refusal: {error}"
        );

        // The laboratory was never committed into.
        let version = lab.root().join("usr/share/rwr-alpm-test/version");
        assert_eq!(fs::read_to_string(version).unwrap().trim(), "1.0-1");
    }
}

impl AlpmLab {
    pub fn repository(&self) -> PathBuf {
        self.base.join("repository")
    }
}

impl AlpmLab {
    /// Genuine signed-repository transaction. Capability/namespace checks run
    /// before key generation, download or COMMIT. No host path is writable.
    pub fn run_signed_transaction_case(&self, case: &str) -> Result<serde_json::Value, String> {
        use crate::libalpm_ffi::{AlpmHandle, AlpmTransaction};
        use std::process::Command;
        let authorization = crate::sandbox_attestation::LabCommitAuthorization::attest()?;
        self.verify_boundary()?;
        if ![
            "valid",
            "missing-db-signature",
            "bad-db-signature",
            "missing-package-signature",
            "bad-package-signature",
            "untrusted-signer",
            "corrupt-archive",
            "download-failure",
            "dependency-failure",
            "database-lock",
            "file-conflict",
            "install-error",
            "interrupt",
        ]
        .contains(&case)
        {
            return Err("Unknown signed laboratory scenario".into());
        }
        let repository = self.base.join("repository");
        let package = repository.join("rwr-test-package-1.1-1-any.pkg.tar.zst");
        let signer = self.base.join("signer");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&signer)
            .map_err(|e| e.to_string())?;
        fn run(command: &mut Command) -> Result<Vec<u8>, String> {
            let output = command.output().map_err(|e| e.to_string())?;
            if !output.status.success() {
                return Err(format!(
                    "Laboratory fixture command failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Ok(output.stdout)
        }
        let gpg = |args: &[&str]| {
            let mut c = Command::new("/usr/bin/gpg");
            c.arg("--homedir")
                .arg(&signer)
                .args([
                    "--batch",
                    "--yes",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                ])
                .args(args);
            c
        };
        run(&mut gpg(&[
            "--quick-generate-key",
            "RWR ephemeral lab <lab@invalid>",
            "ed25519",
            "sign",
            "0",
        ]))?;
        if case != "untrusted-signer" {
            for name in ["pubring.kbx", "pubring.gpg", "trustdb.gpg"] {
                let source = signer.join(name);
                if source.is_file() {
                    fs::copy(source, self.base.join("gnupg").join(name))
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        let signature = repository.join("rwr-test-package-1.1-1-any.pkg.tar.zst.sig");
        let mut sign = gpg(&["--detach-sign", "--output"]);
        sign.arg(&signature).arg(&package);
        run(&mut sign)?;
        if case == "bad-package-signature" {
            fs::write(&signature, b"invalid detached PGP signature").map_err(|e| e.to_string())?;
        }
        let encoded = run(Command::new("/usr/bin/base64")
            .arg("--wrap=0")
            .arg(&signature))?;
        let entries = self.base.join("signed-db");
        fs::create_dir(&entries).map_err(|e| e.to_string())?;
        run(Command::new("/usr/bin/tar")
            .arg("-xzf")
            .arg(repository.join("rwr-test.db.tar.gz"))
            .arg("-C")
            .arg(&entries))?;
        let desc = entries.join("rwr-test-package-1.1-1/desc");
        let mut metadata = fs::read_to_string(&desc).map_err(|e| e.to_string())?;
        if case != "missing-package-signature" {
            metadata.push_str(&format!(
                "\n%PGPSIG%\n{}\n\n",
                String::from_utf8(encoded).map_err(|e| e.to_string())?
            ));
        }
        if case == "dependency-failure" {
            metadata.push_str("\n%DEPENDS%\nrwr-nonexistent-dependency>=1\n\n");
        }
        fs::write(desc, metadata).map_err(|e| e.to_string())?;
        let database = repository.join("rwr-test.db");
        run(Command::new("/usr/bin/tar")
            .arg("-czf")
            .arg(&database)
            .arg("-C")
            .arg(&entries)
            .arg("rwr-test-package-1.1-1"))?;
        let db_signature = repository.join("rwr-test.db.sig");
        let mut sign = gpg(&["--detach-sign", "--output"]);
        sign.arg(&db_signature).arg(&database);
        run(&mut sign)?;
        if case == "missing-db-signature" {
            fs::remove_file(&db_signature).map_err(|e| e.to_string())?;
        }
        if case == "bad-db-signature" {
            fs::write(&db_signature, b"invalid database signature").map_err(|e| e.to_string())?;
        }
        if case == "missing-package-signature" {
            fs::remove_file(&signature).map_err(|e| e.to_string())?;
        }
        if case == "corrupt-archive" {
            use std::io::Write;
            std::fs::OpenOptions::new()
                .append(true)
                .open(&package)
                .map_err(|e| e.to_string())?
                .write_all(b"tampered")
                .map_err(|e| e.to_string())?;
        }
        if case == "download-failure" {
            fs::remove_file(&package).map_err(|e| e.to_string())?;
        }
        if case == "valid" {
            // Exercise the production GUI/helper planner's two private GPG
            // homes before returning to the execution keyring in this process.
            let plan =
                crate::production_alpm_flow::PreparedFullUpgrade::prepare_isolated(self.root())?;
            plan.confirm_and_revalidate(true)?;
        }
        // Discard only the unsigned private copy. The new database MUST verify.
        fs::remove_file(self.db.join("sync/rwr-test.db")).map_err(|e| e.to_string())?;
        let version = self.root.join("usr/share/rwr-alpm-test/version");
        let (callback_tx, callback_rx) = std::sync::mpsc::sync_channel(128);
        let mut downloaded = false;
        let mut signatures = false;
        let mut commit_started = false;
        let mut interrupted = false;
        let result = (|| -> Result<(), String> {
            let mut handle = AlpmHandle::new_isolated_lab(self)?;
            handle.set_lab_architecture()?;
            handle.configure_lab_options(self)?;
            let db = handle.register_fixed_lab_repository_strict(&repository)?;
            handle.register_lab_event_callback()?;
            if case == "valid" {
                handle.configure_signed_lab_progress(callback_tx.clone())?;
            }
            handle.update_database(db, true)?;
            if case == "database-lock" {
                fs::write(self.db.join("db.lck"), b"another laboratory transaction")
                    .map_err(|e| e.to_string())?;
            }
            let mut download = AlpmTransaction::begin_download_only(&handle)?;
            Self::prepare_verified_transaction(&mut download)?;
            let targets = download.signed_download_targets()?;
            download.commit_isolated_lab_authorized(&authorization)?;
            downloaded = self
                .base
                .join("cache/rwr-test-package-1.1-1-any.pkg.tar.zst")
                .is_file();
            let verified = handle.verify_downloads(&targets, &self.base.join("cache"))?;
            signatures = true;
            download.release()?;
            if fs::read_to_string(&version)
                .map_err(|e| e.to_string())?
                .trim()
                != "1.0-1"
            {
                return Err("Download-only phase unexpectedly installed a package".into());
            }
            if case == "file-conflict" {
                fs::write(
                    self.db.join("local/rwr-test-package-1.0-1/files"),
                    "%FILES%\n\n",
                )
                .map_err(|e| e.to_string())?;
            }
            drop(handle);
            let mut handle = AlpmHandle::new_isolated_lab(self)?;
            handle.set_lab_architecture()?;
            handle.configure_lab_options(self)?;
            handle.register_fixed_lab_repository_strict(&repository)?;
            handle.register_lab_event_callback()?;
            if case == "valid" {
                handle.configure_signed_lab_progress(callback_tx.clone())?;
            }
            let mut install = AlpmTransaction::begin(&handle)?;
            Self::prepare_verified_transaction(&mut install)?;
            if case == "install-error" {
                fs::set_permissions(version.parent().unwrap(), fs::Permissions::from_mode(0o500))
                    .map_err(|e| e.to_string())?;
            }
            if case == "interrupt" {
                handle
                    .cancellation_request()
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
            self.verify_boundary()?;
            // Durable marker precedes any possible mutation. No rollback claim.
            fs::write(
                self.base.join("transaction-journal"),
                "commit-started; interrupted outcome requires recovery\n",
            )
            .map_err(|e| e.to_string())?;
            commit_started = true;
            let committed = install.commit_signed_lab(&authorization, &verified);
            interrupted = handle.interruption_delivered();
            committed?;
            install.release()?;
            if fs::read_to_string(&version)
                .map_err(|e| e.to_string())?
                .trim()
                != "1.1-1"
            {
                return Err("Post-install version check failed; recovery required".into());
            }
            Ok(())
        })();
        if case == "install-error" {
            fs::set_permissions(version.parent().unwrap(), fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let installed = fs::read_to_string(&version).map_err(|e| e.to_string())?;
        let error = result.as_ref().err().cloned();
        if case == "valid" {
            result?;
            if !downloaded || !signatures {
                return Err("Signed stages were not actually verified".into());
            }
        } else {
            if result.is_ok() {
                return Err(format!("Unsafe acceptance of negative signed case: {case}"));
            }
            if case != "interrupt" && installed.trim() != "1.0-1" {
                return Err(format!("Negative case modified installed payload: {case}"));
            }
            if case == "interrupt" && !interrupted {
                return Err("Interrupt was not delivered to ALPM".into());
            }
        }
        self.verify_boundary()?;
        let callbacks: Vec<_> = callback_rx.try_iter().collect();
        let download_callbacks = callbacks
            .iter()
            .filter(|v| {
                v["text"]
                    .as_str()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
                    .is_some_and(|v| v["stage"] == "download")
            })
            .count();
        let install_callbacks = callbacks
            .iter()
            .filter(|v| {
                v["text"]
                    .as_str()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
                    .is_some_and(|v| {
                        v["stage"] == "alpm-progress"
                            && v["kind"]
                                .as_i64()
                                .is_some_and(|kind| (0..=4).contains(&kind))
                    })
            })
            .count();
        Ok(
            serde_json::json!({"download_callbacks":download_callbacks,"install_callbacks":install_callbacks,"case":case,"observed":if error.is_none(){"success"}else{"rejected"},
            "downloaded":downloaded,"signatures_verified":signatures,"commit_started":commit_started,
            "interrupt_delivered":interrupted,"installed_version":installed.trim(),"error":error,
            "partial_installation_possible":commit_started && case!="valid","automatic_rollback":false,
            "real_execution_enabled":false}),
        )
    }
}
