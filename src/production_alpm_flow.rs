//! RWR PACKAGE INTELLIGENCE — production ALPM flow specification.
//!
//! Real full-upgrade PREPARE planning uses private database copies and fresh
//! configured repositories. The host is never updated by planning. Production
//! execution remains disabled and requires both privileged authorization and
//! an explicitly confirmed, revalidated plan matching the live transaction.

use crate::libalpm_ffi::AlpmTransactionPlan;
use crate::transaction_state::UpdatePhase;

/// Whether the production flow may execute. Permanently false until the
/// privileged backend, authorization path and packaging are verified.
pub use crate::supervisor_trust::system_execution_enabled as real_flow_enabled;

/// Canonical production stages. Download and signature verification are
/// explicit boundaries before the irreversible COMMIT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionAlpmPhase {
    Prepare,
    Download,
    Signatures,
    Commit,
    Finished,
}

impl ProductionAlpmPhase {
    /// Ordinary forward transitions. COMMIT is deliberately excluded:
    /// entering it requires `begin_commit` with an authorization token.
    pub fn allows_advance(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Prepare, Self::Download) | (Self::Download, Self::Signatures)
        )
    }

    /// The worker boundary that must be verified before COMMIT may begin.
    pub fn requires_worker_ready(self) -> bool {
        matches!(self, Self::Signatures)
    }
}

/// Classification of known libalpm transaction error numbers. Unknown or
/// future errors are deliberately not guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpmErrorKind {
    UnsatisfiedDependencies,
    ConflictingDependencies,
    FileConflicts,
    SignatureVerification,
    RetrievalFailure,
    Unknown,
}

pub fn classify_alpm_error(errno: i32) -> AlpmErrorKind {
    match errno {
        crate::libalpm_ffi::ALPM_ERR_UNSATISFIED_DEPS => AlpmErrorKind::UnsatisfiedDependencies,
        crate::libalpm_ffi::ALPM_ERR_CONFLICTING_DEPS => AlpmErrorKind::ConflictingDependencies,
        crate::libalpm_ffi::ALPM_ERR_FILE_CONFLICTS => AlpmErrorKind::FileConflicts,
        crate::libalpm_ffi::ALPM_ERR_DB_INVALID_SIG
        | crate::libalpm_ffi::ALPM_ERR_PKG_INVALID_SIG
        | crate::libalpm_ffi::ALPM_ERR_PKG_MISSING_SIG
        | crate::libalpm_ffi::ALPM_ERR_SIG_MISSING
        | crate::libalpm_ffi::ALPM_ERR_SIG_INVALID => AlpmErrorKind::SignatureVerification,
        crate::libalpm_ffi::ALPM_ERR_RETRIEVE_PREPARE | crate::libalpm_ffi::ALPM_ERR_RETRIEVE => {
            AlpmErrorKind::RetrievalFailure
        }
        _ => AlpmErrorKind::Unknown,
    }
}

/// COMMIT authority is independent of the GUI claim. Construction requires
/// REAL MODE, a kernel-authenticated launcher and an actual Polkit decision.
#[derive(Debug)]
pub struct SystemCommitAuthorization {
    transaction_id: String,
    plan_digest: String,
    caller_uid: u32,
}

/// Ordered production flow state. Every destructive boundary is gated:
/// phases advance only in canonical order, a recorded failure blocks all
/// progress, and COMMIT additionally requires an authorization token and
/// the matching mode.
#[derive(Debug)]
pub struct ProductionAlpmFlow {
    locked: bool,
    phase: Option<ProductionAlpmPhase>,
    plan: Option<AlpmTransactionPlan>,
    error: Option<AlpmErrorKind>,
    sync_evidence: Option<bool>,
    download_evidence: Option<bool>,
    signatures_evidence: Option<bool>,
}

impl Default for ProductionAlpmFlow {
    fn default() -> Self {
        Self::new()
    }
}

/// Non-destructive stages whose real execution must be evidenced honestly:
/// a stage that libalpm did not perform is reported as not exercised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowStage {
    DatabaseSync,
    Download,
    Signatures,
}

impl ProductionAlpmFlow {
    /// Production mode: requires the runtime deployment gate and authority.
    pub fn new() -> Self {
        Self {
            locked: true,
            phase: Some(ProductionAlpmPhase::Prepare),
            plan: None,
            error: None,
            sync_evidence: None,
            download_evidence: None,
            signatures_evidence: None,
        }
    }

    /// Isolated laboratory mode: stages execute only inside the attested
    /// sandbox (the commit token is unconstructible on the host), and the
    /// production `begin_commit` stays locked regardless of this mode.
    pub fn new_isolated_lab() -> Self {
        Self {
            locked: false,
            ..Self::new()
        }
    }

    pub fn phase(&self) -> Option<ProductionAlpmPhase> {
        self.phase
    }

    pub fn plan(&self) -> Option<&AlpmTransactionPlan> {
        self.plan.as_ref()
    }

    pub fn error(&self) -> Option<AlpmErrorKind> {
        self.error
    }

    /// PREPARE completed: store the verified plan. Download follows on the
    /// next successful advance.
    pub fn record_prepared(&mut self, plan: AlpmTransactionPlan) -> Result<(), String> {
        if self.phase != Some(ProductionAlpmPhase::Prepare) {
            return Err(format!(
                "Production ALPM PREPARE refused in {:?} phase",
                self.phase
            ));
        }
        self.plan = Some(plan);
        Ok(())
    }

    /// Advance through the non-destructive boundaries (download, signature
    /// verification). Any recorded failure blocks progress permanently.
    /// In production mode this stays locked; the laboratory scope is
    /// authorized by the sandbox attestation token at the COMMIT boundary.
    pub fn advance(&mut self) -> Result<ProductionAlpmPhase, String> {
        if self.locked {
            return Err("REAL MODE locked: production ALPM flow disabled".into());
        }

        if self.error.is_some() {
            return Err("Production ALPM flow already failed".into());
        }

        let next = match self.phase {
            Some(ProductionAlpmPhase::Prepare) => ProductionAlpmPhase::Download,
            Some(ProductionAlpmPhase::Download) => ProductionAlpmPhase::Signatures,
            other => {
                return Err(format!(
                    "Invalid production ALPM flow transition from {other:?}"
                ));
            }
        };

        self.phase = Some(next);
        Ok(next)
    }

    /// COMMIT boundary: deployment opt-in never replaces verified authority.
    pub fn begin_commit(
        &mut self,
        authorization: &SystemCommitAuthorization,
        confirmation: ConfirmedUpgrade,
        transaction: &crate::libalpm_ffi::AlpmTransaction<'_>,
    ) -> Result<ProductionAlpmPhase, String> {
        if !real_flow_enabled() {
            return Err("REAL MODE locked: production COMMIT disabled".into());
        }

        authorization.verify_confirmation(&confirmation)?;
        confirmation.verify_transaction(transaction)?;
        if self.plan.as_ref() != Some(&transaction.planned_packages()?) {
            return Err("Flow selection differs from the confirmed live transaction".into());
        }

        if self.error.is_some() || self.phase != Some(ProductionAlpmPhase::Signatures) {
            return Err("Production COMMIT requires verified signatures".into());
        }

        self.phase = Some(ProductionAlpmPhase::Commit);
        Ok(ProductionAlpmPhase::Commit)
    }

    /// COMMIT boundary in the isolated laboratory. The attestation token is
    /// only constructible inside the sandbox, so on the host this is
    /// unreachable and the flow can never enter COMMIT.
    pub fn begin_commit_isolated_lab(
        &mut self,
        _authorization: &crate::sandbox_attestation::LabCommitAuthorization,
    ) -> Result<ProductionAlpmPhase, String> {
        if self.locked {
            return Err("REAL MODE locked: laboratory flow scope violated".into());
        }

        if self.error.is_some() || self.phase != Some(ProductionAlpmPhase::Signatures) {
            return Err("Laboratory COMMIT requires the signatures boundary".into());
        }

        self.phase = Some(ProductionAlpmPhase::Commit);
        Ok(ProductionAlpmPhase::Commit)
    }

    /// The verified result boundary: only a COMMIT may finish a flow.
    pub fn finish(&mut self) -> Result<ProductionAlpmPhase, String> {
        if self.phase != Some(ProductionAlpmPhase::Commit) {
            return Err("Production ALPM result requires COMMIT".into());
        }

        self.phase = Some(ProductionAlpmPhase::Finished);
        Ok(ProductionAlpmPhase::Finished)
    }

    /// Record whether libalpm actually performed a stage (honest reporting:
    /// the laboratory repository has no signatures, so signature checks are
    /// reported as not exercised).
    pub fn record_stage_evidence(&mut self, stage: FlowStage, executed: bool) {
        match stage {
            FlowStage::DatabaseSync => self.sync_evidence = Some(executed),
            FlowStage::Download => self.download_evidence = Some(executed),
            FlowStage::Signatures => self.signatures_evidence = Some(executed),
        }
    }

    pub fn stage_evidence(&self, stage: FlowStage) -> Option<bool> {
        match stage {
            FlowStage::DatabaseSync => self.sync_evidence,
            FlowStage::Download => self.download_evidence,
            FlowStage::Signatures => self.signatures_evidence,
        }
    }

    /// Record a failed libalpm operation. The flow can never advance again.
    pub fn fail(&mut self, errno: i32) -> AlpmErrorKind {
        let kind = classify_alpm_error(errno);
        self.error = Some(kind);
        kind
    }

    /// The `UpdatePhase` boundary the transaction worker must observe
    /// before the matching flow stage may proceed.
    pub fn worker_phase(&self) -> UpdatePhase {
        match self.phase {
            Some(ProductionAlpmPhase::Commit) => UpdatePhase::Commit,
            Some(ProductionAlpmPhase::Finished) => UpdatePhase::Finished,
            Some(_) | None => UpdatePhase::Prepare,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::libalpm_ffi::AlpmPlannedPackage;

    fn fixed_plan() -> AlpmTransactionPlan {
        AlpmTransactionPlan {
            add: vec![AlpmPlannedPackage {
                name: "rwr-test-package".into(),
                version: "1.1-1".into(),
            }],
            remove: vec![],
        }
    }

    #[test]
    fn real_flow_remains_disabled() {
        assert!(!real_flow_enabled());
        let mut flow = ProductionAlpmFlow::new();
        flow.record_prepared(fixed_plan()).unwrap();
        assert!(flow.advance().is_err());
        assert_eq!(flow.plan().unwrap().add[0].version, "1.1-1");
    }

    #[test]
    fn canonical_order_is_enforced() {
        assert!(ProductionAlpmPhase::Prepare.allows_advance(ProductionAlpmPhase::Download));
        assert!(ProductionAlpmPhase::Download.allows_advance(ProductionAlpmPhase::Signatures));
        assert!(!ProductionAlpmPhase::Prepare.allows_advance(ProductionAlpmPhase::Commit));
        assert!(!ProductionAlpmPhase::Signatures.allows_advance(ProductionAlpmPhase::Finished));
        assert!(ProductionAlpmPhase::Signatures.requires_worker_ready());
        assert!(!ProductionAlpmPhase::Commit.requires_worker_ready());
    }

    #[test]
    fn prepare_recorded_plan_is_visible_and_errors_block_flow() {
        let mut flow = ProductionAlpmFlow::new();
        assert!(flow.plan().is_none());

        flow.record_prepared(fixed_plan()).unwrap();
        assert!(flow.plan().is_some());
        assert_eq!(flow.worker_phase(), UpdatePhase::Prepare);

        let kind = flow.fail(crate::libalpm_ffi::ALPM_ERR_FILE_CONFLICTS);
        assert_eq!(kind, AlpmErrorKind::FileConflicts);
        assert_eq!(flow.error(), Some(AlpmErrorKind::FileConflicts));
    }

    #[test]
    fn error_classification_maps_known_alpm_errnos() {
        assert_eq!(
            classify_alpm_error(crate::libalpm_ffi::ALPM_ERR_UNSATISFIED_DEPS),
            AlpmErrorKind::UnsatisfiedDependencies
        );
        assert_eq!(
            classify_alpm_error(crate::libalpm_ffi::ALPM_ERR_CONFLICTING_DEPS),
            AlpmErrorKind::ConflictingDependencies
        );
        assert_eq!(
            classify_alpm_error(crate::libalpm_ffi::ALPM_ERR_FILE_CONFLICTS),
            AlpmErrorKind::FileConflicts
        );
        assert_eq!(
            classify_alpm_error(crate::libalpm_ffi::ALPM_ERR_DB_INVALID_SIG),
            AlpmErrorKind::SignatureVerification
        );
        assert_eq!(
            classify_alpm_error(crate::libalpm_ffi::ALPM_ERR_SIG_INVALID),
            AlpmErrorKind::SignatureVerification
        );
        assert_eq!(
            classify_alpm_error(crate::libalpm_ffi::ALPM_ERR_SIG_MISSING),
            AlpmErrorKind::SignatureVerification
        );
        assert_eq!(
            classify_alpm_error(crate::libalpm_ffi::ALPM_ERR_RETRIEVE),
            AlpmErrorKind::RetrievalFailure
        );
        assert_eq!(
            classify_alpm_error(crate::libalpm_ffi::ALPM_ERR_RETRIEVE_PREPARE),
            AlpmErrorKind::RetrievalFailure
        );
        assert_eq!(classify_alpm_error(12345), AlpmErrorKind::Unknown);
    }

    #[test]
    fn finish_requires_commit_boundary() {
        let mut flow = ProductionAlpmFlow::new();
        assert!(flow.finish().is_err());
        assert_eq!(flow.phase(), Some(ProductionAlpmPhase::Prepare));
        assert_eq!(flow.worker_phase(), UpdatePhase::Prepare);
    }

    #[test]
    fn worker_ready_boundary_is_observed_before_commit() {
        use crate::transaction_worker::TransactionWorker;

        let mut worker = TransactionWorker::new();
        worker
            .receive_ipc_line(r#"{"type":"started"}"#)
            .expect("helper session must start");

        let mut flow = ProductionAlpmFlow::new();
        flow.record_prepared(fixed_plan()).unwrap();
        assert_eq!(flow.worker_phase(), UpdatePhase::Prepare);

        // The worker Ready boundary follows the started session, but the
        // locked flow can never reach Signatures or COMMIT, so the worker
        // Commit boundary stays unreachable in production today.
        worker.advance_phase(UpdatePhase::Ready).unwrap();
        assert_eq!(worker.phase(), UpdatePhase::Ready);
        assert!(flow.advance().is_err());
        assert_eq!(flow.phase(), Some(ProductionAlpmPhase::Prepare));
        assert_eq!(flow.worker_phase(), UpdatePhase::Prepare);
        // `begin_commit` is unreachable by construction: a
        // `SystemCommitAuthorization` value cannot be created anywhere.
    }
}

/// A real, dependency-resolved ALPM plan from freshly synchronized repositories.
/// The source databases are read only; all ALPM locks/downloads live in a private
/// directory. This is review data, never permission to execute a transaction.
pub struct PreparedFullUpgrade {
    config: crate::libalpm_ffi::PacmanConfig,
    system: bool,
    keyring: Vec<(String, Vec<u8>)>,
    local: Vec<(std::path::PathBuf, Vec<u8>)>,
    repositories: Vec<(std::path::PathBuf, Vec<u8>)>,
    initial: AlpmTransactionPlan,
    details: crate::libalpm_ffi::AlpmPreparedUpgrade,
}

/// Can only be created after explicit confirmation and a second full PREPARE.
/// Final execution must additionally compare the actual live transaction.
pub struct ConfirmedUpgrade {
    plan: PreparedFullUpgrade,
}

struct PlanningDirectory(std::path::PathBuf);

impl PlanningDirectory {
    fn create() -> Result<Self, String> {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join("rwr-plan-XXXXXX");
        let mut bytes = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|e| e.to_string())?
            .into_bytes_with_nul();
        if unsafe { libc::mkdtemp(bytes.as_mut_ptr().cast()) }.is_null() {
            return Err(std::io::Error::last_os_error().to_string());
        }
        bytes.pop();
        let directory = Self(std::ffi::OsString::from_vec(bytes).into());
        for name in ["db", "cache", "hooks", "gnupg"] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(directory.0.join(name))
                .map_err(|e| e.to_string())?;
        }
        Ok(directory)
    }
}

impl Drop for PlanningDirectory {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!("RWR PLAN: private directory cleanup failed: {error}");
        }
    }
}

// Capture exact bytes, not timestamps or an implementation-dependent hash.
// Refuse symlinks and bound memory; a changing/locked source never yields a plan.
fn database_snapshot(
    directory: &std::path::Path,
) -> Result<Vec<(std::path::PathBuf, Vec<u8>)>, String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    fn walk(
        base: &std::path::Path,
        path: &std::path::Path,
        depth: usize,
        total: &mut usize,
        files: &mut Vec<(std::path::PathBuf, Vec<u8>)>,
    ) -> Result<(), String> {
        if depth > 8 || files.len() >= 100_000 {
            return Err("Database snapshot exceeds bounds".into());
        }
        let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).map_err(|e| e.to_string())? {
                walk(
                    base,
                    &entry.map_err(|e| e.to_string())?.path(),
                    depth + 1,
                    total,
                    files,
                )?;
            }
        } else if metadata.is_file() {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)
                .map_err(|e| e.to_string())?;
            if !file.metadata().map_err(|e| e.to_string())?.is_file() {
                return Err("Database entry changed to a special file".into());
            }
            let mut bytes = Vec::new();
            file.take(64 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            *total += bytes.len();
            if bytes.len() > 64 * 1024 * 1024 || *total > 256 * 1024 * 1024 {
                return Err("Database snapshot too large".into());
            }
            files.push((
                path.strip_prefix(base).map_err(|e| e.to_string())?.into(),
                bytes,
            ));
        } else {
            return Err("Database snapshot contains a symlink or special file".into());
        }
        Ok(())
    }
    let mut files = Vec::new();
    walk(directory, directory, 0, &mut 0, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

fn unlocked_local_snapshot(
    config: &crate::libalpm_ffi::PacmanConfig,
) -> Result<Vec<(std::path::PathBuf, Vec<u8>)>, String> {
    local_snapshot(config, false)
}

fn local_snapshot(
    config: &crate::libalpm_ffi::PacmanConfig,
    own_active_lock: bool,
) -> Result<Vec<(std::path::PathBuf, Vec<u8>)>, String> {
    let database = std::path::Path::new(&config.db_path);
    if !own_active_lock {
        match std::fs::symlink_metadata(database.join("db.lck")) {
            Ok(_) => {
                return Err(
                    "Package database is locked; prepare a new plan after it is released".into(),
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    let result = database_snapshot(&database.join("local"))?;
    if !own_active_lock && std::fs::symlink_metadata(database.join("db.lck")).is_ok() {
        return Err("Package database changed during plan capture".into());
    }
    Ok(result)
}

// Verification receives a private copy of public keys/trust only. GnuPG may
// create locks/trust metadata, so never point the preview at the host keyring.
fn planning_keyring(
    config: &crate::libalpm_ffi::PacmanConfig,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut result = Vec::new();
    for name in ["pubring.gpg", "pubring.kbx", "trustdb.gpg"] {
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(std::path::Path::new(&config.gpg_dir).join(name))
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("Cannot read verification keyring: {e}")),
        };
        if !file.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err("Verification keyring is not a regular file".into());
        }
        let mut bytes = Vec::new();
        file.take(32 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 32 * 1024 * 1024 {
            return Err("Verification keyring too large".into());
        }
        result.push((name.into(), bytes));
    }
    Ok(result)
}

impl PreparedFullUpgrade {
    pub fn prepare_system() -> Result<Self, String> {
        Self::prepare_config(crate::libalpm_ffi::PacmanConfig::read()?, true)
    }

    fn prepare_config(
        config: crate::libalpm_ffi::PacmanConfig,
        system: bool,
    ) -> Result<Self, String> {
        use crate::libalpm_ffi::{AlpmHandle, AlpmTransaction};
        if !std::path::Path::new(&config.root).is_absolute()
            || !std::path::Path::new(&config.db_path).is_absolute()
            || config.repositories.is_empty()
        {
            return Err("Invalid full-upgrade configuration".into());
        }
        let local = unlocked_local_snapshot(&config)?;
        let keyring = planning_keyring(&config)?;
        let directory = PlanningDirectory::create()?;
        let local_copy = directory.0.join("db/local");
        std::fs::create_dir(&local_copy).map_err(|e| e.to_string())?;
        for (relative, bytes) in &local {
            let target = local_copy.join(relative);
            std::fs::create_dir_all(target.parent().ok_or("Invalid local database entry")?)
                .map_err(|e| e.to_string())?;
            std::fs::write(target, bytes).map_err(|e| e.to_string())?;
        }
        for (name, bytes) in &keyring {
            std::fs::write(directory.0.join("gnupg").join(name), bytes)
                .map_err(|e| e.to_string())?;
        }
        let mut effective = config.clone();
        effective.gpg_dir = directory.0.join("gnupg").to_string_lossy().into_owned();
        effective.db_path = directory.0.join("db").to_string_lossy().into_owned();
        effective.cache_dir = directory.0.join("cache").to_string_lossy().into_owned();
        effective.log_file = directory.0.join("plan.log").to_string_lossy().into_owned();
        effective.hook_dirs = vec![directory.0.join("hooks").to_string_lossy().into_owned()];
        let handle =
            AlpmHandle::new_private_plan(std::path::Path::new(&config.root), &directory.0)?;
        let count = handle.configure(&effective)?;
        if count != config.repositories.len() {
            return Err("Incomplete full-upgrade repository configuration".into());
        }
        handle.configure_plan_questions()?;
        handle.refresh_plan_databases()?;
        let mut transaction = AlpmTransaction::begin(&handle)?;
        transaction.select_system_upgrade()?;
        let initial = transaction.planned_packages()?;
        transaction.prepare()?;
        let details = transaction.prepared_upgrade_details(&initial)?;
        transaction.release()?;
        let repositories = database_snapshot(&directory.0.join("db/sync"))?;
        if planning_keyring(&config)? != keyring
            || unlocked_local_snapshot(&config)? != local
            || (system && crate::libalpm_ffi::PacmanConfig::read()? != config)
        {
            return Err("Installed packages or configuration changed; prepare a new plan".into());
        }
        Ok(Self {
            config,
            system,
            keyring,
            local,
            repositories,
            initial,
            details,
        })
    }

    pub fn details(&self) -> &crate::libalpm_ffi::AlpmPreparedUpgrade {
        &self.details
    }

    pub fn confirm_and_revalidate(&self, confirmed: bool) -> Result<ConfirmedUpgrade, String> {
        if !confirmed {
            return Err("Explicit confirmation of the complete package plan is required".into());
        }
        let config = if self.system {
            crate::libalpm_ffi::PacmanConfig::read()?
        } else {
            self.config.clone()
        };
        if config != self.config
            || planning_keyring(&config)? != self.keyring
            || unlocked_local_snapshot(&config)? != self.local
        {
            return Err("Plan is stale: installed packages or configuration changed; confirmation invalidated".into());
        }
        // Re-download repository metadata and repeat full dependency resolution.
        let fresh = Self::prepare_config(config, self.system)?;
        // Semantic equivalence: the complete PREPARE result (packages, epochs,
        // repositories, arches, archive names/SHA256/PGP signatures,
        // dependencies, relations, removals, decisions) must be identical.
        // A mirror rebuilding an unrelated part of extra.db is not a change.
        if fresh.details != self.details {
            return Err("Plan is stale: repositories or prepared packages changed; review and confirm a new plan".into());
        }
        Ok(ConfirmedUpgrade { plan: fresh })
    }

    pub fn review_text(&self) -> String {
        let mut text = String::from("ALPM PREPARE — świeże repozytoria / fresh repositories\n\n");
        for package in &self.details.add {
            let action = if package.dependency_added {
                "ZALEŻNOŚĆ / DEPENDENCY"
            } else if package.installed_version.is_some() {
                "AKTUALIZACJA / UPGRADE"
            } else {
                "INSTALACJA / INSTALL"
            };
            text.push_str(&format!(
                "{action}: {} {} → {} [{}]\n",
                package.name,
                package.installed_version.as_deref().unwrap_or("—"),
                package.version,
                package.repository
            ));
            if !package.dependencies.is_empty() {
                text.push_str(&format!(
                    "  Wymaga / Requires: {}\n",
                    package.dependencies.join(", ")
                ));
            }
        }
        text.push_str("\nUSUNIĘCIA / REMOVALS:\n");
        for package in &self.details.remove {
            text.push_str(&format!("{} {}\n", package.name, package.version));
        }
        if self.details.remove.is_empty() {
            text.push_str("—\n");
        }
        if !self.details.decisions.is_empty() {
            text.push_str("\nDecyzje PREPARE / PREPARE decisions:\n");
            for kind in &self.details.decisions {
                text.push_str(match kind {
                    1 => "Ignored package retained as ignored.\n",
                    2 => "Proposed replacement included for explicit approval.\n",
                    4 => "Conflicting package removal included for explicit approval.\n",
                    32 => "First dependency provider selected; review the selected packages.\n",
                    _ => "Destructive/partial/key-import request refused.\n",
                });
            }
        }
        text.push_str("\nPotwierdzenie ponownie pobierze bazy i sprawdzi CAŁY plan. Zmiana unieważnia zgodę.\nConfirmation revalidates the complete plan. Changes invalidate consent.\nPREPARE nie wykonuje COMMIT. Instalacja wymaga osobnego potwierdzenia i Polkit. / PREPARE does not execute COMMIT. Installation requires separate confirmation and Polkit.\n");
        text
    }
}

impl ConfirmedUpgrade {
    /// Final boundary must use the actual live execution transaction, never the
    /// scanner output or just a boolean. This check does not enable COMMIT.
    pub fn verify_transaction(
        &self,
        transaction: &crate::libalpm_ffi::AlpmTransaction<'_>,
    ) -> Result<(), String> {
        if !transaction.matches_plan_source(
            std::path::Path::new(&self.plan.config.root),
            std::path::Path::new(&self.plan.config.db_path),
        )? {
            return Err("Execution transaction is not bound to the confirmed root/database".into());
        }
        if planning_keyring(&self.plan.config)? != self.plan.keyring
            || local_snapshot(&self.plan.config, true)? != self.plan.local
            || (self.plan.system && crate::libalpm_ffi::PacmanConfig::read()? != self.plan.config)
            || transaction.prepared_upgrade_details(&self.plan.initial)? != self.plan.details
        {
            return Err("Actual transaction differs from confirmed plan; COMMIT refused".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod full_upgrade_plan_tests {
    use super::*;
    use crate::libalpm_ffi::{AlpmHandle, AlpmTransaction, PacmanConfig};
    use std::path::Path;

    fn fixture_config(lab: &crate::alpm_lab::AlpmLab) -> PacmanConfig {
        let base = lab.root().parent().unwrap();
        PacmanConfig {
            root: lab.root().to_str().unwrap().into(),
            db_path: lab.db().to_str().unwrap().into(),
            cache_dir: base.join("cache").to_str().unwrap().into(),
            gpg_dir: base.join("gnupg").to_str().unwrap().into(),
            check_space: false,
            architecture: "x86_64".into(),
            repositories: vec!["rwr-test".into()],
            repository_servers: vec![(
                "rwr-test".into(),
                vec![format!("file://{}", base.join("repository").display())],
            )],
            signature_policy: vec![
                "PackageRequired".into(),
                "PackageTrustedOnly".into(),
                "DatabaseOptional".into(),
                "DatabaseTrustedOnly".into(),
            ],
            repository_signature_policies: Vec::new(),
            ignore_pkg: Vec::new(),
            ignore_group: Vec::new(),
            no_upgrade: Vec::new(),
            no_extract: Vec::new(),
            hook_dirs: vec![base.join("hooks").to_str().unwrap().into()],
            log_file: base.join("plan.log").to_str().unwrap().into(),
        }
    }

    fn write_repository(lab: &crate::alpm_lab::AlpmLab, target: &str) {
        let base = lab.root().parent().unwrap();
        let build = base.join(format!("repo-build-{target}"));
        std::fs::create_dir(&build).unwrap();
        for (name, version, extra) in [
            (
                "rwr-test-package",
                target,
                "%DEPENDS%\nrwr-test-dep>=1\n\n%REPLACES%\nrwr-old-package\n\n",
            ),
            ("rwr-test-dep", "1.0-1", ""),
        ] {
            let entry = build.join(format!("{name}-{version}"));
            std::fs::create_dir(&entry).unwrap();
            std::fs::write(entry.join("desc"), format!(
                "%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%FILENAME%\n{name}-{version}-any.pkg.tar.zst\n\n%ARCH%\nany\n\n%CSIZE%\n1\n\n%ISIZE%\n1\n\n%SHA256SUM%\n{}\n\n{extra}", "0".repeat(64)
            )).unwrap();
        }
        let output = std::process::Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(base.join("repository/rwr-test.db"))
            .arg("-C")
            .arg(&build)
            .arg(format!("rwr-test-package-{target}"))
            .arg("rwr-test-dep-1.0-1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn add_removed_package(lab: &crate::alpm_lab::AlpmLab) {
        let directory = lab.db().join("local/rwr-old-package-1.0-1");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            directory.join("desc"),
            "%NAME%\nrwr-old-package\n\n%VERSION%\n1.0-1\n\n%ARCH%\nany\n\n%REASON%\n0\n\n",
        )
        .unwrap();
        std::fs::write(directory.join("files"), "%FILES%\n\n").unwrap();
    }

    #[test]
    fn full_upgrade_plan_uses_real_alpm_dependencies_removals_and_revalidation() {
        let lab = crate::alpm_lab::AlpmLab::create().unwrap();
        add_removed_package(&lab);
        write_repository(&lab, "1.1-1");
        let config = fixture_config(&lab);
        let before = database_snapshot(lab.root()).unwrap();
        let plan = PreparedFullUpgrade::prepare_config(config.clone(), false).unwrap();
        assert_eq!(database_snapshot(lab.root()).unwrap(), before);
        let package = plan
            .details()
            .add
            .iter()
            .find(|p| p.name == "rwr-test-package")
            .unwrap();
        assert_eq!(package.installed_version.as_deref(), Some("1.0-1"));
        assert_eq!(package.version, "1.1-1");
        assert_eq!(package.dependencies, ["rwr-test-dep>=1"]);
        assert!(
            plan.details()
                .add
                .iter()
                .any(|p| p.name == "rwr-test-dep" && p.dependency_added)
        );
        assert!(
            plan.details()
                .remove
                .iter()
                .any(|p| p.name == "rwr-old-package" && p.version == "1.0-1")
        );
        let rendered = plan.review_text();
        assert!(rendered.contains("1.0-1 → 1.1-1"));
        assert!(rendered.contains("rwr-test-dep>=1"));
        assert!(rendered.contains("rwr-old-package 1.0-1"));
        assert!(plan.confirm_and_revalidate(false).is_err());
        let confirmation = plan.confirm_and_revalidate(true).unwrap();
        assert_eq!(database_snapshot(lab.root()).unwrap(), before);

        // A live transaction on stale repository metadata is refused, even
        // though it happens to select the same main package/version.
        {
            let handle =
                AlpmHandle::new(Path::new(&config.root), Path::new(&config.db_path)).unwrap();
            handle.configure(&config).unwrap();
            handle.configure_plan_questions().unwrap();
            let mut tx = AlpmTransaction::begin(&handle).unwrap();
            tx.select_system_upgrade().unwrap();
            tx.prepare().unwrap();
            assert!(confirmation.verify_transaction(&tx).is_err());
            tx.release().unwrap();
        }

        // The actual execution transaction must also match, under its own lock.
        // This laboratory transaction is only PREPARE; no COMMIT is invoked.
        std::fs::copy(
            lab.root().parent().unwrap().join("repository/rwr-test.db"),
            lab.db().join("sync/rwr-test.db"),
        )
        .unwrap();
        let handle = AlpmHandle::new(Path::new(&config.root), Path::new(&config.db_path)).unwrap();
        handle.configure(&config).unwrap();
        handle.configure_plan_questions().unwrap();
        let mut tx = AlpmTransaction::begin(&handle).unwrap();
        tx.select_system_upgrade().unwrap();
        tx.prepare().unwrap();
        confirmation.verify_transaction(&tx).unwrap();
        tx.release().unwrap();
        drop(handle);

        // A repository update invalidates the reviewed plan, even with the
        // original scan/installed versions unchanged.
        write_repository(&lab, "1.2-1");
        assert!(
            plan.confirm_and_revalidate(true)
                .err()
                .unwrap()
                .contains("Plan is stale")
        );
        let fresh = PreparedFullUpgrade::prepare_config(config.clone(), false).unwrap();
        assert!(
            fresh
                .details()
                .add
                .iter()
                .any(|p| p.name == "rwr-test-package" && p.version == "1.2-1")
        );
        std::fs::write(
            lab.db().join("local/rwr-test-package-1.0-1/desc"),
            "%NAME%\nrwr-test-package\n\n%VERSION%\n1.0-2\n\n",
        )
        .unwrap();
        assert!(
            fresh
                .confirm_and_revalidate(true)
                .err()
                .unwrap()
                .contains("installed packages")
        );
        assert!(!real_flow_enabled());
    }

    #[test]
    fn full_upgrade_plan_refuses_locked_database_and_unsafe_snapshot() {
        let lab = crate::alpm_lab::AlpmLab::create().unwrap();
        let config = fixture_config(&lab);
        let untrusted = AlpmHandle::new(lab.root(), lab.db()).unwrap();
        assert!(
            untrusted
                .refresh_plan_databases()
                .unwrap_err()
                .contains("private planning handle")
        );
        drop(untrusted);
        std::fs::write(lab.db().join("db.lck"), b"another transaction").unwrap();
        assert!(
            PreparedFullUpgrade::prepare_config(config.clone(), false)
                .err()
                .unwrap()
                .contains("locked")
        );
        std::fs::remove_file(lab.db().join("db.lck")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", lab.db().join("local/unsafe")).unwrap();
        assert!(
            PreparedFullUpgrade::prepare_config(config, false)
                .err()
                .unwrap()
                .contains("symlink")
        );
    }
}

impl PreparedFullUpgrade {
    /// Laboratory endpoint shares the real planner. No caller-supplied system
    /// config is accepted, and its commitment is separated from system scope.
    pub fn prepare_isolated(root: &std::path::Path) -> Result<Self, String> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let root = root.canonicalize().map_err(|e| e.to_string())?;
        let base = root.parent().ok_or("Missing isolated base")?;
        let temp = std::env::temp_dir()
            .canonicalize()
            .map_err(|e| e.to_string())?;
        let meta = std::fs::symlink_metadata(base).map_err(|e| e.to_string())?;
        if root != base.join("root")
            || base.parent() != Some(temp.as_path())
            || !base
                .file_name()
                .is_some_and(|s| s.to_string_lossy().starts_with("rwr-alpm-lab-"))
            || !meta.is_dir()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.permissions().mode() & 0o777 != 0o700
        {
            return Err("Isolated plan requires an owned private laboratory".into());
        }
        let config = crate::libalpm_ffi::PacmanConfig {
            root: root.to_str().ok_or("Invalid isolated root")?.into(),
            db_path: root
                .join("var/lib/pacman")
                .to_str()
                .ok_or("Invalid isolated DB")?
                .into(),
            cache_dir: base
                .join("cache")
                .to_str()
                .ok_or("Invalid isolated cache")?
                .into(),
            gpg_dir: base
                .join("gnupg")
                .to_str()
                .ok_or("Invalid isolated keyring")?
                .into(),
            check_space: false,
            architecture: "x86_64".into(),
            repositories: vec!["rwr-test".into()],
            repository_servers: vec![(
                "rwr-test".into(),
                vec![format!("file://{}", base.join("repository").display())],
            )],
            signature_policy: vec![
                "PackageRequired".into(),
                "PackageTrustedOnly".into(),
                "DatabaseOptional".into(),
                "DatabaseTrustedOnly".into(),
            ],
            repository_signature_policies: Vec::new(),
            ignore_pkg: Vec::new(),
            ignore_group: Vec::new(),
            no_upgrade: Vec::new(),
            no_extract: Vec::new(),
            hook_dirs: vec![base.join("hooks").to_str().ok_or("Invalid hooks")?.into()],
            log_file: base.join("plan.log").to_str().ok_or("Invalid log")?.into(),
        };
        Self::prepare_config(config, false)
    }

    fn commitment(&self) -> Result<String, String> {
        use std::io::Write;
        let directory = PlanningDirectory::create()?;
        let path = directory.0.join("commitment");
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| e.to_string())?;
        fn frame(out: &mut impl Write, bytes: &[u8]) -> Result<(), String> {
            out.write_all(&(bytes.len() as u64).to_le_bytes())
                .and_then(|_| out.write_all(bytes))
                .map_err(|e| e.to_string())
        }
        // v2: semantic commitment. Raw repository database bytes are not bound
        // (mirrors rebuild them constantly); every PREPARE result field that
        // can affect the transaction is, including each archive's identity.
        frame(&mut out, b"rwr-full-upgrade-plan-v2")?;
        frame(&mut out, if self.system { b"system" } else { b"isolated" })?;
        let c = &self.config;
        frame(&mut out,&serde_json::to_vec(&serde_json::json!({
            "root":c.root,"db":c.db_path,"cache":c.cache_dir,"gpg":c.gpg_dir,"check_space":c.check_space,
            "architecture":c.architecture,"repositories":c.repositories,"servers":c.repository_servers,
            "signatures":c.signature_policy,"repo_signatures":c.repository_signature_policies,
            "ignore_pkg":c.ignore_pkg,"ignore_group":c.ignore_group,"no_upgrade":c.no_upgrade,"no_extract":c.no_extract,
            "hooks":c.hook_dirs,"log":c.log_file
        })).map_err(|e|e.to_string())?)?;
        use std::os::unix::ffi::OsStrExt;
        for (kind, snapshot) in [(b"local".as_slice(), &self.local)] {
            frame(&mut out, kind)?;
            frame(&mut out, &(snapshot.len() as u64).to_le_bytes())?;
            for (name, bytes) in snapshot {
                frame(&mut out, name.as_os_str().as_bytes())?;
                frame(&mut out, bytes)?;
            }
        }
        frame(&mut out, b"keyring")?;
        frame(&mut out, &(self.keyring.len() as u64).to_le_bytes())?;
        for (name, bytes) in &self.keyring {
            frame(&mut out, name.as_bytes())?;
            frame(&mut out, bytes)?;
        }
        let packages:Vec<_> = self.details.add.iter().map(|p|serde_json::json!({"name":p.name,"old":p.installed_version,
            "new":p.version,"repository":p.repository,"arch":p.arch,"filename":p.filename,"sha256":p.sha256,
            "signature":p.signature,"dependencies":p.dependencies,"provides":p.provides,"conflicts":p.conflicts,
            "replaces":p.replaces,"dependency_added":p.dependency_added})).collect();
        let remove: Vec<_> = self
            .details
            .remove
            .iter()
            .map(|p| serde_json::json!({"name":p.name,"version":p.version}))
            .collect();
        frame(&mut out,&serde_json::to_vec(&serde_json::json!({"add":packages,"remove":remove,"decisions":self.details.decisions})).map_err(|e|e.to_string())?)?;
        out.flush().map_err(|e| e.to_string())?;
        crate::libalpm_ffi::plan_file_sha256(&path)
    }

    /// The helper recomputes all inputs; the GUI claim confers no authority.
    pub fn validate_claim(
        &self,
        request: &crate::transaction_ipc::PlanValidationRequest,
    ) -> Result<(), String> {
        request.validate()?;
        if request.scope != if self.system { "system" } else { "isolated" }
            || self.commitment()? != request.plan_digest
        {
            // Diagnostics only: the refusal is unchanged. Repository databases
            // are fetched again here, so a mirror update since confirmation
            // shows up as different core.db/extra.db hashes and package counts.
            let summary = self
                .commitment_summary()
                .unwrap_or_else(|error| format!("summary unavailable: {error}"));
            return Err(format!(
                "Prepared packages or plan inputs differ from the confirmed plan; fresh plan [{summary}]; prepare and confirm a new plan"
            ));
        }
        Ok(())
    }

    /// Short per-input hashes of the commitment (config, installed database,
    /// each repository database, keyring, PREPARE result) for comparing two
    /// plans when their digests differ. Informational; grants nothing.
    pub fn commitment_summary(&self) -> Result<String, String> {
        let directory = PlanningDirectory::create()?;
        let mut index = 0usize;
        let mut hash = |bytes: &[u8]| -> Result<String, String> {
            index += 1;
            let path = directory.0.join(format!("summary-{index}"));
            std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
            Ok(crate::libalpm_ffi::plan_file_sha256(&path)?[..12].to_string())
        };
        fn joined(entries: &[(std::path::PathBuf, Vec<u8>)]) -> Vec<u8> {
            let mut all = Vec::new();
            for (name, bytes) in entries {
                all.extend_from_slice(&(name.as_os_str().len() as u64).to_le_bytes());
                all.extend_from_slice(name.as_os_str().as_encoded_bytes());
                all.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                all.extend_from_slice(bytes);
            }
            all
        }
        let mut parts = vec![
            format!(
                "add={} remove={} decisions={}",
                self.details.add.len(),
                self.details.remove.len(),
                self.details.decisions.len()
            ),
            format!("config={}", hash(format!("{:?}", self.config).as_bytes())?),
            format!("local={}", hash(&joined(&self.local))?),
        ];
        for (name, bytes) in &self.repositories {
            parts.push(format!("{}={}", name.display(), hash(bytes)?));
        }
        let mut keyring = Vec::new();
        for (name, bytes) in &self.keyring {
            keyring.extend_from_slice(name.as_bytes());
            keyring.extend_from_slice(bytes);
        }
        parts.push(format!("keyring={}", hash(&keyring)?));
        parts.push(format!(
            "details={}",
            hash(format!("{:?}", self.details).as_bytes())?
        ));
        Ok(parts.join(" "))
    }
}

impl ConfirmedUpgrade {
    pub fn validation_request(
        &self,
        transaction_id: &str,
    ) -> Result<crate::transaction_ipc::PlanValidationRequest, String> {
        let request = crate::transaction_ipc::PlanValidationRequest {
            transaction_id: transaction_id.into(),
            plan_digest: self.plan.commitment()?,
            scope: if self.plan.system {
                "system"
            } else {
                "isolated"
            }
            .into(),
        };
        request.validate()?;
        Ok(request)
    }
}

/// Actual helper-side read-only exchange. Ordinary transaction IPC carries all
/// lifecycle messages; a versioned, bound envelope carries the plan claim.
/// Even a matching plan cannot reach SystemCommitAuthorization or COMMIT.
/// Read-only validation shared by the helper and sandboxed USER supervisor.
/// No confirmation/authority token is created; two fresh PREPAREs must agree.
pub fn validate_fresh_plan_claim(
    request: &crate::transaction_ipc::PlanValidationRequest,
    mut prepare: impl FnMut() -> Result<PreparedFullUpgrade, String>,
    scope: &str,
) -> Result<(), String> {
    request.validate()?;
    if request.scope != scope {
        return Err("Plan request scope does not match validator mode".into());
    }
    let first = prepare()?;
    first.validate_claim(request)?;
    let second = prepare()?;
    second.validate_claim(request)?;
    Ok(())
}

pub fn serve_plan_validation(
    input: &mut impl std::io::BufRead,
    output: &mut impl std::io::Write,
    mut prepare: impl FnMut() -> Result<PreparedFullUpgrade, String>,
    scope: &str,
) -> Result<(), String> {
    use crate::transaction_ipc::{MAX_MESSAGE_BYTES, PLAN_PROTOCOL_VERSION, PlanValidationRequest};
    use std::io::{BufRead, Read};
    let mut emit = |value: serde_json::Value| -> Result<(), String> {
        writeln!(output, "{value}")
            .and_then(|_| output.flush())
            .map_err(|e| e.to_string())
    };
    emit(
        serde_json::json!({"type":"hello","component":"rwr-update-helper","operation":"validate-plan",
        "protocol_version":PLAN_PROTOCOL_VERSION,"real_execution_enabled":false}),
    )?;
    emit(serde_json::json!({"type":"started"}))?;
    let result = (|| -> Result<(), String> {
        let mut bytes = Vec::new();
        input
            .take((MAX_MESSAGE_BYTES + 1) as u64)
            .read_until(b'\n', &mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > MAX_MESSAGE_BYTES || bytes.last() != Some(&b'\n') {
            return Err("Invalid plan request framing".into());
        }
        let request = PlanValidationRequest::parse(
            &serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
        )?;
        if request.scope != scope {
            return Err("Plan request scope does not match helper mode".into());
        }
        emit(
            serde_json::json!({"type":"progress","text":"Independent ALPM PREPARE and plan comparison"}),
        )?;
        validate_fresh_plan_claim(&request, &mut prepare, scope)?;
        emit(serde_json::json!({"type":"phase","phase":"ready"}))?;
        emit(serde_json::json!({"type":"progress","text":request.evidence()}))?;
        emit(serde_json::json!({"type":"completed","exit_code":0}))
    })();
    if let Err(error) = &result {
        emit(serde_json::json!({"type":"failed","text":error}))?;
    }
    result
}

fn polkit_plan_details(
    request: &crate::transaction_ipc::PlanValidationRequest,
) -> std::collections::HashMap<String, String> {
    std::collections::HashMap::from([
        ("transaction_id".into(), request.transaction_id.clone()),
        ("plan_digest".into(), request.plan_digest.clone()),
    ])
}

fn require_allowed_polkit_result(
    allowed: bool,
    challenge: bool,
    details: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    // Polkit documents a non-empty value (not necessarily the literal true).
    if details
        .get("polkit.dismissed")
        .is_some_and(|v| !v.is_empty())
    {
        return Err("Polkit authentication cancelled by user".into());
    }
    if !allowed {
        return Err(if challenge {
            "Polkit authentication not completed; check the session authentication agent"
        } else {
            "Polkit denied"
        }
        .into());
    }
    if challenge {
        return Err("Incomplete or inconsistent Polkit authorization result".into());
    }
    Ok(())
}

// A transaction may have concurrent ATTACH/answer/cancel checks on the shared
// system bus. Polkit cancellation IDs identify checks, not transaction plans.
fn next_polkit_check_id() -> Result<String, String> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = NEXT
        .fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |n| n.checked_add(1),
        )
        .map_err(|_| "Polkit check identifier exhausted")?;
    Ok(format!("rwr-{}-{id}", std::process::id()))
}

impl SystemCommitAuthorization {
    /// No environment variable, digest or GUI boolean can construct authority.
    /// A missing/disabled deployment policy stops before bus/host access.
    pub fn verify_polkit(
        request: &crate::transaction_ipc::PlanValidationRequest,
        launcher: &std::os::unix::net::UnixStream,
    ) -> Result<Self, String> {
        if !real_flow_enabled() {
            return Err("REAL MODE locked: execution authorization disabled".into());
        }
        let subject =
            Self::verify_component_polkit(request, launcher, false, AuthorizationPurpose::Execute)?;
        Ok(Self {
            transaction_id: subject.transaction_id,
            plan_digest: subject.plan_digest,
            caller_uid: subject.caller_uid,
        })
    }

    pub fn verify_supervisor_polkit(
        request: &crate::transaction_ipc::PlanValidationRequest,
        client: &std::os::unix::net::UnixStream,
    ) -> Result<Self, String> {
        if !real_flow_enabled() {
            return Err("REAL MODE locked: execution authorization disabled".into());
        }
        let subject =
            Self::verify_component_polkit(request, client, true, AuthorizationPurpose::Execute)?;
        Ok(Self {
            transaction_id: subject.transaction_id,
            plan_digest: subject.plan_digest,
            caller_uid: subject.caller_uid,
        })
    }

    fn verify_component_polkit(
        request: &crate::transaction_ipc::PlanValidationRequest,
        launcher: &std::os::unix::net::UnixStream,
        supervisor: bool,
        purpose: AuthorizationPurpose,
    ) -> Result<VerifiedSystemSubject, String> {
        use gtk4::{gio, glib::variant::ToVariant};
        use std::os::unix::fs::MetadataExt;
        request.validate()?;
        if request.scope != "system"
            || unsafe { libc::getuid() } != 0
            || unsafe { libc::geteuid() } != 0
        {
            return Err("System COMMIT requires a privileged system helper".into());
        }
        let executable = if supervisor {
            crate::supervisor_trust::open_system_supervisor()?
        } else {
            crate::supervisor_trust::open_system_helper()?
        };
        let binary = executable.metadata().map_err(|e| e.to_string())?;
        let running = std::fs::metadata("/proc/self/exe").map_err(|e| e.to_string())?;
        if !binary.is_file()
            || binary.uid() != 0
            || binary.mode() & 0o6022 != 0
            || binary.dev() != running.dev()
            || binary.ino() != running.ino()
        {
            return Err("Untrusted or replaced privileged helper executable".into());
        }
        let subject_process = crate::supervisor_trust::PeerProcess::from_socket(launcher)?;
        let peer = subject_process.credentials();
        // Kernel credentials identify the subject only. They grant no authority;
        // the independent Polkit decision below is mandatory. No PKEXEC_UID or
        // parent-process relationship is accepted as authorization evidence.
        if peer.uid == 0 || peer.pid <= 1 {
            return Err("Invalid unprivileged Polkit subject".into());
        }
        fn process_start(pid: i32, uid: u32) -> Result<u64, String> {
            let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
                .map_err(|e| e.to_string())?;
            let ids = status
                .lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .ok_or("Launcher UID unavailable")?;
            if ids
                .split_whitespace()
                .any(|v| v.parse::<u32>().ok() != Some(uid))
            {
                return Err("Launcher credentials changed".into());
            }
            let stat =
                std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| e.to_string())?;
            stat.rsplit_once(") ")
                .and_then(|(_, tail)| tail.split_whitespace().nth(19))
                .ok_or("Missing launcher start time")?
                .parse::<u64>()
                .map_err(|e| e.to_string())
        }
        let start = process_start(peer.pid, peer.uid)?;
        let subject = std::collections::HashMap::from([
            ("pid".to_string(), (peer.pid as u32).to_variant()),
            ("start-time".to_string(), start.to_variant()),
            ("uid".to_string(), peer.uid.to_variant()),
        ]);
        let details = polkit_plan_details(request);
        let cancellation_id = next_polkit_check_id()?;
        let parameters = (
            ("unix-process", subject),
            purpose.action(),
            details,
            1u32,
            cancellation_id.as_str(),
        )
            .to_variant();
        crate::test_isolation::refuse("Polkit authorization")?;
        let bus = gio::bus_get_sync(gio::BusType::System, gio::Cancellable::NONE)
            .map_err(|e| e.to_string())?;
        let response = bus
            .call_sync(
                Some("org.freedesktop.PolicyKit1"),
                "/org/freedesktop/PolicyKit1/Authority",
                "org.freedesktop.PolicyKit1.Authority",
                "CheckAuthorization",
                Some(&parameters),
                None,
                gio::DBusCallFlags::NONE,
                120_000,
                gio::Cancellable::NONE,
            )
            .map_err(|e| format!("Polkit authorization unavailable: {e}"))?;
        let ((allowed, challenge, details),) = response
            .get::<((bool, bool, std::collections::HashMap<String, String>),)>()
            .ok_or("Invalid Polkit authorization result")?;
        require_allowed_polkit_result(allowed, challenge, &details)?;
        if process_start(peer.pid, peer.uid)? != start || !subject_process.is_alive()? {
            return Err("Polkit subject identity changed during authorization".into());
        }
        Ok(VerifiedSystemSubject {
            transaction_id: request.transaction_id.clone(),
            plan_digest: request.plan_digest.clone(),
            caller_uid: peer.uid,
        })
    }
    pub fn subject_uid(&self) -> u32 {
        self.caller_uid
    }
    pub(crate) fn require_enabled(&self) -> Result<(), String> {
        if !real_flow_enabled() || unsafe { libc::geteuid() } != 0 || self.caller_uid == 0 {
            return Err("REAL MODE locked or invalid system authority".into());
        }
        Ok(())
    }
    pub(crate) fn verify_confirmation(
        &self,
        confirmation: &ConfirmedUpgrade,
    ) -> Result<(), String> {
        self.require_enabled()?;
        if !confirmation.plan.system || confirmation.plan.commitment()? != self.plan_digest {
            return Err("Polkit authority is bound to a different transaction plan".into());
        }
        Ok(())
    }
}

/// Root-owned append+fsync journal. A surviving commit-started record is UNKNOWN,
/// never success and never evidence that a package manager rollback happened.
struct ExecutionJournal(std::fs::File);
impl ExecutionJournal {
    fn system(auth: &SystemCommitAuthorization) -> Result<Self, String> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
        auth.require_enabled()?;
        let directory = std::path::Path::new("/var/lib/rwr-package-intelligence");
        for parent in directory.ancestors().skip(1) {
            let meta = std::fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
            if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return Err("Unsafe execution journal ancestor".into());
            }
        }
        match std::fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.to_string()),
        }
        let meta = std::fs::symlink_metadata(directory).map_err(|e| e.to_string())?;
        if !meta.is_dir() || meta.uid() != 0 || meta.permissions().mode() & 0o777 != 0o700 {
            return Err("Unsafe system transaction journal directory".into());
        }
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(format!("{}.jsonl", auth.transaction_id)))
            .map_err(|e| format!("Transaction ID already used or journal unavailable: {e}"))?;
        std::fs::File::open(directory)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(Self(file))
    }
    fn record(&mut self, value: serde_json::Value) -> Result<(), String> {
        use std::io::Write;
        writeln!(self.0, "{value}")
            .and_then(|_| self.0.sync_all())
            .map_err(|e| format!("Cannot persist transaction outcome: {e}"))
    }
}

/// Actual system backend, still unreachable while REAL MODE is false. Every
/// destructive boundary requires independently obtained Polkit authority, exact
/// plan equality, downloaded archive checksums and mandatory trusted signatures.
pub fn execute_authorized_system_upgrade(
    auth: SystemCommitAuthorization,
    confirmation: ConfirmedUpgrade,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    connected: std::sync::Arc<std::sync::atomic::AtomicBool>,
    service_alive: impl Fn() -> bool,
    progress: std::sync::mpsc::SyncSender<serde_json::Value>,
    questions: std::sync::Arc<crate::libalpm_ffi::ExecutionQuestions>,
    mut emit: impl FnMut(serde_json::Value) -> Result<(), String>,
) -> Result<(), String> {
    use crate::libalpm_ffi::{AlpmHandle, AlpmTransaction};
    use std::sync::atomic::Ordering::Relaxed;
    auth.verify_confirmation(&confirmation)?;
    let mut journal = ExecutionJournal::system(&auth)?;
    journal.record(serde_json::json!({"transaction_id":auth.transaction_id,"plan_digest":auth.plan_digest,"phase":"authorized","caller_uid":auth.caller_uid,"automatic_rollback":false}))?;
    let mut entered_commit = false;
    let result = (|| -> Result<(), String> {
        if cancel.load(Relaxed) || !connected.load(Relaxed) || !service_alive() {
            return Err("Cancelled or IPC lost before transaction".into());
        }
        let mut handle = AlpmHandle::open_authorized_system(&auth)?;
        handle.set_cancellation_request(cancel.clone());
        handle.register_authorized_events(&auth)?;
        handle.configure_execution_stream(&auth, progress.clone(), questions.clone())?;
        handle.refresh_authorized_databases(&auth)?;
        let mut download = AlpmTransaction::begin_download_only(&handle)?;
        download.select_system_upgrade()?;
        let initial = download.planned_packages()?;
        download.prepare()?;
        confirmation.verify_transaction(&download)?;
        let expected = download.prepared_upgrade_details(&initial)?;
        let targets = download.signed_download_targets()?;
        emit(serde_json::json!({"type":"phase","phase":"ready"}))?;
        emit(
            serde_json::json!({"type":"progress","text":"Downloading signed packages; no installation yet"}),
        )?;
        download.download_system_authorized(&auth, &confirmation)?;
        let cache = std::path::PathBuf::from(&confirmation.plan.config.cache_dir);
        emit(
            serde_json::json!({"type":"progress","text":serde_json::json!({"stage":"signatures"}).to_string()}),
        )?;
        let verified = handle.verify_downloads(&targets, &cache)?;
        download.release()?;
        drop(handle);
        journal.record(
            serde_json::json!({"phase":"packages_verified","transaction_id":auth.transaction_id}),
        )?;
        // New handle and lock: never use the stale pre-download local cache.
        let mut handle = AlpmHandle::open_authorized_system(&auth)?;
        handle.set_cancellation_request(cancel.clone());
        handle.register_authorized_events(&auth)?;
        handle.configure_execution_stream(&auth, progress.clone(), questions.clone())?;
        let mut install = AlpmTransaction::begin(&handle)?;
        install.select_system_upgrade()?;
        let selected = install.planned_packages()?;
        install.prepare()?;
        confirmation.verify_transaction(&install)?;
        if install.prepared_upgrade_details(&selected)? != expected {
            return Err(
                "Actual execution plan changed after download; confirmation invalidated".into(),
            );
        }
        auth.verify_confirmation(&confirmation)?;
        handle.verify_downloads(&targets, &cache)?;
        if cancel.load(Relaxed) || !connected.load(Relaxed) || !service_alive() {
            return Err("Cancelled or IPC lost before COMMIT; nothing installed".into());
        }
        journal.record(serde_json::json!({"phase":"commit_started","transaction_id":auth.transaction_id,"partial_installation_possible":true,"automatic_rollback":false}))?;
        entered_commit = true;
        emit(serde_json::json!({"type":"phase","phase":"commit"}))?;
        // After this point loss of GUI/progress IPC does not kill ALPM. The
        // durable journal is authoritative if the result cannot be delivered.
        install.commit_system_authorized(&auth, &confirmation, &verified)?;
        install.release()?;
        handle.verify_installed_upgrade(&expected)?;
        journal.record(serde_json::json!({"phase":"finished","transaction_id":auth.transaction_id,"outcome":"success","automatic_rollback":false}))?;
        let _ = emit(
            serde_json::json!({"type":"progress","text":"Installation verified; durable outcome saved"}),
        );
        Ok(())
    })();
    if let Err(error) = &result {
        let _=journal.record(serde_json::json!({"phase":"failed","transaction_id":auth.transaction_id,"error":error.chars().take(2048).collect::<String>(),"partial_installation_possible":entered_commit,"automatic_rollback":false}));
    }
    result.map_err(|e|if entered_commit {format!("COMMIT failed or outcome incomplete: {e}; partial installation is possible; no automatic rollback; recovery required")}else{e})
}

impl SystemCommitAuthorization {
    /// Reconnect/restart recovery is read-only and requires a fresh independent
    /// Polkit decision. Missing records are distinct from incomplete records.
    /// Never re-run COMMIT on the strength of recovered data.
    pub fn recover_execution_status(&self) -> Result<Option<serde_json::Value>, String> {
        self.require_enabled()?;
        read_authorized_execution_status(&VerifiedSystemSubject {
            transaction_id: self.transaction_id.clone(),
            plan_digest: self.plan_digest.clone(),
            caller_uid: self.caller_uid,
        })
    }
}

fn read_authorized_execution_status(
    subject: &VerifiedSystemSubject,
) -> Result<Option<serde_json::Value>, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
        return Err("Root journal access required".into());
    }
    let directory = std::path::Path::new("/var/lib/rwr-package-intelligence");
    for parent in directory.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let metadata = match std::fs::symlink_metadata(parent) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && parent == directory => {
                return Ok(None);
            }
            Err(e) => return Err(e.to_string()),
        };
        if !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || (parent == directory && metadata.mode() & 0o777 != 0o700)
        {
            return Err("Untrusted execution journal directory".into());
        }
    }
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(directory.join(format!("{}.jsonl", subject.transaction_id)))
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err("Untrusted execution journal file".into());
    }
    let request = crate::transaction_ipc::PlanValidationRequest {
        transaction_id: subject.transaction_id.clone(),
        plan_digest: subject.plan_digest.clone(),
        scope: "system".into(),
    };
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(65537)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 65536 {
        return Err("Oversized root execution journal".into());
    }
    if let Some(end) = bytes.iter().position(|b| *b == b'\n') {
        let first: serde_json::Value =
            serde_json::from_slice(&bytes[..end]).map_err(|e| e.to_string())?;
        if first["caller_uid"].as_u64() != Some(subject.caller_uid as u64) {
            return Err("Execution journal belongs to another authorized subject".into());
        }
    } else if !bytes.is_empty() {
        return Err("Incomplete authorization journal; owner cannot be established".into());
    }
    crate::supervisor_session::recover_execution_journal(bytes.as_slice(), &request).map(Some)
}

#[cfg(test)]
mod authority_recovery_gate_tests {
    #[test]
    fn unvalidated_authority_cannot_read_or_replay_host_journal() {
        // Even an internally constructed token cannot bypass the REAL gate.
        // No Polkit success is simulated; this exercises denial before host IO.
        let authority = super::SystemCommitAuthorization {
            transaction_id: "denied-recovery".into(),
            plan_digest: "a".repeat(64),
            caller_uid: unsafe { libc::getuid() },
        };
        assert!(!super::real_flow_enabled());
        assert!(
            authority
                .recover_execution_status()
                .unwrap_err()
                .contains("REAL MODE locked")
        );
    }
}

impl SystemCommitAuthorization {
    /// Held by the HELPER, across download/PREPARE/COMMIT and broker restarts.
    /// flock is never removed to unlock; process exit releases the kernel lock.
    pub fn acquire_execution_lease(&self) -> Result<std::fs::File, String> {
        use std::os::{
            fd::AsRawFd,
            unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        };
        self.require_enabled()?;
        let directory = std::path::Path::new("/var/lib/rwr-package-intelligence");
        for parent in directory.ancestors().skip(1) {
            let meta = std::fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
            if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return Err("Unsafe execution lease ancestor".into());
            }
        }
        match std::fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.to_string()),
        }
        let meta = std::fs::symlink_metadata(directory).map_err(|e| e.to_string())?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o777 != 0o700 {
            return Err("Unsafe execution lease directory".into());
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join("execution.lock"))
            .map_err(|e| e.to_string())?;
        let meta = file.metadata().map_err(|e| e.to_string())?;
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o777 != 0o600 || meta.nlink() != 1 {
            return Err("Unsafe execution lease file".into());
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(
                "Another helper owns system execution, possibly after supervisor restart".into(),
            );
        }
        Ok(file)
    }
}

// A read decision is intentionally not convertible to SystemCommitAuthorization.
// It can be obtained with REAL=false, but only after the actual root/Polkit path.
struct VerifiedSystemSubject {
    transaction_id: String,
    plan_digest: String,
    caller_uid: u32,
}
pub struct SystemReadAuthorization {
    subject: VerifiedSystemSubject,
}
impl SystemReadAuthorization {
    pub fn verify_supervisor_polkit(
        request: &crate::transaction_ipc::PlanValidationRequest,
        client: &std::os::unix::net::UnixStream,
    ) -> Result<Self, String> {
        Ok(Self {
            subject: SystemCommitAuthorization::verify_component_polkit(
                request,
                client,
                true,
                AuthorizationPurpose::Read,
            )?,
        })
    }
    pub fn subject_uid(&self) -> u32 {
        self.subject.caller_uid
    }
    pub fn recover_execution_status(&self) -> Result<Option<serde_json::Value>, String> {
        read_authorized_execution_status(&self.subject)
    }
}

#[cfg(test)]
mod read_authority_boundary_tests {
    #[test]
    fn read_decision_does_not_require_real_but_still_requires_actual_root_polkit() {
        assert_ne!(
            unsafe { libc::getuid() },
            0,
            "Boundary test requires ordinary UID"
        );
        let request = crate::transaction_ipc::PlanValidationRequest {
            transaction_id: "read-denied".into(),
            plan_digest: "a".repeat(64),
            scope: "system".into(),
        };
        let (client, _) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(!super::real_flow_enabled());
        let error = super::SystemReadAuthorization::verify_supervisor_polkit(&request, &client)
            .err()
            .unwrap();
        assert!(!error.contains("REAL MODE locked"));
        assert!(error.contains("privileged"));
        assert!(
            super::SystemCommitAuthorization::verify_supervisor_polkit(&request, &client)
                .err()
                .unwrap()
                .contains("REAL MODE locked")
        );
    }
}

enum AuthorizationPurpose {
    Read,
    Execute,
}
impl AuthorizationPurpose {
    fn action(&self) -> &'static str {
        match self {
            Self::Read => "io.github.runningwithrottweilers.rwr-package-intelligence.inspect",
            Self::Execute => "io.github.runningwithrottweilers.rwr-package-intelligence.update",
        }
    }
}
#[cfg(test)]
mod policy_purpose_tests {
    #[test]
    fn read_policy_is_not_update_authority() {
        assert_ne!(
            super::AuthorizationPurpose::Read.action(),
            super::AuthorizationPurpose::Execute.action()
        );
        assert!(
            super::AuthorizationPurpose::Read
                .action()
                .ends_with(".inspect")
        );
        assert!(!super::real_flow_enabled());
    }
}

#[cfg(test)]
mod user_validator_scope_tests {
    #[test]
    fn isolated_user_validation_repeats_real_prepare_and_rejects_changed_claim() {
        let lab = crate::alpm_lab::AlpmLab::create().unwrap();
        let plan = super::PreparedFullUpgrade::prepare_isolated(lab.root()).unwrap();
        let review = plan.review_text();
        assert!(!review.contains("REAL MODE LOCKED"));
        assert!(review.contains("separate confirmation and Polkit"));
        let request = plan
            .confirm_and_revalidate(true)
            .unwrap()
            .validation_request("inline-user-plan")
            .unwrap();
        let mut calls = 0;
        super::validate_fresh_plan_claim(
            &request,
            || {
                calls += 1;
                super::PreparedFullUpgrade::prepare_isolated(lab.root())
            },
            "isolated",
        )
        .unwrap();
        assert_eq!(calls, 2);
        let mut changed = request;
        changed.plan_digest = "b".repeat(64);
        let mut calls = 0;
        assert!(
            super::validate_fresh_plan_claim(
                &changed,
                || {
                    calls += 1;
                    super::PreparedFullUpgrade::prepare_isolated(lab.root())
                },
                "isolated"
            )
            .is_err()
        );
        assert_eq!(calls, 1);
    }
    #[test]
    fn scope_mismatch_cannot_invoke_prepare_or_grant_authority() {
        let request = crate::transaction_ipc::PlanValidationRequest {
            transaction_id: "wrong-user-scope".into(),
            plan_digest: "a".repeat(64),
            scope: "isolated".into(),
        };
        let mut called = false;
        let result = super::validate_fresh_plan_claim(
            &request,
            || {
                called = true;
                Err("must not run".into())
            },
            "system",
        );
        assert!(result.is_err());
        assert!(!called);
    }
}

#[cfg(test)]
mod polkit_check_id_tests {
    #[test]
    fn concurrent_checks_never_reuse_plan_as_cancellation_id() {
        let mut threads = Vec::new();
        for _ in 0..16 {
            threads.push(std::thread::spawn(|| {
                (0..16)
                    .map(|_| super::next_polkit_check_id().unwrap())
                    .collect::<Vec<_>>()
            }));
        }
        let ids: Vec<_> = threads
            .into_iter()
            .flat_map(|t| t.join().unwrap())
            .collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
        assert_eq!(ids.len(), 256);
    }
}

#[cfg(test)]
mod polkit_decision_binding_tests {
    use super::*;
    #[test]
    fn denial_dismissal_and_missing_authentication_remain_distinct() {
        let mut details = std::collections::HashMap::new();
        assert!(
            require_allowed_polkit_result(false, false, &details)
                .unwrap_err()
                .contains("Polkit denied")
        );
        assert!(
            require_allowed_polkit_result(false, true, &details)
                .unwrap_err()
                .contains("authentication agent")
        );
        details.insert("polkit.dismissed".into(), "1".into());
        assert!(
            require_allowed_polkit_result(false, false, &details)
                .unwrap_err()
                .contains("cancelled")
        );
        assert!(require_allowed_polkit_result(true, false, &details).is_err());
    }
    #[test]
    fn only_unambiguous_positive_decision_is_accepted() {
        let details = std::collections::HashMap::new();
        assert!(require_allowed_polkit_result(true, false, &details).is_ok());
        assert!(require_allowed_polkit_result(true, true, &details).is_err());
    }
    #[test]
    fn authorization_details_preserve_exact_plan_reference() {
        let request = crate::transaction_ipc::PlanValidationRequest {
            transaction_id: "polkit-plan".into(),
            plan_digest: "a".repeat(64),
            scope: "system".into(),
        };
        let details = polkit_plan_details(&request);
        assert_eq!(details["transaction_id"], request.transaction_id);
        assert_eq!(details["plan_digest"], request.plan_digest);
        let mut changed = request.clone();
        changed.plan_digest = "b".repeat(64);
        assert_ne!(polkit_plan_details(&changed), details);
        changed = request;
        changed.transaction_id = "other-plan".into();
        assert_ne!(polkit_plan_details(&changed), details);
    }
}

#[cfg(test)]
mod plan_commitment_diagnostics {
    /// Read-only diagnostic: prepares the system plan in a private directory
    /// (downloads repository databases only) and prints its digest and input
    /// summary. Run explicitly with --ignored; never authorizes anything.
    #[test]
    #[ignore]
    fn print_system_plan_commitment_summary() {
        let plan = super::PreparedFullUpgrade::prepare_system().unwrap();
        println!(
            "euid={} digest={}",
            unsafe { libc::geteuid() },
            plan.commitment().unwrap()
        );
        println!("{}", plan.commitment_summary().unwrap());
    }

    fn package() -> crate::libalpm_ffi::AlpmUpgradePackage {
        crate::libalpm_ffi::AlpmUpgradePackage {
            name: "zlib".into(),
            installed_version: Some("1:1.3.2-4".into()),
            version: "1:1.4-1".into(),
            repository: "core".into(),
            arch: "x86_64".into(),
            filename: "zlib-1:1.4-1-x86_64.pkg.tar.zst".into(),
            sha256: "0123456789abcdef".repeat(4),
            signature: Some("iQIzBAABCAAdFiEE".into()),
            dependencies: vec!["glibc".into()],
            provides: vec!["libz.so=1-64".into()],
            conflicts: Vec::new(),
            replaces: Vec::new(),
            dependency_added: false,
        }
    }

    pub(super) fn fixture() -> super::PreparedFullUpgrade {
        super::PreparedFullUpgrade {
            config: crate::libalpm_ffi::PacmanConfig {
                root: "/".into(),
                db_path: "/var/lib/pacman/".into(),
                cache_dir: "/var/cache/pacman/pkg/".into(),
                gpg_dir: "/etc/pacman.d/gnupg/".into(),
                check_space: true,
                architecture: "x86_64".into(),
                repositories: vec!["core".into(), "extra".into()],
                repository_servers: vec![
                    ("core".into(), vec!["https://a.example/core".into()]),
                    ("extra".into(), vec!["https://a.example/extra".into()]),
                ],
                signature_policy: vec!["Required".into()],
                repository_signature_policies: Vec::new(),
                ignore_pkg: Vec::new(),
                ignore_group: Vec::new(),
                no_upgrade: Vec::new(),
                no_extract: Vec::new(),
                hook_dirs: Vec::new(),
                log_file: "/var/log/pacman.log".into(),
            },
            system: true,
            keyring: vec![("pubring.gpg".into(), b"keys".to_vec())],
            local: vec![("zlib-1:1.3.2-4/desc".into(), b"local".to_vec())],
            repositories: vec![
                ("core.db".into(), b"core-v1".to_vec()),
                ("extra.db".into(), b"extra-v1".to_vec()),
            ],
            initial: crate::libalpm_ffi::AlpmTransactionPlan {
                add: Vec::new(),
                remove: Vec::new(),
            },
            details: crate::libalpm_ffi::AlpmPreparedUpgrade {
                add: vec![package()],
                remove: Vec::new(),
                decisions: Vec::new(),
            },
        }
    }

    fn request(plan_digest: String) -> crate::transaction_ipc::PlanValidationRequest {
        crate::transaction_ipc::PlanValidationRequest {
            transaction_id: "plan-1".into(),
            plan_digest,
            scope: "system".into(),
        }
    }

    #[test]
    fn mismatch_keeps_refusal_and_names_inputs() {
        let plan = fixture();
        let digest = plan.commitment().unwrap();
        plan.validate_claim(&request(digest.clone())).unwrap();
        let error = plan
            .validate_claim(&request("0123456789abcdef".repeat(4)))
            .unwrap_err();
        assert!(
            error.starts_with("Prepared packages or plan inputs differ from the confirmed plan")
        );
        for field in [
            "add=1",
            "config=",
            "local=",
            "core.db=",
            "extra.db=",
            "keyring=",
            "details=",
        ] {
            assert!(error.contains(field), "{field}: {error}");
        }
        // A rebuilt extra.db is visible in the summary but, with an identical
        // PREPARE result, no longer invalidates the confirmed plan.
        let mut changed = plan;
        let before = changed.commitment_summary().unwrap();
        changed.repositories[1].1 = b"extra-v2".to_vec();
        let after = changed.commitment_summary().unwrap();
        assert_eq!(changed.commitment().unwrap(), digest);
        changed.validate_claim(&request(digest.clone())).unwrap();
        let differing: Vec<_> = before
            .split(' ')
            .zip(after.split(' '))
            .filter(|(a, b)| a != b)
            .map(|(a, _)| a.split('=').next().unwrap().to_string())
            .collect();
        assert_eq!(differing, vec!["extra.db"]);
    }
}

#[cfg(test)]
mod semantic_plan_commitment_tests {
    use super::plan_commitment_diagnostics::fixture;

    fn refused(change: impl FnOnce(&mut super::PreparedFullUpgrade)) {
        let confirmed = fixture();
        let digest = confirmed.commitment().unwrap();
        let mut fresh = fixture();
        change(&mut fresh);
        assert_ne!(fresh.commitment().unwrap(), digest);
        let request = crate::transaction_ipc::PlanValidationRequest {
            transaction_id: "plan-1".into(),
            plan_digest: digest,
            scope: "system".into(),
        };
        let error = fresh.validate_claim(&request).unwrap_err();
        assert!(error.starts_with("Prepared packages or plan inputs differ"));
        // A PREPARE-result change is also caught by the second PREPARE
        // comparison in confirm_and_revalidate (fresh.details != details).
        if fresh.config == confirmed.config
            && fresh.keyring == confirmed.keyring
            && fresh.local == confirmed.local
            && fresh.system == confirmed.system
        {
            assert_ne!(fresh.details, confirmed.details);
        }
    }

    #[test]
    fn unrelated_repository_database_rebuild_keeps_plan() {
        let confirmed = fixture();
        let mut fresh = fixture();
        fresh.repositories[1].1 = b"extra.db rebuilt with unrelated packages".to_vec();
        fresh.repositories[0].1.clear();
        assert_eq!(fresh.commitment().unwrap(), confirmed.commitment().unwrap());
        assert_eq!(fresh.details, confirmed.details);
    }

    #[test]
    fn package_set_version_and_epoch_changes_are_refused() {
        refused(|p| p.details.add[0].version = "1:1.4-2".into());
        refused(|p| p.details.add[0].version = "2:1.4-1".into());
        refused(|p| p.details.add[0].installed_version = Some("1:1.3.2-5".into()));
        refused(|p| p.details.add[0].name = "zlib-ng".into());
        refused(|p| {
            let mut extra = p.details.add[0].clone();
            extra.name = "minizip".into();
            p.details.add.push(extra);
        });
        refused(|p| p.details.add.clear());
        refused(|p| {
            p.details
                .remove
                .push(crate::libalpm_ffi::AlpmPlannedPackage {
                    name: "zlib-compat".into(),
                    version: "1.0-1".into(),
                })
        });
        refused(|p| p.details.decisions.push(1));
    }

    #[test]
    fn dependency_and_relation_changes_are_refused() {
        refused(|p| p.details.add[0].dependencies.push("evil".into()));
        refused(|p| p.details.add[0].dependencies.clear());
        refused(|p| p.details.add[0].dependency_added = true);
        refused(|p| p.details.add[0].provides.push("libc.so=6-64".into()));
        refused(|p| p.details.add[0].conflicts.push("glibc".into()));
        refused(|p| p.details.add[0].replaces.push("openssl".into()));
    }

    #[test]
    fn archive_identity_signature_and_repository_changes_are_refused() {
        refused(|p| p.details.add[0].sha256 = "f".repeat(64));
        refused(|p| p.details.add[0].filename = "zlib-1:1.4-1-x86_64.pkg.tar.xz".into());
        refused(|p| p.details.add[0].arch = "any".into());
        refused(|p| p.details.add[0].signature = Some("iQIzBAABCAAdFiEF".into()));
        refused(|p| p.details.add[0].signature = None);
        refused(|p| p.details.add[0].repository = "extra".into());
    }

    #[test]
    fn configuration_trust_keyring_and_installed_state_changes_are_refused() {
        refused(|p| p.config.repository_servers[1].1 = vec!["https://evil.example/extra".into()]);
        refused(|p| p.config.signature_policy = vec!["Optional".into()]);
        refused(|p| {
            p.config.repository_signature_policies =
                vec![("extra".into(), vec!["PackageOptional".into()])]
        });
        refused(|p| p.config.ignore_pkg.push("linux".into()));
        refused(|p| p.config.repositories.push("testing".into()));
        refused(|p| p.keyring[0].1 = b"other keys".to_vec());
        refused(|p| p.local[0].1 = b"changed local".to_vec());
        refused(|p| p.system = false);
    }
}
