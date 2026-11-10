//! Persistent diagnostic supervisor state.
//! Local state only. No package execution or privileged operations.

use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorState {
    pub transaction_id: String,
    pub phase: String,
    pub outcome: String,
    pub sequence: u64,
}

impl SupervisorState {
    pub fn diagnostic(id: &str) -> Result<Self, String> {
        if !valid_id(id) {
            return Err("Invalid transaction identifier".into());
        }

        Ok(Self {
            transaction_id: id.into(),
            phase: "prepare".into(),
            outcome: "running".into(),
            sequence: 0,
        })
    }

    /// Mirror verified worker state without authorizing execution.
    pub fn sync_from_worker(
        &mut self,
        worker: &crate::transaction_worker::TransactionWorker,
    ) -> Result<bool, String> {
        use crate::transaction_protocol::TransactionOutcome;
        use crate::transaction_state::UpdatePhase;

        let phase = match worker.phase() {
            UpdatePhase::Prepare => "prepare",
            UpdatePhase::Ready => "ready",
            UpdatePhase::Commit => "commit",
            UpdatePhase::Finished => "finished",
        };

        let outcome = match worker.outcome() {
            Some(TransactionOutcome::Running) => "running",
            Some(TransactionOutcome::Success) => "success",
            Some(TransactionOutcome::Failure) => "failure",
            Some(TransactionOutcome::Cancelled) => "cancelled",
            None => return Err("Worker has no verified outcome".into()),
        };

        if self.phase == phase && self.outcome == outcome {
            return Ok(false);
        }

        if self.outcome != "running" || self.phase == "finished" {
            return Err("Cannot modify terminal supervisor state".into());
        }

        let valid = match (self.phase.as_str(), phase, outcome) {
            ("prepare", "ready", "running") => true,
            ("ready", "commit", "running") => true,
            ("prepare" | "ready" | "commit", "finished", "success" | "failure" | "cancelled") => {
                true
            }
            _ => false,
        };

        if !valid {
            return Err(format!(
                "Invalid supervisor transition: {} -> {} ({})",
                self.phase, phase, outcome
            ));
        }

        let next_sequence = self
            .sequence
            .checked_add(1)
            .ok_or("Supervisor sequence overflow")?;

        self.sequence = next_sequence;
        self.phase = phase.into();
        self.outcome = outcome.into();

        Ok(true)
    }

    /// Persist a verified worker transition before publishing it in memory.
    /// No transaction execution or COMMIT authorization is performed.
    pub fn persist_from_worker(
        &mut self,
        worker: &crate::transaction_worker::TransactionWorker,
        path: &Path,
    ) -> Result<bool, String> {
        let mut next = self.clone();

        if !next.sync_from_worker(worker)? {
            return Ok(false);
        }

        next.update(path)?;
        *self = next;

        Ok(true)
    }

    pub fn as_json(&self) -> Value {
        json!({
            "transaction_id": self.transaction_id,
            "phase": self.phase,
            "outcome": self.outcome,
            "sequence": self.sequence,
            "real_execution_enabled": false
        })
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err("Unsafe state file".into());
        }

        if metadata.len() > 16 * 1024 {
            return Err("State file too large".into());
        }

        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let object = value.as_object().ok_or("State must be an object")?;

        if object.len() != 5 || value["real_execution_enabled"] != false {
            return Err("Invalid or unsafe state schema".into());
        }

        let id = value["transaction_id"]
            .as_str()
            .ok_or("Missing transaction ID")?;
        let phase = value["phase"].as_str().ok_or("Missing phase")?;
        let outcome = value["outcome"].as_str().ok_or("Missing outcome")?;
        let sequence = value["sequence"].as_u64().ok_or("Missing sequence")?;

        if !valid_id(id) || !valid_phase(phase) || !valid_outcome(outcome) {
            return Err("Invalid state values".into());
        }

        Ok(Self {
            transaction_id: id.into(),
            phase: phase.into(),
            outcome: outcome.into(),
            sequence,
        })
    }

    pub fn save(&self, destination: &Path) -> Result<(), String> {
        self.validate()?;

        let parent = destination.parent().ok_or("Missing state directory")?;
        let parent_meta = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;

        if !parent_meta.file_type().is_dir() {
            return Err("State parent is not a real directory".into());
        }

        if parent_meta.permissions().mode() & 0o077 != 0 {
            return Err("State directory must be private".into());
        }

        if fs::symlink_metadata(destination).is_ok() {
            return Err("State already exists; use update".into());
        }

        self.write_atomic(destination)
    }

    pub fn update(&self, destination: &Path) -> Result<(), String> {
        self.validate()?;

        let previous = Self::load(destination)?;

        if self.transaction_id != previous.transaction_id {
            return Err("Transaction identifier changed".into());
        }

        if self.sequence
            != previous
                .sequence
                .checked_add(1)
                .ok_or("Sequence overflow")?
        {
            return Err("Invalid state sequence".into());
        }

        self.write_atomic(destination)
    }

    fn validate(&self) -> Result<(), String> {
        if !valid_id(&self.transaction_id)
            || !valid_phase(&self.phase)
            || !valid_outcome(&self.outcome)
        {
            return Err("Invalid supervisor state".into());
        }
        Ok(())
    }

    fn write_atomic(&self, destination: &Path) -> Result<(), String> {
        let parent = destination.parent().ok_or("Missing state directory")?;
        let metadata = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;

        if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("Unsafe state directory".into());
        }

        let number = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".rwr-state-{}-{}.tmp", std::process::id(), number));

        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|e| e.to_string())?;

            writeln!(file, "{}", self.as_json()).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;

            fs::rename(&temporary, destination).map_err(|e| e.to_string())?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|e| e.to_string())?;

            Ok(())
        })();

        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }

        result
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b"-"[0])
}

fn valid_phase(value: &str) -> bool {
    matches!(value, "prepare" | "ready" | "commit" | "finished")
}

fn valid_outcome(value: &str) -> bool {
    matches!(value, "running" | "success" | "failure" | "cancelled")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_directory() -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "rwr-state-{}-{}",
            std::process::id(),
            NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[test]
    fn sync_from_worker_rejects_invalid_transitions() {
        use crate::transaction_protocol::TransactionMessage;
        use crate::transaction_state::UpdatePhase;
        use crate::transaction_worker::TransactionWorker;

        let mut state = SupervisorState::diagnostic("rwr-sync-test").unwrap();
        let mut worker = TransactionWorker::new();

        assert!(state.sync_from_worker(&worker).is_err());
        assert_eq!(state.sequence, 0);

        worker.receive(TransactionMessage::Started).unwrap();
        assert!(!state.sync_from_worker(&worker).unwrap());

        worker.advance_phase(UpdatePhase::Ready).unwrap();
        assert!(state.sync_from_worker(&worker).unwrap());
        assert_eq!(state.phase, "ready");
        assert_eq!(state.sequence, 1);

        assert!(!state.sync_from_worker(&worker).unwrap());
        assert_eq!(state.sequence, 1);

        worker.advance_phase(UpdatePhase::Commit).unwrap();
        assert!(state.sync_from_worker(&worker).unwrap());
        assert_eq!(state.phase, "commit");
        assert_eq!(state.sequence, 2);

        worker
            .receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        assert!(!state.sync_from_worker(&worker).unwrap());

        worker.process_exited(0).unwrap();
        assert!(state.sync_from_worker(&worker).unwrap());
        assert_eq!(state.phase, "finished");
        assert_eq!(state.outcome, "success");
        assert_eq!(state.sequence, 3);

        assert!(!state.sync_from_worker(&worker).unwrap());

        let mut second = TransactionWorker::new();
        second.receive(TransactionMessage::Started).unwrap();
        assert!(state.sync_from_worker(&second).is_err());
        assert_eq!(state.sequence, 3);
    }

    #[test]
    fn sync_from_worker_rejects_skipped_phase() {
        use crate::transaction_protocol::TransactionMessage;
        use crate::transaction_state::UpdatePhase;
        use crate::transaction_worker::TransactionWorker;

        let mut state = SupervisorState::diagnostic("rwr-skip-test").unwrap();
        let mut worker = TransactionWorker::new();

        worker.receive(TransactionMessage::Started).unwrap();
        worker.advance_phase(UpdatePhase::Ready).unwrap();
        worker.advance_phase(UpdatePhase::Commit).unwrap();

        assert!(state.sync_from_worker(&worker).is_err());
        assert_eq!(state.phase, "prepare");
        assert_eq!(state.sequence, 0);
    }

    #[test]
    fn persist_from_worker_survives_reload() {
        use crate::transaction_protocol::TransactionMessage;
        use crate::transaction_state::UpdatePhase;
        use crate::transaction_worker::TransactionWorker;

        let directory = private_directory();
        let path = directory.join("state.json");

        let mut state = SupervisorState::diagnostic("rwr-persist-test").unwrap();
        state.save(&path).unwrap();

        let mut worker = TransactionWorker::new();
        worker.receive(TransactionMessage::Started).unwrap();
        worker.advance_phase(UpdatePhase::Ready).unwrap();

        assert!(state.persist_from_worker(&worker, &path).unwrap());
        assert_eq!(state.phase, "ready");
        assert_eq!(state.sequence, 1);
        assert_eq!(SupervisorState::load(&path).unwrap(), state);

        assert!(!state.persist_from_worker(&worker, &path).unwrap());
        assert_eq!(state.sequence, 1);

        worker.advance_phase(UpdatePhase::Commit).unwrap();
        assert!(state.persist_from_worker(&worker, &path).unwrap());

        worker
            .receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        worker.process_exited(0).unwrap();

        assert!(state.persist_from_worker(&worker, &path).unwrap());
        assert_eq!(state.phase, "finished");
        assert_eq!(state.outcome, "success");
        assert_eq!(SupervisorState::load(&path).unwrap(), state);

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn persist_failure_does_not_change_memory() {
        use crate::transaction_protocol::TransactionMessage;
        use crate::transaction_state::UpdatePhase;
        use crate::transaction_worker::TransactionWorker;

        let directory = private_directory();
        let missing = directory.join("missing.json");

        let mut state = SupervisorState::diagnostic("rwr-failure-test").unwrap();
        let original = state.clone();

        let mut worker = TransactionWorker::new();
        worker.receive(TransactionMessage::Started).unwrap();
        worker.advance_phase(UpdatePhase::Ready).unwrap();

        assert!(state.persist_from_worker(&worker, &missing).is_err());
        assert_eq!(state, original);
        assert!(!missing.exists());

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn save_load_and_update() {
        let directory = private_directory();
        let path = directory.join("state.json");
        let mut state = SupervisorState::diagnostic("rwr-test-1").unwrap();

        state.save(&path).unwrap();
        assert_eq!(SupervisorState::load(&path).unwrap(), state);
        assert!(state.save(&path).is_err());

        state.phase = "ready".into();
        state.sequence = 1;
        state.update(&path).unwrap();

        assert_eq!(SupervisorState::load(&path).unwrap(), state);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_sequence_rollback() {
        let directory = private_directory();
        let path = directory.join("state.json");
        let state = SupervisorState::diagnostic("test-rollback").unwrap();

        state.save(&path).unwrap();
        assert!(state.update(&path).is_err());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_invalid_identifier() {
        assert!(SupervisorState::diagnostic("../escape").is_err());
        assert!(SupervisorState::diagnostic("space name").is_err());
        assert!(SupervisorState::diagnostic("").is_err());
    }

    #[test]
    fn rejects_symlink_state() {
        let directory = private_directory();
        let original = directory.join("original.json");
        let link = directory.join("state.json");

        SupervisorState::diagnostic("test-link")
            .unwrap()
            .save(&original)
            .unwrap();
        std::os::unix::fs::symlink(&original, &link).unwrap();

        assert!(SupervisorState::load(&link).is_err());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn real_mode_remains_disabled() {
        let directory = private_directory();
        let path = directory.join("state.json");

        SupervisorState::diagnostic("test-safe")
            .unwrap()
            .save(&path)
            .unwrap();
        let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();

        assert_eq!(value["real_execution_enabled"], false);
        fs::remove_dir_all(directory).unwrap();
    }
}
