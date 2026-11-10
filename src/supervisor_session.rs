//! In-memory diagnostic session. The supervisor, never the GUI, owns transaction
//! lifetime. Connection tokens identify connections only; transport authentication
//! must be performed by the caller. No execution or cancellation is authorized here.

use crate::supervisor_state::SupervisorState;
use crate::transaction_worker::TransactionWorker;
use std::sync::Arc;

/// Opaque connection generation, scoped to its originating session.
#[derive(Debug)]
pub struct ClientToken {
    generation: u64,
    session: Arc<()>,
}

#[derive(Debug)]
pub struct SupervisorSession {
    state: SupervisorState,
    client: Option<u64>,
    generation: u64,
    identity: Arc<()>,
    progress: Option<String>,
    question: Option<(u64, String)>,
    answer: Option<bool>,
}

impl SupervisorSession {
    /// Recovery is read-only: never replay a helper after supervisor restart.
    /// An interrupted running state requires explicit recovery by its owner.
    pub fn restore_finished(path: &std::path::Path, transaction_id: &str) -> Result<Self, String> {
        let state = SupervisorState::load(path)?;
        if state.transaction_id != transaction_id
            || state.phase != "finished"
            || !matches!(state.outcome.as_str(), "success" | "failure" | "cancelled")
        {
            return Err("Refusing to replay unfinished or mismatched diagnostic session".into());
        }
        let mut session = Self::diagnostic(transaction_id)?;
        session.state = state;
        Ok(session)
    }

    pub fn diagnostic(transaction_id: &str) -> Result<Self, String> {
        Ok(Self {
            state: SupervisorState::diagnostic(transaction_id)?,
            client: None,
            generation: 0,
            identity: Arc::new(()),
            progress: None,
            question: None,
            answer: None,
        })
    }

    /// Returns a detached copy: clients cannot mutate authoritative state.
    pub fn snapshot(&self) -> SupervisorState {
        self.state.clone()
    }

    pub fn client_connected(&self) -> bool {
        self.client.is_some()
    }

    pub fn real_execution_enabled(&self) -> bool {
        false
    }

    /// Attach or replace a GUI connection and return the current transaction state.
    /// Wrong transaction IDs and exhausted generations leave the session unchanged.
    /// Tokens must only be used with the session which issued them.
    pub fn attach(
        &mut self,
        transaction_id: &str,
    ) -> Result<(ClientToken, SupervisorState), String> {
        if transaction_id != self.state.transaction_id {
            return Err("Transaction identifier mismatch".into());
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or("Client generation overflow")?;
        self.generation = generation;
        self.client = Some(generation);
        Ok((
            ClientToken {
                generation,
                session: Arc::clone(&self.identity),
            },
            self.snapshot(),
        ))
    }

    /// A dropped socket is not a cancellation request. Stale disconnects are ignored.
    pub fn disconnect(&mut self, token: ClientToken) -> bool {
        if !Arc::ptr_eq(&self.identity, &token.session) || self.client != Some(token.generation) {
            return false;
        }
        self.client = None;
        true
    }

    /// Mirror verified worker transitions even while no GUI is connected.
    /// Terminal state and sequence validation remain owned by SupervisorState.
    pub fn sync_from_worker(&mut self, worker: &TransactionWorker) -> Result<bool, String> {
        self.state.sync_from_worker(worker)
    }

    /// Retain only the latest validated helper progress, with bounded memory.
    pub fn record_progress(&mut self, text: &str) -> Result<(), String> {
        if text.is_empty() || text.len() > 16 * 1024 || self.state.outcome != "running" {
            return Err("Invalid progress or terminal session".into());
        }
        // JSON escaping can expand each byte sixfold; stay within the client's
        // 16 KiB response limit, including the remaining state fields.
        let mut end = text.len().min(2048);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        self.progress = Some(text[..end].to_owned());
        Ok(())
    }

    pub fn as_json(&self) -> serde_json::Value {
        let mut value = self.state.as_json();
        if let Some(progress) = &self.progress {
            value["progress"] = progress.clone().into();
        }
        if let Some((id, text)) = &self.question {
            value["question"] = serde_json::json!({"id": id, "text": text});
        }
        value
    }

    pub fn ask_question(&mut self, id: u64, text: &str) -> Result<(), String> {
        if id == 0
            || text.is_empty()
            || text.len() > 512
            || self.question.is_some()
            || self.state.outcome != "running"
        {
            return Err("Invalid diagnostic question".into());
        }
        self.question = Some((id, text.into()));
        self.answer = None;
        Ok(())
    }

    pub fn answer_question(
        &mut self,
        transaction_id: &str,
        id: u64,
        approved: bool,
    ) -> Result<(), String> {
        if transaction_id != self.state.transaction_id
            || self.state.outcome != "running"
            || self.question.as_ref().map(|question| question.0) != Some(id)
            || self.answer.is_some()
        {
            return Err("Stale or mismatched diagnostic answer".into());
        }
        self.answer = Some(approved);
        Ok(())
    }

    pub fn take_answer(&mut self) -> Option<bool> {
        let answer = self.answer.take()?;
        self.question = None;
        Some(answer)
    }

    /// Publish in memory only after the verified transition has been persisted.
    pub fn persist_from_worker(
        &mut self,
        worker: &TransactionWorker,
        path: &std::path::Path,
    ) -> Result<bool, String> {
        let changed = self.state.persist_from_worker(worker, path)?;
        if self.state.outcome != "running" {
            self.question = None;
            self.answer = None;
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction_protocol::TransactionMessage;
    use crate::transaction_state::UpdatePhase;

    #[test]
    fn restart_restores_finished_state_without_replaying_unfinished_work() {
        use std::os::unix::fs::DirBuilderExt;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("rwr-restore-{}-{nonce}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("state.json");
        let mut state = SupervisorState::diagnostic("restart-test").unwrap();
        state.save(&path).unwrap();
        assert!(SupervisorSession::restore_finished(&path, "restart-test").is_err());
        state.phase = "finished".into();
        state.outcome = "failure".into();
        state.sequence = 1;
        state.update(&path).unwrap();
        assert!(SupervisorSession::restore_finished(&path, "wrong-id").is_err());
        let mut restored = SupervisorSession::restore_finished(&path, "restart-test").unwrap();
        assert_eq!(restored.attach("restart-test").unwrap().1, state);
        assert!(!restored.real_execution_enabled());
        assert_eq!(SupervisorState::load(&path).unwrap(), state);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn helper_progress_is_bounded_and_survives_gui_disconnect() {
        let mut session = SupervisorSession::diagnostic("progress-test").unwrap();
        session
            .record_progress(&"\u{0001}".repeat(16 * 1024))
            .unwrap();
        assert!(session.as_json().to_string().len() < 16 * 1024);
        session.record_progress(&"ą".repeat(2000)).unwrap();
        let before = session.as_json();
        let (token, _) = session.attach("progress-test").unwrap();
        session.disconnect(token);
        assert_eq!(session.as_json(), before);
        assert!(session.record_progress("").is_err());
        assert_eq!(session.as_json(), before);
    }

    #[test]
    fn disconnect_during_commit_preserves_transaction_and_reconnects_to_result() {
        let mut session = SupervisorSession::diagnostic("session-49").unwrap();
        let mut worker = TransactionWorker::new();
        worker.receive(TransactionMessage::Started).unwrap();
        let (token, initial) = session.attach("session-49").unwrap();
        assert_eq!(initial.sequence, 0);
        worker.advance_phase(UpdatePhase::Ready).unwrap();
        session.sync_from_worker(&worker).unwrap();
        worker.advance_phase(UpdatePhase::Commit).unwrap();
        session.sync_from_worker(&worker).unwrap();
        let before = session.snapshot();
        assert!(session.disconnect(token));
        assert!(!session.client_connected());
        assert_eq!(session.snapshot(), before);
        assert_eq!(worker.phase(), UpdatePhase::Commit);

        let (token, running) = session.attach("session-49").unwrap();
        assert_eq!(running, before);
        session.disconnect(token);
        worker
            .receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        worker.process_exited(0).unwrap();
        assert!(session.sync_from_worker(&worker).unwrap());
        let (_, finished) = session.attach("session-49").unwrap();
        assert_eq!(finished.phase, "finished");
        assert_eq!(finished.outcome, "success");
        assert_eq!(finished.sequence, 3);
        assert!(!session.sync_from_worker(&worker).unwrap());
        assert!(!session.real_execution_enabled());
        assert_eq!(finished.as_json()["real_execution_enabled"], false);
    }

    #[test]
    fn stale_disconnect_cannot_remove_replacement_client() {
        let mut session = SupervisorSession::diagnostic("session-49").unwrap();
        let (old, _) = session.attach("session-49").unwrap();
        let (current, _) = session.attach("session-49").unwrap();
        assert!(!session.disconnect(old));
        assert!(session.client_connected());
        assert!(session.disconnect(current));
    }

    #[test]
    fn token_from_another_session_is_rejected() {
        let mut first = SupervisorSession::diagnostic("same-id").unwrap();
        let mut second = SupervisorSession::diagnostic("same-id").unwrap();
        let (foreign, _) = first.attach("same-id").unwrap();
        let (local, _) = second.attach("same-id").unwrap();
        assert!(!second.disconnect(foreign));
        assert!(second.client_connected());
        assert!(second.disconnect(local));
    }

    #[test]
    fn invalid_attach_and_overflow_are_atomic() {
        assert!(SupervisorSession::diagnostic("../invalid").is_err());
        let mut session = SupervisorSession::diagnostic("session-49").unwrap();
        let (token, before) = session.attach("session-49").unwrap();
        assert!(session.attach("other").is_err());
        session.generation = u64::MAX;
        assert!(session.attach("session-49").is_err());
        assert_eq!(session.snapshot(), before);
        assert!(session.disconnect(token));
    }

    #[test]
    fn snapshots_and_rejected_transitions_cannot_mutate_session() {
        let mut session = SupervisorSession::diagnostic("session-49").unwrap();
        let before = session.snapshot();
        let mut copy = session.snapshot();
        copy.phase = "finished".into();
        let worker = TransactionWorker::new();
        assert!(session.sync_from_worker(&worker).is_err());
        assert_eq!(session.snapshot(), before);
        assert!(!session.client_connected());
    }
}

/// A plan-validation result is never an update result or COMMIT permission.
#[derive(Debug, Clone)]
pub struct PlanValidationSession {
    pub request: crate::transaction_ipc::PlanValidationRequest,
    state: SupervisorState,
    result: &'static str,
    error: Option<String>,
}

impl PlanValidationSession {
    pub fn new(request: crate::transaction_ipc::PlanValidationRequest) -> Result<Self, String> {
        request.validate()?;
        Ok(Self {
            state: SupervisorState::diagnostic(&request.transaction_id)?,
            request,
            result: "pending",
            error: None,
        })
    }
    pub fn observe(&mut self, worker: &TransactionWorker) -> Result<(), String> {
        // Publish terminal state only after bound evidence/exit and persistence.
        if worker.phase() != crate::transaction_state::UpdatePhase::Finished {
            self.state.sync_from_worker(worker)?;
        }
        Ok(())
    }
    pub fn as_json(&self) -> serde_json::Value {
        let mut value = self.state.as_json();
        value["operation"] = "validate-plan".into();
        value["protocol_version"] = crate::transaction_ipc::PLAN_PROTOCOL_VERSION.into();
        value["plan_digest"] = self.request.plan_digest.clone().into();
        value["scope"] = self.request.scope.clone().into();
        value["validation_outcome"] = self.result.into();
        value["commit_authorized"] = false.into();
        value["update_executed"] = false.into();
        if let Some(error) = &self.error {
            value["error"] = error.clone().into();
        }
        value
    }
    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let request = crate::transaction_ipc::PlanValidationRequest::parse(&serde_json::json!({
            "operation":value["operation"],"protocol_version":value["protocol_version"],
            "transaction_id":value["transaction_id"],"plan_digest":value["plan_digest"],"scope":value["scope"]}))?;
        let result = match value["validation_outcome"].as_str() {
            Some("pending") => "pending",
            Some("validated") => "validated",
            Some("rejected") => "rejected",
            _ => return Err("Invalid validation outcome".into()),
        };
        let valid = match result {
            "pending" => {
                matches!(value["phase"].as_str(), Some("prepare" | "ready"))
                    && value["outcome"] == "running"
            }
            "validated" => value["phase"] == "finished" && value["outcome"] == "success",
            _ => value["phase"] == "finished" && value["outcome"] == "failure",
        };
        if !valid
            || value["real_execution_enabled"] != false
            || value["commit_authorized"] != false
            || value["update_executed"] != false
            || value
                .as_object()
                .is_none_or(|v| v.len() != if value.get("error").is_some() { 13 } else { 12 })
        {
            return Err("Unsafe or ambiguous plan validation result".into());
        }
        if value.get("error").is_some() != (result == "rejected") {
            return Err("Validation error/result disagree".into());
        }
        let error = value
            .get("error")
            .map(|v| {
                v.as_str()
                    .filter(|s| s.len() <= 2048)
                    .map(str::to_owned)
                    .ok_or("Invalid validation error")
            })
            .transpose()?;
        Ok(Self {
            state: SupervisorState {
                transaction_id: request.transaction_id.clone(),
                phase: value["phase"].as_str().ok_or("Missing phase")?.into(),
                outcome: value["outcome"].as_str().ok_or("Missing outcome")?.into(),
                sequence: value["sequence"].as_u64().ok_or("Missing sequence")?,
            },
            request,
            result,
            error,
        })
    }
    fn finish(&mut self, result: Result<(), String>) -> Result<(), String> {
        use crate::transaction_protocol::TransactionMessage;
        let mut worker = TransactionWorker::new();
        worker.receive(TransactionMessage::Started)?;
        match result {
            Ok(()) => {
                worker.receive(TransactionMessage::Completed { exit_code: 0 })?;
                worker.process_exited(0)?;
                self.result = "validated";
            }
            Err(error) => {
                worker.receive(TransactionMessage::Failed("Plan validation refused".into()))?;
                worker.process_exited(1)?;
                self.result = "rejected";
                self.error = Some(error.chars().take(500).collect());
            }
        }
        self.state.sync_from_worker(&worker)?;
        Ok(())
    }
    pub fn complete_and_save(
        &mut self,
        result: Result<(), String>,
        path: &std::path::Path,
    ) -> Result<(), String> {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let mut next = self.clone();
        next.finish(result)?;
        let parent = path.parent().ok_or("Missing validation directory")?;
        let meta = std::fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
        if !meta.is_dir()
            || meta.permissions().mode() & 0o777 != 0o700
            || meta.uid() != unsafe { libc::geteuid() }
        {
            return Err("Validation directory must be private and owned".into());
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| e.to_string())?;
        writeln!(file, "{}", next.as_json())
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        std::fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        *self = next;
        Ok(())
    }
    pub fn fail_without_persistence(&mut self, error: String) {
        let _ = self.finish(Err(error));
    }
    pub fn load(
        path: &std::path::Path,
        request: &crate::transaction_ipc::PlanValidationRequest,
    ) -> Result<Self, String> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !meta.is_file()
            || meta.permissions().mode() & 0o777 != 0o600
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.len() > 16 * 1024
        {
            return Err("Unsafe validation result file".into());
        }
        let result = Self::from_json(
            &serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?,
        )?;
        if &result.request != request || result.result == "pending" {
            return Err("Validation result binding mismatch".into());
        }
        Ok(result)
    }
}

/// Supervise the existing helper IPC, require an exact handshake/evidence and
/// verify process exit. Command construction/trust stays with the supervisor.
pub fn supervise_plan_validation(
    command: &mut std::process::Command,
    request: &crate::transaction_ipc::PlanValidationRequest,
    mut observe: impl FnMut(&TransactionWorker) -> Result<(), String>,
) -> Result<(), String> {
    use crate::transaction_ipc::{
        IpcMessage, MAX_MESSAGE_BYTES, PLAN_PROTOCOL_VERSION, parse_message,
    };
    use std::io::{BufRead, BufReader, Read, Write};
    use std::process::Stdio;
    request.validate()?;
    let child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut guard = crate::process_guard::ChildGuard(child);
    let stdout = guard.0.stdout.take().ok_or("Missing validation output")?;
    let mut stdin = guard.0.stdin.take().ok_or("Missing validation input")?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(32);
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut bytes = Vec::new();
            match reader
                .by_ref()
                .take((MAX_MESSAGE_BYTES + 1) as u64)
                .read_until(b'\n', &mut bytes)
            {
                Ok(0) => break,
                Ok(_) if bytes.len() <= MAX_MESSAGE_BYTES && bytes.last() == Some(&b'\n') => {
                    if sender.send(Ok(bytes)).is_err() {
                        break;
                    }
                }
                _ => {
                    let _ = sender.send(Err("Invalid validation IPC framing".to_string()));
                    break;
                }
            }
        }
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let receive = || -> Result<Option<Vec<u8>>, String> {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(result) => result.map(Some),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Ok(None),
            _ => Err("Plan validation helper timed out".into()),
        }
    };
    let hello = receive()?.ok_or("Helper missing version handshake")?;
    let hello: serde_json::Value = serde_json::from_slice(&hello).map_err(|e| e.to_string())?;
    if hello.as_object().is_none_or(|v| v.len() != 5)
        || hello["type"] != "hello"
        || hello["component"] != "rwr-update-helper"
        || hello["operation"] != "validate-plan"
        || hello["protocol_version"].as_u64() != Some(PLAN_PROTOCOL_VERSION)
        || hello["real_execution_enabled"] != false
    {
        return Err("Untrusted validation helper identity or IPC version".into());
    }
    writeln!(stdin, "{}", request.as_json())
        .and_then(|_| stdin.flush())
        .map_err(|e| e.to_string())?;
    drop(stdin);
    let mut worker = TransactionWorker::new();
    let mut evidence = false;
    let mut failure = None;
    while let Some(bytes) = receive()? {
        let line = std::str::from_utf8(&bytes)
            .map_err(|e| e.to_string())?
            .trim_end_matches(['\r', '\n']);
        let message = parse_message(line)?;
        match &message {
            IpcMessage::Question { .. }
            | IpcMessage::Cancelled
            | IpcMessage::Phase(crate::transaction_ipc::IpcPhase::Commit) => {
                return Err(
                    "Validation helper attempted execution or interactive authorization".into(),
                );
            }
            IpcMessage::Progress(text) => {
                if serde_json::from_str::<serde_json::Value>(text)
                    .ok()
                    .is_some_and(|v| v["operation"] == "validate-plan")
                {
                    if evidence {
                        return Err("Duplicate plan validation evidence".into());
                    }
                    request.verify_evidence(text)?;
                    evidence = true;
                }
            }
            IpcMessage::Failed(text) => failure = Some(text.clone()),
            _ => {}
        }
        worker.receive_ipc_line(line)?;
        observe(&worker)?;
    }
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    let exit = guard.wait_for_exit(remaining.min(std::time::Duration::from_secs(10)))?;
    worker.process_exited(exit)?;
    if !evidence
        || worker.outcome() != Some(crate::transaction_protocol::TransactionOutcome::Success)
        || failure.is_some()
    {
        return Err(
            failure.unwrap_or_else(|| "Helper exit/result lacks matching plan evidence".into())
        );
    }
    Ok(())
}

/// Read-only recovery of the root-owned execution journal. The caller MUST
/// authenticate and authorize access and verify file provenance first. A valid
/// JSON record, UID or digest is never authority to execute or replay COMMIT.
/// Without a live owner, any nonterminal/torn journal has an UNKNOWN outcome.
pub fn recover_execution_journal(
    input: impl std::io::Read,
    request: &crate::transaction_ipc::PlanValidationRequest,
) -> Result<serde_json::Value, String> {
    use std::io::Read;
    request.validate()?;
    if request.scope != "system" {
        return Err("Execution recovery requires system scope".into());
    }
    let mut bytes = Vec::new();
    input
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 65536 {
        return Err("Oversized execution journal".into());
    }
    let mut phase = "none";
    let mut commit = false;
    let mut terminal = None;
    let mut error = None;
    let mut torn = false;
    for line in bytes.split_inclusive(|b| *b == b'\n') {
        if line.last() != Some(&b'\n') {
            torn = true;
            break;
        }
        if terminal.is_some() {
            return Err("Record after terminal execution outcome".into());
        }
        let record: serde_json::Value =
            serde_json::from_slice(line).map_err(|_| "Malformed execution journal")?;
        if record["transaction_id"] != request.transaction_id {
            return Err("Execution journal transaction mismatch".into());
        }
        let next = record["phase"].as_str().ok_or("Missing journal phase")?;
        match (phase, next) {
            ("none", "authorized")
                if record["plan_digest"] == request.plan_digest
                    && record["automatic_rollback"] == false => {}
            ("authorized", "packages_verified") => {}
            ("packages_verified", "commit_started")
                if record["partial_installation_possible"] == true
                    && record["automatic_rollback"] == false =>
            {
                commit = true;
            }
            ("commit_started", "finished")
                if record["outcome"] == "success" && record["automatic_rollback"] == false =>
            {
                terminal = Some("success");
            }
            ("authorized" | "packages_verified" | "commit_started", "failed")
                if record["partial_installation_possible"] == commit
                    && record["automatic_rollback"] == false
                    && record["error"].as_str().is_some_and(|e| !e.is_empty()) =>
            {
                terminal = Some("failure");
                error = record["error"].as_str().map(str::to_owned);
            }
            _ => return Err("Invalid execution journal binding or transition".into()),
        }
        phase = match next {
            "authorized" => "authorized",
            "packages_verified" => "packages_verified",
            "commit_started" => "commit_started",
            "finished" => "finished",
            _ => "failed",
        };
    }
    Ok(serde_json::json!({
        "transaction_id":request.transaction_id, "plan_digest":request.plan_digest,
        "outcome":if torn { "unknown" } else { terminal.unwrap_or("unknown") },
        "phase":phase, "partial_installation_possible":commit && (torn || terminal != Some("success")),
        "automatic_rollback":false, "replay_authorized":false,
        "error":error,
        "real_execution_enabled":crate::production_alpm_flow::real_flow_enabled()
    }))
}

#[cfg(test)]
mod execution_recovery_tests {
    use super::*;
    fn request() -> crate::transaction_ipc::PlanValidationRequest {
        crate::transaction_ipc::PlanValidationRequest {
            transaction_id: "recovery-1".into(),
            plan_digest: "a".repeat(64),
            scope: "system".into(),
        }
    }
    fn records() -> Vec<serde_json::Value> {
        let r = request();
        vec![
            serde_json::json!({"phase":"authorized","transaction_id":r.transaction_id,"plan_digest":r.plan_digest,"automatic_rollback":false}),
            serde_json::json!({"phase":"packages_verified","transaction_id":r.transaction_id}),
            serde_json::json!({"phase":"commit_started","transaction_id":r.transaction_id,"partial_installation_possible":true,"automatic_rollback":false}),
            serde_json::json!({"phase":"finished","transaction_id":r.transaction_id,"outcome":"success","automatic_rollback":false}),
        ]
    }
    fn encoded(records: &[serde_json::Value]) -> String {
        records.iter().map(|r| format!("{r}\n")).collect()
    }
    #[test]
    fn execution_recovery_requires_terminal_record_and_never_replays() {
        let entries = records();
        for count in 0..entries.len() {
            let status =
                recover_execution_journal(encoded(&entries[..count]).as_bytes(), &request())
                    .unwrap();
            assert_eq!(status["outcome"], "unknown");
            assert_eq!(status["replay_authorized"], false);
        }
        let status = recover_execution_journal(encoded(&entries).as_bytes(), &request()).unwrap();
        assert_eq!(status["outcome"], "success");
        let torn = encoded(&entries[..3]) + "{\"phase\":\"finished\"";
        let status = recover_execution_journal(torn.as_bytes(), &request()).unwrap();
        assert_eq!(status["outcome"], "unknown");
        assert_eq!(status["partial_installation_possible"], true);
    }
    #[test]
    fn execution_recovery_rejects_wrong_binding_order_and_appended_success() {
        let mut entries = records();
        let mut wrong = request();
        wrong.plan_digest = "b".repeat(64);
        assert!(recover_execution_journal(encoded(&entries).as_bytes(), &wrong).is_err());
        entries.swap(1, 2);
        assert!(recover_execution_journal(encoded(&entries).as_bytes(), &request()).is_err());
        entries = records();
        entries.push(entries.last().unwrap().clone());
        assert!(recover_execution_journal(encoded(&entries).as_bytes(), &request()).is_err());
        assert!(recover_execution_journal(&vec![b'x'; 65537][..], &request()).is_err());
        assert!(recover_execution_journal(b"not json\n".as_slice(), &request()).is_err());
    }
    #[test]
    fn execution_recovery_keeps_install_failure_and_partial_state() {
        let mut entries = records();
        entries.pop();
        entries.push(serde_json::json!({"phase":"failed","transaction_id":"recovery-1","error":"installation failed","partial_installation_possible":true,"automatic_rollback":false}));
        let status = recover_execution_journal(encoded(&entries).as_bytes(), &request()).unwrap();
        assert_eq!(status["outcome"], "failure");
        assert_eq!(status["error"], "installation failed");
        assert_eq!(status["partial_installation_possible"], true);
    }
}

/// One supervisor-owned execution. This is state, never an authorization token.
/// GUI attachment cannot create/replay a process or change the bound request.
pub struct ExecutionSession {
    pub request: crate::transaction_ipc::PlanValidationRequest,
    worker: TransactionWorker,
    sequence: u64,
    progress: String,
    question: Option<(u64, String)>,
    outcome: String,
    error: Option<String>,
    commit_seen: bool,
}
impl ExecutionSession {
    pub fn new(request: crate::transaction_ipc::PlanValidationRequest) -> Result<Self, String> {
        request.validate()?;
        if request.scope != "system" {
            return Err("System scope required".into());
        }
        Ok(Self {
            request,
            worker: TransactionWorker::new(),
            sequence: 0,
            progress: String::new(),
            question: None,
            outcome: "running".into(),
            error: None,
            commit_seen: false,
        })
    }
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({"operation":"execute-upgrade","protocol_version":1,
            "transaction_id":self.request.transaction_id,"plan_digest":self.request.plan_digest,
            "sequence":self.sequence,"phase":format!("{:?}",self.worker.phase()).to_lowercase(),
            "outcome":self.outcome,"progress":self.progress,"question":self.question.as_ref().map(|(id,text)|serde_json::json!({"id":id,"text":text})),
            "error":self.error,"partial_installation_possible":self.commit_seen && self.outcome!="success",
            "automatic_rollback":false,"replay_authorized":false,"real_execution_enabled":crate::production_alpm_flow::real_flow_enabled()})
    }
    pub fn observe_line(&mut self, line: &str) -> Result<(), String> {
        use crate::transaction_ipc::IpcMessage;
        if self.outcome != "running" {
            return Err("Terminal execution session".into());
        }
        let message = crate::transaction_ipc::parse_message(line)?;
        self.worker.receive_ipc_line(line)?;
        match message {
            IpcMessage::Progress(text) => self.progress = text.chars().take(2048).collect(),
            IpcMessage::Question { id, text } => self.question = Some((id, text)),
            IpcMessage::Failed(text) => self.error = Some(text),
            _ => {}
        }
        self.commit_seen |= self.worker.phase() == crate::transaction_state::UpdatePhase::Commit;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("Execution sequence exhausted")?;
        Ok(())
    }
    pub fn answer(&mut self, id: u64, approved: bool) -> Result<(), String> {
        if self.outcome != "running" || self.question.as_ref().map(|q| q.0) != Some(id) {
            return Err("Stale execution answer".into());
        }
        self.worker.answer_question(id, approved)?;
        self.question = None;
        self.sequence += 1;
        Ok(())
    }
    pub fn finish(&mut self, exit: i32, journal: Option<serde_json::Value>) -> Result<(), String> {
        if self.outcome != "running" {
            return Err("Execution result is immutable".into());
        }
        let verified_exit = self.worker.process_exited(exit).is_ok();
        let worker_success =
            self.worker.outcome() == Some(crate::transaction_protocol::TransactionOutcome::Success);
        let bound = journal.as_ref().is_none_or(|j| {
            j["transaction_id"] == self.request.transaction_id
                && j["plan_digest"] == self.request.plan_digest
        });
        // The durable journal can observe COMMIT even if its IPC phase was
        // lost. Never advertise a clean pre-install failure on that basis.
        if bound {
            if let Some(record) = journal.as_ref() {
                self.commit_seen |= record["partial_installation_possible"] == true
                    || matches!(
                        record["phase"].as_str(),
                        Some("commit_started" | "finished")
                    );
                if self.error.is_none() {
                    self.error = record["error"].as_str().map(str::to_owned);
                }
            }
        }
        let durable = journal.as_ref().and_then(|j| j["outcome"].as_str());
        self.outcome = if bound
            && verified_exit
            && exit == 0
            && worker_success
            && durable == Some("success")
        {
            "success"
        } else if bound
            && verified_exit
            && exit != 0
            && (durable == Some("failure") || (journal.is_none() && !self.commit_seen))
        {
            "failure"
        } else {
            "unknown"
        }
        .into();
        self.question = None;
        self.sequence += 1;
        Ok(())
    }
    pub fn supervision_lost(&mut self, error: String) {
        // A later transport failure must not erase an already verified result.
        if self.outcome != "running" {
            return;
        }
        self.outcome = "unknown".into();
        self.error = Some(error);
        self.question = None;
        self.sequence += 1;
    }
}

/// Existing helper IPC under service ownership. No authority is synthesized:
/// production callers must obtain Polkit authority before constructing Command.
/// Loss of a GUI only drops its answer sender; COMMIT ownership stays here.
pub fn supervise_execution(
    command: &mut std::process::Command,
    session: &std::sync::Arc<std::sync::Mutex<ExecutionSession>>,
    answers: std::sync::mpsc::Receiver<crate::transaction_ipc::IpcReply>,
    recover: impl FnOnce() -> Result<Option<serde_json::Value>, String>,
) -> Result<(), String> {
    use std::io::{BufRead, Read, Write};
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let request = session
        .lock()
        .map_err(|_| "Execution session poisoned")?
        .request
        .clone();
    let child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut guard = crate::process_guard::ChildGuard(child);
    let mut stdin = guard.0.stdin.take().ok_or("Missing execution stdin")?;
    let stdout = guard.0.stdout.take().ok_or("Missing execution stdout")?;
    let (tx, rx) = std::sync::mpsc::sync_channel(32);
    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stdout);
        loop {
            let mut bytes = Vec::new();
            match reader.by_ref().take(16385).read_until(b'\n', &mut bytes) {
                Ok(0) => break,
                Ok(_) if bytes.len() <= 16384 && bytes.last() == Some(&b'\n') => {
                    if tx
                        .send(String::from_utf8(bytes).map_err(|e| e.to_string()))
                        .is_err()
                    {
                        break;
                    }
                }
                _ => {
                    let _ = tx.send(Err("Invalid execution frame".into()));
                    break;
                }
            }
        }
    });
    let result = (|| -> Result<(), String> {
        let mut claim = request.as_json();
        claim["operation"] = "execute-upgrade".into();
        writeln!(stdin, "{claim}")
            .and_then(|_| stdin.flush())
            .map_err(|e| e.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(6 * 3600);
        loop {
            if Instant::now() >= deadline {
                return Err("Execution supervision deadline; outcome UNKNOWN".into());
            }
            match answers.try_recv() {
                Ok(reply) => {
                    let crate::transaction_ipc::IpcReply::Answer { id, approved } = reply;
                    if session
                        .lock()
                        .map_err(|_| "Execution session poisoned")?
                        .answer(id, approved)
                        .is_err()
                    {
                        continue; // Stale/duplicate GUI replies cannot kill supervision.
                    }
                    writeln!(
                        stdin,
                        "{}",
                        crate::transaction_ipc::encode_reply(
                            &crate::transaction_ipc::IpcReply::Answer { id, approved }
                        )
                    )
                    .and_then(|_| stdin.flush())
                    .map_err(|e| e.to_string())?;
                }
                Err(
                    std::sync::mpsc::TryRecvError::Empty
                    | std::sync::mpsc::TryRecvError::Disconnected,
                ) => {}
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(line) => session
                    .lock()
                    .map_err(|_| "Execution session poisoned")?
                    .observe_line(line?.trim_end())?,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        let exit = guard.wait_for_exit(Duration::from_secs(10))?;
        let journal = recover()?;
        session
            .lock()
            .map_err(|_| "Execution session poisoned")?
            .finish(exit, journal)?;
        Ok(())
    })();
    drop(stdin);
    if let Err(error) = &result {
        // Closing supervisor IPC makes the helper stop before COMMIT; once
        // COMMIT starts its journal, not killing the process, decides recovery.
        guard.preserve_and_reap();
        if let Ok(mut session) = session.lock() {
            session.supervision_lost(error.clone());
        }
    }
    result
}

#[cfg(test)]
mod execution_ownership_tests {
    use super::*;
    fn request() -> crate::transaction_ipc::PlanValidationRequest {
        crate::transaction_ipc::PlanValidationRequest {
            transaction_id: "owned-1".into(),
            plan_digest: "a".repeat(64),
            scope: "system".into(),
        }
    }
    fn lines(session: &mut ExecutionSession) {
        for line in [
            r#"{"type":"started"}"#,
            r#"{"type":"phase","phase":"ready"}"#,
            r#"{"type":"phase","phase":"commit"}"#,
        ] {
            session.observe_line(line).unwrap();
        }
    }
    fn durable(outcome: &str) -> serde_json::Value {
        let r = request();
        serde_json::json!({"transaction_id":r.transaction_id,"plan_digest":r.plan_digest,"outcome":outcome})
    }
    #[test]
    fn execution_success_requires_exit_and_matching_durable_result() {
        for (exit, journal, expected) in [
            (0, Some(durable("success")), "success"),
            (1, Some(durable("success")), "unknown"),
            (0, None, "unknown"),
            (0, Some(durable("unknown")), "unknown"),
        ] {
            let mut s = ExecutionSession::new(request()).unwrap();
            lines(&mut s);
            s.observe_line(r#"{"type":"completed","exit_code":0}"#)
                .unwrap();
            s.finish(exit, journal).unwrap();
            assert_eq!(s.snapshot()["outcome"], expected);
            assert!(s.finish(0, Some(durable("success"))).is_err());
        }
    }
    #[test]
    fn execution_wrong_plan_and_ipc_loss_never_become_success() {
        let mut s = ExecutionSession::new(request()).unwrap();
        lines(&mut s);
        s.observe_line(r#"{"type":"completed","exit_code":0}"#)
            .unwrap();
        let mut j = durable("success");
        j["plan_digest"] = "b".repeat(64).into();
        s.finish(0, Some(j)).unwrap();
        assert_eq!(s.snapshot()["outcome"], "unknown");
        let mut s = ExecutionSession::new(request()).unwrap();
        lines(&mut s);
        s.supervision_lost("IPC EOF".into());
        assert_eq!(s.snapshot()["outcome"], "unknown");
        assert_eq!(s.snapshot()["partial_installation_possible"], true);
    }
    #[test]
    fn execution_rejection_is_failure_without_commit() {
        let mut s = ExecutionSession::new(request()).unwrap();
        s.observe_line(r#"{"type":"started"}"#).unwrap();
        s.observe_line(r#"{"type":"failed","text":"Authorization denied"}"#)
            .unwrap();
        s.finish(1, None).unwrap();
        assert_eq!(s.snapshot()["outcome"], "failure");
    }
    #[test]
    fn execution_fixture_outlives_gui_answer_channel() {
        // Process ownership only: not an ALPM transaction or a Polkit test.
        let session = std::sync::Arc::new(std::sync::Mutex::new(
            ExecutionSession::new(request()).unwrap(),
        ));
        let (sender, receiver) = std::sync::mpsc::channel();
        drop(sender);
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c",r#"read request
printf '%s\n' '{"type":"started"}' '{"type":"phase","phase":"ready"}' '{"type":"phase","phase":"commit"}'
/usr/bin/sleep 0.05
printf '%s\n' '{"type":"completed","exit_code":0}'"#]);
        supervise_execution(&mut command, &session, receiver, || {
            Ok(Some(durable("success")))
        })
        .unwrap();
        assert_eq!(session.lock().unwrap().snapshot()["outcome"], "success");
    }
}

#[cfg(test)]
mod execution_question_process_tests {
    use super::*;
    #[test]
    fn execution_helper_question_is_answered_through_owned_session() {
        let request = crate::transaction_ipc::PlanValidationRequest {
            transaction_id: "question-process".into(),
            plan_digest: "a".repeat(64),
            scope: "system".into(),
        };
        let session = std::sync::Arc::new(std::sync::Mutex::new(
            ExecutionSession::new(request.clone()).unwrap(),
        ));
        let observed = session.clone();
        let (answers, replies) = std::sync::mpsc::channel();
        let task = std::thread::spawn(move || {
            let mut child = std::process::Command::new("/bin/sh");
            child.args(["-c",r#"read request
printf '%s\n' '{"type":"started"}' '{"type":"question","id":1,"text":"Reviewed replacement?"}'
read answer
printf '%s\n' '{"type":"phase","phase":"ready"}' '{"type":"phase","phase":"commit"}' '{"type":"completed","exit_code":0}'"#]);
            supervise_execution(&mut child, &observed, replies, || {
                Ok(Some(
                    serde_json::json!({"transaction_id":request.transaction_id,"plan_digest":request.plan_digest,"outcome":"success"}),
                ))
            })
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while session.lock().unwrap().snapshot()["question"]["id"] != 1 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        answers
            .send(crate::transaction_ipc::IpcReply::Answer {
                id: 1,
                approved: true,
            })
            .unwrap();
        task.join().unwrap().unwrap();
        assert_eq!(session.lock().unwrap().snapshot()["outcome"], "success");
    }
    #[test]
    fn execution_malformed_ipc_preserves_committing_process() {
        use std::os::unix::fs::DirBuilderExt;
        let directory =
            std::env::temp_dir().join(format!("rwr-owned-commit-{}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let marker = directory.join("finished");
        let request = crate::transaction_ipc::PlanValidationRequest {
            transaction_id: "broken-stream".into(),
            plan_digest: "a".repeat(64),
            scope: "system".into(),
        };
        let session = std::sync::Arc::new(std::sync::Mutex::new(
            ExecutionSession::new(request).unwrap(),
        ));
        let (_answers, replies) = std::sync::mpsc::channel();
        let mut child = std::process::Command::new("/bin/sh");
        child.args(["-c",r#"read request
printf '%s\n' '{"type":"started"}' '{"type":"phase","phase":"ready"}' '{"type":"phase","phase":"commit"}' 'invalid JSON'
/usr/bin/sleep 0.05
printf finished > "$1""#,"rwr-owned"]).arg(&marker);
        assert!(supervise_execution(&mut child, &session, replies, || Ok(None)).is_err());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !marker.exists() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(session.lock().unwrap().snapshot()["outcome"], "unknown");
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(test)]
mod terminal_result_transport_tests {
    use super::ExecutionSession;
    use crate::transaction_ipc::PlanValidationRequest;
    #[test]
    fn later_disconnect_preserves_verified_success() {
        let request = PlanValidationRequest {
            transaction_id: "verified-success".into(),
            plan_digest: "a".repeat(64),
            scope: "system".into(),
        };
        let mut session = ExecutionSession::new(request.clone()).unwrap();
        for line in [
            r#"{"type":"started"}"#,
            r#"{"type":"phase","phase":"ready"}"#,
            r#"{"type":"phase","phase":"commit"}"#,
            r#"{"type":"completed","exit_code":0}"#,
        ] {
            session.observe_line(line).unwrap();
        }
        session
            .finish(
                0,
                Some(serde_json::json!({
                    "transaction_id":request.transaction_id,
                    "plan_digest":request.plan_digest,
                    "outcome":"success",
                })),
            )
            .unwrap();
        let before = session.snapshot();
        assert_eq!(before["outcome"], "success");
        session.supervision_lost("late disconnect".into());
        assert_eq!(session.snapshot(), before);
    }
    #[test]
    fn later_ipc_errors_cannot_overwrite_verified_failure_or_unknown() {
        let request = PlanValidationRequest {
            transaction_id: "immutable-result".into(),
            plan_digest: "a".repeat(64),
            scope: "system".into(),
        };
        let mut failed = ExecutionSession::new(request.clone()).unwrap();
        failed.observe_line(r#"{"type":"started"}"#).unwrap();
        failed
            .observe_line(r#"{"type":"failed","text":"database locked"}"#)
            .unwrap();
        failed.finish(1, None).unwrap();
        let before = failed.snapshot();
        failed.supervision_lost("late EOF".into());
        assert_eq!(failed.snapshot(), before);
        let mut unknown = ExecutionSession::new(request).unwrap();
        unknown.supervision_lost("original recovery required".into());
        let before = unknown.snapshot();
        unknown.supervision_lost("later disconnect".into());
        assert_eq!(unknown.snapshot(), before);
    }
}

#[cfg(test)]
mod durable_commit_evidence_tests {
    use super::ExecutionSession;
    use crate::transaction_ipc::PlanValidationRequest;
    fn request() -> PlanValidationRequest {
        PlanValidationRequest {
            transaction_id: "lost-commit-phase".into(),
            plan_digest: "a".repeat(64),
            scope: "system".into(),
        }
    }
    #[test]
    fn missed_commit_ipc_preserves_journal_warning_and_error() {
        let request = request();
        let mut session = ExecutionSession::new(request.clone()).unwrap();
        session.observe_line(r#"{"type":"started"}"#).unwrap();
        session
            .finish(
                1,
                Some(serde_json::json!({
                    "transaction_id":request.transaction_id, "plan_digest":request.plan_digest,
                    "outcome":"failure", "phase":"failed", "partial_installation_possible":true,
                    "error":"hook failed after installation began",
                })),
            )
            .unwrap();
        let state = session.snapshot();
        assert_eq!(state["outcome"], "failure");
        assert_eq!(state["partial_installation_possible"], true);
        assert_eq!(state["error"], "hook failed after installation began");
    }
    #[test]
    fn incomplete_commit_journal_is_unknown_with_partial_installation_warning() {
        let request = request();
        let mut session = ExecutionSession::new(request.clone()).unwrap();
        session.observe_line(r#"{"type":"started"}"#).unwrap();
        session.finish(1, Some(serde_json::json!({
            "transaction_id":request.transaction_id, "plan_digest":request.plan_digest,
            "outcome":"unknown", "phase":"commit_started", "partial_installation_possible":true,
        }))).unwrap();
        let state = session.snapshot();
        assert_eq!(state["outcome"], "unknown");
        assert_eq!(state["partial_installation_possible"], true);
        assert_eq!(state["replay_authorized"], false);
    }
    #[test]
    fn foreign_journal_cannot_supply_error_or_commit_evidence() {
        let mut session = ExecutionSession::new(request()).unwrap();
        session.observe_line(r#"{"type":"started"}"#).unwrap();
        session.finish(1, Some(serde_json::json!({
            "transaction_id":"foreign", "plan_digest":"b".repeat(64),
            "outcome":"failure", "partial_installation_possible":true, "error":"foreign error",
        }))).unwrap();
        let state = session.snapshot();
        assert_eq!(state["outcome"], "unknown");
        assert!(state["error"].is_null());
    }
}
