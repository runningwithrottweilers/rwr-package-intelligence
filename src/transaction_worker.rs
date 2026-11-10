//! Safe adapter between transaction messages and the protocol.
//! No privileged process or package manager is executed.

use crate::transaction_protocol::{TransactionMessage, TransactionOutcome, TransactionProtocol};
use crate::transaction_state::UpdatePhase;

pub struct TransactionWorker {
    protocol: TransactionProtocol,
    phase: UpdatePhase,
}

impl TransactionWorker {
    pub fn new() -> Self {
        Self {
            protocol: TransactionProtocol::new(),
            phase: UpdatePhase::Prepare,
        }
    }

    /// Phase tracking is separate from IPC progress text. Only a trusted
    /// transaction coordinator may call this method after observing the
    /// corresponding libalpm boundary. It does not execute any operation.
    pub fn phase(&self) -> UpdatePhase {
        self.phase
    }

    pub fn advance_phase(&mut self, next: UpdatePhase) -> Result<(), String> {
        let valid = matches!(
            (self.phase, next),
            (UpdatePhase::Prepare, UpdatePhase::Ready) | (UpdatePhase::Ready, UpdatePhase::Commit)
        );
        if !valid {
            return Err(format!(
                "Invalid update phase transition: {:?} -> {:?}",
                self.phase, next
            ));
        }
        if !self.protocol.is_active() {
            return Err("Cannot advance phase without running transaction".into());
        }
        self.phase = next;
        Ok(())
    }

    /// A phase becomes Finished only after the existing protocol has
    /// verified a terminal outcome, including process exit when required.
    fn sync_terminal_phase(&mut self) {
        if matches!(
            self.outcome(),
            Some(
                TransactionOutcome::Success
                    | TransactionOutcome::Cancelled
                    | TransactionOutcome::Failure
            )
        ) {
            self.phase = UpdatePhase::Finished;
        }
    }

    pub fn receive(&mut self, message: TransactionMessage) -> Result<(), String> {
        let result = self.protocol.receive(message);
        self.sync_terminal_phase();
        result
    }

    // ETAP 4.5Q-N2: route known libalpm events through the existing protocol.
    pub fn receive_alpm_event(&mut self, code: i32, english: bool) -> Result<(), String> {
        let Some((pl, en)) = crate::libalpm_ffi::alpm_event_message(code) else {
            return Ok(());
        };
        let text = if english { en } else { pl };
        self.receive(TransactionMessage::Progress(text.to_owned()))
    }

    // O5: preserve the order of events delivered by the libalpm adapter.
    pub fn receive_alpm_sequence(&mut self, sequence: &[i32], english: bool) -> Result<(), String> {
        for &code in sequence {
            self.receive_alpm_event(code, english)?;
        }
        Ok(())
    }

    pub fn receive_ipc_line(&mut self, line: &str) -> Result<(), String> {
        use crate::transaction_ipc::{IpcMessage, parse_message};

        let message = parse_message(line)?;

        match message {
            IpcMessage::Started => self.receive(TransactionMessage::Started),
            IpcMessage::Progress(text) => self.receive(TransactionMessage::Progress(text)),
            IpcMessage::Phase(phase) => self.advance_phase(match phase {
                crate::transaction_ipc::IpcPhase::Ready => UpdatePhase::Ready,
                crate::transaction_ipc::IpcPhase::Commit => UpdatePhase::Commit,
            }),
            IpcMessage::Question { id, text } => {
                let expected = self.protocol.pending_question_id();

                if expected.is_some() {
                    // A second question while one is unanswered is a helper
                    // protocol violation, same class as an identifier
                    // mismatch: fail closed instead of staying Running.
                    self.connection_lost();
                    return Err("Another question is pending".into());
                }

                self.receive(TransactionMessage::Question(text))?;

                if self.protocol.pending_question_id() != Some(id) {
                    self.connection_lost();
                    return Err("IPC question identifier mismatch".into());
                }

                Ok(())
            }
            IpcMessage::Completed { exit_code } => {
                self.receive(TransactionMessage::Completed { exit_code })
            }
            IpcMessage::Failed(text) => self.receive(TransactionMessage::Failed(text)),
            IpcMessage::Cancelled => self.receive(TransactionMessage::Cancelled),
        }
    }

    pub fn pending_question_id(&self) -> Option<u64> {
        self.protocol.pending_question_id()
    }

    pub fn answer_question(&mut self, question_id: u64, approved: bool) -> Result<(), String> {
        let result = self.protocol.answer_question_with_id(question_id, approved);
        self.sync_terminal_phase();
        result
    }

    pub fn process_exited(&mut self, exit_code: i32) -> Result<(), String> {
        let result = self.protocol.verify_process_exit(exit_code);
        self.sync_terminal_phase();
        result
    }

    pub fn connection_lost(&mut self) {
        self.protocol.disconnected();
        self.sync_terminal_phase();
    }

    pub fn outcome(&self) -> Option<TransactionOutcome> {
        self.protocol.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phases_require_explicit_order_and_running_protocol() {
        let mut worker = TransactionWorker::new();
        assert_eq!(worker.phase(), UpdatePhase::Prepare);
        assert!(worker.advance_phase(UpdatePhase::Ready).is_err());
        worker.receive(TransactionMessage::Started).unwrap();
        assert!(worker.advance_phase(UpdatePhase::Commit).is_err());
        worker.advance_phase(UpdatePhase::Ready).unwrap();
        assert!(worker.phase().allows_cancel_request());
        worker.advance_phase(UpdatePhase::Commit).unwrap();
        assert!(!worker.phase().allows_cancel_request());
        assert!(worker.phase().requires_supervision_after_disconnect());
        assert!(worker.advance_phase(UpdatePhase::Finished).is_err());
        assert!(worker.advance_phase(UpdatePhase::Ready).is_err());
    }

    #[test]
    fn progress_never_implicitly_enters_commit() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"progress","text":"COMMIT"}"#)
            .unwrap();
        assert_eq!(worker.phase(), UpdatePhase::Prepare);
    }

    #[test]
    fn success_is_finished_only_after_verified_process_exit() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker.advance_phase(UpdatePhase::Ready).unwrap();
        worker.advance_phase(UpdatePhase::Commit).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"completed","exit_code":0}"#)
            .unwrap();
        assert_eq!(worker.phase(), UpdatePhase::Commit);
        worker.process_exited(0).unwrap();
        assert_eq!(worker.phase(), UpdatePhase::Finished);
    }

    #[test]
    fn real_laboratory_events_reach_transaction_worker() {
        let lab = crate::alpm_lab::AlpmLab::create().unwrap();
        let events = lab.prepare_isolated_transaction_with_events().unwrap();

        for code in [5, 6, 7, 8] {
            assert!(events.contains(&code), "Missing real event {code}");
        }

        for english in [false, true] {
            let mut worker = TransactionWorker::new();
            worker.receive(TransactionMessage::Started).unwrap();
            worker.receive_alpm_sequence(&events, english).unwrap();
            assert_eq!(worker.outcome(), Some(TransactionOutcome::Running));
        }

        println!("REAL LAB EVENTS: {:?}", events);
        println!("TRANSACTION WORKER: PL/EN PASS");
        println!("COMMIT: NOT CALLED");
    }

    #[test]
    fn alpm_sequence_accepts_ordered_events() {
        let mut worker = TransactionWorker::new();
        worker.receive(TransactionMessage::Started).unwrap();
        worker.receive_alpm_sequence(&[5, 6, 7, 8], false).unwrap();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Running));
    }

    #[test]
    fn alpm_sequence_rejected_before_start() {
        let mut worker = TransactionWorker::new();
        assert!(worker.receive_alpm_sequence(&[5, 6], false).is_err());
    }

    #[test]
    fn alpm_sequence_ignores_unknown_events() {
        let mut worker = TransactionWorker::new();
        worker.receive(TransactionMessage::Started).unwrap();
        worker.receive_alpm_sequence(&[999, 5, 6], true).unwrap();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Running));
    }

    #[test]
    fn alpm_progress_accepts_polish_and_english() {
        let mut worker = TransactionWorker::new();
        worker.receive(TransactionMessage::Started).unwrap();
        worker.receive_alpm_event(5, false).unwrap();
        worker.receive_alpm_event(6, true).unwrap();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Running));
    }

    #[test]
    fn alpm_progress_rejected_before_start() {
        let mut worker = TransactionWorker::new();
        assert!(worker.receive_alpm_event(5, false).is_err());
    }

    #[test]
    fn alpm_progress_rejected_after_completion() {
        let mut worker = TransactionWorker::new();
        worker.receive(TransactionMessage::Started).unwrap();
        worker
            .receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        assert!(worker.receive_alpm_event(5, true).is_err());
    }

    #[test]
    fn unknown_alpm_event_is_ignored() {
        let mut worker = TransactionWorker::new();
        worker.receive_alpm_event(999, false).unwrap();
        assert_eq!(worker.outcome(), None);
    }

    #[test]
    fn worker_requires_verified_success() {
        let mut worker = TransactionWorker::new();
        worker.receive(TransactionMessage::Started).unwrap();
        worker
            .receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Running));
        worker.process_exited(0).unwrap();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Success));
    }

    #[test]
    fn worker_rejects_wrong_question_id() {
        let mut worker = TransactionWorker::new();
        worker.receive(TransactionMessage::Started).unwrap();
        worker
            .receive(TransactionMessage::Question("Proceed?".into()))
            .unwrap();
        assert!(worker.answer_question(999, true).is_err());
        assert_eq!(worker.pending_question_id(), Some(1));
    }

    #[test]
    fn worker_rejects_unverified_completion() {
        let mut worker = TransactionWorker::new();
        worker.receive(TransactionMessage::Started).unwrap();
        worker
            .receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        worker.connection_lost();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn worker_detects_process_failure() {
        let mut worker = TransactionWorker::new();
        worker.receive(TransactionMessage::Started).unwrap();
        worker
            .receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        worker.process_exited(1).unwrap();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn worker_rejects_stale_answer() {
        let mut worker = TransactionWorker::new();
        worker.receive(TransactionMessage::Started).unwrap();
        worker
            .receive(TransactionMessage::Question("First?".into()))
            .unwrap();
        worker.answer_question(1, true).unwrap();
        worker
            .receive(TransactionMessage::Question("Second?".into()))
            .unwrap();
        assert!(worker.answer_question(1, true).is_err());
        assert_eq!(worker.pending_question_id(), Some(2));
    }
}

#[cfg(test)]
mod ipc_integration_tests {
    use super::*;

    #[test]
    fn ipc_phase_requires_started_and_ordered_boundaries() {
        let mut worker = TransactionWorker::new();
        assert!(
            worker
                .receive_ipc_line(r#"{"type":"phase","phase":"ready"}"#)
                .is_err()
        );
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        assert!(
            worker
                .receive_ipc_line(r#"{"type":"phase","phase":"commit"}"#)
                .is_err()
        );
        worker
            .receive_ipc_line(r#"{"type":"phase","phase":"ready"}"#)
            .unwrap();
        assert_eq!(worker.phase(), UpdatePhase::Ready);
        worker
            .receive_ipc_line(r#"{"type":"phase","phase":"commit"}"#)
            .unwrap();
        assert_eq!(worker.phase(), UpdatePhase::Commit);
        assert!(
            worker
                .receive_ipc_line(r#"{"type":"phase","phase":"ready"}"#)
                .is_err()
        );
    }

    #[test]
    fn ipc_success_requires_process_exit() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"progress","text":"Downloading"}"#)
            .unwrap();
        worker
            .receive_ipc_line(r#"{"type":"completed","exit_code":0}"#)
            .unwrap();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Running));
        worker.process_exited(0).unwrap();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Success));
    }

    #[test]
    fn ipc_question_identifier_matches() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"question","id":1,"text":"Proceed?"}"#)
            .unwrap();
        assert_eq!(worker.pending_question_id(), Some(1));
        worker.answer_question(1, true).unwrap();
        assert_eq!(worker.pending_question_id(), None);
    }

    #[test]
    fn ipc_question_identifier_mismatch_fails_closed() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        assert!(
            worker
                .receive_ipc_line(r#"{"type":"question","id":999,"text":"Proceed?"}"#)
                .is_err()
        );
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn ipc_rejects_unknown_command_field() {
        let mut worker = TransactionWorker::new();
        assert!(
            worker
                .receive_ipc_line(r#"{"type":"started","command":"pacman"}"#)
                .is_err()
        );
    }

    #[test]
    fn ipc_rejects_progress_before_start() {
        let mut worker = TransactionWorker::new();
        assert!(
            worker
                .receive_ipc_line(r#"{"type":"progress","text":"Downloading"}"#)
                .is_err()
        );
    }

    #[test]
    fn ipc_rejects_duplicate_completion() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"completed","exit_code":0}"#)
            .unwrap();
        assert!(
            worker
                .receive_ipc_line(r#"{"type":"completed","exit_code":0}"#)
                .is_err()
        );
    }

    // ETAP 4 regression: the protocol keeps `outcome == Running` after
    // failure, cancellation, an unanswered question or a claimed completion
    // (until process exit). `advance_phase` must not accept IPC phase
    // boundaries in any of those states — a helper that already reported a
    // terminal condition cannot move the session into the Commit boundary.
    #[test]
    fn ipc_phase_rejected_after_failed_message() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"phase","phase":"ready"}"#)
            .unwrap();
        worker
            .receive_ipc_line(r#"{"type":"failed","text":"Disk full"}"#)
            .unwrap();
        assert!(
            worker
                .receive_ipc_line(r#"{"type":"phase","phase":"commit"}"#)
                .is_err()
        );
        assert_eq!(worker.phase(), UpdatePhase::Ready);
        worker.process_exited(1).unwrap();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn ipc_phase_rejected_after_cancellation() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker.receive_ipc_line(r#"{"type":"cancelled"}"#).unwrap();
        assert!(
            worker
                .receive_ipc_line(r#"{"type":"phase","phase":"ready"}"#)
                .is_err()
        );
        assert_eq!(worker.phase(), UpdatePhase::Prepare);
        worker.process_exited(2).unwrap();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Cancelled));
    }

    #[test]
    fn ipc_phase_rejected_while_question_pending() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"phase","phase":"ready"}"#)
            .unwrap();
        worker
            .receive_ipc_line(r#"{"type":"question","id":1,"text":"Proceed?"}"#)
            .unwrap();
        assert!(
            worker
                .receive_ipc_line(r#"{"type":"phase","phase":"commit"}"#)
                .is_err()
        );
        assert_eq!(worker.phase(), UpdatePhase::Ready);
        assert_eq!(worker.pending_question_id(), Some(1));
    }

    #[test]
    fn ipc_phase_rejected_after_claimed_completion() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"phase","phase":"ready"}"#)
            .unwrap();
        worker
            .receive_ipc_line(r#"{"type":"completed","exit_code":0}"#)
            .unwrap();
        assert!(
            worker
                .receive_ipc_line(r#"{"type":"phase","phase":"commit"}"#)
                .is_err()
        );
        assert_eq!(worker.phase(), UpdatePhase::Ready);
        worker.process_exited(0).unwrap();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Success));
    }

    // ETAP 4H-69 regression: an observed process exit must always produce a
    // verified terminal outcome, even when the helper died before `started`
    // or while a question was unanswered.
    #[test]
    fn worker_finalizes_failure_for_pre_start_exit() {
        let mut worker = TransactionWorker::new();
        worker.process_exited(1).unwrap();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Failure));
        assert_eq!(worker.phase(), UpdatePhase::Finished);
    }

    #[test]
    fn worker_finalizes_failure_for_exit_during_question() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"question","id":1,"text":"Proceed?"}"#)
            .unwrap();
        worker.process_exited(0).unwrap();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Failure));
        assert_eq!(worker.pending_question_id(), None);
        assert_eq!(worker.phase(), UpdatePhase::Finished);
    }

    #[test]
    fn worker_disconnect_clears_pending_question() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"question","id":1,"text":"Proceed?"}"#)
            .unwrap();
        worker.connection_lost();
        assert_eq!(worker.pending_question_id(), None);
        assert!(worker.answer_question(1, true).is_err());
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Failure));
    }

    // ETAP 4 IPC closure regression: a helper that sends a second question
    // while one is unanswered violates the one-question rule and must fail
    // closed, like an identifier mismatch.
    #[test]
    fn duplicate_ipc_question_fails_closed() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"question","id":1,"text":"First?"}"#)
            .unwrap();
        assert!(
            worker
                .receive_ipc_line(r#"{"type":"question","id":2,"text":"Second?"}"#)
                .is_err()
        );
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Failure));
        assert_eq!(worker.pending_question_id(), None);
        assert!(worker.answer_question(1, true).is_err());
    }

    #[test]
    fn denial_then_late_answer_stays_terminal_after_disconnect() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"question","id":1,"text":"Proceed?"}"#)
            .unwrap();
        worker.answer_question(1, false).unwrap();
        worker.connection_lost();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Failure));
        assert!(worker.answer_question(1, true).is_err());
    }

    // ETAP 4 IPC+HELPER closure: the full canonical helper session through
    // the IPC surface — every message kind, an approval and a denial, a
    // verified exit, and a disconnect, in protocol order.
    #[test]
    fn full_helper_session_covers_all_message_paths() {
        let mut worker = TransactionWorker::new();

        // Started -> Progress.
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"progress","text":"Downloading"}"#)
            .unwrap();

        // Question -> Answer (approved).
        worker
            .receive_ipc_line(r#"{"type":"question","id":1,"text":"Proceed?"}"#)
            .unwrap();
        worker.answer_question(1, true).unwrap();

        // Phase boundary, then Question -> Denial -> helper Cancelled.
        worker
            .receive_ipc_line(r#"{"type":"phase","phase":"ready"}"#)
            .unwrap();
        worker
            .receive_ipc_line(r#"{"type":"question","id":2,"text":"Commit?"}"#)
            .unwrap();
        worker.answer_question(2, false).unwrap();
        worker.receive_ipc_line(r#"{"type":"cancelled"}"#).unwrap();

        // Verified exit finalizes the cooperative cancellation.
        worker.process_exited(2).unwrap();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Cancelled));
        assert_eq!(worker.phase(), UpdatePhase::Finished);

        // Every later message path is closed.
        for line in [
            r#"{"type":"started"}"#,
            r#"{"type":"progress","text":"late"}"#,
            r#"{"type":"failed","text":"late"}"#,
            r#"{"type":"cancelled"}"#,
            r#"{"type":"completed","exit_code":0}"#,
        ] {
            assert!(worker.receive_ipc_line(line).is_err(), "accepted: {line}");
        }
        assert!(worker.answer_question(2, true).is_err());

        // A separate session: Failed path finalizes as Failure on exit.
        let mut failed = TransactionWorker::new();
        failed.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        failed
            .receive_ipc_line(r#"{"type":"failed","text":"Disk full"}"#)
            .unwrap();
        failed.process_exited(1).unwrap();
        assert_eq!(failed.outcome(), Some(TransactionOutcome::Failure));
    }
}
