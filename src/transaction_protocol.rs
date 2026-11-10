//! Protocol for a future privileged update helper.
//! This module does not execute commands or request privileges.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionMessage {
    Started,
    Progress(String),
    Question(String),
    Completed { exit_code: i32 },
    Failed(String),
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionOutcome {
    Running,
    Success,
    Failure,
    Cancelled,
}

#[derive(Debug, Default)]
pub struct TransactionProtocol {
    started: bool,
    terminal: bool,
    awaiting_answer: bool,
    pending_question_id: Option<u64>,
    next_question_id: u64,
    claimed_exit_code: Option<i32>,
    cancellation_requested: bool,
    cancellation_reported: bool,
    failure_reported: bool,
    outcome: Option<TransactionOutcome>,
}

impl TransactionProtocol {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn outcome(&self) -> Option<TransactionOutcome> {
        self.outcome
    }

    /// Whether the protocol is in its normal running state and accepts
    /// ordinary transaction messages. False once the helper reported
    /// failure, cancellation, claimed completion, awaits an answer, or
    /// the protocol terminated. `outcome()` alone is not sufficient:
    /// it stays `Running` after `Failed`/`Cancelled`/`Completed` until
    /// the process exit is verified.
    pub fn is_active(&self) -> bool {
        self.started
            && !self.terminal
            && !self.awaiting_answer
            && self.claimed_exit_code.is_none()
            && !self.cancellation_requested
            && !self.failure_reported
    }

    pub fn receive(&mut self, message: TransactionMessage) -> Result<(), String> {
        if self.terminal {
            return Err("Transaction already terminated".into());
        }

        match message {
            TransactionMessage::Started => {
                if self.started || self.claimed_exit_code.is_some() {
                    return Err("Duplicate start event".into());
                }
                self.started = true;
                self.outcome = Some(TransactionOutcome::Running);
            }
            TransactionMessage::Progress(_) => {
                if !self.started
                    || self.awaiting_answer
                    || self.claimed_exit_code.is_some()
                    || self.cancellation_requested
                    || self.failure_reported
                {
                    return Err("Transaction not ready for progress".into());
                }
            }
            TransactionMessage::Question(_) => {
                if !self.started
                    || self.awaiting_answer
                    || self.claimed_exit_code.is_some()
                    || self.cancellation_requested
                    || self.failure_reported
                {
                    return Err("Transaction not ready for question".into());
                }
                self.awaiting_answer = true;
                self.next_question_id = self
                    .next_question_id
                    .checked_add(1)
                    .ok_or_else(|| "Question identifier overflow".to_string())?;
                self.pending_question_id = Some(self.next_question_id);
            }
            TransactionMessage::Completed { exit_code } => {
                if !self.started {
                    return Err("Transaction not started".into());
                }
                if self.cancellation_requested || self.failure_reported {
                    return Err("Completion after cancellation or failure".into());
                }
                if self.claimed_exit_code.is_some() {
                    return Err("Duplicate completion event".into());
                }
                if self.awaiting_answer {
                    return Err("Question remains unanswered".into());
                }
                self.claimed_exit_code = Some(exit_code);
            }
            TransactionMessage::Failed(_) => {
                if !self.started
                    || self.claimed_exit_code.is_some()
                    || self.cancellation_requested
                    || self.failure_reported
                {
                    return Err("Unexpected failure event".into());
                }
                self.failure_reported = true;
                self.awaiting_answer = false;
                self.pending_question_id = None;
            }
            TransactionMessage::Cancelled => {
                if !self.started
                    || self.claimed_exit_code.is_some()
                    || self.cancellation_reported
                    || self.failure_reported
                {
                    return Err("Unexpected cancellation event".into());
                }
                self.cancellation_requested = true;
                self.cancellation_reported = true;
                self.awaiting_answer = false;
                self.pending_question_id = None;
            }
        }

        Ok(())
    }

    pub fn pending_question_id(&self) -> Option<u64> {
        self.pending_question_id
    }

    pub fn answer_question_with_id(
        &mut self,
        question_id: u64,
        approved: bool,
    ) -> Result<(), String> {
        if self.terminal || !self.awaiting_answer {
            return Err("No pending question".into());
        }
        if self.pending_question_id != Some(question_id) {
            return Err("Question identifier mismatch".into());
        }
        self.awaiting_answer = false;
        self.pending_question_id = None;
        if !approved {
            self.cancellation_requested = true;
        }
        Ok(())
    }

    pub fn answer_question(&mut self, approved: bool) -> Result<(), String> {
        let id = self
            .pending_question_id
            .ok_or_else(|| "No pending question".to_string())?;
        self.answer_question_with_id(id, approved)
    }

    pub fn verify_process_exit(&mut self, exit_code: i32) -> Result<(), String> {
        if self.terminal {
            return Err("Transaction already terminated".into());
        }
        // An observed process exit is final even when the helper died
        // before `started` or with an unanswered question: neither state
        // can ever be a success, so the exit finalizes as Failure instead
        // of leaving the protocol without a verified outcome. The pending
        // question, if any, can never be answered after exit.
        self.terminal = true;
        self.awaiting_answer = false;
        self.pending_question_id = None;
        self.outcome = Some(
            if self.cancellation_requested && self.cancellation_reported && exit_code == 2 {
                TransactionOutcome::Cancelled
            } else if !self.cancellation_requested
                && !self.failure_reported
                && exit_code == 0
                && self.claimed_exit_code == Some(0)
            {
                TransactionOutcome::Success
            } else {
                TransactionOutcome::Failure
            },
        );
        Ok(())
    }

    pub fn disconnected(&mut self) {
        if !self.terminal {
            self.terminal = true;
            // A lost connection invalidates any pending question, mirroring
            // the Failed and Cancelled finalization paths.
            self.awaiting_answer = false;
            self.pending_question_id = None;
            self.outcome = Some(TransactionOutcome::Failure);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_transaction_requires_explicit_completion() {
        let mut protocol = TransactionProtocol::new();
        protocol.receive(TransactionMessage::Started).unwrap();
        protocol
            .receive(TransactionMessage::Progress("Downloading".into()))
            .unwrap();
        assert_eq!(protocol.outcome(), Some(TransactionOutcome::Running));
        protocol
            .receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        assert_eq!(protocol.outcome(), Some(TransactionOutcome::Running));
        protocol.verify_process_exit(0).unwrap();
        assert_eq!(protocol.outcome(), Some(TransactionOutcome::Success));
    }

    #[test]
    fn nonzero_exit_is_failure() {
        let mut protocol = TransactionProtocol::new();
        protocol.receive(TransactionMessage::Started).unwrap();
        protocol
            .receive(TransactionMessage::Completed { exit_code: 1 })
            .unwrap();
        assert_eq!(protocol.outcome(), Some(TransactionOutcome::Running));
        protocol.verify_process_exit(1).unwrap();
        assert_eq!(protocol.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn disconnect_is_not_success() {
        let mut protocol = TransactionProtocol::new();
        protocol.receive(TransactionMessage::Started).unwrap();
        protocol.disconnected();
        assert_eq!(protocol.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn cannot_complete_before_start() {
        let mut protocol = TransactionProtocol::new();
        assert!(
            protocol
                .receive(TransactionMessage::Completed { exit_code: 0 })
                .is_err()
        );
    }

    #[test]
    fn cannot_complete_twice() {
        let mut protocol = TransactionProtocol::new();
        protocol.receive(TransactionMessage::Started).unwrap();
        protocol
            .receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        assert!(
            protocol
                .receive(TransactionMessage::Completed { exit_code: 0 })
                .is_err()
        );
    }

    #[test]
    fn cancellation_is_terminal() {
        let mut protocol = TransactionProtocol::new();
        protocol.receive(TransactionMessage::Started).unwrap();
        protocol.receive(TransactionMessage::Cancelled).unwrap();
        assert_eq!(protocol.outcome(), Some(TransactionOutcome::Running));
        protocol.verify_process_exit(2).unwrap();
        assert_eq!(protocol.outcome(), Some(TransactionOutcome::Cancelled));
        assert!(
            protocol
                .receive(TransactionMessage::Progress("late".into()))
                .is_err()
        );
    }

    #[test]
    fn questions_require_running_transaction() {
        let mut protocol = TransactionProtocol::new();
        assert!(
            protocol
                .receive(TransactionMessage::Question("Proceed?".into()))
                .is_err()
        );
        protocol.receive(TransactionMessage::Started).unwrap();
        assert!(
            protocol
                .receive(TransactionMessage::Question("Proceed?".into()))
                .is_ok()
        );
    }

    #[test]
    fn is_active_tracks_protocol_lifecycle() {
        let mut p = TransactionProtocol::new();
        assert!(!p.is_active(), "not started yet");

        p.receive(TransactionMessage::Started).unwrap();
        assert!(p.is_active(), "running");

        p.receive(TransactionMessage::Question("Proceed?".into()))
            .unwrap();
        assert!(!p.is_active(), "question awaits an answer");

        p.answer_question(true).unwrap();
        assert!(p.is_active(), "answer resumed the transaction");

        p.receive(TransactionMessage::Failed("Error".into()))
            .unwrap();
        assert!(!p.is_active(), "failure was reported");
    }

    #[test]
    fn process_exit_before_start_finalizes_failure() {
        let mut p = TransactionProtocol::new();
        p.verify_process_exit(1).unwrap();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Failure));
        assert!(p.receive(TransactionMessage::Started).is_err());
    }

    #[test]
    fn process_exit_during_pending_question_finalizes_failure() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Question("Proceed?".into()))
            .unwrap();
        p.verify_process_exit(0).unwrap();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn disconnect_clears_pending_question() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Question("Proceed?".into()))
            .unwrap();
        p.disconnected();
        assert_eq!(p.pending_question_id(), None);
        assert!(p.answer_question(true).is_err());
        assert_eq!(p.outcome(), Some(TransactionOutcome::Failure));
    }
}

#[cfg(test)]
mod verification_tests {
    use super::*;

    #[test]
    fn helper_success_without_process_verification_is_not_success() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Running));
    }

    #[test]
    fn process_failure_overrides_helper_success() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        p.verify_process_exit(1).unwrap();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn process_success_without_helper_completion_is_failure() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.verify_process_exit(0).unwrap();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn rejected_question_cancels_transaction() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Question("Continue?".into()))
            .unwrap();
        p.answer_question(false).unwrap();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Running));
        p.receive(TransactionMessage::Cancelled).unwrap();
        p.verify_process_exit(2).unwrap();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Cancelled));
    }

    #[test]
    fn duplicate_question_is_rejected() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Question("First?".into()))
            .unwrap();
        assert!(
            p.receive(TransactionMessage::Question("Second?".into()))
                .is_err()
        );
    }

    #[test]
    fn disconnect_after_claimed_success_is_failure() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        p.disconnected();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Failure));
    }
}

#[cfg(test)]
mod completion_guard_tests {
    use super::*;

    #[test]
    fn progress_after_claimed_completion_is_rejected() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        assert!(
            p.receive(TransactionMessage::Progress("late".into()))
                .is_err()
        );
    }

    #[test]
    fn question_after_claimed_completion_is_rejected() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        assert!(
            p.receive(TransactionMessage::Question("late".into()))
                .is_err()
        );
    }

    #[test]
    fn verified_completion_is_terminal() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        p.verify_process_exit(0).unwrap();

        assert_eq!(p.outcome(), Some(TransactionOutcome::Success));
        assert!(p.receive(TransactionMessage::Started).is_err());
        assert!(p.verify_process_exit(0).is_err());
    }
}

#[cfg(test)]
mod question_identity_tests {
    use super::*;

    #[test]
    fn question_receives_identifier() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Question("Continue?".into()))
            .unwrap();
        assert_eq!(p.pending_question_id(), Some(1));
    }

    #[test]
    fn wrong_question_identifier_is_rejected() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Question("Continue?".into()))
            .unwrap();
        assert!(p.answer_question_with_id(999, true).is_err());
        assert_eq!(p.pending_question_id(), Some(1));
    }

    #[test]
    fn correct_identifier_resumes_transaction() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Question("Continue?".into()))
            .unwrap();
        p.answer_question_with_id(1, true).unwrap();
        assert_eq!(p.pending_question_id(), None);
        assert!(
            p.receive(TransactionMessage::Progress("resumed".into()))
                .is_ok()
        );
    }

    #[test]
    fn stale_question_identifier_is_rejected() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Question("First?".into()))
            .unwrap();
        p.answer_question_with_id(1, true).unwrap();
        p.receive(TransactionMessage::Question("Second?".into()))
            .unwrap();
        assert_eq!(p.pending_question_id(), Some(2));
        assert!(p.answer_question_with_id(1, true).is_err());
    }

    #[test]
    fn new_start_after_claimed_completion_is_rejected() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        assert!(p.receive(TransactionMessage::Started).is_err());
    }
}

#[cfg(test)]
mod cancellation_safety_tests {
    use super::*;

    #[test]
    fn rejection_blocks_progress_question_and_completion() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Question("Proceed?".into()))
            .unwrap();
        p.answer_question(false).unwrap();

        assert!(
            p.receive(TransactionMessage::Progress("late".into()))
                .is_err()
        );
        assert!(
            p.receive(TransactionMessage::Question("late".into()))
                .is_err()
        );
        assert!(
            p.receive(TransactionMessage::Completed { exit_code: 0 })
                .is_err()
        );
        assert_eq!(p.outcome(), Some(TransactionOutcome::Running));
    }

    #[test]
    fn cancellation_requires_report_and_exit_two() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Cancelled).unwrap();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Running));
        p.verify_process_exit(2).unwrap();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Cancelled));
    }

    #[test]
    fn cancellation_with_wrong_exit_code_fails() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Cancelled).unwrap();
        p.verify_process_exit(0).unwrap();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn cancellation_disconnect_fails_closed() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Cancelled).unwrap();
        p.disconnected();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn cancellation_blocks_late_progress() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Cancelled).unwrap();
        assert!(
            p.receive(TransactionMessage::Progress("late".into()))
                .is_err()
        );
    }
}

#[cfg(test)]
mod failure_finalization_tests {
    use super::*;

    #[test]
    fn failed_message_waits_for_process_exit() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Failed("Error".into()))
            .unwrap();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Running));
        p.verify_process_exit(1).unwrap();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn failed_message_cannot_become_success() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Failed("Error".into()))
            .unwrap();
        p.verify_process_exit(0).unwrap();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn nonzero_completion_waits_for_process_exit() {
        let mut p = TransactionProtocol::new();
        p.receive(TransactionMessage::Started).unwrap();
        p.receive(TransactionMessage::Completed { exit_code: 1 })
            .unwrap();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Running));
        p.verify_process_exit(1).unwrap();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn failure_before_start_is_rejected() {
        let mut p = TransactionProtocol::new();
        assert!(
            p.receive(TransactionMessage::Failed("Error".into()))
                .is_err()
        );
    }
}

#[cfg(test)]
mod stage_2_2_failure_guards {
    use super::*;

    fn failed_protocol() -> TransactionProtocol {
        let mut protocol = TransactionProtocol::new();
        protocol.receive(TransactionMessage::Started).unwrap();
        protocol
            .receive(TransactionMessage::Failed("Test failure".into()))
            .unwrap();
        protocol
    }

    #[test]
    fn rejects_progress_after_failure() {
        let mut p = failed_protocol();
        assert!(
            p.receive(TransactionMessage::Progress("Late".into()))
                .is_err()
        );
    }

    #[test]
    fn rejects_question_after_failure() {
        let mut p = failed_protocol();
        assert!(
            p.receive(TransactionMessage::Question("Late?".into()))
                .is_err()
        );
    }

    #[test]
    fn rejects_completion_after_failure() {
        let mut p = failed_protocol();
        assert!(
            p.receive(TransactionMessage::Completed { exit_code: 0 })
                .is_err()
        );
    }

    #[test]
    fn rejects_cancellation_after_failure() {
        let mut p = failed_protocol();
        assert!(p.receive(TransactionMessage::Cancelled).is_err());
    }

    #[test]
    fn failure_requires_process_exit() {
        let mut p = failed_protocol();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Running));
        p.verify_process_exit(1).unwrap();
        assert_eq!(p.outcome(), Some(TransactionOutcome::Failure));
    }
}
