// RWR PACKAGE INTELLIGENCE — ETAP 4F
// Pure transaction state machine. No process execution.

/// Safety boundary for a future privileged transaction.
/// `Commit` is irreversible from the GUI's perspective: disconnect is not
/// permission to terminate the helper while package files may be changing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatePhase {
    Prepare,
    Ready,
    Commit,
    Finished,
}

impl UpdatePhase {
    /// Whether a supervisor may request cooperative cancellation.
    /// This never authorizes killing a process or executing a transaction.
    pub fn allows_cancel_request(self) -> bool {
        matches!(self, Self::Prepare | Self::Ready)
    }

    /// A lost GUI must not be interpreted as transaction completion.
    pub fn requires_supervision_after_disconnect(self) -> bool {
        matches!(self, Self::Commit)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    Idle,
    Authorizing,
    Running,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionEvent {
    RequestAuthorization,
    AuthorizationGranted,
    AuthorizationDenied,
    Complete,
    Cancel,
    Fail,
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionMachine {
    state: TransactionState,
}

impl TransactionMachine {
    pub fn new() -> Self {
        Self {
            state: TransactionState::Idle,
        }
    }

    pub fn state(&self) -> TransactionState {
        self.state
    }

    pub fn apply(&mut self, event: TransactionEvent) -> Result<TransactionState, String> {
        use TransactionEvent::*;
        use TransactionState::*;

        let next = match (self.state, event) {
            (Idle, RequestAuthorization) => Authorizing,
            (Authorizing, AuthorizationGranted) => Running,
            (Authorizing, AuthorizationDenied) => Cancelled,
            (Running, Complete) => Completed,
            (Running, Cancel) => Cancelled,
            (Running, Fail) => Failed,
            (Authorizing, Cancel) => Cancelled,
            (Completed | Cancelled | Failed, Reset) => Idle,
            _ => {
                return Err(format!(
                    "Invalid transition: {:?} + {:?}",
                    self.state, event
                ));
            }
        };

        self.state = next;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_is_only_requestable_before_commit() {
        assert!(UpdatePhase::Prepare.allows_cancel_request());
        assert!(UpdatePhase::Ready.allows_cancel_request());
        assert!(!UpdatePhase::Commit.allows_cancel_request());
        assert!(!UpdatePhase::Finished.allows_cancel_request());
    }

    #[test]
    fn commit_requires_supervision_after_gui_disconnect() {
        assert!(!UpdatePhase::Prepare.requires_supervision_after_disconnect());
        assert!(!UpdatePhase::Ready.requires_supervision_after_disconnect());
        assert!(UpdatePhase::Commit.requires_supervision_after_disconnect());
        assert!(!UpdatePhase::Finished.requires_supervision_after_disconnect());
    }

    #[test]
    fn starts_idle() {
        assert_eq!(TransactionMachine::new().state(), TransactionState::Idle);
    }

    #[test]
    fn valid_demo_flow() {
        let mut m = TransactionMachine::new();
        assert_eq!(
            m.apply(TransactionEvent::RequestAuthorization),
            Ok(TransactionState::Authorizing)
        );
        assert_eq!(
            m.apply(TransactionEvent::AuthorizationGranted),
            Ok(TransactionState::Running)
        );
        assert_eq!(
            m.apply(TransactionEvent::Complete),
            Ok(TransactionState::Completed)
        );
    }

    #[test]
    fn cannot_run_without_authorization() {
        let mut m = TransactionMachine::new();
        assert!(m.apply(TransactionEvent::AuthorizationGranted).is_err());
        assert_eq!(m.state(), TransactionState::Idle);
    }

    #[test]
    fn denied_authorization_cancels() {
        let mut m = TransactionMachine::new();
        m.apply(TransactionEvent::RequestAuthorization).unwrap();
        assert_eq!(
            m.apply(TransactionEvent::AuthorizationDenied),
            Ok(TransactionState::Cancelled)
        );
    }

    #[test]
    fn cannot_start_twice() {
        let mut m = TransactionMachine::new();
        m.apply(TransactionEvent::RequestAuthorization).unwrap();
        m.apply(TransactionEvent::AuthorizationGranted).unwrap();
        assert!(m.apply(TransactionEvent::RequestAuthorization).is_err());
    }

    #[test]
    fn failure_and_reset() {
        let mut m = TransactionMachine::new();
        m.apply(TransactionEvent::RequestAuthorization).unwrap();
        m.apply(TransactionEvent::AuthorizationGranted).unwrap();
        assert_eq!(
            m.apply(TransactionEvent::Fail),
            Ok(TransactionState::Failed)
        );
        assert_eq!(m.apply(TransactionEvent::Reset), Ok(TransactionState::Idle));
    }

    #[test]
    fn cancellation_and_reset() {
        let mut m = TransactionMachine::new();
        m.apply(TransactionEvent::RequestAuthorization).unwrap();
        assert_eq!(
            m.apply(TransactionEvent::Cancel),
            Ok(TransactionState::Cancelled)
        );
        assert_eq!(m.apply(TransactionEvent::Reset), Ok(TransactionState::Idle));
    }
}
