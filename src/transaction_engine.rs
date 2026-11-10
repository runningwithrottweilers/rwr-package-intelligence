// RWR PACKAGE INTELLIGENCE — ETAP 4C
// Transaction decision layer. No process execution.

use crate::authorization_gate::{AuthorizationDecision, AuthorizationMode, authorize};
use crate::update_engine::UpdatePlan;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionMode {
    Demo,
    Real,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionDecision {
    StartDemo,
    Denied,
}

pub fn prepare_transaction(
    plan: &UpdatePlan,
    mode: TransactionMode,
    confirmed: bool,
) -> TransactionDecision {
    let auth_mode = match mode {
        TransactionMode::Demo => AuthorizationMode::Demo,
        TransactionMode::Real => AuthorizationMode::Real,
    };

    match authorize(plan, auth_mode, confirmed) {
        AuthorizationDecision::DemoAllowed => TransactionDecision::StartDemo,
        AuthorizationDecision::RealAllowed => TransactionDecision::Denied,
        AuthorizationDecision::Denied => TransactionDecision::Denied,
    }
}

// ETAP 4G — Isolated DEMO transaction controller.
// No process execution. REAL MODE remains denied.

use crate::transaction_state::{TransactionEvent, TransactionMachine, TransactionState};

#[derive(Debug)]
pub struct DemoTransactionController {
    machine: TransactionMachine,
}

impl DemoTransactionController {
    pub fn new() -> Self {
        Self {
            machine: TransactionMachine::new(),
        }
    }

    pub fn state(&self) -> TransactionState {
        self.machine.state()
    }

    pub fn begin(
        &mut self,
        plan: &UpdatePlan,
        mode: TransactionMode,
        confirmed: bool,
    ) -> Result<TransactionDecision, String> {
        if self.machine.state() != TransactionState::Idle {
            return Err("Transaction is not idle".into());
        }

        self.machine.apply(TransactionEvent::RequestAuthorization)?;

        let decision = prepare_transaction(plan, mode, confirmed);

        match decision {
            TransactionDecision::StartDemo if mode == TransactionMode::Demo => {
                self.machine.apply(TransactionEvent::AuthorizationGranted)?;
                Ok(TransactionDecision::StartDemo)
            }
            _ => {
                self.machine.apply(TransactionEvent::AuthorizationDenied)?;
                Ok(TransactionDecision::Denied)
            }
        }
    }

    pub fn complete(&mut self) -> Result<TransactionState, String> {
        self.machine.apply(TransactionEvent::Complete)
    }

    pub fn cancel(&mut self) -> Result<TransactionState, String> {
        self.machine.apply(TransactionEvent::Cancel)
    }

    pub fn fail(&mut self) -> Result<TransactionState, String> {
        self.machine.apply(TransactionEvent::Fail)
    }

    pub fn reset(&mut self) -> Result<TransactionState, String> {
        self.machine.apply(TransactionEvent::Reset)
    }
}

#[cfg(test)]
mod integration_4g_tests {
    use super::*;

    fn plan() -> UpdatePlan {
        UpdatePlan::arch_full_upgrade()
    }

    #[test]
    fn demo_authorization_starts_running() {
        let mut c = DemoTransactionController::new();
        assert_eq!(
            c.begin(&plan(), TransactionMode::Demo, true),
            Ok(TransactionDecision::StartDemo)
        );
        assert_eq!(c.state(), TransactionState::Running);
    }

    #[test]
    fn denied_authorization_cancels() {
        let mut c = DemoTransactionController::new();
        assert_eq!(
            c.begin(&plan(), TransactionMode::Demo, false),
            Ok(TransactionDecision::Denied)
        );
        assert_eq!(c.state(), TransactionState::Cancelled);
    }

    #[test]
    fn real_mode_always_denied() {
        for confirmed in [false, true] {
            let mut c = DemoTransactionController::new();
            assert_eq!(
                c.begin(&plan(), TransactionMode::Real, confirmed),
                Ok(TransactionDecision::Denied)
            );
            assert_eq!(c.state(), TransactionState::Cancelled);
        }
    }

    #[test]
    fn concurrent_start_is_blocked() {
        let mut c = DemoTransactionController::new();
        c.begin(&plan(), TransactionMode::Demo, true).unwrap();
        assert!(c.begin(&plan(), TransactionMode::Demo, true).is_err());
        assert_eq!(c.state(), TransactionState::Running);
    }

    #[test]
    fn complete_and_reset() {
        let mut c = DemoTransactionController::new();
        assert!(c.complete().is_err());
        c.begin(&plan(), TransactionMode::Demo, true).unwrap();
        assert_eq!(c.complete(), Ok(TransactionState::Completed));
        assert_eq!(c.reset(), Ok(TransactionState::Idle));
    }

    #[test]
    fn cancel_failure_and_invalid_plan() {
        let mut c = DemoTransactionController::new();
        c.begin(&plan(), TransactionMode::Demo, true).unwrap();
        assert_eq!(c.cancel(), Ok(TransactionState::Cancelled));
        c.reset().unwrap();

        c.begin(&plan(), TransactionMode::Demo, true).unwrap();
        assert_eq!(c.fail(), Ok(TransactionState::Failed));
        c.reset().unwrap();

        let mut invalid = plan();
        invalid.arguments.push("--noconfirm".into());
        assert_eq!(
            c.begin(&invalid, TransactionMode::Demo, true),
            Ok(TransactionDecision::Denied)
        );
        assert_eq!(c.state(), TransactionState::Cancelled);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmed_demo_is_allowed() {
        let plan = UpdatePlan::arch_full_upgrade();
        assert_eq!(
            prepare_transaction(&plan, TransactionMode::Demo, true),
            TransactionDecision::StartDemo
        );
    }

    #[test]
    fn unconfirmed_demo_is_denied() {
        let plan = UpdatePlan::arch_full_upgrade();
        assert_eq!(
            prepare_transaction(&plan, TransactionMode::Demo, false),
            TransactionDecision::Denied
        );
    }

    #[test]
    fn real_mode_is_always_denied() {
        let plan = UpdatePlan::arch_full_upgrade();

        for confirmed in [false, true] {
            assert_eq!(
                prepare_transaction(&plan, TransactionMode::Real, confirmed),
                TransactionDecision::Denied
            );
        }
    }

    #[test]
    fn invalid_plan_is_denied() {
        let mut plan = UpdatePlan::arch_full_upgrade();
        plan.arguments.push("--noconfirm".into());

        assert_eq!(
            prepare_transaction(&plan, TransactionMode::Demo, true),
            TransactionDecision::Denied
        );
    }

    #[test]
    fn missing_authorization_requirement_is_denied() {
        let mut plan = UpdatePlan::arch_full_upgrade();
        plan.requires_authorization = false;

        assert_eq!(
            prepare_transaction(&plan, TransactionMode::Demo, true),
            TransactionDecision::Denied
        );
    }
}

#[cfg(test)]
mod integration_4g8_tests {
    use super::*;

    fn plan() -> UpdatePlan {
        UpdatePlan::arch_full_upgrade()
    }

    #[test]
    fn cannot_restart_running_transaction() {
        let mut c = DemoTransactionController::new();
        c.begin(&plan(), TransactionMode::Demo, true).unwrap();
        assert!(c.begin(&plan(), TransactionMode::Demo, true).is_err());
        assert_eq!(c.state(), TransactionState::Running);
    }

    #[test]
    fn completed_transaction_requires_reset() {
        let mut c = DemoTransactionController::new();
        c.begin(&plan(), TransactionMode::Demo, true).unwrap();
        c.complete().unwrap();

        assert!(c.begin(&plan(), TransactionMode::Demo, true).is_err());
        assert_eq!(c.state(), TransactionState::Completed);
    }

    #[test]
    fn denied_transaction_cannot_complete() {
        let mut c = DemoTransactionController::new();
        c.begin(&plan(), TransactionMode::Demo, false).unwrap();

        assert!(c.complete().is_err());
        assert_eq!(c.state(), TransactionState::Cancelled);
    }

    #[test]
    fn failed_transaction_can_reset_and_restart() {
        let mut c = DemoTransactionController::new();
        c.begin(&plan(), TransactionMode::Demo, true).unwrap();
        c.fail().unwrap();

        assert!(c.begin(&plan(), TransactionMode::Demo, true).is_err());

        c.reset().unwrap();

        assert_eq!(
            c.begin(&plan(), TransactionMode::Demo, true),
            Ok(TransactionDecision::StartDemo)
        );
    }

    #[test]
    fn real_mode_denial_cannot_be_bypassed() {
        let mut c = DemoTransactionController::new();

        assert_eq!(
            c.begin(&plan(), TransactionMode::Real, true),
            Ok(TransactionDecision::Denied)
        );

        assert_eq!(c.state(), TransactionState::Cancelled);

        assert!(c.begin(&plan(), TransactionMode::Demo, true).is_err());

        c.reset().unwrap();

        assert_eq!(
            c.begin(&plan(), TransactionMode::Real, true),
            Ok(TransactionDecision::Denied)
        );

        assert_eq!(c.state(), TransactionState::Cancelled);
    }
}
