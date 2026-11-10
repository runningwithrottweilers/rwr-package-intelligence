// RWR PACKAGE INTELLIGENCE
// Real update preflight: validation only.
// No command execution.

use crate::update_engine::UpdatePlan;
use crate::update_launcher::LaunchSpec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightApproval {
    pub plan: UpdatePlan,
    pub launch: LaunchSpec,
}

pub fn prepare_real_update(
    plan: &UpdatePlan,
    user_confirmed: bool,
) -> Result<PreflightApproval, String> {
    if !user_confirmed {
        return Err("Explicit user confirmation required".into());
    }

    plan.validate()?;

    let launch = LaunchSpec::arch_upgrade();
    launch.validate()?;

    Ok(PreflightApproval {
        plan: plan.clone(),
        launch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_preflight_does_not_authorize_real_execution() {
        use crate::authorization_gate::{AuthorizationDecision, AuthorizationMode, authorize};

        let plan = UpdatePlan::arch_full_upgrade();

        assert!(prepare_real_update(&plan, true).is_ok());

        assert_eq!(
            authorize(&plan, AuthorizationMode::Real, false),
            AuthorizationDecision::Denied
        );
        assert_eq!(
            authorize(&plan, AuthorizationMode::Real, true),
            AuthorizationDecision::Denied
        );
    }

    #[test]
    fn rejects_missing_confirmation() {
        let plan = UpdatePlan::arch_full_upgrade();
        assert!(prepare_real_update(&plan, false).is_err());
    }

    #[test]
    fn accepts_valid_plan_as_data_only() {
        let plan = UpdatePlan::arch_full_upgrade();
        let approval = prepare_real_update(&plan, true).unwrap();
        assert_eq!(approval.launch.program, "/usr/bin/pkexec");
        assert_eq!(approval.launch.arguments, ["/usr/bin/pacman", "-Syu"]);
    }

    #[test]
    fn rejects_partial_upgrade() {
        let mut plan = UpdatePlan::arch_full_upgrade();
        plan.arguments = vec!["-Sy".into()];
        assert!(prepare_real_update(&plan, true).is_err());
    }

    #[test]
    fn rejects_unattended_upgrade() {
        let mut plan = UpdatePlan::arch_full_upgrade();
        plan.arguments.push("--noconfirm".into());
        assert!(prepare_real_update(&plan, true).is_err());
    }
}
