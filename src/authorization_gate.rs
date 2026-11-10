// RWR PACKAGE INTELLIGENCE — ETAP 3F
// Authorization policy. No command execution.

use crate::update_engine::UpdatePlan;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationMode {
    Demo,
    Real,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationDecision {
    DemoAllowed,
    RealAllowed,
    Denied,
}

pub fn authorize(
    plan: &UpdatePlan,
    mode: AuthorizationMode,
    user_confirmed: bool,
) -> AuthorizationDecision {
    if plan.validate().is_err() || !user_confirmed {
        return AuthorizationDecision::Denied;
    }

    match mode {
        AuthorizationMode::Demo => AuthorizationDecision::DemoAllowed,
        AuthorizationMode::Real => AuthorizationDecision::Denied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_requires_confirmation() {
        let plan = UpdatePlan::arch_full_upgrade();
        assert_eq!(
            authorize(&plan, AuthorizationMode::Demo, false),
            AuthorizationDecision::Denied
        );
    }

    #[test]
    fn confirmed_demo_is_allowed() {
        let plan = UpdatePlan::arch_full_upgrade();
        assert_eq!(
            authorize(&plan, AuthorizationMode::Demo, true),
            AuthorizationDecision::DemoAllowed
        );
    }

    #[test]
    fn real_mode_requires_confirmation() {
        let plan = UpdatePlan::arch_full_upgrade();
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
    fn invalid_plan_is_denied() {
        let mut plan = UpdatePlan::arch_full_upgrade();
        plan.arguments.push("--noconfirm".into());
        assert_eq!(
            authorize(&plan, AuthorizationMode::Demo, true),
            AuthorizationDecision::Denied
        );
    }

    #[test]
    fn unauthorized_plan_is_denied() {
        let mut plan = UpdatePlan::arch_full_upgrade();
        plan.requires_authorization = false;
        assert_eq!(
            authorize(&plan, AuthorizationMode::Demo, true),
            AuthorizationDecision::Denied
        );
    }
}
