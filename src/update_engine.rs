// RWR PACKAGE INTELLIGENCE
// Stage 16P-B: planning only.
// This module never executes commands.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePlan {
    pub program: String,
    pub arguments: Vec<String>,
    pub requires_authorization: bool,
}

impl UpdatePlan {
    pub fn arch_full_upgrade() -> Self {
        Self {
            program: "pacman".to_string(),
            arguments: vec!["-Syu".to_string()],
            requires_authorization: true,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.program != "pacman" {
            return Err("Unsupported update program".into());
        }

        if self.arguments.as_slice() != ["-Syu"] {
            return Err("Only full Arch Linux upgrades are permitted".into());
        }

        if !self.requires_authorization {
            return Err("Administrator authorization is required".into());
        }

        Ok(())
    }

    pub fn display_command(&self) -> String {
        format!("{} {}", self.program, self.arguments.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_full_upgrade_plan() {
        let plan = UpdatePlan::arch_full_upgrade();
        assert_eq!(plan.display_command(), "pacman -Syu");
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn requires_authorization() {
        let mut plan = UpdatePlan::arch_full_upgrade();
        plan.requires_authorization = false;
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_partial_upgrade() {
        let mut plan = UpdatePlan::arch_full_upgrade();
        plan.arguments = vec!["-Sy".into()];
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_forced_upgrade() {
        let mut plan = UpdatePlan::arch_full_upgrade();
        plan.arguments = vec!["-Syu".into(), "--noconfirm".into()];
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_other_programs() {
        let mut plan = UpdatePlan::arch_full_upgrade();
        plan.program = "sh".into();
        assert!(plan.validate().is_err());
    }
}
