// RWR PACKAGE INTELLIGENCE
// Stage 16P-K9: process result interpretation only.
// Does not execute commands.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateResult {
    Success,
    Failed(i32),
    Terminated,
    Unknown,
}

impl UpdateResult {
    pub fn from_exit_code(code: Option<i32>) -> Self {
        match code {
            Some(0) => Self::Success,
            Some(value) => Self::Failed(value),
            None => Self::Terminated,
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_success() {
        assert_eq!(UpdateResult::from_exit_code(Some(0)), UpdateResult::Success);
    }

    #[test]
    fn detects_failure() {
        assert_eq!(
            UpdateResult::from_exit_code(Some(1)),
            UpdateResult::Failed(1)
        );
    }

    #[test]
    fn detects_signal_termination() {
        assert_eq!(UpdateResult::from_exit_code(None), UpdateResult::Terminated);
    }

    #[test]
    fn success_flag_is_strict() {
        assert!(UpdateResult::Success.is_success());
        assert!(!UpdateResult::Failed(1).is_success());
        assert!(!UpdateResult::Unknown.is_success());
    }
}
