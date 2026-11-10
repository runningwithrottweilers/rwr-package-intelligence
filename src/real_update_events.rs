// RWR PACKAGE INTELLIGENCE
// Production update event model.
// Data structures only — no process execution.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RealUpdateEvent {
    AuthorizationRequested,
    AuthorizationGranted,
    AuthorizationDenied,
    Started,
    Phase(crate::real_progress::UpgradeEvent),
    Question { id: u64, text: String },
    Finished { exit_code: i32 },
    Failed(String),
}

impl RealUpdateEvent {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::AuthorizationDenied | Self::Finished { .. } | Self::Failed(_)
        )
    }

    pub fn succeeded(&self) -> bool {
        matches!(self, Self::Finished { exit_code: 0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_requires_zero_exit_code() {
        assert!(RealUpdateEvent::Finished { exit_code: 0 }.succeeded());
        assert!(!RealUpdateEvent::Finished { exit_code: 1 }.succeeded());
    }

    #[test]
    fn progress_is_not_completion() {
        let event = RealUpdateEvent::Phase(crate::real_progress::UpgradeEvent::Downloading);
        assert!(!event.is_terminal());
        assert!(!event.succeeded());
    }

    #[test]
    fn authorization_denied_is_terminal() {
        assert!(RealUpdateEvent::AuthorizationDenied.is_terminal());
    }
}

impl RealUpdateEvent {
    pub fn from_pacman_line(line: &str) -> Self {
        Self::Phase(crate::real_progress::classify_line(line))
    }
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    #[test]
    fn maps_download_phase() {
        assert_eq!(
            RealUpdateEvent::from_pacman_line(":: Retrieving packages..."),
            RealUpdateEvent::Phase(crate::real_progress::UpgradeEvent::Downloading)
        );
    }

    #[test]
    fn maps_upgrade_phase() {
        assert_eq!(
            RealUpdateEvent::from_pacman_line("(1/3) upgrading linux"),
            RealUpdateEvent::Phase(crate::real_progress::UpgradeEvent::Upgrading)
        );
    }

    #[test]
    fn error_line_is_not_success() {
        let event = RealUpdateEvent::from_pacman_line("error: failed to commit transaction");
        assert!(!event.succeeded());
        assert!(!event.is_terminal());
    }
}
