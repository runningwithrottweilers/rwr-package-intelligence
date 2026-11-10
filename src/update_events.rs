use crate::update_progress::{UpdatePhase, UpdateProgress};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateEvent {
    DownloadProgress(u8),
    VerificationStarted,
    InstallationStarted,
    InstallationCompleted,
    Cancelled,
    Failed,
}

pub struct UpdateEventController {
    progress: UpdateProgress,
}

impl UpdateEventController {
    pub fn new() -> Self {
        Self {
            progress: UpdateProgress::new(),
        }
    }

    pub fn progress(&self) -> UpdateProgress {
        self.progress
    }

    pub fn apply(&mut self, event: UpdateEvent) -> Result<(), String> {
        match event {
            UpdateEvent::DownloadProgress(percent) => self.progress.set_download_progress(percent),
            UpdateEvent::VerificationStarted => self.progress.start_verification(),
            UpdateEvent::InstallationStarted => self.progress.start_installation(),
            UpdateEvent::Cancelled => self.progress.cancel(),
            UpdateEvent::InstallationCompleted => self.progress.complete(),
            UpdateEvent::Failed => {
                if self.progress.phase == UpdatePhase::Completed {
                    return Err("Completed update cannot fail".into());
                }
                self.progress.fail();
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_waiting() {
        let controller = UpdateEventController::new();
        assert_eq!(controller.progress().phase, UpdatePhase::Waiting);
    }

    #[test]
    fn accepts_download_progress() {
        let mut controller = UpdateEventController::new();
        controller.apply(UpdateEvent::DownloadProgress(45)).unwrap();
        assert_eq!(controller.progress().percent, 45);
    }

    #[test]
    fn rejects_decreasing_progress() {
        let mut controller = UpdateEventController::new();
        controller.apply(UpdateEvent::DownloadProgress(80)).unwrap();
        assert!(controller.apply(UpdateEvent::DownloadProgress(30)).is_err());
    }

    #[test]
    fn rejects_early_installation() {
        let mut controller = UpdateEventController::new();
        assert!(controller.apply(UpdateEvent::InstallationStarted).is_err());
    }

    #[test]
    fn completes_valid_sequence() {
        let mut controller = UpdateEventController::new();
        controller
            .apply(UpdateEvent::DownloadProgress(100))
            .unwrap();
        controller.apply(UpdateEvent::VerificationStarted).unwrap();
        controller.apply(UpdateEvent::InstallationStarted).unwrap();
        controller
            .apply(UpdateEvent::InstallationCompleted)
            .unwrap();
        assert_eq!(controller.progress().phase, UpdatePhase::Completed);
    }

    #[test]
    fn handles_failure() {
        let mut controller = UpdateEventController::new();
        controller.apply(UpdateEvent::Failed).unwrap();
        assert_eq!(controller.progress().phase, UpdatePhase::Failed);
    }

    #[test]
    fn rejects_failure_after_completion() {
        let mut controller = UpdateEventController::new();
        controller
            .apply(UpdateEvent::DownloadProgress(100))
            .unwrap();
        controller.apply(UpdateEvent::VerificationStarted).unwrap();
        controller.apply(UpdateEvent::InstallationStarted).unwrap();
        controller
            .apply(UpdateEvent::InstallationCompleted)
            .unwrap();
        assert!(controller.apply(UpdateEvent::Failed).is_err());
    }

    #[test]
    fn accepts_verification_stage() {
        let mut controller = UpdateEventController::new();
        controller
            .apply(UpdateEvent::DownloadProgress(100))
            .unwrap();
        controller.apply(UpdateEvent::VerificationStarted).unwrap();
        assert_eq!(controller.progress().phase, UpdatePhase::Verifying);
    }

    #[test]
    fn accepts_cancellation_before_installation() {
        let mut controller = UpdateEventController::new();
        controller.apply(UpdateEvent::DownloadProgress(30)).unwrap();
        controller.apply(UpdateEvent::Cancelled).unwrap();
        assert_eq!(controller.progress().phase, UpdatePhase::Cancelled);
        assert!(controller.apply(UpdateEvent::InstallationStarted).is_err());
    }
}
