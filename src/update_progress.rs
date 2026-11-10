#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatePhase {
    Waiting,
    Downloading,
    Verifying,
    Installing,
    Cancelled,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateProgress {
    pub phase: UpdatePhase,
    pub percent: u8,
}

impl UpdateProgress {
    pub fn new() -> Self {
        Self {
            phase: UpdatePhase::Waiting,
            percent: 0,
        }
    }

    pub fn set_download_progress(&mut self, percent: u8) -> Result<(), String> {
        if percent > 100 {
            return Err("Download progress exceeds 100%".into());
        }

        if !matches!(self.phase, UpdatePhase::Waiting | UpdatePhase::Downloading) {
            return Err("Download progress cannot be changed in this phase".into());
        }

        if self.phase == UpdatePhase::Downloading && percent < self.percent {
            return Err("Download progress cannot decrease".into());
        }

        self.phase = UpdatePhase::Downloading;
        self.percent = percent;
        Ok(())
    }

    pub fn start_verification(&mut self) -> Result<(), String> {
        if self.phase != UpdatePhase::Downloading || self.percent != 100 {
            return Err("Download must finish before verification".into());
        }
        self.phase = UpdatePhase::Verifying;
        Ok(())
    }

    pub fn cancel(&mut self) -> Result<(), String> {
        if !matches!(
            self.phase,
            UpdatePhase::Waiting | UpdatePhase::Downloading | UpdatePhase::Verifying
        ) {
            return Err("Cannot cancel after installation has started".into());
        }
        self.phase = UpdatePhase::Cancelled;
        Ok(())
    }

    pub fn start_installation(&mut self) -> Result<(), String> {
        if self.phase != UpdatePhase::Verifying || self.percent != 100 {
            return Err("Download must finish before installation".into());
        }

        self.phase = UpdatePhase::Installing;
        Ok(())
    }

    pub fn complete(&mut self) -> Result<(), String> {
        if self.phase != UpdatePhase::Installing {
            return Err("Installation has not started".into());
        }

        self.phase = UpdatePhase::Completed;
        Ok(())
    }

    pub fn fail(&mut self) {
        if self.phase != UpdatePhase::Completed {
            self.phase = UpdatePhase::Failed;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_waiting() {
        let progress = UpdateProgress::new();
        assert_eq!(progress.phase, UpdatePhase::Waiting);
        assert_eq!(progress.percent, 0);
    }

    #[test]
    fn tracks_download() {
        let mut progress = UpdateProgress::new();
        progress.set_download_progress(40).unwrap();
        assert_eq!(progress.phase, UpdatePhase::Downloading);
        assert_eq!(progress.percent, 40);
    }

    #[test]
    fn rejects_invalid_percentage() {
        let mut progress = UpdateProgress::new();
        assert!(progress.set_download_progress(101).is_err());
    }

    #[test]
    fn rejects_decreasing_progress() {
        let mut progress = UpdateProgress::new();
        progress.set_download_progress(60).unwrap();
        assert!(progress.set_download_progress(30).is_err());
    }

    #[test]
    fn requires_finished_download() {
        let mut progress = UpdateProgress::new();
        progress.set_download_progress(50).unwrap();
        assert!(progress.start_installation().is_err());
    }

    #[test]
    fn completes_valid_sequence() {
        let mut progress = UpdateProgress::new();
        progress.set_download_progress(100).unwrap();
        progress.start_verification().unwrap();
        progress.start_installation().unwrap();
        progress.complete().unwrap();
        assert_eq!(progress.phase, UpdatePhase::Completed);
    }

    #[test]
    fn records_failure() {
        let mut progress = UpdateProgress::new();
        progress.fail();
        assert_eq!(progress.phase, UpdatePhase::Failed);
    }

    #[test]
    fn verification_requires_completed_download() {
        let mut progress = UpdateProgress::new();
        progress.set_download_progress(50).unwrap();
        assert!(progress.start_verification().is_err());
    }

    #[test]
    fn cancellation_before_installation() {
        let mut progress = UpdateProgress::new();
        progress.set_download_progress(40).unwrap();
        progress.cancel().unwrap();
        assert_eq!(progress.phase, UpdatePhase::Cancelled);
        assert!(progress.set_download_progress(60).is_err());
    }

    #[test]
    fn rejects_cancel_after_installation() {
        let mut progress = UpdateProgress::new();
        progress.set_download_progress(100).unwrap();
        progress.start_verification().unwrap();
        progress.start_installation().unwrap();
        assert!(progress.cancel().is_err());
    }
}
