// RWR PACKAGE INTELLIGENCE — K35-B14 FIX
// Strict event stream, TEST MODE.
// No process execution.

use crate::update_event_parser::apply_event;
use crate::update_events::UpdateEventController;
use crate::update_progress::{UpdatePhase, UpdateProgress};

pub struct UpdateEventStream {
    controller: UpdateEventController,
    rejected: bool,
}

impl UpdateEventStream {
    pub fn new() -> Self {
        Self {
            controller: UpdateEventController::new(),
            rejected: false,
        }
    }

    pub fn progress(&self) -> UpdateProgress {
        self.controller.progress()
    }

    pub fn is_rejected(&self) -> bool {
        self.rejected
    }

    pub fn push(&mut self, line: &str) -> Result<UpdateProgress, String> {
        if self.rejected {
            return Err("Event stream already rejected".into());
        }

        if self.is_finished() {
            self.rejected = true;
            return Err("Event stream already finished".into());
        }

        if let Err(error) = apply_event(&mut self.controller, line) {
            self.rejected = true;
            return Err(error);
        }

        Ok(self.controller.progress())
    }

    pub fn push_lines(&mut self, input: &str) -> Result<UpdateProgress, String> {
        for line in input.lines() {
            self.push(line)?;
        }

        Ok(self.progress())
    }

    pub fn is_finished(&self) -> bool {
        matches!(
            self.progress().phase,
            UpdatePhase::Completed | UpdatePhase::Cancelled | UpdatePhase::Failed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_waiting() {
        let stream = UpdateEventStream::new();
        assert_eq!(stream.progress().phase, UpdatePhase::Waiting);
        assert!(!stream.is_rejected());
    }

    #[test]
    fn accepts_download_progress() {
        let mut stream = UpdateEventStream::new();
        let progress = stream.push("RWR_EVENT=DOWNLOAD:45").unwrap();

        assert_eq!(progress.phase, UpdatePhase::Downloading);
        assert_eq!(progress.percent, 45);
    }

    #[test]
    fn completes_valid_stream() {
        let mut stream = UpdateEventStream::new();

        let lines = [
            "RWR_EVENT=DOWNLOAD:50",
            "RWR_EVENT=DOWNLOAD:100",
            "RWR_EVENT=VERIFY",
            "RWR_EVENT=INSTALL",
            "RWR_EVENT=COMPLETE",
        ];

        for line in lines {
            stream.push(line).unwrap();
        }

        assert_eq!(stream.progress().phase, UpdatePhase::Completed);
        assert!(stream.is_finished());
    }

    #[test]
    fn rejects_invalid_order() {
        let mut stream = UpdateEventStream::new();

        assert!(stream.push("RWR_EVENT=INSTALL").is_err());
        assert!(stream.is_rejected());
        assert!(stream.push("RWR_EVENT=DOWNLOAD:20").is_err());
    }

    #[test]
    fn rejects_unknown_event() {
        let mut stream = UpdateEventStream::new();

        assert!(stream.push("RWR_EVENT=UNKNOWN").is_err());
        assert!(stream.is_rejected());
        assert_eq!(stream.progress().phase, UpdatePhase::Waiting);
    }

    #[test]
    fn handles_cancellation() {
        let mut stream = UpdateEventStream::new();

        stream.push("RWR_EVENT=DOWNLOAD:30").unwrap();
        let progress = stream.push("RWR_EVENT=CANCEL").unwrap();

        assert_eq!(progress.phase, UpdatePhase::Cancelled);
        assert!(stream.is_finished());
        assert!(stream.push("RWR_EVENT=INSTALL").is_err());
    }
}
