// RWR PACKAGE INTELLIGENCE — ETAP 1A
// Asynchronous event worker — TEST MODE ONLY.
// No pacman, pkexec, sudo or external process execution.

use crate::download_progress::DownloadTracker;
use crate::update_event_stream::UpdateEventStream;
use crate::update_progress::UpdateProgress;
use std::sync::mpsc::{self, Receiver};
use std::thread;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerMessage {
    Progress(UpdateProgress),
    Finished,
}

pub type WorkerResult = Result<WorkerMessage, String>;

pub fn start_test_worker() -> Receiver<WorkerResult> {
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        let mut stream = UpdateEventStream::new();

        let mut tracker = DownloadTracker::new();

        for (name, size) in [
            ("linux-test", 100_u64),
            ("mesa-test", 300_u64),
            ("gtk-test", 600_u64),
        ] {
            if let Err(error) = tracker.add_package(name, size) {
                let _ = sender.send(Err(error));
                return;
            }
        }

        let mut events = Vec::new();
        events.push("RWR_EVENT=DOWNLOAD:0".to_string());

        for (name, downloaded) in [
            ("linux-test", 100_u64),
            ("mesa-test", 150_u64),
            ("mesa-test", 300_u64),
            ("gtk-test", 300_u64),
            ("gtk-test", 600_u64),
        ] {
            if let Err(error) = tracker.update(name, downloaded) {
                let _ = sender.send(Err(error));
                return;
            }

            events.push(format!("RWR_EVENT=DOWNLOAD:{}", tracker.percent()));
        }

        if !tracker.is_complete() {
            let _ = sender.send(Err("Download simulation incomplete".into()));
            return;
        }

        events.extend([
            "RWR_EVENT=VERIFY".to_string(),
            "RWR_EVENT=INSTALL".to_string(),
            "RWR_EVENT=COMPLETE".to_string(),
        ]);

        for event in events {
            match stream.push(&event) {
                Ok(progress) => {
                    if sender.send(Ok(WorkerMessage::Progress(progress))).is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = sender.send(Err(error));
                    return;
                }
            }
        }

        if stream.is_finished() && !stream.is_rejected() {
            let _ = sender.send(Ok(WorkerMessage::Finished));
        } else {
            let _ = sender.send(Err("Worker did not finish correctly".into()));
        }
    });

    receiver
}

/// Classifies supplied output lines without executing any process.
/// This is not proof that a system upgrade succeeded.
pub fn classify_upgrade_output(input: &str) -> Vec<crate::real_progress::UpgradeEvent> {
    input
        .lines()
        .map(crate::real_progress::classify_line)
        .collect()
}

/// Processes supplied text lines asynchronously.
/// Does not launch pacman, pkexec or any external command.
/// End of input is not proof of a successful system upgrade.
pub fn start_output_worker(lines: Vec<String>) -> Receiver<crate::real_progress::UpgradeEvent> {
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        for line in lines {
            let event = crate::real_progress::classify_line(&line);

            if sender.send(event).is_err() {
                return;
            }
        }
    });

    receiver
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update_progress::UpdatePhase;

    #[test]
    fn classifies_supplied_upgrade_output() {
        use crate::real_progress::UpgradeEvent;

        let events = classify_upgrade_output(
            ":: Synchronizing package databases...\nresolving dependencies...",
        );

        assert_eq!(
            events,
            vec![
                UpgradeEvent::Synchronizing,
                UpgradeEvent::ResolvingDependencies,
            ]
        );
    }

    #[test]
    fn preserves_upgrade_event_order() {
        use crate::real_progress::UpgradeEvent;

        let events = classify_upgrade_output(":: Retrieving packages...\n(1/2) upgrading example");

        assert_eq!(events.len(), 2);
        assert_eq!(events[0], UpgradeEvent::Downloading);
        assert_eq!(events[1], UpgradeEvent::Upgrading);
    }

    #[test]
    fn empty_output_produces_no_events() {
        assert!(classify_upgrade_output("").is_empty());
    }

    #[test]
    fn unknown_output_is_preserved() {
        use crate::real_progress::UpgradeEvent;

        assert_eq!(
            classify_upgrade_output("example output"),
            vec![UpgradeEvent::Output("example output".into())]
        );
    }

    #[test]
    fn output_worker_preserves_order() {
        use crate::real_progress::UpgradeEvent;

        let receiver = start_output_worker(vec![
            ":: Synchronizing package databases...".into(),
            "resolving dependencies...".into(),
        ]);

        assert_eq!(
            receiver.into_iter().collect::<Vec<_>>(),
            vec![
                UpgradeEvent::Synchronizing,
                UpgradeEvent::ResolvingDependencies,
            ]
        );
    }

    #[test]
    fn output_worker_accepts_empty_input() {
        let receiver = start_output_worker(Vec::new());
        assert!(receiver.into_iter().collect::<Vec<_>>().is_empty());
    }

    #[test]
    fn output_worker_reports_error_text() {
        use crate::real_progress::UpgradeEvent;

        let receiver = start_output_worker(vec!["error: failed to synchronize databases".into()]);

        assert!(matches!(receiver.recv().unwrap(), UpgradeEvent::Error(_)));
    }

    #[test]
    fn output_worker_disconnects_after_input() {
        let receiver = start_output_worker(vec!["example".into()]);

        assert!(receiver.recv().is_ok());
        assert!(receiver.recv().is_err());
    }

    #[test]
    fn worker_sends_messages() {
        let receiver = start_test_worker();
        assert!(receiver.recv().unwrap().is_ok());
    }

    #[test]
    fn worker_reaches_completion() {
        let receiver = start_test_worker();
        let messages: Vec<_> = receiver.into_iter().collect();

        assert!(
            messages
                .iter()
                .any(|message| { matches!(message, Ok(WorkerMessage::Finished)) })
        );
    }

    #[test]
    fn worker_reports_download() {
        let receiver = start_test_worker();
        let messages: Vec<_> = receiver.into_iter().collect();

        assert!(messages.iter().any(|message| {
            matches!(
                message,
                Ok(WorkerMessage::Progress(progress))
                    if progress.phase == UpdatePhase::Downloading
            )
        }));
    }

    #[test]
    fn worker_reports_installation() {
        let receiver = start_test_worker();
        let messages: Vec<_> = receiver.into_iter().collect();

        assert!(messages.iter().any(|message| {
            matches!(
                message,
                Ok(WorkerMessage::Progress(progress))
                    if progress.phase == UpdatePhase::Installing
            )
        }));
    }

    #[test]
    fn worker_has_no_errors() {
        let receiver = start_test_worker();
        let messages: Vec<_> = receiver.into_iter().collect();

        assert!(!messages.is_empty());
        assert!(messages.iter().all(Result::is_ok));
    }
}
