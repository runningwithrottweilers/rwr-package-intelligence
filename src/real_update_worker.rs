// RWR PACKAGE INTELLIGENCE
// Process event worker.
// Restricted diagnostic executables only.
// No pacman, pkexec or shell execution.

use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};

use crate::real_update_events::RealUpdateEvent;

pub fn start_diagnostic_worker(program: &str) -> Result<Receiver<RealUpdateEvent>, String> {
    if !matches!(program, "/usr/bin/true" | "/usr/bin/false") {
        return Err("Executable not permitted".into());
    }

    let program = program.to_owned();
    let (sender, receiver) = mpsc::channel();

    std::thread::spawn(move || {
        let status = Command::new(&program)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        let event = match status {
            Ok(status) => match status.code() {
                Some(code) => RealUpdateEvent::Finished { exit_code: code },
                None => RealUpdateEvent::Failed("Process terminated by signal".into()),
            },
            Err(error) => RealUpdateEvent::Failed(error.to_string()),
        };

        let _ = sender.send(event);
    });

    Ok(receiver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn true_reports_success() {
        let receiver = start_diagnostic_worker("/usr/bin/true").unwrap();
        let event = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(event.succeeded());
    }

    #[test]
    fn false_reports_failure() {
        let receiver = start_diagnostic_worker("/usr/bin/false").unwrap();
        let event = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(event, RealUpdateEvent::Finished { exit_code: 1 });
        assert!(!event.succeeded());
    }

    #[test]
    fn pacman_is_forbidden() {
        assert!(start_diagnostic_worker("/usr/bin/pacman").is_err());
    }

    #[test]
    fn pkexec_is_forbidden() {
        assert!(start_diagnostic_worker("/usr/bin/pkexec").is_err());
    }
}
