// RWR PACKAGE INTELLIGENCE
// IPC DEMO WORKER — TEST MODE ONLY.
// Never invokes pacman, pkexec or sudo.

use crate::transaction_ipc::{IpcReply, encode_reply};
use crate::transaction_protocol::TransactionOutcome;
use crate::transaction_worker::TransactionWorker;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcDemoEvent {
    Started,
    Question(String),
    Completed,
    Cancelled,
    Failed(String),
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Ok(None) = self.0.try_wait() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn execute(
    helper: &str,
    approved: bool,
    sender: &mpsc::Sender<IpcDemoEvent>,
) -> Result<TransactionOutcome, String> {
    let expected =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/debug/rwr-ipc-test-helper");

    let requested =
        std::fs::canonicalize(helper).map_err(|error| format!("Invalid helper path: {error}"))?;

    let allowed = std::fs::canonicalize(&expected)
        .map_err(|error| format!("Test helper unavailable: {error}"))?;

    if requested != allowed {
        return Err("Unauthorized helper executable".into());
    }

    let child = Command::new(&allowed)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;

    let mut guard = ChildGuard(child);
    let mut stdin = guard.0.stdin.take().ok_or("Missing stdin")?;
    let stdout = guard.0.stdout.take().ok_or("Missing stdout")?;

    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        for _ in 0..3 {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut worker = TransactionWorker::new();

    for index in 0..3 {
        let line = rx
            .recv_timeout(Duration::from_secs(3))
            .map_err(|_| "IPC timeout".to_string())?;

        worker.receive_ipc_line(line.trim_end())?;
        if index == 0 {
            let _ = sender.send(IpcDemoEvent::Started);
        }
        if index == 1 {
            let id = worker.pending_question_id().ok_or("Missing question")?;

            worker.answer_question(id, approved)?;

            let reply = encode_reply(&IpcReply::Answer { id, approved });
            writeln!(stdin, "{reply}").map_err(|error| error.to_string())?;
            stdin.flush().map_err(|error| error.to_string())?;
            drop(stdin);
            // The third message is read on the next iteration.
            break;
        }
    }

    let final_line = rx
        .recv_timeout(Duration::from_secs(3))
        .map_err(|_| "IPC completion timeout".to_string())?;

    if !approved && final_line.trim_end() != r#"{"type":"cancelled"}"# {
        return Err("Expected cancellation".into());
    }

    worker.receive_ipc_line(final_line.trim_end())?;

    let deadline = Instant::now() + Duration::from_secs(3);

    let exit_code = loop {
        if let Some(status) = guard.0.try_wait().map_err(|e| e.to_string())? {
            break status.code().unwrap_or(-1);
        }
        if Instant::now() >= deadline {
            return Err("Helper exit timeout".into());
        }
        thread::sleep(Duration::from_millis(20));
    };

    worker.process_exited(exit_code)?;

    worker.outcome().ok_or("Missing transaction outcome".into())
}

pub fn start_ipc_demo_worker(helper: String, approved: bool) -> Receiver<IpcDemoEvent> {
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || match execute(&helper, approved, &sender) {
        Ok(TransactionOutcome::Success) => {
            let _ = sender.send(IpcDemoEvent::Completed);
        }
        Ok(TransactionOutcome::Cancelled) => {
            let _ = sender.send(IpcDemoEvent::Cancelled);
        }
        Ok(other) => {
            let _ = sender.send(IpcDemoEvent::Failed(format!("{other:?}")));
        }
        Err(error) => {
            let _ = sender.send(IpcDemoEvent::Failed(error));
        }
    });

    receiver
}

#[cfg(test)]
mod ipc_demo_worker_tests {
    use super::*;

    fn helper_path() -> String {
        format!(
            "{}/target/debug/rwr-ipc-test-helper",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    #[test]
    fn approved_helper_completes() {
        let (sender, _receiver) = mpsc::channel();
        let result = execute(&helper_path(), true, &sender).unwrap();
        assert_eq!(result, TransactionOutcome::Success);
    }

    #[test]
    fn rejected_helper_cancels() {
        let (sender, _receiver) = mpsc::channel();
        let result = execute(&helper_path(), false, &sender).unwrap();
        assert_eq!(result, TransactionOutcome::Cancelled);
    }

    #[test]
    fn public_worker_reports_started_and_completed() {
        let receiver = start_ipc_demo_worker(helper_path(), true);

        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(5)).unwrap(),
            IpcDemoEvent::Started
        );

        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(5)).unwrap(),
            IpcDemoEvent::Completed
        );
    }
}
