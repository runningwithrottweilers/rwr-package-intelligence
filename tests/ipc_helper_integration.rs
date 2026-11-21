use rwr_package_intelligence::transaction_ipc;
use rwr_package_intelligence::transaction_protocol;
use rwr_package_intelligence::transaction_state;
use rwr_package_intelligence::transaction_worker;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use transaction_ipc::{IpcReply, encode_reply};
use transaction_protocol::TransactionOutcome;
use transaction_worker::TransactionWorker;

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn run_helper(approved: bool) {
    let helper = env!("CARGO_BIN_EXE_rwr-ipc-test-helper");

    let child = Command::new(helper)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Cannot start test helper");

    let mut guard = ChildGuard { child };

    let mut stdin = guard.child.stdin.take().expect("Missing stdin");
    let stdout = guard.child.stdout.take().expect("Missing stdout");

    let (sender, receiver) = mpsc::channel::<String>();

    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);

        for _ in 0..3 {
            let mut line = String::new();

            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if sender.send(line).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let receive = || {
        receiver
            .recv_timeout(Duration::from_secs(3))
            .expect("IPC timeout or disconnected helper")
    };

    let mut worker = TransactionWorker::new();

    let line = receive();
    worker.receive_ipc_line(line.trim_end()).unwrap();

    let line = receive();
    worker.receive_ipc_line(line.trim_end()).unwrap();

    let id = worker.pending_question_id().expect("Missing question");

    worker.answer_question(id, approved).unwrap();

    let reply = encode_reply(&IpcReply::Answer { id, approved });

    writeln!(stdin, "{reply}").unwrap();
    stdin.flush().unwrap();
    drop(stdin);

    let line = receive();

    if approved {
        worker.receive_ipc_line(line.trim_end()).unwrap();

        let status = guard.child.wait().unwrap();
        assert_eq!(status.code(), Some(0));

        worker.process_exited(0).unwrap();

        assert_eq!(worker.outcome(), Some(TransactionOutcome::Success));
    } else {
        let status = guard.child.wait().unwrap();
        assert_eq!(status.code(), Some(2));

        assert_eq!(line.trim_end(), r#"{"type":"cancelled"}"#);
        worker.receive_ipc_line(line.trim_end()).unwrap();
        worker.process_exited(2).unwrap();

        assert_eq!(worker.outcome(), Some(TransactionOutcome::Cancelled));
    }
}

#[test]
fn helper_approved_transaction() {
    run_helper(true);
}

#[test]
fn helper_rejected_transaction() {
    run_helper(false);
}

// This test process never reaches the production host (deny-only).
rwr_package_intelligence::isolate_test_binary!();
