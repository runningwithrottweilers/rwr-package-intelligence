//! Integration tests using a harmless real OS process.
//! No pacman, no shell and no privilege escalation.

#[cfg(test)]
mod tests {
    use crate::transaction_protocol::TransactionOutcome;
    use crate::transaction_worker::TransactionWorker;
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    fn run_fixture(lines: &str) -> Result<TransactionOutcome, String> {
        let mut child = Command::new("/usr/bin/printf")
            .arg("%s")
            .arg(lines)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "Missing stdout pipe".to_string())?;

        let mut worker = TransactionWorker::new();

        for line in BufReader::new(stdout).lines() {
            let line = line.map_err(|e| e.to_string())?;

            if let Err(error) = worker.receive_ipc_line(&line) {
                worker.connection_lost();
                let _ = child.wait();
                return Err(error);
            }
        }

        let status = child.wait().map_err(|e| e.to_string())?;
        let exit_code = status.code().unwrap_or(-1);

        worker.process_exited(exit_code)?;
        worker.outcome().ok_or_else(|| "Missing outcome".into())
    }

    #[test]
    fn real_pipe_success() {
        let input = concat!(
            r#"{"type":"started"}"#,
            "\n",
            r#"{"type":"progress","text":"Downloading"}"#,
            "\n",
            r#"{"type":"completed","exit_code":0}"#,
            "\n",
        );
        assert_eq!(run_fixture(input).unwrap(), TransactionOutcome::Success);
    }

    #[test]
    fn real_pipe_without_completion_fails() {
        let input = concat!(r#"{"type":"started"}"#, "\n");
        assert_eq!(run_fixture(input).unwrap(), TransactionOutcome::Failure);
    }

    #[test]
    fn real_pipe_rejects_invalid_json() {
        assert!(run_fixture("{invalid json}\n").is_err());
    }

    #[test]
    fn real_pipe_rejects_duplicate_completion() {
        let input = concat!(
            r#"{"type":"started"}"#,
            "\n",
            r#"{"type":"completed","exit_code":0}"#,
            "\n",
            r#"{"type":"completed","exit_code":0}"#,
            "\n",
        );
        assert!(run_fixture(input).is_err());
    }

    #[test]
    fn process_nonzero_exit_is_failure() {
        use std::process::Command;

        let status = Command::new("/usr/bin/false").status().unwrap();

        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"completed","exit_code":0}"#)
            .unwrap();

        worker.process_exited(status.code().unwrap_or(-1)).unwrap();

        assert_eq!(worker.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn process_exit_without_completion_is_failure() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker.process_exited(0).unwrap();

        assert_eq!(worker.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn signal_termination_is_failure() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"completed","exit_code":0}"#)
            .unwrap();

        worker.process_exited(-1).unwrap();

        assert_eq!(worker.outcome(), Some(TransactionOutcome::Failure));
    }

    #[test]
    fn malformed_completion_is_rejected() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();

        assert!(
            worker
                .receive_ipc_line(r#"{"type":"completed","exit_code":"zero"}"#)
                .is_err()
        );

        worker.connection_lost();

        assert_eq!(worker.outcome(), Some(TransactionOutcome::Failure));
    }
}

#[cfg(test)]
mod duplex_tests {
    use crate::transaction_ipc::{IpcReply, encode_reply, parse_reply};
    use crate::transaction_protocol::TransactionOutcome;
    use crate::transaction_worker::TransactionWorker;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    fn echo_reply(reply: &IpcReply) -> Result<IpcReply, String> {
        let mut child = Command::new("/usr/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "Missing stdin".to_string())?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "Missing stdout".to_string())?;

        let encoded = encode_reply(reply);

        writeln!(stdin, "{encoded}").map_err(|e| e.to_string())?;
        drop(stdin);

        let mut line = String::new();
        BufReader::new(stdout)
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;

        let status = child.wait().map_err(|e| e.to_string())?;

        if !status.success() {
            return Err("Echo process failed".into());
        }

        parse_reply(line.trim_end())
    }

    #[test]
    fn approved_reply_roundtrip_over_real_pipe() {
        let reply = IpcReply::Answer {
            id: 1,
            approved: true,
        };
        assert_eq!(echo_reply(&reply).unwrap(), reply);
    }

    #[test]
    fn rejected_reply_roundtrip_over_real_pipe() {
        let reply = IpcReply::Answer {
            id: 2,
            approved: false,
        };
        assert_eq!(echo_reply(&reply).unwrap(), reply);
    }

    #[test]
    fn echoed_reply_can_resume_worker() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"question","id":1,"text":"Proceed?"}"#)
            .unwrap();

        let reply = echo_reply(&IpcReply::Answer {
            id: 1,
            approved: true,
        })
        .unwrap();

        let IpcReply::Answer { id, approved } = reply;
        worker.answer_question(id, approved).unwrap();

        worker
            .receive_ipc_line(r#"{"type":"completed","exit_code":0}"#)
            .unwrap();
        worker.process_exited(0).unwrap();

        assert_eq!(worker.outcome(), Some(TransactionOutcome::Success));
    }

    #[test]
    fn echoed_rejection_cancels_worker() {
        let mut worker = TransactionWorker::new();
        worker.receive_ipc_line(r#"{"type":"started"}"#).unwrap();
        worker
            .receive_ipc_line(r#"{"type":"question","id":1,"text":"Proceed?"}"#)
            .unwrap();

        let reply = echo_reply(&IpcReply::Answer {
            id: 1,
            approved: false,
        })
        .unwrap();

        let IpcReply::Answer { id, approved } = reply;
        worker.answer_question(id, approved).unwrap();
        assert_eq!(worker.outcome(), Some(TransactionOutcome::Running));
        worker.receive_ipc_line(r#"{"type":"cancelled"}"#).unwrap();
        worker.process_exited(2).unwrap();

        assert_eq!(worker.outcome(), Some(TransactionOutcome::Cancelled));
    }
}

#[cfg(test)]
mod stage_4_11q_real_helper_ipc {
    use crate::transaction_protocol::TransactionOutcome;

    #[test]
    fn real_helper_lab_prepare_reaches_verified_success() {
        let outcome = crate::lab_ipc_runner::run_lab_ipc().expect("Laboratory IPC runner failed");

        assert_eq!(outcome, TransactionOutcome::Success);

        println!("RWR IPC: shared laboratory runner verified");
        println!("RWR IPC: helper process exit verified");
        println!("RWR IPC: isolated libalpm PREPARE successful");
        println!("RWR IPC: no commit, no system changes");
    }
}
