// RWR PACKAGE INTELLIGENCE
// Laboratory IPC runner. Unprivileged, fixed helper only.
// No sudo, pkexec, pacman or transaction commit.

use crate::transaction_ipc::{IpcMessage, MAX_MESSAGE_BYTES, parse_message};
use crate::transaction_protocol::TransactionOutcome;
use crate::transaction_worker::TransactionWorker;

use std::io::BufReader;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::ipc_stream::read_ipc_stream;
use crate::process_guard::ChildGuard;

fn sandbox_command(
    helper: &std::path::Path,
    seccomp_fd: Option<std::os::fd::RawFd>,
    mode: &str,
) -> Result<Command, String> {
    let project = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .map_err(|e| format!("Cannot resolve laboratory project: {e}"))?;

    if !helper.starts_with(project.join("target/debug")) {
        return Err("Laboratory helper is outside the expected build directory".into());
    }

    let bwrap = std::path::Path::new("/usr/bin/bwrap");

    if !bwrap.is_file() {
        return Err("Bubblewrap is required for laboratory IPC".into());
    }

    let mut command = Command::new(bwrap);

    command.args([
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--disable-userns",
        "--assert-userns-disabled",
        "--die-with-parent",
        "--new-session",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib",
        "/lib64",
        "--dir",
        "/etc",
        "--dir",
        "/home",
    ]);

    for component in project.ancestors().skip(1).collect::<Vec<_>>().iter().rev() {
        if *component != std::path::Path::new("/") && *component != std::path::Path::new("/home") {
            command.arg("--dir").arg(component);
        }
    }

    let fixture = project.join("tests/fixtures/alpm-upgrade-lab");

    if !fixture.is_dir() {
        return Err("Laboratory fixtures unavailable".into());
    }

    command
        .arg("--dir")
        .arg(project.join("target"))
        .arg("--dir")
        .arg(project.join("target/debug"))
        .arg("--ro-bind")
        .arg(helper)
        .arg(helper)
        .arg("--dir")
        .arg(project.join("tests"))
        .arg("--dir")
        .arg(project.join("tests/fixtures"))
        .arg("--ro-bind")
        .arg(&fixture)
        .arg(&fixture)
        .args(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"])
        .arg("--chdir")
        .arg(&project);

    if let Some(fd) = seccomp_fd {
        command.arg("--seccomp").arg(fd.to_string());
    }

    command.arg("--").arg(helper).arg(mode);

    Ok(command)
}

#[derive(Debug)]
pub enum LabIpcUiEvent {
    Progress(String),
    Finished(Result<TransactionOutcome, String>),
}

pub fn start_lab_ipc_live() -> mpsc::Receiver<LabIpcUiEvent> {
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        let result = run_lab_ipc_internal(Some(&sender), Duration::from_secs(5));
        let _ = sender.send(LabIpcUiEvent::Finished(result));
    });

    receiver
}

pub fn run_lab_ipc() -> Result<TransactionOutcome, String> {
    run_lab_ipc_internal(None, Duration::from_secs(5))
}

fn run_lab_ipc_internal(
    event_sender: Option<&mpsc::Sender<LabIpcUiEvent>>,
    timeout: Duration,
) -> Result<TransactionOutcome, String> {
    if unsafe { geteuid() } == 0 {
        return Err("Laboratory runner refuses root privileges".into());
    }

    let helper =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/debug/rwr-update-helper");

    let helper = helper
        .canonicalize()
        .map_err(|e| format!("Laboratory helper unavailable: {e}"))?;

    let seccomp_filter = crate::lab_seccomp::prepare_filter()?;

    let mut command = sandbox_command(
        &helper,
        Some(std::os::fd::AsRawFd::as_raw_fd(&seccomp_filter)),
        "--lab-prepare",
    )?;

    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Cannot start sandboxed laboratory helper: {e}"))?;

    drop(seccomp_filter);

    let mut guard = ChildGuard(child);
    let stdout = guard.0.stdout.take().ok_or("Missing helper stdout")?;

    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        read_ipc_stream(BufReader::new(stdout), tx);
    });

    let mut worker = TransactionWorker::new();
    // O7B_EVENT_SEQUENCE: fixed callback order from isolated PREPARE.
    let mut count = 0usize;
    let expected_codes = [5, 6, 7, 8];
    let deadline = Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());

        if remaining.is_zero() {
            return Err("Laboratory IPC timeout".into());
        }

        match rx.recv_timeout(remaining) {
            Ok(Ok(bytes)) => {
                if bytes.len() > MAX_MESSAGE_BYTES {
                    return Err("Oversized laboratory IPC message".into());
                }

                let line = std::str::from_utf8(&bytes)
                    .map_err(|_| "Invalid IPC UTF-8")?
                    .trim_end_matches(|c: char| c as u32 == 10 || c as u32 == 13);

                if count >= 7 {
                    return Err("Unexpected extra laboratory IPC message".into());
                }

                let message = parse_message(line)?;

                match (count, &message) {
                    (0, IpcMessage::Started) => {}
                    (1..=4, IpcMessage::Progress(text))
                        if text == &format!("ALPM_EVENT:{}", expected_codes[count - 1]) => {}
                    (5, IpcMessage::Progress(text)) if text == "rwr-test-package -> 1.1-1" => {}
                    (6, IpcMessage::Completed { exit_code: 0 }) => {}
                    _ => {
                        return Err("Unexpected laboratory callback IPC sequence".into());
                    }
                }

                worker.receive_ipc_line(line)?;

                // Forward only successfully validated IPC progress.
                if let (Some(sender), IpcMessage::Progress(text)) = (event_sender, &message) {
                    let _ = sender.send(LabIpcUiEvent::Progress(text.clone()));
                }

                count += 1;
            }
            Ok(Err(error)) => return Err(error),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err("Laboratory IPC timeout".into());
            }
        }
    }

    if count != 7 {
        return Err(format!("Expected 7 IPC messages, received {count}"));
    }

    let remaining = deadline.saturating_duration_since(Instant::now());
    let exit_code = guard.wait_for_exit(remaining)?;

    worker.process_exited(exit_code)?;

    worker.outcome().ok_or("Missing IPC outcome".into())
}

unsafe extern "C" {
    fn geteuid() -> u32;
}

#[cfg(test)]
mod timeout_regression_tests {
    use super::*;

    #[test]
    fn laboratory_zero_timeout_fails_closed() {
        let result = run_lab_ipc_internal(None, Duration::ZERO);

        assert!(
            matches!(&result, Err(message) if message == "Laboratory IPC timeout"),
            "Expected laboratory timeout, got: {result:?}"
        );
    }
}

// RWR ETAP 4.6-I8 — FULL PREPARE IPC INTEGRATION
#[cfg(test)]
mod full_prepare_integration_tests {
    use super::*;

    #[test]
    fn full_prepare_ipc_process_integration() {
        let result = run_lab_ipc();
        assert!(
            matches!(result, Ok(TransactionOutcome::Success)),
            "Full laboratory PREPARE failed: {result:?}"
        );
    }
}

// RWR ETAP 4.8AD-21 — SECCOMP FAIL-CLOSED INTEGRATION
#[cfg(test)]
mod seccomp_fail_closed_integration_tests {
    use super::*;

    #[test]
    fn laboratory_helper_rejects_missing_seccomp() {
        let helper = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/debug/rwr-update-helper")
            .canonicalize()
            .expect("Laboratory helper binary required");

        // Deliberately use the original sandbox command without --seccomp.
        let output = sandbox_command(&helper, None, "--lab-prepare")
            .expect("Cannot construct laboratory sandbox")
            .stdin(Stdio::null())
            .output()
            .expect("Cannot start laboratory helper");

        assert!(
            !output.status.success(),
            "Helper unexpectedly accepted missing seccomp"
        );

        let stdout = String::from_utf8(output.stdout).expect("Helper output must be UTF-8");

        let stderr = String::from_utf8(output.stderr).expect("Helper errors must be UTF-8");

        assert!(
            stderr.contains("Sandbox verification failed: invalid Seccomp status"),
            "Expected seccomp rejection, got: {stderr}"
        );

        let messages: Vec<serde_json::Value> = stdout
            .lines()
            .map(|line| serde_json::from_str(line).expect("Invalid helper JSON"))
            .collect();

        assert_eq!(messages.len(), 2, "Unexpected helper IPC messages");
        assert_eq!(messages[0]["type"], "started");
        assert_eq!(messages[1]["type"], "failed");

        assert!(
            !stdout.contains("ALPM_EVENT"),
            "ALPM callbacks must not run without seccomp"
        );

        assert!(
            !stdout.contains("completed"),
            "Helper must not complete without seccomp"
        );
    }
}

// RWR ETAP 4 — CONTROLLED ISOLATED COMMIT INTEGRATION
#[cfg(test)]
mod isolated_commit_integration_tests {
    use super::*;

    #[test]
    fn laboratory_commit_ipc_integration() {
        let helper = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/debug/rwr-update-helper")
            .canonicalize()
            .expect("Laboratory helper binary required");

        let seccomp_filter = crate::lab_seccomp::prepare_filter().unwrap();

        let output = sandbox_command(
            &helper,
            Some(std::os::fd::AsRawFd::as_raw_fd(&seccomp_filter)),
            "--lab-commit",
        )
        .unwrap()
        .stdin(Stdio::null())
        .output()
        .expect("Cannot start laboratory commit helper");

        assert!(
            output.status.success(),
            "Laboratory COMMIT helper failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8(output.stdout).expect("Helper output must be UTF-8");
        let messages: Vec<serde_json::Value> = stdout
            .lines()
            .map(|line| serde_json::from_str(line).expect("Invalid helper JSON"))
            .collect();

        assert!(messages.len() >= 4, "Unexpectedly few commit messages");
        assert_eq!(messages[0]["type"], "started");
        assert_eq!(messages.last().unwrap()["type"], "completed");
        assert_eq!(messages.last().unwrap()["exit_code"], 0);

        // Honest stage evidence: the retrieval is performed into the lab
        // cache; the fixture repository is unsigned (siglevel 0), so the
        // signature stage must be reported as NOT exercised.
        let flow_lines: Vec<&str> = messages
            .iter()
            .filter_map(|message| message["text"].as_str())
            .filter(|text| text.starts_with("FLOW:"))
            .collect();

        assert!(
            flow_lines.contains(&"FLOW:sync=true"),
            "Expected executed database synchronisation evidence, got: {flow_lines:?}"
        );
        assert!(
            flow_lines.contains(&"FLOW:download=true"),
            "Expected executed download evidence, got: {flow_lines:?}"
        );
        assert!(
            flow_lines.contains(&"FLOW:signatures=false"),
            "Signature stage must be reported as not exercised, got: {flow_lines:?}"
        );

        // The commit path must deliver real libalpm commit events.
        let events: Vec<i32> = messages
            .iter()
            .filter_map(|message| {
                message["text"]
                    .as_str()
                    .and_then(|text| text.strip_prefix("ALPM_EVENT:"))
                    .and_then(|code| code.parse().ok())
            })
            .collect();

        assert!(
            events.contains(&9),
            "Expected COMMIT transaction start event, got: {events:?}"
        );

        for message in &messages {
            assert_ne!(message["type"], "failed", "Helper reported: {message}");
        }
    }
}

// RWR ETAP 4.6-I10 — BOUNDED STREAM TRANSPORT TESTS
#[cfg(test)]
mod stream_transport_tests {
    use super::*;
    use std::io::Cursor;

    fn collect(input: Vec<u8>) -> Vec<Result<Vec<u8>, String>> {
        let (tx, rx) = mpsc::channel();
        read_ipc_stream(BufReader::new(Cursor::new(input)), tx);
        rx.into_iter().collect()
    }

    #[test]
    fn accepts_variable_message_count() {
        let input = b"{\"type\":\"started\"}\n{\"type\":\"progress\",\"text\":\"one\"}\n{\"type\":\"progress\",\"text\":\"two\"}\n{\"type\":\"completed\",\"exit_code\":0}\n";
        let messages = collect(input.to_vec());

        assert_eq!(messages.len(), 4);

        for message in messages {
            let bytes = message.unwrap();
            let line = std::str::from_utf8(&bytes).unwrap().trim_end();
            assert!(parse_message(line).is_ok());
        }
    }

    #[test]
    fn rejects_incomplete_line() {
        let messages = collect(b"{\"type\":\"started\"}".to_vec());

        assert_eq!(messages.len(), 1);
        assert!(matches!(&messages[0], Err(error) if error == "Incomplete IPC line"));
    }

    #[test]
    fn rejects_oversized_line() {
        let mut input = vec![b'x'; MAX_MESSAGE_BYTES + 1];
        input.push(b'\n');

        let messages = collect(input);

        assert_eq!(messages.len(), 1);
        assert!(matches!(&messages[0], Err(error) if error == "Oversized IPC message"));
    }
}

#[cfg(test)]
mod signed_transaction_integration_tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn signed_transactions_enforce_crypto_and_real_failure_boundaries() {
        let helper = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/debug/rwr-update-helper")
            .canonicalize()
            .unwrap();
        let mut reports: Vec<serde_json::Value> = Vec::new();
        for case in [
            "valid",
            "missing-db-signature",
            "bad-db-signature",
            "missing-package-signature",
            "bad-package-signature",
            "untrusted-signer",
            "corrupt-archive",
            "download-failure",
            "dependency-failure",
            "database-lock",
            "file-conflict",
            "install-error",
            "interrupt",
        ] {
            let filter = crate::lab_seccomp::prepare_filter().unwrap();
            let mut command = sandbox_command(
                &helper,
                Some(std::os::fd::AsRawFd::as_raw_fd(&filter)),
                "--lab-signed-case",
            )
            .unwrap();
            command.arg(case);
            let mut guard = ChildGuard(
                command
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
            drop(filter);
            let stdout = guard.0.stdout.take().unwrap();
            let stderr = guard.0.stderr.take().unwrap();
            let read = |stream: Box<dyn Read + Send>| {
                thread::spawn(move || {
                    let mut bytes = Vec::new();
                    stream.take(1024 * 1024).read_to_end(&mut bytes).unwrap();
                    bytes
                })
            };
            let out = read(Box::new(stdout));
            let err = read(Box::new(stderr));
            let exit = guard.wait_for_exit(Duration::from_secs(30));
            drop(guard);
            let output = String::from_utf8(out.join().unwrap()).unwrap();
            let errors = String::from_utf8_lossy(&err.join().unwrap()).into_owned();
            assert_eq!(
                exit.unwrap(),
                0,
                "Signed laboratory {case} failed: {errors}\n{output}"
            );
            let messages: Vec<serde_json::Value> = output
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(messages.first().unwrap()["type"], "started");
            assert_eq!(messages.last().unwrap()["type"], "completed");
            let report: serde_json::Value = serde_json::from_str(
                messages.iter().find(|v| v["type"] == "progress").unwrap()["text"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(report["case"], case);
            reports.push(report);
        }
        assert_eq!(reports.len(), 13);
        let valid = reports.iter().find(|v| v["case"] == "valid").unwrap();
        assert_eq!(valid["observed"], "success");
        assert_eq!(valid["installed_version"], "1.1-1");
        assert_eq!(valid["downloaded"], true);
        assert_eq!(valid["signatures_verified"], true);
        let mut cases = std::collections::HashSet::new();
        for report in &reports {
            let case = report["case"].as_str().unwrap();
            assert!(cases.insert(case));
            assert_eq!(report["real_execution_enabled"], false);
            assert_eq!(report["automatic_rollback"], false);
            if case != "valid" {
                assert_eq!(report["observed"], "rejected", "{report}");
                assert!(report["error"].as_str().is_some_and(|e| !e.is_empty()));
                if case != "interrupt" {
                    assert_eq!(report["installed_version"], "1.0-1", "{report}");
                }
            }
            if ["file-conflict", "install-error", "interrupt"].contains(&case) {
                assert_eq!(report["downloaded"], true, "{report}");
                assert_eq!(report["signatures_verified"], true, "{report}");
            }
            if case == "interrupt" {
                assert_eq!(report["interrupt_delivered"], true, "{report}");
            }
            if case == "database-lock" {
                assert!(report["error"].as_str().unwrap().contains("lock"));
            }
            if case == "dependency-failure" {
                assert!(
                    report["error"].as_str().unwrap().contains("(45)"),
                    "{report}"
                );
            }
        }
    }
}

#[cfg(test)]
mod signed_progress_integration_tests {
    use super::*;
    #[test]
    fn signed_lab_emits_actual_download_and_install_callbacks() {
        use std::io::Read;
        let helper = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/debug/rwr-update-helper")
            .canonicalize()
            .unwrap();
        let filter = crate::lab_seccomp::prepare_filter().unwrap();
        let mut command = sandbox_command(
            &helper,
            Some(std::os::fd::AsRawFd::as_raw_fd(&filter)),
            "--lab-signed-case",
        )
        .unwrap();
        command.arg("valid");
        let mut guard = ChildGuard(
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        drop(filter);
        let mut stdout = guard.0.stdout.take().unwrap();
        let mut stderr = guard.0.stderr.take().unwrap();
        let exit = guard.wait_for_exit(Duration::from_secs(30)).unwrap();
        let mut output = String::new();
        stdout.take(65536).read_to_string(&mut output).unwrap();
        let mut errors = String::new();
        stderr.take(65536).read_to_string(&mut errors).unwrap();
        assert_eq!(exit, 0, "{errors}\n{output}");
        let messages: Vec<serde_json::Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let report: serde_json::Value = serde_json::from_str(
            messages.iter().find(|v| v["type"] == "progress").unwrap()["text"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(report["observed"], "success");
        assert_eq!(report["signatures_verified"], true);
        assert!(
            report["download_callbacks"].as_u64().unwrap() > 0,
            "{report}"
        );
        assert!(
            report["install_callbacks"].as_u64().unwrap() > 0,
            "{report}"
        );
    }
}
