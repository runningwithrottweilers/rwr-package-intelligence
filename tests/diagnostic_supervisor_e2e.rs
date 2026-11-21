//! Diagnostic helper -> activated supervisor -> socket -> GTK client adapter.
//! No production helper, package operations or GTK display are used.

use rwr_package_intelligence::process_guard::ChildGuard;
use rwr_package_intelligence::supervisor_client::{
    diagnostic_session_summary, read_supervisor_state,
};
use std::os::fd::AsRawFd;
use std::os::unix::{fs::DirBuilderExt, net::UnixListener, process::CommandExt};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Fixture(std::path::PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn supervisor_fixture(
    controlled: bool,
) -> (Fixture, ChildGuard, std::path::PathBuf, std::path::PathBuf) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let fixture =
        Fixture(std::env::temp_dir().join(format!("rwr-e2e-{}-{nonce}", std::process::id())));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&fixture.0)
        .unwrap();
    let socket = fixture.0.join("s.sock");
    let state_path = fixture.0.join("state.json");
    let listener = UnixListener::bind(&socket).unwrap();
    let listener_fd = listener.as_raw_fd();
    // The shell exports its own PID and exec preserves it for socket activation.
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "export LISTEN_PID=$$; exec \"$1\"", "rwr-e2e"])
        .arg(env!("CARGO_BIN_EXE_rwr-transaction-supervisor"))
        .env("LISTEN_FDS", "1")
        .env("RWR_DIAGNOSTIC_TEST_PROGRESS", "1")
        .env("RWR_DIAGNOSTIC_TRANSACTION_ID", "e2e-diagnostic")
        .env("RWR_DIAGNOSTIC_STATE_PATH", &state_path)
        .env(
            "RWR_DIAGNOSTIC_HELPER_PATH",
            env!("CARGO_BIN_EXE_rwr-ipc-test-helper"),
        )
        .env_remove("RWR_DIAGNOSTIC_SLEEP_SECONDS")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if controlled {
        command
            .env("RWR_DIAGNOSTIC_CONTROL", "1")
            .env_remove("RWR_DIAGNOSTIC_TRANSACTION_ID")
            .env_remove("RWR_DIAGNOSTIC_HELPER_PATH");
    } else {
        command.env_remove("RWR_DIAGNOSTIC_CONTROL");
    }
    // Only async-signal-safe descriptor operations run between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if listener_fd != 3 && libc::dup2(listener_fd, 3) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let supervisor = ChildGuard(command.spawn().unwrap());
    drop(listener);
    (fixture, supervisor, socket, state_path)
}

#[test]
fn diagnostic_helper_socket_gui_reconnect() {
    let (_fixture, mut supervisor, socket, state_path) = supervisor_fixture(false);
    let deadline = Instant::now() + Duration::from_secs(5);
    let finished = loop {
        assert!(
            supervisor.0.try_wait().unwrap().is_none(),
            "Supervisor exited early"
        );
        assert!(
            Instant::now() < deadline,
            "Diagnostic transaction timed out"
        );
        // Every call connects and drops its socket, just like the GTK poller.
        let state = read_supervisor_state(&socket).expect("GUI client read");
        assert_eq!(state["transaction_id"], "e2e-diagnostic");
        assert_eq!(state["real_execution_enabled"], false);
        assert!(diagnostic_session_summary(&state).unwrap().is_some());
        if state["phase"] == "finished" {
            break state;
        }
        assert_eq!(state["outcome"], "running");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(finished["outcome"], "success");
    // This exact text originates in a helper IPC Progress event, not in the
    // supervisor's synthetic start message, and survives the socket read.
    assert_eq!(
        finished["progress"],
        "TEST MODE: simulated diagnostic progress"
    );
    assert_eq!(finished["sequence"], 1);
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(saved["outcome"], "success");
    assert_eq!(saved["real_execution_enabled"], false);
    let reconnected = read_supervisor_state(&socket).expect("GUI reconnect after completion");
    assert_eq!(reconnected, finished);
    assert!(
        diagnostic_session_summary(&reconnected)
            .unwrap()
            .unwrap()
            .contains("finished · success")
    );
    assert!(
        diagnostic_session_summary(&reconnected)
            .unwrap()
            .unwrap()
            .contains("TEST MODE: simulated diagnostic progress")
    );
}

#[test]
fn gui_controls_diagnostic_session_and_recovers_question_and_result() {
    use rwr_package_intelligence::supervisor_client::{
        answer_diagnostic_question, pending_diagnostic_question, start_diagnostic_session,
    };
    for approved in [true, false] {
        let (_fixture, mut supervisor, socket, path) = supervisor_fixture(true);
        // Initial GTK monitoring must not terminate a supervisor with no session.
        assert!(
            read_supervisor_state(&socket)
                .unwrap()
                .get("transaction_id")
                .is_none()
        );
        let started = start_diagnostic_session(&socket, "gui-control-test").unwrap();
        assert_eq!(started["outcome"], "running");
        let deadline = Instant::now() + Duration::from_secs(5);
        let question = loop {
            assert!(Instant::now() < deadline);
            let state = read_supervisor_state(&socket).unwrap();
            if let Some((id, text)) = pending_diagnostic_question(&state).unwrap() {
                assert_eq!(state["phase"], "ready");
                assert!(text.contains("TEST MODE"));
                assert!(state["progress"].as_str().unwrap().contains("preparing"));
                break id;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        // A fresh socket sees the pending question; GUI disconnection is not cancellation.
        let rejoined = read_supervisor_state(&socket).unwrap();
        assert_eq!(
            pending_diagnostic_question(&rejoined).unwrap().unwrap().0,
            question
        );
        // Retry start is idempotent and cannot launch another helper.
        assert_eq!(
            start_diagnostic_session(&socket, "gui-control-test").unwrap()["phase"],
            "ready"
        );
        assert!(start_diagnostic_session(&socket, "another-session").is_err());
        assert!(answer_diagnostic_question(&socket, "wrong-session", question, true).is_err());
        assert!(
            answer_diagnostic_question(&socket, "gui-control-test", question + 1, true).is_err()
        );
        answer_diagnostic_question(&socket, "gui-control-test", question, approved).unwrap();
        assert!(
            answer_diagnostic_question(&socket, "gui-control-test", question, approved).is_err()
        );
        let finished = loop {
            assert!(Instant::now() < deadline);
            let state = read_supervisor_state(&socket).unwrap();
            if state["phase"] == "finished" {
                break state;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(
            finished["outcome"],
            if approved { "success" } else { "cancelled" }
        );
        assert_eq!(finished["sequence"], if approved { 3 } else { 2 });
        assert!(pending_diagnostic_question(&finished).unwrap().is_none());
        assert_eq!(finished["real_execution_enabled"], false);
        assert_eq!(read_supervisor_state(&socket).unwrap(), finished);
        assert!(
            diagnostic_session_summary(&finished)
                .unwrap()
                .unwrap()
                .contains("finished")
        );
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["outcome"], finished["outcome"]);
        assert!(supervisor.0.try_wait().unwrap().is_none());
    }
    let (_fixture, _supervisor, socket, _) = supervisor_fixture(false);
    assert!(start_diagnostic_session(&socket, "control-disabled").is_err());
}

#[test]
fn user_handshake_eof_timeout_and_reconnect() {
    use std::io::{BufRead, BufReader, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    let (_fixture, mut supervisor, socket, _) = supervisor_fixture(true);
    let initial = read_supervisor_state(&socket).expect("versioned USER status");
    // An accept followed immediately by EOF must not terminate the supervisor.
    drop(UnixStream::connect(&socket).unwrap());
    for frame in [
        "{\"command\":\"status\",\"protocol_version\":99}\n",
        "{\"command\":\"status\",\"protocol_version\":1}",
    ] {
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap(),
            rwr_package_intelligence::supervisor_client::user_hello()
        );
        stream.write_all(frame.as_bytes()).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        line.clear();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        let refused: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(refused["real_execution_enabled"], false);
        assert!(refused["error"].is_string(), "{refused}");
        assert_eq!(read_supervisor_state(&socket).unwrap(), initial);
    }
    let stream = UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    assert!(reader.read_line(&mut line).unwrap() > 0);
    line.clear();
    let started = Instant::now();
    assert_eq!(
        reader.read_line(&mut line).unwrap(),
        0,
        "idle peer must close"
    );
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(read_supervisor_state(&socket).unwrap(), initial);
    assert!(supervisor.0.try_wait().unwrap().is_none());
}

// This test process never reaches the production host (deny-only).
rwr_package_intelligence::isolate_test_binary!();
