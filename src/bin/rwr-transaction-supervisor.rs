//! RWR PACKAGE INTELLIGENCE — transaction supervisor.
//! Diagnostic status only. No package execution or privileged operations.

#[path = "../supervisor_trust.rs"]
mod supervisor_trust;
#[path = "../test_isolation.rs"]
#[allow(dead_code)]
mod test_isolation;

use rwr_package_intelligence::supervisor_session::SupervisorSession;
use rwr_package_intelligence::supervisor_state::SupervisorState;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::ExitCode;

fn real_execution_enabled() -> bool {
    rwr_package_intelligence::supervisor_trust::system_execution_enabled()
}

fn supervisor_status_json() -> String {
    serde_json::json!({
        "component": "rwr-transaction-supervisor",
        "implementation": "diagnostic-only",
        "real_execution_enabled": real_execution_enabled(),
        "transaction_supervision_ready": false,
        "service_integration_ready": false
    })
    .to_string()
}

fn run_diagnostic_process(id: &str, path: &Path, program: &str) -> Result<String, String> {
    if !matches!(program, "/usr/bin/true" | "/usr/bin/false") {
        return Err("Diagnostic program not allowed".into());
    }

    use rwr_package_intelligence::transaction_protocol::TransactionMessage;
    use rwr_package_intelligence::transaction_worker::TransactionWorker;

    let mut state = SupervisorState::diagnostic(id)?;
    let mut worker = TransactionWorker::new();
    worker.receive(TransactionMessage::Started)?;
    state.save(path)?;

    let status = std::process::Command::new(program)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    let succeeded = match status {
        Ok(child) => {
            let mut supervised = SupervisedProcess {
                child: rwr_package_intelligence::process_guard::ChildGuard(child),
            };

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);

            loop {
                match supervised.poll_exit() {
                    Ok(Some(result)) => break result.success(),
                    Ok(None) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    _ => break false,
                }
            }
        }
        Err(_) => false,
    };

    if succeeded {
        worker.receive(TransactionMessage::Completed { exit_code: 0 })?;
        worker.process_exited(0)?;
    } else {
        worker.receive(TransactionMessage::Failed(
            "Diagnostic process failed".into(),
        ))?;
        worker.process_exited(1)?;
    }

    state.persist_from_worker(&worker, path)?;

    Ok(serde_json::json!({
        "transaction_id": state.transaction_id,
        "phase": state.phase,
        "outcome": state.outcome,
        "sequence": state.sequence,
        "real_execution_enabled": false
    })
    .to_string())
}

// RWR ETAP 4.8AD-36 — diagnostic IPC protocol integration.
// This operation does not spawn processes or perform package operations.
fn run_diagnostic_ipc(valid: bool) -> Result<String, String> {
    use rwr_package_intelligence::transaction_worker::TransactionWorker;

    let mut worker = TransactionWorker::new();

    let messages = if valid {
        vec![
            r#"{"type":"started"}"#,
            r#"{"type":"progress","text":"Diagnostic preparation"}"#,
            r#"{"type":"phase","phase":"ready"}"#,
            r#"{"type":"completed","exit_code":0}"#,
        ]
    } else {
        vec![
            r#"{"type":"started"}"#,
            r#"{"type":"completed","exit_code":0}"#,
            r#"{"type":"progress","text":"Invalid late progress"}"#,
        ]
    };

    for message in messages {
        worker.receive_ipc_line(message)?;
    }

    worker.process_exited(0)?;

    let outcome = format!("{:?}", worker.outcome());

    Ok(serde_json::json!({
        "mode": "diagnostic-ipc",
        "outcome": outcome,
        "real_execution_enabled": false
    })
    .to_string())
}

// Diagnostic-only child IPC. No privileged helper or package changes.
// Diagnostic-only child IPC with bounded reads and a session deadline.
// Never used for privileged package transactions.
fn run_diagnostic_ipc_process(helper: &Path) -> Result<String, String> {
    run_observed_diagnostic_helper(helper, |_, _| Ok(()))
}

fn run_observed_diagnostic_helper(
    helper: &Path,
    observe: impl FnMut(
        &rwr_package_intelligence::transaction_worker::TransactionWorker,
        Option<&rwr_package_intelligence::transaction_ipc::IpcMessage>,
    ) -> Result<(), String>,
) -> Result<String, String> {
    run_answered_diagnostic_helper(helper, observe, |_, _| Ok(true), false)
}

fn run_answered_diagnostic_helper(
    helper: &Path,
    mut observe: impl FnMut(
        &rwr_package_intelligence::transaction_worker::TransactionWorker,
        Option<&rwr_package_intelligence::transaction_ipc::IpcMessage>,
    ) -> Result<(), String>,
    mut answer: impl FnMut(u64, &str) -> Result<bool, String>,
    interactive: bool,
) -> Result<String, String> {
    let expected = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/debug/rwr-ipc-test-helper");
    let executable = supervisor_trust::open_diagnostic_helper(helper, &expected)?;
    use std::os::fd::AsRawFd;
    let pinned_path = format!("/proc/self/fd/{}", executable.as_raw_fd());

    use rwr_package_intelligence::process_guard::ChildGuard;
    use rwr_package_intelligence::transaction_ipc::{
        IpcMessage, IpcReply, encode_reply, parse_message,
    };
    use rwr_package_intelligence::transaction_protocol::TransactionOutcome;
    use rwr_package_intelligence::transaction_worker::TransactionWorker;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    const SESSION_TIMEOUT: Duration = Duration::from_secs(10);
    const EXIT_TIMEOUT: Duration = Duration::from_secs(2);

    let mut command = Command::new(&pinned_path);
    if interactive {
        command
            .env("RWR_DIAGNOSTIC_TEST_PHASES", "1")
            .env("RWR_DIAGNOSTIC_TEST_PROGRESS", "1");
    }
    let child = command
        .env("RWR_DIAGNOSTIC_HANDSHAKE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Diagnostic helper spawn failed: {e}"))?;

    let mut guard = ChildGuard(child);
    let stdout = guard.0.stdout.take().ok_or("Missing helper stdout")?;
    let mut stdin = guard.0.stdin.take().ok_or("Missing helper stdin")?;

    let (tx, rx) = mpsc::sync_channel(32);

    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);

        loop {
            let mut bytes = Vec::new();
            let result = Read::by_ref(&mut reader)
                .take((16 * 1024 + 1) as u64)
                .read_until(10u8, &mut bytes);

            match result {
                Ok(0) => break,
                Ok(_) => {
                    if bytes.len() > 16 * 1024 || bytes.last() != Some(&10u8) {
                        let _ = tx.send(Err("Invalid IPC line size or framing".into()));
                        break;
                    }

                    if tx.send(Ok(bytes)).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e.to_string()));
                    break;
                }
            }
        }
    });

    let mut deadline = Instant::now() + SESSION_TIMEOUT;
    let mut worker = TransactionWorker::new();
    let mut answered = false;
    let mut verified_hello = false;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());

        if remaining.is_zero() {
            return Err("Diagnostic IPC session timeout".into());
        }

        match rx.recv_timeout(remaining) {
            Ok(Ok(bytes)) => {
                let line = std::str::from_utf8(&bytes)
                    .map_err(|_| "Invalid IPC UTF-8")?
                    .trim_end_matches([char::from(13), char::from(10)]);

                if !verified_hello {
                    supervisor_trust::verify_hello(line)?;
                    verified_hello = true;
                    continue;
                }
                let message = parse_message(line)?;
                worker.receive_ipc_line(line)?;
                observe(&worker, Some(&message))?;

                if let IpcMessage::Question { id, text } = message {
                    if answered {
                        return Err("Duplicate diagnostic question".into());
                    }

                    let waiting_since = Instant::now();
                    let approved = answer(id, &text)?;
                    // Human response time is bounded by the session answer callback.
                    deadline += waiting_since.elapsed();
                    worker.answer_question(id, approved)?;

                    let reply = encode_reply(&IpcReply::Answer { id, approved });

                    writeln!(stdin, "{reply}").map_err(|e| e.to_string())?;
                    stdin.flush().map_err(|e| e.to_string())?;
                    answered = true;
                }
            }
            Ok(Err(error)) => return Err(error),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err("Diagnostic IPC session timeout".into());
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    if !verified_hello {
        return Err("Helper disconnected without verified IPC handshake".into());
    }
    drop(stdin);

    let remaining = deadline.saturating_duration_since(Instant::now());

    if remaining.is_zero() {
        return Err("Diagnostic IPC exit deadline expired".into());
    }

    let exit_code = guard.wait_for_exit(remaining.min(EXIT_TIMEOUT))?;
    worker.process_exited(exit_code)?;

    if !answered
        || !matches!(
            worker.outcome(),
            Some(TransactionOutcome::Success | TransactionOutcome::Cancelled)
        )
    {
        return Err("Diagnostic IPC did not finish successfully".into());
    }

    observe(&worker, None)?;

    Ok(serde_json::json!({
        "mode": "diagnostic-ipc-process",
        "outcome": if worker.outcome() == Some(TransactionOutcome::Success) { "success" } else { "cancelled" },
        "question_answered": true,
        "real_execution_enabled": false
    })
    .to_string())
}

fn run(arguments: &[String]) -> Result<String, String> {
    if arguments.len() == 2 && arguments[0] == "--diagnostic-ipc-process" {
        return run_diagnostic_ipc_process(Path::new(&arguments[1]));
    }

    if arguments == ["--diagnostic-ipc"] {
        return run_diagnostic_ipc(true);
    }

    if arguments == ["--diagnostic-ipc-invalid"] {
        return run_diagnostic_ipc(false);
    }

    if arguments.len() == 4 && arguments[0] == "--diagnostic-run" {
        return run_diagnostic_process(&arguments[1], Path::new(&arguments[2]), &arguments[3]);
    }

    if arguments.len() == 3 && arguments[0] == "--state-create" {
        let state = SupervisorState::diagnostic(&arguments[1])?;
        state.save(Path::new(&arguments[2]))?;
        return Ok("Diagnostic state created".into());
    }

    if arguments.len() == 2 && arguments[0] == "--state-show" {
        let state = SupervisorState::load(Path::new(&arguments[1]))?;
        return Ok(serde_json::json!({
            "transaction_id": state.transaction_id,
            "phase": state.phase,
            "outcome": state.outcome,
            "sequence": state.sequence,
            "real_execution_enabled": false
        })
        .to_string());
    }

    if arguments == ["--status"] {
        return Ok(supervisor_status_json());
    }

    Err("Transaction supervisor operations are not implemented".into())
}

const SOCKET_ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn verify_peer_uid(stream: &std::os::unix::net::UnixStream) -> Result<(), String> {
    use std::mem::{MaybeUninit, size_of};
    use std::os::fd::AsRawFd;

    let mut credentials = MaybeUninit::<libc::ucred>::uninit();
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;

    // SAFETY: The kernel writes at most length bytes into a correctly
    // allocated ucred buffer. The returned length is checked before read.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    };

    if result != 0 {
        return Err(format!(
            "Cannot read peer credentials: {}",
            std::io::Error::last_os_error()
        ));
    }

    if length as usize != size_of::<libc::ucred>() {
        return Err("Unexpected peer credential size".into());
    }

    // SAFETY: getsockopt succeeded and filled the entire ucred structure.
    let credentials = unsafe { credentials.assume_init() };

    // SAFETY: geteuid has no memory-safety preconditions.
    let expected_uid = unsafe { libc::geteuid() };

    if credentials.uid != expected_uid {
        return Err("Diagnostic client UID mismatch".into());
    }

    Ok(())
}

fn serve_status_once(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    use std::time::Instant;

    if path.exists() {
        return Err("Socket path already exists".into());
    }

    let listener = UnixListener::bind(path)
        .map_err(|error| format!("Cannot bind diagnostic socket: {error}"))?;

    let result = (|| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("Cannot secure diagnostic socket: {error}"))?;

        listener
            .set_nonblocking(true)
            .map_err(|error| format!("Cannot configure diagnostic socket: {error}"))?;

        let deadline = Instant::now() + SOCKET_ACCEPT_TIMEOUT;

        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    verify_peer_uid(&stream)?;
                    if send_user_hello(&mut stream).is_err() {
                        continue;
                    }
                    match read_diagnostic_command(&mut stream)? {
                        UserCommand::Disconnected => continue,
                        UserCommand::Command(command)
                            if command.as_object().is_some_and(|o| o.len() == 1)
                                && command["command"] == "status" => {}
                        _ => return Err("Status-only USER endpoint".into()),
                    }
                    writeln!(stream, "{}", supervisor_status_json())
                        .map_err(|error| format!("Cannot send diagnostic status: {error}"))?;
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err("Diagnostic socket accept timeout".into());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => {
                    return Err(format!("Cannot accept diagnostic client: {error}"));
                }
            }
        }
    })();

    drop(listener);
    let _ = std::fs::remove_file(path);
    result
}

/// Owns a diagnostic child process independently of the GUI.
/// No privileged or real package execution is permitted here.
struct SupervisedProcess {
    child: rwr_package_intelligence::process_guard::ChildGuard,
}

impl SupervisedProcess {
    fn poll_exit(&mut self) -> Result<Option<std::process::ExitStatus>, String> {
        self.child
            .0
            .try_wait()
            .map_err(|error| format!("Cannot inspect supervised child: {error}"))
    }
}

/// A supervisor must not exit while it owns a running transaction.
fn should_stop_supervisor(
    active_process: bool,
    idle_elapsed: std::time::Duration,
    idle_timeout: std::time::Duration,
) -> bool {
    !active_process && idle_elapsed >= idle_timeout
}

#[cfg(test)]
mod supervisor_lifetime_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn active_process_prevents_idle_shutdown() {
        assert!(!should_stop_supervisor(
            true,
            Duration::from_secs(60),
            Duration::from_secs(10),
        ));
    }

    #[test]
    fn idle_supervisor_can_stop() {
        assert!(should_stop_supervisor(
            false,
            Duration::from_secs(10),
            Duration::from_secs(10),
        ));
    }

    #[test]
    fn recent_activity_prevents_shutdown() {
        assert!(!should_stop_supervisor(
            false,
            Duration::from_secs(2),
            Duration::from_secs(10),
        ));
    }
}

// One read-only connection never owns or cancels the supervised process.
fn send_session_snapshot(
    stream: &mut std::os::unix::net::UnixStream,
    session: &mut SupervisorSession,
) -> Result<(), String> {
    let id = session.snapshot().transaction_id;
    let (token, _) = session.attach(&id)?;
    let result = send_status_response(stream, &(session.as_json().to_string() + "\n"));
    session.disconnect(token);
    result
}

fn send_status_response(
    stream: &mut std::os::unix::net::UnixStream,
    response: &str,
) -> Result<(), String> {
    stream
        .set_write_timeout(Some(std::time::Duration::from_millis(100)))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(response.as_bytes())
        .map_err(|error| error.to_string())
}

// Used for both observed exits and failure to launch the diagnostic child.
fn finish_diagnostic_session(
    session: &mut SupervisorSession,
    worker: &mut rwr_package_intelligence::transaction_worker::TransactionWorker,
    exit_code: i32,
    path: &Path,
) -> Result<(), String> {
    use rwr_package_intelligence::transaction_protocol::TransactionMessage;
    if exit_code == 0 {
        worker.receive(TransactionMessage::Completed { exit_code })?;
    } else {
        worker.receive(TransactionMessage::Failed(
            "Diagnostic process failed".into(),
        ))?;
    }
    worker.process_exited(exit_code)?;
    session.persist_from_worker(worker, path)?;
    Ok(())
}

type SharedDiagnosticSession = std::sync::Arc<std::sync::Mutex<SupervisorSession>>;

fn observe_session_helper(
    session: &mut SupervisorSession,
    worker: &rwr_package_intelligence::transaction_worker::TransactionWorker,
    message: Option<&rwr_package_intelligence::transaction_ipc::IpcMessage>,
    path: &Path,
) -> Result<(), String> {
    use rwr_package_intelligence::transaction_ipc::IpcMessage;
    session.persist_from_worker(worker, path)?;
    match message {
        Some(IpcMessage::Started) => session.record_progress("Diagnostic helper started")?,
        Some(IpcMessage::Progress(text)) => session.record_progress(text)?,
        _ => {}
    }
    Ok(())
}

fn start_session_helper(
    helper: std::path::PathBuf,
    path: std::path::PathBuf,
    session: SharedDiagnosticSession,
) -> std::thread::JoinHandle<Result<(), String>> {
    start_session_helper_mode(helper, path, session, false)
}

fn start_session_helper_mode(
    helper: std::path::PathBuf,
    path: std::path::PathBuf,
    session: SharedDiagnosticSession,
    interactive: bool,
) -> std::thread::JoinHandle<Result<(), String>> {
    std::thread::spawn(move || {
        let result = run_answered_diagnostic_helper(
            &helper,
            |worker, message| {
                let mut session = session.lock().map_err(|_| "Session lock poisoned")?;
                observe_session_helper(&mut session, worker, message, &path)
            },
            |id, text| {
                if !interactive {
                    return Ok(true);
                }
                session
                    .lock()
                    .map_err(|_| "Session lock poisoned")?
                    .ask_question(id, text)?;
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
                loop {
                    if let Some(answer) = session
                        .lock()
                        .map_err(|_| "Session lock poisoned")?
                        .take_answer()
                    {
                        return Ok(answer);
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err("Diagnostic question timed out".into());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            },
            interactive,
        );
        if let Err(error) = result {
            let mut session = session.lock().map_err(|_| "Session lock poisoned")?;
            if session.snapshot().outcome == "running" {
                let mut worker =
                    rwr_package_intelligence::transaction_worker::TransactionWorker::new();
                worker.receive(
                    rwr_package_intelligence::transaction_protocol::TransactionMessage::Started,
                )?;
                finish_diagnostic_session(&mut session, &mut worker, 1, &path)?;
            }
            eprintln!("RWR SUPERVISOR: diagnostic helper failed: {error}");
        }
        Ok(())
    })
}

// USER commands require a complete, versioned frame after the server hello.
enum UserCommand {
    Disconnected,
    Command(serde_json::Value),
}
fn send_user_hello(stream: &mut std::os::unix::net::UnixStream) -> Result<(), String> {
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    writeln!(
        stream,
        "{}",
        rwr_package_intelligence::supervisor_client::user_hello()
    )
    .map_err(|e| e.to_string())
}
fn read_diagnostic_command(
    stream: &mut std::os::unix::net::UnixStream,
) -> Result<UserCommand, String> {
    read_user_command_with_timeout(stream, std::time::Duration::from_secs(2))
}
fn read_user_command_with_timeout(
    stream: &mut std::os::unix::net::UnixStream,
    timeout: std::time::Duration,
) -> Result<UserCommand, String> {
    use std::io::Read;
    let deadline = std::time::Instant::now() + timeout;
    let mut bytes = Vec::new();
    // Small frames; one byte prevents consuming a second command accidentally.
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return if bytes.is_empty() {
                Ok(UserCommand::Disconnected)
            } else {
                Err("USER IPC command timeout".into())
            };
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|e| e.to_string())?;
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Ok(UserCommand::Disconnected),
            Ok(0) => return Err("Invalid diagnostic control frame: EOF".into()),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e)
                if bytes.is_empty()
                    && matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::ConnectionReset
                    ) =>
            {
                return Ok(UserCommand::Disconnected);
            }
            Err(e) => return Err(e.to_string()),
        }
        bytes.push(byte[0]);
        if bytes.len() > 4096 {
            return Err("Invalid diagnostic control frame".into());
        }
        if byte[0] == b'\n' {
            break;
        }
    }
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if value["protocol_version"] != rwr_package_intelligence::supervisor_client::USER_IPC_VERSION {
        return Err("USER IPC protocol version mismatch".into());
    }
    value
        .as_object_mut()
        .ok_or("Invalid USER command")?
        .remove("protocol_version");
    Ok(UserCommand::Command(value))
}

type SharedPlanValidation = std::sync::Arc<
    std::sync::Mutex<rwr_package_intelligence::supervisor_session::PlanValidationSession>,
>;

fn handle_plan_validation_command(
    command: &serde_json::Value,
    current: &mut Option<SharedPlanValidation>,
    task: &mut Option<std::thread::JoinHandle<()>>,
) -> Result<serde_json::Value, String> {
    use rwr_package_intelligence::supervisor_session::{
        PlanValidationSession, supervise_plan_validation,
    };
    use rwr_package_intelligence::transaction_ipc::PlanValidationRequest;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if std::env::var("RWR_PLAN_VALIDATION_ENABLED").as_deref() != Ok("1") {
        return Err("Read-only helper plan validation is not configured".into());
    }
    if command.as_object().is_none_or(|v| v.len() != 2) {
        return Err("Unexpected plan command fields".into());
    }
    let request = PlanValidationRequest::parse(&command["request"])?;
    let directory = std::env::var_os("RWR_PLAN_VALIDATION_DIRECTORY")
        .map(std::path::PathBuf::from)
        .ok_or("Missing private validation result directory")?;
    let meta = std::fs::symlink_metadata(&directory).map_err(|e| e.to_string())?;
    if !meta.is_dir()
        || meta.permissions().mode() & 0o777 != 0o700
        || meta.uid() != unsafe { libc::geteuid() }
    {
        return Err("Validation result directory is not private and owned".into());
    }
    let path = directory.join(format!("plan-{}.json", request.transaction_id));
    if let Some(active) = current.as_ref() {
        let active = active
            .lock()
            .map_err(|_| "Plan validation session poisoned")?;
        if active.request.transaction_id == request.transaction_id {
            if active.request != request {
                return Err("Transaction ID is already bound to a different plan".into());
            }
            return Ok(active.as_json());
        }
    }
    if std::fs::symlink_metadata(&path).is_ok() {
        return Ok(PlanValidationSession::load(&path, &request)?.as_json());
    }
    if command["command"] == "validation_status" {
        return Err("Unknown plan validation transaction".into());
    }
    if task.is_some() {
        return Err("Another plan validation is in progress".into());
    }
    let lab = std::env::var_os("RWR_PLAN_VALIDATION_LAB_ROOT").map(std::path::PathBuf::from);
    if request.scope != if lab.is_some() { "isolated" } else { "system" } {
        return Err("Supervisor validation scope mismatch".into());
    }
    // USER systemd mount sandbox implicitly maps only the user's UID. Root
    // ownership becomes overflow UID there, which must never be trusted as root.
    // Production USER validation runs the same read-only ALPM code in-process;
    // no external code is loaded/executed on an unverifiable ownership claim.
    let executable = if lab.is_some() {
        let helper = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/debug/rwr-update-helper");
        Some(supervisor_trust::open_diagnostic_helper(&helper, &helper)?)
    } else {
        None
    };
    let shared = std::sync::Arc::new(std::sync::Mutex::new(PlanValidationSession::new(
        request.clone(),
    )?));
    let running = shared.clone();
    *task = Some(std::thread::spawn(move || {
        let result = if let Some(executable) = executable {
            let mut command =
                std::process::Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()));
            command
                .arg("--validate-plan-lab")
                .arg(lab.expect("isolated validator root"));
            supervise_plan_validation(&mut command, &request, |worker| {
                running
                    .lock()
                    .map_err(|_| "Plan session poisoned")?
                    .observe(worker)
            })
        } else {
            rwr_package_intelligence::production_alpm_flow::validate_fresh_plan_claim(
                &request,
                rwr_package_intelligence::production_alpm_flow::PreparedFullUpgrade::prepare_system,
                "system",
            )
        };
        if let Ok(mut session) = running.lock() {
            if let Err(error) = session.complete_and_save(result, &path) {
                session.fail_without_persistence(format!(
                    "Cannot persist validation outcome: {error}"
                ));
            }
        }
    }));
    let response = shared
        .lock()
        .map_err(|_| "Plan session poisoned")?
        .as_json();
    *current = Some(shared);
    Ok(response)
}

fn serve_activated_socket() -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        return Err("USER supervisor refuses root execution".into());
    }
    let diagnostic_state_path =
        std::env::var_os("RWR_DIAGNOSTIC_STATE_PATH").map(std::path::PathBuf::from);

    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixListener;

    let expected_pid = std::process::id().to_string();

    let listen_pid = std::env::var("LISTEN_PID").map_err(|_| "Missing LISTEN_PID")?;

    let listen_fds = std::env::var("LISTEN_FDS").map_err(|_| "Missing LISTEN_FDS")?;

    if listen_pid != expected_pid || listen_fds != "1" {
        return Err("Invalid systemd socket activation environment".into());
    }

    // Clear activation environment before handling any client.
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
    }

    let fd = 3;

    let mut socket_type: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut length,
        )
    };

    if result != 0
        || length as usize != std::mem::size_of::<libc::c_int>()
        || socket_type != libc::SOCK_STREAM
    {
        return Err("Invalid activated socket type".into());
    }

    let mut accepting: libc::c_int = 0;
    length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut accepting as *mut libc::c_int).cast(),
            &mut length,
        )
    };

    if result != 0 || length as usize != std::mem::size_of::<libc::c_int>() || accepting != 1 {
        return Err("Activated socket is not listening".into());
    }

    let listener = unsafe { UnixListener::from_raw_fd(fd) };

    listener
        .set_nonblocking(true)
        .map_err(|error| format!("Cannot configure activated socket: {error}"))?;

    let idle_timeout = std::time::Duration::from_secs(10);
    let mut last_activity = std::time::Instant::now();

    // Diagnostic-only session. Never launches a privileged helper.
    let diagnostic_id = std::env::var("RWR_DIAGNOSTIC_TRANSACTION_ID").ok();

    let helper_path = std::env::var_os("RWR_DIAGNOSTIC_HELPER_PATH").map(std::path::PathBuf::from);
    if helper_path.is_some()
        && (diagnostic_id.is_none() || std::env::var_os("RWR_DIAGNOSTIC_SLEEP_SECONDS").is_some())
    {
        return Err("Diagnostic helper requires transaction ID and excludes sleep mode".into());
    }
    let restored_session = if let (Some(id), Some(path)) =
        (diagnostic_id.as_deref(), diagnostic_state_path.as_deref())
    {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Some(SupervisorSession::restore_finished(path, id)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("Cannot inspect diagnostic state: {error}")),
        }
    } else {
        None
    };
    let restoring = restored_session.is_some();
    let mut helper_session = None;
    let mut helper_task = None;
    if let Some(helper) = helper_path.filter(|_| !restoring) {
        let path = diagnostic_state_path
            .as_ref()
            .ok_or("Diagnostic state path required")?;
        let session = SupervisorSession::diagnostic(
            diagnostic_id.as_deref().ok_or("Missing diagnostic ID")?,
        )?;
        session.snapshot().save(path)?;
        let shared = std::sync::Arc::new(std::sync::Mutex::new(session));
        helper_task = Some(start_session_helper(helper, path.clone(), shared.clone()));
        helper_session = Some(shared);
    }
    let mut session = diagnostic_id
        .as_deref()
        .filter(|_| helper_session.is_none() && !restoring)
        .map(SupervisorSession::diagnostic)
        .transpose()?
        .or(restored_session);
    let mut supervised_process = if let Some(id) =
        diagnostic_id.filter(|_| helper_session.is_none() && !restoring)
    {
        let path = diagnostic_state_path
            .as_deref()
            .ok_or("Diagnostic state path required")?;

        let state = session
            .as_ref()
            .ok_or("Missing diagnostic session")?
            .snapshot();
        debug_assert_eq!(state.transaction_id, id);
        let mut worker = rwr_package_intelligence::transaction_worker::TransactionWorker::new();
        worker
            .receive(rwr_package_intelligence::transaction_protocol::TransactionMessage::Started)?;

        // Explicit diagnostic-only delay, never used by production updates.
        let diagnostic_delay = std::env::var("RWR_DIAGNOSTIC_SLEEP_SECONDS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()
            .map_err(|_| "Invalid diagnostic delay")?;

        let mut command = if let Some(seconds) = diagnostic_delay {
            if seconds == 0 || seconds > 20 {
                return Err("Diagnostic delay must be 1..=20 seconds".into());
            }

            let mut command = std::process::Command::new("/usr/bin/sleep");
            command.arg(seconds.to_string());
            command
        } else {
            std::process::Command::new("/usr/bin/true")
        };

        // Validate configuration before publishing a running transaction.
        state.save(path)?;
        match command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(child) => Some((
                SupervisedProcess {
                    child: rwr_package_intelligence::process_guard::ChildGuard(child),
                },
                worker,
            )),
            Err(error) => {
                finish_diagnostic_session(
                    session.as_mut().ok_or("Missing diagnostic session")?,
                    &mut worker,
                    1,
                    path,
                )?;
                eprintln!("RWR SUPERVISOR: diagnostic spawn failed: {error}");
                None
            }
        }
    } else {
        None
    };

    let mut plan_validation: Option<SharedPlanValidation> = None;
    let mut plan_task: Option<std::thread::JoinHandle<()>> = None;
    loop {
        if plan_task.as_ref().is_some_and(|task| task.is_finished()) {
            let _ = plan_task.take().ok_or("Missing plan task")?.join();
            last_activity = std::time::Instant::now();
        }

        if helper_task.as_ref().is_some_and(|task| task.is_finished()) {
            helper_task
                .take()
                .ok_or("Missing helper task")?
                .join()
                .map_err(|_| "Diagnostic helper task panicked")??;
            last_activity = std::time::Instant::now();
        }

        if let Some((process, worker)) = supervised_process.as_mut() {
            if let Some(status) = process.poll_exit()? {
                use std::os::unix::process::ExitStatusExt;
                let code = status
                    .code()
                    .unwrap_or_else(|| 128 + status.signal().unwrap_or(1));
                finish_diagnostic_session(
                    session.as_mut().ok_or("Missing diagnostic session")?,
                    worker,
                    code,
                    diagnostic_state_path
                        .as_deref()
                        .ok_or("Missing diagnostic state path")?,
                )?;
                // Give clients a full reconnect window after a long-running child.
                last_activity = std::time::Instant::now();
                supervised_process = None;
            }
        }

        match listener.accept() {
            Ok((mut stream, _)) => {
                if let Err(error) = verify_peer_uid(&stream) {
                    eprintln!("RWR SUPERVISOR: rejected diagnostic client: {error}");
                    continue;
                }

                if send_user_hello(&mut stream).is_err() {
                    continue;
                }
                let incoming = read_diagnostic_command(&mut stream);
                if matches!(incoming, Ok(UserCommand::Disconnected)) {
                    continue;
                }
                let mut plan_response = None;
                let command_result = (|| -> Result<(), String> {
                    let UserCommand::Command(command) = incoming? else {
                        return Ok(());
                    };
                    if command.as_object().is_some_and(|o| o.len() == 1)
                        && command["command"] == "status"
                    {
                        return Ok(());
                    }
                    if matches!(
                        command["command"].as_str(),
                        Some("validate_plan" | "validation_status")
                    ) {
                        if command["command"] == "validate_plan"
                            && (helper_task.is_some() || supervised_process.is_some())
                        {
                            return Err(
                                "Finish the current diagnostic session before plan validation"
                                    .into(),
                            );
                        }
                        plan_response = Some(handle_plan_validation_command(
                            &command,
                            &mut plan_validation,
                            &mut plan_task,
                        )?);
                        return Ok(());
                    }
                    if std::env::var("RWR_DIAGNOSTIC_CONTROL").as_deref() != Ok("1") {
                        return Err("Diagnostic control is disabled".into());
                    }
                    let object = command.as_object().ok_or("Invalid diagnostic command")?;
                    let id = command["transaction_id"]
                        .as_str()
                        .ok_or("Missing transaction ID")?;
                    match command["command"].as_str() {
                        Some("start") if object.len() == 2 => {
                            if plan_task.is_some() {
                                return Err("Plan validation is already running".into());
                            }

                            if let Some(shared) = helper_session.as_ref() {
                                if shared
                                    .lock()
                                    .map_err(|_| "Session lock poisoned")?
                                    .snapshot()
                                    .transaction_id
                                    == id
                                {
                                    return Ok(()); // Idempotent reconnect/retry, never replay.
                                }
                            }
                            if helper_session.is_some()
                                || session.is_some()
                                || supervised_process.is_some()
                            {
                                return Err(
                                    "A diagnostic session already exists; reconnect to read it"
                                        .into(),
                                );
                            }
                            let path = diagnostic_state_path
                                .as_ref()
                                .ok_or("Diagnostic state path required")?;
                            let state = SupervisorSession::diagnostic(id)?;
                            let helper = Path::new(env!("CARGO_MANIFEST_DIR"))
                                .join("target/debug/rwr-ipc-test-helper");
                            let _verified =
                                supervisor_trust::open_diagnostic_helper(&helper, &helper)?;
                            let state = if path.exists() {
                                SupervisorSession::restore_finished(path, id)?
                            } else {
                                state.snapshot().save(path)?;
                                state
                            };
                            let finished = state.snapshot().phase == "finished";
                            let shared = std::sync::Arc::new(std::sync::Mutex::new(state));
                            if !finished {
                                helper_task = Some(start_session_helper_mode(
                                    helper,
                                    path.clone(),
                                    shared.clone(),
                                    true,
                                ));
                            }
                            helper_session = Some(shared);
                            Ok(())
                        }
                        Some("answer") if object.len() == 4 => {
                            let question = command["question_id"]
                                .as_u64()
                                .ok_or("Missing question ID")?;
                            let approved = command["approved"]
                                .as_bool()
                                .ok_or("Missing diagnostic answer")?;
                            helper_session
                                .as_ref()
                                .ok_or("No diagnostic helper session")?
                                .lock()
                                .map_err(|_| "Session lock poisoned")?
                                .answer_question(id, question, approved)
                        }
                        _ => Err("Unsupported diagnostic command".into()),
                    }
                })();
                if let Err(error) = command_result {
                    let response = serde_json::json!({"real_execution_enabled":false,"error":error})
                        .to_string() + "\n";
                    let _ = send_status_response(&mut stream, &response);
                    continue;
                }

                if let Some(response) = plan_response {
                    let _ = send_status_response(&mut stream, &(response.to_string() + "\n"));
                    last_activity = std::time::Instant::now();
                    continue;
                }
                if let Some(shared) = plan_validation.as_ref() {
                    let response = shared
                        .lock()
                        .map_err(|_| "Plan session poisoned")?
                        .as_json();
                    let _ = send_status_response(&mut stream, &(response.to_string() + "\n"));
                    last_activity = std::time::Instant::now();
                    continue;
                }
                if let Some(shared) = helper_session.as_ref() {
                    let mut session = shared.lock().map_err(|_| "Session lock poisoned")?;
                    if let Err(error) = send_session_snapshot(&mut stream, &mut session) {
                        eprintln!("RWR SUPERVISOR: diagnostic client disconnected: {error}");
                    }
                } else if let Some(session) = session.as_mut() {
                    if let Err(error) = send_session_snapshot(&mut stream, session) {
                        eprintln!("RWR SUPERVISOR: diagnostic client disconnected: {error}");
                    }
                } else {
                    let response = if let Some(path) = diagnostic_state_path
                        .as_deref()
                        .filter(|path| path.exists())
                    {
                        SupervisorState::load(path)?.as_json().to_string() + "\n"
                    } else {
                        format!("{}\n", supervisor_status_json())
                    };
                    if let Err(error) = send_status_response(&mut stream, &response) {
                        eprintln!("RWR SUPERVISOR: diagnostic client disconnected: {error}");
                    }
                }

                last_activity = std::time::Instant::now();
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let active_process =
                    supervised_process.is_some() || helper_task.is_some() || plan_task.is_some();
                if should_stop_supervisor(active_process, last_activity.elapsed(), idle_timeout) {
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(format!("Activated socket accept failed: {error}"));
            }
        }
    }
}

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--serve-system") {
        return match serve_system_socket() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("RWR SYSTEM SUPERVISOR: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if std::env::var_os("LISTEN_FDS").is_some() || std::env::var_os("LISTEN_PID").is_some() {
        return match serve_activated_socket() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("RWR SUPERVISOR: {error}");
                ExitCode::FAILURE
            }
        };
    }

    let arguments: Vec<String> = std::env::args().skip(1).collect();

    if arguments.len() == 2 && arguments[0] == "--listen-status-once" {
        let path = Path::new(&arguments[1]);
        return match serve_status_once(path) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("RWR SUPERVISOR: {error}");
                ExitCode::FAILURE
            }
        };
    }

    match run(&arguments) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("RWR SUPERVISOR: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_session_full_cycle_and_launch_error() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::{fs::DirBuilderExt, net::UnixStream};
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("rwr-helper-cycle-{}-{nonce}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("state.json");
        let mut session = SupervisorSession::diagnostic("helper-cycle").unwrap();
        session.snapshot().save(&path).unwrap();
        let helper = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/debug/rwr-ipc-test-helper");
        let mut saw_started = false;
        let mut saw_question = false;
        run_observed_diagnostic_helper(&helper, |worker, message| {
            observe_session_helper(&mut session, worker, message, &path)?;
            use rwr_package_intelligence::transaction_ipc::IpcMessage;
            if matches!(message, Some(IpcMessage::Started)) {
                saw_started = true;
                let (mut server, client) = UnixStream::pair().unwrap();
                drop(client);
                assert!(send_session_snapshot(&mut server, &mut session).is_err());
                assert_eq!(session.snapshot().outcome, "running");
            }
            if matches!(message, Some(IpcMessage::Question { .. })) {
                saw_question = true;
                assert_eq!(session.as_json()["progress"], "Diagnostic helper started");
                assert!(!session.client_connected());
            }
            Ok(())
        })
        .unwrap();
        assert!(saw_started && saw_question);
        let (mut server, client) = UnixStream::pair().unwrap();
        send_session_snapshot(&mut server, &mut session).unwrap();
        let mut line = String::new();
        BufReader::new(client).read_line(&mut line).unwrap();
        let result: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(result["outcome"], "success");
        assert_eq!(result["real_execution_enabled"], false);
        assert_eq!(SupervisorState::load(&path).unwrap(), session.snapshot());

        let error_path = directory.join("failed.json");
        let failed = SupervisorSession::diagnostic("helper-error").unwrap();
        failed.snapshot().save(&error_path).unwrap();
        let shared = std::sync::Arc::new(std::sync::Mutex::new(failed));
        start_session_helper(
            directory.join("missing-helper"),
            error_path.clone(),
            shared.clone(),
        )
        .join()
        .unwrap()
        .unwrap();
        assert_eq!(shared.lock().unwrap().snapshot().outcome, "failure");
        assert_eq!(
            SupervisorState::load(&error_path).unwrap().outcome,
            "failure"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn diagnostic_finish_persists_success_failure_and_signal_for_reconnect() {
        use rwr_package_intelligence::transaction_protocol::TransactionMessage;
        use rwr_package_intelligence::transaction_worker::TransactionWorker;
        use std::os::unix::fs::DirBuilderExt;

        for (code, outcome) in [(0, "success"), (1, "failure"), (143, "failure")] {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir()
                .join(format!("rwr-finish-{}-{nonce}-{code}", std::process::id()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            let path = directory.join("state.json");
            let mut session = SupervisorSession::diagnostic("finish-test").unwrap();
            session.snapshot().save(&path).unwrap();
            let mut worker = TransactionWorker::new();
            worker.receive(TransactionMessage::Started).unwrap();
            finish_diagnostic_session(&mut session, &mut worker, code, &path).unwrap();
            let (token, result) = session.attach("finish-test").unwrap();
            assert_eq!(result.phase, "finished");
            assert_eq!(result.outcome, outcome);
            assert_eq!(result.sequence, 1);
            assert_eq!(SupervisorState::load(&path).unwrap(), result);
            session.disconnect(token);
            assert_eq!(session.attach("finish-test").unwrap().1, result);
            assert!(!session.real_execution_enabled());
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn session_socket_disconnect_and_reconnect_preserve_transaction() {
        use rwr_package_intelligence::transaction_protocol::TransactionMessage;
        use rwr_package_intelligence::transaction_state::UpdatePhase;
        use rwr_package_intelligence::transaction_worker::TransactionWorker;
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixStream;

        let mut session = SupervisorSession::diagnostic("socket-session").unwrap();
        let mut worker = TransactionWorker::new();
        worker.receive(TransactionMessage::Started).unwrap();
        for phase in [UpdatePhase::Ready, UpdatePhase::Commit] {
            worker.advance_phase(phase).unwrap();
            session.sync_from_worker(&worker).unwrap();
        }
        let before = session.snapshot();
        let (mut server, client) = UnixStream::pair().unwrap();
        drop(client);
        assert!(send_session_snapshot(&mut server, &mut session).is_err());
        assert!(!session.client_connected());
        assert_eq!(session.snapshot(), before);
        assert_eq!(worker.phase(), UpdatePhase::Commit);

        worker
            .receive(TransactionMessage::Completed { exit_code: 0 })
            .unwrap();
        worker.process_exited(0).unwrap();
        session.sync_from_worker(&worker).unwrap();
        for _ in 0..2 {
            let (mut server, client) = UnixStream::pair().unwrap();
            send_session_snapshot(&mut server, &mut session).unwrap();
            let mut line = String::new();
            BufReader::new(client).read_line(&mut line).unwrap();
            let state: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(state, session.snapshot().as_json());
            assert_eq!(state["outcome"], "success");
            assert_eq!(state["sequence"], 3);
            assert_eq!(state["real_execution_enabled"], false);
            assert!(!session.client_connected());
        }
    }

    #[test]
    fn status_reports_real_mode_disabled() {
        let value: serde_json::Value = serde_json::from_str(&supervisor_status_json()).unwrap();
        assert_eq!(value["real_execution_enabled"], false);
        assert_eq!(value["transaction_supervision_ready"], false);
        assert_eq!(value["service_integration_ready"], false);
    }

    #[test]
    fn transaction_execution_is_rejected() {
        assert!(run(&["--upgrade".into()]).is_err());
        assert!(run(&[]).is_err());
    }

    #[test]
    fn status_is_read_only() {
        assert!(run(&["--status".into()]).is_ok());
    }
}

// System service entry point. It starts privileged; it NEVER elevates a user
// service and never disables NoNewPrivileges. Both REAL gates remain closed.
fn serve_system_socket() -> Result<(), String> {
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::MetadataExt;
    if unsafe { libc::geteuid() } != 0
        || unsafe { libc::getuid() } != 0
        || unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1
    {
        return Err("System supervisor requires root with NoNewPrivileges".into());
    }
    if std::env::var("LISTEN_PID").ok() != Some(std::process::id().to_string())
        || std::env::var("LISTEN_FDS").as_deref() != Ok("1")
    {
        return Err("One systemd listening socket required".into());
    }
    let listener = unsafe { UnixListener::from_raw_fd(3) };
    let address = listener.local_addr().map_err(|e| e.to_string())?;
    let expected = Path::new(rwr_package_intelligence::supervisor_trust::SYSTEM_SOCKET);
    if address.as_pathname() != Some(expected) {
        return Err("Unexpected system socket address".into());
    }
    for parent in expected.ancestors().skip(1) {
        let meta = std::fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err("Unsafe system socket directory".into());
        }
    }
    type Registry =
        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, SystemExecution>>>;
    let sessions: Registry = Default::default();
    let clients = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for socket in listener.incoming() {
        let socket = socket.map_err(|e| e.to_string())?;
        use std::sync::atomic::Ordering::SeqCst;
        if clients.fetch_add(1, SeqCst) >= 32 {
            clients.fetch_sub(1, SeqCst);
            continue;
        }
        let sessions = sessions.clone();
        let clients = clients.clone();
        std::thread::spawn(move || {
            if let Err(error) = system_execution_client(socket, &sessions) {
                eprintln!("RWR SYSTEM SESSION: {error}");
            }
            clients.fetch_sub(1, SeqCst);
        });
    }
    Ok(())
}

struct SystemExecution {
    owner_uid: u32,
    control: std::sync::Arc<std::sync::Mutex<Option<std::os::unix::net::UnixStream>>>,
    session: std::sync::Arc<
        std::sync::Mutex<rwr_package_intelligence::supervisor_session::ExecutionSession>,
    >,
    answers: std::sync::mpsc::SyncSender<rwr_package_intelligence::transaction_ipc::IpcReply>,
}

// A world-connectable endpoint must bound the whole request, not each read.
// Keep buffered bytes after the first newline for subsequent question replies.
fn read_system_command_frame(
    input: &mut std::io::BufReader<std::os::unix::net::UnixStream>,
    timeout: std::time::Duration,
) -> Result<Option<serde_json::Value>, String> {
    use std::io::BufRead;
    let deadline = std::time::Instant::now() + timeout;
    let mut bytes = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err("System request frame deadline exceeded".into())
            };
        }
        input
            .get_ref()
            .set_read_timeout(Some(remaining))
            .map_err(|e| e.to_string())?;
        let available = match input.fill_buf() {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e)
                if bytes.is_empty()
                    && matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::ConnectionReset
                    ) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(format!("System request frame incomplete: {e}")),
        };
        if available.is_empty() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err("Invalid system request frame: EOF".into())
            };
        }
        let count = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |end| end + 1);
        if bytes.len() + count > 16384 {
            return Err("Oversized system request frame".into());
        }
        bytes.extend_from_slice(&available[..count]);
        let complete = available[count - 1] == b'\n';
        input.consume(count);
        if complete {
            return serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| e.to_string());
        }
    }
}

fn system_execution_client(
    mut socket: std::os::unix::net::UnixStream,
    sessions: &std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, SystemExecution>>>,
) -> Result<(), String> {
    use rwr_package_intelligence::{
        production_alpm_flow::SystemCommitAuthorization,
        supervisor_session::{ExecutionSession, supervise_execution},
        transaction_ipc::{IpcReply, PlanValidationRequest},
    };
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    socket
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    if !rwr_package_intelligence::supervisor_trust::send_system_server_hello(&mut socket)? {
        return Ok(());
    }
    let mut input = std::io::BufReader::new(socket.try_clone().map_err(|e| e.to_string())?);
    let Some(value) = read_system_command_frame(&mut input, std::time::Duration::from_secs(5))?
    else {
        return Ok(());
    };
    if value.as_object().is_some_and(|v| v.len() == 1) && value["command"] == "status" {
        let status = serde_json::json!({"component":"rwr-system-supervisor","protocol_version":1,"real_execution_enabled":rwr_package_intelligence::production_alpm_flow::real_flow_enabled(),"commit_authorized":false,"execution_locked":require_system_execution_enabled().is_err()});
        writeln!(socket, "{status}").map_err(|e| e.to_string())?;
        return Ok(());
    }
    if value.as_object().is_none_or(|v| v.len() != 2)
        || !matches!(
            value["command"].as_str(),
            Some("execute" | "attach" | "cancel")
        )
    {
        return Err("Invalid system session command".into());
    }
    let request = PlanValidationRequest::parse(&value["request"])?;
    let client_process =
        rwr_package_intelligence::supervisor_trust::PeerProcess::from_socket(&socket)?;
    let decision = if value["command"] == "attach" {
        rwr_package_intelligence::production_alpm_flow::SystemReadAuthorization::verify_supervisor_polkit(&request,&socket).map(SessionAuthority::Read)
    } else {
        require_system_execution_enabled()
            .and_then(|_| SystemCommitAuthorization::verify_supervisor_polkit(&request, &socket))
            .map(SessionAuthority::Execute)
    };
    let authority = match decision {
        Ok(authority) => authority,
        Err(error) => {
            let code = if error.contains("REAL MODE locked") {
                "execution_locked"
            } else {
                "authorization_denied"
            };
            return send_execution_refusal(&mut socket, &request, code, &error);
        }
    };
    let authorized_uid = authority.subject_uid();
    let mut control_authorized = matches!(&authority, SessionAuthority::Execute(_));
    let recovered = match authority.recover_execution_status() {
        Ok(status) => status,
        Err(error) => {
            return send_execution_refusal(&mut socket, &request, "history_unavailable", &error);
        }
    };
    let (session, answers, control) = {
        let mut registry = sessions.lock().map_err(|_| "Execution registry poisoned")?;
        if let Some(existing) = registry.get(&request.transaction_id) {
            if existing.owner_uid != authority.subject_uid() {
                return send_execution_refusal(
                    &mut socket,
                    &request,
                    "binding_mismatch",
                    "Execution belongs to another authorized subject",
                );
            }
            let session = existing
                .session
                .lock()
                .map_err(|_| "Execution session poisoned")?;
            if session.request != request {
                return send_execution_refusal(
                    &mut socket,
                    &request,
                    "binding_mismatch",
                    "Transaction ID already bound to another plan",
                );
            }
            if session.snapshot()["outcome"] != "running" {
                if let Some(status) = recovered
                    .as_ref()
                    .filter(|s| matches!(s["outcome"].as_str(), Some("success" | "failure")))
                {
                    let status = recovered_execution_snapshot(status.clone());
                    writeln!(socket, "{status}").map_err(|e| e.to_string())?;
                    return Ok(());
                }
            }
            drop(session);
            (
                existing.session.clone(),
                existing.answers.clone(),
                existing.control.clone(),
            )
        } else if let Some(status) = recovered {
            let status = recovered_execution_snapshot(status);
            writeln!(socket, "{status}").map_err(|e| e.to_string())?;
            return Ok(());
        } else {
            if value["command"] != "execute" {
                return send_execution_refusal(
                    &mut socket,
                    &request,
                    "unknown_transaction",
                    "Unknown execution transaction; attach never starts COMMIT",
                );
            }
            if registry.len() >= 64 {
                return Err(
                    "Execution history capacity reached; restart safely after recovery".into(),
                );
            }
            if registry.values().any(|s| {
                s.session
                    .lock()
                    .map(|s| s.snapshot()["outcome"] == "running")
                    .unwrap_or(true)
            }) {
                return Err("Another system transaction is active".into());
            }
            let session = std::sync::Arc::new(std::sync::Mutex::new(ExecutionSession::new(
                request.clone(),
            )?));
            let (tx, rx) = std::sync::mpsc::sync_channel(32);
            let executable = rwr_package_intelligence::supervisor_trust::open_system_helper()?;
            fn duplicate(fd: i32) -> Result<OwnedFd, String> {
                let owned = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
                if owned < 0 {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                Ok(unsafe { OwnedFd::from_raw_fd(owned) })
            }
            let executable = duplicate(executable.as_raw_fd())?;
            let proof = duplicate(socket.as_raw_fd())?;
            let (control, child_control) =
                std::os::unix::net::UnixStream::pair().map_err(|e| e.to_string())?;
            let child_control = duplicate(child_control.as_raw_fd())?;
            let mut command =
                std::process::Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()));
            command
                .arg("--supervised-upgrade")
                .env_clear()
                .env("PATH", "/usr/bin")
                .env("LANG", "C.UTF-8");
            let (proof_fd, control_fd) = (proof.as_raw_fd(), child_control.as_raw_fd());
            unsafe {
                command.pre_exec(move || {
                    if libc::dup2(proof_fd, 3) < 0 || libc::dup2(control_fd, 4) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let control = std::sync::Arc::new(std::sync::Mutex::new(Some(control)));
            let process_control = control.clone();
            let owner_uid = authority.subject_uid();
            let authority = match authority {
                SessionAuthority::Execute(authority) => authority,
                _ => return Err("Read authorization cannot start helper".into()),
            };
            let observed = session.clone();
            std::thread::spawn(move || {
                let result = supervise_execution(&mut command, &observed, rx, || {
                    authority.recover_execution_status()
                });
                if let Err(error) = result {
                    if let Ok(mut state) = observed.lock() {
                        state.supervision_lost(error);
                    }
                }
                if let Ok(mut connection) = process_control.lock() {
                    connection.take();
                }
                drop((proof, child_control, executable));
            });
            registry.insert(
                request.transaction_id.clone(),
                SystemExecution {
                    owner_uid,
                    control: control.clone(),
                    session: session.clone(),
                    answers: tx.clone(),
                },
            );
            (session, tx, control)
        }
    };
    if value["command"] == "cancel" {
        if let Some(control) = control
            .lock()
            .map_err(|_| "Execution control poisoned")?
            .as_mut()
        {
            let cancellation =
                serde_json::json!({"type":"cancel","transaction_id":request.transaction_id});
            writeln!(control, "{cancellation}")
                .and_then(|_| control.flush())
                .map_err(|e| e.to_string())?;
        }
    }
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(100)))
        .map_err(|e| e.to_string())?;
    let mut sequence = None;
    let mut last_sent = std::time::Instant::now();
    let mut pending = Vec::new();
    loop {
        if !client_process.is_alive()? {
            return Ok(());
        }
        let snapshot = session
            .lock()
            .map_err(|_| "Execution session poisoned")?
            .snapshot();
        if sequence != snapshot["sequence"].as_u64()
            || last_sent.elapsed() >= std::time::Duration::from_secs(5)
        {
            writeln!(socket, "{snapshot}").map_err(|e| e.to_string())?;
            sequence = snapshot["sequence"].as_u64();
            last_sent = std::time::Instant::now();
        }
        if snapshot["outcome"] != "running" {
            return Ok(());
        }
        let mut buffer = [0u8; 1024];
        match input.read(&mut buffer) {
            Ok(0) => return Ok(()), // Disconnection never cancels the owned process.
            Ok(n) => {
                pending.extend_from_slice(&buffer[..n]);
                if pending.len() > 16384 {
                    return Err("Oversized execution answer".into());
                }
                while let Some(end) = pending.iter().position(|b| *b == b'\n') {
                    let line: Vec<_> = pending.drain(..=end).collect();
                    let reply: serde_json::Value =
                        serde_json::from_slice(&line).map_err(|e| e.to_string())?;
                    if reply.as_object().is_none_or(|r| r.len() != 4)
                        || reply["command"] != "answer"
                        || reply["transaction_id"] != request.transaction_id
                    {
                        return Err("Mismatched execution answer".into());
                    }
                    let id = reply["id"].as_u64().ok_or("Missing question ID")?;
                    let approved = reply["approved"].as_bool().ok_or("Missing answer")?;
                    // Validate pending ID synchronously before queueing; stale
                    // clients cannot disrupt the process by injecting answers.
                    if snapshot["question"]["id"].as_u64() != Some(id) {
                        return Err("Stale answer".into());
                    }
                    match authorize_execution_reply(
                        &request,
                        &socket,
                        authorized_uid,
                        control_authorized,
                    ) {
                        Ok(()) => control_authorized = true,
                        Err(error) => {
                            let code = if error.contains("REAL MODE locked") {
                                "execution_locked"
                            } else {
                                "authorization_denied"
                            };
                            return send_execution_refusal(&mut socket, &request, code, &error);
                        }
                    }
                    answers
                        .try_send(IpcReply::Answer { id, approved })
                        .map_err(|e| e.to_string())?;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

#[cfg(test)]
mod system_entry_gate_tests {
    #[test]
    fn system_mutation_stops_with_real_disabled() {
        assert!(!super::real_execution_enabled());
        assert!(
            super::require_system_execution_enabled()
                .unwrap_err()
                .contains("REAL MODE locked")
        );
    }
}

fn recovered_execution_snapshot(mut status: serde_json::Value) -> serde_json::Value {
    status["operation"] = "execute-upgrade".into();
    status["protocol_version"] = 1.into();
    status["sequence"] = 0.into();
    status["progress"] =
        "Wynik odczytany z dziennika, bez ponowienia / Durable result recovered without replay"
            .into();
    status["question"] = serde_json::Value::Null;
    status
}

fn require_system_execution_enabled() -> Result<(), String> {
    if !real_execution_enabled()
        || !rwr_package_intelligence::production_alpm_flow::real_flow_enabled()
    {
        return Err("REAL MODE locked: system execution supervisor disabled".into());
    }
    Ok(())
}
enum SessionAuthority {
    Read(rwr_package_intelligence::production_alpm_flow::SystemReadAuthorization),
    Execute(rwr_package_intelligence::production_alpm_flow::SystemCommitAuthorization),
}
impl SessionAuthority {
    fn subject_uid(&self) -> u32 {
        match self {
            Self::Read(a) => a.subject_uid(),
            Self::Execute(a) => a.subject_uid(),
        }
    }
    fn recover_execution_status(&self) -> Result<Option<serde_json::Value>, String> {
        match self {
            Self::Read(a) => a.recover_execution_status(),
            Self::Execute(a) => a.recover_execution_status(),
        }
    }
}

fn send_execution_refusal(
    socket: &mut std::os::unix::net::UnixStream,
    request: &rwr_package_intelligence::transaction_ipc::PlanValidationRequest,
    code: &str,
    error: &str,
) -> Result<(), String> {
    let value = serde_json::json!({"operation":"execution-refusal","protocol_version":1,"transaction_id":request.transaction_id,"plan_digest":request.plan_digest,"code":code,"error":error.chars().take(1024).collect::<String>(),"commit_authorized":false,"request_executed":false,"real_execution_enabled":rwr_package_intelligence::production_alpm_flow::real_flow_enabled()});
    rwr_package_intelligence::supervisor_client::validate_execution_refusal(&value, request)?;
    writeln!(socket, "{value}").map_err(|e| e.to_string())
}

// A read connection cannot reply to solver questions using .inspect authority.
// Both already-approved and newly-approved control paths retain the REAL gate.
fn authorize_execution_reply(
    request: &rwr_package_intelligence::transaction_ipc::PlanValidationRequest,
    socket: &std::os::unix::net::UnixStream,
    owner: u32,
    already_authorized: bool,
) -> Result<(), String> {
    require_system_execution_enabled()?;
    if already_authorized {
        return Ok(());
    }
    let authority=rwr_package_intelligence::production_alpm_flow::SystemCommitAuthorization::verify_supervisor_polkit(request,socket)?;
    if authority.subject_uid() != owner {
        return Err("Question owner changed".into());
    }
    Ok(())
}
#[cfg(test)]
mod read_reply_gate_tests {
    #[test]
    fn read_and_cached_control_cannot_answer_with_real_disabled() {
        let request = rwr_package_intelligence::transaction_ipc::PlanValidationRequest {
            transaction_id: "reply-denied".into(),
            plan_digest: "a".repeat(64),
            scope: "system".into(),
        };
        let (socket, _) = std::os::unix::net::UnixStream::pair().unwrap();
        for cached in [false, true] {
            assert!(
                super::authorize_execution_reply(
                    &request,
                    &socket,
                    unsafe { libc::getuid() },
                    cached
                )
                .unwrap_err()
                .contains("REAL MODE locked")
            );
        }
    }
}

#[cfg(test)]
mod empty_system_request_tests {
    use super::*;
    use std::io::{Read, Write};
    #[test]
    fn disconnect_after_hello_is_clean_but_partial_json_is_rejected() {
        for partial in [false, true] {
            let (server, mut client) = std::os::unix::net::UnixStream::pair().unwrap();
            let task =
                std::thread::spawn(move || system_execution_client(server, &Default::default()));
            client.write_all(b"R").unwrap();
            let mut hello = [0];
            client.read_exact(&mut hello).unwrap();
            assert_eq!(hello, [b'R']);
            if partial {
                client.write_all(b"{").unwrap();
            }
            client.shutdown(std::net::Shutdown::Both).unwrap();
            let result = task.join().unwrap();
            if partial {
                assert!(result.unwrap_err().contains("Invalid system request frame"));
            } else {
                assert!(result.is_ok());
            }
        }
    }
}

#[cfg(test)]
mod readonly_status_protocol_tests {
    use super::*;
    use std::io::{BufRead, Read, Write};
    #[test]
    fn status_and_reconnect_do_not_create_sessions() {
        // Protocol test only: no root credentials or Polkit success fabricated.
        let sessions = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        for _ in 0..2 {
            let (server, mut client) = std::os::unix::net::UnixStream::pair().unwrap();
            let registry = sessions.clone();
            let task = std::thread::spawn(move || system_execution_client(server, &registry));
            client.write_all(b"R").unwrap();
            let mut hello = [0];
            client.read_exact(&mut hello).unwrap();
            assert_eq!(hello, [b'R']);
            writeln!(client, "{}", serde_json::json!({"command":"status"})).unwrap();
            let mut frame = Vec::new();
            std::io::BufReader::new(client)
                .take(4097)
                .read_until(b'\n', &mut frame)
                .unwrap();
            let value: serde_json::Value = serde_json::from_slice(&frame).unwrap();
            assert_eq!(value["component"], "rwr-system-supervisor");
            assert_eq!(value["protocol_version"], 1);
            assert_eq!(value["real_execution_enabled"], false);
            assert_eq!(value["commit_authorized"], false);
            assert_eq!(value["execution_locked"], true);
            task.join().unwrap().unwrap();
            assert!(sessions.lock().unwrap().is_empty());
        }
    }
}

#[cfg(test)]
mod user_command_transport_tests {
    use super::*;
    #[test]
    fn user_empty_eof_is_clean_but_partial_frame_is_rejected() {
        for bytes in [b"".as_slice(), b"{}".as_slice()] {
            let (mut server, mut client) = std::os::unix::net::UnixStream::pair().unwrap();
            client.write_all(bytes).unwrap();
            drop(client);
            let result =
                read_user_command_with_timeout(&mut server, std::time::Duration::from_millis(50));
            if bytes.is_empty() {
                assert!(matches!(result, Ok(UserCommand::Disconnected)));
            } else {
                assert!(result.is_err());
            }
        }
    }
    #[test]
    fn user_command_version_is_mandatory_before_dispatch() {
        for version in [None, Some(99), Some(1)] {
            let (mut server, mut client) = std::os::unix::net::UnixStream::pair().unwrap();
            let mut command = serde_json::json!({"command":"status"});
            if let Some(version) = version {
                command["protocol_version"] = version.into();
            }
            writeln!(client, "{command}").unwrap();
            let result =
                read_user_command_with_timeout(&mut server, std::time::Duration::from_millis(50));
            if version == Some(1) {
                let Ok(UserCommand::Command(value)) = result else {
                    panic!("Missing command");
                };
                assert_eq!(value, serde_json::json!({"command":"status"}));
            } else {
                assert!(result.is_err());
            }
        }
    }
    #[test]
    fn user_idle_timeout_is_bounded_and_clean() {
        let (mut server, _client) = std::os::unix::net::UnixStream::pair().unwrap();
        let start = std::time::Instant::now();
        assert!(matches!(
            read_user_command_with_timeout(&mut server, std::time::Duration::from_millis(20)),
            Ok(UserCommand::Disconnected)
        ));
        assert!(start.elapsed() < std::time::Duration::from_millis(200));
    }
}

#[cfg(test)]
mod system_frame_deadline_tests {
    use super::read_system_command_frame;
    use std::io::{BufReader, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};
    #[test]
    fn trickling_unauthorized_peer_cannot_hold_a_slot_indefinitely() {
        let (server, mut peer) = UnixStream::pair().unwrap();
        let sender = std::thread::spawn(move || {
            for _ in 0..100 {
                if peer.write_all(b" ").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let mut reader = BufReader::new(server);
        let start = Instant::now();
        assert!(read_system_command_frame(&mut reader, Duration::from_millis(50)).is_err());
        assert!(start.elapsed() < Duration::from_millis(400));
        drop(reader);
        sender.join().unwrap();
    }
    #[test]
    fn bounded_command_retains_buffered_answer_without_dispatching_it() {
        let (server, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(b"{\"command\":\"status\"}\n{\"command\":\"answer\"}\n")
            .unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reader = BufReader::new(server);
        let value = read_system_command_frame(&mut reader, Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(value["command"], "status");
        let mut remainder = String::new();
        reader.read_to_string(&mut remainder).unwrap();
        assert_eq!(remainder, "{\"command\":\"answer\"}\n");
    }
}

// Test builds of this binary never reach the production host (deny-only).
rwr_package_intelligence::isolate_test_binary!();
