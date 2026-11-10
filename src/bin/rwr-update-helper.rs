//! RWR PACKAGE INTELLIGENCE — production helper entry point.
//! Read-only plan validation and a gated signed transaction backend.
//! System execution remains disabled; laboratory COMMIT requires attestation.

#[path = "../transaction_ipc.rs"]
mod transaction_ipc;

use rwr_package_intelligence::libalpm_ffi;

fn real_execution_enabled() -> bool {
    rwr_package_intelligence::supervisor_trust::system_execution_enabled()
}

/// Open the configured system libalpm handle for future production integration.
/// Read-only validation: no synchronization, transaction or package changes.
#[allow(dead_code)]
fn inspect_system_alpm() -> Result<usize, String> {
    let handle = libalpm_ffi::AlpmHandle::open_system_configured()?;
    handle.local_package_count()
}

fn validate_ipc_reply(line: &str) -> Result<transaction_ipc::IpcReply, String> {
    transaction_ipc::parse_reply(line)
}

fn validate_execution_request() -> Result<(), &'static str> {
    if !real_execution_enabled() {
        return Err("REAL MODE locked: privileged service validation incomplete");
    }

    Ok(())
}

unsafe extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

fn run_lab_prepare() -> Result<(), String> {
    use rwr_package_intelligence::alpm_lab::AlpmLab;
    use std::io::{self, Write};

    let stdout = io::stdout();
    let mut output = stdout.lock();

    writeln!(
        output,
        "{}",
        serde_json::json!({
            "type": "started"
        })
    )
    .map_err(|e| e.to_string())?;

    output.flush().map_err(|e| e.to_string())?;

    let result = (|| -> Result<(), String> {
        rwr_package_intelligence::sandbox_attestation::verify_lab_sandbox()?;
        let lab = AlpmLab::create()?;
        // O7-B: real callback codes collected during isolated PREPARE.
        // The laboratory method verifies the fixed transaction plan.
        let events = lab.prepare_isolated_transaction_with_events()?;

        if events != [5, 6, 7, 8] {
            return Err("Unexpected isolated libalpm event sequence".into());
        }

        for code in events {
            writeln!(
                output,
                "{}",
                serde_json::json!({
                    "type": "progress",
                    "text": format!("ALPM_EVENT:{code}")
                })
            )
            .map_err(|e| e.to_string())?;
            output.flush().map_err(|e| e.to_string())?;
        }

        writeln!(
            output,
            "{}",
            serde_json::json!({
                "type": "progress",
                "text": format!(
                    "{} -> {}",
                    "rwr-test-package",
                    "1.1-1"
                )
            })
        )
        .map_err(|e| e.to_string())?;

        writeln!(
            output,
            "{}",
            serde_json::json!({
                "type": "completed",
                "exit_code": 0
            })
        )
        .map_err(|e| e.to_string())?;

        output.flush().map_err(|e| e.to_string())?;

        Ok(())
    })();

    if let Err(ref error) = result {
        writeln!(
            output,
            "{}",
            serde_json::json!({
                "type": "failed",
                "text": error
            })
        )
        .map_err(|e| e.to_string())?;

        output.flush().map_err(|e| e.to_string())?;
    }

    result
}

fn run_lab_commit() -> Result<(), String> {
    use rwr_package_intelligence::alpm_lab::AlpmLab;
    use std::io::{self, Write};

    let stdout = io::stdout();
    let mut output = stdout.lock();

    writeln!(
        output,
        "{}",
        serde_json::json!({
            "type": "started"
        })
    )
    .map_err(|e| e.to_string())?;

    output.flush().map_err(|e| e.to_string())?;

    let result = (|| -> Result<(), String> {
        let lab = AlpmLab::create()?;
        // Controlled COMMIT inside the isolated laboratory root only.
        // The attestation token is unobtainable outside the sandbox.
        // The flow reports honestly which stages libalpm performed.
        let (events, sync_executed, download_executed, signatures_executed) =
            lab.run_isolated_commit_with_events()?;

        writeln!(
            output,
            "{}",
            serde_json::json!({
                "type": "progress",
                "text": format!("FLOW:sync={}", sync_executed)
            })
        )
        .map_err(|e| e.to_string())?;

        writeln!(
            output,
            "{}",
            serde_json::json!({
                "type": "progress",
                "text": format!("FLOW:download={}", download_executed)
            })
        )
        .map_err(|e| e.to_string())?;

        writeln!(
            output,
            "{}",
            serde_json::json!({
                "type": "progress",
                "text": format!("FLOW:signatures={}", signatures_executed)
            })
        )
        .map_err(|e| e.to_string())?;

        for code in events {
            writeln!(
                output,
                "{}",
                serde_json::json!({
                    "type": "progress",
                    "text": format!("ALPM_EVENT:{code}")
                })
            )
            .map_err(|e| e.to_string())?;
            output.flush().map_err(|e| e.to_string())?;
        }

        writeln!(
            output,
            "{}",
            serde_json::json!({
                "type": "completed",
                "exit_code": 0
            })
        )
        .map_err(|e| e.to_string())?;

        output.flush().map_err(|e| e.to_string())?;

        Ok(())
    })();

    if let Err(ref error) = result {
        writeln!(
            output,
            "{}",
            serde_json::json!({
                "type": "failed",
                "text": error
            })
        )
        .map_err(|e| e.to_string())?;

        output.flush().map_err(|e| e.to_string())?;
    }

    result
}

// Serialize a user cancellation against the last pre-COMMIT boundary.
// A delayed control frame must never arm libalpm's interrupt during installation.
struct PreCommitCancellation {
    open: std::sync::Mutex<bool>,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl PreCommitCancellation {
    fn new(cancel: std::sync::Arc<std::sync::atomic::AtomicBool>) -> Self {
        Self {
            open: std::sync::Mutex::new(true),
            cancel,
        }
    }
    fn request(&self) -> Result<bool, String> {
        let open = self
            .open
            .lock()
            .map_err(|_| "Cancellation boundary poisoned")?;
        if !*open {
            return Ok(false);
        }
        self.cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(true)
    }
    fn close_for_commit(&self) -> Result<(), String> {
        let mut open = self
            .open
            .lock()
            .map_err(|_| "Cancellation boundary poisoned")?;
        *open = false;
        if self.cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("Cancelled before COMMIT; nothing installed".into());
        }
        Ok(())
    }
}

fn run_system_upgrade(supervised: bool) -> Result<(), String> {
    use rwr_package_intelligence::{
        production_alpm_flow::{
            PreparedFullUpgrade, SystemCommitAuthorization, execute_authorized_system_upgrade,
        },
        transaction_ipc::PlanValidationRequest,
    };
    use std::io::{BufRead, Read, Write};
    use std::os::fd::FromRawFd;
    validate_execution_request().map_err(str::to_owned)?;
    if !supervised {
        return Err("GUI-owned execution is disabled; use the system supervisor".into());
    }
    let mut bytes = Vec::new();
    std::io::BufReader::new(std::io::stdin().lock())
        .take((transaction_ipc::MAX_MESSAGE_BYTES + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > transaction_ipc::MAX_MESSAGE_BYTES || bytes.last() != Some(&b'\n') {
        return Err("Invalid upgrade IPC frame".into());
    }
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if value["operation"] != "execute-upgrade" {
        return Err("Read-only validation claims cannot request execution".into());
    }
    value["operation"] = "validate-plan".into();
    let request = PlanValidationRequest::parse(&value)?;
    if request.scope != "system" {
        return Err("Laboratory claims cannot authorize a system update".into());
    }
    let mut domain = 0i32;
    let mut size = std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            3,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            (&mut domain as *mut i32).cast(),
            &mut size,
        )
    } != 0
        || domain != libc::AF_UNIX
    {
        return Err("Authenticated launcher socket required".into());
    }
    let mut socket_type = 0i32;
    size = std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            3,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut i32).cast(),
            &mut size,
        )
    } != 0
        || socket_type != libc::SOCK_STREAM
    {
        return Err("Launcher proof must be a Unix stream".into());
    }
    let launcher = unsafe { std::os::unix::net::UnixStream::from_raw_fd(3) };
    let auth = SystemCommitAuthorization::verify_polkit(&request, &launcher)?;
    if let Some(status) = auth.recover_execution_status()? {
        // An authenticated reconnect returns history, never a second COMMIT.
        // An incomplete journal may still have a live owner: do not replay it.
        let mut output = std::io::stdout().lock();
        writeln!(
            output,
            "{}",
            serde_json::json!({"type":"progress","text":status.to_string()})
        )
        .and_then(|_| output.flush())
        .map_err(|e| e.to_string())?;
        return match status["outcome"].as_str() {
            Some("success") => Ok(()),
            Some("failure") => Err("Persisted transaction failed; COMMIT will not be replayed; recovery may be required".into()),
            _ => Err("Persisted transaction outcome UNKNOWN; COMMIT will not be replayed; consult its supervisor and journal".into()),
        };
    }
    drop(launcher); // The original GUI proof is not inherited by GPG/hooks.
    let launcher = if supervised {
        // FD 3 identifies the original GUI subject for Polkit. FD 4 belongs
        // to the service, so GUI disconnection is not a cancellation request.
        let control = unsafe { std::os::unix::net::UnixStream::from_raw_fd(4) };
        let peer = rwr_package_intelligence::supervisor_trust::PeerProcess::from_socket(&control)?;
        if peer.credentials().uid != 0
            || unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1
        {
            return Err(
                "Supervised execution requires the root service and NoNewPrivileges".into(),
            );
        }
        rwr_package_intelligence::supervisor_trust::verify_system_supervisor_peer(&control)?;
        if unsafe {
            libc::fcntl(
                std::os::fd::AsRawFd::as_raw_fd(&control),
                libc::F_SETFD,
                libc::FD_CLOEXEC,
            )
        } < 0
        {
            return Err(
                "Cannot protect supervisor control descriptor from hook inheritance".into(),
            );
        }
        control
    } else {
        return Err("GUI-owned execution is disabled; use the system supervisor".into());
    };
    let service_peer =
        rwr_package_intelligence::supervisor_trust::PeerProcess::from_socket(&launcher)?;
    let service_probe = launcher.try_clone().map_err(|e| e.to_string())?;
    let _execution_lease = auth.acquire_execution_lease()?;
    let fresh = PreparedFullUpgrade::prepare_system()?;
    fresh.validate_claim(&request)?;
    // A helper-owned confirmation is meaningful only in combination with the
    // independently verified Polkit capability, never from GUI data alone.
    let confirmed = fresh.confirm_and_revalidate(true)?;
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let connected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    launcher
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .map_err(|e| e.to_string())?;
    let cancellation = std::sync::Arc::new(PreCommitCancellation::new(cancel.clone()));
    let (c, online, finished, id) = (
        cancellation.clone(),
        connected.clone(),
        done.clone(),
        request.transaction_id.clone(),
    );
    std::thread::spawn(move || {
        let mut input = std::io::BufReader::new(launcher);
        while !finished.load(std::sync::atomic::Ordering::Relaxed) {
            let mut bytes = Vec::new();
            match input.by_ref().take(4097).read_until(b'\n', &mut bytes) {
                Err(e)
                    if bytes.is_empty()
                        && matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                {
                    continue;
                }
                Ok(n) if n > 0 && bytes.len() <= 4096 && bytes.last() == Some(&b'\n') => {
                    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if value.as_object().is_some_and(|v| v.len() == 2)
                            && value["type"] == "cancel"
                            && value["transaction_id"] == id
                        {
                            // Late requests do not interrupt an installing ALPM.
                            // Lock errors fail the control channel closed.
                            if c.request().is_err() {
                                online.store(false, std::sync::atomic::Ordering::Relaxed);
                                break;
                            }
                            continue;
                        }
                    }
                    online.store(false, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
                _ => {
                    online.store(false, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
            }
        }
    });
    let (progress_tx, progress_rx) = std::sync::mpsc::sync_channel::<serde_json::Value>(128);
    let (reply_tx, reply_rx) = std::sync::mpsc::channel();
    let questions = std::sync::Arc::new(
        rwr_package_intelligence::libalpm_ffi::ExecutionQuestions::new(
            progress_tx.clone(),
            reply_rx,
            connected.clone(),
            cancel.clone(),
        ),
    );
    let reply_connected = connected.clone();
    std::thread::spawn(move || {
        let mut input = std::io::BufReader::new(std::io::stdin());
        loop {
            let mut bytes = Vec::new();
            match input.by_ref().take(4097).read_until(b'\n', &mut bytes) {
                Ok(n) if n > 0 && bytes.len() <= 4096 && bytes.last() == Some(&b'\n') => {
                    let parsed = std::str::from_utf8(&bytes)
                        .ok()
                        .and_then(|line| transaction_ipc::parse_reply(line.trim_end()).ok());
                    if let Some(transaction_ipc::IpcReply::Answer { id, approved }) = parsed {
                        if reply_tx.send((id, approved)).is_ok() {
                            continue;
                        }
                    }
                }
                _ => {}
            }
            reply_connected.store(false, std::sync::atomic::Ordering::Relaxed);
            break;
        }
    });
    let progress_connected = connected.clone();
    let progress_thread = std::thread::spawn(move || {
        while let Ok(value) = progress_rx.recv() {
            let mut output = std::io::stdout().lock();
            if writeln!(output, "{value}")
                .and_then(|_| output.flush())
                .is_err()
            {
                progress_connected.store(false, std::sync::atomic::Ordering::Relaxed);
            }
        }
    });
    let result = execute_authorized_system_upgrade(
        auth,
        confirmed,
        cancel,
        connected,
        || {
            use std::os::fd::AsRawFd;
            if !service_peer.is_alive().unwrap_or(false) {
                return false;
            }
            let mut byte = 0u8;
            let result = unsafe {
                libc::recv(
                    service_probe.as_raw_fd(),
                    (&mut byte as *mut u8).cast(),
                    1,
                    libc::MSG_PEEK | libc::MSG_DONTWAIT,
                )
            };
            result > 0
                || (result < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock)
        },
        progress_tx.clone(),
        questions.clone(),
        |value| {
            if value["type"] == "phase" && value["phase"] == "commit" {
                cancellation.close_for_commit()?;
            }
            let mut out = std::io::stdout().lock();
            writeln!(out, "{value}")
                .and_then(|_| out.flush())
                .map_err(|e| e.to_string())
        },
    );
    drop(questions);
    drop(progress_tx);
    let _ = progress_thread.join();
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    result
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();

    if arguments == ["--upgrade"] || arguments == ["--supervised-upgrade"] {
        use std::io::Write;
        let _ = writeln!(
            std::io::stdout(),
            "{}",
            serde_json::json!({"type":"started"})
        );
        let result = run_system_upgrade(arguments == ["--supervised-upgrade"]);
        let (message, code) = match result {
            Ok(()) => (serde_json::json!({"type":"completed","exit_code":0}), 0),
            Err(error) => (
                serde_json::json!({"type":"failed","text":error.chars().take(2048).collect::<String>()}),
                1,
            ),
        };
        let _ = writeln!(std::io::stdout(), "{message}");
        std::process::exit(code);
    }

    if arguments.len() == 2 && arguments[0] == "--lab-signed-case" {
        use std::io::Write;
        let result = (|| -> Result<(), String> {
            rwr_package_intelligence::sandbox_attestation::verify_lab_sandbox()?;
            let mut output = std::io::stdout().lock();
            writeln!(output, "{}", serde_json::json!({"type":"started"}))
                .map_err(|e| e.to_string())?;
            let lab = rwr_package_intelligence::alpm_lab::AlpmLab::create()?;
            let evidence = lab.run_signed_transaction_case(&arguments[1])?;
            writeln!(
                output,
                "{}",
                serde_json::json!({"type":"progress","text":evidence.to_string()})
            )
            .and_then(|_| output.flush())
            .map_err(|e| e.to_string())?;
            writeln!(
                output,
                "{}",
                serde_json::json!({"type":"completed","exit_code":0})
            )
            .and_then(|_| output.flush())
            .map_err(|e| e.to_string())?;
            Ok(())
        })();
        if let Err(error) = result {
            eprintln!("RWR SIGNED LAB: {error}");
            std::process::exit(1);
        }
        return;
    }

    if arguments == ["--validate-plan"]
        || (arguments.len() == 2 && arguments[0] == "--validate-plan-lab")
    {
        // This endpoint can only validate a claim. It never requests privilege
        // or interprets GUI confirmation as execution authorization.
        let isolated = arguments.len() == 2;
        if isolated && unsafe { libc_geteuid() } == 0 {
            eprintln!("RWR: isolated plan validation refuses privileged execution");
            std::process::exit(1);
        }
        let root = arguments.get(1).map(std::path::PathBuf::from);
        let result = rwr_package_intelligence::production_alpm_flow::serve_plan_validation(
            &mut std::io::BufReader::new(std::io::stdin().lock()),
            &mut std::io::stdout().lock(),
            || {
                if let Some(root) = &root {
                    rwr_package_intelligence::production_alpm_flow::PreparedFullUpgrade::prepare_isolated(root)
                } else {
                    rwr_package_intelligence::production_alpm_flow::PreparedFullUpgrade::prepare_system()
                }
            },
            if isolated { "isolated" } else { "system" },
        );
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }

    if arguments == ["--lab-prepare"] || arguments == ["--lab-commit"] {
        if unsafe { libc_geteuid() } == 0 {
            eprintln!("RWR LAB: refusing privileged execution");
            std::process::exit(1);
        }

        let result = if arguments[0] == "--lab-prepare" {
            run_lab_prepare()
        } else {
            run_lab_commit()
        };

        if let Err(error) = result {
            eprintln!("RWR LAB ERROR: {error}");
            std::process::exit(1);
        }

        return;
    }

    use std::io::{self, Write};

    let reason = match validate_execution_request() {
        Ok(()) => "REAL MODE locked: unexpected authorization state",
        Err(reason) => reason,
    };

    let stdout = io::stdout();
    let mut output = stdout.lock();

    let result = writeln!(output, "{}", serde_json::json!({"type":"started"}))
        .and_then(|_| {
            writeln!(
                output,
                "{}",
                serde_json::json!({
                    "type":"failed",
                    "text":reason
                })
            )
        })
        .and_then(|_| output.flush());

    if let Err(error) = result {
        eprintln!("RWR HELPER IPC ERROR: {error}");
    }

    eprintln!("RWR HELPER: {reason}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_system_alpm_is_readable() {
        let count = inspect_system_alpm().expect("Cannot initialize configured system libalpm");
        assert!(count > 0, "Expected installed packages in system database");
    }

    #[test]
    fn production_execution_is_disabled() {
        assert!(!real_execution_enabled());
    }

    #[test]
    fn helper_rejects_execution() {
        assert!(validate_execution_request().is_err());
    }
}

#[cfg(test)]
mod stage_2_6_ipc_tests {
    use super::*;

    #[test]
    fn accepts_valid_ipc_reply() {
        let reply = validate_ipc_reply(r#"{"type":"answer","id":1,"approved":false}"#).unwrap();

        assert_eq!(
            reply,
            transaction_ipc::IpcReply::Answer {
                id: 1,
                approved: false,
            }
        );
    }

    #[test]
    fn rejects_unknown_ipc_command() {
        assert!(validate_ipc_reply(r#"{"type":"execute","command":"pacman"}"#).is_err());
    }

    #[test]
    fn rejects_extra_ipc_fields() {
        assert!(
            validate_ipc_reply(r#"{"type":"answer","id":1,"approved":true,"command":"pacman"}"#)
                .is_err()
        );
    }

    #[test]
    fn rejects_oversized_ipc_reply() {
        let input = "x".repeat(transaction_ipc::MAX_MESSAGE_BYTES + 1);
        assert!(validate_ipc_reply(&input).is_err());
    }

    #[test]
    fn real_execution_remains_disabled() {
        assert!(validate_execution_request().is_err());
        assert!(!real_execution_enabled());
    }
}

#[cfg(test)]
mod stage_4_11e_libalpm_link_tests {
    #[test]
    fn helper_links_to_real_libalpm() {
        let version = rwr_package_intelligence::libalpm_ffi::version()
            .expect("libalpm must return a valid version");
        assert!(!version.trim().is_empty());
        assert!(!super::real_execution_enabled());
        println!("RWR HELPER → LIBALPM VERSION: {version}");
    }
}

#[cfg(test)]
mod stage_4_11j_transaction_tests {
    #[test]
    fn helper_prepares_isolated_alpm_transaction() {
        use rwr_package_intelligence::alpm_lab::AlpmLab;

        assert!(!super::real_execution_enabled());

        let lab = AlpmLab::create().unwrap();

        let plan = lab.prepare_isolated_transaction().unwrap();

        assert_eq!(plan.add.len(), 1);
        assert_eq!(plan.add[0].name, "rwr-test-package");
        assert_eq!(plan.add[0].version, "1.1-1");
        assert!(plan.remove.is_empty());

        println!("RWR HELPER: isolated ALPM PREPARE completed");
        println!("RWR HELPER: planned rwr-test-package 1.0-1 → 1.1-1; no commit");
    }
}

#[cfg(test)]
mod pre_commit_cancellation_tests {
    use super::PreCommitCancellation;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    #[test]
    fn accepted_cancellation_prevents_commit_boundary() {
        let flag = Arc::new(AtomicBool::new(false));
        let control = PreCommitCancellation::new(flag.clone());
        assert!(control.request().unwrap());
        assert!(
            control
                .close_for_commit()
                .unwrap_err()
                .contains("nothing installed")
        );
        assert!(flag.load(Ordering::SeqCst));
    }
    #[test]
    fn delayed_cancel_does_not_arm_installation_interrupt() {
        let flag = Arc::new(AtomicBool::new(false));
        let control = PreCommitCancellation::new(flag.clone());
        control.close_for_commit().unwrap();
        assert!(!control.request().unwrap());
        assert!(!flag.load(Ordering::SeqCst));
    }
    #[test]
    fn racing_cancel_is_either_accepted_before_commit_or_ignored_after_it() {
        for _ in 0..64 {
            let flag = Arc::new(AtomicBool::new(false));
            let control = Arc::new(PreCommitCancellation::new(flag.clone()));
            let other = control.clone();
            let caller = std::thread::spawn(move || other.request().unwrap());
            let commit = control.close_for_commit();
            let accepted = caller.join().unwrap();
            assert_eq!(accepted, commit.is_err());
            assert_eq!(flag.load(Ordering::SeqCst), accepted);
        }
    }
}

// Test builds of this binary never reach the production host (deny-only).
rwr_package_intelligence::isolate_test_binary!();
