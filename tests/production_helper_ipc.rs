use rwr_package_intelligence::transaction_ipc;
use rwr_package_intelligence::transaction_protocol;
use rwr_package_intelligence::transaction_state;
use rwr_package_intelligence::transaction_worker;
use std::process::Command;
use transaction_protocol::TransactionOutcome;
use transaction_worker::TransactionWorker;

#[test]
fn production_helper_reports_failure_over_ipc() {
    let output = Command::new(env!("CARGO_BIN_EXE_rwr-update-helper"))
        .output()
        .expect("Cannot launch helper");

    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();

    assert_eq!(lines.len(), 2);

    let mut worker = TransactionWorker::new();

    worker.receive_ipc_line(lines[0]).unwrap();
    worker.receive_ipc_line(lines[1]).unwrap();

    assert_eq!(worker.outcome(), Some(TransactionOutcome::Running));

    worker.process_exited(1).unwrap();

    assert_eq!(worker.outcome(), Some(TransactionOutcome::Failure));
}

#[test]
fn production_helper_never_reports_success() {
    let output = Command::new(env!("CARGO_BIN_EXE_rwr-update-helper"))
        .arg("--execute")
        .output()
        .unwrap();

    assert!(!output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();

    for line in stdout.lines() {
        let message = transaction_ipc::parse_message(line).unwrap();

        assert!(!matches!(
            message,
            transaction_ipc::IpcMessage::Completed { exit_code: 0 }
        ));
    }
}

// Actual production process supervision, not a simulated Polkit response.
// This intentionally proves only the locked path; no COMMIT is authorized.
#[test]
fn supervised_production_helper_refusal_survives_gui_detach() {
    use rwr_package_intelligence::supervisor_session::{ExecutionSession, supervise_execution};
    use std::sync::{Arc, Mutex, mpsc};
    assert!(!rwr_package_intelligence::production_alpm_flow::real_flow_enabled());
    let request = transaction_ipc::PlanValidationRequest {
        transaction_id: "production-supervised-locked".into(),
        plan_digest: "a".repeat(64),
        scope: "system".into(),
    };
    let session = Arc::new(Mutex::new(ExecutionSession::new(request.clone()).unwrap()));
    let (gui, answers) = mpsc::channel();
    drop(gui); // GUI disappearance must not discard the helper's final refusal.
    let mut helper = Command::new(env!("CARGO_BIN_EXE_rwr-update-helper"));
    helper
        .arg("--supervised-upgrade")
        .env_clear()
        .env("PATH", "/usr/bin")
        // Deny-only: the helper must not consult the host policy, which may be
        // enabled on a deployed machine. Production units never set this.
        .env(rwr_package_intelligence::test_isolation::ENV, "1");
    let mut recovery_calls = 0;
    supervise_execution(&mut helper, &session, answers, || {
        recovery_calls += 1;
        // No privileged journal exists: do not fabricate a durable outcome.
        Ok(None)
    })
    .unwrap();
    assert_eq!(recovery_calls, 1);
    let snapshot = session.lock().unwrap().snapshot();
    assert_eq!(snapshot["transaction_id"], request.transaction_id);
    assert_eq!(snapshot["plan_digest"], request.plan_digest);
    assert_eq!(snapshot["outcome"], "failure");
    assert!(
        snapshot["error"]
            .as_str()
            .unwrap()
            .contains("REAL MODE locked")
    );
    assert_eq!(snapshot["partial_installation_possible"], false);
    assert_eq!(snapshot["replay_authorized"], false);
    assert_eq!(snapshot["real_execution_enabled"], false);
}

// This test process never reaches the production host (deny-only).
rwr_package_intelligence::isolate_test_binary!();
