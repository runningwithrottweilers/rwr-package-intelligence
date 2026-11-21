//! Real isolated ALPM -> confirmed commitment -> production helper's read-only
//! endpoint -> activated supervisor -> GUI client. No COMMIT or host repository.
use rwr_package_intelligence::{
    alpm_lab::AlpmLab,
    process_guard::ChildGuard,
    production_alpm_flow::PreparedFullUpgrade,
    supervisor_client::{
        diagnostic_session_summary, plan_validation_status, submit_plan_validation,
    },
};
use std::os::{
    fd::AsRawFd,
    unix::{fs::DirBuilderExt, net::UnixListener, process::CommandExt},
};
use std::{
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn start_supervisor(root: &Path, directory: &Path, socket: &Path) -> ChildGuard {
    let listener = UnixListener::bind(socket).unwrap();
    let fd = listener.as_raw_fd();
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "export LISTEN_PID=$$; exec \"$1\"",
            "rwr-plan-integration",
        ])
        .arg(env!("CARGO_BIN_EXE_rwr-transaction-supervisor"))
        .env("LISTEN_FDS", "1")
        .env("RWR_PLAN_VALIDATION_ENABLED", "1")
        .env("RWR_PLAN_VALIDATION_DIRECTORY", directory)
        .env("RWR_PLAN_VALIDATION_LAB_ROOT", root)
        .env_remove("RWR_DIAGNOSTIC_TRANSACTION_ID")
        .env_remove("RWR_DIAGNOSTIC_STATE_PATH")
        .env_remove("RWR_DIAGNOSTIC_HELPER_PATH")
        .env_remove("RWR_DIAGNOSTIC_SLEEP_SECONDS")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    unsafe {
        command.pre_exec(move || {
            if fd != 3 && libc::dup2(fd, 3) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    ChildGuard(command.spawn().unwrap())
}

fn finish(
    socket: &Path,
    request: &rwr_package_intelligence::transaction_ipc::PlanValidationRequest,
) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < deadline, "Validation did not finish");
        let result = plan_validation_status(socket, request).unwrap();
        if result["validation_outcome"] != "pending" {
            return result;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn confirmed_plan_crosses_real_helper_supervisor_and_reconnects() {
    let lab = AlpmLab::create().unwrap();
    let before = std::fs::read(lab.db().join("local/rwr-test-package-1.0-1/desc")).unwrap();
    let plan = PreparedFullUpgrade::prepare_isolated(lab.root()).unwrap();
    let confirmed = plan.confirm_and_revalidate(true).unwrap();
    let request = confirmed.validation_request("confirmed-plan-1").unwrap();
    let directory = lab.root().parent().unwrap().join("validation");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let socket = lab.root().parent().unwrap().join("plan.sock");
    let mut supervisor = start_supervisor(lab.root(), &directory, &socket);
    submit_plan_validation(&socket, &request).unwrap(); // Request socket is dropped.
    let success = finish(&socket, &request);
    assert_eq!(success["validation_outcome"], "validated", "{success}");
    assert_eq!(success["transaction_id"], request.transaction_id);
    assert_eq!(success["plan_digest"], request.plan_digest);
    assert_eq!(success["commit_authorized"], false);
    assert_eq!(success["update_executed"], false);
    assert_eq!(success["real_execution_enabled"], false);
    assert!(
        diagnostic_session_summary(&success)
            .unwrap()
            .unwrap()
            .contains("PLAN VALIDATION")
    );
    assert_eq!(submit_plan_validation(&socket, &request).unwrap(), success);
    let mut forged = request.clone();
    forged.plan_digest = "f".repeat(64);
    assert!(submit_plan_validation(&socket, &forged).is_err());
    assert_eq!(
        std::fs::read(lab.db().join("local/rwr-test-package-1.0-1/desc")).unwrap(),
        before
    );
    assert!(supervisor.0.try_wait().unwrap().is_none());
    drop(supervisor);
    std::fs::remove_file(&socket).unwrap(); // Only the socket created by this test.
    supervisor = start_supervisor(lab.root(), &directory, &socket);
    assert_eq!(plan_validation_status(&socket, &request).unwrap(), success);
    assert_eq!(submit_plan_validation(&socket, &request).unwrap(), success);

    // A validly encoded GUI claim is not authority. A new transaction with a
    // forged commitment must be independently refused by the actual helper.
    forged.transaction_id = "forged-plan-2".into();
    submit_plan_validation(&socket, &forged).unwrap();
    let rejected = finish(&socket, &forged);
    assert_eq!(rejected["validation_outcome"], "rejected", "{rejected}");
    assert_eq!(rejected["update_executed"], false);
    assert_eq!(rejected["commit_authorized"], false);

    // Change the installed state inside the private laboratory, keeping the
    // original GUI commitment. The helper must refuse that stale plan too.
    let changed = String::from_utf8(before)
        .unwrap()
        .replace("\n1.0-1\n", "\n1.0-2\n");
    std::fs::write(lab.db().join("local/rwr-test-package-1.0-1/desc"), changed).unwrap();
    let mut stale = request.clone();
    stale.transaction_id = "stale-plan-3".into();
    submit_plan_validation(&socket, &stale).unwrap();
    let rejected = finish(&socket, &stale);
    assert_eq!(rejected["validation_outcome"], "rejected", "{rejected}");
    assert!(rejected["error"].as_str().unwrap().contains("differ"));
    assert_eq!(rejected["commit_authorized"], false);
    assert!(supervisor.0.try_wait().unwrap().is_none());
}

// This test process never reaches the production host (deny-only).
rwr_package_intelligence::isolate_test_binary!();
