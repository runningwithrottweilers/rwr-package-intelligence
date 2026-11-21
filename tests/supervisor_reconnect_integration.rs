// RWR ETAP 4.8AD-33
// Diagnostic state persistence test. No package operations.

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn diagnostic_state_survives_process_exit() {
    let binary = env!("CARGO_BIN_EXE_rwr-transaction-supervisor");

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let base = std::env::temp_dir().join(format!(
        "rwr-supervisor-state-{}-{nonce}",
        std::process::id()
    ));

    std::fs::create_dir(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();

    let state = base.join("state.json");

    let result = Command::new(binary)
        .arg("--diagnostic-run")
        .arg("state-test")
        .arg(&state)
        .arg("/usr/bin/true")
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert!(
        result.status.success(),
        "Supervisor failed: status={:?}, stderr={}",
        result.status,
        String::from_utf8_lossy(&result.stderr)
    );

    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();

    assert_eq!(saved["transaction_id"], "state-test");
    assert_eq!(saved["phase"], "finished");
    assert_eq!(saved["outcome"], "success");
    assert_eq!(saved["real_execution_enabled"], false);

    let shown = Command::new(binary)
        .arg("--state-show")
        .arg(&state)
        .output()
        .unwrap();

    assert!(
        shown.status.success(),
        "State read failed: {}",
        String::from_utf8_lossy(&shown.stderr)
    );

    let restored: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();

    assert_eq!(restored["transaction_id"], saved["transaction_id"]);
    assert_eq!(restored["phase"], saved["phase"]);
    assert_eq!(restored["outcome"], saved["outcome"]);

    std::fs::remove_dir_all(&base).unwrap();
}

// This test process never reaches the production host (deny-only).
rwr_package_intelligence::isolate_test_binary!();
