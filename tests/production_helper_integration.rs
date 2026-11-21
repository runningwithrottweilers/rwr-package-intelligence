//! Integration tests for the fail-closed production helper.
//! No package manager, privileges or system updates.

use std::process::Command;

fn run_helper(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rwr-update-helper"))
        .args(args)
        .output()
        .expect("Cannot start production helper")
}

#[test]
fn helper_denies_execution_without_arguments() {
    let output = run_helper(&[]);

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("REAL MODE locked"));
}

#[test]
fn helper_denies_execute_argument() {
    let output = run_helper(&["--execute"]);

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("REAL MODE locked"));
}

#[test]
fn helper_denies_arbitrary_command_argument() {
    let output = run_helper(&["pacman", "-Syu"]);

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn helper_produces_no_success_ipc_message() {
    let output = run_helper(&[]);

    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8(output.stdout).expect("Helper output must be UTF-8");

    let lines: Vec<&str> = stdout.lines().collect();

    assert_eq!(lines.len(), 2);

    let started: serde_json::Value = serde_json::from_str(lines[0]).unwrap();

    let failed: serde_json::Value = serde_json::from_str(lines[1]).unwrap();

    assert_eq!(started["type"], "started");
    assert_eq!(failed["type"], "failed");

    assert!(
        failed["text"]
            .as_str()
            .unwrap_or("")
            .contains("REAL MODE locked")
    );

    assert!(
        lines.iter().all(|line| {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();

            value["type"] != "completed"
        }),
        "Production helper must never report completion"
    );
}

// This test process never reaches the production host (deny-only).
rwr_package_intelligence::isolate_test_binary!();
