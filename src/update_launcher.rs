// RWR PACKAGE INTELLIGENCE
// Stage 16P-K4: command preparation only.
// No process execution in this module.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    pub program: String,
    pub arguments: Vec<String>,
}

impl LaunchSpec {
    pub fn arch_upgrade() -> Self {
        Self {
            program: "/usr/bin/pkexec".into(),
            arguments: vec!["/usr/bin/pacman".into(), "-Syu".into()],
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.program != "/usr/bin/pkexec" {
            return Err("Invalid authorization program".into());
        }
        if self.arguments != ["/usr/bin/pacman", "-Syu"] {
            return Err("Invalid upgrade arguments".into());
        }
        Ok(())
    }
}

// Prepare a terminal command. This does not execute it.
pub fn wezterm_upgrade() -> LaunchSpec {
    LaunchSpec {
        program: "/usr/bin/wezterm".into(),
        arguments: vec![
            "start".into(),
            "--always-new-process".into(),
            "--class".into(),
            "rwr-package-intelligence".into(),
            "--".into(),
            "/usr/bin/bash".into(),
            "/usr/lib/rwr-package-intelligence/rwr-real-upgrade.sh".into(),
        ],
    }
}

pub fn validate_wezterm_upgrade(spec: &LaunchSpec) -> Result<(), String> {
    let expected = wezterm_upgrade();
    if spec != &expected {
        return Err("Invalid terminal upgrade command".into());
    }
    Ok(())
}

/// Launches a validated full system upgrade in an interactive terminal.
/// Must only be called after explicit user confirmation.
/// Never called by tests or application startup.
pub fn launch_confirmed_upgrade(
    plan: &crate::update_engine::UpdatePlan,
    confirmed: bool,
) -> Result<(), String> {
    if !confirmed {
        return Err("Explicit confirmation required".into());
    }

    plan.validate()?;

    Err("REAL MODE locked: production IPC not integrated".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_full_upgrade() {
        assert!(LaunchSpec::arch_upgrade().validate().is_ok());
    }

    #[test]
    fn rejects_other_program() {
        let mut spec = LaunchSpec::arch_upgrade();
        spec.program = "/bin/sh".into();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn rejects_extra_arguments() {
        let mut spec = LaunchSpec::arch_upgrade();
        spec.arguments.push("--noconfirm".into());
        assert!(spec.validate().is_err());
    }
}

#[cfg(test)]
mod real_mode_guard_tests {
    use super::*;

    #[test]
    fn real_mode_cannot_launch_even_with_confirmation() {
        let plan = crate::update_engine::UpdatePlan::arch_full_upgrade();

        assert!(plan.validate().is_ok());

        let denied = crate::authorization_gate::authorize(
            &plan,
            crate::authorization_gate::AuthorizationMode::Real,
            false,
        );

        assert_eq!(
            denied,
            crate::authorization_gate::AuthorizationDecision::Denied
        );

        let allowed = crate::authorization_gate::authorize(
            &plan,
            crate::authorization_gate::AuthorizationMode::Real,
            true,
        );

        assert_eq!(
            allowed,
            crate::authorization_gate::AuthorizationDecision::Denied
        );
    }

    #[test]
    fn confirmed_real_mode_cannot_launch_terminal() {
        let plan = crate::update_engine::UpdatePlan::arch_full_upgrade();

        assert!(launch_confirmed_upgrade(&plan, true).is_err());
    }

    #[test]
    fn real_mode_cannot_launch_without_confirmation() {
        let plan = crate::update_engine::UpdatePlan::arch_full_upgrade();

        assert!(launch_confirmed_upgrade(&plan, false).is_err());
    }
}

#[cfg(test)]
mod wezterm_tests {
    use super::*;

    #[test]
    fn builds_expected_terminal_command() {
        let spec = wezterm_upgrade();
        assert_eq!(spec.program, "/usr/bin/wezterm");
        assert!(validate_wezterm_upgrade(&spec).is_ok());
    }

    #[test]
    fn terminal_preserves_interactive_pacman() {
        let spec = wezterm_upgrade();

        assert!(validate_wezterm_upgrade(&spec).is_ok());
        assert_eq!(spec.program, "/usr/bin/wezterm");
        assert!(spec.arguments.contains(&"/usr/bin/bash".to_string()));
        assert!(
            spec.arguments
                .iter()
                .any(|arg| { arg == "/usr/lib/rwr-package-intelligence/rwr-real-upgrade.sh" })
        );
        assert!(!spec.arguments.contains(&"--noconfirm".to_string()));
    }

    #[test]
    fn rejects_terminal_argument_injection() {
        let mut spec = wezterm_upgrade();
        spec.arguments.push("--noconfirm".into());
        assert!(validate_wezterm_upgrade(&spec).is_err());
    }

    #[test]
    fn rejects_shell_replacement() {
        let mut spec = wezterm_upgrade();
        spec.arguments[5] = "/bin/sh".into();
        assert!(validate_wezterm_upgrade(&spec).is_err());
    }
}

/// Prepare a terminal command without launching it.
/// REAL MODE remains disabled in the GUI.

/// Locate the upgrade script supplied by the installed package or AppImage.
/// APPDIR is used only when it points to the running AppImage mount.
fn resolve_upgrade_script() -> Result<String, String> {
    use std::path::PathBuf;

    if let (Some(appdir), Some(appimage)) =
        (std::env::var_os("APPDIR"), std::env::var_os("APPIMAGE"))
    {
        let appdir = PathBuf::from(appdir);
        let appimage = PathBuf::from(appimage);

        if !appdir.is_absolute() || !appimage.is_absolute() {
            return Err("Invalid AppImage environment".into());
        }

        let executable =
            std::env::current_exe().map_err(|e| format!("Cannot identify executable: {e}"))?;

        let root = appdir
            .canonicalize()
            .map_err(|e| format!("Invalid AppImage directory: {e}"))?;

        let executable = executable
            .canonicalize()
            .map_err(|e| format!("Invalid executable path: {e}"))?;

        if !executable.starts_with(&root) {
            return Err("AppImage executable is outside APPDIR".into());
        }

        let script = root.join("usr/lib/rwr-package-intelligence/rwr-real-upgrade.sh");

        let script = script
            .canonicalize()
            .map_err(|e| format!("AppImage upgrade script unavailable: {e}"))?;

        if !script.starts_with(&root) {
            return Err("Upgrade script escapes AppImage directory".into());
        }

        return Ok(script.to_string_lossy().into_owned());
    }

    let script = PathBuf::from("/usr/lib/rwr-package-intelligence/rwr-real-upgrade.sh");

    if !script.is_file() {
        #[cfg(debug_assertions)]
        {
            let source_script =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/rwr-real-upgrade.sh");

            if source_script.is_file() {
                let resolved = source_script
                    .canonicalize()
                    .map_err(|e| format!("Cannot resolve development upgrade script: {e}"))?;
                return Ok(resolved.to_string_lossy().into_owned());
            }
        }

        return Err(
            "Upgrade script unavailable. Install the Arch package or verify the AppImage.".into(),
        );
    }

    Ok(script.to_string_lossy().into_owned())
}

pub fn prepare_universal_terminal() -> Result<crate::terminal_backend::TerminalCommand, String> {
    use crate::terminal_backend::{SessionEnvironment, detect_session_environment};

    match detect_session_environment() {
        SessionEnvironment::Desktop => {}
        SessionEnvironment::Ssh => {
            return Err("SSH session: graphical terminal launch disabled".into());
        }
        SessionEnvironment::Tty => {
            return Err("TTY session: graphical terminal launch disabled".into());
        }
    }

    let backend = crate::terminal_backend::detect_terminal()
        .ok_or_else(|| "No supported terminal found".to_string())?;

    let script = resolve_upgrade_script()?;

    backend.build_command(&script)
}

/// Validates authorization before preparing a universal terminal command.
/// Does not spawn a process or execute an upgrade.
pub fn prepare_authorized_terminal(
    plan: &crate::update_engine::UpdatePlan,
    user_confirmed: bool,
) -> Result<crate::terminal_backend::TerminalCommand, String> {
    use crate::authorization_gate::{AuthorizationDecision, AuthorizationMode, authorize};

    if authorize(plan, AuthorizationMode::Real, user_confirmed)
        != AuthorizationDecision::RealAllowed
    {
        return Err("REAL MODE disabled by authorization policy".into());
    }

    crate::real_update_preflight::prepare_real_update(plan, user_confirmed)?;
    prepare_universal_terminal()
}

// RWR ETAP 4.6-G — PRODUCTION HELPER SPEC
// Specification only. Never launches a process.
pub fn production_helper_spec() -> LaunchSpec {
    LaunchSpec {
        program: "/usr/bin/pkexec".into(),
        arguments: vec![
            "/usr/lib/rwr-package-intelligence/rwr-update-helper".into(),
            "--upgrade".into(),
        ],
    }
}

pub fn validate_production_helper_spec(spec: &LaunchSpec) -> Result<(), String> {
    if spec != &production_helper_spec() {
        return Err("Invalid production helper launch specification".into());
    }

    Ok(())
}

// RWR ETAP 4.6-H1 — IPC INTEGRATION PRECHECK
// Validation only. No process execution or privilege escalation.
pub fn validate_production_ipc_precheck() -> Result<(), String> {
    let spec = production_helper_spec();
    validate_production_helper_spec(&spec)?;

    if !crate::production_ipc::PRODUCTION_BACKEND_AVAILABLE {
        return Err("REAL MODE locked: production helper backend is unavailable".into());
    }
    // This deployment check cannot authorize a transaction. The supervisor and
    // helper independently require Polkit and the current confirmed ALPM plan.
    // Legacy terminal authorization deliberately remains Denied.
    rwr_package_intelligence::supervisor_trust::require_system_execution_policy()
}

// RWR ETAP 4.6-H2 — IPC ADAPTER
// Processes supplied IPC data only. Never starts a privileged process.
pub fn validate_helper_ipc_result(
    lines: &[String],
    process_exit_code: i32,
) -> Result<crate::transaction_protocol::TransactionOutcome, String> {
    use crate::transaction_worker::TransactionWorker;

    let mut worker = TransactionWorker::new();

    for line in lines {
        if let Err(error) = worker.receive_ipc_line(line) {
            worker.connection_lost();
            return Err(error);
        }
    }

    worker.process_exited(process_exit_code)?;

    worker
        .outcome()
        .ok_or_else(|| "Missing verified transaction outcome".to_string())
}

// RWR ETAP 4.6-H3 — IPC ADAPTER TESTS
#[cfg(test)]
mod production_ipc_adapter_tests {
    use super::*;
    use crate::transaction_protocol::TransactionOutcome;

    #[test]
    fn accepts_verified_success() {
        let lines = vec![
            r#"{"type":"started"}"#.to_string(),
            r#"{"type":"completed","exit_code":0}"#.to_string(),
        ];

        assert_eq!(
            validate_helper_ipc_result(&lines, 0).unwrap(),
            TransactionOutcome::Success
        );
    }

    #[test]
    fn rejects_missing_completion() {
        let lines = vec![r#"{"type":"started"}"#.to_string()];

        assert_ne!(
            validate_helper_ipc_result(&lines, 0).unwrap(),
            TransactionOutcome::Success
        );
    }

    #[test]
    fn rejects_invalid_json() {
        let lines = vec![
            r#"{"type":"started"}"#.to_string(),
            "INVALID_JSON".to_string(),
        ];

        assert!(validate_helper_ipc_result(&lines, 0).is_err());
    }
}

// RWR ETAP 4.6-K3A — production IPC supervisor entry point.
// The supervisor remains fail-closed until the helper backend is complete.
#[allow(dead_code)]
pub fn start_production_ipc(
    plan: &crate::update_engine::UpdatePlan,
    confirmed: bool,
) -> Result<
    (
        std::sync::mpsc::Receiver<crate::production_ipc::ProductionIpcEvent>,
        std::sync::mpsc::Sender<crate::transaction_ipc::IpcReply>,
    ),
    String,
> {
    if !confirmed {
        return Err("Explicit confirmation required".into());
    }

    plan.validate()?;
    validate_production_ipc_precheck()?;
    crate::production_ipc::start_production_helper(plan, confirmed)
}

#[cfg(test)]
mod production_readiness_integration_tests {
    use super::*;

    #[test]
    fn production_readiness_gate_is_shared_by_gui_and_launcher() {
        let reason = validate_production_ipc_precheck().unwrap_err();
        assert!(reason.contains("REAL MODE locked"));
        assert!(!rwr_package_intelligence::production_alpm_flow::real_flow_enabled());
        let plan = crate::update_engine::UpdatePlan::arch_full_upgrade();
        // Both paths stop before inspecting or launching any executable.
        assert_eq!(start_production_ipc(&plan, true).unwrap_err(), reason);
        assert!(
            start_production_ipc(&plan, false)
                .unwrap_err()
                .contains("confirmation")
        );
        let mut invalid = plan;
        invalid.arguments.push("--noconfirm".into());
        assert!(
            start_production_ipc(&invalid, true)
                .unwrap_err()
                .contains("Only full")
        );
    }
}

pub fn start_confirmed_production_ipc(
    request: &crate::transaction_ipc::PlanValidationRequest,
) -> Result<
    (
        std::sync::mpsc::Receiver<crate::production_ipc::ProductionIpcEvent>,
        std::sync::mpsc::Sender<crate::transaction_ipc::IpcReply>,
    ),
    String,
> {
    request.validate()?;
    validate_production_ipc_precheck()?;
    crate::production_ipc::start_confirmed_production_helper(request)
}

/// Local rejection only; a GUI confirmation never grants Polkit authority.
pub fn validate_pending_execution_confirmation(
    current: Option<&crate::transaction_ipc::PlanValidationRequest>,
    reviewed: &crate::transaction_ipc::PlanValidationRequest,
    busy: bool,
) -> Result<(), String> {
    reviewed.validate()?;
    if reviewed.scope != "system" {
        return Err("System scope required".into());
    }
    if busy {
        return Err(
            "Operation already active; recover its result instead of starting again".into(),
        );
    }
    if current != Some(reviewed) {
        return Err("Confirmed plan expired or changed; prepare and review it again".into());
    }
    Ok(())
}

#[cfg(test)]
mod pending_confirmation_tests {
    use super::validate_pending_execution_confirmation as check;
    use crate::transaction_ipc::PlanValidationRequest;
    fn request() -> PlanValidationRequest {
        PlanValidationRequest {
            transaction_id: "reviewed-1".into(),
            plan_digest: "a".repeat(64),
            scope: "system".into(),
        }
    }
    #[test]
    fn changed_removed_and_replaced_plans_are_rejected() {
        let reviewed = request();
        assert!(check(None, &reviewed, false).is_err());
        let mut current = reviewed.clone();
        current.plan_digest = "b".repeat(64);
        assert!(check(Some(&current), &reviewed, false).is_err());
        current = reviewed.clone();
        current.transaction_id = "other-session".into();
        assert!(check(Some(&current), &reviewed, false).is_err());
    }
    #[test]
    fn active_operation_rejects_duplicate_confirmation() {
        let reviewed = request();
        assert!(check(Some(&reviewed), &reviewed, true).is_err());
    }
    #[test]
    fn current_confirmation_does_not_open_real_gate() {
        let reviewed = request();
        check(Some(&reviewed), &reviewed, false).unwrap();
        assert!(
            super::start_confirmed_production_ipc(&reviewed)
                .unwrap_err()
                .contains("REAL MODE locked")
        );
    }
}
