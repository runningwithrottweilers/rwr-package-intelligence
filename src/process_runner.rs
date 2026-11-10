// RWR PACKAGE INTELLIGENCE
// K17 — restricted test process runner.
// No pacman, no pkexec, no shell.

use std::process::Command;

#[derive(Debug, PartialEq, Eq)]
pub enum ProcessResult {
    Success,
    Failed(i32),
    Terminated,
    LaunchError,
}

pub fn run_test_process(program: &str) -> ProcessResult {
    if !matches!(program, "/usr/bin/true" | "/usr/bin/false") {
        return ProcessResult::LaunchError;
    }

    if program == "/usr/bin/true" {
        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    match Command::new(program).status() {
        Ok(status) => match status.code() {
            Some(0) => ProcessResult::Success,
            Some(code) => ProcessResult::Failed(code),
            None => ProcessResult::Terminated,
        },
        Err(_) => ProcessResult::LaunchError,
    }
}

// K29: Controller owns only a diagnostic sleep process.
pub struct TestProcessController {
    child: Option<std::process::Child>,
}

impl TestProcessController {
    pub fn start() -> std::io::Result<Self> {
        use std::process::Stdio;

        let child = Command::new("/usr/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        Ok(Self { child: Some(child) })
    }

    pub fn is_running(&mut self) -> std::io::Result<bool> {
        match self.child.as_mut() {
            Some(child) => match child.try_wait()? {
                Some(_) => {
                    self.child = None;
                    Ok(false)
                }
                None => Ok(true),
            },
            None => Ok(false),
        }
    }

    pub fn try_result(&mut self) -> std::io::Result<Option<ProcessResult>> {
        let Some(child) = self.child.as_mut() else {
            return Ok(None);
        };

        let Some(status) = child.try_wait()? else {
            return Ok(None);
        };

        self.child = None;

        Ok(Some(match status.code() {
            Some(0) => ProcessResult::Success,
            Some(code) => ProcessResult::Failed(code),
            None => ProcessResult::Terminated,
        }))
    }

    pub fn cancel(&mut self) -> std::io::Result<ProcessResult> {
        let Some(mut child) = self.child.take() else {
            return Ok(ProcessResult::LaunchError);
        };

        if child.try_wait()?.is_none() {
            child.kill()?;
        }

        let status = child.wait()?;

        Ok(match status.code() {
            Some(0) => ProcessResult::Success,
            Some(code) => ProcessResult::Failed(code),
            None => ProcessResult::Terminated,
        })
    }
}

impl Drop for TestProcessController {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn true_returns_success() {
        assert_eq!(run_test_process("/usr/bin/true"), ProcessResult::Success);
    }

    #[test]
    fn false_returns_failure() {
        assert_eq!(run_test_process("/usr/bin/false"), ProcessResult::Failed(1));
    }

    #[test]
    fn rejects_pacman() {
        assert_eq!(
            run_test_process("/usr/bin/pacman"),
            ProcessResult::LaunchError
        );
    }

    #[cfg(unix)]
    #[test]
    fn detects_real_sigterm() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::{Command, Stdio};

        let mut child = Command::new("/usr/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Nie mozna uruchomic procesu testowego");

        let pid = child.id();

        let signal_status = Command::new("/usr/bin/kill")
            .arg("-TERM")
            .arg("--")
            .arg(pid.to_string())
            .status()
            .expect("Nie mozna wyslac SIGTERM");

        if !signal_status.success() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("Wyslanie SIGTERM nie powiodlo sie");
        }

        let status = child.wait().expect("Nie mozna odczytac statusu procesu");

        assert_eq!(status.signal(), Some(15));
        assert_eq!(status.code(), None);
    }

    #[cfg(unix)]
    #[test]
    fn cancels_own_test_process() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::{Command, Stdio};

        let mut child = Command::new("/usr/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Nie mozna uruchomic procesu testowego");

        child.kill().expect("Nie mozna anulowac procesu testowego");

        let status = child.wait().expect("Nie mozna odebrac statusu procesu");

        assert!(!status.success());
        assert_eq!(status.code(), None);
        assert_eq!(status.signal(), Some(9));
    }

    #[cfg(unix)]
    #[test]
    fn controller_starts_and_cancels() {
        let mut controller =
            TestProcessController::start().expect("Nie mozna uruchomic kontrolera");

        assert!(controller.is_running().unwrap());

        let result = controller.cancel().unwrap();
        assert_eq!(result, ProcessResult::Terminated);

        assert!(!controller.is_running().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn controller_rejects_second_cancel() {
        let mut controller = TestProcessController::start().unwrap();

        assert_eq!(controller.cancel().unwrap(), ProcessResult::Terminated);

        assert_eq!(controller.cancel().unwrap(), ProcessResult::LaunchError);
    }

    #[cfg(unix)]
    #[test]
    fn controller_drop_reaps_child() {
        let controller = TestProcessController::start().unwrap();

        let pid = controller.child.as_ref().unwrap().id();

        drop(controller);

        let proc_path = format!("/proc/{pid}");

        assert!(
            !std::path::Path::new(&proc_path).exists(),
            "Proces testowy nadal istnieje po Drop"
        );
    }

    #[test]
    fn rejects_shell() {
        assert_eq!(
            run_test_process("/usr/bin/bash"),
            ProcessResult::LaunchError
        );
    }
}
