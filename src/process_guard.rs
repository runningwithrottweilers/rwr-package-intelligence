//! Shared child-process lifecycle guard.
//! Terminates and reaps a still-running child on drop.

use std::process::Child;

pub struct ChildGuard(pub Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Ok(None) = self.0.try_wait() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

// RWR ETAP 4.6-I5 — PROCESS EXIT SUPERVISION
impl ChildGuard {
    pub fn wait_for_exit(&mut self, timeout: std::time::Duration) -> Result<i32, String> {
        use std::os::unix::process::ExitStatusExt;
        use std::time::Instant;

        let deadline = Instant::now() + timeout;

        loop {
            let status = self.0.try_wait().map_err(|e| e.to_string())?;

            if let Some(status) = status {
                return Ok(status
                    .code()
                    .unwrap_or_else(|| status.signal().map(|signal| 128 + signal).unwrap_or(-1)));
            }

            if Instant::now() >= deadline {
                return Err("Helper process exit timeout".into());
            }

            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

impl ChildGuard {
    /// An in-flight package COMMIT must never be killed by an IPC error/drop.
    /// Transfer the one owned Child to a reaper; the helper's durable journal
    /// determines the result. The caller must report UNKNOWN until recovered.
    pub fn preserve_and_reap(self) {
        let guard = std::mem::ManuallyDrop::new(self);
        // Exactly one move of Child; suppress only ChildGuard's kill-on-drop.
        let mut child = unsafe { std::ptr::read(&guard.0) };
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}

#[cfg(test)]
mod commit_preservation_tests {
    #[test]
    fn ipc_error_drop_does_not_kill_committing_process() {
        use std::os::unix::fs::DirBuilderExt;
        let base = std::env::temp_dir().join(format!("rwr-preserve-{}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&base)
            .unwrap();
        let marker = base.join("completed");
        let child = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                "/usr/bin/sleep 0.05; printf complete > \"$1\"",
                "rwr-preserve",
            ])
            .arg(&marker)
            .spawn()
            .unwrap();
        super::ChildGuard(child).preserve_and_reap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !marker.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(std::fs::read(&marker).unwrap(), b"complete");
        std::fs::remove_dir_all(base).unwrap();
    }
}
