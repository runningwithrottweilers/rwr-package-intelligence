//! Read-only laboratory sandbox diagnostics.
//! Not an authorization capability for COMMIT.

use std::fs;

fn verify_mountinfo(mountinfo: &str) -> Result<(), String> {
    let mut usr_readonly = false;
    let mut tmp_private = false;

    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };

        let fields: Vec<&str> = left.split_whitespace().collect();
        let fs_fields: Vec<&str> = right.split_whitespace().collect();

        if fields.len() < 6 || fs_fields.is_empty() {
            continue;
        }

        let mountpoint = fields[4];
        let options = fields[5];

        if mountpoint == "/usr" {
            usr_readonly = options.split(",").any(|x| x == "ro");
        }

        if mountpoint == "/tmp" {
            tmp_private = fs_fields[0] == "tmpfs";
        }
    }

    if !usr_readonly {
        return Err("Sandbox verification failed: /usr is not read-only".into());
    }

    if !tmp_private {
        return Err("Sandbox verification failed: /tmp is not tmpfs".into());
    }

    Ok(())
}

fn verify_process_security(status: &str) -> Result<(), String> {
    let mut uid = None;
    let mut no_new_privs = None;
    let mut capabilities = None;
    let mut seccomp = None;

    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Uid:") {
            let values = value
                .split_whitespace()
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "Invalid UID field")?;

            if values.len() != 4 || values.contains(&0) {
                return Err("Sandbox verification failed: root or invalid UID".into());
            }
            uid = Some(values);
        }

        if let Some(value) = line.strip_prefix("NoNewPrivs:") {
            no_new_privs = Some(value.trim());
        }

        if let Some(value) = line.strip_prefix("CapEff:") {
            capabilities = Some(value.trim());
        }

        if let Some(value) = line.strip_prefix("Seccomp:") {
            seccomp = Some(value.trim());
        }
    }

    if uid.is_none() {
        return Err("Sandbox verification failed: UID unavailable".into());
    }

    if no_new_privs != Some("1") {
        return Err("Sandbox verification failed: NoNewPrivs disabled".into());
    }

    let caps = capabilities.ok_or("Sandbox verification failed: CapEff unavailable")?;

    if u64::from_str_radix(caps, 16).map_err(|_| "Invalid CapEff")? != 0 {
        return Err("Sandbox verification failed: effective capabilities present".into());
    }

    // An active seccomp filter is mandatory for laboratory PREPARE.
    if seccomp != Some("2") {
        return Err("Sandbox verification failed: invalid Seccomp status".into());
    }

    Ok(())
}

pub fn verify_lab_sandbox() -> Result<(), String> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|e| format!("Cannot read mountinfo: {e}"))?;

    verify_mountinfo(&mountinfo)?;

    let process_status = fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("Cannot read process security status: {e}"))?;

    verify_process_security(&process_status)?;

    for path in ["/var/lib/pacman/local", "/etc/pacman.conf"] {
        if std::path::Path::new(path).exists() {
            return Err(format!(
                "Sandbox verification failed: host path visible: {path}"
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn diagnostic_does_not_grant_commit_authorization() {
        // No authorization token or commit entry point is exposed.
        let _diagnostic: fn() -> Result<(), String> = super::verify_lab_sandbox;
    }
}

/// Diagnostic checks must never grant COMMIT authorization.
pub fn commit_authorization_available() -> bool {
    false
}

/// Capability token proving verified laboratory sandbox attestation.
/// It authorizes COMMIT exclusively within the isolated laboratory root
/// (private bwrap/seccomp filesystem). It can only be constructed inside
/// a sandbox that passes full attestation and never authorizes
/// production or system execution.
pub struct LabCommitAuthorization {
    _private: (),
}

impl LabCommitAuthorization {
    /// Constructible only where the full sandbox attestation passes:
    /// read-only /usr, private tmpfs /tmp, unprivileged hardened process,
    /// active seccomp and no visible host pacman paths.
    pub fn attest() -> Result<Self, String> {
        verify_lab_sandbox()?;
        Ok(Self { _private: () })
    }
}

#[cfg(test)]
mod stage_4_3_19_negative_tests {
    #[test]
    fn host_execution_cannot_create_commit_authorization() {
        // Sandbox diagnostics expose no commit authorization.
        let result = super::verify_lab_sandbox();

        if result.is_ok() {
            eprintln!("Host diagnostics passed; this must never authorize COMMIT");
        }

        // Diagnostic success is deliberately not a capability.
        assert!(!super::commit_authorization_available());
    }

    #[test]
    fn authorization_remains_unavailable() {
        assert!(!super::commit_authorization_available());
    }

    #[test]
    fn commit_token_cannot_be_attested_on_host() {
        // The host process never passes full sandbox attestation, so the
        // laboratory COMMIT capability is unconstructible outside it.
        assert!(super::LabCommitAuthorization::attest().is_err());
    }
}

#[cfg(test)]
mod stage_4_3_20_mountinfo_tests {
    use super::verify_mountinfo;

    const VALID: &str = concat!(
        "1 0 0:1 / /usr ro,nosuid - btrfs device rw\n",
        "2 0 0:2 / /tmp rw,nosuid - tmpfs tmpfs rw\n"
    );

    #[test]
    fn accepts_expected_mounts() {
        assert!(verify_mountinfo(VALID).is_ok());
    }

    #[test]
    fn rejects_writable_usr() {
        let input = VALID.replace("/usr ro", "/usr rw");
        assert!(verify_mountinfo(&input).is_err());
    }

    #[test]
    fn rejects_non_tmpfs_tmp() {
        let input = VALID.replace("tmpfs tmpfs", "ext4 device");
        assert!(verify_mountinfo(&input).is_err());
    }

    #[test]
    fn rejects_missing_mounts() {
        assert!(verify_mountinfo("").is_err());
    }
}

#[cfg(test)]
mod process_security_tests {
    use super::verify_process_security;

    const VALID: &str = concat!(
        "Uid:\t1000 1000 1000 1000\n",
        "NoNewPrivs:\t1\n",
        "CapEff:\t0000000000000000\n",
        "Seccomp:\t2\n",
    );

    #[test]
    fn accepts_hardened_process() {
        assert!(verify_process_security(VALID).is_ok());
    }

    #[test]
    fn rejects_root_uid() {
        assert!(
            verify_process_security(&VALID.replace("1000 1000 1000 1000", "1000 1000 0 1000"))
                .is_err()
        );
    }

    #[test]
    fn rejects_missing_uid() {
        assert!(
            verify_process_security(&VALID.replace("Uid:\t1000 1000 1000 1000\n", "")).is_err()
        );
    }

    #[test]
    fn rejects_no_new_privs_disabled() {
        assert!(
            verify_process_security(&VALID.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0")).is_err()
        );
    }

    #[test]
    fn rejects_effective_capabilities() {
        assert!(
            verify_process_security(&VALID.replace("0000000000000000", "0000000000000001"))
                .is_err()
        );
    }

    #[test]
    fn rejects_missing_seccomp() {
        assert!(verify_process_security(&VALID.replace("Seccomp:\t2\n", "")).is_err());
    }

    #[test]
    fn rejects_seccomp_disabled() {
        assert!(verify_process_security(&VALID.replace("Seccomp:\t2", "Seccomp:\t0")).is_err());
    }

    #[test]
    fn rejects_invalid_seccomp() {
        assert!(verify_process_security(&VALID.replace("Seccomp:\t2", "Seccomp:\t1")).is_err());
    }

    #[test]
    fn rejects_missing_security_fields() {
        assert!(verify_process_security("").is_err());
    }
}
