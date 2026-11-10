use std::collections::HashSet;
use std::process::Command;

/// Each scan owns its database, independently of desktop widgets and other
/// checkupdates processes. Never share or remove another process's db.lck.
struct ScanDatabase(std::path::PathBuf);

impl ScanDatabase {
    fn create() -> Result<Self, String> {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let template = std::env::temp_dir().join("rwr-checkupdates-XXXXXX");
        let mut bytes = std::ffi::CString::new(template.as_os_str().as_bytes())
            .map_err(|_| "Invalid scanner temporary directory")?
            .into_bytes_with_nul();
        // mkdtemp creates a unique directory with mode 0700 atomically.
        if unsafe { libc::mkdtemp(bytes.as_mut_ptr().cast()) }.is_null() {
            return Err(format!(
                "Cannot create scanner database: {}",
                std::io::Error::last_os_error()
            ));
        }
        bytes.pop();
        Ok(Self(std::ffi::OsString::from_vec(bytes).into()))
    }
}

impl Drop for ScanDatabase {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!("RWR SCAN: cannot remove private scanner database: {error}");
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageUpdate {
    pub name: String,
    pub installed: String,
    pub available: String,
}

fn parse_updates(input: &str) -> Result<Vec<PackageUpdate>, String> {
    let mut updates = Vec::new();
    let mut names = HashSet::new();

    for (index, line) in input.lines().enumerate() {
        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split_whitespace().collect();

        if fields.len() != 4 || fields[2] != "->" {
            return Err(format!(
                "Invalid checkupdates output at line {}: {}",
                index + 1,
                line
            ));
        }

        let name = fields[0];
        let installed = fields[1];
        let available = fields[3];

        if !names.insert(name.to_string()) {
            return Err(format!("Duplicate package at line {}: {}", index + 1, name));
        }

        updates.push(PackageUpdate {
            name: name.to_string(),
            installed: installed.to_string(),
            available: available.to_string(),
        });
    }

    Ok(updates)
}

pub fn check_updates() -> Result<Vec<PackageUpdate>, String> {
    let mut command = Command::new("checkupdates");
    command.arg("--nocolor");
    check_updates_with(command)
}

fn check_updates_with(mut command: Command) -> Result<Vec<PackageUpdate>, String> {
    let database = ScanDatabase::create()?;
    let output = command
        .env("CHECKUPDATES_DB", &database.0)
        .output()
        .map_err(|e| format!("Cannot run checkupdates: {e}"))?;

    let code = output.status.code();

    if !output.status.success() && code != Some(2) {
        return Err(format!(
            "checkupdates failed (exit {:?}): {}",
            code,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| format!("Invalid UTF-8 from checkupdates: {e}"))?;

    if code == Some(2) && !stdout.trim().is_empty() {
        return Err("checkupdates returned exit 2 with unexpected output".to_string());
    }

    parse_updates(&stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_private_databases_do_not_touch_shared_lock() {
        use std::os::unix::fs::PermissionsExt;
        let shared = ScanDatabase::create().unwrap();
        assert_eq!(
            std::fs::metadata(&shared.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let lock = shared.0.join("db.lck");
        std::fs::write(&lock, b"owned by another scanner").unwrap();
        let jobs: Vec<_> = (0..2)
            .map(|_| {
                let shared = shared.0.clone();
                std::thread::spawn(move || {
                    // Fixture only: model checkupdates' exclusive database lock.
                    // No checkupdates, package manager or network is executed.
                    let mut command = Command::new("/bin/sh");
                    command
                        .args([
                            "-c",
                            r#"
                    test -d "$CHECKUPDATES_DB" || exit 10
                    (set -C; : > "$CHECKUPDATES_DB/db.lck") 2>/dev/null || {
                        printf 'Cannot fetch updates: database is locked' >&2
                        exit 1
                    }
                    printf '%s 1 -> 2\n' "${CHECKUPDATES_DB##*/}"
                "#,
                        ])
                        .env("CHECKUPDATES_DB", shared);
                    check_updates_with(command).unwrap()
                })
            })
            .collect();
        let results: Vec<_> = jobs.into_iter().map(|job| job.join().unwrap()).collect();
        assert_ne!(results[0][0].name, results[1][0].name);
        for updates in results {
            assert!(!std::env::temp_dir().join(&updates[0].name).exists());
        }
        assert_eq!(std::fs::read(&lock).unwrap(), b"owned by another scanner");
    }

    #[test]
    fn scanner_preserves_failures_and_no_updates_exit_semantics() {
        for (script, expected) in [
            (
                "printf 'Cannot fetch updates: network unavailable' >&2; exit 1",
                Some("network unavailable"),
            ),
            ("exit 2", None),
            (
                "printf 'unexpected output'; exit 2",
                Some("unexpected output"),
            ),
        ] {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", script]);
            let result = check_updates_with(command);
            match expected {
                Some(reason) => assert!(result.unwrap_err().contains(reason)),
                None => assert!(result.unwrap().is_empty()),
            }
        }
    }

    #[test]
    fn parses_normal_update() {
        let result = parse_updates("expat 2.7.0-1 -> 2.7.1-1").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "expat");
        assert_eq!(result[0].available, "2.7.1-1");
    }

    #[test]
    fn supports_epoch_versions() {
        let result = parse_updates("example 1:2.0-1 -> 2:2.1-1").unwrap();
        assert_eq!(result[0].installed, "1:2.0-1");
        assert_eq!(result[0].available, "2:2.1-1");
    }

    #[test]
    fn supports_multiple_packages() {
        let result = parse_updates("expat 2.7.0-1 -> 2.7.1-1\nmpv 0.40.0-1 -> 0.41.0-1\n").unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn empty_output_is_valid() {
        assert!(parse_updates("").unwrap().is_empty());
        assert!(parse_updates("\n \n").unwrap().is_empty());
    }

    #[test]
    fn rejects_malformed_output() {
        assert!(parse_updates("invalid package line").is_err());
        assert!(parse_updates("expat 1.0 => 2.0").is_err());
    }

    #[test]
    fn rejects_duplicate_packages() {
        assert!(parse_updates("expat 1.0 -> 2.0\nexpat 1.0 -> 2.0").is_err());
    }
}
