// RWR PACKAGE INTELLIGENCE — K13
// Harmless test: true / false only.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;

fn run_test(program: &str, report: &Path) -> Result<i32, String> {
    if !matches!(program, "/usr/bin/true" | "/usr/bin/false") {
        return Err("Program not permitted".into());
    }

    let status = Command::new(program).status().map_err(|e| e.to_string())?;

    let code = status.code().ok_or_else(|| "No exit code".to_string())?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(report)
        .map_err(|e| e.to_string())?;

    writeln!(file, "RWR_PACMAN_EXIT={code}").map_err(|e| e.to_string())?;

    file.sync_all().map_err(|e| e.to_string())?;

    Ok(code)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = std::env::temp_dir().join(format!("rwr-k13-{}", std::process::id()));

    fs::create_dir(&directory)?;

    for (name, program) in [("success", "/usr/bin/true"), ("failure", "/usr/bin/false")] {
        let report = directory.join(format!("{name}.report"));
        let code = run_test(program, &report)?;

        println!("TEST: {name}");
        println!("EXIT CODE: {code}");
        println!("{}", fs::read_to_string(&report)?);
    }

    println!("KATALOG: {}", directory.display());
    Ok(())
}
