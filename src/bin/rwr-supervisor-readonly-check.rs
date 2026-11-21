//! Controlled Dell E2E probe using the actual GUI client library. No GTK window,
//! helper launch, EXECUTE/CANCEL command, installation or package manager.
use rwr_package_intelligence::{
    supervisor_client as client, transaction_ipc::PlanValidationRequest,
};
use std::io::{BufRead, Read};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn status(label: &str) -> Result<(), String> {
    let value = client::read_system_supervisor_status()?;
    if value["real_execution_enabled"] != false
        || value["execution_locked"] != true
        || value["commit_authorized"] != false
    {
        return Err("Unsafe status: expected REAL=false and COMMIT locked".into());
    }
    println!("PASS {label}: {}", value);
    Ok(())
}
fn expect_idle_close(mut socket: UnixStream, label: &str) -> Result<(), String> {
    socket
        .set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|e| e.to_string())?;
    let started = Instant::now();
    let mut byte = [0];
    let closed = match socket.read(&mut byte) {
        Ok(0) => true,
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => true,
        Ok(_) => return Err(format!("{label}: unexpected application data")),
        Err(error) => {
            return Err(format!(
                "{label}: server did not close idle connection: {error}"
            ));
        }
    };
    if !closed || started.elapsed() < Duration::from_secs(4) {
        return Err(format!(
            "{label}: closed too early to demonstrate the 5s server timeout"
        ));
    }
    println!(
        "PASS {label}: closed by server after {:.2}s",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
fn transport() -> Result<(), String> {
    status("status / verified GUI client handshake")?;
    let socket = UnixStream::connect(rwr_package_intelligence::supervisor_trust::SYSTEM_SOCKET)
        .map_err(|e| e.to_string())?;
    socket
        .shutdown(std::net::Shutdown::Both)
        .map_err(|e| e.to_string())?;
    drop(socket); // Deliberately no data; this must not stop the service.
    status("reconnect after empty disconnect")?;
    println!("TEST idle timeout before handshake (about 5s)");
    expect_idle_close(
        UnixStream::connect(rwr_package_intelligence::supervisor_trust::SYSTEM_SOCKET)
            .map_err(|e| e.to_string())?,
        "idle before handshake",
    )?;
    status("reconnect after handshake timeout")?;
    println!("TEST idle timeout after verified handshake (about 5s)");
    expect_idle_close(
        client::connect_readonly_system_probe()?,
        "idle before JSON request",
    )?;
    status("final reconnect")
}
fn inspect_denial() -> Result<(), String> {
    status("before inspect denial")?;
    println!(
        "TEST .inspect: w oknie Polkit wybierz ODRZUĆ/ANULUJ. Zgoda na odczyt NIE zaliczy tego testu odmowy."
    );
    let request = PlanValidationRequest {
        transaction_id: format!(
            "rwr-ro-probe-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_nanos()
        ),
        plan_digest: "0".repeat(64),
        scope: "system".into(),
    };
    request.validate()?;
    // Hardcoded ATTACH. The synthetic ID locates no approved plan and cannot
    // start anything: server ATTACH never falls back to EXECUTE.
    let socket = client::connect_system_execution(&request, true)?;
    let mut bytes = Vec::new();
    std::io::BufReader::new(socket)
        .take(16385)
        .read_until(b'\n', &mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 16384 || bytes.last() != Some(&b'\n') {
        return Err("Invalid refusal frame".into());
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    client::validate_execution_refusal(&value, &request)?;
    if value["code"] != "authorization_denied" {
        return Err(format!(
            "Expected authorization_denied, received {}: {}. No COMMIT was requested; an approved read/missing history is NOT a denial PASS.",
            value["code"], value["error"]
        ));
    }
    let detail = value["error"].as_str().unwrap_or("").to_lowercase();
    if !detail.contains("polkit denied") && !detail.contains("cancel") {
        return Err(format!(
            "Refusal did not demonstrate a Polkit denial/cancellation: {}; inspect logs",
            value["error"]
        ));
    }
    println!(
        "PASS readonly ATTACH refused by actual supervisor: {}",
        value
    );
    println!(
        "NOTE: inspect error details/logs; this is not proof of successful Polkit authorization."
    );
    status("reconnect after refusal")
}
fn run() -> Result<(), String> {
    if unsafe { libc::getuid() } == 0 || unsafe { libc::geteuid() } == 0 {
        return Err("Run this GUI-client test as an ordinary user, not root".into());
    }
    if rwr_package_intelligence::production_alpm_flow::real_flow_enabled() {
        return Err("This probe requires REAL=false".into());
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode] if mode == "--status-only" => status("readonly status"),
        [mode] if mode == "--transport" => transport(),
        [mode] if mode == "--inspect-denial" => inspect_denial(),
        _ => Err(
            "Usage: rwr-supervisor-readonly-check --status-only | --transport | --inspect-denial"
                .into(),
        ),
    }
}
fn main() {
    if let Err(error) = rwr_package_intelligence::test_isolation::refuse("readonly system probe")
        .and_then(|_| run())
    {
        eprintln!("FAIL / BLOCKED: {error}");
        std::process::exit(1);
    }
}

// Test builds of this binary never reach the production host (deny-only).
rwr_package_intelligence::isolate_test_binary!();
