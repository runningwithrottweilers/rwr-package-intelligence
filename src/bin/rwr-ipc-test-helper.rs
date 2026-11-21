use serde_json::{Value, json};
use std::io::{self, BufRead, BufReader, Read, Write};

const MAX_MESSAGE_BYTES: usize = 16 * 1024;

fn run() -> Result<i32, String> {
    let stdout = io::stdout();
    let mut output = stdout.lock();

    // Versioned diagnostic fixture handshake requested only by the supervisor.
    if std::env::var("RWR_DIAGNOSTIC_HANDSHAKE").as_deref() == Ok("1") {
        writeln!(
            output,
            "{}",
            json!({
                "type":"hello", "component":"rwr-ipc-test-helper",
                "protocol_version":1, "real_execution_enabled":false
            })
        )
        .map_err(|e| e.to_string())?;
    }

    writeln!(output, "{}", json!({"type":"started"})).map_err(|e| e.to_string())?;
    let phases = std::env::var("RWR_DIAGNOSTIC_TEST_PHASES").as_deref() == Ok("1");
    if phases {
        writeln!(
            output,
            "{}",
            json!({"type":"progress","text":"TEST MODE: preparing diagnostic session"})
        )
        .map_err(|e| e.to_string())?;
        writeln!(output, "{}", json!({"type":"phase","phase":"ready"}))
            .map_err(|e| e.to_string())?;
    }

    writeln!(
        output,
        "{}",
        json!({
            "type":"question",
            "id":1,
            "text":"TEST MODE: Continue simulated transaction?"
        })
    )
    .map_err(|e| e.to_string())?;
    output.flush().map_err(|e| e.to_string())?;

    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut limited = reader.by_ref().take((MAX_MESSAGE_BYTES + 2) as u64);
    let mut bytes = Vec::new();
    limited
        .read_until(b'\n', &mut bytes)
        .map_err(|e| e.to_string())?;

    if bytes.is_empty() || bytes.len() > MAX_MESSAGE_BYTES + 1 || bytes.last() != Some(&b'\n') {
        return Err("Invalid or oversized IPC input".into());
    }

    bytes.pop();
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err("IPC input exceeds size limit".into());
    }

    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid JSON reply".to_string())?;
    let object = value.as_object().ok_or("Reply must be an object")?;

    if object.len() != 3
        || object.get("type").and_then(Value::as_str) != Some("answer")
        || object.get("id").and_then(Value::as_u64) != Some(1)
    {
        return Err("Invalid IPC reply identity".into());
    }

    match object.get("approved").and_then(Value::as_bool) {
        Some(true) => {
            if phases {
                writeln!(output, "{}", json!({"type":"phase","phase":"commit"}))
                    .map_err(|e| e.to_string())?;
            }
            // Opt-in fixture event; no package work or timing assumptions.
            if std::env::var("RWR_DIAGNOSTIC_TEST_PROGRESS").as_deref() == Ok("1") {
                writeln!(
                    output,
                    "{}",
                    json!({"type":"progress","text":"TEST MODE: simulated diagnostic progress"})
                )
                .map_err(|e| e.to_string())?;
            }
            writeln!(output, "{}", json!({"type":"completed","exit_code":0}))
                .map_err(|e| e.to_string())?;
            output.flush().map_err(|e| e.to_string())?;
            Ok(0)
        }
        Some(false) => {
            writeln!(output, "{}", json!({"type":"cancelled"})).map_err(|e| e.to_string())?;
            output.flush().map_err(|e| e.to_string())?;
            Ok(2)
        }
        None => Err("Invalid approval value".into()),
    }
}

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("RWR TEST HELPER: {error}");
            1
        }
    };
    std::process::exit(code);
}
