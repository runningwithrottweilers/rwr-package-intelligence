//! GUI transport to the system supervisor. No child process or elevation here.
use crate::transaction_ipc::{IpcReply, PlanValidationRequest};
use crate::transaction_protocol::TransactionOutcome;
use std::io::{BufRead, Read, Write};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

/// Code availability only; never grants permission to execute.
pub const PRODUCTION_BACKEND_AVAILABLE: bool = true;
#[derive(Debug)]
pub enum ProductionIpcEvent {
    Progress(String),
    Question { id: u64, text: String },
    Cancelled,
    Snapshot(serde_json::Value),
    Finished(Result<TransactionOutcome, String>),
}

pub fn start_production_helper(
    plan: &crate::update_engine::UpdatePlan,
    confirmed: bool,
) -> Result<(Receiver<ProductionIpcEvent>, Sender<IpcReply>), String> {
    if !confirmed {
        return Err("Explicit user confirmation required".into());
    }
    plan.validate()?;
    Err("REAL MODE locked: a confirmed ALPM transaction is required".into())
}

pub fn start_confirmed_production_helper(
    request: &PlanValidationRequest,
) -> Result<(Receiver<ProductionIpcEvent>, Sender<IpcReply>), String> {
    start_session(request, false)
}
pub fn reconnect_production_session(
    request: &PlanValidationRequest,
) -> Result<(Receiver<ProductionIpcEvent>, Sender<IpcReply>), String> {
    start_session(request, true)
}
fn start_session(
    request: &PlanValidationRequest,
    attach: bool,
) -> Result<(Receiver<ProductionIpcEvent>, Sender<IpcReply>), String> {
    request.validate()?;
    if request.scope != "system" {
        return Err("System scope required".into());
    }
    if !attach {
        if !PRODUCTION_BACKEND_AVAILABLE
            || !rwr_package_intelligence::production_alpm_flow::real_flow_enabled()
        {
            return Err("REAL MODE locked: system supervisor validation incomplete".into());
        }
        crate::update_launcher::validate_production_ipc_precheck()?;
        rwr_package_intelligence::supervisor_client::save_execution_reference(request)?;
    }
    let request = request.clone();
    let (tx, rx) = mpsc::channel();
    let (answer_tx, answer_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = observe_session(&request, attach, &tx, answer_rx);
        let _ = tx.send(ProductionIpcEvent::Finished(result));
    });
    Ok((rx, answer_tx))
}

fn observe_session(
    request: &PlanValidationRequest,
    attach: bool,
    events: &Sender<ProductionIpcEvent>,
    answers: Receiver<IpcReply>,
) -> Result<TransactionOutcome, String> {
    observe_session_with_connector(
        request,
        attach,
        events,
        answers,
        rwr_package_intelligence::supervisor_client::connect_system_execution,
    )
}

/// Terminal outcome of an already validated execution snapshot.
/// A definite pre-COMMIT failure is reported only when the supervisor states
/// `outcome:"failure"` AND `partial_installation_possible:false`; the
/// supervisor sets that only for a verified non-zero helper exit with a
/// durable failure record (or no journal) and no COMMIT seen in IPC or the
/// journal. Anything else stays UNKNOWN / recovery required.
fn terminal_session_result(
    value: &serde_json::Value,
    request: &PlanValidationRequest,
) -> Option<Result<TransactionOutcome, String>> {
    match value["outcome"].as_str() {
        Some("success") if value["partial_installation_possible"] == false => {
            Some(Ok(TransactionOutcome::Success))
        }
        Some("failure") if value["partial_installation_possible"] == false => {
            Some(Ok(TransactionOutcome::Failure))
        }
        Some("failure") => Some(Err(format!(
            "{}; COMMIT may have started: partial installation possible; no automatic rollback; recovery required",
            value["error"]
                .as_str()
                .unwrap_or("Transaction FAILED; inspect durable journal")
        ))),
        Some("success" | "unknown") => Some(Err(format!(
            "UNKNOWN: transaction {}; do not repeat COMMIT; recovery required",
            request.transaction_id
        ))),
        _ => None,
    }
}

#[cfg(test)]
mod terminal_session_result_tests {
    use super::*;
    fn request() -> PlanValidationRequest {
        PlanValidationRequest {
            transaction_id: "plan-1".into(),
            plan_digest: "0123456789abcdef".repeat(4),
            scope: "system".into(),
        }
    }
    fn snapshot(outcome: &str, partial: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"outcome":outcome,"partial_installation_possible":partial,
            "error":"Unsafe package archive filename"})
    }
    #[test]
    fn pre_commit_failure_is_definite_only_with_explicit_no_partial() {
        assert_eq!(
            terminal_session_result(&snapshot("failure", false.into()), &request()),
            Some(Ok(TransactionOutcome::Failure))
        );
        for partial in [
            serde_json::json!(true),
            serde_json::Value::Null,
            "false".into(),
            0.into(),
        ] {
            let result =
                terminal_session_result(&snapshot("failure", partial), &request()).unwrap();
            assert!(
                result
                    .unwrap_err()
                    .contains("partial installation possible")
            );
        }
    }
    #[test]
    fn unknown_running_and_inconsistent_success_never_become_definite() {
        assert!(
            terminal_session_result(&snapshot("unknown", false.into()), &request())
                .unwrap()
                .unwrap_err()
                .contains("UNKNOWN")
        );
        assert!(
            terminal_session_result(&snapshot("success", true.into()), &request())
                .unwrap()
                .is_err()
        );
        assert_eq!(
            terminal_session_result(&snapshot("success", false.into()), &request()),
            Some(Ok(TransactionOutcome::Success))
        );
        assert_eq!(
            terminal_session_result(&snapshot("running", false.into()), &request()),
            None
        );
    }
}

fn validate_session_response(
    value: &serde_json::Value,
    request: &PlanValidationRequest,
) -> Result<(), String> {
    if value["operation"] == "execution-refusal" {
        rwr_package_intelligence::supervisor_client::validate_execution_refusal(value, request)?;
        return Err(format!(
            "Request refused ({}): {}; transaction outcome unchanged",
            value["code"].as_str().unwrap_or("unknown"),
            value["error"].as_str().unwrap_or("")
        ));
    }
    rwr_package_intelligence::supervisor_client::validate_execution_snapshot(value, request)
}

fn observe_session_with_connector(
    request: &PlanValidationRequest,
    attach: bool,
    events: &Sender<ProductionIpcEvent>,
    answers: Receiver<IpcReply>,
    mut connect: impl FnMut(
        &PlanValidationRequest,
        bool,
    ) -> Result<std::os::unix::net::UnixStream, String>,
) -> Result<TransactionOutcome, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(6 * 3600);
    let mut attach = attach;
    for attempt in 0..3 {
        let socket = match connect(request, attach) {
            Ok(socket) => socket,
            Err(error) if attach && attempt < 2 => {
                let _ = events.send(ProductionIpcEvent::Progress(format!(
                    "UNKNOWN · {} · {error}",
                    request.transaction_id
                )));
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
            Err(error) => {
                return Err(format!(
                    "UNKNOWN · {} · {error}; reconnect by ID, never repeat COMMIT",
                    request.transaction_id
                ));
            }
        };
        let mut last_question = None;
        let mut pending_question = None;
        let mut answered_question = None;
        // After ANY send attempt, reconnect may only ATTACH; never retry execute.
        attach = true;
        let mut writer = socket.try_clone().map_err(|e| e.to_string())?;
        struct Disconnect(std::os::unix::net::UnixStream);
        impl Drop for Disconnect {
            fn drop(&mut self) {
                let _ = self.0.shutdown(std::net::Shutdown::Both);
            }
        }
        let _connection = Disconnect(writer.try_clone().map_err(|e| e.to_string())?);
        let (tx, rx) = mpsc::sync_channel(32);
        std::thread::spawn(move || {
            let mut input = std::io::BufReader::new(socket);
            loop {
                let mut bytes = Vec::new();
                match input.by_ref().take(16385).read_until(b'\n', &mut bytes) {
                    Ok(0) => break,
                    Ok(_) if bytes.len() <= 16384 && bytes.last() == Some(&b'\n') => {
                        if tx
                            .send(
                                serde_json::from_slice::<serde_json::Value>(&bytes)
                                    .map_err(|e| e.to_string()),
                            )
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::UnexpectedEof
                        ) =>
                    {
                        break;
                    }
                    _ => {
                        let _ = tx.send(Err("Invalid system supervisor framing".into()));
                        break;
                    }
                }
            }
        });
        let mut last_sequence = None;
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "UNKNOWN: observation timeout for {}; no COMMIT retry",
                    request.transaction_id
                ));
            }
            match answers.try_recv() {
                Ok(IpcReply::Answer { id, approved }) => {
                    // A dialog can outlive its snapshot or a broken connection.
                    // Never forward stale/duplicate answers into a fresh session.
                    if pending_question != Some(id) || answered_question == Some(id) {
                        continue;
                    }
                    answered_question = Some(id);
                    let reply = serde_json::json!({"command":"answer","transaction_id":request.transaction_id,"id":id,"approved":approved});
                    if writeln!(writer, "{reply}")
                        .and_then(|_| writer.flush())
                        .is_err()
                    {
                        break;
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    // GUI lifetime never owns helper lifetime.
                    return Err(format!(
                        "GUI detached; reconnect to transaction {}",
                        request.transaction_id
                    ));
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Ok(value)) => {
                    // Keep the connector's 180s budget for fresh .update
                    // authorization when answering a question after ATTACH.
                    validate_session_response(&value, request)?;
                    let sequence = value["sequence"]
                        .as_u64()
                        .ok_or("Missing session sequence")?;
                    if last_sequence.is_some_and(|old| sequence < old) {
                        return Err("Execution sequence regressed".into());
                    }
                    last_sequence = Some(sequence);
                    let _ = events.send(ProductionIpcEvent::Snapshot(value.clone()));
                    pending_question = value["question"]["id"].as_u64();
                    if let (Some(id), Some(text)) = (
                        value["question"]["id"].as_u64(),
                        value["question"]["text"].as_str(),
                    ) {
                        if last_question != Some(id) {
                            last_question = Some(id);
                            let _ = events.send(ProductionIpcEvent::Question {
                                id,
                                text: text.into(),
                            });
                        }
                    }
                    if let Some(result) = terminal_session_result(&value, request) {
                        if let (Ok(TransactionOutcome::Failure), Some(error)) =
                            (&result, value["error"].as_str())
                        {
                            let _ = events.send(ProductionIpcEvent::Progress(error.into()));
                        }
                        return result;
                    }
                }
                Ok(Err(error)) => {
                    return Err(format!(
                        "UNKNOWN: invalid supervisor frame: {error}; reconnect using the same ID"
                    ));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        let _ = events.send(ProductionIpcEvent::Progress(format!(
            "Connection lost; attaching to {} ({}/3)",
            request.transaction_id,
            attempt + 1
        )));
    }
    Err(format!(
        "UNKNOWN: cannot reconnect to {}; never repeat COMMIT automatically",
        request.transaction_id
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn confirmed_production_request_stops_before_spawn() {
        let request = PlanValidationRequest {
            transaction_id: "locked-1".into(),
            plan_digest: "a".repeat(64),
            scope: "system".into(),
        };
        assert!(PRODUCTION_BACKEND_AVAILABLE);
        assert!(!rwr_package_intelligence::production_alpm_flow::real_flow_enabled());
        assert!(
            request_execution_cancellation(&request)
                .unwrap_err()
                .contains("REAL MODE locked")
        );
        assert!(
            start_confirmed_production_helper(&request)
                .unwrap_err()
                .contains("REAL MODE locked")
        );
        // Read-only reconnect has a separate path, never an execution grant.
    }
    #[test]
    fn production_entrypoint_requires_confirmation() {
        let plan = crate::update_engine::UpdatePlan::arch_full_upgrade();
        assert!(
            start_production_helper(&plan, false)
                .unwrap_err()
                .contains("confirmation")
        );
        assert!(
            start_production_helper(&plan, true)
                .unwrap_err()
                .contains("REAL MODE locked")
        );
    }
}

/// Explicit cancellation is independent of disconnect and never repeats execute.
/// The server obtains a fresh Polkit decision and writes to its owned control FD.
pub fn request_execution_cancellation(
    request: &PlanValidationRequest,
) -> Result<Receiver<Result<serde_json::Value, String>>, String> {
    request.validate()?;
    if !PRODUCTION_BACKEND_AVAILABLE
        || !rwr_package_intelligence::production_alpm_flow::real_flow_enabled()
    {
        return Err("REAL MODE locked: cancellation endpoint is not deployed/validated".into());
    }
    crate::update_launcher::validate_production_ipc_precheck()?;
    let request = request.clone();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let result = (|| -> Result<serde_json::Value, String> {
            let socket =
                rwr_package_intelligence::supervisor_client::connect_system_cancellation(&request)?;
            let mut input = std::io::BufReader::new(socket);
            let mut bytes = Vec::new();
            input
                .by_ref()
                .take(16385)
                .read_until(b'\n', &mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() > 16384 || bytes.last() != Some(&b'\n') {
                return Err("Invalid cancellation response".into());
            }
            let snapshot = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            validate_session_response(&snapshot, &request)?;
            Ok(snapshot)
        })();
        let _ = sender.send(result);
    });
    Ok(receiver)
}

#[cfg(test)]
mod reconnect_wire_tests {
    use super::*;
    fn request() -> PlanValidationRequest {
        PlanValidationRequest {
            transaction_id: "wire-1".into(),
            plan_digest: "a".repeat(64),
            scope: "system".into(),
        }
    }
    fn unknown(request: &PlanValidationRequest) -> serde_json::Value {
        let mut session =
            rwr_package_intelligence::supervisor_session::ExecutionSession::new(request.clone())
                .unwrap();
        session.supervision_lost("owner unavailable".into());
        session.snapshot()
    }
    #[test]
    fn disconnect_retries_attach_without_repeating_execute() {
        let request = request();
        let (events, _) = mpsc::channel();
        let (_answers, rx) = mpsc::channel();
        let mut calls = Vec::new();
        let result =
            observe_session_with_connector(&request, false, &events, rx, |request, attach| {
                calls.push(attach);
                let (client, mut server) =
                    std::os::unix::net::UnixStream::pair().map_err(|e| e.to_string())?;
                if calls.len() > 1 {
                    writeln!(server, "{}", unknown(request)).unwrap();
                }
                Ok(client)
            });
        assert!(result.unwrap_err().contains("UNKNOWN"));
        assert_eq!(calls, [false, true]);
    }
    #[test]
    fn silent_transport_timeout_attaches_instead_of_executing_again() {
        let request = request();
        let (events, _) = mpsc::channel();
        let (_answers, rx) = mpsc::channel();
        let mut calls = Vec::new();
        let result =
            observe_session_with_connector(&request, false, &events, rx, |request, attach| {
                calls.push(attach);
                let (client, mut server) =
                    std::os::unix::net::UnixStream::pair().map_err(|e| e.to_string())?;
                client
                    .set_read_timeout(Some(Duration::from_millis(20)))
                    .unwrap();
                if calls.len() == 1 {
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(100));
                        drop(server);
                    });
                } else {
                    writeln!(server, "{}", unknown(request)).unwrap();
                }
                Ok(client)
            });
        assert!(result.unwrap_err().contains("UNKNOWN"));
        assert_eq!(calls, [false, true]);
    }
    #[test]
    fn obsolete_and_duplicate_dialog_answers_are_not_forwarded() {
        use std::io::BufReader;
        let request = request();
        let mut session =
            rwr_package_intelligence::supervisor_session::ExecutionSession::new(request.clone())
                .unwrap();
        session.observe_line(r#"{"type":"started"}"#).unwrap();
        session
            .observe_line(r#"{"type":"question","id":1,"text":"first"}"#)
            .unwrap();
        session.answer(1, true).unwrap();
        session
            .observe_line(r#"{"type":"question","id":2,"text":"current"}"#)
            .unwrap();
        let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (events, received) = mpsc::channel();
        let (answers, replies) = mpsc::channel();
        let observer = std::thread::spawn(move || {
            let mut connection = Some(client);
            observe_session_with_connector(&request, true, &events, replies, |_, _| {
                Ok(connection.take().expect("unexpected reconnect"))
            })
        });
        writeln!(server, "{}", session.snapshot()).unwrap();
        loop {
            if matches!(
                received.recv_timeout(Duration::from_secs(2)).unwrap(),
                ProductionIpcEvent::Question { id: 2, .. }
            ) {
                break;
            }
        }
        answers
            .send(IpcReply::Answer {
                id: 1,
                approved: true,
            })
            .unwrap();
        answers
            .send(IpcReply::Answer {
                id: 2,
                approved: false,
            })
            .unwrap();
        answers
            .send(IpcReply::Answer {
                id: 2,
                approved: true,
            })
            .unwrap();
        let mut reader = BufReader::new(server.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["id"], 2);
        assert_eq!(value["approved"], false);
        server
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        line.clear();
        let duplicate = reader.read_line(&mut line);
        session.supervision_lost("test end, no transaction executed".into());
        writeln!(server, "{}", session.snapshot()).unwrap();
        assert!(observer.join().unwrap().unwrap_err().contains("UNKNOWN"));
        assert!(
            duplicate.is_err(),
            "duplicate answer reached supervisor: {line}"
        );
    }
    #[test]
    fn snapshots_preserve_timeout_for_answer_authorization() {
        // Transport regression only: no Polkit decision or COMMIT is simulated.
        let request = request();
        let mut session =
            rwr_package_intelligence::supervisor_session::ExecutionSession::new(request.clone())
                .unwrap();
        let snapshot = session.snapshot();
        let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(180)))
            .unwrap();
        let probe = client.try_clone().unwrap();
        let (events, received) = mpsc::channel();
        let (_answers, replies) = mpsc::channel();
        let observer = std::thread::spawn(move || {
            let mut connection = Some(client);
            observe_session_with_connector(&request, true, &events, replies, |_, _| {
                Ok(connection.take().expect("no reconnect expected"))
            })
        });
        writeln!(server, "{snapshot}").unwrap();
        assert!(matches!(
            received.recv_timeout(Duration::from_secs(2)).unwrap(),
            ProductionIpcEvent::Snapshot(_)
        ));
        let timeout = probe.read_timeout().unwrap();
        session.supervision_lost("end transport regression".into());
        writeln!(server, "{}", session.snapshot()).unwrap();
        assert!(observer.join().unwrap().unwrap_err().contains("UNKNOWN"));
        assert_eq!(
            timeout,
            Some(Duration::from_secs(180)),
            "snapshot must not shorten pending .update authorization budget"
        );
    }
    #[test]
    fn authorization_refusal_is_not_a_transaction_result() {
        let request = request();
        let (events, received) = mpsc::channel();
        let (_answers, rx) = mpsc::channel();
        let mut calls = 0;
        let result = observe_session_with_connector(
            &request,
            true,
            &events,
            rx,
            |request, attach| {
                assert!(attach);
                calls += 1;
                let (client, mut server) =
                    std::os::unix::net::UnixStream::pair().map_err(|e| e.to_string())?;
                let refusal = serde_json::json!({"operation":"execution-refusal","protocol_version":1,"transaction_id":request.transaction_id,"plan_digest":request.plan_digest,"code":"authorization_denied","error":"denied","commit_authorized":false,"request_executed":false,"real_execution_enabled":false});
                writeln!(server, "{refusal}").unwrap();
                Ok(client)
            },
        );
        assert!(
            result
                .unwrap_err()
                .contains("transaction outcome unchanged")
        );
        assert_eq!(calls, 1);
        assert!(
            received
                .try_iter()
                .all(|event| !matches!(event, ProductionIpcEvent::Snapshot(_)))
        );
    }
}

#[cfg(test)]
mod cancellation_response_tests {
    use super::*;
    #[test]
    fn cancellation_retains_real_authorization_refusal_and_binding() {
        let request = PlanValidationRequest {
            transaction_id: "cancel-denied".into(),
            plan_digest: "a".repeat(64),
            scope: "system".into(),
        };
        let mut response = serde_json::json!({
            "operation":"execution-refusal", "protocol_version":1,
            "transaction_id":request.transaction_id, "plan_digest":request.plan_digest,
            "code":"authorization_denied", "error":"Polkit denied",
            "commit_authorized":false, "request_executed":false,
            "real_execution_enabled":false
        });
        let error = validate_session_response(&response, &request).unwrap_err();
        assert!(error.contains("Polkit denied"));
        assert!(error.contains("transaction outcome unchanged"));
        response["transaction_id"] = "another-session".into();
        assert!(
            validate_session_response(&response, &request)
                .unwrap_err()
                .contains("Invalid execution refusal")
        );
    }
}
