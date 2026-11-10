//! JSON Lines protocol for a future privileged helper.
//! Parsing only: no process execution, privileges or package changes.

use serde_json::Value;

pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcPhase {
    Ready,
    Commit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcMessage {
    Started,
    Progress(String),
    Phase(IpcPhase),
    Question { id: u64, text: String },
    Completed { exit_code: i32 },
    Failed(String),
    Cancelled,
}

pub fn parse_message(line: &str) -> Result<IpcMessage, String> {
    if line.len() > MAX_MESSAGE_BYTES {
        return Err("IPC message exceeds size limit".into());
    }

    let value: Value =
        serde_json::from_str(line).map_err(|_| "Invalid JSON message".to_string())?;

    let object = value
        .as_object()
        .ok_or_else(|| "IPC message must be an object".to_string())?;

    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| "Missing message type".to_string())?;

    let allowed: &[&str] = match kind {
        "started" | "cancelled" => &["type"],
        "progress" | "failed" => &["type", "text"],
        "phase" => &["type", "phase"],
        "question" => &["type", "id", "text"],
        "completed" => &["type", "exit_code"],
        _ => return Err("Unknown IPC message type".into()),
    };

    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("Unknown IPC message field".into());
    }

    let text = || -> Result<String, String> {
        object
            .get("text")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| "Missing or empty text".to_string())
    };

    match kind {
        "started" => Ok(IpcMessage::Started),
        "progress" => Ok(IpcMessage::Progress(text()?)),
        "phase" => {
            let phase = match object.get("phase").and_then(Value::as_str) {
                Some("ready") => IpcPhase::Ready,
                Some("commit") => IpcPhase::Commit,
                _ => return Err("Invalid or unsupported IPC phase".into()),
            };
            Ok(IpcMessage::Phase(phase))
        }
        "question" => {
            let id = object
                .get("id")
                .and_then(Value::as_u64)
                .filter(|id| *id > 0)
                .ok_or_else(|| "Invalid question id".to_string())?;
            Ok(IpcMessage::Question { id, text: text()? })
        }
        "completed" => {
            let code = object
                .get("exit_code")
                .and_then(Value::as_i64)
                .and_then(|n| i32::try_from(n).ok())
                .ok_or_else(|| "Invalid exit code".to_string())?;
            Ok(IpcMessage::Completed { exit_code: code })
        }
        "failed" => Ok(IpcMessage::Failed(text()?)),
        "cancelled" => Ok(IpcMessage::Cancelled),
        _ => Err("Unknown message".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_started() {
        assert_eq!(
            parse_message(r#"{"type":"started"}"#).unwrap(),
            IpcMessage::Started
        );
    }

    #[test]
    fn parses_progress() {
        assert_eq!(
            parse_message(r#"{"type":"progress","text":"Downloading"}"#).unwrap(),
            IpcMessage::Progress("Downloading".into())
        );
    }

    #[test]
    fn parses_explicit_phase_boundaries() {
        assert_eq!(
            parse_message(r#"{"type":"phase","phase":"ready"}"#).unwrap(),
            IpcMessage::Phase(IpcPhase::Ready)
        );
        assert_eq!(
            parse_message(r#"{"type":"phase","phase":"commit"}"#).unwrap(),
            IpcMessage::Phase(IpcPhase::Commit)
        );
    }

    #[test]
    fn rejects_unsupported_or_ambiguous_phase() {
        for input in [
            r#"{"type":"phase","phase":"prepare"}"#,
            r#"{"type":"phase","phase":"finished"}"#,
            r#"{"type":"phase","phase":"commit","text":"fake"}"#,
            r#"{"type":"phase","phase":null}"#,
        ] {
            assert!(parse_message(input).is_err(), "accepted: {input}");
        }
    }

    #[test]
    fn parses_question() {
        assert_eq!(
            parse_message(r#"{"type":"question","id":7,"text":"Proceed?"}"#).unwrap(),
            IpcMessage::Question {
                id: 7,
                text: "Proceed?".into()
            }
        );
    }

    #[test]
    fn parses_completion() {
        assert_eq!(
            parse_message(r#"{"type":"completed","exit_code":0}"#).unwrap(),
            IpcMessage::Completed { exit_code: 0 }
        );
    }

    #[test]
    fn rejects_unknown_type() {
        assert!(parse_message(r#"{"type":"execute"}"#).is_err());
    }

    #[test]
    fn rejects_unknown_field() {
        assert!(parse_message(r#"{"type":"started","command":"pacman"}"#).is_err());
    }

    #[test]
    fn rejects_invalid_question_id() {
        assert!(parse_message(r#"{"type":"question","id":0,"text":"Proceed?"}"#).is_err());
    }

    #[test]
    fn rejects_oversized_message() {
        let input = "x".repeat(MAX_MESSAGE_BYTES + 1);
        assert!(parse_message(&input).is_err());
    }
}

/// Messages sent from the GUI to a future privileged helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcReply {
    Answer { id: u64, approved: bool },
}

pub fn parse_reply(line: &str) -> Result<IpcReply, String> {
    if line.len() > MAX_MESSAGE_BYTES {
        return Err("IPC reply exceeds size limit".into());
    }

    let value: Value = serde_json::from_str(line).map_err(|_| "Invalid JSON reply".to_string())?;

    let object = value
        .as_object()
        .ok_or_else(|| "IPC reply must be an object".to_string())?;

    if object.len() != 3
        || !object.contains_key("type")
        || !object.contains_key("id")
        || !object.contains_key("approved")
    {
        return Err("Invalid IPC reply fields".into());
    }

    if object.get("type").and_then(Value::as_str) != Some("answer") {
        return Err("Unknown IPC reply type".into());
    }

    let id = object
        .get("id")
        .and_then(Value::as_u64)
        .filter(|id| *id > 0)
        .ok_or_else(|| "Invalid reply question id".to_string())?;

    let approved = object
        .get("approved")
        .and_then(Value::as_bool)
        .ok_or_else(|| "Invalid approval value".to_string())?;

    Ok(IpcReply::Answer { id, approved })
}

pub fn encode_reply(reply: &IpcReply) -> String {
    match reply {
        IpcReply::Answer { id, approved } => serde_json::json!({
            "type": "answer",
            "id": id,
            "approved": approved,
        })
        .to_string(),
    }
}

#[cfg(test)]
mod reply_tests {
    use super::*;

    #[test]
    fn parses_approved_answer() {
        assert_eq!(
            parse_reply(r#"{"type":"answer","id":1,"approved":true}"#).unwrap(),
            IpcReply::Answer {
                id: 1,
                approved: true
            }
        );
    }

    #[test]
    fn parses_rejected_answer() {
        assert_eq!(
            parse_reply(r#"{"type":"answer","id":2,"approved":false}"#).unwrap(),
            IpcReply::Answer {
                id: 2,
                approved: false
            }
        );
    }

    #[test]
    fn rejects_zero_question_id() {
        assert!(parse_reply(r#"{"type":"answer","id":0,"approved":true}"#).is_err());
    }

    #[test]
    fn rejects_string_approval() {
        assert!(parse_reply(r#"{"type":"answer","id":1,"approved":"yes"}"#).is_err());
    }

    #[test]
    fn rejects_unknown_reply_field() {
        assert!(
            parse_reply(r#"{"type":"answer","id":1,"approved":true,"command":"pacman"}"#).is_err()
        );
    }

    #[test]
    fn reply_roundtrip() {
        let original = IpcReply::Answer {
            id: 42,
            approved: false,
        };
        let encoded = encode_reply(&original);
        assert_eq!(parse_reply(&encoded).unwrap(), original);
    }
}

/// Read-only validation protocol: these values are claims, never COMMIT authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanValidationRequest {
    pub transaction_id: String,
    pub plan_digest: String,
    pub scope: String,
}

pub const PLAN_PROTOCOL_VERSION: u64 = 1;

impl PlanValidationRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.transaction_id.is_empty()
            || self.transaction_id.len() > 64
            || !self
                .transaction_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || self.plan_digest.len() != 64
            || !self
                .plan_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || !matches!(self.scope.as_str(), "system" | "isolated")
        {
            return Err("Invalid transaction ID, plan digest or validation scope".into());
        }
        Ok(())
    }

    pub fn as_json(&self) -> Value {
        serde_json::json!({"operation":"validate-plan","protocol_version":PLAN_PROTOCOL_VERSION,
            "transaction_id":self.transaction_id,"plan_digest":self.plan_digest,"scope":self.scope})
    }

    pub fn parse(value: &Value) -> Result<Self, String> {
        if value.as_object().is_none_or(|v| v.len() != 5)
            || value["operation"] != "validate-plan"
            || value["protocol_version"].as_u64() != Some(PLAN_PROTOCOL_VERSION)
        {
            return Err("Unsupported plan validation protocol or fields".into());
        }
        let request = Self {
            transaction_id: value["transaction_id"]
                .as_str()
                .ok_or("Missing transaction ID")?
                .into(),
            plan_digest: value["plan_digest"]
                .as_str()
                .ok_or("Missing plan digest")?
                .into(),
            scope: value["scope"]
                .as_str()
                .ok_or("Missing validation scope")?
                .into(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Bound evidence is carried in existing Progress IPC, before Completed.
    pub fn evidence(&self) -> String {
        serde_json::json!({"operation":"validate-plan","transaction_id":self.transaction_id,
            "plan_digest":self.plan_digest,"scope":self.scope,"plan_matches":true,
            "commit_authorized":false})
        .to_string()
    }

    pub fn verify_evidence(&self, text: &str) -> Result<(), String> {
        let value: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        if value.as_object().is_none_or(|v| v.len() != 6)
            || value["operation"] != "validate-plan"
            || value["transaction_id"] != self.transaction_id
            || value["plan_digest"] != self.plan_digest
            || value["scope"] != self.scope
            || value["plan_matches"] != true
            || value["commit_authorized"] != false
        {
            return Err("Helper plan evidence is missing, unbound or authorizes execution".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod plan_validation_security_tests {
    use super::*;
    #[test]
    fn plan_validation_rejects_authority_fields_wrong_versions_ids_and_evidence() {
        let request = PlanValidationRequest {
            transaction_id: "plan-1".into(),
            plan_digest: "a".repeat(64),
            scope: "system".into(),
        };
        assert_eq!(
            PlanValidationRequest::parse(&request.as_json()).unwrap(),
            request
        );
        request.verify_evidence(&request.evidence()).unwrap();
        for (field, bad) in [
            ("commit_authorized", serde_json::json!(true)),
            ("protocol_version", serde_json::json!(2)),
            ("transaction_id", serde_json::json!("../escape")),
            ("scope", serde_json::json!("execute")),
        ] {
            let mut value = request.as_json();
            value[field] = bad;
            assert!(PlanValidationRequest::parse(&value).is_err());
        }
        let mut other = request.clone();
        other.transaction_id = "plan-2".into();
        assert!(other.verify_evidence(&request.evidence()).is_err());
        let mut evidence: Value = serde_json::from_str(&request.evidence()).unwrap();
        evidence["commit_authorized"] = true.into();
        assert!(request.verify_evidence(&evidence.to_string()).is_err());
    }
}
