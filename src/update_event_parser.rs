use crate::update_events::{UpdateEvent, UpdateEventController};

pub fn parse_event(line: &str) -> Result<UpdateEvent, String> {
    let value = line
        .strip_prefix("RWR_EVENT=")
        .ok_or("Missing RWR_EVENT prefix")?;

    match value {
        "VERIFY" => Ok(UpdateEvent::VerificationStarted),
        "INSTALL" => Ok(UpdateEvent::InstallationStarted),
        "COMPLETE" => Ok(UpdateEvent::InstallationCompleted),
        "CANCEL" => Ok(UpdateEvent::Cancelled),
        "FAIL" => Ok(UpdateEvent::Failed),
        _ => {
            let percent = value.strip_prefix("DOWNLOAD:").ok_or("Unknown event")?;

            if percent.is_empty()
                || percent.len() > 3
                || !percent.bytes().all(|c| c.is_ascii_digit())
                || (percent.len() > 1 && percent.as_bytes()[0] == 48)
            {
                return Err("Invalid percentage".into());
            }

            let percent = percent.parse::<u8>().map_err(|_| "Invalid percentage")?;

            if percent > 100 {
                return Err("Percentage exceeds 100".into());
            }

            Ok(UpdateEvent::DownloadProgress(percent))
        }
    }
}

pub fn apply_event(controller: &mut UpdateEventController, line: &str) -> Result<(), String> {
    controller.apply(parse_event(line)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update_progress::UpdatePhase;

    #[test]
    fn parses_download() {
        assert_eq!(
            parse_event("RWR_EVENT=DOWNLOAD:42").unwrap(),
            UpdateEvent::DownloadProgress(42)
        );
    }

    #[test]
    fn parses_stages() {
        assert_eq!(
            parse_event("RWR_EVENT=VERIFY").unwrap(),
            UpdateEvent::VerificationStarted
        );
        assert_eq!(
            parse_event("RWR_EVENT=INSTALL").unwrap(),
            UpdateEvent::InstallationStarted
        );
        assert_eq!(
            parse_event("RWR_EVENT=COMPLETE").unwrap(),
            UpdateEvent::InstallationCompleted
        );
        assert_eq!(
            parse_event("RWR_EVENT=CANCEL").unwrap(),
            UpdateEvent::Cancelled
        );
        assert_eq!(parse_event("RWR_EVENT=FAIL").unwrap(), UpdateEvent::Failed);
    }

    #[test]
    fn rejects_invalid_data() {
        for line in [
            "",
            "DOWNLOAD:20",
            "RWR_EVENT=UNKNOWN",
            "RWR_EVENT=DOWNLOAD:-1",
            "RWR_EVENT=DOWNLOAD:101",
            "RWR_EVENT=DOWNLOAD:001",
            "RWR_EVENT=DOWNLOAD:abc",
            "RWR_EVENT=DOWNLOAD:20 extra",
        ] {
            assert!(parse_event(line).is_err());
        }
    }

    #[test]
    fn accepts_complete_sequence() {
        let mut controller = UpdateEventController::new();

        for event in [
            "RWR_EVENT=DOWNLOAD:50",
            "RWR_EVENT=DOWNLOAD:100",
            "RWR_EVENT=VERIFY",
            "RWR_EVENT=INSTALL",
            "RWR_EVENT=COMPLETE",
        ] {
            apply_event(&mut controller, event).unwrap();
        }

        assert_eq!(controller.progress().phase, UpdatePhase::Completed);
    }

    #[test]
    fn rejects_invalid_sequence() {
        let mut controller = UpdateEventController::new();
        assert!(apply_event(&mut controller, "RWR_EVENT=INSTALL").is_err());
        apply_event(&mut controller, "RWR_EVENT=DOWNLOAD:80").unwrap();
        assert!(apply_event(&mut controller, "RWR_EVENT=DOWNLOAD:20").is_err());
    }

    #[test]
    fn cancellation_blocks_installation() {
        let mut controller = UpdateEventController::new();
        apply_event(&mut controller, "RWR_EVENT=DOWNLOAD:30").unwrap();
        apply_event(&mut controller, "RWR_EVENT=CANCEL").unwrap();

        assert_eq!(controller.progress().phase, UpdatePhase::Cancelled);
        assert!(apply_event(&mut controller, "RWR_EVENT=INSTALL").is_err());
    }
}
