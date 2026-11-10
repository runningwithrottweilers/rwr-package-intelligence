//! FBI ACCESS AUTHORIZATION — presentation of system Polkit authorization.
//!
//! Status only. The password is typed exclusively in the session's system
//! Polkit agent, which the root supervisor/helper invoke themselves. This
//! module has no password field, opens no dialog, asks for no confirmation
//! and grants nothing: states are derived only from events the GUI already
//! receives (supervisor snapshots and terminal results).
use gtk4::prelude::*;
use gtk4::{Box as GtkBox, Label, Orientation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    /// Installation: supervisor (.update) then helper (.update), two dialogs.
    Execute,
    /// SPRAWDŹ WYNIK: read-only attach, supervisor (.inspect), one dialog.
    Inspect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    Refused,
    Cancelled,
    NoAgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessStatus {
    Awaiting,
    /// Execute only: supervisor accepted (first snapshot); helper pending.
    FirstGranted,
    Granted,
    Denied(Denial),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FbiAccess {
    pub kind: AccessKind,
    pub status: AccessStatus,
    pub case_id: String,
    supervisor_granted: bool,
}

impl FbiAccess {
    pub fn awaiting(kind: AccessKind, case_id: &str) -> Self {
        Self {
            kind,
            status: AccessStatus::Awaiting,
            case_id: case_id.into(),
            supervisor_granted: false,
        }
    }

    /// A validated supervisor snapshot exists only after the supervisor's
    /// Polkit decision; `phase: ready` exists only after the helper's own
    /// Polkit decision and a successful PREPARE.
    pub fn on_snapshot(&mut self, value: &serde_json::Value) {
        if matches!(self.status, AccessStatus::Granted | AccessStatus::Denied(_)) {
            return;
        }
        let running = value["outcome"] == "running";
        let helper_passed = value["outcome"] == "success"
            || (running
                && matches!(
                    value["phase"].as_str(),
                    Some("ready" | "commit" | "commit_started")
                ));
        self.status = match self.kind {
            AccessKind::Inspect => AccessStatus::Granted,
            AccessKind::Execute if helper_passed => AccessStatus::Granted,
            AccessKind::Execute if running => {
                self.supervisor_granted = true;
                AccessStatus::FirstGranted
            }
            AccessKind::Execute => self.status,
        };
    }

    /// After the terminal result: keep the card only for an authorization
    /// denial; otherwise the regular result screen takes over.
    pub fn after_finished(mut self, text: &str) -> Option<Self> {
        if self.status == AccessStatus::Granted {
            return None;
        }
        let denial = denial_from_text(text)?;
        self.status = AccessStatus::Denied(denial);
        Some(self)
    }
}

/// Maps the existing Polkit error texts (production_alpm_flow::
/// require_allowed_polkit_result, supervisor `authorization_denied`).
pub fn denial_from_text(text: &str) -> Option<Denial> {
    if text.contains("Polkit authentication cancelled by user") {
        Some(Denial::Cancelled)
    } else if text.contains("Polkit authentication not completed")
        || text.contains("Polkit authorization unavailable")
    {
        Some(Denial::NoAgent)
    } else if text.contains("Polkit denied") || text.contains("(authorization_denied)") {
        Some(Denial::Refused)
    } else {
        None
    }
}

fn tr(english: bool, pl: &str, en: &str) -> String {
    if english { en } else { pl }.to_string()
}

/// (title, detail) for a state.
pub fn texts(access: &FbiAccess, english: bool) -> (String, String) {
    match (access.kind, access.status) {
        (AccessKind::Execute, AccessStatus::Awaiting) => (
            tr(
                english,
                "OCZEKIWANIE NA AUTORYZACJĘ",
                "AWAITING AUTHORIZATION",
            ),
            tr(
                english,
                "Okno systemowe Polkit poprosi o hasło administratora (supervisor, 1/2).",
                "The system Polkit dialog will ask for the administrator password (supervisor, 1/2).",
            ),
        ),
        (AccessKind::Inspect, AccessStatus::Awaiting) => (
            tr(
                english,
                "OCZEKIWANIE NA AUTORYZACJĘ",
                "AWAITING AUTHORIZATION",
            ),
            tr(
                english,
                "SPRAWDŹ WYNIK: tylko odczyt, bez COMMIT. Okno Polkit poprosi o hasło.",
                "CHECK RESULT: read-only, no COMMIT. The Polkit dialog will ask for the password.",
            ),
        ),
        (_, AccessStatus::FirstGranted) => (
            tr(english, "AUTORYZACJA 1/2 PRZYJĘTA", "CLEARANCE 1/2 GRANTED"),
            tr(
                english,
                "Drugie okno Polkit (2/2): helper transakcji sprawdza uprawnienia niezależnie.",
                "Second Polkit dialog (2/2): the transaction helper checks authorization independently.",
            ),
        ),
        (AccessKind::Execute, AccessStatus::Granted) => (
            "ACCESS GRANTED".into(),
            tr(
                english,
                "Autoryzacja potwierdzona. Plan sprawdzony ponownie — pobieranie i weryfikacja podpisów.",
                "Authorization confirmed. Plan rechecked — downloading and verifying signatures.",
            ),
        ),
        (AccessKind::Inspect, AccessStatus::Granted) => (
            "ACCESS GRANTED".into(),
            tr(
                english,
                "Autoryzacja potwierdzona. Odczyt wyniku transakcji, bez COMMIT.",
                "Authorization confirmed. Reading the transaction result, no COMMIT.",
            ),
        ),
        (_, AccessStatus::Denied(denial)) => (
            "ACCESS DENIED".into(),
            match denial {
                Denial::Refused => tr(
                    english,
                    "Polkit odmówił autoryzacji.",
                    "Polkit denied authorization.",
                ),
                Denial::Cancelled => tr(
                    english,
                    "Anulowano okno Polkit.",
                    "The Polkit dialog was cancelled.",
                ),
                Denial::NoAgent => tr(
                    english,
                    "Uwierzytelnienie Polkit nie zostało ukończone. Sprawdź agenta sesji.",
                    "Polkit authentication did not complete. Check the session authentication agent.",
                ),
            },
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Idle,
    Now,
    Ok,
    No,
}

/// Step labels and their states.
pub fn steps(access: &FbiAccess, english: bool) -> Vec<(String, Step)> {
    use Step::*;
    match access.kind {
        AccessKind::Execute => {
            let states = match access.status {
                AccessStatus::Awaiting => [Now, Idle, Idle, Idle],
                AccessStatus::FirstGranted => [Ok, Now, Idle, Idle],
                AccessStatus::Granted => [Ok, Ok, Ok, Idle],
                AccessStatus::Denied(_) if access.supervisor_granted => [Ok, No, Idle, Idle],
                AccessStatus::Denied(_) => [No, Idle, Idle, Idle],
            };
            ["SUPERVISOR", "HELPER", "PLAN", "COMMIT"]
                .into_iter()
                .map(String::from)
                .zip(states)
                .collect()
        }
        AccessKind::Inspect => {
            let states = match access.status {
                AccessStatus::Awaiting | AccessStatus::FirstGranted => [Now, Idle],
                AccessStatus::Granted => [Ok, Ok],
                AccessStatus::Denied(_) => [No, Idle],
            };
            vec![
                ("SUPERVISOR".into(), states[0]),
                (tr(english, "ODCZYT WYNIKU", "RESULT READ"), states[1]),
            ]
        }
    }
}

pub struct FbiCard {
    pub root: GtkBox,
    case: Label,
    status: Label,
    detail: Label,
    steps: GtkBox,
    note: Label,
}

pub fn build_card() -> FbiCard {
    let root = GtkBox::new(Orientation::Vertical, 6);
    root.add_css_class("fbi-card");
    root.set_visible(false);
    let top = GtkBox::new(Orientation::Horizontal, 12);
    let seal = Label::new(Some("FBI · ACCESS AUTHORIZATION"));
    seal.add_css_class("fbi-seal");
    seal.set_hexpand(true);
    seal.set_xalign(0.0);
    let case = Label::new(None);
    case.add_css_class("fbi-case");
    case.set_xalign(1.0);
    case.set_wrap(true);
    case.set_wrap_mode(gtk4::pango::WrapMode::WordChar);
    top.append(&seal);
    top.append(&case);
    let status = Label::new(None);
    status.add_css_class("fbi-status");
    status.set_xalign(0.0);
    let detail = Label::new(None);
    detail.add_css_class("fbi-detail");
    detail.set_xalign(0.0);
    detail.set_wrap(true);
    let steps = GtkBox::new(Orientation::Horizontal, 8);
    steps.add_css_class("fbi-steps");
    let note = Label::new(None);
    note.add_css_class("fbi-note");
    note.set_xalign(0.0);
    note.set_wrap(true);
    for widget in [
        top.upcast_ref::<gtk4::Widget>(),
        status.upcast_ref(),
        detail.upcast_ref(),
        steps.upcast_ref(),
        note.upcast_ref(),
    ] {
        root.append(widget);
    }
    FbiCard {
        root,
        case,
        status,
        detail,
        steps,
        note,
    }
}

pub fn update_card(card: &FbiCard, access: Option<&FbiAccess>, english: bool) {
    let Some(access) = access else {
        card.root.set_visible(false);
        return;
    };
    for class in ["fbi-pending", "fbi-granted", "fbi-denied"] {
        card.root.remove_css_class(class);
    }
    card.root.add_css_class(match access.status {
        AccessStatus::Granted => "fbi-granted",
        AccessStatus::Denied(_) => "fbi-denied",
        _ => "fbi-pending",
    });
    let (title, detail) = texts(access, english);
    card.status.set_text(&format!("● {title}"));
    card.detail.set_text(&detail);
    card.case.set_text(&format!(
        "{} {}",
        tr(english, "SPRAWA", "CASE"),
        access.case_id
    ));
    card.note.set_text(&tr(
        english,
        "Hasło wpisujesz wyłącznie w systemowym oknie Polkit. RWR nie zbiera ani nie widzi hasła.",
        "You type the password only in the system Polkit dialog. RWR never collects or sees it.",
    ));
    while let Some(child) = card.steps.first_child() {
        card.steps.remove(&child);
    }
    for (name, step) in steps(access, english) {
        let label = Label::new(Some(&name));
        label.add_css_class("fbi-step");
        label.add_css_class(match step {
            Step::Idle => "fbi-step-idle",
            Step::Now => "fbi-step-now",
            Step::Ok => "fbi-step-ok",
            Step::No => "fbi-step-no",
        });
        card.steps.append(&label);
    }
    card.root.set_visible(true);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn execute_needs_helper_phase_for_access_granted() {
        let mut access = FbiAccess::awaiting(AccessKind::Execute, "plan-1");
        access.on_snapshot(&json!({"outcome":"running","phase":"prepare"}));
        assert_eq!(access.status, AccessStatus::FirstGranted);
        access.on_snapshot(&json!({"outcome":"running","phase":"ready"}));
        assert_eq!(access.status, AccessStatus::Granted);
        // Never regresses once granted.
        access.on_snapshot(&json!({"outcome":"running","phase":"prepare"}));
        assert_eq!(access.status, AccessStatus::Granted);
        assert_eq!(access.clone().after_finished("Polkit denied"), None);
    }

    #[test]
    fn terminal_failure_does_not_imply_helper_authorization() {
        let mut access = FbiAccess::awaiting(AccessKind::Execute, "plan-1");
        access.on_snapshot(&json!({"outcome":"failure","phase":"finished"}));
        assert_eq!(access.status, AccessStatus::Awaiting);
        let denied = access.after_finished("Polkit denied").unwrap();
        assert_eq!(denied.status, AccessStatus::Denied(Denial::Refused));
    }

    #[test]
    fn inspect_is_granted_by_first_snapshot() {
        let mut access = FbiAccess::awaiting(AccessKind::Inspect, "plan-1");
        access.on_snapshot(&json!({"outcome":"unknown","phase":"prepare"}));
        assert_eq!(access.status, AccessStatus::Granted);
    }

    #[test]
    fn existing_polkit_errors_map_to_denial_reasons() {
        for (text, denial) in [
            (
                "Request refused (authorization_denied): Polkit denied; transaction outcome unchanged",
                Denial::Refused,
            ),
            (
                "Request refused (authorization_denied): Polkit authentication cancelled by user; transaction outcome unchanged",
                Denial::Cancelled,
            ),
            (
                "Polkit authentication not completed; check the session authentication agent",
                Denial::NoAgent,
            ),
            ("Polkit authorization unavailable: timeout", Denial::NoAgent),
        ] {
            assert_eq!(denial_from_text(text), Some(denial), "{text}");
        }
        assert_eq!(denial_from_text("Unsafe package archive filename"), None);
        assert_eq!(denial_from_text("UNKNOWN: transaction plan-1"), None);
    }

    #[test]
    fn denial_after_supervisor_marks_helper_step() {
        let mut access = FbiAccess::awaiting(AccessKind::Execute, "plan-1");
        access.on_snapshot(&json!({"outcome":"running","phase":"prepare"}));
        let denied = access
            .after_finished("Polkit authentication cancelled by user")
            .unwrap();
        assert_eq!(denied.status, AccessStatus::Denied(Denial::Cancelled));
        let states: Vec<Step> = steps(&denied, false).into_iter().map(|s| s.1).collect();
        assert_eq!(states, vec![Step::Ok, Step::No, Step::Idle, Step::Idle]);
        let fresh = FbiAccess::awaiting(AccessKind::Execute, "plan-2");
        let refused = fresh.after_finished("(authorization_denied)").unwrap();
        assert_eq!(steps(&refused, true)[0].1, Step::No);
    }

    #[test]
    fn non_authorization_failures_hide_the_card() {
        let access = FbiAccess::awaiting(AccessKind::Execute, "plan-1");
        assert_eq!(
            access.after_finished("Prepared packages or plan inputs differ"),
            None
        );
    }

    #[test]
    fn texts_are_bilingual_and_explain_denial() {
        let mut access = FbiAccess::awaiting(AccessKind::Execute, "plan-1");
        assert!(texts(&access, false).0.contains("OCZEKIWANIE"));
        assert!(texts(&access, true).0.contains("AWAITING"));
        access.on_snapshot(&json!({"phase":"ready","outcome":"running"}));
        assert_eq!(texts(&access, false).0, "ACCESS GRANTED");
        let denied = FbiAccess::awaiting(AccessKind::Inspect, "plan-1")
            .after_finished("Polkit denied")
            .unwrap();
        assert_eq!(texts(&denied, false).0, "ACCESS DENIED");
        assert!(texts(&denied, false).1.contains("odmówił autoryzacji"));
        assert!(texts(&denied, true).1.contains("denied authorization"));
    }

    #[test]
    fn module_never_collects_a_password_or_adds_a_dialog() {
        let source = include_str!("fbi_access.rs");
        let code = &source[..source.find("#[cfg(test)]").unwrap()];
        for forbidden in [
            "PasswordEntry",
            "Entry::",
            "set_visibility(false)",
            "MessageDialog",
            "Dialog::",
            "pkexec",
            "CheckAuthorization",
        ] {
            assert!(!code.contains(forbidden), "{forbidden}");
        }
    }
}

#[cfg(test)]
mod widget_tests {
    use super::*;
    use gtk4::prelude::WidgetExt;

    #[test]
    fn card_shows_state_classes_and_hides_without_access() {
        gtk4::init().expect("private GTK test display");
        let card = build_card();
        update_card(&card, None, false);
        assert!(!card.root.is_visible());
        let mut access = FbiAccess::awaiting(AccessKind::Execute, "plan-1");
        update_card(&card, Some(&access), false);
        assert!(card.root.is_visible() && card.root.has_css_class("fbi-pending"));
        assert!(card.status.text().contains("OCZEKIWANIE"));
        access.on_snapshot(&serde_json::json!({"phase":"ready","outcome":"running"}));
        update_card(&card, Some(&access), true);
        assert!(card.root.has_css_class("fbi-granted") && !card.root.has_css_class("fbi-pending"));
        assert!(card.status.text().contains("ACCESS GRANTED"));
        let denied = FbiAccess::awaiting(AccessKind::Execute, "plan-2")
            .after_finished("Polkit denied")
            .unwrap();
        update_card(&card, Some(&denied), true);
        assert!(card.root.has_css_class("fbi-denied"));
        assert!(card.detail.text().contains("denied authorization"));
        let mut count = 0;
        let mut child = card.steps.first_child();
        while let Some(widget) = child {
            count += 1;
            child = widget.next_sibling();
        }
        assert_eq!(count, 4);
    }
}
