use crate::classification::{self, Attention, Category};
use crate::intelligence::{self, Language};
use crate::packages::{self, PackageUpdate};
use crate::ufo_progress::{UfoStage, UfoStatus, build_ufo_scene};
use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{
    Application, ApplicationWindow, Box as GtkBox, Button, ButtonsType, Label, MessageDialog,
    MessageType, Orientation, ScrolledWindow,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

type ScanResults = Vec<(PackageUpdate, String)>;

struct UiState {
    language: Language,
    updates: Option<ScanResults>,
    scanning: bool,
    analyzing_changelogs: bool,
    changelog_total: usize,
    changelog_completed: usize,
    changelogs: HashMap<String, crate::changelog_fetch::ChangelogResult>,
    /// Read by the scan worker (ALPM database access stays off the GTK thread).
    system_info: Option<crate::system_info::SystemInfo>,
    /// Stop flag of the running changelog analysis.
    analysis_cancel: Option<Arc<AtomicBool>>,
    /// Incremented by every scan/stop; stale analysis results are ignored.
    analysis_generation: u64,
    analysis_cancelled: bool,
    error: Option<String>,
    last_scan: Option<(std::time::SystemTime, bool, usize)>,
    transaction_controller: crate::transaction_engine::DemoTransactionController,
    test_animation_active: bool,
    demo_authorization_open: bool,
    test_animation_progress: f64,
    lab_ipc_progress: Option<String>,
    system_backend_available: bool,
    real_update_active: bool,
    real_update_can_interrupt: bool,
    preparing_upgrade: bool,
    production_confirmation_open: bool,
    confirmed_plan: Option<crate::transaction_ipc::PlanValidationRequest>,
    execution_reference: Option<crate::transaction_ipc::PlanValidationRequest>,
    real_update_phase: Option<crate::real_progress::UpgradeEvent>,
    real_update_percent: Option<u8>,
    /// UFO scene only: phase and detail of the supervised transaction,
    /// taken from supervisor snapshots. Presentation, never authority.
    ufo_real_stage: Option<UfoStage>,
    ufo_real_detail: String,
    transaction_result: Option<UiTransactionResult>,
    /// FBI ACCESS AUTHORIZATION card: presentation of system Polkit only.
    fbi_access: Option<crate::fbi_access::FbiAccess>,
}

/// Presentation only: an IPC error never becomes a successful transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResultKind {
    Success,
    Failed,
    Cancelled,
    Unknown,
    Blocked,
}

struct UiTransactionResult {
    kind: ResultKind,
    detail: String,
    transaction_id: Option<String>,
}

fn result_kind(
    result: &Result<crate::transaction_protocol::TransactionOutcome, String>,
) -> ResultKind {
    use crate::transaction_protocol::TransactionOutcome;
    match result {
        Ok(TransactionOutcome::Success) => ResultKind::Success,
        Ok(TransactionOutcome::Failure) => ResultKind::Failed,
        Ok(TransactionOutcome::Cancelled) => ResultKind::Cancelled,
        Ok(TransactionOutcome::Running) | Err(_) => ResultKind::Unknown,
    }
}

/// Manual, user-confirmed read-only check of the saved ID: `attach` only,
/// never execute or COMMIT. Triggers Polkit (.inspect) in the supervisor.
#[allow(clippy::too_many_arguments)]
fn startup_unknown_result_text(language: Language, id: &str) -> String {
    tr(
        language,
        &format!(
            "WYNIK NIEZNANY: zapisana transakcja {id}. Nie sprawdzono automatycznie, bo wymaga to hasła administratora. Nie ponawiaj aktualizacji; użyj SPRAWDŹ WYNIK."
        ),
        &format!(
            "OUTCOME UNKNOWN: saved transaction {id}. Not checked automatically because it requires the administrator password. Do not retry the update; use CHECK RESULT."
        ),
    )
}

fn start_manual_result_check(
    request: &crate::transaction_ipc::PlanValidationRequest,
    window: &ApplicationWindow,
    state: &Rc<RefCell<UiState>>,
    status: &Label,
    list: &GtkBox,
    scan: &Button,
    install: &Button,
    footer: &Label,
) {
    match crate::production_ipc::reconnect_production_session(request) {
        Ok((events, answers)) => {
            state.borrow_mut().real_update_active = true;
            state.borrow_mut().fbi_access = Some(crate::fbi_access::FbiAccess::awaiting(
                crate::fbi_access::AccessKind::Inspect,
                &request.transaction_id,
            ));
            reset_ufo_transaction(state);
            poll_production_ipc_events(
                events,
                answers,
                window.clone(),
                Rc::clone(state),
                status.clone(),
                list.clone(),
                scan.clone(),
                install.clone(),
                footer.clone(),
            );
        }
        Err(error) => {
            let text = format!(
                "{}: {error}",
                tr(
                    state.borrow().language,
                    "Sprawdzenie wyniku zablokowane",
                    "Result check blocked"
                )
            );
            state.borrow_mut().transaction_result = Some(UiTransactionResult {
                kind: ResultKind::Unknown,
                detail: text.clone(),
                transaction_id: Some(request.transaction_id.clone()),
            });
            status.set_text(&text);
        }
    }
}

/// SPRAWDŹ WYNIK is not on the main screen: only an UNKNOWN outcome with a
/// saved ID offers a manual read-only check (or diagnostics mode).
fn recovery_check_visible(state: &UiState, diagnostic_ui: bool) -> bool {
    diagnostic_ui
        || (!state.real_update_active
            && state.execution_reference.is_some()
            && state
                .transaction_result
                .as_ref()
                .is_some_and(|result| result.kind == ResultKind::Unknown))
}

fn package_priority(state: &UiState, name: &str) -> crate::update_cards::Priority {
    state
        .changelogs
        .get(name)
        .map(crate::update_cards::priority)
        .unwrap_or(crate::update_cards::Priority::Unknown)
}

fn priority_counts(state: &UiState, updates: &ScanResults) -> [usize; 4] {
    use crate::update_cards::Priority;
    let mut counts = [0; 4];
    for (package, _) in updates {
        counts[match package_priority(state, &package.name) {
            Priority::Security => 0,
            Priority::Review => 1,
            Priority::Routine => 2,
            Priority::Unknown => 3,
        }] += 1;
    }
    counts
}

fn append_transaction_result(list: &GtkBox, state: &UiState) {
    let Some(result) = state
        .transaction_result
        .as_ref()
        .filter(|_| !state.real_update_active)
    else {
        return;
    };
    let language = state.language;
    let (pl, en, css) = match result.kind {
        ResultKind::Blocked => (
            "INSTALACJA ZABLOKOWANA",
            "INSTALLATION BLOCKED",
            "result-unknown",
        ),
        ResultKind::Success => (
            "AKTUALIZACJA ZAKOŃCZONA",
            "UPDATE COMPLETED",
            "result-success",
        ),
        ResultKind::Failed => ("AKTUALIZACJA NIEUDANA", "UPDATE FAILED", "result-failed"),
        ResultKind::Cancelled => (
            "AKTUALIZACJA ANULOWANA",
            "UPDATE CANCELLED",
            "result-unknown",
        ),
        ResultKind::Unknown => (
            "WYNIK NIEZNANY — SPRAWDŹ SESJĘ",
            "OUTCOME UNKNOWN — CHECK SESSION",
            "result-unknown",
        ),
    };
    let panel = GtkBox::new(Orientation::Vertical, 8);
    panel.add_css_class("transaction-result");
    panel.add_css_class(css);
    let title = Label::new(Some(&tr(language, pl, en)));
    title.set_xalign(0.0);
    title.set_wrap(true);
    title.add_css_class("result-title");
    panel.append(&title);
    let detail = Label::new(Some(&result.detail));
    detail.set_xalign(0.0);
    detail.set_wrap(true);
    detail.set_selectable(true);
    panel.append(&detail);
    if let Some(id) = &result.transaction_id {
        let id = Label::new(Some(&format!(
            "{}: {id}",
            tr(language, "ID transakcji", "Transaction ID")
        )));
        id.set_xalign(0.0);
        id.set_wrap(true);
        id.set_selectable(true);
        panel.append(&id);
    }
    if !matches!(result.kind, ResultKind::Success | ResultKind::Blocked) {
        let note = Label::new(Some(&tr(
            language,
            "Nie zakładaj wycofania zmian. Sprawdź zapisany wynik transakcji przed kolejną próbą.",
            "Do not assume changes were rolled back. Check the saved transaction outcome before retrying.",
        )));
        note.set_xalign(0.0);
        note.set_wrap(true);
        panel.append(&note);
    }
    list.append(&panel);
}

impl UiState {
    fn can_prepare_upgrade(&self) -> bool {
        !self.preparing_upgrade
            && !self.production_confirmation_open
            && !self.scanning
            && !self.analyzing_changelogs
            && !self.real_update_active
            && !self.test_animation_active
            && !self.demo_authorization_open
            && !(self.execution_reference.is_some()
                && self
                    .transaction_result
                    .as_ref()
                    .is_some_and(|r| r.kind == ResultKind::Unknown))
    }
}

/// Maps the current GUI state to the UFO scene. Returns `None` when the scene
/// is hidden, otherwise its status and whether it takes over the central
/// package area (`true`: download/install) or is a strip above it (scan).
fn ufo_view(current: &UiState) -> Option<(UfoStatus, bool)> {
    let english = matches!(current.language, Language::English);
    let status = |stage, progress, detail: String| UfoStatus {
        stage,
        progress,
        detail,
        english,
    };
    if current.real_update_active {
        let stage = current.ufo_real_stage.unwrap_or(UfoStage::Preparing);
        let progress = current.real_update_percent.map(|p| f64::from(p) / 100.0);
        return Some((
            status(stage, progress, current.ufo_real_detail.clone()),
            true,
        ));
    }
    if current.test_animation_active {
        let detail = current.lab_ipc_progress.clone().unwrap_or_default();
        return Some((
            status(UfoStage::Preparing, None, format!("LAB IPC · {detail}")),
            true,
        ));
    }
    if current.preparing_upgrade {
        return Some((status(UfoStage::Preparing, None, String::new()), false));
    }
    if current.analyzing_changelogs {
        let (done, total) = (current.changelog_completed, current.changelog_total);
        let progress = (total > 0).then(|| done as f64 / total as f64);
        let detail = if total > 0 {
            format!("{done} / {total}")
        } else {
            String::new()
        };
        return Some((status(UfoStage::Changelogs, progress, detail), false));
    }
    if current.scanning {
        return Some((status(UfoStage::Scanning, None, String::new()), false));
    }
    None
}

/// UFO phase for a supervisor snapshot (`phase`, optional progress object).
fn ufo_stage_for_snapshot(phase: &str, progress: Option<&serde_json::Value>) -> UfoStage {
    match phase {
        "finished" => return UfoStage::Finished,
        "commit" | "commit_started" => return UfoStage::Install,
        _ => {}
    }
    match progress.and_then(|p| p["stage"].as_str()) {
        Some("download") => UfoStage::Download,
        Some("signatures") => UfoStage::Verify,
        Some("alpm-progress") => match progress.and_then(|p| p["kind"].as_i64()) {
            Some(0..=4) => UfoStage::Install,
            Some(5..=9) => UfoStage::Verify,
            _ => UfoStage::Preparing,
        },
        _ if phase == "ready" => UfoStage::Download,
        _ => UfoStage::Preparing,
    }
}

fn ufo_snapshot_state(
    phase: &str,
    outcome: &str,
    progress: Option<&serde_json::Value>,
) -> (UfoStage, Option<u8>) {
    if matches!(outcome, "failure" | "unknown") {
        return (UfoStage::Failed, None);
    }
    if outcome == "success" {
        return (UfoStage::Finished, Some(100));
    }
    let stage = ufo_stage_for_snapshot(phase, progress);
    // A phase frame may still carry the last download progress text. Never
    // display its percent as installation progress or retain it after a stage.
    let percent = progress
        .filter(|p| ufo_stage_for_snapshot("", Some(p)) == stage)
        .and_then(|p| p["percent"].as_u64())
        .map(|p| p.min(100) as u8);
    (stage, percent)
}

/// Clears UFO presentation data left from a previous transaction.
fn reset_ufo_transaction(state: &Rc<RefCell<UiState>>) {
    let mut current = state.borrow_mut();
    current.real_update_percent = None;
    current.ufo_real_stage = None;
    current.ufo_real_detail.clear();
}

fn tr(language: Language, pl: &str, en: &str) -> String {
    match language {
        Language::Polish => pl.to_string(),
        Language::English => en.to_string(),
    }
}

fn description(name: &str) -> String {
    crate::package_description::read_description(name)
}

fn update_install_availability(button: &Button, state: &UiState) {
    button.set_tooltip_text(Some(&tr(state.language,
        "Przygotuj świeży plan i przejrzyj pakiety. Instalacja wymaga potwierdzenia, walidacji USER, polityki wykonania i Polkit.",
        "Prepare a fresh plan and review packages. Installation requires confirmation, USER validation, execution policy and Polkit.")));
    button.set_sensitive(state.can_prepare_upgrade());
}

const REAL_MODE_LABEL_NAME: &str = "rwr-real-mode-status";

/// The REAL MODE status label in the bottom heading, found by name rather than
/// position: the diagnostic SUPERVISOR label is prepended to the same row.
fn real_mode_label(install_button: &Button) -> Option<Label> {
    let heading = install_button.parent()?.parent()?.first_child()?;
    let mut child = heading.first_child();
    while let Some(widget) = child {
        if widget.widget_name() == REAL_MODE_LABEL_NAME {
            return widget.downcast::<Label>().ok();
        }
        child = widget.next_sibling();
    }
    None
}

fn refresh(
    list: &GtkBox,
    status: &Label,
    button: &Button,
    install_button: &Button,
    footer: &Label,
    state: &Rc<RefCell<UiState>>,
) {
    let state = state.borrow();
    if let Some(test_label) = real_mode_label(install_button) {
        test_label.set_text(&tr(
            state.language,
            if crate::update_launcher::validate_production_ipc_precheck().is_ok() {
                "REAL MODE · WYMAGA AUTORYZACJI"
            } else {
                "REAL MODE · ZABLOKOWANY"
            },
            if crate::update_launcher::validate_production_ipc_precheck().is_ok() {
                "REAL MODE · AUTHORIZATION REQUIRED"
            } else {
                "REAL MODE · LOCKED"
            },
        ));
    }

    install_button.set_label(&tr(state.language, "AKTUALIZUJ", "UPDATE"));

    update_install_availability(install_button, &state);
    let language = state.language;
    let _language_code = language.code();
    if state.analyzing_changelogs {
        // The same button stops a long analysis (network sources).
        button.set_label(&tr(language, "ZATRZYMAJ ANALIZĘ", "STOP ANALYSIS"));
        button.set_sensitive(!state.test_animation_active && !state.demo_authorization_open);
    } else {
        button.set_label(&tr(language, "SKANUJ", "SCAN"));
        button.set_sensitive(
            !state.scanning && !state.test_animation_active && !state.demo_authorization_open,
        );
    }
    let footer_detail = if state.scanning {
        tr(language, "Sprawdzanie aktualizacji", "Checking for updates")
    } else if state.analyzing_changelogs {
        format!(
            "{}: {}/{}",
            tr(language, "Weryfikacja changelogów", "Checking changelogs"),
            state.changelog_completed,
            state.changelog_total
        )
    } else if state.error.is_some() {
        tr(
            language,
            "Sprawdzanie nie powiodło się",
            "Update check failed",
        )
    } else if state.updates.is_none() {
        tr(language, "Oczekiwanie na skanowanie", "Waiting for scan")
    } else if state.changelog_total == 0 {
        tr(
            language,
            "Brak changelogów do weryfikacji",
            "No changelogs to verify",
        )
    } else if state.analysis_cancelled {
        format!(
            "{}: {}/{}",
            tr(language, "Analiza zatrzymana", "Analysis stopped"),
            state.changelog_completed,
            state.changelog_total
        )
    } else {
        let verified = state
            .changelogs
            .values()
            .filter(|result| {
                matches!(
                    result.status,
                    crate::changelog_fetch::ChangelogStatus::ReleaseNotes
                        | crate::changelog_fetch::ChangelogStatus::PackagingHistory
                )
            })
            .count();

        format!(
            "{}: {}/{}",
            tr(language, "Zweryfikowano źródła", "Verified sources"),
            verified,
            state.changelog_total
        )
    };

    footer.set_text(&format!(
        "{}  •  {}",
        tr(
            language,
            "SKANOWANIE BEZ ZMIAN W SYSTEMIE",
            "SCANNING WITHOUT SYSTEM CHANGES"
        ),
        footer_detail
    ));

    while let Some(child) = list.first_child() {
        list.remove(&child);
    }

    append_transaction_result(list, &state);

    if state.scanning {
        status.set_text(&tr(
            language,
            "Sprawdzanie aktualizacji...",
            "Checking for updates...",
        ));
    } else if state.analyzing_changelogs {
        let percent = if state.changelog_total == 0 {
            0
        } else {
            state.changelog_completed * 100 / state.changelog_total
        };

        status.set_text(&format!(
            "{}: {} / {} ({}%)",
            tr(language, "Analiza changelogów", "Analyzing changelogs"),
            state.changelog_completed,
            state.changelog_total,
            percent,
        ));
    } else if let Some(error) = &state.error {
        status.set_text(&format!(
            "{}: {error}",
            tr(language, "Błąd skanowania", "Scan error")
        ));
    } else if let Some(updates) = &state.updates {
        let security_fixes = state
            .changelogs
            .values()
            .filter(|result| {
                crate::update_cards::priority(result) == crate::update_cards::Priority::Security
            })
            .count();
        let mut status_text = format!(
            "{}: {}",
            tr(language, "Dostępne aktualizacje", "Available updates"),
            updates.len()
        );
        if security_fixes > 0 {
            status_text.push_str(&format!(
                "  ·  {}: {security_fixes}",
                tr(
                    language,
                    "potwierdzone poprawki bezpieczeństwa",
                    "confirmed security fixes"
                )
            ));
        }
        status.set_text(&status_text);
        if let (true, Some(system)) = (updates.is_empty(), state.system_info.as_ref()) {
            let panel = GtkBox::new(Orientation::Vertical, 10);
            panel.add_css_class("system-info-panel");

            let heading = Label::new(Some(&tr(
                language,
                "SYSTEM AKTUALNY — INFORMACJE",
                "SYSTEM UP TO DATE — INFORMATION",
            )));
            heading.set_xalign(0.0);
            heading.add_css_class("system-info-title");
            panel.append(&heading);

            for (label, value) in [
                (
                    tr(language, "Dystrybucja", "Distribution"),
                    system.distribution.clone(),
                ),
                (tr(language, "Jądro", "Kernel"), system.kernel.clone()),
                (tr(language, "Pulpit", "Desktop"), system.desktop.clone()),
                (
                    tr(language, "Zainstalowane pakiety", "Installed packages"),
                    system
                        .installed_packages
                        .map(|count| count.to_string())
                        .unwrap_or_else(|| tr(language, "Niedostępne", "Unavailable")),
                ),
            ] {
                let line = Label::new(Some(&format!("{label}: {value}")));
                line.set_xalign(0.0);
                line.set_wrap(true);
                line.add_css_class("system-info-line");
                panel.append(&line);
            }

            if let Some((when, success, count)) = &state.last_scan {
                let timestamp = when
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .and_then(|duration| {
                        glib::DateTime::from_unix_local(duration.as_secs() as i64).ok()
                    })
                    .and_then(|date| date.format("%Y-%m-%d %H:%M:%S").ok())
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| tr(language, "Nieznany", "Unknown"));

                let result_text = if *success {
                    tr(language, "Zakończono pomyślnie", "Completed successfully")
                } else {
                    tr(language, "Błąd skanowania", "Scan failed")
                };

                for (label, value) in [
                    (tr(language, "Ostatnie skanowanie", "Last scan"), timestamp),
                    (tr(language, "Wynik", "Result"), result_text),
                    (
                        tr(language, "Wykryte aktualizacje", "Detected updates"),
                        count.to_string(),
                    ),
                ] {
                    let line = Label::new(Some(&format!("{label}: {value}")));
                    line.set_xalign(0.0);
                    line.set_wrap(true);
                    line.add_css_class("system-info-line");
                    panel.append(&line);
                }
            }

            list.append(&panel);
        }
        let counts = priority_counts(&state, updates);
        let summary = GtkBox::new(Orientation::Horizontal, 8);
        summary.set_homogeneous(true);
        for (count, pl, en, css) in [
            (updates.len(), "AKTUALIZACJE", "UPDATES", "stat-total"),
            (
                counts[0],
                "POPRAWKI OCHRONY",
                "SECURITY FIXES",
                "stat-security",
            ),
            (counts[1], "DO SPRAWDZENIA", "REVIEW", "stat-review"),
            (counts[3], "NIEUSTALONE", "UNDETERMINED", "stat-unknown"),
        ] {
            let card = GtkBox::new(Orientation::Vertical, 4);
            card.add_css_class("summary-card");
            card.add_css_class(css);
            let value = Label::new(Some(&count.to_string()));
            value.add_css_class("summary-value");
            let caption = Label::new(Some(&tr(language, pl, en)));
            caption.set_wrap(true);
            caption.add_css_class("summary-caption");
            card.append(&value);
            card.append(&caption);
            summary.append(&card);
        }
        list.append(&summary);
        if counts[0] + counts[1] > 0 {
            let warning = Label::new(Some(&tr(
                language,
                "! Potwierdzone źródła zgłaszają poprawki bezpieczeństwa lub zmiany wymagające uwagi. Sprawdź oznaczone pakiety i ich źródła.",
                "! Verified sources report security fixes or changes requiring review. Check the marked packages and their sources.",
            )));
            warning.set_xalign(0.0);
            warning.set_wrap(true);
            warning.add_css_class("evidence-alert");
            list.append(&warning);
        }
        let heading = Label::new(Some(&tr(
            language,
            "PAKIETY · kolejność według potwierdzonych sygnałów, potem nazwy",
            "PACKAGES · verified signals first, then name",
        )));
        heading.set_xalign(0.0);
        heading.set_wrap(true);
        heading.add_css_class("list-heading");
        list.append(&heading);
        let mut ordered: Vec<_> = updates.iter().collect();
        ordered.sort_by(|(a, _), (b, _)| {
            package_priority(&state, &a.name)
                .cmp(&package_priority(&state, &b.name))
                .then_with(|| a.name.cmp(&b.name))
        });
        for (package, desc) in ordered {
            let row = GtkBox::new(Orientation::Vertical, 4);
            row.add_css_class("package-row");
            let name = Label::new(Some(&package.name));
            name.set_xalign(0.0);
            name.add_css_class("package-title");
            let top = GtkBox::new(Orientation::Horizontal, 10);
            name.set_hexpand(true);
            top.append(&name);
            let priority = package_priority(&state, &package.name);
            let (pl, en, css) = match priority {
                crate::update_cards::Priority::Security => {
                    ("OCHRONA", "SECURITY", "priority-security")
                }
                crate::update_cards::Priority::Review => ("SPRAWDŹ", "REVIEW", "priority-review"),
                crate::update_cards::Priority::Routine => ("ZWYKŁY", "ROUTINE", "priority-routine"),
                crate::update_cards::Priority::Unknown => {
                    ("NIEUSTALONY", "UNDETERMINED", "priority-unknown")
                }
            };
            row.add_css_class(css);
            let priority_label = Label::new(Some(&tr(language, pl, en)));
            priority_label.add_css_class("priority-chip");
            priority_label.set_tooltip_text(Some(&crate::update_cards::priority_text(
                priority, language,
            )));
            top.append(&priority_label);
            row.append(&top);
            let versions = GtkBox::new(Orientation::Horizontal, 8);
            for (caption, value, css) in [
                (
                    tr(language, "STARA", "OLD"),
                    package.installed.as_str(),
                    "version-old",
                ),
                (
                    tr(language, "NOWA", "NEW"),
                    package.available.as_str(),
                    "version-new",
                ),
            ] {
                let column = GtkBox::new(Orientation::Vertical, 2);
                column.set_hexpand(true);
                let label = Label::new(Some(&caption));
                label.set_xalign(0.0);
                label.add_css_class("version-caption");
                let value = Label::new(Some(value));
                value.set_xalign(0.0);
                value.set_wrap(true);
                value.set_selectable(true);
                value.add_css_class(css);
                column.append(&label);
                column.append(&value);
                versions.append(&column);
            }
            versions.add_css_class("package-version");
            row.append(&versions);
            let classification = classification::classify(&package.name);
            let category_name = match classification.category {
                Category::System => tr(language, "SYSTEM", "SYSTEM"),
                Category::Kernel => tr(language, "JĄDRO", "KERNEL"),
                Category::Drivers => tr(language, "STEROWNIKI", "DRIVERS"),
                Category::SecurityTools => tr(language, "NARZĘDZIA OCHRONY", "SECURITY TOOLS"),
                Category::Network => tr(language, "SIEĆ", "NETWORK"),
                Category::Desktop => tr(language, "PULPIT", "DESKTOP"),
                Category::Libraries => tr(language, "BIBLIOTEKI", "LIBRARIES"),
                Category::Applications => tr(language, "APLIKACJE", "APPLICATIONS"),
                Category::Other => tr(language, "INNE", "OTHER"),
            };
            let category_line = GtkBox::new(Orientation::Horizontal, 8);
            let category_label = Label::new(Some(&category_name));
            category_label.add_css_class("package-category");
            category_line.append(&category_label);
            if classification.attention == Attention::Elevated {
                let attention_label =
                    Label::new(Some(&tr(language, "WYMAGA UWAGI", "REQUIRES ATTENTION")));
                attention_label.add_css_class("package-attention");
                attention_label.set_tooltip_text(Some(&tr(
                    language,
                    "Istotny komponent systemu; nie oznacza potwierdzonej luki bezpieczeństwa.",
                    "Important system component; does not indicate a confirmed security vulnerability.",
                )));
                category_line.append(&attention_label);
            }
            let analysis = state.changelogs.get(&package.name);
            // Only confirmed signals (tracker advisories, verified breaking entries).
            for badge in analysis
                .map(crate::update_cards::badges)
                .unwrap_or_default()
            {
                let badge_label =
                    Label::new(Some(&crate::update_cards::badge_text(badge, language)));
                badge_label.add_css_class(crate::update_cards::badge_css_class(badge));
                badge_label
                    .set_tooltip_text(Some(&crate::update_cards::badge_tooltip(badge, language)));
                category_line.append(&badge_label);
            }
            row.append(&category_line);

            let info = intelligence::explain(&package.name, language);
            let purpose = info.as_ref().map(|x| x.purpose.clone()).unwrap_or_else(|| {
                if desc.is_empty() {
                    tr(
                        language,
                        "Opis pakietu niedostępny",
                        "Package description unavailable",
                    )
                } else {
                    crate::package_description::repository_description_text(language, desc)
                }
            });
            let details = Label::new(Some(&format!(
                "{}  ·  {purpose}",
                tr(language, "FUNKCJA", "PURPOSE")
            )));
            details.set_xalign(0.0);
            details.set_wrap(true);
            details.add_css_class("package-description");
            row.append(&details);

            let extra = GtkBox::new(Orientation::Vertical, 6);
            let expander = gtk4::Expander::new(Some(&tr(
                language,
                "SZCZEGÓŁY I ŹRÓDŁA",
                "DETAILS AND SOURCES",
            )));
            expander.add_css_class("package-details");
            expander.set_child(Some(&extra));
            let mut impact_text = if let Some(info) = info {
                info.impact
            } else {
                crate::package_description::impact_hint_text(
                    language,
                    crate::package_description::impact_hint(desc),
                )
            };
            if let Some(note) = crate::package_description::change_kind_note(
                language,
                &package.installed,
                &package.available,
            ) {
                impact_text = format!("{impact_text} {note}");
            }

            let impact = Label::new(Some(&format!(
                "{}  ·  {}",
                tr(language, "WPŁYW", "IMPACT"),
                impact_text
            )));
            impact.set_xalign(0.0);
            impact.set_wrap(true);
            impact.add_css_class("package-description");
            extra.append(&impact);
            if let Some(result) = analysis {
                let priority = Label::new(Some(&format!(
                    "{}  ·  {}",
                    tr(language, "PRIORYTET", "PRIORITY"),
                    crate::update_cards::priority_text(
                        crate::update_cards::priority(result),
                        language
                    )
                )));
                priority.set_xalign(0.0);
                priority.set_wrap(true);
                priority.add_css_class("package-description");
                extra.append(&priority);
            }
            let changelog_text = match analysis {
                Some(result) => crate::update_analysis::render_text(result, language),
                None if state.analyzing_changelogs
                    && crate::update_analysis::should_analyze(
                        &package.name,
                        &package.installed,
                        &package.available,
                    ) =>
                {
                    tr(
                        language,
                        "◈ Analiza changelogu...",
                        "◈ Analyzing changelog...",
                    )
                }
                None if state.analysis_cancelled
                    && crate::update_analysis::should_analyze(
                        &package.name,
                        &package.installed,
                        &package.available,
                    ) =>
                {
                    tr(
                        language,
                        "◈ Analiza zatrzymana — uruchom skanowanie ponownie",
                        "◈ Analysis stopped — scan again to continue",
                    )
                }
                None => tr(
                    language,
                    "◈ Brak skonfigurowanego źródła changelogu dla tej aktualizacji",
                    "◈ No changelog source configured for this update",
                ),
            };

            let changes = Label::new(Some(&changelog_text));
            changes.set_xalign(0.0);
            changes.set_wrap(true);
            changes.add_css_class("package-note");
            extra.append(&changes);

            if let Some(result) = analysis {
                // Release / packaging page for people; API JSON only as fallback.
                let page = crate::update_cards::source_page(result).or_else(|| {
                    crate::changelog_fetch::trusted_source_url(&result.source_url)
                        .then(|| result.source_url.clone())
                });
                if let Some(source_url) = page {
                    let source_button =
                        Button::with_label(&tr(language, "OTWÓRZ ŹRÓDŁO", "OPEN SOURCE"));
                    source_button.add_css_class("source-button");
                    source_button.set_halign(gtk4::Align::Start);

                    source_button.set_tooltip_text(Some(&source_url));

                    source_button.connect_clicked(move |_| {
                        if !crate::update_cards::trusted_browser_url(&source_url)
                            && !crate::changelog_fetch::trusted_source_url(&source_url)
                        {
                            return;
                        }

                        if let Err(error) = gtk4::gio::AppInfo::launch_default_for_uri(
                            &source_url,
                            None::<&gtk4::gio::AppLaunchContext>,
                        ) {
                            eprintln!("Cannot open changelog source: {error}");
                        }
                    });

                    extra.append(&source_button);
                }
            }

            row.append(&expander);
            list.append(&row);
        }
    } else {
        status.set_text(&tr(language, "Gotowy do skanowania", "Ready to scan"));
    }
}

/// Parallel analysis threads. Small on purpose: requests to one source are
/// deduplicated by the response cache and GitHub limits unauthenticated use.
const ANALYSIS_WORKERS: usize = 4;

fn start_changelog_worker(
    updates: Vec<PackageUpdate>,
    cancel: Arc<AtomicBool>,
) -> mpsc::Receiver<(String, crate::changelog_fetch::ChangelogResult)> {
    let (sender, receiver) = mpsc::channel();
    let workers = ANALYSIS_WORKERS.min(updates.len()).max(1);
    let queue = Arc::new(Mutex::new(std::collections::VecDeque::from(updates)));

    for _ in 0..workers {
        let sender = sender.clone();
        let queue = Arc::clone(&queue);
        let cancel = Arc::clone(&cancel);
        std::thread::spawn(move || {
            loop {
                if cancel.load(AtomicOrdering::Relaxed) {
                    break;
                }
                let next = queue.lock().unwrap_or_else(|p| p.into_inner()).pop_front();
                let Some(package) = next else {
                    break;
                };
                if !crate::update_analysis::should_analyze(
                    &package.name,
                    &package.installed,
                    &package.available,
                ) {
                    continue;
                }

                // Releases between versions, Arch packaging history (pkgbase)
                // and Arch Security Tracker; read-only, cached network requests.
                let result = crate::update_analysis::analyze(
                    &package.name,
                    &package.installed,
                    &package.available,
                );

                if cancel.load(AtomicOrdering::Relaxed)
                    || sender.send((package.name, result)).is_err()
                {
                    break;
                }
            }
        });
    }

    receiver
}

/// Stops the running analysis: workers finish their current request and
/// exit; results that still arrive belong to an old generation and are dropped.
fn stop_analysis(state: &mut UiState) {
    if let Some(cancel) = state.analysis_cancel.take() {
        cancel.store(true, AtomicOrdering::Relaxed);
    }
    state.analysis_generation += 1;
    if state.analyzing_changelogs {
        state.analyzing_changelogs = false;
        state.analysis_cancelled = true;
    }
}

fn scan(
    list: &GtkBox,
    status: &Label,
    button: &Button,
    install_button: &Button,
    footer: &Label,
    state: &Rc<RefCell<UiState>>,
) {
    {
        let current = state.borrow();
        if current.test_animation_active
            || current.demo_authorization_open
            || current.preparing_upgrade
            || current.production_confirmation_open
            || current.real_update_active
        {
            return;
        }
        if current.analyzing_changelogs {
            drop(current);
            stop_analysis(&mut state.borrow_mut());
            refresh(list, status, button, install_button, footer, state);
            return;
        }
        if current.scanning {
            return;
        }
    }
    {
        let mut state = state.borrow_mut();
        stop_analysis(&mut state);
        state.analysis_cancelled = false;
        state.scanning = true;
        // A new scan/plan starts a new case: clear an old ACCESS DENIED card.
        state.fbi_access = None;
        state.confirmed_plan = None;
        state.updates = None;
        state.changelogs.clear();
        state.changelog_total = 0;
        state.changelog_completed = 0;
        state.error = None;
    }
    refresh(list, status, button, install_button, footer, state);
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let result = packages::check_updates().map(|updates| {
            updates
                .into_iter()
                .map(|pkg| {
                    let desc = description(&pkg.name);
                    (pkg, desc)
                })
                .collect::<ScanResults>()
        });
        // Only shown when the system is up to date; read here, not on the GTK thread.
        let system_info =
            matches!(&result, Ok(updates) if updates.is_empty()).then(crate::system_info::read);
        let _ = sender.send((result, system_info));
    });
    let list = list.clone();
    let status = status.clone();
    let button = button.clone();
    let install_button = install_button.clone();
    let footer = footer.clone();
    let state = Rc::clone(state);
    glib::timeout_add_local(Duration::from_millis(100), move || {
        match receiver.try_recv() {
            Ok((result, system_info)) => {
                {
                    let mut state = state.borrow_mut();
                    state.scanning = false;
                    state.system_info = system_info;
                    match result {
                        Ok(updates) => {
                            let count = updates.len();
                            state.last_scan = Some((std::time::SystemTime::now(), true, count));
                            state.updates = Some(updates);
                            state.error = None;
                        }
                        Err(error) => {
                            eprintln!("RWR SCAN: {error}");
                            state.last_scan = Some((std::time::SystemTime::now(), false, 0));
                            state.updates = None;
                            state.error = Some(error);
                        }
                    }
                }
                let changelog_packages = {
                    let mut state = state.borrow_mut();
                    if state.error.is_none() {
                        let packages: Vec<PackageUpdate> = state
                            .updates
                            .as_ref()
                            .into_iter()
                            .flat_map(|updates| updates.iter())
                            .filter(|(pkg, _)| {
                                crate::update_analysis::should_analyze(
                                    &pkg.name,
                                    &pkg.installed,
                                    &pkg.available,
                                )
                            })
                            .map(|(pkg, _)| pkg.clone())
                            .collect();
                        state.changelog_total = packages.len();
                        state.changelog_completed = 0;
                        state.analyzing_changelogs = !packages.is_empty();
                        packages
                    } else {
                        state.analyzing_changelogs = false;
                        Vec::new()
                    }
                };

                if !changelog_packages.is_empty() {
                    let cancel = Arc::new(AtomicBool::new(false));
                    let generation = {
                        let mut state = state.borrow_mut();
                        state.analysis_cancel = Some(Arc::clone(&cancel));
                        state.analysis_generation
                    };
                    let changelog_receiver = start_changelog_worker(changelog_packages, cancel);
                    let changelog_state = Rc::clone(&state);
                    let changelog_button = button.clone();
                    let changelog_install_button = install_button.clone();
                    let changelog_list = list.clone();
                    let changelog_status = status.clone();
                    let changelog_footer = footer.clone();

                    glib::timeout_add_local(Duration::from_millis(100), move || {
                        // A newer scan or a stop request replaced this analysis.
                        if changelog_state.borrow().analysis_generation != generation {
                            return glib::ControlFlow::Break;
                        }
                        // Take every result that is ready, then re-render once:
                        // cached results arrive in bursts (one card rebuild per tick).
                        let mut received = 0;
                        let mut finished = false;
                        loop {
                            match changelog_receiver.try_recv() {
                                Ok((name, result)) => {
                                    received += 1;
                                    let mut state = changelog_state.borrow_mut();
                                    state.changelogs.insert(name, result);
                                    state.changelog_completed = state.changelogs.len();
                                }
                                Err(mpsc::TryRecvError::Empty) => break,
                                Err(mpsc::TryRecvError::Disconnected) => {
                                    finished = true;
                                    break;
                                }
                            }
                        }
                        if finished {
                            let mut state = changelog_state.borrow_mut();
                            state.analyzing_changelogs = false;
                            state.analysis_cancel = None;
                        }
                        if received > 0 || finished {
                            // Progress text and verified cards (N10).
                            refresh(
                                &changelog_list,
                                &changelog_status,
                                &changelog_button,
                                &changelog_install_button,
                                &changelog_footer,
                                &changelog_state,
                            );
                        }
                        if finished {
                            glib::ControlFlow::Break
                        } else {
                            glib::ControlFlow::Continue
                        }
                    });
                }

                refresh(&list, &status, &button, &install_button, &footer, &state);
                glib::ControlFlow::Break
            }
            Err(mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
            Err(mpsc::TryRecvError::Disconnected) => {
                {
                    let mut state = state.borrow_mut();
                    state.scanning = false;
                    state.error = Some(tr(
                        state.language,
                        "Skaner zakończył pracę nieoczekiwanie",
                        "Scanner stopped unexpectedly",
                    ));
                }
                refresh(&list, &status, &button, &install_button, &footer, &state);
                glib::ControlFlow::Break
            }
        }
    });
}

pub fn build_ui(app: &Application) {
    // Presentation only: never changes authorization or REAL MODE.
    let diagnostic_ui = std::env::var("RWR_GUI_DIAGNOSTICS").as_deref() == Ok("1");
    let css = gtk4::CssProvider::new();
    css.load_from_data(include_str!("../assets/style.css"));
    if let Some(display) = gtk4::gdk::Display::default() {
        gtk4::style_context_add_provider_for_display(
            &display,
            &css,
            gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
    let window = ApplicationWindow::builder()
        .application(app)
        .title("RWR Package Intelligence")
        .default_width(950)
        .default_height(850)
        .build();
    window.add_css_class("rwr-window");
    let root = GtkBox::new(Orientation::Vertical, 0);
    root.add_css_class("root");
    // RWR UFO banner
    let banner_bytes = include_bytes!("../assets/rwr-package-banner.png");
    let banner_loader = gtk4::gdk_pixbuf::PixbufLoader::new();
    banner_loader
        .write(banner_bytes)
        .expect("Embedded RWR banner decode failed");
    banner_loader
        .close()
        .expect("Embedded RWR banner incomplete");
    let banner_pixbuf = banner_loader.pixbuf().expect("Embedded RWR banner missing");
    let banner_texture = gtk4::gdk::Texture::for_pixbuf(&banner_pixbuf);
    let banner = gtk4::Picture::for_paintable(&banner_texture);
    banner.set_can_shrink(true);
    banner.set_keep_aspect_ratio(true);
    banner.set_hexpand(true);
    banner.set_vexpand(false);
    banner.add_css_class("rwr-banner");

    let banner_frame = GtkBox::new(Orientation::Vertical, 0);
    banner_frame.set_size_request(-1, 200);
    banner_frame.set_hexpand(true);
    banner_frame.set_vexpand(false);
    banner_frame.set_overflow(gtk4::Overflow::Hidden);
    banner_frame.append(&banner);
    root.append(&banner_frame);

    let motto = Label::new(Some("THE TRUTH IS OUT THERE"));
    motto.set_halign(gtk4::Align::Center);
    motto.add_css_class("rwr-motto");
    root.append(&motto);

    // RWR UFO — visual-only scene. One shared status, two placements:
    // a large strip in the work area while scanning, and the full central
    // area (instead of package descriptions) during download/installation.
    let ufo_status = Rc::new(RefCell::new(UfoStatus::default()));
    let ufo_strip = build_ufo_scene(Rc::clone(&ufo_status));
    ufo_strip.set_hexpand(true);
    ufo_strip.set_vexpand(false);
    ufo_strip.set_height_request(260);
    ufo_strip.add_css_class("ufo-strip");
    ufo_strip.set_visible(false);
    let ufo_stage_view = build_ufo_scene(Rc::clone(&ufo_status));
    ufo_stage_view.set_hexpand(true);
    ufo_stage_view.set_vexpand(true);
    ufo_stage_view.add_css_class("ufo-stage");
    let lang_button = Button::with_label("🇬🇧 EN");
    lang_button.set_tooltip_text(Some("Switch to English / Przełącz na polski"));
    lang_button.add_css_class("language-button");
    let controls = GtkBox::new(Orientation::Vertical, 10);
    controls.add_css_class("controls");

    let status_row = GtkBox::new(Orientation::Horizontal, 12);
    status_row.set_hexpand(true);

    let status = Label::new(Some("Gotowy do skanowania"));
    status.set_xalign(0.0);
    status.set_hexpand(true);
    status.set_valign(gtk4::Align::Center);
    status.add_css_class("status");

    lang_button.set_valign(gtk4::Align::Center);
    lang_button.set_hexpand(false);

    status_row.append(&status);
    status_row.append(&lang_button);

    let button = Button::with_label("SKANUJ");
    button.add_css_class("scan-button");
    button.set_hexpand(true);

    let install_button = Button::with_label("AKTUALIZUJ");
    install_button.add_css_class("rwr-install-button");
    install_button.set_sensitive(false);
    install_button.set_hexpand(true);
    install_button.set_visible(true);

    let action_buttons = GtkBox::new(Orientation::Horizontal, 12);
    action_buttons.set_hexpand(true);
    action_buttons.set_homogeneous(true);
    action_buttons.append(&button);
    action_buttons.append(&install_button);
    // Not part of the main screen: shown only for an UNKNOWN outcome (manual
    // check) or in diagnostics. Startup attaches automatically by saved ID.
    let recover_button = Button::with_label("SPRAWDŹ WYNIK");
    recover_button.add_css_class("rwr-install-button");
    recover_button.set_tooltip_text(Some("Wymaga autoryzacji administratora; tylko odczyt, bez COMMIT / Requires administrator authorization; read-only, no COMMIT"));
    recover_button.set_visible(diagnostic_ui);
    action_buttons.append(&recover_button);
    let cancel_button = Button::with_label("PRZERWIJ");
    cancel_button.add_css_class("rwr-install-button");
    cancel_button.set_visible(false);
    action_buttons.append(&cancel_button);

    // RWR X-FILES — niezalezna demonstracja, bez aktualizacji systemu.
    let demo_button = Button::with_label("DEMO UFO");
    demo_button.add_css_class("rwr-install-button");
    demo_button.set_hexpand(true);
    // Laboratory demonstration only. Never enables real updates.
    demo_button.set_label("LAB IPC");
    demo_button.set_visible(diagnostic_ui);
    action_buttons.append(&demo_button);

    controls.append(&status_row);
    root.append(&controls);
    root.append(&ufo_strip);
    let fbi_card = crate::fbi_access::build_card();
    root.append(&fbi_card.root);
    let scroll = ScrolledWindow::new();
    scroll.set_vexpand(true);
    scroll.set_hexpand(true);
    scroll.set_min_content_height(200);
    scroll.add_css_class("package-scroll");
    let list = GtkBox::new(Orientation::Vertical, 8);
    list.add_css_class("package-list");
    scroll.set_child(Some(&list));
    let work_stack = gtk4::Stack::new();
    work_stack.set_vexpand(true);
    work_stack.set_hexpand(true);
    work_stack.set_vhomogeneous(false);
    work_stack.set_transition_type(gtk4::StackTransitionType::Crossfade);
    work_stack.set_transition_duration(250);
    work_stack.add_named(&scroll, Some("packages"));
    work_stack.add_named(&ufo_stage_view, Some("ufo"));
    work_stack.set_visible_child_name("packages");
    root.append(&work_stack);

    let bottom_panel = GtkBox::new(Orientation::Vertical, 9);
    bottom_panel.add_css_class("bottom-actions");

    let bottom_heading = GtkBox::new(Orientation::Horizontal, 8);
    let test_label = Label::new(Some("REAL MODE · ZABLOKOWANY"));
    test_label.set_widget_name(REAL_MODE_LABEL_NAME);
    test_label.add_css_class("test-mode-label");
    test_label.set_hexpand(true);
    test_label.set_xalign(1.0);
    // RWR 4.8AD-80: read-only diagnostic supervisor status.
    // Never starts a service, helper, transaction or privileged process.
    let supervisor_label = Label::new(Some("SUPERVISOR · SPRAWDZANIE"));
    supervisor_label.add_css_class("test-mode-label");
    supervisor_label.set_xalign(0.0);
    supervisor_label.set_hexpand(true);
    supervisor_label.set_visible(diagnostic_ui);
    bottom_heading.prepend(&supervisor_label);

    bottom_heading.append(&test_label);
    bottom_panel.append(&bottom_heading);
    bottom_panel.append(&action_buttons);
    root.append(&bottom_panel);

    // RWR ARCHIWUM X — status demonstracji PL/EN.
    let demo_phase_label = Label::new(None);
    demo_phase_label.set_halign(gtk4::Align::Center);
    demo_phase_label.set_margin_top(5);
    demo_phase_label.set_margin_bottom(5);
    demo_phase_label.add_css_class("status");
    demo_phase_label.set_visible(false);
    root.append(&demo_phase_label);

    let footer = Label::new(None);
    footer.add_css_class("footer");
    root.append(&footer);
    // A saved unresolved ID is shown as UNKNOWN without authorizing or attaching.
    // Test fixtures such as `reviewed-1` are ignored, not deleted.
    let saved_execution =
        rwr_package_intelligence::supervisor_client::load_execution_reference().ok();
    let ignored_test_reference = saved_execution
        .as_ref()
        .filter(|r| rwr_package_intelligence::supervisor_client::is_test_artifact_reference(r))
        .map(|r| r.transaction_id.clone());
    let saved_execution = saved_execution
        .filter(|r| !rwr_package_intelligence::supervisor_client::is_test_artifact_reference(r));
    let state = Rc::new(RefCell::new(UiState {
        language: Language::Polish,
        updates: None,
        scanning: false,
        analyzing_changelogs: false,
        changelog_total: 0,
        changelog_completed: 0,
        changelogs: HashMap::new(),
        system_info: None,
        analysis_cancel: None,
        analysis_generation: 0,
        analysis_cancelled: false,
        error: None,
        last_scan: None,
        transaction_controller: crate::transaction_engine::DemoTransactionController::new(),
        test_animation_active: false,
        demo_authorization_open: false,
        test_animation_progress: 0.0,
        lab_ipc_progress: None,
        system_backend_available: false,
        real_update_active: false,
        real_update_can_interrupt: false,
        preparing_upgrade: false,
        production_confirmation_open: false,
        confirmed_plan: None,
        execution_reference: saved_execution,
        real_update_phase: None,
        real_update_percent: None,
        ufo_real_stage: None,
        ufo_real_detail: String::new(),
        transaction_result: None,
        fbi_access: None,
    }));

    {
        let state = Rc::clone(&state);
        let window = window.clone();
        let status = status.clone();
        let list = list.clone();
        let scan = button.clone();
        let install = install_button.clone();
        let footer = footer.clone();
        recover_button.connect_clicked(move |_| {
            if state.borrow().real_update_active
                || state.borrow().preparing_upgrade
                || state.borrow().production_confirmation_open
            {
                return;
            }
            let Some(request) = state.borrow().execution_reference.clone() else {
                status.set_text(&tr(
                    state.borrow().language,
                    "Brak zapamiętanej transakcji",
                    "No saved transaction",
                ));
                return;
            };
            // `attach` needs Polkit (.inspect, auth_admin): warn before asking.
            let language = state.borrow().language;
            let dialog = MessageDialog::builder()
                .transient_for(&window)
                .modal(true)
                .message_type(MessageType::Question)
                .buttons(ButtonsType::None)
                .text(tr(language, "RWR // SPRAWDŹ WYNIK", "RWR // CHECK RESULT"))
                .secondary_text(tr(
                    language,
                    &format!("Sprawdzenie wyniku transakcji {} wymaga autoryzacji administratora (Polkit, hasło). Tylko odczyt: nie uruchamia aktualizacji ani COMMIT. Kontynuować?", request.transaction_id),
                    &format!("Checking the result of transaction {} requires administrator authorization (Polkit, password). Read-only: it does not start an update or COMMIT. Continue?", request.transaction_id),
                ))
                .build();
            dialog.add_button(&tr(language, "ANULUJ", "CANCEL"), gtk4::ResponseType::Cancel);
            dialog.add_button(
                &tr(language, "AUTORYZUJ I SPRAWDŹ", "AUTHORIZE AND CHECK"),
                gtk4::ResponseType::Accept,
            );
            let (window, state, status) = (window.clone(), Rc::clone(&state), status.clone());
            let (list, scan, install, footer) =
                (list.clone(), scan.clone(), install.clone(), footer.clone());
            dialog.connect_response(move |dialog, response| {
                dialog.close();
                if response != gtk4::ResponseType::Accept || state.borrow().real_update_active {
                    return;
                }
                start_manual_result_check(
                    &request,
                    &window,
                    &state,
                    &status,
                    &list,
                    &scan,
                    &install,
                    &footer,
                );
            });
            dialog.present();
        });
    }

    {
        let state = Rc::clone(&state);
        let card_window = window.downgrade();
        let mut shown: Option<(Option<crate::fbi_access::FbiAccess>, bool)> = None;
        glib::timeout_add_local(Duration::from_millis(150), move || {
            if card_window.upgrade().is_none() {
                return glib::ControlFlow::Break;
            }
            let current = state.borrow();
            let view = (
                current.fbi_access.clone(),
                matches!(current.language, Language::English),
            );
            if shown.as_ref() != Some(&view) {
                crate::fbi_access::update_card(&fbi_card, view.0.as_ref(), view.1);
                shown = Some(view);
            }
            glib::ControlFlow::Continue
        });
    }

    // Startup never attaches: `attach` requires Polkit (.inspect, auth_admin).
    // Only the unauthenticated global status is read; the saved ID is shown as
    // WYNIK NIEZNANY with the manual SPRAWDŹ WYNIK check.
    if let Some(id) = &ignored_test_reference {
        status.set_text(&tr(
            state.borrow().language,
            &format!("Pominięto testowy identyfikator transakcji {id} (plik stanu bez zmian)."),
            &format!("Ignored test transaction ID {id} (state file left unchanged)."),
        ));
    }
    if state
        .borrow()
        .execution_reference
        .as_ref()
        .is_some_and(|reference| {
            !rwr_package_intelligence::supervisor_client::execution_reference_resolved(reference)
        })
    {
        let reference = state.borrow().execution_reference.clone();
        if let Some(reference) = reference {
            let language = state.borrow().language;
            let detail = startup_unknown_result_text(language, &reference.transaction_id);
            state.borrow_mut().transaction_result = Some(UiTransactionResult {
                kind: ResultKind::Unknown,
                detail: detail.clone(),
                transaction_id: Some(reference.transaction_id.clone()),
            });
            status.set_text(&detail);
            // Safe status read: no Polkit, no session, no transaction data.
            let (sender, receiver) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = sender.send(
                    rwr_package_intelligence::supervisor_client::read_system_supervisor_status(),
                );
            });
            let status = status.clone();
            glib::timeout_add_local(Duration::from_millis(200), move || {
                match receiver.try_recv() {
                    Ok(result) => {
                        let line = match result {
                            Ok(_) => tr(
                                language,
                                "SUPERVISOR SYSTEMOWY: dostępny",
                                "SYSTEM SUPERVISOR: available",
                            ),
                            Err(_) => tr(
                                language,
                                "SUPERVISOR SYSTEMOWY: niedostępny",
                                "SYSTEM SUPERVISOR: unavailable",
                            ),
                        };
                        status.set_text(&format!("{detail}\n{line}"));
                        glib::ControlFlow::Break
                    }
                    Err(mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                    Err(mpsc::TryRecvError::Disconnected) => glib::ControlFlow::Break,
                }
            });
        }
    }

    {
        let state = Rc::clone(&state);
        let window = window.clone();
        let status = status.clone();
        cancel_button.connect_clicked(move |_|{
            if !state.borrow().real_update_active || !state.borrow().real_update_can_interrupt {return;}
            let Some(request)=state.borrow().execution_reference.clone() else {return;};
            let language=state.borrow().language;
            let dialog=MessageDialog::builder().transient_for(&window).modal(true).message_type(MessageType::Warning).buttons(ButtonsType::None)
                .text(tr(language,"RWR // PRZERWANIE TRANSAKCJI","RWR // INTERRUPT TRANSACTION"))
                .secondary_text(tr(language,"Po COMMIT możliwe są częściowe zmiany. Pacman nie zapewnia automatycznego rollbacku. Wysłać żądanie przerwania?","After COMMIT partial changes are possible. Pacman provides no automatic rollback. Request interruption?"))
                .build();
            dialog.add_button(&tr(language,"WRÓĆ","BACK"),gtk4::ResponseType::Cancel);
            dialog.add_button(&tr(language,"ZAŻĄDAJ PRZERWANIA","REQUEST INTERRUPTION"),gtk4::ResponseType::Accept);
            let status=status.clone();
            dialog.connect_response(move |dialog,response|{
                dialog.close();if response!=gtk4::ResponseType::Accept{return;}
                match crate::production_ipc::request_execution_cancellation(&request){
                    Ok(receiver)=>{
                        let status=status.clone();
                        glib::timeout_add_local(Duration::from_millis(100),move||{
                            match receiver.try_recv(){
                                Ok(Ok(snapshot))=>{status.set_text(&format!("{} · {}",tr(language,"Żądanie przekazane; sprawdź wynik sesji","Request submitted; check session outcome"),snapshot["outcome"].as_str().unwrap_or("UNKNOWN")));glib::ControlFlow::Break}
                                Ok(Err(error))=>{status.set_text(&error);glib::ControlFlow::Break}
                                Err(mpsc::TryRecvError::Empty)=>glib::ControlFlow::Continue,
                                Err(_)=>{status.set_text("UNKNOWN · IPC");glib::ControlFlow::Break}
                            }
                        });
                    }
                    Err(error)=>status.set_text(&error),
                }
            });dialog.present();
        });
    }

    // System endpoint health is read-only; it cannot authorize or start COMMIT.
    {
        let (sender, receiver) = mpsc::channel();
        let state = Rc::clone(&state);
        let install = install_button.clone();
        let weak_window = window.downgrade();
        let mut pending = false;
        let mut next = std::time::Instant::now();
        glib::timeout_add_local(Duration::from_millis(100), move || {
            if weak_window.upgrade().is_none() {
                return glib::ControlFlow::Break;
            }
            if !pending && std::time::Instant::now() >= next {
                pending = true;
                next = std::time::Instant::now() + Duration::from_secs(5);
                let sender = sender.clone();
                std::thread::spawn(move || {
                    let _ = sender.send(
                        rwr_package_intelligence::supervisor_client::read_system_supervisor_status(
                        ),
                    );
                });
            }
            if let Ok(result) = receiver.try_recv() {
                pending = false;
                state.borrow_mut().system_backend_available = result.is_ok();
                update_install_availability(&install, &state.borrow());
            }
            glib::ControlFlow::Continue
        });
    }

    // RWR 4.8AD-85: periodic read-only supervisor monitoring.
    // Network/IPC work runs outside the GTK main thread; diagnostic UI only.
    if diagnostic_ui {
        let socket = rwr_package_intelligence::supervisor_client::default_supervisor_socket();

        let (sender, receiver) = mpsc::channel();
        let supervisor_label = supervisor_label.clone();
        let supervisor_state = Rc::clone(&state);
        let supervisor_window = window.clone();
        let question_open = Rc::new(std::cell::Cell::new(false));
        let mut last_question: Option<(String, u64)> = None;

        let mut next_check = std::time::Instant::now();
        let mut request_pending = false;
        let mut last_available: Option<bool> = None;

        glib::timeout_add_local(Duration::from_millis(100), move || {
            if !request_pending && std::time::Instant::now() >= next_check {
                let sender = sender.clone();
                let socket = socket.clone();

                request_pending = true;
                next_check = std::time::Instant::now() + Duration::from_secs(5);

                std::thread::spawn(move || {
                    let result =
                        rwr_package_intelligence::supervisor_client::read_supervisor_state(&socket);
                    let _ = sender.send(result);
                });
            }

            match receiver.try_recv() {
                Ok(result) => {
                    request_pending = false;

                    // A reachable supervisor reporting REAL=true is not "unavailable".
                    let reported_real = match result {
                        Ok(ref value) => value["real_execution_enabled"].as_bool(),
                        Err(_) => None,
                    };
                    let available = reported_real.is_some();

                    let language = supervisor_state.borrow().language;
                    let text = if reported_real == Some(true) {
                        tr(
                            language,
                            "SUPERVISOR · DIAGNOSTYKA / REAL MODE WŁĄCZONY W POLITYCE",
                            "SUPERVISOR · DIAGNOSTIC / REAL MODE ENABLED BY POLICY",
                        )
                    } else if available {
                        tr(
                            language,
                            "SUPERVISOR · DIAGNOSTYKA / REAL MODE ZABLOKOWANY",
                            "SUPERVISOR · DIAGNOSTIC / REAL MODE LOCKED",
                        )
                    } else {
                        tr(
                            language,
                            "SUPERVISOR · BRAK POLACZENIA",
                            "SUPERVISOR · UNAVAILABLE",
                        )
                    };

                    let text = match result.as_ref().ok().and_then(|value| {
                        rwr_package_intelligence::supervisor_client::diagnostic_session_summary(
                            value,
                        )
                        .ok()
                        .flatten()
                    }) {
                        Some(summary) => format!("{text}\n{summary}"),
                        None => text.to_string(),
                    };
                    supervisor_label.set_text(&text);
                    if let Ok(value) = &result {
                        if let Ok(Some((id, question_text))) =
                            rwr_package_intelligence::supervisor_client::pending_diagnostic_question(
                                value,
                            )
                        {
                            let transaction_id = value["transaction_id"]
                                .as_str()
                                .unwrap_or_default()
                                .to_owned();
                            let key = (transaction_id.clone(), id);
                            if last_question.as_ref() != Some(&key) && !question_open.get() {
                                last_question = Some(key);
                                question_open.set(true);
                                let dialog = MessageDialog::builder()
                                    .transient_for(&supervisor_window)
                                    .modal(true)
                                    .message_type(MessageType::Question)
                                    .buttons(ButtonsType::YesNo)
                                    .text("LAB SUPERVISOR · REAL MODE LOCKED")
                                    .secondary_text(&question_text)
                                    .build();
                                let socket = socket.clone();
                                let sender = sender.clone();
                                let open = Rc::clone(&question_open);
                                dialog.connect_response(move |dialog, response| {
                                    dialog.close();
                                    open.set(false);
                                    let socket = socket.clone();
                                    let sender = sender.clone();
                                    let transaction_id = transaction_id.clone();
                                    let approved = response == gtk4::ResponseType::Yes;
                                    std::thread::spawn(move || {
                                        let result = rwr_package_intelligence::supervisor_client::answer_diagnostic_question(
                                            &socket, &transaction_id, id, approved);
                                        let _ = sender.send(result);
                                    });
                                });
                                dialog.present();
                            }
                        } else {
                            last_question = None;
                        }
                    } else {
                        last_question = None;
                    }

                    if last_available != Some(available) {
                        eprintln!(
                            "RWR SUPERVISOR: {}",
                            if available {
                                "diagnostic connection available"
                            } else {
                                "diagnostic connection unavailable"
                            }
                        );
                    }

                    last_available = Some(available);
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    supervisor_label.set_text("SUPERVISOR · IPC ERROR");
                    return glib::ControlFlow::Break;
                }
            }

            glib::ControlFlow::Continue
        });
    }

    // UFO visibility follows actual scanner activity.
    let ufo_visibility = ufo_strip.downgrade();
    let ufo_work_stack = work_stack.downgrade();
    let ufo_state = Rc::clone(&state);
    let ufo_value = Rc::clone(&ufo_status);
    let demo_phase_display = demo_phase_label.clone();
    let cancel_visibility = cancel_button.downgrade();
    let recover_visibility = recover_button.downgrade();
    let scan_availability = button.downgrade();
    glib::timeout_add_local(Duration::from_millis(100), move || {
        let Some(ufo_visibility) = ufo_visibility.upgrade() else {
            return glib::ControlFlow::Break;
        };

        let current = ufo_state.borrow();
        let active = current.test_animation_active;
        let real_active = current.real_update_active;
        if let Some(scan) = scan_availability.upgrade() {
            scan.set_sensitive(
                !current.preparing_upgrade
                    && !current.scanning
                    && !current.real_update_active
                    && !current.production_confirmation_open
                    && !current.test_animation_active
                    && !current.demo_authorization_open,
            );
        }

        let view = ufo_view(&current);
        let full = matches!(view, Some((_, true)));
        ufo_visibility.set_visible(matches!(view, Some((_, false))));
        if let Some(stack) = ufo_work_stack.upgrade() {
            // The package list returns as soon as the operation ends.
            let page = if full { "ufo" } else { "packages" };
            if stack.visible_child_name().as_deref() != Some(page) {
                stack.set_visible_child_name(page);
            }
        }
        if let Some((status, _)) = view {
            if *ufo_value.borrow() != status {
                *ufo_value.borrow_mut() = status;
            }
        }
        if let Some(recover) = recover_visibility.upgrade() {
            recover.set_visible(recovery_check_visible(&current, diagnostic_ui));
        }
        if let Some(cancel) = cancel_visibility.upgrade() {
            cancel.set_visible(current.real_update_active && current.real_update_can_interrupt);
        }
        let show_phase =
            diagnostic_ui && (real_active || active || current.test_animation_progress >= 1.0);
        demo_phase_display.set_visible(show_phase);

        if show_phase && real_active {
            use crate::real_progress::UpgradeEvent;

            let (pl, en) = match current.real_update_phase.as_ref() {
                Some(UpgradeEvent::Synchronizing) => {
                    ("SYNCHRONIZACJA BAZ", "SYNCHRONIZING DATABASES")
                }
                Some(UpgradeEvent::ResolvingDependencies) => {
                    ("ROZWIAZYWANIE ZALEZNOSCI", "RESOLVING DEPENDENCIES")
                }
                Some(UpgradeEvent::CheckingConflicts) => {
                    ("SPRAWDZANIE KONFLIKTOW", "CHECKING CONFLICTS")
                }
                Some(UpgradeEvent::Downloading) => ("POBIERANIE PAKIETOW", "DOWNLOADING PACKAGES"),
                Some(UpgradeEvent::Installing | UpgradeEvent::Upgrading) => {
                    ("INSTALOWANIE PAKIETOW", "INSTALLING PACKAGES")
                }
                Some(UpgradeEvent::CheckingKeys) => ("WERYFIKACJA KLUCZY", "VERIFYING KEYS"),
                Some(UpgradeEvent::RunningHooks) => ("WYKONYWANIE HOOKOW", "RUNNING HOOKS"),
                Some(UpgradeEvent::Warning(_)) => ("OSTRZEZENIE", "WARNING"),
                Some(UpgradeEvent::Error(_)) => ("BLAD AKTUALIZACJI", "UPDATE ERROR"),
                _ => ("OCZEKIWANIE NA ZDARZENIA", "WAITING FOR EVENTS"),
            };

            demo_phase_display.set_label(&tr(current.language, pl, en));
        } else if show_phase {
            let (pl, en) = if !active {
                (
                    "LAB IPC — PREPARE ZAKOŃCZONY",
                    "LAB IPC — PREPARE COMPLETED",
                )
            } else if active {
                if let Some(message) = current.lab_ipc_progress.as_ref() {
                    if let Some(raw) = message.strip_prefix("ALPM_EVENT:") {
                        if let Ok(code) = raw.parse::<i32>() {
                            if let Some((pl, en)) = crate::libalpm_ffi::alpm_event_message(code) {
                                demo_phase_display.set_label(&format!(
                                    "LAB IPC — {}",
                                    tr(current.language, pl, en)
                                ));
                                return glib::ControlFlow::Continue;
                            }
                        }
                    }

                    demo_phase_display.set_label(&format!(
                        "{}: {}",
                        tr(
                            current.language,
                            "LAB IPC — ZWERYFIKOWANY PLAN",
                            "LAB IPC — VERIFIED PLAN",
                        ),
                        message
                    ));
                    return glib::ControlFlow::Continue;
                }
                (
                    "LAB IPC — PRZYGOTOWYWANIE PLANU",
                    "LAB IPC — PREPARING PLAN",
                )
            } else {
                (
                    "LAB IPC — PRZYGOTOWYWANIE PLANU",
                    "LAB IPC — PREPARING PLAN",
                )
            };

            demo_phase_display.set_label(&tr(current.language, pl, en));
        }

        glib::ControlFlow::Continue
    });
    {
        let list = list.clone();
        let status = status.clone();
        let button = button.clone();
        let install_button = install_button.clone();
        let footer = footer.clone();
        let state = Rc::clone(&state);
        button.clone().connect_clicked(move |_| {
            scan(&list, &status, &button, &install_button, &footer, &state)
        });
    }
    {
        let list = list.clone();
        let status = status.clone();
        let button = button.clone();
        let install_button = install_button.clone();
        let footer = footer.clone();
        let state = Rc::clone(&state);
        let recover_button = recover_button.clone();
        let cancel_button = cancel_button.clone();
        lang_button.connect_clicked(move |lang_button| {
            let language = {
                let mut state = state.borrow_mut();
                state.language = match state.language {
                    Language::Polish => Language::English,
                    Language::English => Language::Polish,
                };
                state.language
            };
            recover_button.set_label(&tr(language, "SPRAWDŹ WYNIK", "CHECK RESULT"));
            cancel_button.set_label(&tr(language, "PRZERWIJ", "INTERRUPT"));
            lang_button.set_label(match language {
                Language::Polish => "🇬🇧 EN",
                Language::English => "🇵🇱 PL",
            });
            refresh(&list, &status, &button, &install_button, &footer, &state);
        });
    }
    {
        let window = window.clone();
        let state = Rc::clone(&state);
        let production_list = list.clone();
        let production_status = status.clone();
        let production_scan_button = button.clone();
        let production_install_button = install_button.clone();
        let production_footer = footer.clone();

        install_button.connect_clicked(move |_| {
            let state_for_plan = Rc::clone(&state);
            let window_after_plan = window.clone();
            let status_after_plan = production_status.clone();
            let list_after_plan = production_list.clone();
            let scan_after_plan = production_scan_button.clone();
            let install_after_plan = production_install_button.clone();
            let footer_after_plan = production_footer.clone();
            let state_after_plan = Rc::clone(&state);
            let after_validation: Rc<dyn Fn()> = Rc::new(move || {
                // This callback is reached only after a fresh, explicitly
                // confirmed and bound USER validation result.
                if let Err(reason) = crate::update_launcher::validate_production_ipc_precheck() {
                    present_execution_block(
                        &window_after_plan,
                        &state_after_plan,
                        &list_after_plan,
                        &status_after_plan,
                        &scan_after_plan,
                        &install_after_plan,
                        &footer_after_plan,
                        &reason,
                    );
                } else {
                    request_system_upgrade_dialog(
                        &window_after_plan,
                        Rc::clone(&state_after_plan),
                        &status_after_plan,
                        &list_after_plan,
                        &scan_after_plan,
                        &install_after_plan,
                        &footer_after_plan,
                    );
                }
            });
            request_full_upgrade_plan(
                &window,
                &production_install_button,
                &production_status,
                &production_install_button,
                state_for_plan,
                after_validation,
            );
        });
    }

    {
        let window = window.clone();
        let state = Rc::clone(&state);
        let supervisor_status = supervisor_label.clone();
        if std::env::var_os("RWR_DIAGNOSTIC_SUPERVISOR_SOCKET").is_some() {
            demo_button.set_label("LAB SUPERVISOR");
        }
        demo_button.connect_clicked(move |_| {
            if let Some(socket) = std::env::var_os("RWR_DIAGNOSTIC_SUPERVISOR_SOCKET") {
                request_supervisor_lab(&window, socket.into(), &supervisor_status);
                return;
            }

            let language = {
                let mut current = state.borrow_mut();
                if current.test_animation_active || current.demo_authorization_open {
                    return;
                }
                current.demo_authorization_open = true;
                current.language
            };

            let plan = crate::update_engine::UpdatePlan::arch_full_upgrade();
            if let Err(error) = plan.validate() {
                eprintln!("RWR: Invalid update plan: {error}");
                state.borrow_mut().demo_authorization_open = false;
                return;
            }

            // RWR ARCHIWUM X — dwujezyczna autoryzacja demonstracji.
            // Plan jest walidowany powyzej; zadne polecenie nie jest wykonywane.
            let access_description = tr(
                language,
                "KLASYFIKACJA: TRYB TESTOWY\n\nOperacja: izolowany test libalpm PREPARE.\n\nCzy uruchomic laboratoryjny test IPC?\n\nBez hasla. Bez pobierania. Bez instalacji.",
                "CLASSIFICATION: TEST MODE\n\nOperation: isolated libalpm PREPARE test.\n\nRun the laboratory IPC test?\n\nNo password. No downloads. No installation.",
            );

            let dialog = MessageDialog::builder()
                .transient_for(&window)
                .modal(true)
                .message_type(MessageType::Question)
                .buttons(ButtonsType::None)
                .text(tr(
                    language,
                    "RWR // ARCHIWUM X — AUTORYZACJA DOSTĘPU",
                    "RWR // X-FILES — ACCESS AUTHORIZATION",
                ))
                .secondary_text(access_description)
                .build();
            dialog.add_button(
                &tr(language, "ANULUJ", "CANCEL"),
                gtk4::ResponseType::Cancel,
            );
            dialog.add_button(
                &tr(language, "URUCHOM LAB IPC", "RUN LAB IPC"),
                gtk4::ResponseType::Ok,
            );
            dialog.add_css_class("rwr-auth-dialog");

            let animation_state = Rc::clone(&state);
            dialog.connect_response(move |dialog, response| {
                dialog.close();
                animation_state.borrow_mut().demo_authorization_open = false;

                if response == gtk4::ResponseType::Ok {
                    use crate::transaction_engine::{TransactionDecision, TransactionMode};

                    let plan = crate::update_engine::UpdatePlan::arch_full_upgrade();

                    let decision = {
                        use crate::transaction_state::TransactionState;

                        let mut current = animation_state.borrow_mut();
                        let state = current.transaction_controller.state();

                        if matches!(
                            state,
                            TransactionState::Completed
                                | TransactionState::Cancelled
                                | TransactionState::Failed
                        ) {
                            if let Err(error) = current.transaction_controller.reset() {
                                eprintln!("RWR: Demo reset failed: {error}");
                                return;
                            }
                        }

                        current.transaction_controller.begin(
                            &plan,
                            TransactionMode::Demo,
                            true,
                        )
                    };

                    match decision {
                        Ok(TransactionDecision::StartDemo) => {}
                        Ok(TransactionDecision::Denied) => {
                            eprintln!("RWR: Demo authorization denied");
                            return;
                        }
                        Err(error) => {
                            eprintln!("RWR: Transaction blocked: {error}");
                            return;
                        }
                    }

                    let start_demo = {
                        let mut current = animation_state.borrow_mut();
                        if current.test_animation_active {
                            false
                        } else {
                            current.test_animation_active = true;
                            current.test_animation_progress = 0.0;
                            current.lab_ipc_progress = None;
                            true
                        }
                    };

                    if start_demo {
                        let demo_state = Rc::clone(&animation_state);
                        let receiver = crate::lab_ipc_runner::start_lab_ipc_live();

                        glib::timeout_add_local(Duration::from_millis(100), move || {
                            use crate::transaction_protocol::TransactionOutcome;
                            use crate::transaction_state::TransactionState;

                            use crate::lab_ipc_runner::LabIpcUiEvent;

                            match receiver.try_recv() {
                                Ok(LabIpcUiEvent::Progress(text)) => {
                                    demo_state.borrow_mut().lab_ipc_progress = Some(text);
                                    glib::ControlFlow::Continue
                                }
                                Ok(LabIpcUiEvent::Finished(Ok(TransactionOutcome::Success))) => {
                                    let mut current = demo_state.borrow_mut();

                                    if current.transaction_controller.state()
                                        == TransactionState::Running
                                    {
                                        if let Err(error) =
                                            current.transaction_controller.complete()
                                        {
                                            eprintln!("RWR LAB IPC: {error}");
                                        }
                                    }

                                    current.test_animation_progress = 1.0;
                                    current.test_animation_active = false;
                                    glib::ControlFlow::Break
                                }
                                Ok(LabIpcUiEvent::Finished(Ok(outcome))) => {
                                    eprintln!("RWR LAB IPC: unexpected outcome: {outcome:?}");

                                    let mut current = demo_state.borrow_mut();
                                    if current.transaction_controller.state()
                                        == TransactionState::Running
                                    {
                                        let _ = current.transaction_controller.fail();
                                    }

                                    current.test_animation_progress = -1.0;
                                    current.test_animation_active = false;
                                    glib::ControlFlow::Break
                                }
                                Ok(LabIpcUiEvent::Finished(Err(error))) => {
                                    eprintln!("RWR LAB IPC FAILED: {error}");

                                    let mut current = demo_state.borrow_mut();
                                    if current.transaction_controller.state()
                                        == TransactionState::Running
                                    {
                                        let _ = current.transaction_controller.fail();
                                    }

                                    current.test_animation_progress = -1.0;
                                    current.test_animation_active = false;
                                    glib::ControlFlow::Break
                                }
                                Err(mpsc::TryRecvError::Empty) => {
                                    glib::ControlFlow::Continue
                                }
                                Err(mpsc::TryRecvError::Disconnected) => {
                                    eprintln!("RWR LAB IPC: worker disconnected");

                                    let mut current = demo_state.borrow_mut();
                                    if current.transaction_controller.state()
                                        == TransactionState::Running
                                    {
                                        let _ = current.transaction_controller.fail();
                                    }

                                    current.test_animation_progress = -1.0;
                                    current.test_animation_active = false;
                                    glib::ControlFlow::Break
                                }
                            }
                        });
                    }


                }
            });
            dialog.present();
        });
    }

    window.set_child(Some(&root));
    window.present();
    scan(&list, &status, &button, &install_button, &footer, &state);
}

// RWR IPC DEMO — GTK4 event adapter, TEST MODE ONLY.
fn poll_ipc_demo_events(
    receiver: std::sync::mpsc::Receiver<crate::ipc_demo_worker::IpcDemoEvent>,
    state: Rc<RefCell<UiState>>,
) {
    use crate::ipc_demo_worker::IpcDemoEvent;
    use crate::transaction_state::TransactionState;

    glib::timeout_add_local(Duration::from_millis(100), move || {
        match receiver.try_recv() {
            Ok(IpcDemoEvent::Started) => {
                eprintln!("RWR IPC DEMO: helper started");
                glib::ControlFlow::Continue
            }
            Ok(IpcDemoEvent::Question(text)) => {
                eprintln!("RWR IPC DEMO: question: {text}");
                glib::ControlFlow::Continue
            }
            Ok(IpcDemoEvent::Completed) => {
                let mut current = state.borrow_mut();
                if current.transaction_controller.state() == TransactionState::Running {
                    if let Err(error) = current.transaction_controller.complete() {
                        eprintln!("RWR IPC DEMO: completion error: {error}");
                    }
                }
                current.test_animation_progress = 1.0;
                current.test_animation_active = false;
                glib::ControlFlow::Break
            }
            Ok(IpcDemoEvent::Cancelled) => {
                let mut current = state.borrow_mut();
                if current.transaction_controller.state() == TransactionState::Running {
                    if let Err(error) = current.transaction_controller.cancel() {
                        eprintln!("RWR IPC DEMO: cancellation error: {error}");
                    }
                }
                current.test_animation_active = false;
                glib::ControlFlow::Break
            }
            Ok(IpcDemoEvent::Failed(error)) => {
                eprintln!("RWR IPC DEMO FAILED: {error}");
                let mut current = state.borrow_mut();
                if current.transaction_controller.state() == TransactionState::Running {
                    if let Err(error) = current.transaction_controller.fail() {
                        eprintln!("RWR IPC DEMO: failure transition: {error}");
                    }
                }
                current.test_animation_active = false;
                glib::ControlFlow::Break
            }
            Err(mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
            Err(mpsc::TryRecvError::Disconnected) => {
                let mut current = state.borrow_mut();
                if current.transaction_controller.state() == TransactionState::Running {
                    let _ = current.transaction_controller.fail();
                }
                current.test_animation_active = false;
                glib::ControlFlow::Break
            }
        }
    });
}

// K3B: GTK main-thread adapter for the existing production supervisor.
// This adapter never spawns a helper itself and cannot override REAL MODE locks.
#[allow(clippy::too_many_arguments)]
fn poll_production_ipc_events(
    receiver: mpsc::Receiver<crate::production_ipc::ProductionIpcEvent>,
    answers: mpsc::Sender<crate::transaction_ipc::IpcReply>,
    window: ApplicationWindow,
    state: Rc<RefCell<UiState>>,
    status: Label,
    list: GtkBox,
    scan_button: Button,
    install_button: Button,
    footer: Label,
) {
    use crate::production_ipc::ProductionIpcEvent;
    use crate::transaction_ipc::IpcReply;
    use crate::transaction_protocol::TransactionOutcome;

    let weak_window = window.downgrade();
    // Last helper/supervisor message, kept for a definite pre-COMMIT failure.
    let mut last_progress = String::new();
    glib::timeout_add_local(Duration::from_millis(100), move || {
        let Some(window) = weak_window.upgrade() else {
            return glib::ControlFlow::Break;
        };
        match receiver.try_recv() {
            Ok(ProductionIpcEvent::Snapshot(value)) => {
                if let Some(access) = state.borrow_mut().fbi_access.as_mut() {
                    access.on_snapshot(&value);
                }
                state.borrow_mut().real_update_can_interrupt = value["outcome"] == "running"
                    && value["partial_installation_possible"] == false
                    && matches!(value["phase"].as_str(), Some("prepare" | "ready"));
                let language = state.borrow().language;
                let phase = value["phase"].as_str().unwrap_or("unknown");
                let title = match phase {
                    "prepare" => tr(language, "PRZYGOTOWANIE", "PREPARE"),
                    "ready" => tr(language, "POBIERANIE / WERYFIKACJA", "DOWNLOAD / VERIFY"),
                    "commit" | "commit_started" => tr(
                        language,
                        "INSTALACJA — NIE WYŁĄCZAJ",
                        "INSTALLING — DO NOT POWER OFF",
                    ),
                    "finished" => tr(language, "WYNIK ZAPISANY", "RESULT SAVED"),
                    _ => tr(language, "STAN SESJI", "SESSION STATE"),
                };
                let raw = value["progress"].as_str().unwrap_or("");
                let progress = serde_json::from_str::<serde_json::Value>(raw).ok();
                let detail = if let Some(progress) = progress {
                    let stage = match progress["stage"].as_str() {
                        Some("download") => tr(language, "POBIERANIE", "DOWNLOADING"),
                        Some("signatures") => {
                            tr(language, "WERYFIKACJA PODPISÓW", "VERIFYING SIGNATURES")
                        }
                        Some("alpm-progress") => match progress["kind"].as_i64() {
                            Some(0..=4) => {
                                tr(language, "INSTALACJA PAKIETÓW", "INSTALLING PACKAGES")
                            }
                            Some(5) => tr(language, "SPRAWDZANIE KONFLIKTÓW", "CHECKING CONFLICTS"),
                            Some(6) => tr(language, "SPRAWDZANIE MIEJSCA", "CHECKING DISK SPACE"),
                            Some(7 | 9) => {
                                tr(language, "WERYFIKACJA PAKIETÓW", "VERIFYING PACKAGES")
                            }
                            _ => tr(language, "PRZYGOTOWANIE PAKIETÓW", "PREPARING PACKAGES"),
                        },
                        _ => tr(language, "POSTĘP TRANSAKCJI", "TRANSACTION PROGRESS"),
                    };
                    let package = progress["package"]
                        .as_str()
                        .or_else(|| progress["filename"].as_str())
                        .unwrap_or("");
                    let amount = if let Some(percent) = progress["percent"].as_u64() {
                        format!("{}%", percent.min(100))
                    } else if let (Some(done), Some(total)) =
                        (progress["downloaded"].as_i64(), progress["total"].as_i64())
                    {
                        format!("{done} / {total} B")
                    } else {
                        String::new()
                    };
                    format!("{stage} · {package} · {amount}")
                } else {
                    raw.to_owned()
                };
                {
                    let progress = serde_json::from_str::<serde_json::Value>(raw).ok();
                    let mut current = state.borrow_mut();
                    let (stage, percent) = ufo_snapshot_state(
                        phase,
                        value["outcome"].as_str().unwrap_or("unknown"),
                        progress.as_ref(),
                    );
                    current.ufo_real_stage = Some(stage);
                    current.real_update_percent = percent;
                    current.ufo_real_detail = detail.clone();
                }
                status.set_text(&format!(
                    "RWR // {title} · {}\n{detail}",
                    value["transaction_id"].as_str().unwrap_or("")
                ));
                glib::ControlFlow::Continue
            }
            Ok(ProductionIpcEvent::Progress(message)) => {
                let language = state.borrow().language;
                last_progress = message.chars().take(512).collect();
                status.set_text(&format!(
                    "{}: {message}",
                    tr(language, "Aktualizacja", "Update")
                ));
                glib::ControlFlow::Continue
            }
            Ok(ProductionIpcEvent::Question { id, text }) => {
                let language = state.borrow().language;
                let dialog = MessageDialog::builder()
                    .transient_for(&window)
                    .modal(true)
                    .message_type(MessageType::Question)
                    .buttons(ButtonsType::None)
                    .text(tr(
                        language,
                        "RWR // PYTANIE SYSTEMOWE",
                        "RWR // SYSTEM QUESTION",
                    ))
                    .secondary_text(&text)
                    .build();
                dialog.add_button(
                    &tr(language, "ODRZUĆ", "REJECT"),
                    gtk4::ResponseType::Cancel,
                );
                dialog.add_button(
                    &tr(language, "POTWIERDŹ", "APPROVE"),
                    gtk4::ResponseType::Accept,
                );
                let answers = answers.clone();
                dialog.connect_response(move |dialog, response| {
                    dialog.close();
                    let approved = response == gtk4::ResponseType::Accept;
                    if answers.send(IpcReply::Answer { id, approved }).is_err() {
                        eprintln!("RWR production IPC: answer channel disconnected");
                    }
                });
                dialog.present();
                glib::ControlFlow::Continue
            }
            Ok(ProductionIpcEvent::Cancelled) => {
                status.set_text(&tr(
                    state.borrow().language,
                    "Anulowanie transakcji...",
                    "Cancelling transaction...",
                ));
                glib::ControlFlow::Continue
            }
            Ok(ProductionIpcEvent::Finished(result)) => {
                {
                    let text = match &result {
                        Err(error) => error.clone(),
                        Ok(_) => last_progress.clone(),
                    };
                    let mut current = state.borrow_mut();
                    current.fbi_access = current
                        .fbi_access
                        .take()
                        .and_then(|a| a.after_finished(&text));
                }
                let language = state.borrow().language;
                let kind = result_kind(&result);
                let message = match result {
                    Ok(TransactionOutcome::Success) => {
                        tr(language, "Aktualizacja zakończona", "Update completed")
                    }
                    Ok(TransactionOutcome::Cancelled) => {
                        tr(language, "Aktualizacja anulowana", "Update cancelled")
                    }
                    // Only a supervisor-stated failure with no possible
                    // partial installation arrives as Ok(Failure).
                    Ok(TransactionOutcome::Failure) => format!(
                        "{}\n{last_progress}",
                        tr(
                            language,
                            "NIE WYKONANO: aktualizacja zatrzymana przed COMMIT. Nie zainstalowano pakietów.",
                            "NOT PERFORMED: update stopped before COMMIT. No packages were installed.",
                        )
                    ),
                    Ok(TransactionOutcome::Running) => tr(
                        language,
                        "Błąd: transakcja nadal trwa",
                        "Error: transaction still running",
                    ),
                    Err(error) => format!(
                        "{}: {error}",
                        tr(language, "Błąd aktualizacji", "Update error")
                    ),
                };
                let message = if kind == ResultKind::Unknown {
                    format!(
                        "{message}\n{}",
                        tr(
                            language,
                            "WYNIK NIEZNANY: nie wyłączaj komputera i nie ponawiaj aktualizacji. Użyj SPRAWDŹ WYNIK.",
                            "OUTCOME UNKNOWN: do not power off or retry the update. Use CHECK RESULT.",
                        )
                    )
                } else {
                    message
                };
                if matches!(
                    kind,
                    ResultKind::Success | ResultKind::Failed | ResultKind::Cancelled
                ) {
                    if let Some(reference) = state.borrow().execution_reference.as_ref() {
                        let _ = rwr_package_intelligence::supervisor_client::mark_execution_reference_resolved(reference);
                    }
                }
                {
                    let mut current = state.borrow_mut();
                    current.transaction_result = Some(UiTransactionResult {
                        kind,
                        detail: message.clone(),
                        transaction_id: current
                            .execution_reference
                            .as_ref()
                            .map(|r| r.transaction_id.clone()),
                    });
                    current.real_update_active = false;
                }
                refresh(
                    &list,
                    &status,
                    &scan_button,
                    &install_button,
                    &footer,
                    &state,
                );
                status.set_text(&message);
                if kind == ResultKind::Success {
                    scan(
                        &list,
                        &status,
                        &scan_button,
                        &install_button,
                        &footer,
                        &state,
                    );
                }
                glib::ControlFlow::Break
            }
            Err(mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
            Err(mpsc::TryRecvError::Disconnected) => {
                {
                    let mut current = state.borrow_mut();
                    current.fbi_access = None;
                    current.transaction_result = Some(UiTransactionResult {
                        kind: ResultKind::Unknown,
                        detail: tr(
                            current.language,
                            "Utracono połączenie IPC. Wynik wymaga odzyskania z sesji.",
                            "IPC connection lost. Recover the outcome from the session.",
                        ),
                        transaction_id: current
                            .execution_reference
                            .as_ref()
                            .map(|r| r.transaction_id.clone()),
                    });
                    current.real_update_active = false;
                }
                refresh(
                    &list,
                    &status,
                    &scan_button,
                    &install_button,
                    &footer,
                    &state,
                );
                status.set_text(&tr(
                    state.borrow().language,
                    "Utracono połączenie IPC",
                    "IPC connection lost",
                ));
                glib::ControlFlow::Break
            }
        }
    });
}

// Reuse the existing lab button, but let the supervisor own this diagnostic child.
fn request_supervisor_lab(window: &ApplicationWindow, socket: std::path::PathBuf, status: &Label) {
    let dialog = MessageDialog::builder()
        .transient_for(window)
        .modal(true)
        .message_type(MessageType::Question)
        .buttons(ButtonsType::OkCancel)
        .text("LAB SUPERVISOR · REAL MODE LOCKED")
        .secondary_text(
            "Uruchomic symulowana sesje diagnostyczna? / Start a simulated diagnostic session?",
        )
        .build();
    let status = status.clone();
    dialog.connect_response(move |dialog, response| {
        dialog.close();
        if response != gtk4::ResponseType::Ok {
            return;
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let id = format!("gui-{}-{nonce}", std::process::id());
        let socket = socket.clone();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(
                rwr_package_intelligence::supervisor_client::start_diagnostic_session(&socket, &id),
            );
        });
        let status = status.clone();
        glib::timeout_add_local(Duration::from_millis(100), move || {
            match receiver.try_recv() {
                Ok(Ok(value)) => {
                    if let Ok(Some(text)) =
                        rwr_package_intelligence::supervisor_client::diagnostic_session_summary(
                            &value,
                        )
                    {
                        status.set_text(&format!("LAB SUPERVISOR · {text}"));
                    }
                }
                Ok(Err(error)) => status.set_text(&format!("LAB SUPERVISOR · {error}")),
                Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                Err(mpsc::TryRecvError::Disconnected) => {
                    status.set_text("LAB SUPERVISOR · IPC ERROR")
                }
            }
            glib::ControlFlow::Break
        });
    });
    dialog.present();
}

// ALPM PREPARE and revalidation run outside GTK. Neither action executes COMMIT.

fn execution_block_message(language: Language, reason: &str) -> String {
    format!(
        "{}\n\n{}\n\n{reason}",
        tr(
            language,
            "Plan został sprawdzony, ale instalacja nie została uruchomiona. Wymagana jest poprawna polityka wykonania i dostępny backend SYSTEM. Autoryzacja Polkit i osobne zatwierdzenie transakcji nadal są wymagane.",
            "The plan was checked, but installation was not started. A valid execution policy and an available SYSTEM backend are required. Polkit authorization and separate transaction confirmation are still required."
        ),
        rwr_package_intelligence::supervisor_trust::SYSTEM_EXECUTION_POLICY
    )
}

fn present_execution_block(
    window: &ApplicationWindow,
    state: &Rc<RefCell<UiState>>,
    list: &GtkBox,
    status: &Label,
    scan: &Button,
    update: &Button,
    footer: &Label,
    reason: &str,
) {
    let language = state.borrow().language;
    let message = execution_block_message(language, reason);
    {
        let mut current = state.borrow_mut();
        current.transaction_result = Some(UiTransactionResult {
            kind: ResultKind::Blocked,
            detail: message.clone(),
            transaction_id: current
                .confirmed_plan
                .as_ref()
                .map(|r| r.transaction_id.clone()),
        });
    }
    refresh(list, status, scan, update, footer, state);
    status.set_text(&tr(
        language,
        "INSTALACJA ZABLOKOWANA — sprawdź komunikat",
        "INSTALLATION BLOCKED — see details",
    ));
    let dialog = MessageDialog::builder()
        .transient_for(window)
        .modal(true)
        .message_type(MessageType::Warning)
        .buttons(ButtonsType::Close)
        .text(tr(
            language,
            "INSTALACJA NIE ZOSTAŁA URUCHOMIONA",
            "INSTALLATION WAS NOT STARTED",
        ))
        .secondary_text(&message)
        .build();
    dialog.connect_response(|dialog, _| dialog.close());
    dialog.present();
}

fn request_system_upgrade_dialog(
    window: &ApplicationWindow,
    state: Rc<RefCell<UiState>>,
    production_status: &Label,
    production_list: &GtkBox,
    production_scan_button: &Button,
    production_install_button: &Button,
    production_footer: &Label,
) {
    let language = {
        let current = state.borrow();

        if current.scanning
            || current.preparing_upgrade
            || current.analyzing_changelogs
            || current.test_animation_active
            || current.demo_authorization_open
            || current.real_update_active
            || current.production_confirmation_open
            || current.confirmed_plan.is_none()
        {
            return;
        }

        current.language
    };

    if let Err(reason) = crate::update_launcher::validate_production_ipc_precheck() {
        present_execution_block(
            window,
            &state,
            production_list,
            production_status,
            production_scan_button,
            production_install_button,
            production_footer,
            &reason,
        );
        return;
    }

    if !state.borrow().system_backend_available {
        let reason = tr(
            language,
            "Backend SYSTEM niedostępny. Instalacja zablokowana.",
            "SYSTEM backend unavailable. Installation locked.",
        );
        present_execution_block(
            window,
            &state,
            production_list,
            production_status,
            production_scan_button,
            production_install_button,
            production_footer,
            &reason,
        );
        return;
    }
    let plan = crate::update_engine::UpdatePlan::arch_full_upgrade();

    if let Err(error) = plan.validate() {
        eprintln!("RWR: Invalid update plan: {error}");
        return;
    }

    let Some(confirmed_request) = state.borrow().confirmed_plan.clone() else {
        return;
    };
    let description = tr(
        language,
        "KLASYFIKACJA: AKTUALIZACJA SYSTEMU\n\nOperacja: pelna aktualizacja Arch Linux.\n\nAktualizacja pelnego systemu Arch Linux. Wymagana jest systemowa autoryzacja Polkit. Operacja obejmuje synchronizacje baz i aktualizacje pakietow.\n\nCzy chcesz kontynuowac?",
        "CLASSIFICATION: SYSTEM UPDATE\n\nOperation: full Arch Linux upgrade.\n\nFull Arch Linux system upgrade. System Polkit authorization is required. The operation synchronizes repositories and upgrades installed packages.\n\nDo you want to continue?",
    );

    let description = format!(
        "{description}\n\nID transakcji / Transaction ID: {}\nSHA256 planu / Plan SHA256: {}",
        confirmed_request.transaction_id, confirmed_request.plan_digest
    );

    let dialog = MessageDialog::builder()
        .transient_for(window)
        .modal(true)
        .message_type(MessageType::Question)
        .buttons(ButtonsType::None)
        .text(tr(
            language,
            "RWR // ARCHIWUM X — AUTORYZACJA AKTUALIZACJI",
            "RWR // X-FILES — UPDATE AUTHORIZATION",
        ))
        .secondary_text(description)
        .build();

    dialog.add_button(
        &tr(language, "ANULUJ", "CANCEL"),
        gtk4::ResponseType::Cancel,
    );

    dialog.add_button(
        &tr(language, "AKTUALIZUJ SYSTEM", "UPDATE SYSTEM"),
        gtk4::ResponseType::Accept,
    );

    let parent = window.clone();
    let production_state = Rc::clone(&state);
    let production_list = production_list.clone();
    let production_status = production_status.clone();
    let production_scan_button = production_scan_button.clone();
    let production_install_button = production_install_button.clone();
    let production_footer = production_footer.clone();

    state.borrow_mut().production_confirmation_open = true;
    let handled = Rc::new(std::cell::Cell::new(false));
    dialog.connect_response(move |dialog, response| {
        if handled.replace(true) {
            return;
        }
        dialog.close();
        production_state.borrow_mut().production_confirmation_open = false;

        if response != gtk4::ResponseType::Accept {
            return;
        }

        // Recheck the live plan at acceptance, not only when opening
        // the dialog. Scans/reconnects may have invalidated that copy.
        let confirmation_check = {
            let current = production_state.borrow();
            crate::update_launcher::validate_pending_execution_confirmation(
                current.confirmed_plan.as_ref(),
                &confirmed_request,
                current.real_update_active
                    || current.preparing_upgrade
                    || current.scanning
                    || current.analyzing_changelogs
                    || current.test_animation_active
                    || current.demo_authorization_open,
            )
        };
        if let Err(error) = confirmation_check {
            production_status.set_text(&error);
            return;
        }

        // K3B: supervised production IPC entry point; helper stays locked.
        let result = crate::update_launcher::start_confirmed_production_ipc(&confirmed_request);

        match result {
            Ok((events, answers)) => {
                production_state.borrow_mut().real_update_active = true;
                production_state.borrow_mut().fbi_access =
                    Some(crate::fbi_access::FbiAccess::awaiting(
                        crate::fbi_access::AccessKind::Execute,
                        &confirmed_request.transaction_id,
                    ));
                reset_ufo_transaction(&production_state);
                production_state.borrow_mut().execution_reference = Some(confirmed_request.clone());
                production_state.borrow_mut().confirmed_plan = None;
                poll_production_ipc_events(
                    events,
                    answers,
                    parent.clone(),
                    Rc::clone(&production_state),
                    production_status.clone(),
                    production_list.clone(),
                    production_scan_button.clone(),
                    production_install_button.clone(),
                    production_footer.clone(),
                );
            }
            Err(error) => {
                let message = format!(
                    "{}\n\n{}",
                    tr(
                        language,
                        "Nie mozna uruchomic aktualizacji systemu.",
                        "Unable to start the system update.",
                    ),
                    error
                );

                let error_dialog = MessageDialog::builder()
                    .transient_for(&parent)
                    .modal(true)
                    .message_type(MessageType::Error)
                    .buttons(ButtonsType::Close)
                    .text(tr(
                        language,
                        "RWR // BLAD URUCHAMIANIA",
                        "RWR // LAUNCH ERROR",
                    ))
                    .secondary_text(&message)
                    .build();

                error_dialog.connect_response(|dialog, _| dialog.close());
                error_dialog.present();
            }
        }
    });

    dialog.present();
}

fn validated_gui_plan(
    request: &crate::transaction_ipc::PlanValidationRequest,
    value: &serde_json::Value,
    generation: u64,
    current_generation: u64,
) -> Result<crate::transaction_ipc::PlanValidationRequest, String> {
    request.validate()?;
    let validation =
        rwr_package_intelligence::supervisor_session::PlanValidationSession::from_json(value)?;
    if generation != current_generation
        || request.scope != "system"
        || validation.request != *request
        || value["validation_outcome"] != "validated"
    {
        return Err("Plan changed or USER validation refused; prepare and review again".into());
    }
    Ok(request.clone())
}

/// Present the complete PREPARE plan without changing the object later revalidated.
fn upgrade_plan_review(
    details: &rwr_package_intelligence::libalpm_ffi::AlpmPreparedUpgrade,
    language: Language,
) -> GtkBox {
    let view = GtkBox::new(Orientation::Vertical, 10);
    view.set_margin_top(14);
    view.set_margin_bottom(14);
    view.set_margin_start(18);
    view.set_margin_end(18);
    let label = |text: &str, class: &str| {
        let label = Label::new(Some(text));
        label.set_xalign(0.0);
        label.set_wrap(true);
        label.set_wrap_mode(gtk4::pango::WrapMode::WordChar);
        label.add_css_class(class);
        label
    };
    let upgrades = details
        .add
        .iter()
        .filter(|p| p.installed_version.is_some())
        .count();
    let installs = details.add.len() - upgrades;
    let removals = details.remove.len();
    let dependencies = details.add.iter().filter(|p| p.dependency_added).count();
    let total = details.add.len() + removals;
    view.append(&label(
        &tr(
            language,
            &format!("ŚWIEŻY PLAN ALPM · pakiety: {total}"),
            &format!("FRESH ALPM PLAN · {total} packages"),
        ),
        "package-title",
    ));
    view.append(&label(&tr(language,
        &format!("Aktualizacje: {upgrades}  ·  Instalacje: {installs}  ·  Usunięcia: {removals}  ·  Dobrane jako zależności: {dependencies}"),
        &format!("Upgrades: {upgrades}  ·  Installs: {installs}  ·  Removals: {removals}  ·  Selected as dependencies: {dependencies}")), "package-description"));
    view.append(&label(&tr(language,
        "Po potwierdzeniu aplikacja odświeży repozytoria i ponownie sprawdzi cały plan. Zmiana unieważni zgodę. Instalacja wymaga osobnego potwierdzenia i Polkit.",
        "After confirmation the application refreshes repositories and rechecks the entire plan. A change invalidates consent. Installation requires separate confirmation and Polkit."), "package-note"));

    let content = GtkBox::new(Orientation::Vertical, 8);
    let scroll = ScrolledWindow::new();
    scroll.set_vexpand(true);
    scroll.set_hexpand(true);
    scroll.set_policy(gtk4::PolicyType::Never, gtk4::PolicyType::Automatic);
    scroll.set_min_content_height(200);
    scroll.set_child(Some(&content));
    view.append(&scroll);

    let row = |name: &str, old: &str, new: &str, action: &str, repository: Option<&str>| {
        let card = GtkBox::new(Orientation::Vertical, 5);
        card.add_css_class("package-row");
        let top = GtkBox::new(Orientation::Horizontal, 8);
        let title = label(name, "package-title");
        title.set_hexpand(true);
        title.set_selectable(true);
        top.append(&title);
        top.append(&label(action, "package-category"));
        card.append(&top);
        let versions = GtkBox::new(Orientation::Horizontal, 16);
        versions.set_homogeneous(true);
        for (caption, value, class) in [
            (
                tr(language, "STARA WERSJA", "OLD VERSION"),
                old,
                "version-old",
            ),
            (
                tr(language, "NOWA WERSJA", "NEW VERSION"),
                new,
                "version-new",
            ),
        ] {
            let field = GtkBox::new(Orientation::Vertical, 2);
            field.append(&label(&caption, "version-caption"));
            let value = label(value, class);
            value.set_selectable(true);
            field.append(&value);
            versions.append(&field);
        }
        card.append(&versions);
        if let Some(repository) = repository {
            card.append(&label(
                &tr(
                    language,
                    &format!("Repozytorium: {repository}"),
                    &format!("Repository: {repository}"),
                ),
                "package-description",
            ));
        }
        card
    };
    if removals > 0 {
        content.append(&label(
            &tr(language, "PAKIETY DO USUNIĘCIA", "PACKAGES TO REMOVE"),
            "evidence-alert",
        ));
        for package in &details.remove {
            content.append(&row(
                &package.name,
                &package.version,
                "—",
                &tr(language, "USUNIĘCIE", "REMOVE"),
                None,
            ));
        }
    }
    if !details.decisions.is_empty() {
        content.append(&label(
            &tr(language, "DECYZJE ALPM PREPARE", "ALPM PREPARE DECISIONS"),
            "list-heading",
        ));
        for kind in &details.decisions {
            let (pl, en) = match kind {
                1 => (
                    "Pakiet oznaczony do pominięcia pozostaje pominięty.",
                    "Ignored package retained as ignored.",
                ),
                2 => (
                    "Plan zawiera proponowane zastąpienie pakietu do zatwierdzenia.",
                    "Proposed replacement included for explicit approval.",
                ),
                4 => (
                    "Plan zawiera usunięcie konfliktującego pakietu do zatwierdzenia.",
                    "Conflicting package removal included for explicit approval.",
                ),
                32 => (
                    "Wybrano pierwszego dostawcę zależności. Sprawdź dobrane pakiety.",
                    "First dependency provider selected; review the selected packages.",
                ),
                _ => (
                    "Odrzucono operację destrukcyjną, częściową lub import klucza.",
                    "Destructive/partial/key-import request refused.",
                ),
            };
            content.append(&label(&tr(language, pl, en), "package-note"));
        }
    }
    if !details.add.is_empty() {
        content.append(&label(
            &tr(
                language,
                "AKTUALIZACJE I INSTALACJE",
                "UPGRADES AND INSTALLS",
            ),
            "list-heading",
        ));
    }
    for package in &details.add {
        let action = if package.dependency_added {
            tr(language, "ZALEŻNOŚĆ", "DEPENDENCY")
        } else if package.installed_version.is_some() {
            tr(language, "AKTUALIZACJA", "UPGRADE")
        } else {
            tr(language, "INSTALACJA", "INSTALL")
        };
        let card = row(
            &package.name,
            package.installed_version.as_deref().unwrap_or("—"),
            &package.version,
            &action,
            Some(&package.repository),
        );
        let heading = tr(
            language,
            "Szczegóły pakietu i zależności",
            "Package details and dependencies",
        );
        let expander = gtk4::Expander::new(Some(&heading));
        expander.add_css_class("package-details");
        let mut lines = vec![
            format!(
                "{} · {}",
                tr(language, "Architektura", "Architecture"),
                package.arch
            ),
            format!(
                "{} · {}",
                tr(language, "Archiwum", "Archive"),
                package.filename
            ),
            format!("SHA256 · {}", package.sha256),
        ];
        for (caption, entries) in [
            (tr(language, "Wymaga", "Requires"), &package.dependencies),
            (tr(language, "Dostarcza", "Provides"), &package.provides),
            (tr(language, "Konflikty", "Conflicts"), &package.conflicts),
            (tr(language, "Zastępuje", "Replaces"), &package.replaces),
        ] {
            if !entries.is_empty() {
                lines.push(format!("{caption} · {}", entries.join(", ")));
            }
        }
        let information = label(&lines.join("\n"), "package-description");
        information.set_selectable(true);
        expander.set_child(Some(&information));
        card.append(&expander);
        content.append(&card);
    }
    if total == 0 {
        content.append(&label(
            &tr(
                language,
                "Plan nie zawiera zmian pakietów.",
                "The plan contains no package changes.",
            ),
            "package-description",
        ));
    }
    view
}

fn request_full_upgrade_plan(
    window: &ApplicationWindow,
    button: &Button,
    status: &Label,
    install: &Button,
    state: Rc<RefCell<UiState>>,
    after_validation: Rc<dyn Fn()>,
) {
    use rwr_package_intelligence::production_alpm_flow::PreparedFullUpgrade;
    let generation = {
        let mut current = state.borrow_mut();
        if !current.can_prepare_upgrade() {
            return;
        }
        current.confirmed_plan = None;
        current.preparing_upgrade = true;
        // A new scan/plan starts a new case: clear an old ACCESS DENIED card.
        current.fbi_access = None;
        current.analysis_generation
    };
    update_install_availability(install, &state.borrow());
    let language = state.borrow().language;
    let install = install.clone();
    button.set_sensitive(false);
    status.set_text(&tr(
        language,
        "Przygotowywanie pełnego planu aktualizacji...",
        "Preparing full upgrade plan...",
    ));
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(PreparedFullUpgrade::prepare_system());
    });
    let weak_window = window.downgrade();
    let button = button.clone();
    let status = status.clone();
    glib::timeout_add_local(Duration::from_millis(100), move || {
        let Some(window) = weak_window.upgrade() else {
            state.borrow_mut().preparing_upgrade = false;
            return glib::ControlFlow::Break;
        };
        let plan = match receiver.try_recv() {
            Ok(Ok(plan)) => plan,
            Ok(Err(error)) => {
                state.borrow_mut().preparing_upgrade = false;
                status.set_text(&format!(
                    "{}: {error}",
                    tr(
                        language,
                        "Błąd przygotowania planu",
                        "Plan preparation failed"
                    )
                ));
                button.set_sensitive(true);
                return glib::ControlFlow::Break;
            }
            Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
            Err(mpsc::TryRecvError::Disconnected) => {
                state.borrow_mut().preparing_upgrade = false;
                status.set_text(&tr(
                    language,
                    "Przygotowanie planu przerwane",
                    "Plan preparation interrupted",
                ));
                button.set_sensitive(true);
                return glib::ControlFlow::Break;
            }
        };
        let dialog = gtk4::Dialog::builder()
            .transient_for(&window)
            .modal(true)
            .title(tr(language, "PLAN AKTUALIZACJI", "UPGRADE PLAN"))
            .default_width(850)
            .default_height(600)
            .build();
        dialog
            .content_area()
            .append(&upgrade_plan_review(plan.details(), language));
        dialog.add_button(
            &tr(language, "ANULUJ", "CANCEL"),
            gtk4::ResponseType::Cancel,
        );
        let confirm = dialog.add_button(
            &tr(language, "POTWIERDŹ AKTUALIZACJĘ", "CONFIRM UPDATE"),
            gtk4::ResponseType::Accept,
        );
        confirm.set_sensitive(!plan.details().add.is_empty() || !plan.details().remove.is_empty());
        let owned_plan = Rc::new(RefCell::new(Some(plan)));
        let button = button.clone();
        let status = status.clone();
        let state = Rc::clone(&state);
        let install = install.clone();
        let weak_window = window.downgrade();
        let after_validation = Rc::clone(&after_validation);
        dialog.connect_response(move |dialog, response| {
            // GtkDialog::close can synchronously emit another response.
            // Consume first so re-entry cannot cancel the accepted plan.
            let Some(plan) = owned_plan.borrow_mut().take() else { return; };
            dialog.close();
            if response != gtk4::ResponseType::Accept {
                state.borrow_mut().preparing_upgrade = false;
                button.set_sensitive(true);
                status.set_text(&tr(language, "Plan niepotwierdzony", "Plan not confirmed"));
                return;
            }
            status.set_text(&tr(language, "Ponowna weryfikacja planu przez USER supervisor...", "Revalidating plan through USER supervisor..."));
            let (sender, receiver) = mpsc::channel();
            std::thread::spawn(move || {
                let result = (|| -> Result<_, String> {
                    let confirmation = plan.confirm_and_revalidate(true)?;
                    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_nanos();
                    let request = confirmation.validation_request(&format!("plan-{}-{nonce}", std::process::id()))?;
                    let socket = rwr_package_intelligence::supervisor_client::default_supervisor_socket();
                    let value = rwr_package_intelligence::supervisor_client::validate_confirmed_plan(&socket, &request)
                        .map_err(|error| format!("USER supervisor · {} · {error}", socket.display()))?;
                    Ok((request, value))
                })();
                let _ = sender.send(result);
            });
            let button = button.clone(); let status = status.clone();
            let state = Rc::clone(&state); let install = install.clone();
            let weak_window = weak_window.clone();
            let after_validation = Rc::clone(&after_validation);
            glib::timeout_add_local(Duration::from_millis(100), move || {
                if weak_window.upgrade().is_none() {
                    state.borrow_mut().preparing_upgrade = false;
                    return glib::ControlFlow::Break;
                }
                let result = match receiver.try_recv() {
                    Ok(Ok((request, value))) => validated_gui_plan(&request, &value, generation, state.borrow().analysis_generation),
                    Ok(Err(error)) => Err(error),
                    Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                    Err(mpsc::TryRecvError::Disconnected) => Err("USER validation worker disconnected".into()),
                };
                state.borrow_mut().preparing_upgrade = false;
                let valid = result.is_ok();
                match result {
                    Ok(request) => {
                        state.borrow_mut().confirmed_plan = Some(request);
                        let message = if crate::update_launcher::validate_production_ipc_precheck().is_ok() {
                            tr(language, "Plan zweryfikowany. Możesz wybrać instalację; wymaga ona osobnego potwierdzenia i Polkit.", "Plan validated. Installation requires separate confirmation and Polkit.")
                        } else {
                            tr(language, "Plan zweryfikowany. Instalacja pozostaje zablokowana przez politykę wykonania.", "Plan validated. Installation remains locked by execution policy.")
                        };
                        status.set_text(&message);
                    }
                    Err(error) => {
                        state.borrow_mut().confirmed_plan = None;
                        status.set_text(&format!("{}: {error}", tr(language, "Zgoda na plan nieważna", "Plan consent invalid")));
                        state.borrow_mut().transaction_result = Some(UiTransactionResult {
                            kind: ResultKind::Blocked, detail: error.clone(), transaction_id: None,
                        });
                        if let Some(parent) = weak_window.upgrade() {
                            let dialog = MessageDialog::builder().transient_for(&parent).modal(true)
                                .message_type(MessageType::Warning).buttons(ButtonsType::Close)
                                .text(tr(language, "ZGODA NA PLAN NIEWAŻNA — INSTALACJA NIEURUCHOMIONA", "PLAN CONSENT INVALID — INSTALLATION NOT STARTED"))
                                .secondary_text(&error).build();
                            dialog.connect_response(|dialog, _| dialog.close()); dialog.present();
                        }
                    }
                }
                update_install_availability(&install, &state.borrow());
                update_install_availability(&button, &state.borrow());
                if valid { after_validation(); }
                glib::ControlFlow::Break
            });
        });
        dialog.present();
        glib::ControlFlow::Break
    });
}

#[cfg(test)]
mod gui_upgrade_plan_tests {
    use super::validated_gui_plan;
    use crate::transaction_ipc::PlanValidationRequest;
    fn request() -> PlanValidationRequest {
        PlanValidationRequest {
            transaction_id: "gui-plan".into(),
            plan_digest: "a".repeat(64),
            scope: "system".into(),
        }
    }
    fn validated(request: &PlanValidationRequest) -> serde_json::Value {
        let mut value = rwr_package_intelligence::supervisor_session::PlanValidationSession::new(
            request.clone(),
        )
        .unwrap()
        .as_json();
        value["validation_outcome"] = "validated".into();
        value["phase"] = "finished".into();
        value["outcome"] = "success".into();
        value
    }
    #[test]
    fn user_validation_must_match_plan_and_scan_generation() {
        let request = request();
        let value = validated(&request);
        assert_eq!(validated_gui_plan(&request, &value, 5, 5).unwrap(), request);
        assert!(validated_gui_plan(&request, &value, 5, 6).is_err());
        let mut changed = request.clone();
        changed.plan_digest = "b".repeat(64);
        assert!(validated_gui_plan(&changed, &value, 5, 5).is_err());
        changed = request.clone();
        changed.transaction_id = "other".into();
        assert!(validated_gui_plan(&changed, &value, 5, 5).is_err());
    }
    #[test]
    fn pending_rejected_and_execution_claims_never_enable_installation() {
        let request = request();
        let pending = rwr_package_intelligence::supervisor_session::PlanValidationSession::new(
            request.clone(),
        )
        .unwrap()
        .as_json();
        assert!(validated_gui_plan(&request, &pending, 1, 1).is_err());
        let mut rejected = validated(&request);
        rejected["validation_outcome"] = "rejected".into();
        rejected["outcome"] = "failure".into();
        assert!(validated_gui_plan(&request, &rejected, 1, 1).is_err());
        for field in [
            "commit_authorized",
            "update_executed",
            "real_execution_enabled",
        ] {
            let mut value = validated(&request);
            value[field] = true.into();
            assert!(
                validated_gui_plan(&request, &value, 1, 1).is_err(),
                "{field}"
            );
        }
    }
}

#[cfg(test)]
mod ufo_view_tests {
    use super::ufo_stage_for_snapshot;
    use crate::ufo_progress::UfoStage;
    use serde_json::json;

    #[test]
    fn supervisor_phases_map_to_ufo_stages() {
        assert_eq!(ufo_stage_for_snapshot("prepare", None), UfoStage::Preparing);
        assert_eq!(ufo_stage_for_snapshot("ready", None), UfoStage::Download);
        assert_eq!(
            ufo_stage_for_snapshot("commit_started", None),
            UfoStage::Install
        );
        assert_eq!(
            ufo_stage_for_snapshot("commit", Some(&json!({"stage":"download"}))),
            UfoStage::Install
        );
        assert_eq!(ufo_stage_for_snapshot("finished", None), UfoStage::Finished);
        assert_eq!(ufo_stage_for_snapshot("unknown", None), UfoStage::Preparing);
    }

    #[test]
    fn progress_stages_map_to_ufo_stages() {
        let stage = |value| ufo_stage_for_snapshot("ready", Some(&value));
        assert_eq!(
            stage(json!({"stage":"download","percent":40})),
            UfoStage::Download
        );
        assert_eq!(stage(json!({"stage":"signatures"})), UfoStage::Verify);
        assert_eq!(
            stage(json!({"stage":"alpm-progress","kind":0})),
            UfoStage::Install
        );
        assert_eq!(
            stage(json!({"stage":"alpm-progress","kind":6})),
            UfoStage::Verify
        );
        assert_eq!(stage(json!({"stage":"alpm-progress"})), UfoStage::Preparing);
    }
}

#[cfg(test)]
mod unified_update_ufo_tests {
    use super::*;
    #[test]
    fn test_binary_forces_library_isolation_without_cargo_environment() {
        assert!(rwr_package_intelligence::test_isolation::active());
        assert!(
            rwr_package_intelligence::supervisor_client::default_supervisor_socket()
                .starts_with(rwr_package_intelligence::test_isolation::state_base())
        );
        let error = rwr_package_intelligence::supervisor_trust::open_system_helper().unwrap_err();
        assert!(error.contains("Test isolation"));
    }

    #[test]
    fn recovery_check_is_hidden_on_main_screen_and_offered_only_for_unknown() {
        let mut state = state();
        assert!(!recovery_check_visible(&state, false));
        state.execution_reference = Some(crate::transaction_ipc::PlanValidationRequest {
            transaction_id: "saved-1".into(),
            plan_digest: "0123456789abcdef".repeat(4),
            scope: "system".into(),
        });
        // A saved ID alone no longer puts the button on the main screen.
        assert!(!recovery_check_visible(&state, false));
        for (kind, shown) in [
            (ResultKind::Success, false),
            (ResultKind::Failed, false),
            (ResultKind::Cancelled, false),
            (ResultKind::Unknown, true),
        ] {
            state.transaction_result = Some(UiTransactionResult {
                kind,
                detail: String::new(),
                transaction_id: Some("saved-1".into()),
            });
            assert_eq!(recovery_check_visible(&state, false), shown);
            assert_eq!(state.can_prepare_upgrade(), !shown);
        }
        state.real_update_active = true;
        assert!(!recovery_check_visible(&state, false));
        assert!(recovery_check_visible(&state, true));
    }
    #[test]
    fn manual_check_and_startup_attach_never_execute() {
        let source = include_str!("ui.rs");
        let handler = source.find("recover_button.connect_clicked").unwrap();
        let body = &source[handler..handler + 2600];
        // Manual check warns about authorization before attaching.
        assert!(body.contains("wymaga autoryzacji administratora"));
        assert!(body.contains("start_manual_result_check"));
        assert!(!body.contains("start_confirmed_production"));
        let check = source.find("fn start_manual_result_check(").unwrap();
        let check_body = &source[check..check + 900];
        assert!(check_body.contains("reconnect_production_session"));
        assert!(!check_body.contains("start_confirmed_production"));
        // Startup never clicks the check and never attaches.
        let needle = ["emit", "_clicked()"].concat();
        assert!(!source.contains(&needle));
        let startup = source.find("// Startup never attaches").unwrap();
        let startup_body = &source[startup..startup + 2000];
        assert!(startup_body.contains("read_system_supervisor_status"));
        assert!(!startup_body.contains("reconnect_production_session"));
    }
    #[test]
    fn startup_unknown_text_warns_and_names_saved_id() {
        let text = startup_unknown_result_text(Language::Polish, "saved-7");
        assert!(text.contains("WYNIK NIEZNANY") && text.contains("saved-7"));
        assert!(text.contains("SPRAWDŹ WYNIK") && text.contains("Nie ponawiaj"));
    }
    fn state() -> UiState {
        UiState {
            language: Language::Polish,
            updates: None,
            scanning: false,
            analyzing_changelogs: false,
            changelog_total: 0,
            changelog_completed: 0,
            changelogs: HashMap::new(),
            system_info: None,
            analysis_cancel: None,
            analysis_generation: 0,
            analysis_cancelled: false,
            error: None,
            last_scan: None,
            transaction_controller: crate::transaction_engine::DemoTransactionController::new(),
            test_animation_active: false,
            demo_authorization_open: false,
            test_animation_progress: 0.0,
            lab_ipc_progress: None,
            system_backend_available: false,
            real_update_active: false,
            real_update_can_interrupt: false,
            preparing_upgrade: false,
            production_confirmation_open: false,
            confirmed_plan: None,
            execution_reference: None,
            real_update_phase: None,
            real_update_percent: None,
            ufo_real_stage: None,
            ufo_real_detail: String::new(),
            transaction_result: None,
            fbi_access: None,
        }
    }
    #[test]
    fn update_can_prepare_without_granting_execution_and_blocks_parallel_work() {
        let mut state = state();
        assert!(state.can_prepare_upgrade()); // No plan or root availability needed to PREPARE.
        assert!(crate::update_launcher::validate_production_ipc_precheck().is_err());
        state.preparing_upgrade = true;
        assert!(!state.can_prepare_upgrade());
        state.preparing_upgrade = false;
        state.production_confirmation_open = true;
        assert!(!state.can_prepare_upgrade());
        state.production_confirmation_open = false;
        state.real_update_active = true;
        assert!(!state.can_prepare_upgrade());
    }
    #[test]
    fn scene_uses_scan_strip_and_replaces_packages_only_during_operations() {
        let mut state = state();
        assert!(ufo_view(&state).is_none());
        state.scanning = true;
        assert_eq!(ufo_view(&state).unwrap().1, false);
        state.scanning = false;
        state.real_update_active = true;
        for stage in [UfoStage::Download, UfoStage::Verify, UfoStage::Install] {
            state.ufo_real_stage = Some(stage);
            let (shown, full) = ufo_view(&state).unwrap();
            assert!(full);
            assert_eq!(shown.stage, stage);
            assert_eq!(shown.progress, None);
        }
        state.real_update_active = false;
        assert!(ufo_view(&state).is_none());
    }
    #[test]
    fn stale_progress_and_failed_outcomes_are_not_presented_as_success() {
        let download = serde_json::json!({"stage":"download","percent":99});
        assert_eq!(
            ufo_snapshot_state("ready", "running", Some(&download)),
            (UfoStage::Download, Some(99))
        );
        assert_eq!(
            ufo_snapshot_state("commit", "running", Some(&download)),
            (UfoStage::Install, None)
        );
        assert_eq!(
            ufo_snapshot_state("finished", "failure", None),
            (UfoStage::Failed, None)
        );
        assert_eq!(
            ufo_snapshot_state("commit", "unknown", None),
            (UfoStage::Failed, None)
        );
    }
    #[test]
    fn approved_list_counts_only_scanned_packages_and_verified_signals() {
        use crate::changelog_fetch::{ChangelogResult, ChangelogStatus};
        use crate::update_analysis::SecurityFinding;
        let mut current = state();
        let updates: ScanResults = ["linux", "curl", "example"]
            .into_iter()
            .map(|name| {
                (
                    PackageUpdate {
                        name: name.into(),
                        installed: "1-1".into(),
                        available: "2-1".into(),
                    },
                    String::new(),
                )
            })
            .collect();
        // A system category alone is not evidence of a security issue.
        assert_eq!(priority_counts(&current, &updates), [0, 0, 0, 3]);
        let clean = || ChangelogResult {
            status: ChangelogStatus::NoSource,
            source_url: String::new(),
            summary: None,
            sources: vec![],
            security: SecurityFinding::Checked {
                fixed: vec![],
                remaining: vec![],
            },
        };
        current.changelogs.insert("curl".into(), clean());
        current
            .changelogs
            .insert("stale-not-in-scan".into(), clean());
        assert_eq!(priority_counts(&current, &updates), [0, 0, 1, 2]);
        current.changelogs.get_mut("curl").unwrap().security =
            SecurityFinding::Unavailable(ChangelogStatus::Timeout);
        assert_eq!(priority_counts(&current, &updates), [0, 0, 0, 3]);
    }

    #[test]
    fn approved_result_never_turns_disconnect_or_running_into_success() {
        use crate::transaction_protocol::TransactionOutcome;
        assert_eq!(
            result_kind(&Ok(TransactionOutcome::Success)),
            ResultKind::Success
        );
        assert_eq!(
            result_kind(&Ok(TransactionOutcome::Failure)),
            ResultKind::Failed
        );
        assert_eq!(
            result_kind(&Ok(TransactionOutcome::Cancelled)),
            ResultKind::Cancelled
        );
        assert_eq!(
            result_kind(&Ok(TransactionOutcome::Running)),
            ResultKind::Unknown
        );
        assert_eq!(
            result_kind(&Err("IPC disconnected".into())),
            ResultKind::Unknown
        );
        assert_eq!(
            result_kind(&Err("authorization denied".into())),
            ResultKind::Unknown
        );
    }
    #[test]
    fn execution_block_keeps_actual_reason_and_never_claims_commit() {
        for language in [Language::Polish, Language::English] {
            let reason = format!(
                "REAL MODE locked: missing {}",
                rwr_package_intelligence::supervisor_trust::SYSTEM_EXECUTION_POLICY
            );
            let message = execution_block_message(language, &reason);
            assert!(message.contains(&reason));
            assert!(message.contains("Polkit"));
        }
        assert!(
            execution_block_message(Language::English, "denied")
                .contains("installation was not started")
        );
    }
}

#[cfg(test)]
mod real_mode_label_tests {
    use super::*;

    /// Mirrors the bottom panel: SUPERVISOR label is prepended before REAL MODE.
    #[test]
    fn refresh_targets_real_mode_label_not_prepended_supervisor_label() {
        if gtk4::init().is_err() {
            eprintln!("SKIP: no display for GTK");
            return;
        }
        let bottom_panel = GtkBox::new(Orientation::Vertical, 9);
        let heading = GtkBox::new(Orientation::Horizontal, 8);
        let real_mode = Label::new(Some("REAL MODE · ZABLOKOWANY"));
        real_mode.set_widget_name(REAL_MODE_LABEL_NAME);
        let supervisor = Label::new(Some("SUPERVISOR · SPRAWDZANIE"));
        heading.prepend(&supervisor);
        heading.append(&real_mode);
        let actions = GtkBox::new(Orientation::Horizontal, 8);
        let install = Button::with_label("AKTUALIZUJ");
        actions.append(&install);
        bottom_panel.append(&heading);
        bottom_panel.append(&actions);

        // The old positional lookup picked the supervisor label.
        assert_eq!(
            heading.first_child().unwrap().widget_name(),
            supervisor.widget_name()
        );
        let found = real_mode_label(&install).expect("REAL MODE label");
        assert_eq!(found, real_mode);
        assert_ne!(found, supervisor);
    }

    #[test]
    fn production_layout_names_the_real_mode_label() {
        let source = include_str!("ui.rs");
        let creation = source
            .find("let test_label = Label::new(Some(\"REAL MODE · ZABLOKOWANY\"));")
            .unwrap();
        let naming = source
            .find("test_label.set_widget_name(REAL_MODE_LABEL_NAME);")
            .unwrap();
        assert!(naming > creation);
        assert!(source.contains("bottom_heading.append(&test_label);"));
    }
}

#[cfg(test)]
mod structured_plan_review_tests {
    use super::*;
    use rwr_package_intelligence::libalpm_ffi::{
        AlpmPlannedPackage, AlpmPreparedUpgrade, AlpmUpgradePackage,
    };

    fn inspect(
        widget: &gtk4::Widget,
        labels: &mut Vec<String>,
        expanders: &mut Vec<gtk4::Expander>,
    ) {
        if let Some(label) = widget.downcast_ref::<Label>() {
            labels.push(label.text().to_string());
        }
        if let Some(expander) = widget.downcast_ref::<gtk4::Expander>() {
            expanders.push(expander.clone());
        }
        let mut child = widget.first_child();
        while let Some(current) = child {
            inspect(&current, labels, expanders);
            child = current.next_sibling();
        }
    }

    #[test]
    fn shows_real_plan_fields_and_expandable_dependencies_in_both_languages() {
        gtk4::init().expect("GTK display for the isolated widget test");
        let details = AlpmPreparedUpgrade {
            add: vec![
                AlpmUpgradePackage {
                    name: "main-package".into(),
                    installed_version: Some("1:1.0-1".into()),
                    version: "1:2.0-1".into(),
                    repository: "core".into(),
                    arch: "x86_64".into(),
                    filename: "main-package-1:2.0-1-x86_64.pkg.tar.zst".into(),
                    signature: None,
                    provides: vec![],
                    conflicts: vec![],
                    replaces: vec![],
                    sha256: "a".repeat(64),
                    dependencies: vec!["helper-package>=2".into()],
                    dependency_added: false,
                },
                AlpmUpgradePackage {
                    name: "helper-package".into(),
                    installed_version: None,
                    version: "2-1".into(),
                    repository: "extra".into(),
                    arch: "any".into(),
                    filename: "helper-package-2-1-any.pkg.tar.zst".into(),
                    signature: None,
                    provides: vec![],
                    conflicts: vec![],
                    replaces: vec![],
                    sha256: "b".repeat(64),
                    dependencies: vec![],
                    dependency_added: true,
                },
            ],
            remove: vec![AlpmPlannedPackage {
                name: "conflicting-package".into(),
                version: "0.9-1".into(),
            }],
            decisions: vec![2, 4, 32],
        };
        let original = details.clone();
        for (language, total, summary, removes, repository, recheck) in [
            (
                Language::Polish,
                "pakiety: 3",
                "Aktualizacje: 1  ·  Instalacje: 1  ·  Usunięcia: 1",
                "PAKIETY DO USUNIĘCIA",
                "Repozytorium: core",
                "Zmiana unieważni zgodę",
            ),
            (
                Language::English,
                "3 packages",
                "Upgrades: 1  ·  Installs: 1  ·  Removals: 1",
                "PACKAGES TO REMOVE",
                "Repository: core",
                "A change invalidates consent",
            ),
        ] {
            let view = upgrade_plan_review(&details, language);
            let (mut labels, mut expanders) = (Vec::new(), Vec::new());
            inspect(view.upcast_ref(), &mut labels, &mut expanders);
            for value in [
                total,
                summary,
                removes,
                repository,
                recheck,
                "main-package",
                "1:1.0-1",
                "1:2.0-1",
                "conflicting-package",
                "0.9-1",
            ] {
                assert!(
                    labels.iter().any(|label| label.contains(value)),
                    "missing {value}"
                );
            }
            assert_eq!(expanders.len(), 2);
            assert!(!expanders[0].is_expanded());
            expanders[0].set_expanded(true);
            let body = expanders[0].child().unwrap().downcast::<Label>().unwrap();
            assert!(body.text().contains("helper-package>=2"));
            assert!(
                body.text()
                    .contains("main-package-1:2.0-1-x86_64.pkg.tar.zst")
            );
        }
        assert_eq!(details, original);
    }
}
