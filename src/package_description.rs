// RWR PACKAGE INTELLIGENCE — package description data quality (ETAP 4.10).
// Pure helpers used by the GTK view. Nothing here installs or changes packages.

use crate::intelligence::Language;
use std::process::Command;

/// Builds the read-only `pacman -Qi` query with a fixed C locale, so the
/// field labels ("Description") do not depend on the user's locale (N1).
pub fn description_command(name: &str) -> Command {
    let mut command = Command::new("pacman");
    command
        .env("LC_ALL", "C")
        .env("LANGUAGE", "C")
        .args(["-Qi", name]);
    command
}

/// Extracts the `Description` field from C-locale `pacman -Qi` output.
pub fn parse_pacman_description(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() != "Description" {
            return None;
        }
        let value = value.trim();
        (!value.is_empty() && value != "None").then(|| value.to_string())
    })
}

/// Package description from the Arch repository metadata (always English).
pub fn read_description(name: &str) -> String {
    match description_command(name).output() {
        Ok(out) if out.status.success() => {
            parse_pacman_description(&String::from_utf8_lossy(&out.stdout)).unwrap_or_default()
        }
        _ => String::new(),
    }
}

/// Repository descriptions are English-only; mark them in the Polish view (N4).
pub fn repository_description_text(language: Language, description: &str) -> String {
    match language {
        Language::Polish => format!("(opis z repozytorium Arch, EN) {description}"),
        Language::English => description.to_string(),
    }
}

/// Changelog summaries are copied verbatim from English upstream sources (N4).
pub fn source_summary_text(language: Language, summary: &str) -> String {
    match language {
        Language::Polish => format!("Streszczenie źródła (EN): {summary}"),
        Language::English => summary.to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpactHint {
    Library,
    Driver,
    Kernel,
    Generic,
}

/// Keyword heuristic on the English repository description (N6).
/// "librar" matches both "library" and "libraries".
pub fn impact_hint(description: &str) -> ImpactHint {
    let lower = description.to_lowercase();
    if lower.contains("librar") {
        ImpactHint::Library
    } else if lower.contains("driver") {
        ImpactHint::Driver
    } else if lower.contains("kernel") {
        ImpactHint::Kernel
    } else {
        ImpactHint::Generic
    }
}

pub fn impact_hint_text(language: Language, hint: ImpactHint) -> String {
    let (pl, en) = match hint {
        ImpactHint::Library => (
            "Biblioteka systemowa. Aktualizacja może wpływać na programy, które z niej korzystają.",
            "System library. Updating it may affect applications that depend on it.",
        ),
        ImpactHint::Driver => (
            "Sterownik. Aktualizacja może wpływać na obsługę sprzętu.",
            "Driver. Updating it may affect hardware support.",
        ),
        ImpactHint::Kernel => (
            "Komponent związany z jądrem systemu. Może wymagać ponownego uruchomienia.",
            "Kernel-related component. A restart may be necessary.",
        ),
        ImpactHint::Generic => (
            "Aktualizacja pakietu. Dokładny wpływ wymaga sprawdzenia changelogu.",
            "Package update. The exact impact requires checking the changelog.",
        ),
    };
    match language {
        Language::Polish => pl.to_string(),
        Language::English => en.to_string(),
    }
}

/// Factual note derived from the actual version change (N3), instead of
/// hard-coded per-package assumptions.
pub fn change_kind_note(language: Language, installed: &str, available: &str) -> Option<String> {
    use crate::changelog::{ChangeKind, detect_change};
    let (pl, en) = match detect_change(installed, available) {
        ChangeKind::PackageRevision => (
            "Zmiana dotyczy tylko rewizji pakietu Arch (ta sama wersja upstream).",
            "Only the Arch package revision changes (same upstream version).",
        ),
        ChangeKind::EpochChange => (
            "Zmiana epoki pakietu — sprawdź dokładnie historię wersji.",
            "Package epoch change — review the version history carefully.",
        ),
        _ => return None,
    };
    Some(match language {
        Language::Polish => pl.to_string(),
        Language::English => en.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_command_forces_c_locale() {
        let command = description_command("7zip");
        let envs: Vec<_> = command
            .get_envs()
            .map(|(k, v)| (k.to_owned(), v.map(|v| v.to_owned())))
            .collect();
        assert!(envs.contains(&("LC_ALL".into(), Some("C".into()))));
        assert_eq!(command.get_program(), "pacman");
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args, ["-Qi", "7zip"]);
    }

    #[test]
    fn parses_c_locale_description() {
        let output = "Name            : 7zip\nVersion         : 26.05-1\nDescription     : File archiver for extremely high compression\nArchitecture    : x86_64\n";
        assert_eq!(
            parse_pacman_description(output).as_deref(),
            Some("File archiver for extremely high compression")
        );
    }

    #[test]
    fn description_with_colon_is_kept_whole() {
        let output = "Description     : Tool: does things\n";
        assert_eq!(
            parse_pacman_description(output).as_deref(),
            Some("Tool: does things")
        );
    }

    #[test]
    fn localized_labels_are_not_misread() {
        // Regression for N1: without LC_ALL=C pacman prints localized labels.
        let polish = "Nazwa           : 7zip\nOpis            : File archiver\n";
        assert_eq!(parse_pacman_description(polish), None);
    }

    #[test]
    fn empty_description_is_none() {
        assert_eq!(parse_pacman_description("Description     : None\n"), None);
        assert_eq!(parse_pacman_description(""), None);
    }

    #[test]
    fn polish_view_marks_english_repository_description() {
        assert_eq!(
            repository_description_text(Language::Polish, "File archiver"),
            "(opis z repozytorium Arch, EN) File archiver"
        );
        assert_eq!(
            repository_description_text(Language::English, "File archiver"),
            "File archiver"
        );
    }

    #[test]
    fn polish_view_marks_english_source_summary() {
        assert_eq!(
            source_summary_text(Language::Polish, "Fixed crash."),
            "Streszczenie źródła (EN): Fixed crash."
        );
        assert_eq!(
            source_summary_text(Language::English, "Fixed crash."),
            "Fixed crash."
        );
    }

    #[test]
    fn plural_libraries_are_detected() {
        assert_eq!(
            impact_hint("Shared libraries for image decoding"),
            ImpactHint::Library
        );
        assert_eq!(impact_hint("XML parsing library"), ImpactHint::Library);
    }

    #[test]
    fn other_hints() {
        assert_eq!(impact_hint("Open-source Vulkan driver"), ImpactHint::Driver);
        assert_eq!(impact_hint("Kernel headers"), ImpactHint::Kernel);
        assert_eq!(
            impact_hint("File archiver for extremely high compression"),
            ImpactHint::Generic
        );
        assert_eq!(impact_hint(""), ImpactHint::Generic);
    }

    #[test]
    fn change_note_follows_actual_change_kind() {
        assert!(change_kind_note(Language::Polish, "1:0.41.0-6", "1:0.41.0-7").is_some());
        assert!(change_kind_note(Language::English, "1:2.0-1", "2:2.0-1").is_some());
        // Upstream update must not be described as a mere revision.
        assert_eq!(
            change_kind_note(Language::Polish, "1:0.41.0-7", "1:0.42.0-1"),
            None
        );
        assert_eq!(change_kind_note(Language::Polish, "invalid", "2.0-1"), None);
    }
}
