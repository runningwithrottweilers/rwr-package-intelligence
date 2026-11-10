// RWR PACKAGE INTELLIGENCE
// Real upgrade output classification.
// No commands are executed by this module.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeEvent {
    Synchronizing,
    ResolvingDependencies,
    CheckingConflicts,
    Downloading,
    Installing,
    Upgrading,
    CheckingKeys,
    RunningHooks,
    Warning(String),
    Error(String),
    Output(String),
}

pub fn classify_line(line: &str) -> UpgradeEvent {
    let text = line.trim();
    let lower = text.to_lowercase();

    if lower.starts_with("error:") || lower.starts_with("błąd:") {
        return UpgradeEvent::Error(text.to_string());
    }

    if lower.starts_with("warning:") || lower.starts_with("ostrzeżenie:") {
        return UpgradeEvent::Warning(text.to_string());
    }

    if lower.contains("synchronizing package databases")
        || lower.contains("synchronizowanie baz danych")
    {
        return UpgradeEvent::Synchronizing;
    }

    if lower.contains("resolving dependencies") || lower.contains("rozwiązywanie zależności") {
        return UpgradeEvent::ResolvingDependencies;
    }

    if lower.contains("looking for conflicting packages")
        || lower.contains("wyszukiwanie konfliktujących pakietów")
    {
        return UpgradeEvent::CheckingConflicts;
    }

    if lower.contains("retrieving packages") || lower.contains("pobieranie pakietów") {
        return UpgradeEvent::Downloading;
    }

    if lower.contains("upgrading ") || lower.contains("aktualizowanie ") {
        return UpgradeEvent::Upgrading;
    }

    if lower.contains("installing ") || lower.contains("instalowanie ") {
        return UpgradeEvent::Installing;
    }

    if lower.contains("checking keys in keyring") || lower.contains("sprawdzanie kluczy") {
        return UpgradeEvent::CheckingKeys;
    }

    if lower.contains("running post-transaction hooks")
        || lower.contains("uruchamianie skryptów po transakcji")
    {
        return UpgradeEvent::RunningHooks;
    }

    UpgradeEvent::Output(text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sync() {
        assert_eq!(
            classify_line(":: Synchronizing package databases..."),
            UpgradeEvent::Synchronizing
        );
    }

    #[test]
    fn detects_dependencies() {
        assert_eq!(
            classify_line("resolving dependencies..."),
            UpgradeEvent::ResolvingDependencies
        );
    }

    #[test]
    fn detects_upgrade() {
        assert_eq!(
            classify_line("(1/3) upgrading linux"),
            UpgradeEvent::Upgrading
        );
    }

    #[test]
    fn detects_error() {
        assert_eq!(
            classify_line("error: failed to commit transaction"),
            UpgradeEvent::Error("error: failed to commit transaction".into())
        );
    }

    #[test]
    fn detects_conflicts() {
        assert_eq!(
            classify_line("looking for conflicting packages..."),
            UpgradeEvent::CheckingConflicts
        );
    }

    #[test]
    fn detects_download_phase() {
        assert_eq!(
            classify_line(":: Retrieving packages..."),
            UpgradeEvent::Downloading
        );
    }

    #[test]
    fn detects_installation() {
        assert_eq!(
            classify_line("(2/5) installing example-package"),
            UpgradeEvent::Installing
        );
    }

    #[test]
    fn detects_hooks() {
        assert_eq!(
            classify_line(":: Running post-transaction hooks..."),
            UpgradeEvent::RunningHooks
        );
    }

    #[test]
    fn detects_warning() {
        assert_eq!(
            classify_line("warning: example warning"),
            UpgradeEvent::Warning("warning: example warning".into())
        );
    }

    #[test]
    fn detects_polish_error() {
        assert_eq!(
            classify_line("błąd: przykładowy błąd"),
            UpgradeEvent::Error("błąd: przykładowy błąd".into())
        );
    }

    #[test]
    fn does_not_invent_progress() {
        assert_eq!(
            classify_line("unknown pacman output"),
            UpgradeEvent::Output("unknown pacman output".into())
        );
    }
}
