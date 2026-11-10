// RWR PACKAGE INTELLIGENCE — update card signals (ETAP 4.13).
//
// Derives the priority, badges and human-readable source link of an update
// card ONLY from confirmed analysis results:
// * security priority requires an Arch Security Tracker advisory;
// * "breaking change" requires an entry categorised as breaking in a verified
//   source (the source's own heading or a `!` conventional-commit marker);
// * package names, version jumps or missing data never raise an alarm.

use crate::change_items::ChangeCategory;
use crate::changelog_fetch::{ChangelogResult, ChangelogStatus};
use crate::changelog_sources::{
    ARCH_GITLAB_PREFIX, ARCH_GITLAB_SUFFIX, GITHUB_API_PREFIX, UPSTREAM_SOURCES,
    arch_gitlab_project_is_identity,
};
use crate::intelligence::Language;
use crate::update_analysis::{SecurityFinding, SourceReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// The tracker confirms the update fixes a vulnerability.
    Security,
    /// A verified source reports a breaking change, or the tracker lists a
    /// vulnerability that remains after the update.
    Review,
    /// Confirmed data was checked and contains no such signal.
    Routine,
    /// No confirmed data (sources unavailable or not configured).
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Badge {
    SecurityFix(usize),
    StillVulnerable(usize),
    Breaking,
}

fn verified_sources(result: &ChangelogResult) -> impl Iterator<Item = &SourceReport> {
    result.sources.iter().filter(|s| s.status.is_verified())
}

pub fn badges(result: &ChangelogResult) -> Vec<Badge> {
    let mut badges = Vec::new();
    if let SecurityFinding::Checked { fixed, remaining } = &result.security {
        if !fixed.is_empty() {
            badges.push(Badge::SecurityFix(fixed.len()));
        }
        if !remaining.is_empty() {
            badges.push(Badge::StillVulnerable(remaining.len()));
        }
    }
    if verified_sources(result).any(|s| {
        s.items
            .iter()
            .any(|item| item.category == ChangeCategory::Breaking)
    }) {
        badges.push(Badge::Breaking);
    }
    badges
}

/// The source could not be read (as opposed to having no description).
fn fetch_failed(status: ChangelogStatus) -> bool {
    matches!(
        status,
        ChangelogStatus::Timeout
            | ChangelogStatus::NetworkError
            | ChangelogStatus::RateLimited
            | ChangelogStatus::InvalidResponse
    )
}

pub fn priority(result: &ChangelogResult) -> Priority {
    let badges = badges(result);
    if badges.iter().any(|b| matches!(b, Badge::SecurityFix(_))) {
        Priority::Security
    } else if !badges.is_empty() {
        Priority::Review
    } else if matches!(result.security, SecurityFinding::Checked { .. })
        && !result.sources.iter().any(|s| fetch_failed(s.status))
    {
        // Routine only after a complete check: the tracker answered and no
        // source failed (a failed source could hide a breaking change).
        Priority::Routine
    } else {
        Priority::Unknown
    }
}

fn tr(language: Language, pl: &str, en: &str) -> String {
    match language {
        Language::Polish => pl.to_string(),
        Language::English => en.to_string(),
    }
}

pub fn badge_text(badge: Badge, language: Language) -> String {
    match (badge, language) {
        (Badge::SecurityFix(n), Language::Polish) => format!("POPRAWKA BEZPIECZEŃSTWA ({n})"),
        (Badge::SecurityFix(n), Language::English) => format!("SECURITY FIX ({n})"),
        (Badge::StillVulnerable(n), Language::Polish) => format!("NADAL PODATNY ({n})"),
        (Badge::StillVulnerable(n), Language::English) => format!("STILL VULNERABLE ({n})"),
        (Badge::Breaking, _) => tr(language, "ZMIANA NIEZGODNA", "BREAKING CHANGE"),
    }
}

/// Tooltip naming the evidence behind a badge.
pub fn badge_tooltip(badge: Badge, language: Language) -> String {
    match badge {
        Badge::SecurityFix(_) => tr(
            language,
            "Potwierdzone przez Arch Security Tracker: ta aktualizacja usuwa znaną podatność.",
            "Confirmed by Arch Security Tracker: this update fixes a known vulnerability.",
        ),
        Badge::StillVulnerable(_) => tr(
            language,
            "Arch Security Tracker: podatność nie jest usunięta w dostępnej wersji.",
            "Arch Security Tracker: the vulnerability is not fixed in the available version.",
        ),
        Badge::Breaking => tr(
            language,
            "Zweryfikowane źródło oznacza zmianę jako niezgodną wstecz. Sprawdź konfigurację po aktualizacji.",
            "A verified source marks a backward-incompatible change. Check your configuration after updating.",
        ),
    }
}

/// CSS class of a badge (defined in assets/style.css).
pub fn badge_css_class(badge: Badge) -> &'static str {
    match badge {
        Badge::SecurityFix(_) | Badge::StillVulnerable(_) => "package-security",
        Badge::Breaking => "package-review",
    }
}

pub fn priority_text(priority: Priority, language: Language) -> String {
    let (pl, en) = match priority {
        Priority::Security => (
            "WYSOKI — potwierdzona poprawka bezpieczeństwa",
            "HIGH — confirmed security fix",
        ),
        Priority::Review => (
            "SPRAWDŹ PRZED INSTALACJĄ — sygnał w potwierdzonym źródle",
            "REVIEW BEFORE INSTALLING — signal in a confirmed source",
        ),
        Priority::Routine => (
            "ZWYKŁY — potwierdzone źródła nie wskazują zmian wymagających uwagi",
            "ROUTINE — confirmed sources show no changes needing attention",
        ),
        Priority::Unknown => (
            "NIEUSTALONY — sprawdzenie niepełne lub brak potwierdzonych danych",
            "UNDETERMINED — incomplete check or no confirmed data",
        ),
    };
    tr(language, pl, en)
}

// ---------------------------------------------------------------------------
// Human-readable source pages (the API URLs return JSON).

pub const GITHUB_WEB_PREFIX: &str = "https://github.com/";
pub const ARCH_GITLAB_WEB_PREFIX: &str =
    "https://gitlab.archlinux.org/archlinux/packaging/packages/";
pub const ARCH_GITLAB_WEB_SUFFIX: &str = "/-/commits/main";

/// Browser page for an API source URL, built only from validated parts.
pub fn browser_url_for(api_url: &str) -> Option<String> {
    if !crate::changelog_fetch::trusted_source_url(api_url) {
        return None;
    }
    if let Some(rest) = api_url.strip_prefix(ARCH_GITLAB_PREFIX) {
        let pkgbase = rest.strip_suffix(ARCH_GITLAB_SUFFIX)?;
        return Some(format!(
            "{ARCH_GITLAB_WEB_PREFIX}{pkgbase}{ARCH_GITLAB_WEB_SUFFIX}"
        ));
    }
    let rest = api_url.strip_prefix(GITHUB_API_PREFIX)?;
    UPSTREAM_SOURCES.iter().find_map(|source| {
        let tag = rest
            .strip_prefix(source.repository)?
            .strip_prefix("/releases/tags/")?;
        Some(format!(
            "{GITHUB_WEB_PREFIX}{}/releases/tag/{tag}",
            source.repository
        ))
    })
}

/// Strict check before handing a URL to the desktop browser.
pub fn trusted_browser_url(url: &str) -> bool {
    if url.len() > 512 || url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    if let Some(rest) = url.strip_prefix(ARCH_GITLAB_WEB_PREFIX) {
        return rest
            .strip_suffix(ARCH_GITLAB_WEB_SUFFIX)
            .is_some_and(arch_gitlab_project_is_identity);
    }
    if let Some(rest) = url.strip_prefix(GITHUB_WEB_PREFIX) {
        return UPSTREAM_SOURCES.iter().any(|source| {
            rest.strip_prefix(source.repository)
                .and_then(|tail| tail.strip_prefix("/releases/tag/"))
                .is_some_and(|tag| source.tags.accepts_tag(tag))
        });
    }
    false
}

/// Page to open for the card's "open source" button: the primary verified
/// source, otherwise the first source with a known page.
pub fn source_page(result: &ChangelogResult) -> Option<String> {
    let mut ordered: Vec<&SourceReport> = verified_sources(result).collect();
    ordered.extend(result.sources.iter().filter(|s| !s.status.is_verified()));
    ordered
        .into_iter()
        .filter_map(|source| browser_url_for(&source.url))
        .find(|url| trusted_browser_url(url))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change_items::ChangeItem;
    use crate::changelog_sources::SourceKind;
    use crate::update_analysis::Advisory;

    const HYPR_TAG: &str = "https://api.github.com/repos/hyprwm/Hyprland/releases/tags/v0.57.1";
    const NM_ARCH: &str = "https://gitlab.archlinux.org/api/v4/projects/archlinux%2Fpackaging%2Fpackages%2Fnetworkmanager/repository/commits?per_page=20";

    fn source(
        kind: SourceKind,
        status: ChangelogStatus,
        url: &str,
        items: Vec<ChangeItem>,
    ) -> SourceReport {
        SourceReport {
            kind,
            status,
            url: url.to_string(),
            versions: Vec::new(),
            items,
            partial: false,
        }
    }

    fn item(category: ChangeCategory) -> ChangeItem {
        ChangeItem {
            category,
            text: "entry".into(),
        }
    }

    fn advisory(id: &str) -> Advisory {
        Advisory {
            id: id.into(),
            severity: "High".into(),
            kind: "arbitrary code execution".into(),
            issues: vec!["CVE-2026-0001".into()],
            fixed: Some("2.0-1".into()),
        }
    }

    fn result(sources: Vec<SourceReport>, security: SecurityFinding) -> ChangelogResult {
        ChangelogResult {
            status: sources
                .first()
                .map_or(ChangelogStatus::NoSource, |s| s.status),
            source_url: String::new(),
            summary: None,
            sources,
            security,
        }
    }

    fn clean() -> SecurityFinding {
        SecurityFinding::Checked {
            fixed: Vec::new(),
            remaining: Vec::new(),
        }
    }

    #[test]
    fn security_fix_requires_tracker_advisory() {
        let r = result(
            Vec::new(),
            SecurityFinding::Checked {
                fixed: vec![advisory("AVG-1")],
                remaining: Vec::new(),
            },
        );
        assert_eq!(badges(&r), vec![Badge::SecurityFix(1)]);
        assert_eq!(priority(&r), Priority::Security);
    }

    #[test]
    fn security_keyword_in_changelog_is_not_an_alarm() {
        // A "security" entry in release notes is shown in the text, but only
        // the tracker can confirm a fixed vulnerability.
        let r = result(
            vec![source(
                SourceKind::GitHubRelease,
                ChangelogStatus::ReleaseNotes,
                HYPR_TAG,
                vec![item(ChangeCategory::Security)],
            )],
            clean(),
        );
        assert!(badges(&r).is_empty());
        assert_eq!(priority(&r), Priority::Routine);
    }

    #[test]
    fn breaking_change_from_verified_source_needs_review() {
        let r = result(
            vec![source(
                SourceKind::GitHubRelease,
                ChangelogStatus::ReleaseNotes,
                HYPR_TAG,
                vec![item(ChangeCategory::BugFix), item(ChangeCategory::Breaking)],
            )],
            SecurityFinding::Unavailable(ChangelogStatus::Timeout),
        );
        assert_eq!(badges(&r), vec![Badge::Breaking]);
        assert_eq!(priority(&r), Priority::Review);
    }

    #[test]
    fn remaining_vulnerability_needs_review() {
        let r = result(
            Vec::new(),
            SecurityFinding::Checked {
                fixed: Vec::new(),
                remaining: vec![advisory("AVG-2"), advisory("AVG-3")],
            },
        );
        assert_eq!(badges(&r), vec![Badge::StillVulnerable(2)]);
        assert_eq!(priority(&r), Priority::Review);
    }

    #[test]
    fn missing_data_is_unknown_not_alarm() {
        for status in [
            ChangelogStatus::Timeout,
            ChangelogStatus::NetworkError,
            ChangelogStatus::RateLimited,
            ChangelogStatus::NotFound,
        ] {
            let r = result(
                vec![source(
                    SourceKind::GitHubRelease,
                    status,
                    HYPR_TAG,
                    Vec::new(),
                )],
                SecurityFinding::Unavailable(status),
            );
            assert!(badges(&r).is_empty());
            assert_eq!(priority(&r), Priority::Unknown);
        }
        assert_eq!(
            priority(&result(Vec::new(), SecurityFinding::NotChecked)),
            Priority::Unknown
        );
    }

    #[test]
    fn incomplete_checks_are_never_routine() {
        // Verified changelog, but the tracker was not reachable: security unknown.
        let tracker_down = result(
            vec![source(
                SourceKind::ArchPackagingHistory,
                ChangelogStatus::PackagingHistory,
                NM_ARCH,
                vec![item(ChangeCategory::BugFix)],
            )],
            SecurityFinding::Unavailable(ChangelogStatus::Timeout),
        );
        assert_eq!(priority(&tracker_down), Priority::Unknown);
        // Upstream releases refused (rate limit): a breaking change could be missed.
        let upstream_failed = result(
            vec![
                source(
                    SourceKind::GitHubRelease,
                    ChangelogStatus::RateLimited,
                    HYPR_TAG,
                    Vec::new(),
                ),
                source(
                    SourceKind::ArchPackagingHistory,
                    ChangelogStatus::PackagingHistory,
                    NM_ARCH,
                    Vec::new(),
                ),
            ],
            clean(),
        );
        assert_eq!(priority(&upstream_failed), Priority::Unknown);
        // A source that simply has no description of this version is not a failure.
        let no_description = result(
            vec![source(
                SourceKind::ArchPackagingHistory,
                ChangelogStatus::NoChangelog,
                NM_ARCH,
                Vec::new(),
            )],
            clean(),
        );
        assert_eq!(priority(&no_description), Priority::Routine);
    }

    #[test]
    fn clean_tracker_without_changelog_is_routine() {
        assert_eq!(priority(&result(Vec::new(), clean())), Priority::Routine);
    }

    #[test]
    fn texts_exist_in_both_languages() {
        for badge in [
            Badge::SecurityFix(1),
            Badge::StillVulnerable(1),
            Badge::Breaking,
        ] {
            let pl = badge_text(badge, Language::Polish);
            let en = badge_text(badge, Language::English);
            assert!(!pl.is_empty() && !en.is_empty());
            assert_ne!(
                badge_tooltip(badge, Language::Polish),
                badge_tooltip(badge, Language::English)
            );
        }
        for p in [
            Priority::Security,
            Priority::Review,
            Priority::Routine,
            Priority::Unknown,
        ] {
            assert_ne!(
                priority_text(p, Language::Polish),
                priority_text(p, Language::English)
            );
        }
        assert_eq!(
            badge_text(Badge::SecurityFix(2), Language::Polish),
            "POPRAWKA BEZPIECZEŃSTWA (2)"
        );
    }

    #[test]
    fn browser_urls_for_trusted_sources() {
        assert_eq!(
            browser_url_for(HYPR_TAG).as_deref(),
            Some("https://github.com/hyprwm/Hyprland/releases/tag/v0.57.1")
        );
        assert_eq!(
            browser_url_for(NM_ARCH).as_deref(),
            Some(
                "https://gitlab.archlinux.org/archlinux/packaging/packages/networkmanager/-/commits/main"
            )
        );
        // List endpoint and tracker JSON have no single page.
        assert_eq!(
            browser_url_for("https://api.github.com/repos/hyprwm/Hyprland/releases?per_page=20"),
            None
        );
        assert_eq!(
            browser_url_for(crate::changelog_sources::SECURITY_TRACKER_URL),
            None
        );
        // Untrusted API URLs never produce a page.
        assert_eq!(
            browser_url_for("https://api.github.com/repos/evil/repo/releases/tags/v1.0"),
            None
        );
    }

    #[test]
    fn browser_url_validation_is_strict() {
        for good in [
            "https://github.com/hyprwm/Hyprland/releases/tag/v0.57.1",
            "https://github.com/libexpat/libexpat/releases/tag/R_2_7_3",
            "https://gitlab.archlinux.org/archlinux/packaging/packages/mesa/-/commits/main",
        ] {
            assert!(trusted_browser_url(good), "{good}");
        }
        for bad in [
            "http://github.com/hyprwm/Hyprland/releases/tag/v0.57.1",
            "https://github.com/evil/Hyprland/releases/tag/v0.57.1",
            "https://github.com/hyprwm/Hyprland/releases/tag/nightly",
            "https://github.com/hyprwm/Hyprland/releases/tag/v0.57.1?x=1",
            "https://github.com/hyprwm/Hyprland/releases/tag/v0.57.1/../../evil",
            "https://github.com.evil.example/hyprwm/Hyprland/releases/tag/v0.57.1",
            "https://gitlab.archlinux.org/archlinux/packaging/packages/tree/-/commits/main",
            "https://gitlab.archlinux.org/archlinux/packaging/packages/a/b/-/commits/main",
            "https://gitlab.archlinux.org/archlinux/packaging/packages/mesa/-/commits/main#x",
            "https://gitlab.archlinux.org/archlinux/packaging/packages/mesa/-/commits/main ",
            "file:///etc/passwd",
            "",
        ] {
            assert!(!trusted_browser_url(bad), "{bad}");
        }
    }

    #[test]
    fn source_page_prefers_verified_source() {
        let r = result(
            vec![
                source(
                    SourceKind::GitHubRelease,
                    ChangelogStatus::RateLimited,
                    HYPR_TAG,
                    Vec::new(),
                ),
                source(
                    SourceKind::ArchPackagingHistory,
                    ChangelogStatus::PackagingHistory,
                    NM_ARCH,
                    Vec::new(),
                ),
            ],
            clean(),
        );
        assert_eq!(
            source_page(&r).as_deref(),
            Some(
                "https://gitlab.archlinux.org/archlinux/packaging/packages/networkmanager/-/commits/main"
            )
        );
        assert_eq!(source_page(&result(Vec::new(), clean())), None);
    }
}
