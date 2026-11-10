// RWR PACKAGE INTELLIGENCE — changelog source planning (ETAP 4.11).
//
// Rules:
// * Upstream updates (new pkgver) use only curated upstream release sources.
//   Without a curated source there is no plan: nothing is guessed.
// * Arch-only updates (pkgrel or epoch change) use the Arch packaging
//   history of the package's *pkgbase* (split packages share one repository).
// * Every URL produced here must pass `changelog_fetch::trusted_source_url`.

use crate::changelog::{detect_change, upstream_version, valid_version};
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    GitHubRelease,
    ArchPackagingHistory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePlan {
    pub kind: SourceKind,
    pub url: String,
    pub target_version: String,
    /// Arch pkgbase the plan was built for (equals pkgname for non-split packages).
    pub pkgbase: String,
}

/// Tag naming scheme of an upstream GitHub repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagFormat {
    /// `v` + pkgver, e.g. `v0.57.1`.
    VPrefix,
    /// pkgver as-is, e.g. `0.15.0`.
    Plain,
    /// libexpat: `R_` + pkgver with dots replaced by underscores.
    ExpatUnderscore,
}

impl TagFormat {
    pub fn tag_for(self, pkgver: &str) -> String {
        match self {
            Self::VPrefix => format!("v{pkgver}"),
            Self::Plain => pkgver.to_string(),
            Self::ExpatUnderscore => format!("R_{}", pkgver.replace('.', "_")),
        }
    }

    /// Inverse of `tag_for`: the pkgver a release tag stands for, if the tag
    /// follows this repository's scheme.
    pub fn version_from_tag(self, tag: &str) -> Option<String> {
        if !self.accepts_tag(tag) {
            return None;
        }
        match self {
            Self::VPrefix => tag.strip_prefix('v').map(str::to_string),
            Self::Plain => Some(tag.to_string()),
            Self::ExpatUnderscore => tag.strip_prefix("R_").map(|v| v.replace('_', ".")),
        }
    }

    /// Strict shape check used by the URL allowlist.
    pub fn accepts_tag(self, tag: &str) -> bool {
        let body = match self {
            Self::VPrefix => tag.strip_prefix('v'),
            Self::Plain => Some(tag),
            Self::ExpatUnderscore => tag.strip_prefix("R_"),
        };
        let Some(body) = body else {
            return false;
        };
        let allowed = |c: char| match self {
            Self::ExpatUnderscore => c.is_ascii_digit() || c == '_',
            _ => c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+'),
        };
        !body.is_empty()
            && tag.len() <= 128
            && body.starts_with(|c: char| c.is_ascii_digit())
            && body.chars().all(allowed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamSource {
    /// Arch pkgbase this source describes.
    pub pkgbase: &'static str,
    /// GitHub `owner/repo`.
    pub repository: &'static str,
    pub tags: TagFormat,
}

/// Curated upstream release sources, keyed by Arch pkgbase. Each entry is a
/// project that publishes GitHub releases whose tag maps 1:1 to Arch pkgver.
pub const UPSTREAM_SOURCES: &[UpstreamSource] = &[
    UpstreamSource {
        pkgbase: "hyprland",
        repository: "hyprwm/Hyprland",
        tags: TagFormat::VPrefix,
    },
    UpstreamSource {
        pkgbase: "expat",
        repository: "libexpat/libexpat",
        tags: TagFormat::ExpatUnderscore,
    },
    UpstreamSource {
        pkgbase: "xdg-desktop-portal-hyprland",
        repository: "hyprwm/xdg-desktop-portal-hyprland",
        tags: TagFormat::VPrefix,
    },
    UpstreamSource {
        pkgbase: "hyprlock",
        repository: "hyprwm/hyprlock",
        tags: TagFormat::VPrefix,
    },
    UpstreamSource {
        pkgbase: "hypridle",
        repository: "hyprwm/hypridle",
        tags: TagFormat::VPrefix,
    },
    UpstreamSource {
        pkgbase: "hyprpaper",
        repository: "hyprwm/hyprpaper",
        tags: TagFormat::VPrefix,
    },
    UpstreamSource {
        pkgbase: "mpv",
        repository: "mpv-player/mpv",
        tags: TagFormat::VPrefix,
    },
    UpstreamSource {
        pkgbase: "neovim",
        repository: "neovim/neovim",
        tags: TagFormat::VPrefix,
    },
    UpstreamSource {
        pkgbase: "waybar",
        repository: "Alexays/Waybar",
        tags: TagFormat::Plain,
    },
    UpstreamSource {
        pkgbase: "yt-dlp",
        repository: "yt-dlp/yt-dlp",
        tags: TagFormat::Plain,
    },
    UpstreamSource {
        pkgbase: "fastfetch",
        repository: "fastfetch-cli/fastfetch",
        tags: TagFormat::Plain,
    },
    UpstreamSource {
        pkgbase: "python-platformdirs",
        repository: "tox-dev/platformdirs",
        tags: TagFormat::Plain,
    },
];

pub fn upstream_source(pkgbase: &str) -> Option<&'static UpstreamSource> {
    UPSTREAM_SOURCES.iter().find(|s| s.pkgbase == pkgbase)
}

pub const GITHUB_API_PREFIX: &str = "https://api.github.com/repos/";
/// Release list endpoint (newest first); used to cover every release between
/// the installed and the available version.
pub const GITHUB_RELEASE_LIST_SUFFIX: &str = "/releases?per_page=20";
/// Arch Security Tracker: all advisory groups (AVG) with affected/fixed versions.
/// Canonical location (`/all.json` answers with a 308 redirect to it).
pub const SECURITY_TRACKER_URL: &str = "https://security.archlinux.org/issues/all.json";
pub const ARCH_GITLAB_PREFIX: &str =
    "https://gitlab.archlinux.org/api/v4/projects/archlinux%2Fpackaging%2Fpackages%2F";
pub const ARCH_GITLAB_SUFFIX: &str = "/repository/commits?per_page=20";

/// Arch package name rules (shared by source planning and history parsing):
/// lowercase ASCII alphanumerics and `@ . _ + -`, not starting with `-` or `.`.
pub fn valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('-')
        && !name.starts_with('.')
        && name.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '@' | '.' | '_' | '+' | '-')
        })
}

/// True when the Arch GitLab project path equals the pkgbase unchanged.
/// Arch rewrites some names (`+` → `plus`, `tree` → `unix-tree`, ...);
/// such pkgbases get no source instead of a guessed project path.
pub fn arch_gitlab_project_is_identity(pkgbase: &str) -> bool {
    valid_package_name(pkgbase)
        && pkgbase.len() <= 100
        && pkgbase.starts_with(|c: char| c.is_ascii_alphanumeric())
        && pkgbase.ends_with(|c: char| c.is_ascii_alphanumeric())
        && !pkgbase.contains(['+', '@'])
        && !pkgbase.contains("..")
        && !pkgbase.contains("--")
        && !pkgbase.contains("__")
        && !pkgbase.ends_with(".git")
        && !pkgbase.ends_with(".atom")
        && pkgbase != "tree"
}

pub fn arch_history_url(pkgbase: &str) -> Option<String> {
    arch_gitlab_project_is_identity(pkgbase)
        .then(|| format!("{ARCH_GITLAB_PREFIX}{pkgbase}{ARCH_GITLAB_SUFFIX}"))
}

pub fn github_release_url(source: &UpstreamSource, pkgver: &str) -> Option<String> {
    let tag = source.tags.tag_for(pkgver);
    source.tags.accepts_tag(&tag).then(|| {
        format!(
            "{GITHUB_API_PREFIX}{}/releases/tags/{tag}",
            source.repository
        )
    })
}

pub fn github_release_list_url(source: &UpstreamSource) -> String {
    format!(
        "{GITHUB_API_PREFIX}{}{GITHUB_RELEASE_LIST_SUFFIX}",
        source.repository
    )
}

// ---------------------------------------------------------------------------
// pkgname → pkgbase from the local package database (read-only file access).

pub const LOCAL_DB: &str = "/var/lib/pacman/local";
const MAX_DESC_BYTES: u64 = 256 * 1024;

/// Reads `%BASE%` from a local `desc` file. `%NAME%` must match `name`.
/// A missing `%BASE%` means the package is not split (pkgbase = pkgname).
pub fn parse_local_desc_base(content: &str, name: &str) -> Option<String> {
    let mut lines = content.lines();
    let mut found_name = None;
    let mut found_base = None;
    while let Some(line) = lines.next() {
        match line.trim() {
            "%NAME%" => found_name = lines.next().map(str::trim),
            "%BASE%" => found_base = lines.next().map(str::trim),
            _ => {}
        }
    }
    if found_name != Some(name) {
        return None;
    }
    let base = found_base.unwrap_or(name);
    valid_package_name(base).then(|| base.to_string())
}

/// Resolves pkgbase for an installed package version. Returns `None` when the
/// database entry cannot be read or does not match — never a guess.
fn read_desc_base(entry: &Path, name: &str) -> Option<String> {
    let file = std::fs::File::open(entry.join("desc")).ok()?;
    let mut content = String::new();
    file.take(MAX_DESC_BYTES)
        .read_to_string(&mut content)
        .ok()?;
    parse_local_desc_base(&content, name)
}

/// Resolves pkgbase for an installed package. Uses the exact
/// `<name>-<installed>` entry; if that is absent (e.g. the database changed
/// since the scan), the single other entry whose `%NAME%` is exactly `name`.
/// Returns `None` when nothing matches — never a guess.
pub fn resolve_pkgbase_in(db_root: &Path, name: &str, installed: &str) -> Option<String> {
    if !valid_package_name(name) || !valid_version(installed) {
        return None;
    }
    if let Some(base) = read_desc_base(&db_root.join(format!("{name}-{installed}")), name) {
        return Some(base);
    }
    let prefix = format!("{name}-");
    let mut found: Option<String> = None;
    for entry in std::fs::read_dir(db_root).ok()?.flatten() {
        let file_name = entry.file_name();
        let Some(version) = file_name.to_str().and_then(|f| f.strip_prefix(&prefix)) else {
            continue;
        };
        if !valid_version(version) {
            continue;
        }
        // `%NAME%` must equal `name`: "foo-bar-1.0-1" is not package "foo".
        if let Some(base) = read_desc_base(&entry.path(), name) {
            if found.as_ref().is_some_and(|other| other != &base) {
                return None;
            }
            found = Some(base);
        }
    }
    found
}

pub fn resolve_pkgbase(name: &str, installed: &str) -> Option<String> {
    resolve_pkgbase_in(Path::new(LOCAL_DB), name, installed)
}

// ---------------------------------------------------------------------------

/// Pure planning step with an already resolved pkgbase.
pub fn source_for_base(
    name: &str,
    pkgbase: &str,
    installed: &str,
    available: &str,
) -> Option<SourcePlan> {
    if !valid_package_name(name) || !valid_package_name(pkgbase) {
        return None;
    }
    if !valid_version(installed) || !valid_version(available) {
        return None;
    }

    let change = detect_change(installed, available);
    let target = upstream_version(available)?;

    // Upstream change: only a curated upstream release source explains it.
    // Arch-only change (pkgrel/epoch): the pkgbase packaging history does.
    // Unchanged/unknown versions get no source.
    let (kind, url) = if change.is_upstream() {
        let source = upstream_source(pkgbase)?;
        (
            SourceKind::GitHubRelease,
            github_release_url(source, target)?,
        )
    } else if change.is_arch_packaging() {
        (SourceKind::ArchPackagingHistory, arch_history_url(pkgbase)?)
    } else {
        return None;
    };

    Some(SourcePlan {
        kind,
        url,
        target_version: available.to_string(),
        pkgbase: pkgbase.to_string(),
    })
}

/// All trusted sources relevant to an update, primary first:
/// * upstream change: curated upstream releases (if any), then the Arch
///   packaging history (packaging changes made alongside the new version);
/// * Arch-only change: the Arch packaging history.
pub fn plan_sources(
    name: &str,
    pkgbase: &str,
    installed: &str,
    available: &str,
) -> Vec<SourcePlan> {
    let mut plans = Vec::new();
    if let Some(primary) = source_for_base(name, pkgbase, installed, available) {
        plans.push(primary);
    }
    let change = detect_change(installed, available);
    if change.is_upstream() && valid_version(available) {
        if let Some(url) = arch_history_url(pkgbase) {
            if plans.iter().all(|plan| plan.url != url) {
                plans.push(SourcePlan {
                    kind: SourceKind::ArchPackagingHistory,
                    url,
                    target_version: available.to_string(),
                    pkgbase: pkgbase.to_string(),
                });
            }
        }
    }
    plans
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hyprland_release() {
        let plan = source_for_base("hyprland", "hyprland", "0.57.0-3", "0.57.1-1").unwrap();
        assert_eq!(plan.kind, SourceKind::GitHubRelease);
        assert_eq!(
            plan.url,
            "https://api.github.com/repos/hyprwm/Hyprland/releases/tags/v0.57.1"
        );
    }

    #[test]
    fn expat_release() {
        let plan = source_for_base("expat", "expat", "2.9.0-1", "2.10.0-1").unwrap();
        assert!(plan.url.ends_with("/R_2_10_0"));
    }

    #[test]
    fn kwin_revision() {
        let plan = source_for_base("kwin", "kwin", "6.8.2-1", "6.8.2-2").unwrap();
        assert_eq!(plan.kind, SourceKind::ArchPackagingHistory);
        assert_eq!(plan.target_version, "6.8.2-2");
        // Same URL as the previously hard-coded kwin source.
        assert_eq!(
            plan.url,
            "https://gitlab.archlinux.org/api/v4/projects/archlinux%2Fpackaging%2Fpackages%2Fkwin/repository/commits?per_page=20"
        );
    }

    #[test]
    fn plain_and_v_prefixed_tags() {
        let waybar = upstream_source("waybar").unwrap();
        assert_eq!(
            github_release_url(waybar, "0.15.0").unwrap(),
            "https://api.github.com/repos/Alexays/Waybar/releases/tags/0.15.0"
        );
        let mpv = upstream_source("mpv").unwrap();
        assert_eq!(
            github_release_url(mpv, "0.41.0").unwrap(),
            "https://api.github.com/repos/mpv-player/mpv/releases/tags/v0.41.0"
        );
    }

    #[test]
    fn epoch_is_not_part_of_upstream_tag() {
        let plan = source_for_base("mpv", "mpv", "1:0.40.0-3", "1:0.41.0-1").unwrap();
        assert!(plan.url.ends_with("/tags/v0.41.0"));
        assert_eq!(plan.target_version, "1:0.41.0-1");
    }

    #[test]
    fn upstream_update_without_curated_source_has_no_plan() {
        // Never fall back to a guessed or generic upstream source.
        assert!(source_for_base("7zip", "7zip", "25.01-1", "26.05-1").is_none());
        assert!(source_for_base("kwin", "kwin", "6.8.2-2", "6.8.3-1").is_none());
    }

    #[test]
    fn revision_of_any_package_uses_arch_history() {
        let plan = source_for_base("7zip", "7zip", "26.05-1", "26.05-2").unwrap();
        assert_eq!(plan.kind, SourceKind::ArchPackagingHistory);
        assert!(plan.url.contains("%2F7zip/repository/commits"));
    }

    #[test]
    fn revision_is_not_upstream_release() {
        let plan = source_for_base("hyprland", "hyprland", "0.57.1-1", "0.57.1-2").unwrap();
        assert_eq!(plan.kind, SourceKind::ArchPackagingHistory);
        assert!(!plan.url.contains("api.github.com"));
    }

    #[test]
    fn epoch_change_uses_arch_history() {
        let plan = source_for_base("foo", "foo", "1:2.0-1", "2:2.0-1").unwrap();
        assert_eq!(plan.kind, SourceKind::ArchPackagingHistory);
    }

    #[test]
    fn split_package_uses_pkgbase_repository() {
        // libnm is built from the networkmanager pkgbase.
        let plan = source_for_base("libnm", "networkmanager", "1.58.1-2", "1.58.1-3").unwrap();
        assert_eq!(plan.pkgbase, "networkmanager");
        assert!(plan.url.contains("%2Fnetworkmanager/repository/commits"));
        assert!(!plan.url.contains("libnm"));

        // vulkan-radeon is built from mesa.
        let plan = source_for_base("vulkan-radeon", "mesa", "1:25.2.6-1", "1:25.2.6-2").unwrap();
        assert!(plan.url.contains("%2Fmesa/repository/commits"));
    }

    #[test]
    fn split_package_uses_pkgbase_for_upstream_lookup() {
        // A split package whose pkgbase has no curated upstream source.
        assert!(source_for_base("libnm", "networkmanager", "1.58.0-1", "1.58.1-1").is_none());
    }

    #[test]
    fn renamed_gitlab_projects_get_no_guessed_source() {
        assert!(source_for_base("libsigc++", "libsigc++", "3.6.0-1", "3.6.0-2").is_none());
        assert!(source_for_base("tree", "tree", "2.1.0-1", "2.1.0-2").is_none());
    }

    #[test]
    fn gitlab_identity_rules() {
        for base in [
            "mesa",
            "networkmanager",
            "python-platformdirs",
            "gtk4",
            "qt6-base",
            "lib32-mesa",
            "python3.x",
        ] {
            assert!(arch_gitlab_project_is_identity(base), "{base}");
        }
        for base in [
            "",
            "libsigc++",
            "foo@bar",
            "tree",
            "a..b",
            "a--b",
            "a__b",
            "x.git",
            "x.atom",
            "-x",
            "x-",
            "Mesa",
            "a/b",
            "a%2Fb",
            "a?b",
        ] {
            assert!(!arch_gitlab_project_is_identity(base), "{base}");
        }
    }

    #[test]
    fn every_planned_url_is_trusted() {
        for source in UPSTREAM_SOURCES {
            let url = github_release_url(source, "1.2.3").unwrap();
            assert!(crate::changelog_fetch::trusted_source_url(&url), "{url}");
        }
        for base in ["mesa", "networkmanager", "kwin", "7zip"] {
            let url = arch_history_url(base).unwrap();
            assert!(crate::changelog_fetch::trusted_source_url(&url), "{url}");
        }
    }

    #[test]
    fn upstream_table_is_consistent() {
        let mut seen = std::collections::HashSet::new();
        for source in UPSTREAM_SOURCES {
            assert!(seen.insert(source.pkgbase), "duplicate {}", source.pkgbase);
            assert!(valid_package_name(source.pkgbase));
            let (owner, repo) = source.repository.split_once('/').unwrap();
            for part in [owner, repo] {
                assert!(!part.is_empty());
                assert!(
                    part.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                );
                assert!(part != "." && part != "..");
            }
        }
    }

    #[test]
    fn tag_format_shapes() {
        assert!(TagFormat::VPrefix.accepts_tag("v0.57.1"));
        assert!(!TagFormat::VPrefix.accepts_tag("0.57.1"));
        assert!(!TagFormat::VPrefix.accepts_tag("v"));
        assert!(TagFormat::Plain.accepts_tag("2025.10.22"));
        assert!(!TagFormat::Plain.accepts_tag("v1.0"));
        assert!(TagFormat::ExpatUnderscore.accepts_tag("R_2_10_0"));
        assert!(!TagFormat::ExpatUnderscore.accepts_tag("R_2.10.0"));
        assert!(!TagFormat::Plain.accepts_tag("1.0/../x"));
        assert!(!TagFormat::Plain.accepts_tag("1.0?x"));
    }

    #[test]
    fn tag_to_version_round_trip() {
        assert_eq!(
            TagFormat::VPrefix.version_from_tag("v0.57.1").as_deref(),
            Some("0.57.1")
        );
        assert_eq!(
            TagFormat::Plain.version_from_tag("0.15.0").as_deref(),
            Some("0.15.0")
        );
        assert_eq!(
            TagFormat::ExpatUnderscore
                .version_from_tag("R_2_10_0")
                .as_deref(),
            Some("2.10.0")
        );
        assert_eq!(TagFormat::VPrefix.version_from_tag("0.57.1"), None);
        assert_eq!(TagFormat::Plain.version_from_tag("nightly"), None);
        for source in UPSTREAM_SOURCES {
            let tag = source.tags.tag_for("1.2.3");
            assert_eq!(source.tags.version_from_tag(&tag).as_deref(), Some("1.2.3"));
        }
    }

    #[test]
    fn upstream_update_plans_releases_then_arch_history() {
        let plans = plan_sources("hyprland", "hyprland", "0.57.0-3", "0.57.1-1");
        let kinds: Vec<_> = plans.iter().map(|p| p.kind).collect();
        assert_eq!(
            kinds,
            [SourceKind::GitHubRelease, SourceKind::ArchPackagingHistory]
        );
        for plan in &plans {
            assert!(crate::changelog_fetch::trusted_source_url(&plan.url));
        }
    }

    #[test]
    fn upstream_update_without_curated_source_plans_only_arch_history() {
        let plans = plan_sources("7zip", "7zip", "25.01-1", "26.05-1");
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].kind, SourceKind::ArchPackagingHistory);
    }

    #[test]
    fn revision_plans_single_arch_history() {
        let plans = plan_sources("libnm", "networkmanager", "1.58.1-2", "1.58.1-3");
        assert_eq!(plans.len(), 1);
        assert!(plans[0].url.contains("%2Fnetworkmanager/"));
    }

    #[test]
    fn unchanged_or_unsafe_updates_plan_nothing() {
        assert!(plan_sources("kwin", "kwin", "6.8.2-2", "6.8.2-2").is_empty());
        assert!(plan_sources("tree", "tree", "2.1.0-1", "2.2.0-1").is_empty());
        assert!(plan_sources("kwin", "kwin", "6.8.2-2", "6.8.3-1/../x").is_empty());
    }

    #[test]
    fn release_list_urls_are_trusted() {
        for source in UPSTREAM_SOURCES {
            let url = github_release_list_url(source);
            assert!(crate::changelog_fetch::trusted_source_url(&url), "{url}");
        }
    }

    #[test]
    fn unknown_package_has_no_guessed_source() {
        assert!(source_for_base("unknown", "unknown", "1.0-1", "2.0-1").is_none());
    }

    #[test]
    fn unchanged_has_no_source() {
        assert!(source_for_base("hyprland", "hyprland", "0.57.1-1", "0.57.1-1").is_none());
    }

    #[test]
    fn malformed_version_has_no_source() {
        assert!(source_for_base("expat", "expat", "2.9.0-1", "invalid").is_none());
        assert!(source_for_base("expat", "expat", "2.9.0-1", "2.10.0-1/../x").is_none());
    }

    #[test]
    fn package_name_validation_follows_arch_rules() {
        for name in [
            "kwin",
            "python_foo",
            "libsigc++",
            "gtk4",
            "lib32-mesa",
            "foo@bar",
            "qt6.5",
        ] {
            assert!(valid_package_name(name), "{name}");
        }
        for name in [
            "", "-kwin", ".hidden", "Kwin", "a/b", "../kwin", "kwin?x", "kwin%2F", "kw in",
        ] {
            assert!(!valid_package_name(name), "{name}");
        }
    }

    #[test]
    fn invalid_name_has_no_source() {
        assert!(source_for_base("kwin", "../kwin", "6.8.2-1", "6.8.2-2").is_none());
    }

    #[test]
    fn local_desc_base_parsing() {
        let split = "%NAME%\nlibnm\n\n%VERSION%\n1.58.1-3\n\n%BASE%\nnetworkmanager\n\n";
        assert_eq!(
            parse_local_desc_base(split, "libnm").as_deref(),
            Some("networkmanager")
        );
        let plain = "%NAME%\nfoo\n\n%VERSION%\n1.0-1\n";
        assert_eq!(parse_local_desc_base(plain, "foo").as_deref(), Some("foo"));
        // Name mismatch or unsafe base value is never trusted.
        assert_eq!(parse_local_desc_base(split, "networkmanager"), None);
        let bad = "%NAME%\nfoo\n%BASE%\n../etc\n";
        assert_eq!(parse_local_desc_base(bad, "foo"), None);
        assert_eq!(parse_local_desc_base("", "foo"), None);
    }

    fn fixture_db(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "rwr-changelog-sources-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let entry = root.join("libnm-1.58.1-2");
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(
            entry.join("desc"),
            "%NAME%\nlibnm\n\n%VERSION%\n1.58.1-2\n\n%BASE%\nnetworkmanager\n",
        )
        .unwrap();
        root
    }

    #[test]
    fn resolves_pkgbase_from_fixture_database() {
        let root = fixture_db("resolve");
        assert_eq!(
            resolve_pkgbase_in(&root, "libnm", "1.58.1-2").as_deref(),
            Some("networkmanager")
        );
        // Unknown version or traversal attempts resolve to nothing.
        // Installed version changed since the scan: the entry is still found by
        // its exact %NAME%.
        assert_eq!(
            resolve_pkgbase_in(&root, "libnm", "1.58.1-1").as_deref(),
            Some("networkmanager")
        );
        // A different package whose name starts with "libnm-" is not used.
        let other = root.join("libnm-extra-2.0-1");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("desc"), "%NAME%\nlibnm-extra\n%BASE%\nextra\n").unwrap();
        assert_eq!(
            resolve_pkgbase_in(&root, "libnm-extra", "1.0-1").as_deref(),
            Some("extra")
        );
        assert_eq!(
            resolve_pkgbase_in(&root, "libnm", "9.9-1").as_deref(),
            Some("networkmanager")
        );
        assert_eq!(resolve_pkgbase_in(&root, "absent", "1.0-1"), None);
        assert_eq!(resolve_pkgbase_in(&root, "../libnm", "1.58.1-2"), None);
        assert_eq!(resolve_pkgbase_in(&root, "libnm", "1.58.1-2/../x"), None);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
