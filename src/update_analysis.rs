// RWR PACKAGE INTELLIGENCE — update change analysis (ETAP 4.12).
//
// Combines trusted sources for one available update:
// * GitHub releases of curated upstream projects, covering EVERY release
//   between the installed and the available version;
// * Arch packaging history (pkgbase) between the two package versions;
// * Arch Security Tracker advisories fixed (or still open) by the update.
//
// Nothing is invented: every change text comes from a source, categories come
// from the source's own headings/keywords, and missing data is reported as
// missing. Read-only: network GET requests via `changelog_fetch` only.

use crate::change_items::{
    ChangeCategory, ChangeItem, highlights, item_from_commit_text, items_from_release_notes,
};
use crate::changelog::{rpmvercmp, upstream_version, valid_version, vercmp};
use crate::changelog_fetch::{
    ChangelogResult, ChangelogStatus, FetchLimits, HttpError, ReleaseStatus, classify_http_error,
    parse_github_release, release_body_status,
};
use crate::changelog_sources::{
    SECURITY_TRACKER_URL, SourceKind, SourcePlan, UpstreamSource, github_release_list_url,
    github_release_url, plan_sources, upstream_source, valid_package_name,
};
use crate::intelligence::Language;
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

/// Fetches a trusted URL with the given limits.
pub type Fetch<'a> = dyn Fn(&str, FetchLimits) -> Result<String, HttpError> + 'a;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceReport {
    pub kind: SourceKind,
    pub status: ChangelogStatus,
    pub url: String,
    /// Release tags (GitHub) or package versions (Arch) covered, newest first.
    pub versions: Vec<String>,
    pub items: Vec<ChangeItem>,
    /// The history window did not reach the installed version.
    pub partial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    pub id: String,
    pub severity: String,
    pub kind: String,
    pub issues: Vec<String>,
    pub fixed: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityFinding {
    NotChecked,
    Unavailable(ChangelogStatus),
    Checked {
        /// Advisories whose fixed version is reached by this update.
        fixed: Vec<Advisory>,
        /// Open advisories still affecting the available version.
        remaining: Vec<Advisory>,
    },
}

// ---------------------------------------------------------------------------
// Arch Security Tracker

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerEntry {
    pub id: String,
    pub packages: Vec<String>,
    pub status: String,
    pub severity: String,
    pub kind: String,
    pub affected: String,
    pub fixed: Option<String>,
    pub issues: Vec<String>,
}

fn safe_token(value: &str, max: usize) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= max
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' ' | ':')))
    .then(|| value.to_string())
}

/// Parses `all.json`. Malformed entries are skipped; a non-array is invalid.
pub fn parse_security_tracker(json: &str) -> Result<Vec<TrackerEntry>, ChangelogStatus> {
    let Ok(Value::Array(groups)) = serde_json::from_str::<Value>(json) else {
        return Err(ChangelogStatus::InvalidResponse);
    };
    let text = |group: &Value, key: &str, max: usize| {
        group
            .get(key)
            .and_then(Value::as_str)
            .and_then(|v| safe_token(v, max))
    };
    let entries = groups
        .iter()
        .filter_map(|group| {
            let id = text(group, "name", 32).filter(|id| id.starts_with("AVG-"))?;
            let packages: Vec<String> = group
                .get("packages")?
                .as_array()?
                .iter()
                .filter_map(Value::as_str)
                .filter(|name| valid_package_name(name))
                .map(str::to_string)
                .collect();
            let affected = text(group, "affected", 128).filter(|v| valid_version(v))?;
            let fixed = text(group, "fixed", 128).filter(|v| valid_version(v));
            let issues = group
                .get("issues")
                .and_then(Value::as_array)
                .map(|issues| {
                    issues
                        .iter()
                        .filter_map(Value::as_str)
                        .filter_map(|issue| safe_token(issue, 32))
                        .filter(|issue| issue.starts_with("CVE-"))
                        .collect()
                })
                .unwrap_or_default();
            Some(TrackerEntry {
                id,
                packages,
                status: text(group, "status", 32).unwrap_or_else(|| "Unknown".into()),
                severity: text(group, "severity", 32).unwrap_or_else(|| "Unknown".into()),
                kind: text(group, "type", 80).unwrap_or_default(),
                affected,
                fixed,
                issues,
            })
        })
        .collect();
    Ok(entries)
}

fn advisory(entry: &TrackerEntry) -> Advisory {
    Advisory {
        id: entry.id.clone(),
        severity: entry.severity.clone(),
        kind: entry.kind.clone(),
        issues: entry.issues.clone(),
        fixed: entry.fixed.clone(),
    }
}

/// Advisories for `name` (pkgname, as tracked by the Security Tracker).
pub fn security_finding(
    entries: &[TrackerEntry],
    name: &str,
    installed: &str,
    available: &str,
) -> SecurityFinding {
    let mut fixed = Vec::new();
    let mut remaining = Vec::new();
    for entry in entries
        .iter()
        .filter(|e| e.packages.iter().any(|p| p == name))
    {
        match &entry.fixed {
            Some(fix)
                if vercmp(installed, fix) == Ordering::Less
                    && vercmp(fix, available) != Ordering::Greater =>
            {
                fixed.push(advisory(entry));
            }
            fix if entry.status.eq_ignore_ascii_case("vulnerable")
                && vercmp(&entry.affected, available) != Ordering::Greater
                && fix
                    .as_deref()
                    .is_none_or(|f| vercmp(f, available) == Ordering::Greater) =>
            {
                remaining.push(advisory(entry));
            }
            _ => {}
        }
    }
    SecurityFinding::Checked { fixed, remaining }
}

type TrackerData = Result<Arc<Vec<TrackerEntry>>, ChangelogStatus>;

const TRACKER_TTL: Duration = Duration::from_secs(15 * 60);
const TRACKER_ERROR_TTL: Duration = Duration::from_secs(120);

static TRACKER_CACHE: Mutex<Option<(Instant, TrackerData)>> = Mutex::new(None);

pub fn load_security_tracker(fetch: &Fetch) -> TrackerData {
    match fetch(SECURITY_TRACKER_URL, FetchLimits::SECURITY_TRACKER) {
        Ok(json) => parse_security_tracker(&json).map(Arc::new),
        Err(error) => Err(classify_http_error(error)),
    }
}

/// Fetched once and shared by all packages of a scan.
fn cached_security_tracker(fetch: &Fetch) -> TrackerData {
    let mut cache = TRACKER_CACHE.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((at, data)) = cache.as_ref() {
        let ttl = if data.is_ok() {
            TRACKER_TTL
        } else {
            TRACKER_ERROR_TTL
        };
        if at.elapsed() < ttl {
            return data.clone();
        }
    }
    let data = load_security_tracker(fetch);
    *cache = Some((Instant::now(), data.clone()));
    data
}

// ---------------------------------------------------------------------------
// GitHub releases between two upstream versions

struct Release {
    tag: String,
    version: String,
    status: ReleaseStatus,
    items: Vec<ChangeItem>,
}

fn release_from_body(tag: String, version: String, body: Option<&str>) -> Release {
    let status = release_body_status(body);
    let items = if status == ReleaseStatus::Verified {
        items_from_release_notes(body.unwrap_or(""))
    } else {
        Vec::new()
    };
    Release {
        tag,
        version,
        status,
        items,
    }
}

/// Releases in (installed, target] from a release list response.
fn select_releases(
    json: &str,
    source: &UpstreamSource,
    installed: &str,
    target: &str,
) -> Result<Vec<Release>, ChangelogStatus> {
    let Ok(Value::Array(list)) = serde_json::from_str::<Value>(json) else {
        return Err(ChangelogStatus::InvalidResponse);
    };
    let target_tag = source.tags.tag_for(target);
    let mut releases: Vec<Release> = list
        .iter()
        .filter_map(|release| {
            let tag = release.get("tag_name")?.as_str()?;
            if release.get("draft").and_then(Value::as_bool) != Some(false) {
                return None;
            }
            let prerelease = release
                .get("prerelease")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            if prerelease && tag != target_tag {
                return None;
            }
            let version = source.tags.version_from_tag(tag)?;
            let in_range = rpmvercmp(installed, &version) == Ordering::Less
                && rpmvercmp(&version, target) != Ordering::Greater;
            in_range.then(|| {
                release_from_body(
                    tag.to_string(),
                    version,
                    release.get("body").and_then(Value::as_str),
                )
            })
        })
        .collect();
    releases.sort_by(|a, b| rpmvercmp(&b.version, &a.version));
    releases.dedup_by(|a, b| a.tag == b.tag);
    Ok(releases)
}

fn github_report(
    fetch: &Fetch,
    plan: &SourcePlan,
    source: &UpstreamSource,
    installed: &str,
    target: &str,
) -> SourceReport {
    let list_url = github_release_list_url(source);
    let target_tag = source.tags.tag_for(target);

    let mut releases = match fetch(&list_url, FetchLimits::RELEASE_LIST) {
        Ok(json) => match select_releases(&json, source, installed, target) {
            Ok(releases) => releases,
            Err(status) => return report_error(plan, status),
        },
        // Transient failures: do not hammer the API with a second request.
        Err(error @ (HttpError::Timeout | HttpError::RequestFailed | HttpError::RateLimited)) => {
            return report_error(plan, classify_http_error(error));
        }
        Err(_) => Vec::new(),
    };

    // The target release is older than the list window, or the list failed:
    // fetch the target release directly.
    if !releases.iter().any(|r| r.tag == target_tag) {
        let Some(tag_url) = github_release_url(source, target) else {
            return report_error(plan, ChangelogStatus::InvalidResponse);
        };
        match fetch(&tag_url, FetchLimits::SINGLE) {
            Ok(json) => match parse_github_release(&json, &target_tag) {
                ReleaseStatus::Invalid => {
                    return report_error(plan, ChangelogStatus::InvalidResponse);
                }
                _ => {
                    let data: Value = serde_json::from_str(&json).unwrap_or(Value::Null);
                    releases.insert(
                        0,
                        release_from_body(
                            target_tag.clone(),
                            target.to_string(),
                            data.get("body").and_then(Value::as_str),
                        ),
                    );
                }
            },
            Err(error) => return report_error(plan, classify_http_error(error)),
        }
    }

    let status = if releases
        .iter()
        .any(|r| r.status == ReleaseStatus::Verified && !r.items.is_empty())
    {
        ChangelogStatus::ReleaseNotes
    } else if releases
        .iter()
        .any(|r| r.status == ReleaseStatus::ExternalChangelog)
    {
        ChangelogStatus::ExternalChangelog
    } else {
        ChangelogStatus::NoChangelog
    };

    SourceReport {
        kind: SourceKind::GitHubRelease,
        status,
        url: plan.url.clone(),
        versions: releases.iter().map(|r| r.tag.clone()).collect(),
        items: releases.into_iter().flat_map(|r| r.items).collect(),
        partial: false,
    }
}

// ---------------------------------------------------------------------------
// Arch packaging history between two package versions

/// Parses an Arch packaging version commit title: returns (version, description).
///
/// Formats seen in Arch packaging repositories:
/// * `upgpkg: <version>[: <description>]` (pkgctl)
/// * `upgpkg: <pkgbase> <version>` (legacy)
/// * `<version>[: <description>]` (no prefix, e.g. networkmanager history)
pub fn parse_upgpkg(first_line: &str, pkgbase: &str) -> Option<(String, Option<String>)> {
    let line = first_line.trim();
    let rest = line.strip_prefix("upgpkg: ").unwrap_or(line).trim();
    if let Some(version) = rest.strip_prefix(&format!("{pkgbase} ")) {
        let version = version.trim();
        return valid_version(version).then(|| (version.to_string(), None));
    }
    let (version, description) = match rest.split_once(": ") {
        Some((version, description)) => (version, Some(description.trim())),
        None => (rest.trim_end_matches(':'), None),
    };
    valid_version(version).then(|| {
        (
            version.to_string(),
            description.filter(|d| !d.is_empty()).map(str::to_string),
        )
    })
}

fn commit_message(commit: &Value) -> Option<&str> {
    commit.get("message").and_then(Value::as_str)
}

/// Collects packaging changes from the commit releasing `target` back to (not
/// including) the commit releasing `installed`.
pub fn arch_range(
    commits: &[Value],
    pkgbase: &str,
    installed: &str,
    target: &str,
) -> Option<(Vec<String>, Vec<ChangeItem>, bool)> {
    let start = commits.iter().position(|commit| {
        commit_message(commit)
            .and_then(|m| parse_upgpkg(m.lines().next().unwrap_or(""), pkgbase))
            .is_some_and(|(version, _)| version == target)
    })?;

    let mut versions = Vec::new();
    let mut items = Vec::new();
    let mut reached_installed = false;

    for commit in &commits[start..] {
        // Malformed entries are skipped, never fatal.
        let Some(message) = commit_message(commit) else {
            continue;
        };
        let mut lines = message.lines();
        let first = lines.next().unwrap_or("").trim();
        match parse_upgpkg(first, pkgbase) {
            Some((version, description)) => {
                if vercmp(&version, installed) != Ordering::Greater {
                    reached_installed = true;
                    break;
                }
                versions.push(version);
                let description = description.or_else(|| {
                    lines
                        .map(str::trim)
                        .find(|l| crate::change_items::clean_line(l).is_some())
                        .map(str::to_string)
                });
                if let Some(item) = description.as_deref().and_then(item_from_commit_text) {
                    items.push(item);
                }
            }
            None => {
                if let Some(item) = item_from_commit_text(first) {
                    items.push(item);
                }
            }
        }
    }
    Some((versions, items, !reached_installed))
}

fn arch_report(fetch: &Fetch, plan: &SourcePlan, installed: &str) -> SourceReport {
    let json = match fetch(&plan.url, FetchLimits::SINGLE) {
        Ok(json) => json,
        Err(error) => return report_error(plan, classify_http_error(error)),
    };
    let Ok(Value::Array(commits)) = serde_json::from_str::<Value>(&json) else {
        return report_error(plan, ChangelogStatus::InvalidResponse);
    };
    match arch_range(&commits, &plan.pkgbase, installed, &plan.target_version) {
        Some((versions, items, partial)) => SourceReport {
            kind: SourceKind::ArchPackagingHistory,
            status: ChangelogStatus::PackagingHistory,
            url: plan.url.clone(),
            versions,
            items,
            partial,
        },
        None => report_error(plan, ChangelogStatus::NoChangelog),
    }
}

fn report_error(plan: &SourcePlan, status: ChangelogStatus) -> SourceReport {
    SourceReport {
        kind: plan.kind,
        status,
        url: plan.url.clone(),
        versions: Vec::new(),
        items: Vec::new(),
        partial: false,
    }
}

// ---------------------------------------------------------------------------
// Orchestration

/// Updates that can be analysed (valid name and versions).
pub fn should_analyze(name: &str, installed: &str, available: &str) -> bool {
    valid_package_name(name) && valid_version(installed) && valid_version(available)
}

/// Full analysis with injectable network access and tracker data.
pub fn analyze_with(
    fetch: &Fetch,
    tracker: &TrackerData,
    name: &str,
    pkgbase: Option<&str>,
    installed: &str,
    available: &str,
) -> ChangelogResult {
    if !should_analyze(name, installed, available) {
        return ChangelogResult {
            status: ChangelogStatus::NoSource,
            source_url: String::new(),
            summary: None,
            sources: Vec::new(),
            security: SecurityFinding::NotChecked,
        };
    }

    let security = match tracker {
        Ok(entries) => security_finding(entries, name, installed, available),
        Err(status) => SecurityFinding::Unavailable(*status),
    };

    let plans = pkgbase
        .map(|base| plan_sources(name, base, installed, available))
        .unwrap_or_default();

    let sources: Vec<SourceReport> = plans
        .iter()
        .map(|plan| match plan.kind {
            SourceKind::GitHubRelease => {
                match (
                    upstream_source(&plan.pkgbase),
                    upstream_version(installed),
                    upstream_version(available),
                ) {
                    (Some(source), Some(from), Some(to)) => {
                        github_report(fetch, plan, source, from, to)
                    }
                    _ => report_error(plan, ChangelogStatus::InvalidResponse),
                }
            }
            SourceKind::ArchPackagingHistory => arch_report(fetch, plan, installed),
        })
        .collect();

    let primary = sources
        .iter()
        .find(|s| s.status.is_verified())
        .or(sources.first());
    let status = primary.map_or(ChangelogStatus::NoSource, |s| s.status);
    let source_url = primary.map(|s| s.url.clone()).unwrap_or_default();
    let summary = primary.and_then(|s| {
        highlights(&s.items, 1, 1)
            .0
            .first()
            .map(|item| item.text.clone())
    });

    ChangelogResult {
        status,
        source_url,
        summary,
        sources,
        security,
    }
}

fn network_fetch(url: &str, limits: FetchLimits) -> Result<String, HttpError> {
    crate::changelog_fetch::fetch_json_limited(url, limits)
}

// ---------------------------------------------------------------------------
// Response cache shared by all analysis workers.
//
// * repeated scans within the TTL make no new API requests (GitHub allows
//   only 60 unauthenticated requests per hour);
// * split packages sharing a pkgbase (mesa → vulkan-radeon, lib32-mesa, ...)
//   fetch their common Arch packaging history once, even when analysed in
//   parallel: the per-URL slot lock makes concurrent callers wait for the
//   first request instead of duplicating it.

const RESPONSE_TTL: Duration = Duration::from_secs(15 * 60);
/// A missing release/history does not appear within minutes.
const NOT_FOUND_TTL: Duration = Duration::from_secs(15 * 60);
/// GitHub's unauthenticated limit resets hourly; retrying soon only fails again.
const RATE_LIMITED_TTL: Duration = Duration::from_secs(10 * 60);
/// Timeouts and network errors may be transient: retry after a short pause.
const TRANSIENT_ERROR_TTL: Duration = Duration::from_secs(60);
const MAX_CACHED_BYTES: usize = 32 * 1024 * 1024;

fn response_ttl(result: &Result<String, HttpError>) -> Duration {
    match result {
        Ok(_) => RESPONSE_TTL,
        Err(HttpError::NotFound) => NOT_FOUND_TTL,
        Err(HttpError::RateLimited) => RATE_LIMITED_TTL,
        Err(_) => TRANSIENT_ERROR_TTL,
    }
}

struct CachedResponse {
    at: Instant,
    result: Result<String, HttpError>,
}

impl CachedResponse {
    fn fresh_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.at) < response_ttl(&self.result)
    }
    fn size(&self) -> usize {
        self.result.as_ref().map_or(0, String::len)
    }
}

type Slot = Arc<Mutex<Option<CachedResponse>>>;

#[derive(Default)]
pub struct ResponseCache {
    slots: Mutex<HashMap<String, Slot>>,
}

impl ResponseCache {
    pub fn get_or_fetch(
        &self,
        url: &str,
        limits: FetchLimits,
        fetch: &Fetch,
    ) -> Result<String, HttpError> {
        self.get_or_fetch_at(url, limits, fetch, Instant::now())
    }

    fn get_or_fetch_at(
        &self,
        url: &str,
        limits: FetchLimits,
        fetch: &Fetch,
        now: Instant,
    ) -> Result<String, HttpError> {
        let slot = {
            let mut slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
            Arc::clone(slots.entry(url.to_string()).or_default())
        };
        let result = {
            let mut entry = slot.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(cached) = entry.as_ref().filter(|c| c.fresh_at(now)) {
                return cached.result.clone();
            }
            let result = fetch(url, limits);
            *entry = Some(CachedResponse {
                at: now,
                result: result.clone(),
            });
            result
        };
        self.evict(now);
        result
    }

    /// Drops expired entries, then the oldest ones above the size budget.
    /// Slots locked by an in-flight request are left alone.
    fn evict(&self, now: Instant) {
        let mut slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        let mut live: Vec<(String, Instant, usize)> = Vec::new();
        slots.retain(|url, slot| match slot.try_lock() {
            Ok(entry) => match entry.as_ref() {
                Some(cached) if cached.fresh_at(now) => {
                    live.push((url.clone(), cached.at, cached.size()));
                    true
                }
                Some(_) => false,
                None => true,
            },
            Err(_) => true,
        });
        let mut total: usize = live.iter().map(|(_, _, size)| size).sum();
        live.sort_by_key(|(_, at, _)| *at);
        for (url, _, size) in live {
            if total <= MAX_CACHED_BYTES {
                break;
            }
            slots.remove(&url);
            total -= size;
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.slots.lock().unwrap().len()
    }
}

static RESPONSE_CACHE: LazyLock<ResponseCache> = LazyLock::new(ResponseCache::default);

fn cached_network_fetch(url: &str, limits: FetchLimits) -> Result<String, HttpError> {
    RESPONSE_CACHE.get_or_fetch(url, limits, &network_fetch)
}

/// Real analysis used by the GUI worker threads (safe to call in parallel).
pub fn analyze(name: &str, installed: &str, available: &str) -> ChangelogResult {
    let tracker = cached_security_tracker(&network_fetch);
    let pkgbase = crate::changelog_sources::resolve_pkgbase(name, installed);
    analyze_with(
        &cached_network_fetch,
        &tracker,
        name,
        pkgbase.as_deref(),
        installed,
        available,
    )
}

// ---------------------------------------------------------------------------
// Presentation (plain text for the existing GTK label)

fn tr(language: Language, pl: &str, en: &str) -> String {
    match language {
        Language::Polish => pl.to_string(),
        Language::English => en.to_string(),
    }
}

pub fn status_text(status: ChangelogStatus, language: Language) -> String {
    use ChangelogStatus::*;
    let (pl, en) = match status {
        ReleaseNotes => (
            "✓ ZWERYFIKOWANE — informacje o wydaniu",
            "✓ VERIFIED — release notes",
        ),
        PackagingHistory => (
            "✓ ZWERYFIKOWANA HISTORIA PAKIETU ARCH",
            "✓ VERIFIED ARCH PACKAGING HISTORY",
        ),
        ExternalChangelog => (
            "Changelog w źródle zewnętrznym",
            "Changelog at external source",
        ),
        NoChangelog => (
            "BRAK DANYCH — źródło nie opisuje zmian tej wersji",
            "NO DATA — the source does not describe this version",
        ),
        NotFound => (
            "BRAK WYDANIA — źródło nie zawiera tej wersji (HTTP 404)",
            "NO RELEASE — source has no entry for this version (HTTP 404)",
        ),
        RateLimited => (
            "ŹRÓDŁO ODRZUCIŁO ZAPYTANIE — limit zapytań lub brak dostępu (HTTP 403/429)",
            "SOURCE REFUSED REQUEST — rate limit or access denied (HTTP 403/429)",
        ),
        Timeout => (
            "PRZEKROCZONO CZAS — źródło nie odpowiedziało",
            "TIMEOUT — the source did not respond in time",
        ),
        NetworkError => (
            "BŁĄD SIECI — brak połączenia ze źródłem",
            "NETWORK ERROR — cannot reach the source",
        ),
        InvalidResponse => (
            "BŁĄD ŹRÓDŁA — nieprawidłowa odpowiedź",
            "SOURCE ERROR — invalid response",
        ),
        NoSource => (
            "Brak skonfigurowanego źródła changelogu dla tej aktualizacji",
            "No changelog source configured for this update",
        ),
    };
    tr(language, pl, en)
}

pub fn category_label(category: ChangeCategory, language: Language) -> String {
    use ChangeCategory::*;
    let (pl, en) = match category {
        Security => ("BEZPIECZEŃSTWO", "SECURITY"),
        Breaking => ("ZMIANA NIEZGODNA", "BREAKING"),
        BugFix => ("POPRAWKA", "BUG FIX"),
        Feature => ("NOWOŚĆ", "FEATURE"),
        Technical => ("TECHNICZNE", "TECHNICAL"),
        Other => ("INNE", "OTHER"),
    };
    tr(language, pl, en)
}

const MAX_PER_CATEGORY: usize = 2;
const MAX_PER_SOURCE: usize = 6;
const MAX_VERSIONS_SHOWN: usize = 5;

/// Versions oldest → newest; only the newest few when there are many.
fn versions_text(versions_newest_first: &[String]) -> String {
    let shown: Vec<&str> = versions_newest_first
        .iter()
        .take(MAX_VERSIONS_SHOWN)
        .rev()
        .map(String::as_str)
        .collect();
    if versions_newest_first.len() > MAX_VERSIONS_SHOWN {
        format!("…, {}", shown.join(", "))
    } else {
        shown.join(", ")
    }
}

fn render_source(out: &mut Vec<String>, source: &SourceReport, language: Language) {
    let title = match source.kind {
        SourceKind::GitHubRelease => tr(
            language,
            "Wydania upstream (GitHub, treść EN)",
            "Upstream releases (GitHub)",
        ),
        SourceKind::ArchPackagingHistory => tr(
            language,
            "Pakiet Arch (historia pakietowania, treść EN)",
            "Arch package (packaging history)",
        ),
    };

    if !source.status.is_verified() {
        out.push(format!(
            "◈ {title}: {}",
            status_text(source.status, language)
        ));
        return;
    }

    let mut line = format!("◈ {title}");
    if !source.versions.is_empty() {
        line.push_str(": ");
        line.push_str(&versions_text(&source.versions));
    }
    if source.partial {
        line.push_str(&tr(
            language,
            " (historia niepełna — starsze wersje poza zakresem źródła)",
            " (incomplete — older versions are outside the source window)",
        ));
    }
    out.push(line);

    if source.items.is_empty() {
        out.push(format!(
            "   {}",
            tr(
                language,
                "Wersja potwierdzona, ale źródło nie zawiera opisu zmian.",
                "Version confirmed, but the source contains no change description.",
            )
        ));
        return;
    }

    let (picked, omitted) = highlights(&source.items, MAX_PER_CATEGORY, MAX_PER_SOURCE);
    for item in picked {
        out.push(format!(
            "   • [{}] {}",
            category_label(item.category, language),
            item.text
        ));
    }
    if omitted > 0 {
        out.push(format!(
            "   {}",
            match language {
                Language::Polish => format!("… oraz {omitted} innych wpisów w źródle"),
                Language::English => format!("… and {omitted} more entries in the source"),
            }
        ));
    }
}

fn advisory_text(advisory: &Advisory, language: Language) -> String {
    let severity = if advisory.severity.eq_ignore_ascii_case("unknown") {
        tr(language, "ważność nieznana", "severity unknown")
    } else {
        advisory.severity.clone()
    };
    let mut text = format!("{} [{severity}]", advisory.id);
    if !advisory.kind.is_empty() && !advisory.kind.eq_ignore_ascii_case("unknown") {
        text.push_str(&format!(" {}", advisory.kind));
    }
    if !advisory.issues.is_empty() {
        let shown: Vec<&str> = advisory.issues.iter().take(3).map(String::as_str).collect();
        text.push_str(&format!(" — {}", shown.join(", ")));
        if advisory.issues.len() > 3 {
            text.push_str(&format!(" (+{})", advisory.issues.len() - 3));
        }
    }
    text
}

fn render_security(out: &mut Vec<String>, finding: &SecurityFinding, language: Language) {
    match finding {
        SecurityFinding::NotChecked => {}
        SecurityFinding::Unavailable(status) => out.push(format!(
            "◈ Arch Security Tracker: {} ({})",
            tr(language, "niedostępny", "unavailable"),
            status_text(*status, language)
        )),
        SecurityFinding::Checked { fixed, remaining } => {
            if fixed.is_empty() && remaining.is_empty() {
                out.push(format!(
                    "◈ Arch Security Tracker: {}",
                    tr(
                        language,
                        "brak znanych podatności usuwanych tą aktualizacją",
                        "no known vulnerabilities fixed by this update",
                    )
                ));
            }
            for advisory in fixed {
                out.push(format!(
                    "◈ {}: {}",
                    tr(
                        language,
                        "BEZPIECZEŃSTWO — aktualizacja usuwa podatność (Arch Security Tracker)",
                        "SECURITY — this update fixes a vulnerability (Arch Security Tracker)",
                    ),
                    advisory_text(advisory, language)
                ));
            }
            for advisory in remaining {
                out.push(format!(
                    "◈ {}: {}",
                    tr(
                        language,
                        "UWAGA — po aktualizacji nadal podatny (Arch Security Tracker)",
                        "WARNING — still vulnerable after the update (Arch Security Tracker)",
                    ),
                    advisory_text(advisory, language)
                ));
            }
        }
    }
}

/// Text for the changelog label of a package card.
pub fn render_text(result: &ChangelogResult, language: Language) -> String {
    let mut out = vec![format!("◈ {}", status_text(result.status, language))];

    let mut any_items = false;
    for source in &result.sources {
        any_items |= source.status.is_verified() && !source.items.is_empty();
        render_source(&mut out, source, language);
    }
    // Legacy single-source results (fetch_changelog) still show their summary.
    if result.sources.is_empty() {
        if let Some(summary) = &result.summary {
            out.push(crate::package_description::source_summary_text(
                language, summary,
            ));
        }
    }
    render_security(&mut out, &result.security, language);
    if any_items {
        out.push(tr(
            language,
            "Kategorie przypisane wg nagłówków i słów kluczowych źródła.",
            "Categories assigned from the source's headings and keywords.",
        ));
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    const HYPR_LIST: &str = "https://api.github.com/repos/hyprwm/Hyprland/releases?per_page=20";
    const HYPR_TAG: &str = "https://api.github.com/repos/hyprwm/Hyprland/releases/tags/v0.57.1";
    const HYPR_ARCH: &str = "https://gitlab.archlinux.org/api/v4/projects/archlinux%2Fpackaging%2Fpackages%2Fhyprland/repository/commits?per_page=20";
    const NM_ARCH: &str = "https://gitlab.archlinux.org/api/v4/projects/archlinux%2Fpackaging%2Fpackages%2Fnetworkmanager/repository/commits?per_page=20";

    /// Fake network: fixed responses per URL, records requested URLs.
    struct FakeNet {
        responses: HashMap<&'static str, Result<String, HttpError>>,
        calls: RefCell<Vec<String>>,
    }

    impl FakeNet {
        fn new(responses: Vec<(&'static str, Result<String, HttpError>)>) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                calls: RefCell::new(Vec::new()),
            }
        }
        fn fetch(&self, url: &str, _limits: FetchLimits) -> Result<String, HttpError> {
            assert!(
                crate::changelog_fetch::trusted_source_url(url),
                "untrusted request {url}"
            );
            self.calls.borrow_mut().push(url.to_string());
            match self.responses.get(url) {
                Some(Ok(body)) => Ok(body.clone()),
                Some(Err(error)) => Err(clone_error(error)),
                None => Err(HttpError::NotFound),
            }
        }
    }

    fn clone_error(error: &HttpError) -> HttpError {
        match error {
            HttpError::UntrustedUrl => HttpError::UntrustedUrl,
            HttpError::RequestFailed => HttpError::RequestFailed,
            HttpError::Timeout => HttpError::Timeout,
            HttpError::NotFound => HttpError::NotFound,
            HttpError::RateLimited => HttpError::RateLimited,
            HttpError::HttpStatus(code) => HttpError::HttpStatus(*code),
            HttpError::ResponseTooLarge => HttpError::ResponseTooLarge,
            HttpError::InvalidUtf8 => HttpError::InvalidUtf8,
        }
    }

    fn no_tracker() -> TrackerData {
        Ok(Arc::new(Vec::new()))
    }

    fn release(tag: &str, body: &str, prerelease: bool) -> Value {
        serde_json::json!({"tag_name": tag, "draft": false, "prerelease": prerelease, "body": body})
    }

    fn hypr_list() -> String {
        Value::Array(vec![
            release("v0.58.0-rc1", "## Features\n- Future", true),
            release("v0.57.1", "## Fixes\n- Fix black screen on nvidia", false),
            release(
                "v0.57.0",
                "## New features\n- Lua config\n## Fixes\n- Crash on exit",
                false,
            ),
            release("v0.56.0", "## Fixes\n- Old fix", false),
        ])
        .to_string()
    }

    fn analyze_fake(
        net: &FakeNet,
        tracker: &TrackerData,
        name: &str,
        base: &str,
        from: &str,
        to: &str,
    ) -> ChangelogResult {
        analyze_with(&|u, l| net.fetch(u, l), tracker, name, Some(base), from, to)
    }

    #[test]
    fn github_range_covers_all_releases_between_versions() {
        let net = FakeNet::new(vec![
            (HYPR_LIST, Ok(hypr_list())),
            (
                HYPR_ARCH,
                Ok(r#"[{"message":"upgpkg: 0.57.1-1"},{"message":"upgpkg: 0.56.0-2"}]"#.into()),
            ),
        ]);
        let result = analyze_fake(
            &net,
            &no_tracker(),
            "hyprland",
            "hyprland",
            "0.56.0-2",
            "0.57.1-1",
        );
        assert_eq!(result.status, ChangelogStatus::ReleaseNotes);
        let gh = &result.sources[0];
        assert_eq!(gh.versions, ["v0.57.1", "v0.57.0"]);
        let texts: Vec<_> = gh.items.iter().map(|i| i.text.as_str()).collect();
        assert_eq!(
            texts,
            ["Fix black screen on nvidia", "Lua config", "Crash on exit"]
        );
        assert!(!texts.contains(&"Old fix"), "installed release excluded");
        assert!(!texts.contains(&"Future"), "prerelease excluded");
        // Single list request, no per-tag fallback needed.
        assert!(!net.calls.borrow().iter().any(|u| u == HYPR_TAG));
    }

    #[test]
    fn target_missing_from_list_falls_back_to_tag_endpoint() {
        let tag_json =
            serde_json::json!({"tag_name":"v0.57.1","draft":false,"body":"Fixed crash."})
                .to_string();
        let net = FakeNet::new(vec![(HYPR_LIST, Ok("[]".into())), (HYPR_TAG, Ok(tag_json))]);
        let result = analyze_fake(
            &net,
            &no_tracker(),
            "hyprland",
            "hyprland",
            "0.57.0-1",
            "0.57.1-1",
        );
        assert_eq!(result.sources[0].status, ChangelogStatus::ReleaseNotes);
        assert_eq!(result.sources[0].versions, ["v0.57.1"]);
        assert_eq!(result.sources[0].items[0].category, ChangeCategory::BugFix);
    }

    #[test]
    fn timeout_is_reported_and_not_retried() {
        let net = FakeNet::new(vec![
            (HYPR_LIST, Err(HttpError::Timeout)),
            (HYPR_ARCH, Err(HttpError::Timeout)),
        ]);
        let result = analyze_fake(
            &net,
            &no_tracker(),
            "hyprland",
            "hyprland",
            "0.57.0-1",
            "0.57.1-1",
        );
        assert_eq!(result.sources[0].status, ChangelogStatus::Timeout);
        assert_eq!(result.sources[1].status, ChangelogStatus::Timeout);
        assert_eq!(result.status, ChangelogStatus::Timeout);
        assert!(!net.calls.borrow().iter().any(|u| u == HYPR_TAG));
        let text = render_text(&result, Language::Polish);
        assert!(text.contains("PRZEKROCZONO CZAS"));
        assert!(!text.contains("•"), "no change items without data");
    }

    #[test]
    fn network_errors_and_rate_limits_are_reported() {
        for (error, status) in [
            (HttpError::RequestFailed, ChangelogStatus::NetworkError),
            (HttpError::RateLimited, ChangelogStatus::RateLimited),
        ] {
            let net = FakeNet::new(vec![(HYPR_LIST, Err(error))]);
            let result = analyze_fake(
                &net,
                &no_tracker(),
                "hyprland",
                "hyprland",
                "0.57.0-1",
                "0.57.1-1",
            );
            assert_eq!(result.sources[0].status, status);
        }
    }

    #[test]
    fn invalid_responses_are_reported() {
        let net = FakeNet::new(vec![
            (HYPR_LIST, Ok("{not json".into())),
            (HYPR_ARCH, Ok(r#"{"message":"not a list"}"#.into())),
        ]);
        let result = analyze_fake(
            &net,
            &no_tracker(),
            "hyprland",
            "hyprland",
            "0.57.0-1",
            "0.57.1-1",
        );
        assert_eq!(result.sources[0].status, ChangelogStatus::InvalidResponse);
        assert_eq!(result.sources[1].status, ChangelogStatus::InvalidResponse);
    }

    #[test]
    fn wrong_tag_from_tag_endpoint_is_invalid() {
        let wrong = serde_json::json!({"tag_name":"v0.57.0","draft":false,"body":"x"}).to_string();
        let net = FakeNet::new(vec![
            (HYPR_LIST, Err(HttpError::NotFound)),
            (HYPR_TAG, Ok(wrong)),
        ]);
        let result = analyze_fake(
            &net,
            &no_tracker(),
            "hyprland",
            "hyprland",
            "0.57.0-1",
            "0.57.1-1",
        );
        assert_eq!(result.sources[0].status, ChangelogStatus::InvalidResponse);
    }

    #[test]
    fn arch_revision_range_for_split_package() {
        let commits = serde_json::json!([
            {"message": "upgpkg: 1.58.1-4: Fix crash in libnm (CVE-2025-1111)"},
            {"message": "upgpkg: 1.58.1-3: Rebuild for libfoo 3"},
            {"message": "Add nvchecker config"},
            {"id": "malformed"},
            {"message": "upgpkg: 1.58.1-2"},
            {"message": "upgpkg: 1.58.1-1: Older"},
        ])
        .to_string();
        let net = FakeNet::new(vec![(NM_ARCH, Ok(commits))]);
        let result = analyze_fake(
            &net,
            &no_tracker(),
            "libnm",
            "networkmanager",
            "1.58.1-2",
            "1.58.1-3",
        );
        assert_eq!(result.status, ChangelogStatus::PackagingHistory);
        let arch = &result.sources[0];
        assert_eq!(arch.versions, ["1.58.1-3"]);
        let texts: Vec<_> = arch.items.iter().map(|i| i.text.as_str()).collect();
        // Newer -4 is outside the update; -2 (installed) and older are excluded.
        assert_eq!(texts, ["Rebuild for libfoo 3", "Add nvchecker config"]);
        assert!(!arch.partial);
        assert!(
            arch.items
                .iter()
                .all(|i| i.category == ChangeCategory::Technical)
        );
    }

    #[test]
    fn arch_range_marks_incomplete_window() {
        let commits: Vec<Value> = serde_json::from_str(
            r#"[{"message":"upgpkg: 2.0-2: Patch for CVE-2025-2222"},{"message":"upgpkg: 2.0-1"}]"#,
        )
        .unwrap();
        let (versions, items, partial) = arch_range(&commits, "foo", "1.0-1", "2.0-2").unwrap();
        assert_eq!(versions, ["2.0-2", "2.0-1"]);
        assert_eq!(items[0].category, ChangeCategory::Security);
        assert!(partial);
    }

    #[test]
    fn arch_target_missing_is_no_changelog() {
        let net = FakeNet::new(vec![(
            NM_ARCH,
            Ok(r#"[{"message":"upgpkg: 1.58.1-2"}]"#.into()),
        )]);
        let result = analyze_fake(
            &net,
            &no_tracker(),
            "libnm",
            "networkmanager",
            "1.58.1-2",
            "1.58.1-3",
        );
        assert_eq!(result.status, ChangelogStatus::NoChangelog);
    }

    fn commits(json: &str) -> Vec<Value> {
        serde_json::from_str(json).unwrap()
    }

    /// First lines of the real networkmanager packaging history (2026-11-09).
    const REAL_NM_HISTORY: &str = r#"[
        {"message":"upgpkg: 1.58.1-3: rebuild with ppp 2.5.5"},
        {"message":"1.58.1-2: ppp rebuild"},
        {"message":"1.58.1-1"},
        {"message":"1.58.0-1"},
        {"message":"1.56.1-2: rebuild with ppp 2.5.3"},
        {"message":"Remove signature check; key was revoked"},
        {"message":"1.56.1-1"}
    ]"#;

    #[test]
    fn real_networkmanager_history_stops_at_installed_version() {
        let list = commits(REAL_NM_HISTORY);
        let (versions, items, partial) =
            arch_range(&list, "networkmanager", "1.58.1-2", "1.58.1-3").unwrap();
        assert_eq!(versions, ["1.58.1-3"]);
        let texts: Vec<_> = items.iter().map(|i| i.text.as_str()).collect();
        assert_eq!(texts, ["rebuild with ppp 2.5.5"]);
        assert!(!partial);

        // Upstream update 1.56.1-1 -> 1.58.1-3 covers five package versions.
        let (versions, items, partial) =
            arch_range(&list, "networkmanager", "1.56.1-1", "1.58.1-3").unwrap();
        assert_eq!(
            versions,
            ["1.58.1-3", "1.58.1-2", "1.58.1-1", "1.58.0-1", "1.56.1-2"]
        );
        assert!(
            items
                .iter()
                .any(|i| i.text == "Remove signature check; key was revoked")
        );
        assert!(!partial);
    }

    /// Real kwin titles and a Hyprland v0.57.2 notes excerpt (2026-11-09).
    #[test]
    fn real_kwin_titles_and_hyprland_notes() {
        let list = commits(
            r#"[{"message":"upgpkg: 6.8.2-2: Backport crash fix"},{"message":"upgpkg: 6.8.2-1: Upstream update"},{"message":"upgpkg: 6.8.1-2: Fix glitches on NVIDIA"}]"#,
        );
        let (_, items, _) = arch_range(&list, "kwin", "6.8.1-2", "6.8.2-2").unwrap();
        let cats: Vec<_> = items
            .iter()
            .map(|i| (i.text.as_str(), i.category))
            .collect();
        assert_eq!(
            cats,
            [
                ("Backport crash fix", ChangeCategory::Other),
                ("Upstream update", ChangeCategory::Technical)
            ]
        );

        let body = "Another round of patches backported from main on top of 0.57.1.\n\nThis fixes various regressions, as well as some crashes under heavy load from RT scheduling.\n\n## Fixes Backported\n - config/lua: fix accessing an expired window ref from a lua object (#16853) by @vaxerski in https://github.com/hyprwm/Hyprland/pull/16853\n";
        let items = items_from_release_notes(body);
        let last = items.last().unwrap();
        assert_eq!(last.category, ChangeCategory::BugFix);
        assert_eq!(
            last.text,
            "config/lua: fix accessing an expired window ref from a lua object (#16853)"
        );
    }

    #[test]
    fn arch_version_must_match_exactly() {
        let list =
            commits(r#"[{"message":"upgpkg: 6.8.2-20: Rebuild"},{"message":"upgpkg: 6.8.2-2.1"}]"#);
        assert_eq!(arch_range(&list, "kwin", "6.8.2-1", "6.8.2-2"), None);
    }

    #[test]
    fn legacy_commit_format_uses_pkgbase_not_pkgname() {
        let list = commits(r#"[{"message":"upgpkg: networkmanager 1.58.1-3"}]"#);
        assert!(arch_range(&list, "networkmanager", "1.58.1-2", "1.58.1-3").is_some());
        assert_eq!(arch_range(&list, "libnm", "1.58.1-2", "1.58.1-3"), None);
    }

    #[test]
    fn bare_commit_uses_body_line_and_skips_trailers() {
        let list = vec![serde_json::json!({
            "message": "upgpkg: 1:25.2.6-2\n\nSigned-off-by: Packager <p@example.org>\n- Rebuild for llvm 21\n"
        })];
        let (_, items, _) = arch_range(&list, "mesa", "1:25.2.6-1", "1:25.2.6-2").unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].text, "Rebuild for llvm 21");
        assert_eq!(items[0].category, ChangeCategory::Technical);
    }

    #[test]
    fn bare_commit_without_description_yields_no_item() {
        let list =
            commits(r#"[{"message":"upgpkg: kwin 6.8.2-2"},{"message":"upgpkg: kwin 6.8.2-1"}]"#);
        let (versions, items, partial) = arch_range(&list, "kwin", "6.8.2-1", "6.8.2-2").unwrap();
        assert_eq!(versions, ["6.8.2-2"]);
        assert!(items.is_empty());
        assert!(!partial);
    }

    #[test]
    fn empty_or_unrelated_history_has_no_range() {
        assert_eq!(arch_range(&[], "kwin", "6.8.2-1", "6.8.2-2"), None);
        let list = commits(r#"[{"message":"Update README"}]"#);
        assert_eq!(arch_range(&list, "kwin", "6.8.2-1", "6.8.2-2"), None);
    }

    #[test]
    fn upgpkg_title_formats() {
        assert_eq!(
            parse_upgpkg("upgpkg: 1.0-2", "foo"),
            Some(("1.0-2".into(), None))
        );
        assert_eq!(
            parse_upgpkg("upgpkg: 1:0.41.0-7: Rebuild", "mpv"),
            Some(("1:0.41.0-7".into(), Some("Rebuild".into())))
        );
        assert_eq!(
            parse_upgpkg("upgpkg: kwin 6.8.2-2", "kwin"),
            Some(("6.8.2-2".into(), None))
        );
        assert_eq!(
            parse_upgpkg("upgpkg: 1.0-2:", "foo"),
            Some(("1.0-2".into(), None))
        );
        assert_eq!(parse_upgpkg("Update .SRCINFO", "foo"), None);
        // Unprefixed version titles (real networkmanager history).
        assert_eq!(
            parse_upgpkg("1.58.1-2: ppp rebuild", "networkmanager"),
            Some(("1.58.1-2".into(), Some("ppp rebuild".into())))
        );
        assert_eq!(
            parse_upgpkg("1.58.1-1", "networkmanager"),
            Some(("1.58.1-1".into(), None))
        );
        // Ordinary titles starting with digits are not versions.
        assert_eq!(parse_upgpkg("3-way merge of config", "foo"), None);
        assert_eq!(parse_upgpkg("2to3: convert scripts", "foo"), None);
        assert_eq!(parse_upgpkg("upgpkg: ../x", "foo"), None);
    }

    #[test]
    fn upstream_without_curated_source_shows_only_arch_packaging() {
        let arch = "https://gitlab.archlinux.org/api/v4/projects/archlinux%2Fpackaging%2Fpackages%2F7zip/repository/commits?per_page=20";
        let net = FakeNet::new(vec![(
            arch,
            Ok(r#"[{"message":"upgpkg: 26.05-1"},{"message":"upgpkg: 25.01-1"}]"#.into()),
        )]);
        let result = analyze_fake(&net, &no_tracker(), "7zip", "7zip", "25.01-1", "26.05-1");
        assert_eq!(result.sources.len(), 1);
        assert_eq!(result.sources[0].kind, SourceKind::ArchPackagingHistory);
        let text = render_text(&result, Language::Polish);
        assert!(text.contains("Wersja potwierdzona, ale źródło nie zawiera opisu zmian."));
        assert!(!text.contains("•"));
    }

    #[test]
    fn no_pkgbase_means_no_source_but_security_still_checked() {
        let net = FakeNet::new(vec![]);
        let result = analyze_with(
            &|u, l| net.fetch(u, l),
            &no_tracker(),
            "foo",
            None,
            "1.0-1",
            "1.1-1",
        );
        assert_eq!(result.status, ChangelogStatus::NoSource);
        assert!(net.calls.borrow().is_empty());
        let text = render_text(&result, Language::English);
        assert!(text.contains("No changelog source configured"));
        assert!(text.contains("no known vulnerabilities fixed by this update"));
    }

    #[test]
    fn invalid_update_is_not_analyzed() {
        assert!(!should_analyze("../x", "1.0-1", "1.1-1"));
        assert!(!should_analyze("foo", "1.0-1", "1.1-1/../x"));
        let result = analyze_with(
            &|_, _| panic!("no network"),
            &no_tracker(),
            "Foo",
            Some("foo"),
            "1.0-1",
            "1.1-1",
        );
        assert_eq!(result.security, SecurityFinding::NotChecked);
    }

    const TRACKER_JSON: &str = r#"[
        {"name":"AVG-100","packages":["openssl","lib32-openssl"],"status":"Fixed","severity":"High","type":"arbitrary code execution","affected":"3.5.0-1","fixed":"3.5.1-1","ticket":null,"issues":["CVE-2025-0001","CVE-2025-0002"]},
        {"name":"AVG-101","packages":["openssl"],"status":"Fixed","severity":"Low","type":"denial of service","affected":"3.4.0-1","fixed":"3.4.1-1","issues":["CVE-2024-9999"]},
        {"name":"AVG-102","packages":["openssl"],"status":"Vulnerable","severity":"Medium","type":"information disclosure","affected":"3.5.1-1","fixed":null,"issues":["CVE-2025-0003"]},
        {"name":"AVG-103","packages":["curl"],"status":"Fixed","severity":"High","type":"x","affected":"8.0-1","fixed":"8.1-1","issues":[]},
        {"name":"BAD-1","packages":["openssl"],"status":"Fixed","affected":"1-1","fixed":"2-1","issues":[]},
        {"name":"AVG-104","packages":"openssl","affected":"1-1"},
        {"name":"AVG-105","packages":["openssl"],"status":"Fixed","severity":"High","affected":"x/../y","fixed":"3.5.1-1","issues":[]}
    ]"#;

    #[test]
    fn security_tracker_parsing_skips_malformed_entries() {
        let entries = parse_security_tracker(TRACKER_JSON).unwrap();
        let ids: Vec<_> = entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["AVG-100", "AVG-101", "AVG-102", "AVG-103"]);
        assert_eq!(
            parse_security_tracker("{}"),
            Err(ChangelogStatus::InvalidResponse)
        );
        assert_eq!(
            parse_security_tracker("<html>"),
            Err(ChangelogStatus::InvalidResponse)
        );
    }

    #[test]
    fn security_fixes_and_remaining_issues() {
        let entries = parse_security_tracker(TRACKER_JSON).unwrap();
        let finding = security_finding(&entries, "openssl", "3.5.0-1", "3.5.1-1");
        let SecurityFinding::Checked { fixed, remaining } = finding else {
            panic!("checked");
        };
        assert_eq!(
            fixed.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            ["AVG-100"]
        );
        assert_eq!(
            remaining.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            ["AVG-102"]
        );

        // Already-fixed older advisory is not attributed to this update.
        let SecurityFinding::Checked { fixed, .. } =
            security_finding(&entries, "openssl", "3.5.1-1", "3.5.2-1")
        else {
            panic!()
        };
        assert!(fixed.is_empty());
        // Tracker matches pkgname exactly.
        let SecurityFinding::Checked { fixed, remaining } =
            security_finding(&entries, "openssl-1.1", "3.5.0-1", "3.5.1-1")
        else {
            panic!()
        };
        assert!(fixed.is_empty() && remaining.is_empty());
    }

    #[test]
    fn security_rendering_pl_en() {
        let entries = Arc::new(parse_security_tracker(TRACKER_JSON).unwrap());
        let net = FakeNet::new(vec![]);
        let result = analyze_with(
            &|u, l| net.fetch(u, l),
            &Ok(entries),
            "openssl",
            None,
            "3.5.0-1",
            "3.5.1-1",
        );
        let pl = render_text(&result, Language::Polish);
        assert!(pl.contains(
            "BEZPIECZEŃSTWO — aktualizacja usuwa podatność (Arch Security Tracker): AVG-100 [High]"
        ));
        assert!(pl.contains("CVE-2025-0001, CVE-2025-0002"));
        assert!(
            pl.contains("UWAGA — po aktualizacji nadal podatny (Arch Security Tracker): AVG-102")
        );
        let en = render_text(&result, Language::English);
        assert!(en.contains("SECURITY — this update fixes a vulnerability"));
    }

    #[test]
    fn unknown_severity_and_type_are_readable() {
        let entries = parse_security_tracker(
            r#"[{"name":"AVG-2843","packages":["vim"],"status":"Unknown","severity":"Unknown","type":"unknown","affected":"9.0.1224-1","fixed":"9.0.1225-1","issues":["CVE-2023-0433"]}]"#,
        )
        .unwrap();
        let result = analyze_with(
            &|_, _| Err(HttpError::NotFound),
            &Ok(Arc::new(entries)),
            "vim",
            None,
            "9.0.1224-1",
            "9.0.1225-1",
        );
        let pl = render_text(&result, Language::Polish);
        assert!(
            pl.contains("AVG-2843 [ważność nieznana] — CVE-2023-0433"),
            "{pl}"
        );
        assert!(!pl.contains("unknown"));
    }

    #[test]
    fn tracker_unavailable_is_stated() {
        let net = FakeNet::new(vec![]);
        let result = analyze_with(
            &|u, l| net.fetch(u, l),
            &Err(ChangelogStatus::Timeout),
            "foo",
            None,
            "1.0-1",
            "1.1-1",
        );
        let text = render_text(&result, Language::Polish);
        assert!(text.contains("Arch Security Tracker: niedostępny (PRZEKROCZONO CZAS"));
    }

    #[test]
    fn tracker_loading_maps_errors() {
        let ok = load_security_tracker(&|url, limits| {
            assert_eq!(url, SECURITY_TRACKER_URL);
            assert_eq!(limits, FetchLimits::SECURITY_TRACKER);
            Ok("[]".into())
        });
        assert!(ok.unwrap().is_empty());
        assert_eq!(
            load_security_tracker(&|_, _| Err(HttpError::Timeout)).unwrap_err(),
            ChangelogStatus::Timeout
        );
        assert_eq!(
            load_security_tracker(&|_, _| Err(HttpError::ResponseTooLarge)).unwrap_err(),
            ChangelogStatus::InvalidResponse
        );
    }

    #[test]
    fn rendering_lists_categorized_highlights_and_marks_language() {
        let net = FakeNet::new(vec![
            (HYPR_LIST, Ok(hypr_list())),
            (
                HYPR_ARCH,
                Ok(r#"[{"message":"upgpkg: 0.57.1-1"},{"message":"upgpkg: 0.56.0-2"}]"#.into()),
            ),
        ]);
        let result = analyze_fake(
            &net,
            &no_tracker(),
            "hyprland",
            "hyprland",
            "0.56.0-2",
            "0.57.1-1",
        );
        let pl = render_text(&result, Language::Polish);
        assert!(pl.starts_with("◈ ✓ ZWERYFIKOWANE — informacje o wydaniu"));
        assert!(pl.contains("Wydania upstream (GitHub, treść EN): v0.57.0, v0.57.1"));
        assert!(pl.contains("• [POPRAWKA] Fix black screen on nvidia"));
        assert!(pl.contains("• [NOWOŚĆ] Lua config"));
        assert!(pl.contains("Kategorie przypisane wg nagłówków i słów kluczowych źródła."));
        let en = render_text(&result, Language::English);
        assert!(en.contains("• [BUG FIX] Fix black screen on nvidia"));
        assert!(!en.contains("treść EN"));
    }

    #[test]
    fn rendering_never_adds_items_for_unverified_sources() {
        let ext = serde_json::json!([{"tag_name":"v0.57.1","draft":false,"prerelease":false,"body":"- [Changelog](https://example.org)"}]).to_string();
        let net = FakeNet::new(vec![
            (HYPR_LIST, Ok(ext)),
            (HYPR_ARCH, Err(HttpError::NotFound)),
        ]);
        let result = analyze_fake(
            &net,
            &no_tracker(),
            "hyprland",
            "hyprland",
            "0.57.0-1",
            "0.57.1-1",
        );
        assert_eq!(result.sources[0].status, ChangelogStatus::ExternalChangelog);
        let text = render_text(&result, Language::Polish);
        assert!(!text.contains("•"));
        assert!(text.contains("HTTP 404"));
        assert!(!text.contains("Kategorie przypisane"));
    }

    #[test]
    fn long_release_notes_are_limited_with_omitted_count() {
        let body = (1..=20)
            .map(|i| format!("- Fixed issue number {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let list = Value::Array(vec![release(
            "v0.57.1",
            &format!("## Fixes\n{body}"),
            false,
        )])
        .to_string();
        let net = FakeNet::new(vec![(HYPR_LIST, Ok(list))]);
        let result = analyze_fake(
            &net,
            &no_tracker(),
            "hyprland",
            "hyprland",
            "0.57.0-1",
            "0.57.1-1",
        );
        let text = render_text(&result, Language::Polish);
        assert_eq!(text.matches("• [POPRAWKA]").count(), MAX_PER_CATEGORY);
        assert!(text.contains("… oraz 18 innych wpisów w źródle"));
    }

    // --- response cache -------------------------------------------------

    fn counting_fetch<'a>(
        counter: &'a std::sync::atomic::AtomicUsize,
        result: Result<String, HttpError>,
    ) -> impl Fn(&str, FetchLimits) -> Result<String, HttpError> + 'a {
        move |_url, _limits| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            result.clone()
        }
    }

    #[test]
    fn cache_serves_repeated_requests_within_ttl() {
        let cache = ResponseCache::default();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let fetch = counting_fetch(&calls, Ok("[]".into()));
        let t0 = Instant::now();
        for _ in 0..3 {
            assert_eq!(
                cache.get_or_fetch_at(HYPR_ARCH, FetchLimits::SINGLE, &fetch, t0),
                Ok("[]".into())
            );
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        // After the TTL the source is asked again.
        let later = t0 + RESPONSE_TTL + Duration::from_secs(1);
        cache
            .get_or_fetch_at(HYPR_ARCH, FetchLimits::SINGLE, &fetch, later)
            .unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn cache_keeps_transient_errors_only_briefly() {
        let cache = ResponseCache::default();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let fetch = counting_fetch(&calls, Err(HttpError::Timeout));
        let t0 = Instant::now();
        assert_eq!(
            cache.get_or_fetch_at(HYPR_ARCH, FetchLimits::SINGLE, &fetch, t0),
            Err(HttpError::Timeout)
        );
        // Within the short error TTL: no new request.
        cache
            .get_or_fetch_at(
                HYPR_ARCH,
                FetchLimits::SINGLE,
                &fetch,
                t0 + Duration::from_secs(5),
            )
            .unwrap_err();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        // A later rescan retries instead of keeping the error for 15 minutes.
        cache
            .get_or_fetch_at(
                HYPR_ARCH,
                FetchLimits::SINGLE,
                &fetch,
                t0 + TRANSIENT_ERROR_TTL + Duration::from_secs(1),
            )
            .unwrap_err();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn cache_holds_rate_limit_longer_than_timeouts() {
        assert!(response_ttl(&Err(HttpError::RateLimited)) > TRANSIENT_ERROR_TTL);
        assert!(response_ttl(&Err(HttpError::RequestFailed)) == TRANSIENT_ERROR_TTL);
        assert!(response_ttl(&Ok(String::new())) == RESPONSE_TTL);
    }

    #[test]
    fn parallel_requests_for_one_url_fetch_once() {
        let cache = ResponseCache::default();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let fetch = |_url: &str, _limits: FetchLimits| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(50));
            Ok::<_, HttpError>("[]".to_string())
        };
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    cache
                        .get_or_fetch(NM_ARCH, FetchLimits::SINGLE, &fetch)
                        .unwrap()
                });
            }
        });
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn cache_drops_expired_entries() {
        let cache = ResponseCache::default();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let fetch = counting_fetch(&calls, Ok("[]".into()));
        let t0 = Instant::now();
        cache
            .get_or_fetch_at(HYPR_ARCH, FetchLimits::SINGLE, &fetch, t0)
            .unwrap();
        let later = t0 + RESPONSE_TTL + Duration::from_secs(1);
        cache
            .get_or_fetch_at(NM_ARCH, FetchLimits::SINGLE, &fetch, later)
            .unwrap();
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_respects_size_budget() {
        let cache = ResponseCache::default();
        let big = "x".repeat(MAX_CACHED_BYTES / 2 + 1);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let fetch = counting_fetch(&calls, Ok(big));
        let t0 = Instant::now();
        cache
            .get_or_fetch_at(HYPR_LIST, FetchLimits::SINGLE, &fetch, t0)
            .unwrap();
        cache
            .get_or_fetch_at(
                HYPR_TAG,
                FetchLimits::SINGLE,
                &fetch,
                t0 + Duration::from_secs(1),
            )
            .unwrap();
        // The oldest entry is dropped to stay within the budget.
        assert_eq!(cache.len(), 1);
        cache
            .get_or_fetch_at(
                HYPR_TAG,
                FetchLimits::SINGLE,
                &fetch,
                t0 + Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}

/// Live check against the real sources. Not part of the offline suite:
/// `cargo test --offline -- --ignored update_analysis::live`
#[cfg(test)]
mod live {
    #[test]
    #[ignore = "requires network access"]
    fn live_analysis_samples() {
        use crate::intelligence::Language;
        for (name, installed, available) in [
            ("hyprland", "0.57.1-1", "0.57.2-1"),
            ("libnm", "1.58.1-2", "1.58.1-3"),
            ("kwin", "6.8.2-1", "6.8.2-2"),
            ("waybar", "0.15.0-3", "0.16.0-1"),
            ("7zip", "26.05-1", "26.05-2"),
            // Historical update with a real advisory (AVG-2843).
            ("vim", "9.0.1224-1", "9.0.1225-1"),
        ] {
            let result = super::analyze(name, installed, available);
            println!(
                "===== {name} {installed} -> {available}\n{}\n",
                super::render_text(&result, Language::Polish)
            );
        }
    }
}
