use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseStatus {
    Verified,
    ExternalChangelog,
    NoChangelog,
    Invalid,
}

pub fn parse_github_release(input: &str, expected_tag: &str) -> ReleaseStatus {
    if input.len() > 524288 {
        return ReleaseStatus::Invalid;
    }

    let Ok(data) = serde_json::from_str::<Value>(input) else {
        return ReleaseStatus::Invalid;
    };

    if data.get("tag_name").and_then(Value::as_str) != Some(expected_tag) {
        return ReleaseStatus::Invalid;
    }

    if data.get("draft").and_then(Value::as_bool) != Some(false) {
        return ReleaseStatus::Invalid;
    }

    release_body_status(data.get("body").and_then(Value::as_str))
}

/// Classifies a release body: real notes, links to an external changelog, or nothing.
pub fn release_body_status(body: Option<&str>) -> ReleaseStatus {
    let Some(body) = body else {
        return ReleaseStatus::NoChangelog;
    };

    let body = body.trim();

    if body.is_empty()
        || body.lines().all(|line| {
            let line = line.trim();
            line.is_empty()
                || line.starts_with("http://")
                || line.starts_with("https://")
                || line.starts_with("- http")
        })
    {
        return ReleaseStatus::NoChangelog;
    }

    let lines: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();

    let links_only = lines.iter().all(|line| {
        let line = line.trim_start_matches("- ").trim();

        line.starts_with("http://")
            || line.starts_with("https://")
            || (line.starts_with("[") && line.contains("]("))
    });

    if links_only {
        return ReleaseStatus::ExternalChangelog;
    }

    ReleaseStatus::Verified
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    UntrustedUrl,
    /// Transport failure: DNS, connection, TLS (no HTTP status).
    RequestFailed,
    /// The request exceeded the connect or total time limit (curl exit 28).
    Timeout,
    /// HTTP 404: the source has no such release / resource.
    NotFound,
    /// HTTP 403 or 429: access refused or rate limited (e.g. GitHub API limit).
    RateLimited,
    /// Any other non-2xx HTTP status.
    HttpStatus(u16),
    ResponseTooLarge,
    InvalidUtf8,
}

const MAX_RESPONSE_BYTES: usize = 524288;
/// Trailer appended by curl `--write-out`; the HTTP status follows it.
const STATUS_TRAILER: &str = "\nRWR-HTTP-STATUS:";
const CURL_EXIT_FILESIZE_EXCEEDED: i32 = 63;
const CURL_EXIT_TIMEOUT: i32 = 28;

/// Response size and time limits for one source request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchLimits {
    pub max_bytes: usize,
    pub max_seconds: u32,
}

impl FetchLimits {
    pub const SINGLE: Self = Self {
        max_bytes: MAX_RESPONSE_BYTES,
        max_seconds: 15,
    };
    /// GitHub release lists carry several full release notes.
    pub const RELEASE_LIST: Self = Self {
        max_bytes: 3 * 1024 * 1024,
        max_seconds: 20,
    };
    /// Arch Security Tracker `all.json` (all advisories, fetched once per scan).
    pub const SECURITY_TRACKER: Self = Self {
        max_bytes: 8 * 1024 * 1024,
        max_seconds: 25,
    };
}

/// Interprets curl's exit code and stdout (body + status trailer).
pub fn interpret_curl_output_limited(
    exit_code: Option<i32>,
    stdout: &[u8],
    max_bytes: usize,
) -> Result<String, HttpError> {
    match exit_code {
        Some(0) => {}
        Some(CURL_EXIT_FILESIZE_EXCEEDED) => return Err(HttpError::ResponseTooLarge),
        Some(CURL_EXIT_TIMEOUT) => return Err(HttpError::Timeout),
        _ => return Err(HttpError::RequestFailed),
    }

    let text = String::from_utf8(stdout.to_vec()).map_err(|_| HttpError::InvalidUtf8)?;
    let Some((body, status)) = text.rsplit_once(STATUS_TRAILER) else {
        return Err(HttpError::RequestFailed);
    };
    let Ok(status) = status.trim().parse::<u16>() else {
        return Err(HttpError::RequestFailed);
    };

    match status {
        200..=299 => {
            if body.len() > max_bytes {
                Err(HttpError::ResponseTooLarge)
            } else {
                Ok(body.to_string())
            }
        }
        // curl reports 000 when no HTTP response was received.
        0 => Err(HttpError::RequestFailed),
        404 => Err(HttpError::NotFound),
        403 | 429 => Err(HttpError::RateLimited),
        other => Err(HttpError::HttpStatus(other)),
    }
}

pub fn fetch_json_limited(url: &str, limits: FetchLimits) -> Result<String, HttpError> {
    if !trusted_source_url(url) {
        return Err(HttpError::UntrustedUrl);
    }
    let max_time = limits.max_seconds.to_string();
    let max_size = limits.max_bytes.to_string();

    let output = std::process::Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "5",
            "--max-time",
            &max_time,
            "--max-filesize",
            &max_size,
            "--user-agent",
            "RWR-Package-Intelligence/0.1",
            "--header",
            "Accept: application/json",
            "--write-out",
            "\nRWR-HTTP-STATUS:%{http_code}",
            "--",
            url,
        ])
        .output()
        .map_err(|_| HttpError::RequestFailed)?;

    interpret_curl_output_limited(output.status.code(), &output.stdout, limits.max_bytes)
}

/// Strict HTTPS allowlist. Only these URL shapes are accepted:
/// * GitHub release-by-tag API for a repository in `UPSTREAM_SOURCES`, with a
///   tag matching that source's tag format;
/// * GitHub release list API (`/releases?per_page=20`) for those repositories;
/// * the Arch Security Tracker advisory list (`SECURITY_TRACKER_URL`);
/// * Arch packaging commits API for a pkgbase whose GitLab path is the
///   pkgbase itself (see `arch_gitlab_project_is_identity`).
///
/// No query strings, fragments, credentials, ports or extra path segments.
pub fn trusted_source_url(url: &str) -> bool {
    use crate::changelog_sources::{
        ARCH_GITLAB_PREFIX, ARCH_GITLAB_SUFFIX, GITHUB_API_PREFIX, UPSTREAM_SOURCES,
        arch_gitlab_project_is_identity,
    };

    if url.len() > 512 || url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }

    if let Some(rest) = url.strip_prefix(ARCH_GITLAB_PREFIX) {
        return rest
            .strip_suffix(ARCH_GITLAB_SUFFIX)
            .is_some_and(arch_gitlab_project_is_identity);
    }

    if url == crate::changelog_sources::SECURITY_TRACKER_URL {
        return true;
    }

    if let Some(rest) = url.strip_prefix(GITHUB_API_PREFIX) {
        return UPSTREAM_SOURCES.iter().any(|source| {
            let Some(tail) = rest.strip_prefix(source.repository) else {
                return false;
            };
            tail == crate::changelog_sources::GITHUB_RELEASE_LIST_SUFFIX
                || tail
                    .strip_prefix("/releases/tags/")
                    .is_some_and(|tag| source.tags.accepts_tag(tag))
        });
    }

    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangelogStatus {
    ReleaseNotes,
    ExternalChangelog,
    PackagingHistory,
    NoChangelog,
    /// HTTP 404: the configured source has no entry for this version.
    NotFound,
    /// HTTP 403/429: the source refused or rate limited the request.
    RateLimited,
    /// The source did not answer within the time limit.
    Timeout,
    NetworkError,
    InvalidResponse,
    /// No trusted changelog source is configured for this update.
    NoSource,
}

impl ChangelogStatus {
    /// Verified content was obtained from the source.
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::ReleaseNotes | Self::PackagingHistory)
    }
}

#[derive(Debug)]
pub struct ChangelogResult {
    pub status: ChangelogStatus,
    pub source_url: String,
    pub summary: Option<String>,
    /// Per-source findings of the full analysis (empty for `fetch_changelog`).
    pub sources: Vec<crate::update_analysis::SourceReport>,
    /// Arch Security Tracker findings for this update.
    pub security: crate::update_analysis::SecurityFinding,
}

pub fn classify_http_error(error: HttpError) -> ChangelogStatus {
    match error {
        HttpError::RequestFailed => ChangelogStatus::NetworkError,
        HttpError::Timeout => ChangelogStatus::Timeout,
        HttpError::NotFound => ChangelogStatus::NotFound,
        HttpError::RateLimited => ChangelogStatus::RateLimited,
        HttpError::UntrustedUrl
        | HttpError::HttpStatus(_)
        | HttpError::ResponseTooLarge
        | HttpError::InvalidUtf8 => ChangelogStatus::InvalidResponse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_request_failure_is_network_error() {
        assert_eq!(
            classify_http_error(HttpError::RequestFailed),
            ChangelogStatus::NetworkError
        );
    }

    #[test]
    fn untrusted_url_is_invalid_response() {
        assert_eq!(
            classify_http_error(HttpError::UntrustedUrl),
            ChangelogStatus::InvalidResponse
        );
    }

    #[test]
    fn oversized_response_is_invalid_response() {
        assert_eq!(
            classify_http_error(HttpError::ResponseTooLarge),
            ChangelogStatus::InvalidResponse
        );
    }

    #[test]
    fn invalid_utf8_is_invalid_response() {
        assert_eq!(
            classify_http_error(HttpError::InvalidUtf8),
            ChangelogStatus::InvalidResponse
        );
    }

    fn interpret_curl_output(code: Option<i32>, stdout: &[u8]) -> Result<String, HttpError> {
        interpret_curl_output_limited(code, stdout, MAX_RESPONSE_BYTES)
    }

    fn curl_ok(body: &str, status: u16) -> Vec<u8> {
        format!("{body}\nRWR-HTTP-STATUS:{status:03}").into_bytes()
    }

    #[test]
    fn http_200_returns_body() {
        assert_eq!(
            interpret_curl_output(Some(0), &curl_ok("{\"a\":1}", 200)),
            Ok("{\"a\":1}".to_string())
        );
    }

    #[test]
    fn body_containing_newlines_is_preserved() {
        assert_eq!(
            interpret_curl_output(Some(0), &curl_ok("[\n{}\n]", 200)),
            Ok("[\n{}\n]".to_string())
        );
    }

    #[test]
    fn http_404_is_not_found_not_network_error() {
        let error = interpret_curl_output(Some(0), &curl_ok("{\"message\":\"Not Found\"}", 404))
            .unwrap_err();
        assert_eq!(error, HttpError::NotFound);
        assert_eq!(classify_http_error(error), ChangelogStatus::NotFound);
    }

    #[test]
    fn http_403_and_429_are_rate_limited() {
        for status in [403, 429] {
            let error = interpret_curl_output(Some(0), &curl_ok("{}", status)).unwrap_err();
            assert_eq!(error, HttpError::RateLimited);
            assert_eq!(classify_http_error(error), ChangelogStatus::RateLimited);
        }
    }

    #[test]
    fn other_http_errors_are_invalid_response() {
        for status in [301, 500, 503] {
            let error = interpret_curl_output(Some(0), &curl_ok("", status)).unwrap_err();
            assert_eq!(error, HttpError::HttpStatus(status));
            assert_eq!(classify_http_error(error), ChangelogStatus::InvalidResponse);
        }
    }

    #[test]
    fn transport_failures_are_network_errors() {
        // curl exit 6 (DNS), 7 (connect), 35 (TLS), 56 (receive failure).
        for code in [6, 7, 35, 56] {
            assert_eq!(
                interpret_curl_output(Some(code), b""),
                Err(HttpError::RequestFailed)
            );
        }
        assert_eq!(
            interpret_curl_output(None, b""),
            Err(HttpError::RequestFailed)
        );
        assert_eq!(
            interpret_curl_output(Some(0), &curl_ok("", 0)),
            Err(HttpError::RequestFailed)
        );
        assert_eq!(
            interpret_curl_output(Some(0), b"no trailer"),
            Err(HttpError::RequestFailed)
        );
    }

    #[test]
    fn curl_timeout_is_reported_as_timeout() {
        assert_eq!(
            interpret_curl_output(Some(28), b""),
            Err(HttpError::Timeout)
        );
        assert_eq!(
            classify_http_error(HttpError::Timeout),
            ChangelogStatus::Timeout
        );
    }

    #[test]
    fn per_source_size_limits_apply() {
        let body = "x".repeat(MAX_RESPONSE_BYTES + 10);
        assert_eq!(
            interpret_curl_output_limited(
                Some(0),
                &curl_ok(&body, 200),
                FetchLimits::RELEASE_LIST.max_bytes
            ),
            Ok(body.clone())
        );
        assert_eq!(
            interpret_curl_output_limited(Some(0), &curl_ok(&body, 200), 16),
            Err(HttpError::ResponseTooLarge)
        );
    }

    #[test]
    fn release_list_and_security_tracker_urls_are_trusted_exactly() {
        assert!(trusted_source_url(
            "https://api.github.com/repos/hyprwm/Hyprland/releases?per_page=20"
        ));
        assert!(trusted_source_url(
            "https://security.archlinux.org/issues/all.json"
        ));
        for url in [
            "https://api.github.com/repos/hyprwm/Hyprland/releases?per_page=100",
            "https://api.github.com/repos/hyprwm/Hyprland/releases",
            "https://api.github.com/repos/ip7z/7zip/releases?per_page=20",
            "https://security.archlinux.org/issues/all.json?x=1",
            "https://security.archlinux.org/all.json",
            "https://security.archlinux.org/issues/vulnerable.json",
            "http://security.archlinux.org/all.json",
            "https://security.archlinux.org.evil.example/all.json",
        ] {
            assert!(!trusted_source_url(url), "{url}");
        }
    }

    #[test]
    fn release_body_status_classification() {
        assert_eq!(release_body_status(None), ReleaseStatus::NoChangelog);
        assert_eq!(release_body_status(Some("  ")), ReleaseStatus::NoChangelog);
        assert_eq!(
            release_body_status(Some("- [Changelog](https://x/y)")),
            ReleaseStatus::ExternalChangelog
        );
        assert_eq!(
            release_body_status(Some("Fixed crash.")),
            ReleaseStatus::Verified
        );
    }

    #[test]
    fn oversized_bodies_are_rejected() {
        assert_eq!(
            interpret_curl_output(Some(63), b""),
            Err(HttpError::ResponseTooLarge)
        );
        let big = "x".repeat(MAX_RESPONSE_BYTES + 1);
        assert_eq!(
            interpret_curl_output(Some(0), &curl_ok(&big, 200)),
            Err(HttpError::ResponseTooLarge)
        );
    }

    #[test]
    fn invalid_utf8_body_is_rejected() {
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend_from_slice(b"\nRWR-HTTP-STATUS:200");
        assert_eq!(
            interpret_curl_output(Some(0), &bytes),
            Err(HttpError::InvalidUtf8)
        );
    }

    const GITLAB: &str =
        "https://gitlab.archlinux.org/api/v4/projects/archlinux%2Fpackaging%2Fpackages%2F";
    const COMMITS: &str = "/repository/commits?per_page=20";

    #[test]
    fn arch_history_urls_follow_strict_pattern() {
        for base in ["7zip", "mesa", "networkmanager", "python-platformdirs"] {
            assert!(
                trusted_source_url(&format!("{GITLAB}{base}{COMMITS}")),
                "{base}"
            );
        }
        let rejected = [
            format!("{GITLAB}mesa{COMMITS}&per_page=100"),
            format!("{GITLAB}mesa{COMMITS}#x"),
            format!("{GITLAB}mesa/repository/commits"),
            format!("{GITLAB}mesa%2F..%2Fx{COMMITS}"),
            format!("{GITLAB}Mesa{COMMITS}"),
            format!("{GITLAB}libsigc++{COMMITS}"),
            format!("{GITLAB}tree{COMMITS}"),
            format!("{GITLAB}{COMMITS}"),
            format!("{GITLAB}me sa{COMMITS}"),
            format!("{GITLAB}mesa{COMMITS}{COMMITS}"),
            "http://gitlab.archlinux.org/api/v4/projects/archlinux%2Fpackaging%2Fpackages%2Fmesa/repository/commits?per_page=20".to_string(),
            "https://gitlab.archlinux.org:8443/api/v4/projects/archlinux%2Fpackaging%2Fpackages%2Fmesa/repository/commits?per_page=20".to_string(),
            "https://gitlab.archlinux.org/api/v4/projects/archlinux%2Fpackaging%2Fpackages%2Fmesa/repository/files?per_page=20".to_string(),
            "https://gitlab.archlinux.org.evil.example/api/v4/projects/archlinux%2Fpackaging%2Fpackages%2Fmesa/repository/commits?per_page=20".to_string(),
        ];
        for url in rejected {
            assert!(!trusted_source_url(&url), "{url}");
        }
    }

    #[test]
    fn github_urls_only_for_curated_repositories_and_tag_formats() {
        assert!(trusted_source_url(
            "https://api.github.com/repos/Alexays/Waybar/releases/tags/0.15.0"
        ));
        assert!(trusted_source_url(
            "https://api.github.com/repos/mpv-player/mpv/releases/tags/v0.41.0"
        ));
        let rejected = [
            // Not curated.
            "https://api.github.com/repos/ip7z/7zip/releases/tags/26.05",
            "https://api.github.com/repos/hyprwm/Hyprland-evil/releases/tags/v1.0",
            "https://api.github.com/repos/hyprwm/hyprland/releases/tags/v1.0",
            // Wrong tag format for the repository.
            "https://api.github.com/repos/hyprwm/Hyprland/releases/tags/0.57.1",
            "https://api.github.com/repos/Alexays/Waybar/releases/tags/v0.15.0",
            "https://api.github.com/repos/libexpat/libexpat/releases/tags/R_2.10.0",
            // Other endpoints or injection.
            "https://api.github.com/repos/hyprwm/Hyprland/releases/latest",
            "https://api.github.com/repos/hyprwm/Hyprland/releases/tags/v0.57.1/assets",
            "https://api.github.com/repos/hyprwm/Hyprland/releases/tags/v0.57.1#x",
            "https://api.github.com/repos/hyprwm/Hyprland/releases/tags/v0.57.1%2F..",
            "https://api.github.com/repos/hyprwm/Hyprland/releases/tags/v0.57.1\n",
            "https://user@api.github.com/repos/hyprwm/Hyprland/releases/tags/v0.57.1",
            "http://api.github.com/repos/hyprwm/Hyprland/releases/tags/v0.57.1",
        ];
        for url in rejected {
            assert!(!trusted_source_url(url), "{url}");
        }
    }

    #[test]
    fn expat_markdown_links_are_external() {
        let json = r#"{"tag_name":"R_2_10_0","draft":false,"body":"- [Blog post](https://example.org/blog)\n- [Original change log](https://example.org/changes)"}"#;

        assert_eq!(
            parse_github_release(json, "R_2_10_0"),
            ReleaseStatus::ExternalChangelog
        );
    }

    #[test]
    fn normal_release_notes_remain_verified() {
        let json =
            r#"{"tag_name":"v1.0","draft":false,"body":"Fixed crash when closing windows."}"#;

        assert_eq!(parse_github_release(json, "v1.0"), ReleaseStatus::Verified);
    }

    #[test]
    fn accepts_valid_release() {
        let json = r#"{"tag_name":"v0.57.1","draft":false,"body":"Fixed rendering."}"#;
        assert_eq!(
            parse_github_release(json, "v0.57.1"),
            ReleaseStatus::Verified
        );
    }

    #[test]
    fn rejects_wrong_tag() {
        let json = r#"{"tag_name":"v0.57.0","draft":false,"body":"Changes"}"#;
        assert_eq!(
            parse_github_release(json, "v0.57.1"),
            ReleaseStatus::Invalid
        );
    }

    #[test]
    fn rejects_invalid_json() {
        assert_eq!(
            parse_github_release("{broken", "v0.57.1"),
            ReleaseStatus::Invalid
        );
    }

    #[test]
    fn links_are_not_changelog() {
        let json = r#"{"tag_name":"R_2_10_0","draft":false,"body":"https://example.org"}"#;
        assert_eq!(
            parse_github_release(json, "R_2_10_0"),
            ReleaseStatus::NoChangelog
        );
    }

    #[test]
    fn rejects_draft() {
        let json = r#"{"tag_name":"v0.57.1","draft":true,"body":"Changes"}"#;
        assert_eq!(
            parse_github_release(json, "v0.57.1"),
            ReleaseStatus::Invalid
        );
    }

    #[test]
    fn trusted_hyprland_url() {
        assert!(trusted_source_url(
            "https://api.github.com/repos/hyprwm/Hyprland/releases/tags/v0.57.1"
        ));
    }

    #[test]
    fn trusted_expat_url() {
        assert!(trusted_source_url(
            "https://api.github.com/repos/libexpat/libexpat/releases/tags/R_2_10_0"
        ));
    }

    #[test]
    fn trusted_kwin_url() {
        assert!(trusted_source_url(
            "https://gitlab.archlinux.org/api/v4/projects/archlinux%2Fpackaging%2Fpackages%2Fkwin/repository/commits?per_page=20"
        ));
    }

    #[test]
    fn rejects_untrusted_domain() {
        assert!(!trusted_source_url(
            "https://evil.example/api.github.com/repos/hyprwm/Hyprland/releases/tags/v0.57.1"
        ));
    }

    #[test]
    fn rejects_url_suffix_injection() {
        assert!(!trusted_source_url(
            "https://api.github.com/repos/hyprwm/Hyprland/releases/tags/v0.57.1?redirect=https://evil.example"
        ));
    }
}
