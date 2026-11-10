// RWR PACKAGE INTELLIGENCE — change items extracted from verified sources.
//
// Every item text is copied from the source (release notes or Arch packaging
// commits), only stripped of Markdown/link noise and shortened. Categories are
// assigned from the source's own section headings, conventional-commit
// prefixes and explicit keywords. A line that matches nothing is `Other` —
// it is never promoted to a fix, feature or security change by guessing.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChangeCategory {
    Security,
    Breaking,
    BugFix,
    Feature,
    Technical,
    Other,
}

impl ChangeCategory {
    pub const ALL: [ChangeCategory; 6] = [
        Self::Security,
        Self::Breaking,
        Self::BugFix,
        Self::Feature,
        Self::Technical,
        Self::Other,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeItem {
    pub category: ChangeCategory,
    pub text: String,
}

pub const MAX_ITEM_CHARS: usize = 200;
const MAX_ITEMS_PER_SOURCE: usize = 400;

/// Category implied by a section heading such as `## Bug fixes`.
/// Matching is done on whole words (or word stems), never on substrings of
/// unrelated words.
fn heading_category(heading: &str) -> Option<ChangeCategory> {
    let lower = heading.to_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let has = |stems: &[&str]| words.iter().any(|w| stems.iter().any(|s| w.starts_with(s)));
    let is = |exact: &[&str]| words.iter().any(|w| exact.contains(w));

    if has(&["security", "vulnerab"]) || is(&["cve", "cves"]) {
        Some(ChangeCategory::Security)
    } else if has(&["breaking", "incompatib"]) {
        Some(ChangeCategory::Breaking)
    } else if has(&["fix", "bugfix", "regression"]) || is(&["bug", "bugs"]) {
        Some(ChangeCategory::BugFix)
    } else if has(&[
        "feature",
        "addition",
        "enhancement",
        "improvement",
        "highlight",
    ]) || is(&["new", "added", "add"])
    {
        Some(ChangeCategory::Feature)
    } else if has(&[
        "internal",
        "packaging",
        "dependenc",
        "chore",
        "refactor",
        "documentation",
        "maintenance",
        "translation",
        "performance",
    ]) || is(&[
        "build", "builds", "docs", "doc", "ci", "test", "tests", "testing", "deps",
    ]) {
        Some(ChangeCategory::Technical)
    } else {
        None
    }
}

/// Conventional-commit style prefix (`fix:`, `feat(ui):`, ...).
fn prefix_category(lower: &str) -> Option<ChangeCategory> {
    let (head, _) = lower.split_once(':')?;
    let head = head.split('(').next().unwrap_or(head).trim_end_matches('!');
    if lower.split_once(':').is_some_and(|(h, _)| h.ends_with('!')) {
        return Some(ChangeCategory::Breaking);
    }
    match head.trim() {
        "security" => Some(ChangeCategory::Security),
        "fix" | "bugfix" | "bugfixes" | "hotfix" => Some(ChangeCategory::BugFix),
        "feat" | "feature" => Some(ChangeCategory::Feature),
        "chore" | "build" | "ci" | "docs" | "doc" | "refactor" | "style" | "test" | "tests"
        | "perf" | "deps" | "cleanup" => Some(ChangeCategory::Technical),
        _ => None,
    }
}

fn starts_with_word(lower: &str, words: &[&str]) -> bool {
    words.iter().any(|word| {
        lower
            .strip_prefix(word)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with([' ', ':', '(', ',']))
    })
}

/// Category of a single line, given the enclosing section (if any).
pub fn categorize(line: &str, section: Option<ChangeCategory>) -> ChangeCategory {
    let lower = line.to_lowercase();

    // Explicit security markers always win.
    if lower.contains("cve-") || lower.contains("security") || lower.contains("vulnerab") {
        return ChangeCategory::Security;
    }
    if let Some(category) = prefix_category(&lower) {
        return category;
    }
    if let Some(section) = section {
        return section;
    }
    // Packaging housekeeping markers (Arch commits) are technical regardless
    // of the leading verb ("Add nvchecker config", "New upstream release").
    if lower.contains(".srcinfo")
        || lower.contains("nvchecker")
        || lower.contains("checksum")
        || starts_with_word(&lower, &["new upstream", "upstream update", "update to"])
    {
        return ChangeCategory::Technical;
    }
    // A leading scope tag ("[ie/youtube] Fix ...") does not hide the verb.
    let lower = match lower.strip_prefix('[').and_then(|r| r.split_once("] ")) {
        Some((_, rest)) => rest.to_string(),
        None => lower,
    };
    if starts_with_word(&lower, &["breaking"]) {
        ChangeCategory::Breaking
    } else if starts_with_word(
        &lower,
        &[
            "fix",
            "fixed",
            "fixes",
            "fixing",
            "resolve",
            "resolved",
            "resolves",
            "correct",
            "corrected",
        ],
    ) {
        ChangeCategory::BugFix
    } else if starts_with_word(
        &lower,
        &[
            "add",
            "added",
            "adds",
            "new",
            "implement",
            "implemented",
            "introduce",
            "introduced",
            "support",
            "allow",
            "allows",
        ],
    ) {
        ChangeCategory::Feature
    } else if starts_with_word(
        &lower,
        &[
            "rebuild",
            "rebuilt",
            "bump",
            "bumped",
            "update dependency",
            "update dependencies",
            "refactor",
            "build",
            "ci",
            "docs",
            "chore",
            "remove unused",
            "upstream update",
            "update to",
            "new upstream",
        ],
    ) {
        ChangeCategory::Technical
    } else {
        ChangeCategory::Other
    }
}

/// Strips Markdown and GitHub-generated noise; returns `None` for lines that
/// carry no change description (links only, images, separators, trailers).
pub fn clean_line(raw: &str) -> Option<String> {
    let mut line = raw.trim();
    for prefix in ["- [ ] ", "- [x] ", "* ", "- ", "+ ", "• "] {
        if let Some(rest) = line.strip_prefix(prefix) {
            line = rest.trim();
        }
    }
    let lower = line.to_lowercase();
    if line.is_empty()
        || line.starts_with("![")
        || line.starts_with("```")
        || line.starts_with("<!--")
        || line.starts_with('|')
        || line.starts_with("---")
        || lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("signed-off-by:")
        || lower.starts_with("co-authored-by:")
        || lower.starts_with("reviewed-by:")
        || lower.starts_with("full changelog")
        || lower.starts_with("**full changelog")
        || lower.starts_with("new contributors")
        || lower.starts_with("merge branch")
        || lower.starts_with("merge pull request")
        || lower.contains("made their first contribution")
        || line.chars().any(|c| c.is_control())
    {
        return None;
    }

    // [text](url) → text
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(open) = rest.find('[') {
        let after = &rest[open + 1..];
        match after.find("](") {
            Some(close) if !after[..close].contains('[') => {
                let tail = &after[close + 2..];
                match tail.find(')') {
                    Some(end) => {
                        out.push_str(&rest[..open]);
                        out.push_str(&after[..close]);
                        rest = &tail[end + 1..];
                    }
                    None => break,
                }
            }
            _ => {
                out.push_str(&rest[..=open]);
                rest = after;
            }
        }
    }
    out.push_str(rest);

    // GitHub generated notes: "... by @user in https://github.com/.../pull/1"
    if let Some(pos) = out.find(" by @") {
        out.truncate(pos);
    }
    if let Some(pos) = out.find(" in https://") {
        out.truncate(pos);
    }
    let text = out.replace("**", "").replace("__", "");
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let text = text.trim_end_matches([',', ';']).trim().to_string();

    // A bare URL or a bare reference carries no description.
    let has_words = text.chars().filter(|c| c.is_alphabetic()).count() >= 3;
    if !has_words || text.starts_with("http") {
        return None;
    }
    Some(shorten(&text))
}

fn shorten(text: &str) -> String {
    if text.chars().count() <= MAX_ITEM_CHARS {
        return text.to_string();
    }
    let mut cut: String = text.chars().take(MAX_ITEM_CHARS - 1).collect();
    if let Some(space) = cut.rfind(' ') {
        if space > MAX_ITEM_CHARS / 2 {
            cut.truncate(space);
        }
    }
    format!("{}…", cut.trim_end())
}

/// Level for headings without `#` markers (bold or `Word:` lines): they nest
/// below every Markdown heading.
const INLINE_HEADING_LEVEL: usize = 7;

/// A heading line and its nesting level (`#` = 1 ... `######` = 6).
fn heading_text(line: &str) -> Option<(usize, &str)> {
    let trimmed = line.trim();
    if trimmed.starts_with('#') {
        let level = trimmed.chars().take_while(|c| *c == '#').count();
        return Some((level, trimmed[level..].trim()));
    }
    // **Bug fixes** / **Bug fixes:** on its own line
    if let Some(inner) = trimmed
        .strip_prefix("**")
        .and_then(|r| r.strip_suffix("**"))
    {
        if !inner.contains("**") {
            return Some((INLINE_HEADING_LEVEL, inner.trim_end_matches(':').trim()));
        }
    }
    if let Some(inner) = trimmed
        .strip_prefix("**")
        .and_then(|r| r.strip_suffix(":**"))
    {
        return Some((INLINE_HEADING_LEVEL, inner.trim()));
    }
    // "Fixes:" alone on a line
    if trimmed.ends_with(':') && trimmed.len() <= 40 && !trimmed.contains(' ') {
        return Some((INLINE_HEADING_LEVEL, trimmed.trim_end_matches(':')));
    }
    None
}

/// Sections that are not a list of changes (credits, downloads, install
/// instructions). Their lines — including sub-sections — are skipped.
fn non_change_heading(heading: &str) -> bool {
    let lower = heading.to_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let has = |stems: &[&str]| words.iter().any(|w| stems.iter().any(|s| w.starts_with(s)));
    has(&[
        "thank",
        "supporter",
        "sponsor",
        "donat",
        "contributor",
        "install",
        "download",
        "asset",
        "checksum",
        "sha256",
        "acknowledg",
        "credit",
        "patron",
    ]) || lower.contains("description of the various files")
        || lower.contains("full changelog")
}

/// Items from a GitHub release body.
pub fn items_from_release_notes(body: &str) -> Vec<ChangeItem> {
    // Open headings: (level, category, skipped).
    let mut stack: Vec<(usize, Option<ChangeCategory>, bool)> = Vec::new();
    let mut items = Vec::new();
    for line in body.lines() {
        if items.len() >= MAX_ITEMS_PER_SOURCE {
            break;
        }
        if let Some((level, heading)) = heading_text(line) {
            stack.retain(|(open, _, _)| *open < level);
            stack.push((
                level,
                heading_category(heading),
                non_change_heading(heading),
            ));
            continue;
        }
        if stack.iter().any(|(_, _, skipped)| *skipped) {
            continue;
        }
        // Nearest heading with a category; sub-headings such as "Changed"
        // under "Features" inherit it.
        let section = stack.iter().rev().find_map(|(_, category, _)| *category);
        if let Some(text) = clean_line(line) {
            items.push(ChangeItem {
                category: categorize(&text, section),
                text,
            });
        }
    }
    items
}

/// Item from an Arch packaging commit title/description (already stripped of
/// the `upgpkg:` prefix by the caller).
pub fn item_from_commit_text(text: &str) -> Option<ChangeItem> {
    let text = clean_line(text)?;
    Some(ChangeItem {
        category: categorize(&text, None),
        text,
    })
}

/// Most important items first: by category priority, then source order.
/// Returns the selection and the number of omitted items.
pub fn highlights(
    items: &[ChangeItem],
    max_per_category: usize,
    max_total: usize,
) -> (Vec<&ChangeItem>, usize) {
    let mut selected = Vec::new();
    for category in ChangeCategory::ALL {
        let picked = items
            .iter()
            .filter(|item| item.category == category)
            .take(max_per_category);
        for item in picked {
            if selected.len() < max_total {
                selected.push(item);
            }
        }
    }
    let omitted = items.len() - selected.len();
    (selected, omitted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ChangeCategory::*;

    #[test]
    fn sections_assign_categories() {
        let body = "## Security\n- Fix heap overflow in parser (CVE-2025-1234)\n\n## Bug fixes\n- Crash when closing window\n\n### New features\n- Lua configuration\n\n## Internal\n- Bump wlroots\n";
        let items = items_from_release_notes(body);
        let cats: Vec<_> = items.iter().map(|i| i.category).collect();
        assert_eq!(cats, [Security, BugFix, Feature, Technical]);
        assert_eq!(items[1].text, "Crash when closing window");
    }

    #[test]
    fn security_keywords_override_section() {
        let body = "## Bug fixes\n- Fix out-of-bounds read (CVE-2025-0001)\n";
        assert_eq!(items_from_release_notes(body)[0].category, Security);
    }

    #[test]
    fn conventional_commit_prefixes() {
        assert_eq!(categorize("fix(ui): crash on start", None), BugFix);
        assert_eq!(categorize("feat: lua config", None), Feature);
        assert_eq!(categorize("feat!: drop old config", None), Breaking);
        assert_eq!(categorize("chore: update deps", Some(Feature)), Technical);
        assert_eq!(categorize("ci: add runner", None), Technical);
    }

    #[test]
    fn unsectioned_lines_use_leading_verb_only() {
        assert_eq!(
            categorize("Fixed crash when closing windows.", None),
            BugFix
        );
        assert_eq!(categorize("Add support for HDR", None), Feature);
        assert_eq!(categorize("Rebuild for icu 77", None), Technical);
        // "Prefix" must not match "fix"; unknown text stays Other.
        assert_eq!(categorize("Prefixes are now trimmed", None), Other);
        assert_eq!(categorize("As usual, a small update.", None), Other);
    }

    #[test]
    fn github_generated_notes_are_cleaned() {
        let line = "* fix: crash on resize by @someone in https://github.com/o/r/pull/12";
        assert_eq!(clean_line(line).as_deref(), Some("fix: crash on resize"));
        let line = "- Fixed [issue #3](https://github.com/o/r/issues/3) in renderer";
        assert_eq!(
            clean_line(line).as_deref(),
            Some("Fixed issue #3 in renderer")
        );
    }

    #[test]
    fn noise_lines_are_dropped() {
        for line in [
            "",
            "https://example.org",
            "![screenshot](https://x/y.png)",
            "**Full Changelog**: https://github.com/o/r/compare/v1...v2",
            "* @x made their first contribution in https://github.com/o/r/pull/1",
            "Signed-off-by: A <a@b>",
            "---",
            "```",
            "#123",
        ] {
            assert_eq!(clean_line(line), None, "{line:?}");
        }
    }

    #[test]
    fn long_lines_are_shortened() {
        let long = format!("Fixed {}", "word ".repeat(80));
        let text = clean_line(&long).unwrap();
        assert!(text.chars().count() <= MAX_ITEM_CHARS);
        assert!(text.ends_with('…'));
    }

    #[test]
    fn heading_words_do_not_match_inside_other_words() {
        assert_eq!(heading_category("Special thanks"), None);
        assert_eq!(heading_category("Latest release"), None);
        assert_eq!(heading_category("Prefix handling"), None);
        assert_eq!(heading_category("Removed"), None);
        assert_eq!(heading_category("CI"), Some(Technical));
        assert_eq!(heading_category("What's new"), Some(Feature));
        assert_eq!(heading_category("Bug Fixes"), Some(BugFix));
        assert_eq!(heading_category("Security fixes"), Some(Security));
    }

    /// Real heading layouts seen on 2026-11-09 (Hyprland, neovim, mpv, yt-dlp).
    #[test]
    fn credit_and_install_sections_are_skipped() {
        let hyprland = "## Fixes Backported\n - fix crash\n## Special thanks\n#### Top Supporters:\nAlice, Bob, Carol\n#### New Monthly Supporters:\nlazy_sleepers, jar0, Dave\n**Full Changelog**: https://github.com/x/y/compare/a...b\n";
        let items = items_from_release_notes(hyprland);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].category, BugFix);

        let neovim = "## Release notes\n- Changelog for v0.12.6\n## Install\n### Windows\n#### Zip\n1. Download nvim-win64.zip\n### Linux (x86_64)\n- tar xzvf nvim.tar.gz\n";
        let texts: Vec<_> = items_from_release_notes(neovim)
            .into_iter()
            .map(|i| i.text)
            .collect();
        assert_eq!(texts, ["Changelog for v0.12.6"]);

        let ytdlp = "#### A description of the various files is in the README\n- yt-dlp.exe Windows build\n#### Important changes\n- [ie/youtube] Fix signature extraction\n#### Misc. changes\n- **cleanup**: Miscellaneous\n";
        let cats: Vec<_> = items_from_release_notes(ytdlp)
            .into_iter()
            .map(|i| i.category)
            .collect();
        assert_eq!(cats, [BugFix, Technical]);
    }

    #[test]
    fn sub_headings_inherit_parent_category() {
        let mpv = "# Features\n## New\n- vo_gpu: something\n## Changed\n- default changed\n# Fixes and Minor Enhancements\n- player: thing\n";
        let cats: Vec<_> = items_from_release_notes(mpv)
            .into_iter()
            .map(|i| i.category)
            .collect();
        assert_eq!(cats, [Feature, Feature, BugFix]);
    }

    #[test]
    fn arch_upstream_release_titles_are_technical() {
        assert_eq!(categorize("New upstream release", None), Technical);
        assert_eq!(categorize("Update to 6.8.2", None), Technical);
        assert_eq!(categorize("Upstream update", None), Technical);
    }

    #[test]
    fn bold_headings_are_recognized() {
        let body = "**Bug fixes:**\n- crash\n**Features**\n- thing\n";
        let cats: Vec<_> = items_from_release_notes(body)
            .iter()
            .map(|i| i.category)
            .collect();
        assert_eq!(cats, [BugFix, Feature]);
    }

    #[test]
    fn highlights_prioritise_security_and_count_omitted() {
        let items = vec![
            ChangeItem {
                category: Other,
                text: "o".into(),
            },
            ChangeItem {
                category: Feature,
                text: "f1".into(),
            },
            ChangeItem {
                category: Feature,
                text: "f2".into(),
            },
            ChangeItem {
                category: Feature,
                text: "f3".into(),
            },
            ChangeItem {
                category: Security,
                text: "s".into(),
            },
            ChangeItem {
                category: BugFix,
                text: "b".into(),
            },
        ];
        let (picked, omitted) = highlights(&items, 2, 4);
        let texts: Vec<_> = picked.iter().map(|i| i.text.as_str()).collect();
        assert_eq!(texts, ["s", "b", "f1", "f2"]);
        assert_eq!(omitted, 2);
    }

    #[test]
    fn empty_body_has_no_items() {
        assert!(items_from_release_notes("").is_empty());
        assert!(items_from_release_notes("https://example.org\n").is_empty());
    }

    #[test]
    fn commit_text_item() {
        let item = item_from_commit_text("Add patch for CVE-2025-9999").unwrap();
        assert_eq!(item.category, Security);
        assert_eq!(
            item_from_commit_text("Rebuild for llvm 21")
                .unwrap()
                .category,
            Technical
        );
    }
}
