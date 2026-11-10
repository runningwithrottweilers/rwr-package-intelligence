#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    UpstreamVersion,
    PackageRevision,
    EpochChange,
    Unchanged,
    Unknown,
}

fn split_version(version: &str) -> Option<(u64, &str, &str)> {
    let (epoch, rest) = match version.split_once(":") {
        Some((epoch, rest)) => (epoch.parse::<u64>().ok()?, rest),
        None => (0, version),
    };

    let (pkgver, pkgrel) = rest.rsplit_once("-")?;

    if pkgver.is_empty() || pkgrel.is_empty() {
        return None;
    }

    if !pkgrel.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }

    Some((epoch, pkgver, pkgrel))
}

/// Arch version string: `[epoch:]pkgver-pkgrel` using only characters that
/// can appear in a version. Rejects path separators and other injection.
pub fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && !version.starts_with(['.', '-', ':'])
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+' | ':' | '~'))
        && split_version(version).is_some()
}

/// The upstream part (`pkgver`) of a full Arch version, without epoch and pkgrel.
pub fn upstream_version(version: &str) -> Option<&str> {
    if !valid_version(version) {
        return None;
    }
    split_version(version).map(|(_, pkgver, _)| pkgver)
}

impl ChangeKind {
    /// True when the upstream software itself changes (new pkgver).
    pub fn is_upstream(self) -> bool {
        self == Self::UpstreamVersion
    }

    /// True when only Arch packaging metadata changes (pkgrel or epoch).
    pub fn is_arch_packaging(self) -> bool {
        matches!(self, Self::PackageRevision | Self::EpochChange)
    }
}

pub fn detect_change(installed: &str, available: &str) -> ChangeKind {
    let Some((old_epoch, old_ver, old_rel)) = split_version(installed) else {
        return ChangeKind::Unknown;
    };
    let Some((new_epoch, new_ver, new_rel)) = split_version(available) else {
        return ChangeKind::Unknown;
    };

    if old_epoch != new_epoch {
        ChangeKind::EpochChange
    } else if old_ver != new_ver {
        ChangeKind::UpstreamVersion
    } else if old_rel != new_rel {
        ChangeKind::PackageRevision
    } else {
        ChangeKind::Unchanged
    }
}

/// Port of libalpm's `rpmvercmp` for a single version segment (pkgver or pkgrel).
/// Pure comparison only; does not call pacman.
pub fn rpmvercmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    if a == b {
        return Ordering::Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0usize, 0usize);

    while i < a.len() && j < b.len() {
        let (sep_i, sep_j) = (i, j);
        while i < a.len() && !a[i].is_ascii_alphanumeric() {
            i += 1;
        }
        while j < b.len() && !b[j].is_ascii_alphanumeric() {
            j += 1;
        }
        if i >= a.len() || j >= b.len() {
            break;
        }
        // Different separator lengths decide the comparison.
        if i - sep_i != j - sep_j {
            return (i - sep_i).cmp(&(j - sep_j));
        }

        let numeric = a[i].is_ascii_digit();
        let (start_i, start_j) = (i, j);
        let same_kind = |c: u8| {
            if numeric {
                c.is_ascii_digit()
            } else {
                c.is_ascii_alphabetic()
            }
        };
        while i < a.len() && same_kind(a[i]) {
            i += 1;
        }
        while j < b.len() && same_kind(b[j]) {
            j += 1;
        }
        // Segment types differ: numeric is newer than alphabetic.
        if j == start_j {
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        let mut seg_a = &a[start_i..i];
        let mut seg_b = &b[start_j..j];
        if numeric {
            while seg_a.len() > 1 && seg_a[0] == b'0' {
                seg_a = &seg_a[1..];
            }
            while seg_b.len() > 1 && seg_b[0] == b'0' {
                seg_b = &seg_b[1..];
            }
            if seg_a.len() != seg_b.len() {
                return seg_a.len().cmp(&seg_b.len());
            }
        }
        match seg_a.cmp(seg_b) {
            Ordering::Equal => {}
            other => return other,
        }
    }

    let a_done = i >= a.len();
    let b_done = j >= b.len();
    if a_done && b_done {
        return Ordering::Equal;
    }
    // A remaining alphabetic part never beats an empty string.
    let a_alpha = !a_done && a[i].is_ascii_alphabetic();
    let b_alpha = !b_done && b[j].is_ascii_alphabetic();
    if (a_done && !b_alpha) || a_alpha {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// Full Arch version comparison (`[epoch:]pkgver[-pkgrel]`), as `vercmp`.
pub fn vercmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    fn parts(version: &str) -> (u64, &str, Option<&str>) {
        let (epoch, rest) = match version.split_once(':') {
            Some((epoch, rest)) => (epoch.parse().unwrap_or(0), rest),
            None => (0, version),
        };
        match rest.rsplit_once('-') {
            Some((pkgver, pkgrel)) => (epoch, pkgver, Some(pkgrel)),
            None => (epoch, rest, None),
        }
    }

    if a == b {
        return Ordering::Equal;
    }
    let (epoch_a, ver_a, rel_a) = parts(a);
    let (epoch_b, ver_b, rel_b) = parts(b);
    epoch_a
        .cmp(&epoch_b)
        .then_with(|| rpmvercmp(ver_a, ver_b))
        .then_with(|| match (rel_a, rel_b) {
            (Some(x), Some(y)) => rpmvercmp(x, y),
            _ => Ordering::Equal,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_expat() {
        assert_eq!(
            detect_change("2.9.0-1", "2.10.0-1"),
            ChangeKind::UpstreamVersion
        );
    }

    #[test]
    fn upstream_hyprland() {
        assert_eq!(
            detect_change("0.57.0-3", "0.57.1-1"),
            ChangeKind::UpstreamVersion
        );
    }

    #[test]
    fn revision_kwin() {
        assert_eq!(
            detect_change("6.8.2-1", "6.8.2-2"),
            ChangeKind::PackageRevision
        );
    }

    #[test]
    fn revision_mpv_with_epoch() {
        assert_eq!(
            detect_change("1:0.41.0-6", "1:0.41.0-7"),
            ChangeKind::PackageRevision
        );
    }

    #[test]
    fn epoch_change() {
        assert_eq!(detect_change("1:2.0-1", "2:2.0-1"), ChangeKind::EpochChange);
    }

    #[test]
    fn unchanged_version() {
        assert_eq!(detect_change("1.0-1", "1.0-1"), ChangeKind::Unchanged);
    }

    #[test]
    fn unknown_format() {
        assert_eq!(detect_change("invalid", "2.0-1"), ChangeKind::Unknown);
    }

    #[test]
    fn upstream_version_strips_epoch_and_pkgrel() {
        assert_eq!(upstream_version("1:0.41.0-7"), Some("0.41.0"));
        assert_eq!(upstream_version("2.10.0-1"), Some("2.10.0"));
        assert_eq!(upstream_version("26.05-1.1"), Some("26.05"));
        assert_eq!(upstream_version("invalid"), None);
        assert_eq!(upstream_version("../1.0-1"), None);
        assert_eq!(upstream_version("1.0/x-1"), None);
    }

    #[test]
    fn version_validation_rejects_injection() {
        assert!(valid_version("1:0.41.0-7"));
        assert!(valid_version("2025.10.22-1"));
        assert!(!valid_version(""));
        assert!(!valid_version("1.0-1/../../etc"));
        assert!(!valid_version("1.0-1?x=1"));
        assert!(!valid_version("1.0 -1"));
        assert!(!valid_version("1.0-rc"));
    }

    #[test]
    fn upstream_and_packaging_changes_are_distinct() {
        assert!(detect_change("0.57.0-3", "0.57.1-1").is_upstream());
        assert!(!detect_change("0.57.0-3", "0.57.1-1").is_arch_packaging());
        assert!(detect_change("6.8.2-1", "6.8.2-2").is_arch_packaging());
        assert!(!detect_change("6.8.2-1", "6.8.2-2").is_upstream());
        assert!(detect_change("1:2.0-1", "2:2.0-1").is_arch_packaging());
        assert!(!detect_change("1.0-1", "1.0-1").is_upstream());
        assert!(!detect_change("1.0-1", "1.0-1").is_arch_packaging());
    }

    #[test]
    fn rpmvercmp_matches_pacman_documented_order() {
        use std::cmp::Ordering::Less;
        // Order documented in vercmp(8).
        let order = [
            "1.0a", "1.0alpha", "1.0b", "1.0beta", "1.0p", "1.0pre", "1.0rc", "1.0", "1.0.a",
            "1.0.1",
        ];
        for pair in order.windows(2) {
            assert_eq!(
                rpmvercmp(pair[0], pair[1]),
                Less,
                "{} < {}",
                pair[0],
                pair[1]
            );
            assert_eq!(rpmvercmp(pair[1], pair[0]), Less.reverse());
        }
        let numeric = ["1", "1.0", "1.1", "1.1.1", "1.2", "2.0", "3.0.0"];
        for pair in numeric.windows(2) {
            assert_eq!(
                rpmvercmp(pair[0], pair[1]),
                Less,
                "{} < {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn rpmvercmp_numeric_segments() {
        use std::cmp::Ordering::*;
        assert_eq!(rpmvercmp("0.57.1", "0.57.10"), Less);
        assert_eq!(rpmvercmp("2.10.0", "2.9.0"), Greater);
        assert_eq!(rpmvercmp("1.001", "1.1"), Equal);
        assert_eq!(rpmvercmp("2025.10.22", "2025.9.30"), Greater);
        assert_eq!(rpmvercmp("1.0", "1.0"), Equal);
    }

    #[test]
    fn vercmp_full_versions() {
        use std::cmp::Ordering::*;
        assert_eq!(vercmp("1:0.41.0-7", "0.99-1"), Greater);
        assert_eq!(vercmp("6.8.2-1", "6.8.2-2"), Less);
        assert_eq!(vercmp("6.8.2-2", "6.8.2-10"), Less);
        assert_eq!(vercmp("1.0-1", "1.0-1.1"), Less);
        assert_eq!(vercmp("1.0-2", "1.0"), Equal);
        assert_eq!(vercmp("2.10.0-1", "2.9.0-5"), Greater);
    }

    #[test]
    fn package_version_with_hyphen() {
        assert_eq!(
            detect_change("1.0-rc1-1", "1.0-rc2-1"),
            ChangeKind::UpstreamVersion
        );
    }
}
