// RWR PACKAGE INTELLIGENCE — ETAP 2B
// Pure download progress calculation. No system commands.

use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct DownloadTracker {
    packages: HashMap<String, (u64, u64)>,
}

impl DownloadTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_package(&mut self, name: &str, total: u64) -> Result<(), String> {
        if name.is_empty() || total == 0 {
            return Err("Invalid package".into());
        }

        if self.packages.contains_key(name) {
            return Err("Duplicate package".into());
        }

        self.packages.insert(name.to_string(), (0, total));
        Ok(())
    }

    pub fn update(&mut self, name: &str, downloaded: u64) -> Result<(), String> {
        let Some((current, total)) = self.packages.get_mut(name) else {
            return Err("Unknown package".into());
        };

        if downloaded > *total {
            return Err("Downloaded bytes exceed package size".into());
        }

        if downloaded < *current {
            return Err("Download progress cannot decrease".into());
        }

        *current = downloaded;
        Ok(())
    }

    pub fn percent(&self) -> u8 {
        let mut downloaded = 0_u128;
        let mut total = 0_u128;

        for (current, size) in self.packages.values() {
            downloaded += u128::from(*current);
            total += u128::from(*size);
        }

        if total == 0 {
            return 0;
        }

        ((downloaded * 100) / total) as u8
    }

    pub fn is_complete(&self) -> bool {
        !self.packages.is_empty()
            && self
                .packages
                .values()
                .all(|(downloaded, total)| downloaded == total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_empty() {
        let tracker = DownloadTracker::new();
        assert_eq!(tracker.percent(), 0);
        assert!(!tracker.is_complete());
    }

    #[test]
    fn calculates_single_package() {
        let mut tracker = DownloadTracker::new();
        tracker.add_package("linux", 100).unwrap();
        tracker.update("linux", 50).unwrap();
        assert_eq!(tracker.percent(), 50);
    }

    #[test]
    fn weights_by_package_size() {
        let mut tracker = DownloadTracker::new();
        tracker.add_package("small", 100).unwrap();
        tracker.add_package("large", 900).unwrap();
        tracker.update("small", 100).unwrap();
        assert_eq!(tracker.percent(), 10);
    }

    #[test]
    fn rejects_invalid_download() {
        let mut tracker = DownloadTracker::new();
        tracker.add_package("linux", 100).unwrap();
        assert!(tracker.update("linux", 101).is_err());
        assert!(tracker.update("missing", 10).is_err());
    }

    #[test]
    fn rejects_regression_and_duplicates() {
        let mut tracker = DownloadTracker::new();
        tracker.add_package("linux", 100).unwrap();
        tracker.update("linux", 80).unwrap();
        assert!(tracker.update("linux", 50).is_err());
        assert!(tracker.add_package("linux", 100).is_err());
    }

    #[test]
    fn detects_completion() {
        let mut tracker = DownloadTracker::new();
        tracker.add_package("linux", 100).unwrap();
        tracker.add_package("mesa", 200).unwrap();
        tracker.update("linux", 100).unwrap();
        tracker.update("mesa", 200).unwrap();
        assert_eq!(tracker.percent(), 100);
        assert!(tracker.is_complete());
    }
}
