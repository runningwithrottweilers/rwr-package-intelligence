// RWR PACKAGE INTELLIGENCE — DEMO DATA ONLY
use crate::packages::PackageUpdate;

pub fn sample_updates() -> Vec<PackageUpdate> {
    [
        ("linux", "6.0.0", "6.1.0"),
        ("openssl", "3.0.0", "3.1.0"),
        ("networkmanager", "1.0.0", "1.1.0"),
        ("hyprland", "0.50.0", "0.51.0"),
        ("firefox", "140.0", "141.0"),
    ]
    .into_iter()
    .map(|(name, installed, available)| PackageUpdate {
        name: name.to_string(),
        installed: installed.to_string(),
        available: available.to_string(),
    })
    .collect()
}
