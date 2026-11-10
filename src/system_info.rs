// RWR PACKAGE INTELLIGENCE — read-only system information

pub struct SystemInfo {
    pub distribution: String,
    pub kernel: String,
    pub desktop: String,
    pub installed_packages: Option<usize>,
}

pub fn read() -> SystemInfo {
    let distribution = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("PRETTY_NAME="))
                .map(|value| value.trim_matches(char::from(34)).to_string())
        })
        .unwrap_or_else(|| "Linux".to_string());

    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|_| "Unknown".to_string());

    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var("HYPRLAND_INSTANCE_SIGNATURE")
                .ok()
                .map(|_| "Hyprland".to_string())
        })
        .unwrap_or_else(|| "Unknown".to_string());

    let installed_packages = crate::libalpm_ffi::AlpmHandle::new(
        std::path::Path::new("/"),
        std::path::Path::new("/var/lib/pacman"),
    )
    .ok()
    .and_then(|handle| handle.local_package_count().ok());

    SystemInfo {
        distribution,
        kernel,
        desktop,
        installed_packages,
    }
}
