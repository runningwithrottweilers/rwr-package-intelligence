#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    System,
    Kernel,
    Drivers,
    SecurityTools,
    Network,
    Desktop,
    Libraries,
    Applications,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attention {
    Elevated,
    Normal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classification {
    pub category: Category,
    pub attention: Attention,
}

pub fn classify(name: &str) -> Classification {
    let category = match name {
        "pacman" | "systemd" | "mkinitcpio" | "dracut" | "grub" | "systemd-boot" => {
            Category::System
        }

        "linux" | "linux-lts" | "linux-zen" | "linux-hardened" | "linux-firmware" => {
            Category::Kernel
        }

        "mesa" | "vulkan-intel" | "vulkan-radeon" | "nvidia" | "nvidia-open" | "nvidia-utils"
        | "xf86-video-intel" | "xf86-video-amdgpu" => Category::Drivers,

        "openssl" | "gnupg" | "sudo" | "polkit" | "openssh" | "ca-certificates" => {
            Category::SecurityTools
        }

        "networkmanager" | "systemd-resolvconf" | "iwd" | "wpa_supplicant" | "wireguard-tools"
        | "systemd-networkd" => Category::Network,

        "hyprland"
        | "kwin"
        | "plasma-desktop"
        | "gnome-shell"
        | "sway"
        | "waybar"
        | "xdg-desktop-portal-hyprland" => Category::Desktop,

        "glibc" | "gcc-libs" | "openssl-1.1" | "expat" | "zlib" | "libarchive" | "libnm" => {
            Category::Libraries
        }

        "firefox" | "chromium" | "mpv" | "obsidian" | "discord" | "vlc" | "thunderbird" => {
            Category::Applications
        }

        _ => Category::Other,
    };

    let attention = match name {
        "linux" | "linux-lts" | "linux-zen" | "linux-hardened" | "linux-firmware" | "glibc"
        | "systemd" | "pacman" | "mkinitcpio" | "dracut" | "grub" | "systemd-boot" | "sudo"
        | "polkit" | "openssl" | "networkmanager" | "hyprland" | "kwin" | "gnome-shell" => {
            Attention::Elevated
        }
        _ => Attention::Normal,
    };

    Classification {
        category,
        attention,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_kernel() {
        assert_eq!(classify("linux").category, Category::Kernel);
    }

    #[test]
    fn recognizes_drivers() {
        assert_eq!(classify("mesa").category, Category::Drivers);
    }

    #[test]
    fn recognizes_network() {
        assert_eq!(classify("networkmanager").category, Category::Network);
    }

    #[test]
    fn recognizes_desktop() {
        assert_eq!(classify("hyprland").category, Category::Desktop);
    }

    #[test]
    fn recognizes_libraries() {
        assert_eq!(classify("glibc").category, Category::Libraries);
    }

    #[test]
    fn marks_critical_components_for_attention() {
        assert_eq!(classify("pacman").attention, Attention::Elevated);
    }

    #[test]
    fn unknown_package_is_not_assumed_dangerous() {
        let result = classify("unknown-package");
        assert_eq!(result.category, Category::Other);
        assert_eq!(result.attention, Attention::Normal);
    }
}

#[cfg(test)]
mod stage15d_tests {
    use super::*;

    #[test]
    fn recognizes_system_packages() {
        assert_eq!(classify("pacman").category, Category::System);
        assert_eq!(classify("systemd").category, Category::System);
    }

    #[test]
    fn attention_is_not_a_security_verdict() {
        assert_eq!(classify("pacman").attention, Attention::Elevated);
        assert_eq!(classify("unknown-package").attention, Attention::Normal);
    }
}
