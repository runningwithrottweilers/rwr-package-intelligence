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

/// Kernel packages documented by CachyOS, including compiler variants.
/// Do not classify every `linux-cachyos-*` package as a kernel: that namespace
/// also contains headers, debug symbols and prebuilt NVIDIA/ZFS modules.
pub(crate) fn is_cachyos_kernel(name: &str) -> bool {
    let base = name
        .strip_suffix("-lto")
        .or_else(|| name.strip_suffix("-gcc"))
        .unwrap_or(name);
    matches!(
        base,
        "linux-cachyos"
            | "linux-cachyos-lts"
            | "linux-cachyos-bore"
            | "linux-cachyos-bmq"
            | "linux-cachyos-eevdf"
            | "linux-cachyos-deckify"
            | "linux-cachyos-hardened"
            | "linux-cachyos-rc"
            | "linux-cachyos-server"
            | "linux-cachyos-rt-bore"
    )
}

pub fn classify(name: &str) -> Classification {
    if is_cachyos_kernel(name) {
        return Classification {
            category: Category::Kernel,
            attention: Attention::Elevated,
        };
    }
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
    fn cachyos_kernel_variants_receive_arch_kernel_attention() {
        let reference = classify("linux");
        for name in include_str!("../tests/fixtures/cachyos/kernels.txt").lines() {
            assert_eq!(classify(name), reference, "{name}");
        }
    }

    #[test]
    fn cachyos_related_packages_are_not_assumed_to_be_kernels() {
        for name in [
            "linux-cachyos-headers",
            "linux-cachyos-lts-headers",
            "linux-cachyos-hardened-lto-headers",
            "linux-cachyos-dbg",
            "linux-cachyos-nvidia",
            "linux-cachyos-nvidia-open",
            "linux-cachyos-lto-zfs",
            "linux-cachyos-tools",
            "linux-cachyos-unknown",
            "linux-cachyos-lts-lto-lto",
            "linux-cachyosfoo",
            "linux-cachyos-",
            "cachyos-settings",
        ] {
            assert!(!is_cachyos_kernel(name), "{name}");
            assert_eq!(classify(name).category, Category::Other, "{name}");
            assert_eq!(classify(name).attention, Attention::Normal, "{name}");
        }
    }

    #[test]
    fn standard_arch_kernel_and_package_classification_is_unchanged() {
        for name in [
            "linux",
            "linux-lts",
            "linux-zen",
            "linux-hardened",
            "linux-firmware",
        ] {
            assert_eq!(classify(name).category, Category::Kernel, "{name}");
            assert_eq!(classify(name).attention, Attention::Elevated, "{name}");
        }
        for (name, category, attention) in [
            ("pacman", Category::System, Attention::Elevated),
            ("kwin", Category::Desktop, Attention::Elevated),
            ("hyprland", Category::Desktop, Attention::Elevated),
            ("polkit", Category::SecurityTools, Attention::Elevated),
            ("glibc", Category::Libraries, Attention::Elevated),
            ("mesa", Category::Drivers, Attention::Normal),
            ("firefox", Category::Applications, Attention::Normal),
            ("linux-api-headers", Category::Other, Attention::Normal),
        ] {
            assert_eq!(
                classify(name),
                Classification {
                    category,
                    attention
                },
                "{name}"
            );
        }
    }

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
