// RWR PACKAGE INTELLIGENCE — curated package descriptions (PL/EN).
//
// These texts describe WHAT a package is and WHERE an update can matter.
// They never describe what changed in a particular update: confirmed changes
// come only from verified changelog sources (changelog_fetch.rs).
// Rules for every entry:
// * no claims about fixes, features or security content;
// * no assumptions about the running session or the kind of version change;
// * impact statements limited to general, always-true facts
//   (e.g. "the new kernel is used after a reboot").
// Entries are keyed by pkgname (what the scanner reports), so split packages
// such as libnm get their own text even though they share a pkgbase.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Polish,
    English,
}

impl Language {
    pub fn code(self) -> String {
        match self {
            Self::Polish => "pl".to_string(),
            Self::English => "en".to_string(),
        }
    }
}

pub struct PackageInfo {
    pub purpose: String,
    pub impact: String,
}

pub struct InfoEntry {
    pub name: &'static str,
    pub pl_purpose: &'static str,
    pub pl_impact: &'static str,
    pub en_purpose: &'static str,
    pub en_impact: &'static str,
}

const RUNNING_PROCESS_PL: &str =
    "Działający program używa poprzedniej wersji do czasu jego ponownego uruchomienia.";
const RUNNING_PROCESS_EN: &str =
    "A running instance keeps using the previous version until it is restarted.";
const SHARED_LIBRARY_PL: &str = "Biblioteka współdzielona. Działające programy korzystają z poprzedniej wersji do czasu ich ponownego uruchomienia.";
const SHARED_LIBRARY_EN: &str =
    "Shared library. Running programs keep using the previous version until they are restarted.";
const KERNEL_PL: &str = "Nowe jądro zacznie działać dopiero po ponownym uruchomieniu komputera.";
const KERNEL_EN: &str = "The new kernel is used only after the computer is rebooted.";
const GRAPHICS_PL: &str =
    "Nowa wersja sterownika graficznego jest używana przez programy uruchomione po aktualizacji.";
const GRAPHICS_EN: &str =
    "The new graphics driver version is used by programs started after the update.";

pub const INFO_ENTRIES: &[InfoEntry] = &[
    // --- Desktop: Hyprland -------------------------------------------------
    InfoEntry {
        name: "hyprland",
        pl_purpose: "Zarządza oknami, pulpitami i animacjami Wayland.",
        pl_impact: "Dotyczy sesji Hyprland. Po aktualizacji może być potrzebne ponowne uruchomienie sesji Hyprland.",
        en_purpose: "Manages windows, workspaces and animations on Wayland.",
        en_impact: "Relevant to Hyprland sessions. Restarting the Hyprland session may be necessary after updating.",
    },
    InfoEntry {
        name: "xdg-desktop-portal-hyprland",
        pl_purpose: "Integruje aplikacje z funkcjami pulpitu Hyprland.",
        pl_impact: "Może mieć znaczenie dla udostępniania ekranu.",
        en_purpose: "Integrates applications with Hyprland desktop services.",
        en_impact: "May affect screen sharing functionality.",
    },
    InfoEntry {
        name: "hyprlock",
        pl_purpose: "Ekran blokady dla sesji Hyprland.",
        pl_impact: RUNNING_PROCESS_PL,
        en_purpose: "Screen locker for Hyprland sessions.",
        en_impact: RUNNING_PROCESS_EN,
    },
    InfoEntry {
        name: "hypridle",
        pl_purpose: "Usługa reagująca na bezczynność w sesji Hyprland (np. blokada, wygaszanie).",
        pl_impact: RUNNING_PROCESS_PL,
        en_purpose: "Idle management daemon for Hyprland sessions (e.g. locking, screen blanking).",
        en_impact: RUNNING_PROCESS_EN,
    },
    InfoEntry {
        name: "hyprpaper",
        pl_purpose: "Program ustawiający tapetę w sesji Hyprland.",
        pl_impact: RUNNING_PROCESS_PL,
        en_purpose: "Wallpaper utility for Hyprland sessions.",
        en_impact: RUNNING_PROCESS_EN,
    },
    InfoEntry {
        name: "waybar",
        pl_purpose: "Pasek stanu dla kompozytorów Wayland.",
        pl_impact: RUNNING_PROCESS_PL,
        en_purpose: "Status bar for Wayland compositors.",
        en_impact: RUNNING_PROCESS_EN,
    },
    // --- Desktop: KDE ------------------------------------------------------
    InfoEntry {
        name: "kwin",
        pl_purpose: "Kompozytor i menedżer okien KDE Plasma.",
        pl_impact: "Dotyczy sesji KDE Plasma. Po aktualizacji może być potrzebne ponowne uruchomienie sesji Plasma.",
        en_purpose: "KDE Plasma compositor and window manager.",
        en_impact: "Relevant to KDE Plasma sessions. Restarting the Plasma session may be necessary after updating.",
    },
    // --- Kernel and firmware -----------------------------------------------
    InfoEntry {
        name: "linux",
        pl_purpose: "Jądro systemu Linux (wariant standardowy Arch).",
        pl_impact: KERNEL_PL,
        en_purpose: "The Linux kernel (Arch standard variant).",
        en_impact: KERNEL_EN,
    },
    InfoEntry {
        name: "linux-lts",
        pl_purpose: "Jądro Linux z długoterminowym wsparciem (LTS).",
        pl_impact: KERNEL_PL,
        en_purpose: "Long-term support (LTS) Linux kernel.",
        en_impact: KERNEL_EN,
    },
    InfoEntry {
        name: "linux-zen",
        pl_purpose: "Jądro Linux z zestawem poprawek Zen dla komputerów osobistych.",
        pl_impact: KERNEL_PL,
        en_purpose: "Linux kernel with the Zen patch set for desktop use.",
        en_impact: KERNEL_EN,
    },
    InfoEntry {
        name: "linux-firmware",
        pl_purpose: "Oprogramowanie układowe (firmware) dla urządzeń sprzętowych.",
        pl_impact: "Nowy firmware jest zwykle ładowany przy starcie systemu lub ponownym załadowaniu sterownika.",
        en_purpose: "Firmware files for hardware devices.",
        en_impact: "New firmware is usually loaded at boot or when the driver is reloaded.",
    },
    // --- Graphics ----------------------------------------------------------
    InfoEntry {
        name: "mesa",
        pl_purpose: "Otwarte sterowniki grafiki OpenGL dla kart AMD, Intel i innych.",
        pl_impact: GRAPHICS_PL,
        en_purpose: "Open-source OpenGL graphics drivers for AMD, Intel and other GPUs.",
        en_impact: GRAPHICS_EN,
    },
    InfoEntry {
        name: "vulkan-radeon",
        pl_purpose: "Otwarty sterownik Vulkan dla kart AMD (część projektu Mesa).",
        pl_impact: GRAPHICS_PL,
        en_purpose: "Open-source Vulkan driver for AMD GPUs (part of Mesa).",
        en_impact: GRAPHICS_EN,
    },
    InfoEntry {
        name: "vulkan-intel",
        pl_purpose: "Otwarty sterownik Vulkan dla kart Intel (część projektu Mesa).",
        pl_impact: GRAPHICS_PL,
        en_purpose: "Open-source Vulkan driver for Intel GPUs (part of Mesa).",
        en_impact: GRAPHICS_EN,
    },
    // --- Core system -------------------------------------------------------
    InfoEntry {
        name: "systemd",
        pl_purpose: "Menedżer systemu i usług (proces startowy systemu).",
        pl_impact: "Usługi działające w tle mogą używać poprzedniej wersji do czasu ich ponownego uruchomienia lub restartu systemu.",
        en_purpose: "System and service manager (the system's init process).",
        en_impact: "Background services may keep using the previous version until they are restarted or the system is rebooted.",
    },
    InfoEntry {
        name: "systemd-libs",
        pl_purpose: "Biblioteki klienckie systemd używane przez inne programy.",
        pl_impact: SHARED_LIBRARY_PL,
        en_purpose: "systemd client libraries used by other programs.",
        en_impact: SHARED_LIBRARY_EN,
    },
    InfoEntry {
        name: "glibc",
        pl_purpose: "Podstawowa biblioteka języka C, używana przez niemal wszystkie programy.",
        pl_impact: SHARED_LIBRARY_PL,
        en_purpose: "The GNU C library, used by almost every program.",
        en_impact: SHARED_LIBRARY_EN,
    },
    InfoEntry {
        name: "gcc-libs",
        pl_purpose: "Biblioteki uruchomieniowe kompilatora GCC (m.in. libstdc++).",
        pl_impact: SHARED_LIBRARY_PL,
        en_purpose: "GCC runtime libraries (including libstdc++).",
        en_impact: SHARED_LIBRARY_EN,
    },
    InfoEntry {
        name: "openssl",
        pl_purpose: "Biblioteka kryptograficzna i obsługa połączeń TLS/SSL.",
        pl_impact: SHARED_LIBRARY_PL,
        en_purpose: "Cryptography library and TLS/SSL implementation.",
        en_impact: SHARED_LIBRARY_EN,
    },
    InfoEntry {
        name: "expat",
        pl_purpose: "Biblioteka analizująca dokumenty XML.",
        pl_impact: "Może wpływać na programy przetwarzające XML.",
        en_purpose: "Library for parsing XML documents.",
        en_impact: "May affect applications that process XML.",
    },
    InfoEntry {
        name: "glycin",
        pl_purpose: "Komponent do dekodowania obrazów.",
        pl_impact: "Dotyczy aplikacji korzystających z wczytywania obrazów.",
        en_purpose: "Image decoding component.",
        en_impact: "Affects applications that use its image loading functionality.",
    },
    InfoEntry {
        name: "pacman",
        pl_purpose: "Menedżer pakietów Arch Linux.",
        pl_impact: "Zmienione domyślne pliki konfiguracyjne mogą zostać zapisane jako .pacnew do ręcznego przejrzenia.",
        en_purpose: "The Arch Linux package manager.",
        en_impact: "Changed default configuration files may be saved as .pacnew for manual review.",
    },
    InfoEntry {
        name: "sudo",
        pl_purpose: "Uruchamianie poleceń z uprawnieniami innego użytkownika (zwykle administratora).",
        pl_impact: "Zmienione domyślne pliki konfiguracyjne mogą zostać zapisane jako .pacnew do ręcznego przejrzenia.",
        en_purpose: "Runs commands with another user's privileges (usually root).",
        en_impact: "Changed default configuration files may be saved as .pacnew for manual review.",
    },
    InfoEntry {
        name: "polkit",
        pl_purpose: "Autoryzacja działań administracyjnych wykonywanych przez aplikacje.",
        pl_impact: "Dotyczy okien uwierzytelniania i uprawnień aplikacji.",
        en_purpose: "Authorization framework for administrative actions requested by applications.",
        en_impact: "Relevant to authentication prompts and application privileges.",
    },
    // --- Network -----------------------------------------------------------
    InfoEntry {
        name: "networkmanager",
        pl_purpose: "Zarządza połączeniami Wi-Fi i Ethernet.",
        pl_impact: "Działająca usługa NetworkManager używa poprzedniej wersji do czasu jej ponownego uruchomienia lub restartu systemu.",
        en_purpose: "Manages Wi-Fi and Ethernet connections.",
        en_impact: "The running NetworkManager service keeps using the previous version until it is restarted or the system is rebooted.",
    },
    InfoEntry {
        name: "libnm",
        pl_purpose: "Biblioteka komunikacji z NetworkManagerem.",
        pl_impact: "Dotyczy aplikacji korzystających z zarządzania siecią.",
        en_purpose: "Library for communicating with NetworkManager.",
        en_impact: "Affects applications that integrate with network management.",
    },
    InfoEntry {
        name: "ppp",
        pl_purpose: "Obsługuje połączenia sieciowe PPP.",
        pl_impact: "Istotny dla konfiguracji sieci korzystających z PPP.",
        en_purpose: "Provides PPP network connection support.",
        en_impact: "Relevant to network setups using PPP.",
    },
    InfoEntry {
        name: "curl",
        pl_purpose: "Narzędzie i biblioteka (libcurl) do przesyłania danych przez sieć.",
        pl_impact: "Dotyczy programów i skryptów pobierających dane przez sieć.",
        en_purpose: "Command-line tool and library (libcurl) for transferring data over the network.",
        en_impact: "Affects programs and scripts that download data over the network.",
    },
    // --- Applications and tools --------------------------------------------
    InfoEntry {
        name: "firefox",
        pl_purpose: "Przeglądarka internetowa Mozilla Firefox.",
        pl_impact: "Otwarta przeglądarka może poprosić o ponowne uruchomienie po aktualizacji.",
        en_purpose: "Mozilla Firefox web browser.",
        en_impact: "A running browser may ask to be restarted after the update.",
    },
    InfoEntry {
        name: "obsidian",
        pl_purpose: "Program do notatek Markdown i dokumentacji.",
        pl_impact: "Aktualizacja aplikacji; szczegóły nowych funkcji wymagają changelogu.",
        en_purpose: "Markdown note-taking and documentation application.",
        en_impact: "Application update; details of new features require a changelog.",
    },
    InfoEntry {
        name: "mpv",
        pl_purpose: "Odtwarzacz filmów i muzyki.",
        pl_impact: "Może wpływać na odtwarzanie i obsługę formatów multimediów.",
        en_purpose: "Video and audio player.",
        en_impact: "May affect media playback and format support.",
    },
    InfoEntry {
        name: "neovim",
        pl_purpose: "Edytor tekstu oparty na Vim.",
        pl_impact: RUNNING_PROCESS_PL,
        en_purpose: "Vim-based text editor.",
        en_impact: RUNNING_PROCESS_EN,
    },
    InfoEntry {
        name: "7zip",
        pl_purpose: "Archiwizator plików 7z obsługujący wiele formatów archiwów.",
        pl_impact: "Dotyczy pakowania i rozpakowywania archiwów.",
        en_purpose: "File archiver for the 7z format with support for many archive formats.",
        en_impact: "Affects creating and extracting archives.",
    },
    InfoEntry {
        name: "yt-dlp",
        pl_purpose: "Narzędzie wiersza poleceń do pobierania materiałów audio i wideo z serwisów internetowych.",
        pl_impact: "Dotyczy obsługi serwisów, z których pobierane są materiały.",
        en_purpose: "Command-line tool for downloading audio and video from websites.",
        en_impact: "Affects support for the websites media is downloaded from.",
    },
    InfoEntry {
        name: "fastfetch",
        pl_purpose: "Wyświetla w terminalu informacje o systemie i sprzęcie.",
        pl_impact: "Samodzielne narzędzie wiersza poleceń.",
        en_purpose: "Displays system and hardware information in the terminal.",
        en_impact: "Standalone command-line tool.",
    },
    // --- Libraries ---------------------------------------------------------
    InfoEntry {
        name: "python-platformdirs",
        pl_purpose: "Pomaga aplikacjom Python odnajdywać katalogi konfiguracji i danych.",
        pl_impact: "Dotyczy programów korzystających z tej biblioteki.",
        en_purpose: "Helps Python applications locate configuration and data directories.",
        en_impact: "Affects programs that depend on this library.",
    },
    InfoEntry {
        name: "semver",
        pl_purpose: "Obsługuje numery wersji oprogramowania.",
        pl_impact: "Dotyczy narzędzi korzystających z wersjonowania semantycznego.",
        en_purpose: "Handles semantic software version numbers.",
        en_impact: "Affects tools using semantic versioning.",
    },
];

pub fn explain(name: &str, language: Language) -> Option<PackageInfo> {
    let entry = INFO_ENTRIES.iter().find(|entry| entry.name == name)?;
    let (purpose, impact) = match language {
        Language::Polish => (entry.pl_purpose, entry.pl_impact),
        Language::English => (entry.en_purpose, entry.en_impact),
    };
    Some(PackageInfo {
        purpose: purpose.to_string(),
        impact: impact.to_string(),
    })
}

#[cfg(test)]
mod data_quality_tests {
    use super::*;

    #[test]
    fn entries_are_unique_complete_and_bilingual() {
        let mut seen = std::collections::HashSet::new();
        for entry in INFO_ENTRIES {
            assert!(seen.insert(entry.name), "duplicate {}", entry.name);
            for text in [
                entry.pl_purpose,
                entry.pl_impact,
                entry.en_purpose,
                entry.en_impact,
            ] {
                assert!(!text.trim().is_empty(), "{}", entry.name);
                assert!(text.ends_with('.'), "{}: {text}", entry.name);
            }
            assert_ne!(entry.pl_purpose, entry.en_purpose, "{}", entry.name);
            assert_ne!(entry.pl_impact, entry.en_impact, "{}", entry.name);
        }
    }

    #[test]
    fn impact_texts_make_no_session_or_change_kind_assumptions() {
        // Static texts must not claim which session runs nor which kind of
        // version change is happening.
        let forbidden = [
            "bieżącej sesji",
            "current hyprland session",
            "current session",
            "rewizj",
            "revision",
            "nie jest kompozytorem",
            "not the compositor",
        ];
        for entry in INFO_ENTRIES {
            for language in [Language::Polish, Language::English] {
                let info = explain(entry.name, language).unwrap();
                let text = format!("{} {}", info.purpose, info.impact).to_lowercase();
                for phrase in forbidden {
                    assert!(!text.contains(phrase), "{}: {phrase}", entry.name);
                }
            }
        }
    }

    #[test]
    fn descriptions_never_claim_unverified_changes() {
        // Change content belongs to verified changelogs only.
        let forbidden = [
            "naprawia",
            "poprawia",
            "łata",
            "luk",
            "nowe funkcje:",
            "fixes",
            "fixed",
            "patches",
            "vulnerab",
            "cve",
            "new features:",
            "improves",
        ];
        for entry in INFO_ENTRIES {
            let text = format!(
                "{} {} {} {}",
                entry.pl_purpose, entry.pl_impact, entry.en_purpose, entry.en_impact
            )
            .to_lowercase();
            for phrase in forbidden {
                assert!(!text.contains(phrase), "{}: {phrase}", entry.name);
            }
        }
    }

    #[test]
    fn split_packages_are_described_by_pkgname() {
        let libnm = explain("libnm", Language::Polish).unwrap();
        let nm = explain("networkmanager", Language::Polish).unwrap();
        assert_ne!(libnm.purpose, nm.purpose);
        assert!(explain("vulkan-radeon", Language::English).is_some());
    }

    #[test]
    fn language_selects_matching_text() {
        let pl = explain("7zip", Language::Polish).unwrap();
        let en = explain("7zip", Language::English).unwrap();
        assert!(pl.purpose.starts_with("Archiwizator"));
        assert!(en.purpose.starts_with("File archiver"));
    }

    #[test]
    fn unknown_package_has_no_curated_text() {
        assert!(explain("unknown-package", Language::Polish).is_none());
    }
}
