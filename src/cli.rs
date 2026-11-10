// RWR PACKAGE INTELLIGENCE
// Read-only CLI. Never installs or upgrades packages.

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Polish,
    English,
}

impl Language {
    pub fn detect() -> Self {
        let locale = std::env::var("LC_ALL")
            .ok()
            .filter(|value| !value.is_empty())
            .or_else(|| {
                std::env::var("LC_MESSAGES")
                    .ok()
                    .filter(|value| !value.is_empty())
            })
            .or_else(|| std::env::var("LANG").ok())
            .unwrap_or_default();

        if locale.to_ascii_lowercase().starts_with("pl") {
            Self::Polish
        } else {
            Self::English
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "pl" => Some(Self::Polish),
            "en" => Some(Self::English),
            _ => None,
        }
    }
}

pub fn run(language: Language, demo: bool) -> i32 {
    println!("=== RWR PACKAGE INTELLIGENCE ===");

    match language {
        Language::Polish => println!("ARCH LINUX // TRYB TYLKO DO ODCZYTU"),
        Language::English => println!("ARCH LINUX // READ-ONLY MODE"),
    }

    println!();

    if demo {
        println!("=== DEMO / DANE PRZYKŁADOWE ===");
    }
    let result = if demo {
        Ok(crate::cli_demo::sample_updates())
    } else {
        crate::packages::check_updates()
    };
    match result {
        Ok(updates) => {
            if updates.is_empty() {
                match language {
                    Language::Polish => println!("Brak dostepnych aktualizacji."),
                    Language::English => println!("No available updates."),
                }
            } else {
                match language {
                    Language::Polish => println!("Dostepne aktualizacje: {}", updates.len()),
                    Language::English => println!("Available updates: {}", updates.len()),
                }

                println!();

                let mut elevated_count = 0usize;
                for update in updates {
                    let info = crate::classification::classify(&update.name);
                    if info.attention == crate::classification::Attention::Elevated {
                        elevated_count += 1;
                    }
                    let elevated = info.attention == crate::classification::Attention::Elevated;
                    let category = match info.category {
                        crate::classification::Category::Kernel => ("Jądro", "Kernel"),
                        crate::classification::Category::Drivers => ("Sterowniki", "Drivers"),
                        crate::classification::Category::SecurityTools => {
                            ("Bezpieczeństwo", "Security")
                        }
                        crate::classification::Category::Network => ("Sieć", "Network"),
                        crate::classification::Category::Desktop => ("Pulpit", "Desktop"),
                        crate::classification::Category::Libraries => ("Biblioteki", "Libraries"),
                        crate::classification::Category::Applications => {
                            ("Aplikacje", "Applications")
                        }
                        crate::classification::Category::System => ("System", "System"),
                        crate::classification::Category::Other => ("Inne", "Other"),
                    };
                    let label = match (language, elevated) {
                        (Language::Polish, true) => "PODWYŻSZONA UWAGA",
                        (Language::English, true) => "ELEVATED ATTENTION",
                        (Language::Polish, false) => "Normalna uwaga",
                        (Language::English, false) => "Normal attention",
                    };
                    println!(
                        "    {} | {}",
                        if language == Language::Polish {
                            category.0
                        } else {
                            category.1
                        },
                        label
                    );
                    println!(
                        "{}: {} -> {}",
                        update.name, update.installed, update.available
                    );
                }
                match language {
                    Language::Polish => println!("Pakiety wymagające uwagi: {elevated_count}"),
                    Language::English => println!("Packages requiring attention: {elevated_count}"),
                }
            }

            println!();

            match language {
                Language::Polish => println!("TRYB RZECZYWISTY: ZABLOKOWANY"),
                Language::English => println!("REAL MODE: DISABLED"),
            }

            0
        }
        Err(error) => {
            match language {
                Language::Polish => eprintln!("BLAD SKANOWANIA: {error}"),
                Language::English => eprintln!("SCAN ERROR: {error}"),
            }
            1
        }
    }
}

#[cfg(test)]
mod cli_classification_tests {
    use crate::classification::{Attention, Category, classify};

    #[test]
    fn critical_system_packages() {
        assert_eq!(classify("linux").attention, Attention::Elevated);
        assert_eq!(classify("openssl").attention, Attention::Elevated);
    }

    #[test]
    fn desktop_and_network_packages() {
        assert_eq!(classify("networkmanager").category, Category::Network);
        assert_eq!(classify("hyprland").category, Category::Desktop);
    }

    #[test]
    fn ordinary_application() {
        assert_eq!(classify("firefox").category, Category::Applications);
        assert_eq!(classify("firefox").attention, Attention::Normal);
    }
}

#[cfg(test)]
mod cli_report_tests {
    use crate::classification::{Attention, classify};

    #[test]
    fn elevated_package_count_test() {
        let names = ["linux", "openssl", "firefox", "networkmanager", "mpv"];
        let count = names
            .iter()
            .filter(|name| classify(name).attention == Attention::Elevated)
            .count();
        assert_eq!(count, 3);
    }
}
