// RWR PACKAGE INTELLIGENCE
// Terminal backend selection — preparation only.
// Never launches pacman, pkexec or a terminal.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalBackend {
    WezTerm,
    Kitty,
    Alacritty,
    Konsole,
    Foot,
    Xterm,
}

impl TerminalBackend {
    pub fn executable(self) -> &'static str {
        match self {
            Self::WezTerm => "wezterm",
            Self::Kitty => "kitty",
            Self::Alacritty => "alacritty",
            Self::Konsole => "konsole",
            Self::Foot => "foot",
            Self::Xterm => "xterm",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "wezterm" => Some(Self::WezTerm),
            "kitty" => Some(Self::Kitty),
            "alacritty" => Some(Self::Alacritty),
            "konsole" => Some(Self::Konsole),
            "foot" => Some(Self::Foot),
            "xterm" => Some(Self::Xterm),
            _ => None,
        }
    }

    pub fn candidates() -> &'static [Self] {
        &[
            Self::WezTerm,
            Self::Kitty,
            Self::Alacritty,
            Self::Konsole,
            Self::Foot,
            Self::Xterm,
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalCommand {
    pub program: &'static str,
    pub arguments: Vec<String>,
}

impl TerminalBackend {
    pub fn build_command(self, script: &str) -> Result<TerminalCommand, String> {
        let path = std::path::Path::new(script);

        if !path.is_absolute() || script.chars().any(char::is_control) {
            return Err("Invalid script path".into());
        }

        let shell = "/usr/bin/bash";

        let arguments = match self {
            Self::WezTerm => vec!["start", "--always-new-process", "--", shell, script],
            Self::Kitty => vec!["--", shell, script],
            Self::Alacritty => vec!["-e", shell, script],
            Self::Konsole => vec!["-e", shell, script],
            Self::Foot => vec![shell, script],
            Self::Xterm => vec!["-e", shell, script],
        };

        Ok(TerminalCommand {
            program: self.executable(),
            arguments: arguments.into_iter().map(str::to_owned).collect(),
        })
    }
}

pub fn detect_terminal() -> Option<TerminalBackend> {
    let path = std::env::var_os("PATH")?;

    let available = |name: &str| std::env::split_paths(&path).any(|dir| dir.join(name).is_file());

    if let Ok(preferred) = std::env::var("RWR_TERMINAL") {
        if let Some(backend) = TerminalBackend::from_name(&preferred) {
            if available(backend.executable()) {
                return Some(backend);
            }
        }
    }

    TerminalBackend::candidates()
        .iter()
        .copied()
        .find(|backend| available(backend.executable()))
}

#[cfg(test)]
mod command_tests {
    use super::*;

    #[test]
    fn builds_six_terminal_commands() {
        for backend in TerminalBackend::candidates() {
            let cmd = backend.build_command("/opt/rwr/update.sh").unwrap();
            assert_eq!(cmd.program, backend.executable());
            assert!(cmd.arguments.contains(&"/usr/bin/bash".to_string()));
            assert!(cmd.arguments.contains(&"/opt/rwr/update.sh".to_string()));
        }
    }

    #[test]
    fn rejects_unsafe_paths() {
        assert!(TerminalBackend::Kitty.build_command("relative.sh").is_err());
        assert!(
            TerminalBackend::Kitty
                .build_command(
                    "/tmp/a
b"
                )
                .is_err()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_supported_terminals() {
        for terminal in TerminalBackend::candidates() {
            assert_eq!(
                TerminalBackend::from_name(terminal.executable()),
                Some(*terminal)
            );
        }
    }

    #[test]
    fn rejects_unknown_terminal() {
        assert_eq!(TerminalBackend::from_name("unknown"), None);
    }

    #[test]
    fn rejects_command_injection() {
        assert_eq!(TerminalBackend::from_name("wezterm; pacman -Syu"), None);
    }

    #[test]
    fn rejects_terminal_with_arguments() {
        assert_eq!(TerminalBackend::from_name("kitty --execute"), None);
    }
}

/// Session classification only. No process execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnvironment {
    Desktop,
    Ssh,
    Tty,
}

pub fn classify_session(has_ssh: bool, has_display: bool) -> SessionEnvironment {
    if has_ssh {
        SessionEnvironment::Ssh
    } else if has_display {
        SessionEnvironment::Desktop
    } else {
        SessionEnvironment::Tty
    }
}

pub fn detect_session_environment() -> SessionEnvironment {
    let has_ssh =
        std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some();

    let has_display =
        std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();

    classify_session(has_ssh, has_display)
}

#[cfg(test)]
mod session_environment_tests {
    use super::*;

    #[test]
    fn detects_desktop() {
        assert_eq!(classify_session(false, true), SessionEnvironment::Desktop);
    }

    #[test]
    fn detects_ssh_even_with_forwarded_display() {
        assert_eq!(classify_session(true, true), SessionEnvironment::Ssh);
    }

    #[test]
    fn detects_tty_without_ssh_or_display() {
        assert_eq!(classify_session(false, false), SessionEnvironment::Tty);
    }
}
