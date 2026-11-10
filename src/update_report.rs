// RWR PACKAGE INTELLIGENCE
// Stage 16P-K11: report parsing only.
// Does not execute commands.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionReport {
    Success,
    Failed(i32),
    Unknown,
}

impl TransactionReport {
    pub fn parse(input: &str) -> Self {
        let text = input.trim();

        let Some(code_text) = text.strip_prefix("RWR_PACMAN_EXIT=") else {
            return Self::Unknown;
        };

        if code_text.is_empty() || !code_text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Self::Unknown;
        }

        match code_text.parse::<i32>() {
            Ok(0) => Self::Success,
            Ok(code) => Self::Failed(code),
            Err(_) => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_success() {
        assert_eq!(
            TransactionReport::parse("RWR_PACMAN_EXIT=0"),
            TransactionReport::Success
        );
    }

    #[test]
    fn parses_failure() {
        assert_eq!(
            TransactionReport::parse("RWR_PACMAN_EXIT=1"),
            TransactionReport::Failed(1)
        );
    }

    #[test]
    fn rejects_missing_report() {
        assert_eq!(TransactionReport::parse(""), TransactionReport::Unknown);
    }

    #[test]
    fn rejects_unrelated_output() {
        assert_eq!(
            TransactionReport::parse("pacman completed"),
            TransactionReport::Unknown
        );
    }

    #[test]
    fn rejects_invalid_code() {
        assert_eq!(
            TransactionReport::parse("RWR_PACMAN_EXIT=abc"),
            TransactionReport::Unknown
        );
    }

    #[test]
    fn rejects_extra_content() {
        assert_eq!(
            TransactionReport::parse(
                "RWR_PACMAN_EXIT=0
ERROR"
            ),
            TransactionReport::Unknown
        );
    }
}
