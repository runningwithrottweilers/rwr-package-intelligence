//! Deny-only isolation of test processes from the production host.
//!
//! Active in `cfg(test)` builds of this library and in any process started by
//! cargo with `RWR_TEST_ISOLATION` set (see `.cargo/config.toml`). It can only
//! REFUSE: the REAL execution policy reads as locked, and the system supervisor
//! socket, real Polkit and the deployed system helper are unreachable. It never
//! grants, relaxes or bypasses any check. The systemd units start the
//! supervisor with a clean environment and the helper with `env_clear()`, so
//! production processes never see the variable.

pub const ENV: &str = "RWR_TEST_ISOLATION";

static FORCED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn active() -> bool {
    cfg!(test)
        || FORCED.load(std::sync::atomic::Ordering::SeqCst)
        || std::env::var_os(ENV).is_some()
}

/// Called before `main` by `cfg(test)` builds of the binaries (see
/// `isolate_test_binary!`). One-way: isolation can be switched on, never off.
pub fn force() {
    FORCED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Place in every binary crate: in its `cfg(test)` build the test process is
/// isolated before any test runs, even when started without cargo.
#[macro_export]
macro_rules! isolate_test_binary {
    () => {
        #[cfg(test)]
        #[used]
        #[unsafe(link_section = ".init_array")]
        static RWR_TEST_ISOLATION_INIT: extern "C" fn() = {
            extern "C" fn rwr_test_isolation_init() {
                $crate::test_isolation::force();
            }
            rwr_test_isolation_init
        };
    };
}

/// Refuse a host operation when running under test isolation.
pub fn refuse(operation: &str) -> Result<(), String> {
    if active() {
        return Err(format!(
            "Test isolation: {operation} is unavailable to tests (no system socket, helper or Polkit)"
        ));
    }
    Ok(())
}

/// Private per-process state directory used instead of the user's real state.
pub fn state_base() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("rwr-test-state-{}", std::process::id()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn library_tests_are_always_isolated() {
        assert!(super::active());
        assert!(super::refuse("system socket").is_err());
        assert!(
            super::state_base()
                .to_string_lossy()
                .contains("rwr-test-state-")
        );
    }
}
