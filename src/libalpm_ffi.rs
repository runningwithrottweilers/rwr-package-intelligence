//! Minimal production FFI binding to the installed libalpm.
//! Read-only planning and type-gated signed execution. System execution is
//! disabled; laboratory writes require the unchanged sandbox capability.

use std::cell::Cell;
use std::ffi::CStr;
use std::os::raw::c_char;

#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_version() -> *const c_char;
}

pub fn version() -> Result<String, String> {
    let ptr = unsafe { alpm_version() };
    if ptr.is_null() {
        return Err("libalpm returned a null version pointer".into());
    }
    let version = unsafe { CStr::from_ptr(ptr) };
    version
        .to_str()
        .map(str::to_owned)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn libalpm_version_is_available() {
        let version = super::version().unwrap();
        assert!(!version.is_empty());
    }
}

use std::ffi::CString;
use std::path::Path;
use std::ptr::NonNull;

#[repr(C)]
struct RawAlpmHandle {
    _private: [u8; 0],
}

#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_initialize(
        root: *const c_char,
        dbpath: *const c_char,
        err: *mut i32,
    ) -> *mut RawAlpmHandle;
    fn alpm_release(handle: *mut RawAlpmHandle) -> i32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlpmHandleOrigin {
    Untrusted,
    IsolatedLab,
    PrivatePlan,
    AuthorizedSystem,
}

#[derive(Debug)]
struct CallbackContext {
    // Owned by AlpmHandle. Never freed while libalpm can invoke callbacks.
    event_count: std::sync::atomic::AtomicUsize,
    checkdeps_count: std::sync::atomic::AtomicUsize,
    resolvedeps_count: std::sync::atomic::AtomicUsize,
    other_event_count: std::sync::atomic::AtomicUsize,
    event_types: [std::sync::atomic::AtomicUsize; 64],
    event_sequence: std::sync::Mutex<Vec<i32>>,
    plan_questions: std::sync::Mutex<Vec<i32>>,
    interrupt: std::sync::Arc<std::sync::atomic::AtomicBool>,
    interrupt_delivered: std::sync::atomic::AtomicBool,
    callback_handle: std::sync::atomic::AtomicPtr<RawAlpmHandle>,
    progress_stream: std::sync::Mutex<Option<std::sync::mpsc::SyncSender<serde_json::Value>>>,
    interactive_questions: std::sync::Mutex<Option<std::sync::Arc<ExecutionQuestions>>>,
}

impl Default for CallbackContext {
    fn default() -> Self {
        use std::sync::atomic::AtomicUsize;

        Self {
            event_count: AtomicUsize::new(0),
            checkdeps_count: AtomicUsize::new(0),
            resolvedeps_count: AtomicUsize::new(0),
            other_event_count: AtomicUsize::new(0),
            event_types: std::array::from_fn(|_| AtomicUsize::new(0)),
            event_sequence: std::sync::Mutex::new(Vec::new()),
            plan_questions: std::sync::Mutex::new(Vec::new()),
            interrupt: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            interrupt_delivered: std::sync::atomic::AtomicBool::new(false),
            callback_handle: std::sync::atomic::AtomicPtr::new(std::ptr::null_mut()),
            progress_stream: std::sync::Mutex::new(None),
            interactive_questions: std::sync::Mutex::new(None),
        }
    }
}

impl CallbackContext {
    fn event_count(&self) -> usize {
        self.event_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

pub struct AlpmHandle {
    raw: NonNull<RawAlpmHandle>,
    transaction_poisoned: Cell<bool>,
    origin: AlpmHandleOrigin,
    callback_context: Box<CallbackContext>,
}

impl AlpmHandle {
    pub fn new(root: &Path, dbpath: &Path) -> Result<Self, String> {
        // Destructors/callbacks below are verified for this exact installed ABI.
        // Refuse an unvalidated replacement library rather than guess layouts.
        if version()? != "16.0.1" {
            return Err("Unsupported libalpm ABI; validate bindings before use".into());
        }

        use std::os::unix::ffi::OsStrExt;

        let root = CString::new(root.as_os_str().as_bytes())
            .map_err(|_| "Invalid root path".to_string())?;
        let dbpath = CString::new(dbpath.as_os_str().as_bytes())
            .map_err(|_| "Invalid database path".to_string())?;

        let mut error = 0;
        let raw = unsafe { alpm_initialize(root.as_ptr(), dbpath.as_ptr(), &mut error) };

        let raw =
            NonNull::new(raw).ok_or_else(|| format!("libalpm initialization failed: {error}"))?;

        Ok(Self {
            raw,
            transaction_poisoned: Cell::new(false),
            origin: AlpmHandleOrigin::Untrusted,
            callback_context: Box::new(CallbackContext::default()),
        })
    }
}

impl AlpmHandle {
    pub(crate) fn new_isolated_lab(lab: &crate::alpm_lab::AlpmLab) -> Result<Self, String> {
        lab.verify_boundary()?;
        let root = lab.root().canonicalize().map_err(|e| e.to_string())?;
        let dbpath = lab.db().canonicalize().map_err(|e| e.to_string())?;

        if root == Path::new("/") || dbpath != root.join("var/lib/pacman") {
            return Err("Invalid isolated laboratory filesystem".into());
        }

        let mut handle = Self::new(&root, &dbpath)?;
        handle.origin = AlpmHandleOrigin::IsolatedLab;
        Ok(handle)
    }
}

// ETAP 4.5Q-E2: real libalpm event callback, laboratory only.
// Event payload is deliberately opaque until its ABI is mapped.
#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_option_set_eventcb(
        handle: *mut RawAlpmHandle,
        callback: Option<unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void)>,
        context: *mut std::ffi::c_void,
    ) -> i32;
}

// ETAP 4.5Q-M1: verified libalpm event descriptions, PL/EN.
pub fn alpm_event_message(code: i32) -> Option<(&'static str, &'static str)> {
    match code {
        1 => Some(("Sprawdzanie zależności...", "Checking dependencies...")),
        2 => Some((
            "Sprawdzanie zależności zakończone",
            "Dependency check completed",
        )),
        3 => Some((
            "Sprawdzanie konfliktów plików...",
            "Checking file conflicts...",
        )),
        4 => Some((
            "Sprawdzanie konfliktów plików zakończone",
            "File conflict check completed",
        )),
        5 => Some(("Rozwiązywanie zależności...", "Resolving dependencies...")),
        6 => Some((
            "Rozwiązywanie zależności zakończone",
            "Dependency resolution completed",
        )),
        7 => Some((
            "Sprawdzanie konfliktów pakietów...",
            "Checking package conflicts...",
        )),
        8 => Some((
            "Sprawdzanie konfliktów pakietów zakończone",
            "Package conflict check completed",
        )),
        9 => Some((
            "Rozpoczynanie transakcji COMMIT...",
            "Starting COMMIT transaction...",
        )),
        10 => Some((
            "Transakcja zakończona pomyślnie",
            "Transaction completed successfully",
        )),
        13 => Some((
            "Sprawdzanie integralności pakietów...",
            "Checking package integrity...",
        )),
        14 => Some((
            "Sprawdzanie integralności zakończone",
            "Integrity check completed",
        )),
        21 => Some(("Pobieranie pakietów...", "Retrieving packages...")),
        22 => Some(("Pobieranie zakończone", "Package retrieval completed")),
        23 => Some(("Pobieranie nieudane", "Package retrieval failed")),
        _ => None,
    }
}

#[repr(C)]
struct AlpmEventAny {
    event_type: std::ffi::c_int,
}

unsafe extern "C" fn rwr_alpm_event_callback(
    context: *mut std::ffi::c_void,
    event: *mut std::ffi::c_void,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if context.is_null() || event.is_null() {
            return;
        }

        let context = unsafe { &*(context as *const CallbackContext) };
        let event_type = unsafe { (*(event as *const AlpmEventAny)).event_type };

        use std::sync::atomic::Ordering::Relaxed;

        context.event_count.fetch_add(1, Relaxed);
        // Only the ALPM thread calls the FFI interrupt. Other threads may set
        // the atomic request; no raw handle is shared across threads.
        if context.interrupt.load(Relaxed) && matches!(event_type, 9 | 11 | 12) {
            let handle = context.callback_handle.load(Relaxed);
            if !handle.is_null() && unsafe { alpm_trans_interrupt(handle) } == 0 {
                context.interrupt_delivered.store(true, Relaxed);
            }
        }

        if let Ok(mut sequence) = context.event_sequence.lock() {
            if sequence.len() < 1024 {
                sequence.push(event_type);
            }
        }

        if let Ok(index) = usize::try_from(event_type) {
            if let Some(counter) = context.event_types.get(index) {
                counter.fetch_add(1, Relaxed);
            }
        }

        match event_type {
            1 | 2 => {
                context.checkdeps_count.fetch_add(1, Relaxed);
            }
            5 | 6 => {
                context.resolvedeps_count.fetch_add(1, Relaxed);
            }
            _ => {
                context.other_event_count.fetch_add(1, Relaxed);
            }
        }
    }));
}

impl AlpmHandle {
    pub(crate) fn register_lab_event_callback(&mut self) -> Result<(), String> {
        if self.origin != AlpmHandleOrigin::IsolatedLab {
            return Err("Event callback requires isolated laboratory".into());
        }

        self.callback_context
            .callback_handle
            .store(self.raw.as_ptr(), std::sync::atomic::Ordering::Relaxed);
        let context =
            self.callback_context.as_mut() as *mut CallbackContext as *mut std::ffi::c_void;

        let result = unsafe {
            alpm_option_set_eventcb(self.raw.as_ptr(), Some(rwr_alpm_event_callback), context)
        };

        if result != 0 {
            return Err("libalpm event callback registration failed".into());
        }

        Ok(())
    }

    pub fn laboratory_event_sequence(&self) -> Vec<i32> {
        if self.origin != AlpmHandleOrigin::IsolatedLab {
            return Vec::new();
        }
        self.callback_context
            .event_sequence
            .lock()
            .map(|sequence| sequence.clone())
            .unwrap_or_default()
    }

    pub fn laboratory_event_snapshot(&self) -> Vec<(i32, usize)> {
        if self.origin != AlpmHandleOrigin::IsolatedLab {
            return Vec::new();
        }
        self.callback_context
            .event_types
            .iter()
            .enumerate()
            .filter_map(|(code, counter)| {
                let count = counter.load(std::sync::atomic::Ordering::Relaxed);
                if count == 0 {
                    None
                } else {
                    Some((code as i32, count))
                }
            })
            .collect()
    }

    pub(crate) fn laboratory_event_count(&self) -> usize {
        self.callback_context.event_count()
    }
}

impl Drop for AlpmHandle {
    fn drop(&mut self) {
        unsafe {
            // Unregister before CallbackContext is destroyed.
            let result = alpm_option_set_eventcb(self.raw.as_ptr(), None, std::ptr::null_mut());

            if result != 0 {
                eprintln!("RWR: libalpm event callback unregister failed");
            }

            alpm_release(self.raw.as_ptr());
        }
    }
}

#[cfg(test)]
mod handle_tests {
    #[test]
    fn isolated_handle_initializes_and_releases() {
        let base = std::env::temp_dir().join(format!("rwr-alpm-test-{}", std::process::id()));
        let root = base.join("root");
        let db = base.join("db");

        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();

        {
            let _handle = super::AlpmHandle::new(&root, &db).unwrap();
        }

        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[repr(C)]
pub(crate) struct RawAlpmDb {
    _private: [u8; 0],
}

#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_get_localdb(handle: *mut RawAlpmHandle) -> *mut RawAlpmDb;
    fn alpm_db_get_pkgcache(db: *mut RawAlpmDb) -> *mut AlpmList;
}

impl AlpmHandle {
    pub fn local_package_count(&self) -> Result<usize, String> {
        let db = unsafe { alpm_get_localdb(self.raw.as_ptr()) };
        if db.is_null() {
            return Err("libalpm returned null local database".into());
        }

        let mut node = unsafe { alpm_db_get_pkgcache(db) };
        let mut count = 0usize;

        while !node.is_null() {
            count = count
                .checked_add(1)
                .ok_or_else(|| "Package count overflow".to_string())?;
            node = unsafe { (*node).next };
        }

        Ok(count)
    }
}

#[cfg(test)]
mod localdb_tests {
    #[test]
    fn isolated_database_is_empty() {
        let base = std::env::temp_dir().join(format!("rwr-localdb-test-{}", std::process::id()));
        let root = base.join("root");
        let db = base.join("db");

        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();

        {
            let handle = super::AlpmHandle::new(&root, &db).unwrap();
            assert_eq!(handle.local_package_count().unwrap(), 0);
        }

        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[cfg(test)]
mod systemdb_tests {
    #[test]
    fn system_database_matches_pacman() {
        use std::path::Path;
        use std::process::Command;

        let handle = super::AlpmHandle::new(Path::new("/"), Path::new("/var/lib/pacman")).unwrap();

        let libalpm_count = handle.local_package_count().unwrap();

        let output = Command::new("/usr/bin/pacman").arg("-Qq").output().unwrap();

        assert!(output.status.success());

        let pacman_count = String::from_utf8(output.stdout).unwrap().lines().count();

        println!("LIBALPM: {libalpm_count}");
        println!("PACMAN:  {pacman_count}");

        assert_eq!(libalpm_count, pacman_count);
    }
}

#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_register_syncdb(
        handle: *mut RawAlpmHandle,
        name: *const c_char,
        siglevel: i32,
    ) -> *mut RawAlpmDb;

    fn alpm_db_add_server(db: *mut RawAlpmDb, url: *const c_char) -> i32;
}

impl AlpmHandle {
    pub(crate) fn register_fixed_lab_repository(
        &self,
        repository: &Path,
    ) -> Result<*mut RawAlpmDb, String> {
        // The fixture repository is unsigned; siglevel 0 records that
        // honestly instead of pretending signature checks ran.
        self.register_fixed_lab_repository_with_siglevel(repository, 0)
    }

    /// Strict variant: the same fixture repository registered with
    /// mandatory package and database signature enforcement, used to prove
    /// the unsigned fixture is refused. Returns the registered database.
    pub(crate) fn register_fixed_lab_repository_strict(
        &self,
        repository: &Path,
    ) -> Result<*mut RawAlpmDb, String> {
        self.register_fixed_lab_repository_with_siglevel(
            repository,
            ALPM_SIG_PACKAGE | ALPM_SIG_DATABASE,
        )
    }

    fn register_fixed_lab_repository_with_siglevel(
        &self,
        repository: &Path,
        siglevel: i32,
    ) -> Result<*mut RawAlpmDb, String> {
        let _crypto = self.crypto_context()?;
        let repository = repository
            .canonicalize()
            .map_err(|e| format!("Cannot resolve laboratory repository: {e}"))?;

        let name = CString::new("rwr-test").unwrap();
        let server =
            CString::new(format!("file://{}", repository.display())).map_err(|e| e.to_string())?;

        let db = unsafe { alpm_register_syncdb(self.raw.as_ptr(), name.as_ptr(), siglevel) };

        if db.is_null() {
            return Err("Cannot register fixed laboratory repository".into());
        }

        if unsafe { alpm_db_add_server(db, server.as_ptr()) } != 0 {
            return Err("Cannot configure fixed laboratory repository".into());
        }

        Ok(db)
    }

    /// Database synchronisation (laboratory scope): libalpm retrieves the
    /// repository database into the laboratory dbpath through its own
    /// download path. The laboratory boundary must already be verified.
    pub(crate) fn update_database(&self, db: *mut RawAlpmDb, force: bool) -> Result<(), String> {
        let _crypto = self.crypto_context()?;
        if db.is_null() {
            return Err("Cannot synchronize a null laboratory database".into());
        }

        let mut list: *mut AlpmList = std::ptr::null_mut();
        list = unsafe { alpm_list_add(list, db.cast()) };
        if list.is_null() {
            return Err("Cannot allocate laboratory database list".into());
        }

        let result = unsafe { alpm_db_update(self.raw.as_ptr(), list, if force { 1 } else { 0 }) };
        unsafe { alpm_list_free(list) };

        if result != 0 {
            return Err(transaction_error(self, "database update"));
        }

        Ok(())
    }

    pub(crate) fn set_lab_architecture(&self) -> Result<(), String> {
        self.set_architecture("x86_64")
    }

    #[cfg(test)]
    fn register_test_repository(&self, name: &str, server: &str) -> Result<(), String> {
        let name = CString::new(name).map_err(|_| "Invalid repository name".to_string())?;
        let server = CString::new(server).map_err(|_| "Invalid repository server".to_string())?;

        let db = unsafe { alpm_register_syncdb(self.raw.as_ptr(), name.as_ptr(), 0) };

        if db.is_null() {
            return Err("libalpm repository registration failed".into());
        }

        let result = unsafe { alpm_db_add_server(db, server.as_ptr()) };
        if result != 0 {
            return Err("libalpm server registration failed".into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod repository_tests {
    #[test]
    fn isolated_repository_registration() {
        let base = std::env::temp_dir().join(format!("rwr-alpm-repo-test-{}", std::process::id()));
        let root = base.join("root");
        let db = base.join("db");

        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();

        {
            let handle = super::AlpmHandle::new(&root, &db).unwrap();
            handle
                .register_test_repository("rwr-test", "https://example.invalid/rwr-test")
                .unwrap();
        }

        std::fs::remove_dir_all(&base).unwrap();
    }
}

const ALPM_SIG_USE_DEFAULT: i32 = 1 << 30;
const ALPM_SIG_PACKAGE: i32 = 1 << 0;
const ALPM_SIG_PACKAGE_OPTIONAL: i32 = 1 << 1;
const ALPM_SIG_DATABASE: i32 = 1 << 10;
const ALPM_SIG_DATABASE_OPTIONAL: i32 = 1 << 11;

fn signature_level(policy: &[String]) -> Result<i32, String> {
    let mut package_mode = None;
    let mut database_mode = None;
    let mut package_trusted = false;
    let mut database_trusted = false;

    for entry in policy {
        match entry.as_str() {
            "PackageRequired" | "PackageOptional" | "PackageNever" => {
                if package_mode.is_some() {
                    return Err("Duplicate or conflicting package signature mode".into());
                }

                package_mode = Some(match entry.as_str() {
                    "PackageRequired" => ALPM_SIG_PACKAGE,
                    "PackageOptional" => ALPM_SIG_PACKAGE_OPTIONAL,
                    _ => 0,
                });
            }
            "DatabaseRequired" | "DatabaseOptional" | "DatabaseNever" => {
                if database_mode.is_some() {
                    return Err("Duplicate or conflicting database signature mode".into());
                }

                database_mode = Some(match entry.as_str() {
                    "DatabaseRequired" => ALPM_SIG_DATABASE,
                    "DatabaseOptional" => ALPM_SIG_DATABASE_OPTIONAL,
                    _ => 0,
                });
            }
            "PackageTrustedOnly" => {
                if package_trusted {
                    return Err("Duplicate package trust directive".into());
                }
                package_trusted = true;
            }
            "DatabaseTrustedOnly" => {
                if database_trusted {
                    return Err("Duplicate database trust directive".into());
                }
                database_trusted = true;
            }
            other => return Err(format!("Unsupported signature policy: {other}")),
        }
    }

    if package_mode != Some(ALPM_SIG_PACKAGE) || !package_trusted || !database_trusted {
        return Err("Unsafe or incomplete signature policy".into());
    }

    let database = database_mode.ok_or_else(|| "Missing database signature policy".to_string())?;

    if database == 0 {
        return Err("Database signature verification disabled".into());
    }

    Ok(ALPM_SIG_PACKAGE | database)
}

#[cfg(test)]
mod signature_tests {
    #[test]
    fn converts_verified_signature_policy() {
        let policy = vec![
            "PackageRequired".to_string(),
            "PackageTrustedOnly".to_string(),
            "DatabaseOptional".to_string(),
            "DatabaseTrustedOnly".to_string(),
        ];

        assert_eq!(super::signature_level(&policy).unwrap(), 2049);
    }

    #[test]
    fn rejects_weakened_signature_policy() {
        let policy = vec![
            "PackageOptional".to_string(),
            "DatabaseOptional".to_string(),
        ];

        assert!(super::signature_level(&policy).is_err());
    }
    #[test]
    fn rejects_conflicting_package_modes() {
        let policy = vec![
            "PackageRequired".into(),
            "PackageNever".into(),
            "PackageTrustedOnly".into(),
            "DatabaseOptional".into(),
            "DatabaseTrustedOnly".into(),
        ];

        assert!(super::signature_level(&policy).is_err());
    }

    #[test]
    fn rejects_duplicate_package_mode() {
        let policy = vec![
            "PackageRequired".into(),
            "PackageRequired".into(),
            "PackageTrustedOnly".into(),
            "DatabaseOptional".into(),
            "DatabaseTrustedOnly".into(),
        ];

        assert!(super::signature_level(&policy).is_err());
    }

    #[test]
    fn rejects_conflicting_database_modes() {
        let policy = vec![
            "PackageRequired".into(),
            "PackageTrustedOnly".into(),
            "DatabaseRequired".into(),
            "DatabaseNever".into(),
            "DatabaseTrustedOnly".into(),
        ];

        assert!(super::signature_level(&policy).is_err());
    }

    #[test]
    fn rejects_duplicate_trust_directive() {
        let policy = vec![
            "PackageRequired".into(),
            "PackageTrustedOnly".into(),
            "PackageTrustedOnly".into(),
            "DatabaseOptional".into(),
            "DatabaseTrustedOnly".into(),
        ];

        assert!(super::signature_level(&policy).is_err());
    }
}

#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_option_set_default_siglevel(handle: *mut RawAlpmHandle, level: i32) -> i32;

    fn alpm_option_get_default_siglevel(handle: *mut RawAlpmHandle) -> i32;

    fn alpm_db_get_siglevel(db: *mut RawAlpmDb) -> i32;
}

impl AlpmHandle {
    fn register_configured_repositories(&self, config: &PacmanConfig) -> Result<usize, String> {
        let _crypto = self.crypto_context()?;
        let global_siglevel = signature_level(&config.signature_policy)?;

        if unsafe { alpm_option_set_default_siglevel(self.raw.as_ptr(), global_siglevel) } != 0 {
            return Err("Cannot configure default signature level".into());
        }

        let actual_default = unsafe { alpm_option_get_default_siglevel(self.raw.as_ptr()) };

        if actual_default != global_siglevel {
            return Err("Default signature level mismatch".into());
        }

        let mut registered = 0usize;

        for (repo, servers) in &config.repository_servers {
            let policy = config
                .repository_signature_policies
                .iter()
                .find(|(name, _)| name == repo)
                .map(|(_, policy)| policy.as_slice())
                .unwrap_or(&[]);

            let siglevel = if policy.is_empty() {
                ALPM_SIG_USE_DEFAULT
            } else {
                signature_level(policy)?
            };

            let name = CString::new(repo.as_str())
                .map_err(|_| format!("Invalid repository name: {repo}"))?;

            let db = unsafe { alpm_register_syncdb(self.raw.as_ptr(), name.as_ptr(), siglevel) };

            if db.is_null() {
                return Err(format!("Cannot register repository: {repo}"));
            }

            let effective = unsafe { alpm_db_get_siglevel(db) };
            let expected = if policy.is_empty() {
                global_siglevel
            } else {
                siglevel
            };

            if effective != expected {
                return Err(format!("Repository signature level mismatch: {repo}"));
            }

            for server in servers {
                let url = CString::new(server.as_str())
                    .map_err(|_| format!("Invalid server URL in {repo}"))?;

                if unsafe { alpm_db_add_server(db, url.as_ptr()) } != 0 {
                    return Err(format!("Cannot register server for {repo}"));
                }
            }

            registered += 1;
        }

        Ok(registered)
    }
}

#[cfg(test)]
mod configured_repository_tests {
    #[test]
    fn registers_real_configuration_in_isolated_handle() {
        let config = super::PacmanConfig::read().unwrap();

        let base =
            std::env::temp_dir().join(format!("rwr-configured-repo-test-{}", std::process::id()));
        let root = base.join("root");
        let db = base.join("db");

        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();

        {
            let handle = super::AlpmHandle::new(&root, &db).unwrap();
            let count = handle.register_configured_repositories(&config).unwrap();

            println!("Registered repositories: {count}");
            assert_eq!(count, config.repositories.len());
            assert!(count > 0);
        }

        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_option_add_architecture(handle: *mut RawAlpmHandle, arch: *const c_char) -> i32;
}

impl AlpmHandle {
    fn set_architecture(&self, architecture: &str) -> Result<(), String> {
        if architecture.is_empty()
            || !architecture
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err("Invalid package architecture".into());
        }

        let arch =
            CString::new(architecture).map_err(|_| "Invalid architecture string".to_string())?;

        let result = unsafe { alpm_option_add_architecture(self.raw.as_ptr(), arch.as_ptr()) };

        if result != 0 {
            return Err(format!("libalpm rejected architecture: {architecture}"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod architecture_tests {
    #[test]
    fn sets_configured_architecture_in_isolated_handle() {
        let config = super::PacmanConfig::read().unwrap();

        let base =
            std::env::temp_dir().join(format!("rwr-alpm-architecture-test-{}", std::process::id()));
        let root = base.join("root");
        let db = base.join("db");

        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();

        {
            let handle = super::AlpmHandle::new(&root, &db).unwrap();
            handle.set_architecture(&config.architecture).unwrap();

            assert!(handle.set_architecture("").is_err());
            assert!(handle.set_architecture("invalid arch").is_err());

            println!("Architecture: {}", config.architecture);
        }

        std::fs::remove_dir_all(&base).unwrap();
    }
}

impl AlpmHandle {
    /// Open libalpm using the current system pacman configuration.
    /// No database synchronization, downloads or transactions are performed.
    pub fn open_system_configured() -> Result<Self, String> {
        let config = PacmanConfig::read()?;

        if config.root.is_empty() || config.db_path.is_empty() || config.repositories.is_empty() {
            return Err("Incomplete system pacman configuration".into());
        }

        let handle = Self::new(
            std::path::Path::new(&config.root),
            std::path::Path::new(&config.db_path),
        )?;

        let registered = handle.configure(&config)?;

        if registered != config.repositories.len() {
            return Err("Repository registration count mismatch".into());
        }

        Ok(handle)
    }
}

impl AlpmHandle {
    /// Configure an existing handle using validated pacman settings.
    /// Does not synchronize databases, download packages or commit transactions.
    pub fn configure(&self, config: &PacmanConfig) -> Result<usize, String> {
        self.configure_system_options(&config.cache_dir, &config.gpg_dir, config.check_space)?;
        self.set_architecture(&config.architecture)?;
        self.configure_transaction_options(config)?;
        self.register_configured_repositories(config)
    }
}

#[cfg(test)]
mod configuration_integration_tests {
    #[test]
    fn configures_isolated_libalpm_handle() {
        let config = super::PacmanConfig::read().unwrap();

        let base =
            std::env::temp_dir().join(format!("rwr-alpm-config-test-{}", std::process::id()));
        let root = base.join("root");
        let db = base.join("db");

        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();

        {
            let handle = super::AlpmHandle::new(&root, &db).unwrap();
            let registered = handle.configure(&config).unwrap();

            println!("Architecture: {}", config.architecture);
            println!("Repositories: {registered}");

            assert_eq!(registered, config.repositories.len());
            assert_eq!(handle.local_package_count().unwrap(), 0);
        }

        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_option_add_cachedir(handle: *mut RawAlpmHandle, cachedir: *const c_char) -> i32;

    fn alpm_option_set_gpgdir(handle: *mut RawAlpmHandle, gpgdir: *const c_char) -> i32;

    fn alpm_option_set_checkspace(handle: *mut RawAlpmHandle, checkspace: i32) -> i32;
}

impl AlpmHandle {
    pub(crate) fn configure_lab_options(
        &self,
        lab: &crate::alpm_lab::AlpmLab,
    ) -> Result<(), String> {
        lab.verify_boundary()?;

        let base = lab.root().parent().ok_or("Invalid laboratory base")?;

        let cache = base.join("cache");
        let gpg = base.join("gnupg");

        let hooks = base.join("hooks");
        let logfile = base.join("pacman.log");

        self.configure_system_options(
            cache.to_str().ok_or("Invalid laboratory cache path")?,
            gpg.to_str().ok_or("Invalid laboratory GPG path")?,
            false,
        )?;

        self.set_lab_directory_options(&cache, &hooks, &logfile)
    }

    fn configure_system_options(
        &self,
        cache_dir: &str,
        gpg_dir: &str,
        check_space: bool,
    ) -> Result<(), String> {
        if cache_dir.is_empty() || gpg_dir.is_empty() {
            return Err("Missing cache or GPG directory".into());
        }

        let cache = CString::new(cache_dir).map_err(|_| "Invalid cache directory".to_string())?;
        let gpg = CString::new(gpg_dir).map_err(|_| "Invalid GPG directory".to_string())?;

        if unsafe { alpm_option_add_cachedir(self.raw.as_ptr(), cache.as_ptr()) } != 0 {
            return Err("Cannot configure libalpm cache".into());
        }

        if unsafe { alpm_option_set_gpgdir(self.raw.as_ptr(), gpg.as_ptr()) } != 0 {
            return Err("Cannot configure libalpm GPG directory".into());
        }

        if unsafe { alpm_option_set_checkspace(self.raw.as_ptr(), i32::from(check_space)) } != 0 {
            return Err("Cannot configure libalpm disk-space checks".into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod system_options_tests {
    #[test]
    fn configures_system_options_in_isolated_handle() {
        let config = super::PacmanConfig::read().unwrap();

        let base =
            std::env::temp_dir().join(format!("rwr-alpm-options-test-{}", std::process::id()));
        let root = base.join("root");
        let db = base.join("db");
        let cache = base.join("cache");
        let gpg = base.join("gnupg");

        for dir in [&root, &db, &cache, &gpg] {
            std::fs::create_dir_all(dir).unwrap();
        }

        {
            let handle = super::AlpmHandle::new(&root, &db).unwrap();

            handle
                .configure_system_options(cache.to_str().unwrap(), gpg.to_str().unwrap(), true)
                .unwrap();

            assert!(!config.cache_dir.is_empty());
            assert!(handle.configure_system_options("", "", true).is_err());
        }

        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_option_add_ignorepkg(handle: *mut RawAlpmHandle, pkg: *const c_char) -> i32;
    fn alpm_option_add_ignoregroup(handle: *mut RawAlpmHandle, grp: *const c_char) -> i32;
    fn alpm_option_add_noupgrade(handle: *mut RawAlpmHandle, path: *const c_char) -> i32;
    fn alpm_option_add_noextract(handle: *mut RawAlpmHandle, path: *const c_char) -> i32;
    fn alpm_option_add_hookdir(handle: *mut RawAlpmHandle, dir: *const c_char) -> i32;
    fn alpm_option_set_logfile(handle: *mut RawAlpmHandle, path: *const c_char) -> i32;
}

impl AlpmHandle {
    fn configure_transaction_options(&self, config: &PacmanConfig) -> Result<(), String> {
        fn apply(
            handle: *mut RawAlpmHandle,
            values: &[String],
            operation: unsafe extern "C" fn(*mut RawAlpmHandle, *const c_char) -> i32,
        ) -> Result<(), String> {
            for value in values {
                let c_value = CString::new(value.as_str())
                    .map_err(|_| format!("Invalid configuration value: {value}"))?;
                if unsafe { operation(handle, c_value.as_ptr()) } != 0 {
                    return Err(format!("libalpm rejected configuration value: {value}"));
                }
            }
            Ok(())
        }

        let handle = self.raw.as_ptr();

        apply(handle, &config.ignore_pkg, alpm_option_add_ignorepkg)?;
        apply(handle, &config.ignore_group, alpm_option_add_ignoregroup)?;
        apply(handle, &config.no_upgrade, alpm_option_add_noupgrade)?;
        apply(handle, &config.no_extract, alpm_option_add_noextract)?;
        apply(handle, &config.hook_dirs, alpm_option_add_hookdir)?;

        let logfile = CString::new(config.log_file.as_str())
            .map_err(|_| "Invalid log file path".to_string())?;

        if unsafe { alpm_option_set_logfile(handle, logfile.as_ptr()) } != 0 {
            return Err("libalpm rejected log file path".into());
        }

        Ok(())
    }
}

#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_option_get_root(handle: *mut RawAlpmHandle) -> *const c_char;
    fn alpm_option_get_dbpath(handle: *mut RawAlpmHandle) -> *const c_char;
    fn alpm_option_get_gpgdir(handle: *mut RawAlpmHandle) -> *const c_char;
    fn alpm_option_get_logfile(handle: *mut RawAlpmHandle) -> *const c_char;
    fn alpm_option_get_checkspace(handle: *mut RawAlpmHandle) -> i32;
}

#[cfg(test)]
mod option_readback_tests {
    use super::*;

    #[test]
    fn verifies_isolated_option_readback() {
        let base = std::env::temp_dir().join(format!("rwr-alpm-readback-{}", std::process::id()));
        let root = base.join("root");
        let db = base.join("db");
        let cache = base.join("cache");
        let gpg = base.join("gnupg");
        let log = base.join("pacman.log");

        for dir in [&root, &db, &cache, &gpg] {
            std::fs::create_dir_all(dir).unwrap();
        }

        {
            let handle = AlpmHandle::new(&root, &db).unwrap();
            handle
                .configure_system_options(cache.to_str().unwrap(), gpg.to_str().unwrap(), true)
                .unwrap();

            let log_c = CString::new(log.to_str().unwrap()).unwrap();
            assert_eq!(
                unsafe { alpm_option_set_logfile(handle.raw.as_ptr(), log_c.as_ptr()) },
                0
            );

            let gpg_actual = unsafe { CStr::from_ptr(alpm_option_get_gpgdir(handle.raw.as_ptr())) };
            let log_actual =
                unsafe { CStr::from_ptr(alpm_option_get_logfile(handle.raw.as_ptr())) };

            assert_eq!(
                std::path::Path::new(gpg_actual.to_str().unwrap()),
                gpg.as_path()
            );
            assert_eq!(log_actual.to_str().unwrap(), log.to_str().unwrap());
            assert_ne!(
                unsafe { alpm_option_get_checkspace(handle.raw.as_ptr()) },
                0
            );

            println!("GPG: {}", gpg_actual.to_string_lossy());
            println!("LOG: {}", log_actual.to_string_lossy());
            println!("CheckSpace: enabled");
        }

        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_option_get_cachedirs(handle: *mut RawAlpmHandle) -> *mut AlpmList;
    fn alpm_option_get_hookdirs(handle: *mut RawAlpmHandle) -> *mut AlpmList;
    fn alpm_option_get_architectures(handle: *mut RawAlpmHandle) -> *mut AlpmList;
}

#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_list_add(list: *mut AlpmList, data: *mut std::ffi::c_void) -> *mut AlpmList;
    fn alpm_option_set_cachedirs(handle: *mut RawAlpmHandle, dirs: *mut AlpmList) -> i32;
    fn alpm_option_set_hookdirs(handle: *mut RawAlpmHandle, dirs: *mut AlpmList) -> i32;
}

impl AlpmHandle {
    fn set_lab_directory_options(
        &self,
        cache: &Path,
        hooks: &Path,
        logfile: &Path,
    ) -> Result<(), String> {
        use std::os::unix::ffi::OsStrExt;

        fn replace_directory(
            handle: *mut RawAlpmHandle,
            path: &Path,
            setter: unsafe extern "C" fn(*mut RawAlpmHandle, *mut AlpmList) -> i32,
        ) -> Result<(), String> {
            let value = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| "Invalid laboratory directory path".to_string())?;

            let list = unsafe {
                alpm_list_add(
                    std::ptr::null_mut(),
                    value.as_ptr() as *mut std::ffi::c_void,
                )
            };

            if list.is_null() {
                return Err("Cannot allocate libalpm directory list".into());
            }

            let result = unsafe { setter(handle, list) };
            unsafe { alpm_list_free(list) };

            if result != 0 {
                return Err("libalpm rejected laboratory directory".into());
            }

            Ok(())
        }

        replace_directory(self.raw.as_ptr(), cache, alpm_option_set_cachedirs)?;
        replace_directory(self.raw.as_ptr(), hooks, alpm_option_set_hookdirs)?;

        let log = CString::new(logfile.as_os_str().as_bytes())
            .map_err(|_| "Invalid laboratory log path".to_string())?;

        if unsafe { alpm_option_set_logfile(self.raw.as_ptr(), log.as_ptr()) } != 0 {
            return Err("Cannot configure laboratory logfile".into());
        }

        Ok(())
    }
}

#[repr(C)]
struct AlpmList {
    data: *mut std::ffi::c_void,
    prev: *mut AlpmList,
    next: *mut AlpmList,
}

#[cfg(test)]
mod list_readback_tests {
    use super::*;

    unsafe fn list_strings(mut node: *mut AlpmList) -> Vec<String> {
        let mut values = Vec::new();
        while !node.is_null() {
            let data = unsafe { (*node).data };
            assert!(!data.is_null());
            let value = unsafe { CStr::from_ptr(data.cast::<c_char>()) };
            values.push(value.to_string_lossy().into_owned());
            node = unsafe { (*node).next };
        }
        values
    }

    #[test]
    fn verifies_isolated_list_options() {
        let base =
            std::env::temp_dir().join(format!("rwr-alpm-list-readback-{}", std::process::id()));
        let root = base.join("root");
        let db = base.join("db");
        let cache = base.join("cache");
        let gpg = base.join("gnupg");
        let hooks = base.join("hooks");

        for dir in [&root, &db, &cache, &gpg, &hooks] {
            std::fs::create_dir_all(dir).unwrap();
        }

        {
            let handle = AlpmHandle::new(&root, &db).unwrap();
            handle
                .configure_system_options(cache.to_str().unwrap(), gpg.to_str().unwrap(), true)
                .unwrap();
            handle.set_architecture("x86_64").unwrap();

            let hook = CString::new(hooks.to_str().unwrap()).unwrap();
            assert_eq!(
                unsafe { alpm_option_add_hookdir(handle.raw.as_ptr(), hook.as_ptr()) },
                0
            );

            let caches = unsafe { list_strings(alpm_option_get_cachedirs(handle.raw.as_ptr())) };
            let hookdirs = unsafe { list_strings(alpm_option_get_hookdirs(handle.raw.as_ptr())) };
            let architectures =
                unsafe { list_strings(alpm_option_get_architectures(handle.raw.as_ptr())) };

            assert!(caches.iter().any(|v| Path::new(v) == cache.as_path()));
            assert!(hookdirs.iter().any(|v| Path::new(v) == hooks.as_path()));
            assert!(architectures.iter().any(|v| v == "x86_64"));

            println!("Cache: {caches:?}");
            println!("Hooks: {hookdirs:?}");
            println!("Architectures: {architectures:?}");
        }

        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[cfg(test)]
mod laboratory_options_integration_tests {
    use super::*;

    unsafe fn read_list(mut node: *mut AlpmList) -> Vec<String> {
        let mut values = Vec::new();

        while !node.is_null() {
            let value = unsafe { CStr::from_ptr((*node).data.cast::<c_char>()) };

            values.push(value.to_string_lossy().into_owned());
            node = unsafe { (*node).next };
        }

        values
    }

    #[test]
    fn laboratory_uses_only_private_directories() {
        let lab = crate::alpm_lab::AlpmLab::create().unwrap();
        let handle = AlpmHandle::new_isolated_lab(&lab).unwrap();

        handle.configure_lab_options(&lab).unwrap();

        let base = lab.root().parent().unwrap();

        let root_ptr = unsafe { alpm_option_get_root(handle.raw.as_ptr()) };
        let db_ptr = unsafe { alpm_option_get_dbpath(handle.raw.as_ptr()) };

        assert!(!root_ptr.is_null(), "libalpm root is null");
        assert!(!db_ptr.is_null(), "libalpm dbpath is null");

        let root_actual = unsafe { CStr::from_ptr(root_ptr) };
        let db_actual = unsafe { CStr::from_ptr(db_ptr) };

        let root_path = Path::new(root_actual.to_str().unwrap());
        let db_path = Path::new(db_actual.to_str().unwrap());

        assert_eq!(
            root_path.canonicalize().unwrap(),
            lab.root().canonicalize().unwrap(),
            "libalpm root escaped laboratory"
        );

        assert_eq!(
            db_path.canonicalize().unwrap(),
            lab.db().canonicalize().unwrap(),
            "libalpm database escaped laboratory"
        );

        let caches = unsafe { read_list(alpm_option_get_cachedirs(handle.raw.as_ptr())) };

        let hooks = unsafe { read_list(alpm_option_get_hookdirs(handle.raw.as_ptr())) };

        assert_eq!(caches.len(), 1, "Expected exactly one cache directory");
        assert_eq!(hooks.len(), 1, "Expected exactly one hook directory");

        assert_eq!(Path::new(&caches[0]), base.join("cache"));
        assert_eq!(Path::new(&hooks[0]), base.join("hooks"));

        let gpg = unsafe { CStr::from_ptr(alpm_option_get_gpgdir(handle.raw.as_ptr())) };

        let log = unsafe { CStr::from_ptr(alpm_option_get_logfile(handle.raw.as_ptr())) };

        assert_eq!(Path::new(gpg.to_str().unwrap()), base.join("gnupg"));

        assert_eq!(Path::new(log.to_str().unwrap()), base.join("pacman.log"));

        assert_eq!(
            unsafe { alpm_option_get_checkspace(handle.raw.as_ptr()) },
            0
        );
    }
}

// ETAP 4.7B — RAII lifecycle; no commit or database synchronization.
#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_trans_init(handle: *mut RawAlpmHandle, flags: i32) -> i32;
    fn alpm_trans_release(handle: *mut RawAlpmHandle) -> i32;
    fn alpm_errno(handle: *mut RawAlpmHandle) -> i32;
    fn alpm_strerror(error: i32) -> *const c_char;
    fn alpm_trans_prepare(handle: *mut RawAlpmHandle, data: *mut *mut AlpmList) -> i32;
    fn alpm_trans_commit(handle: *mut RawAlpmHandle, data: *mut *mut AlpmList) -> i32;
    fn alpm_sync_sysupgrade(handle: *mut RawAlpmHandle, enable_downgrade: i32) -> i32;
    fn alpm_depmissing_free(miss: *mut std::ffi::c_void);
    fn alpm_db_update(handle: *mut RawAlpmHandle, dbs: *mut AlpmList, force: i32) -> i32;
    fn alpm_conflict_free(conflict: *mut std::ffi::c_void);
    fn alpm_fileconflict_free(conflict: *mut std::ffi::c_void);
    fn alpm_list_free(list: *mut AlpmList);
}

/// Release commit diagnostics only when their payload type is known.
fn free_commit_diagnostics(
    handle: &AlpmHandle,
    diagnostics: *mut AlpmList,
    error: i32,
) -> Result<(), String> {
    if diagnostics.is_null() {
        return Ok(());
    }

    if error != ALPM_ERR_FILE_CONFLICTS {
        unsafe { alpm_list_free(diagnostics) };
        handle.transaction_poisoned.set(true);
        return Err(format!(
            "Unknown libalpm commit diagnostics type ({error}); handle poisoned"
        ));
    }

    let mut node = diagnostics;
    while !node.is_null() {
        unsafe {
            if !(*node).data.is_null() {
                alpm_fileconflict_free((*node).data);
            }
            node = (*node).next;
        }
    }

    unsafe { alpm_list_free(diagnostics) };
    Ok(())
}

fn transaction_error(handle: &AlpmHandle, operation: &str) -> String {
    let error = unsafe { alpm_errno(handle.raw.as_ptr()) };
    let message = unsafe { alpm_strerror(error) };
    let description = if message.is_null() {
        "unknown libalpm error".to_string()
    } else {
        unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned()
    };
    format!("libalpm transaction {operation} failed ({error}): {description}")
}

#[repr(C)]
struct RawAlpmPkg {
    _private: [u8; 0],
}

#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_trans_get_add(handle: *mut RawAlpmHandle) -> *mut AlpmList;
    fn alpm_trans_get_remove(handle: *mut RawAlpmHandle) -> *mut AlpmList;
    fn alpm_pkg_get_name(pkg: *mut RawAlpmPkg) -> *const c_char;
    fn alpm_pkg_get_version(pkg: *mut RawAlpmPkg) -> *const c_char;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlpmPlannedPackage {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlpmTransactionPlan {
    pub add: Vec<AlpmPlannedPackage>,
    pub remove: Vec<AlpmPlannedPackage>,
}

/// Borrowed libalpm transaction lists and package pointers are never freed here.
/// All strings are copied into Rust-owned values before the transaction ends.
fn copy_transaction_packages(mut node: *mut AlpmList) -> Result<Vec<AlpmPlannedPackage>, String> {
    let mut packages = Vec::new();
    while !node.is_null() {
        let pkg = unsafe { (*node).data.cast::<RawAlpmPkg>() };
        if pkg.is_null() {
            return Err("libalpm transaction contains null package pointer".into());
        }
        let name = unsafe { alpm_pkg_get_name(pkg) };
        let version = unsafe { alpm_pkg_get_version(pkg) };
        if name.is_null() || version.is_null() {
            return Err("libalpm transaction contains null package name/version".into());
        }
        let name = unsafe { CStr::from_ptr(name) }
            .to_str()
            .map_err(|_| "libalpm package name is not valid UTF-8")?
            .to_owned();
        let version = unsafe { CStr::from_ptr(version) }
            .to_str()
            .map_err(|_| "libalpm package version is not valid UTF-8")?
            .to_owned();
        if name.is_empty() || version.is_empty() {
            return Err("libalpm transaction contains empty package name/version".into());
        }
        packages.push(AlpmPlannedPackage { name, version });
        node = unsafe { (*node).next };
    }
    Ok(packages)
}

// Verified by a compiled C probe against installed alpm.h/libalpm 16.0.1.
// Error numbers select destructors: a guessed offset is a memory-safety bug.
pub(crate) const ALPM_ERR_DB_INVALID_SIG: i32 = 17;
pub(crate) const ALPM_ERR_PKG_INVALID_SIG: i32 = 37;
pub(crate) const ALPM_ERR_PKG_MISSING_SIG: i32 = 38;
pub(crate) const ALPM_ERR_SIG_MISSING: i32 = 43;
pub(crate) const ALPM_ERR_SIG_INVALID: i32 = 44;
pub(crate) const ALPM_ERR_UNSATISFIED_DEPS: i32 = 45;
pub(crate) const ALPM_ERR_CONFLICTING_DEPS: i32 = 46;
pub(crate) const ALPM_ERR_FILE_CONFLICTS: i32 = 47;
pub(crate) const ALPM_ERR_RETRIEVE_PREPARE: i32 = 48;
pub(crate) const ALPM_ERR_RETRIEVE: i32 = 49;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlpmTransactionPhase {
    Initialized,
    Prepared,
    /// Reserved for a future controlled libalpm commit operation.
    Committing,
    /// Reserved for a successfully completed libalpm commit.
    Committed,
    Failed,
}

/// Internal capability for a verified laboratory sandbox, defined in
/// `sandbox_attestation`. The token is constructible only inside an
/// attested bwrap/seccomp sandbox and authorizes COMMIT only within the
/// isolated laboratory root.
use crate::sandbox_attestation::LabCommitAuthorization;

pub struct AlpmTransaction<'a> {
    handle: &'a AlpmHandle,
    active: bool,
    phase: AlpmTransactionPhase,
    selection_attempted: bool,
    download_only: bool,
}

impl<'a> AlpmTransaction<'a> {
    pub fn begin(handle: &'a AlpmHandle) -> Result<Self, String> {
        Self::begin_flags(handle, false)
    }

    pub(crate) fn begin_download_only(handle: &'a AlpmHandle) -> Result<Self, String> {
        Self::begin_flags(handle, true)
    }

    fn begin_flags(handle: &'a AlpmHandle, download_only: bool) -> Result<Self, String> {
        if handle.transaction_poisoned.get() {
            return Err("libalpm handle poisoned: create a new handle".into());
        }
        if unsafe { alpm_trans_init(handle.raw.as_ptr(), if download_only { 1 << 9 } else { 0 }) }
            != 0
        {
            return Err(transaction_error(handle, "initialization"));
        }
        Ok(Self {
            handle,
            active: true,
            phase: AlpmTransactionPhase::Initialized,
            selection_attempted: false,
            download_only,
        })
    }

    /// Select upgrade candidates from already registered sync databases.
    /// This changes only the in-memory transaction; it does not refresh databases,
    /// download packages or commit. A selection attempt is one-shot.
    pub fn select_system_upgrade(&mut self) -> Result<(), String> {
        let _crypto = self.handle.crypto_context()?;
        if !self.active {
            return Err("libalpm transaction is no longer active".into());
        }
        if self.handle.transaction_poisoned.get() {
            return Err("libalpm handle poisoned: upgrade selection refused".into());
        }
        if self.phase != AlpmTransactionPhase::Initialized || self.selection_attempted {
            return Err("libalpm upgrade selection requires fresh Initialized transaction".into());
        }
        self.selection_attempted = true;
        // 0 forbids downgrades. Failure invalidates this transaction's phase.
        if unsafe { alpm_sync_sysupgrade(self.handle.raw.as_ptr(), 0) } != 0 {
            self.phase = AlpmTransactionPhase::Failed;
            return Err(transaction_error(self.handle, "upgrade selection"));
        }
        Ok(())
    }

    /// Snapshot the current transaction selection without committing or changing it.
    /// Empty lists are valid (an isolated transaction with no selected packages).
    pub fn planned_packages(&self) -> Result<AlpmTransactionPlan, String> {
        if !self.active {
            return Err("libalpm transaction is no longer active".into());
        }
        if self.handle.transaction_poisoned.get() {
            return Err("libalpm handle poisoned: plan read refused".into());
        }
        if !matches!(
            self.phase,
            AlpmTransactionPhase::Initialized | AlpmTransactionPhase::Prepared
        ) {
            return Err("libalpm transaction failed: plan read refused".into());
        }
        let add = unsafe { alpm_trans_get_add(self.handle.raw.as_ptr()) };
        let remove = unsafe { alpm_trans_get_remove(self.handle.raw.as_ptr()) };
        Ok(AlpmTransactionPlan {
            add: copy_transaction_packages(add)?,
            remove: copy_transaction_packages(remove)?,
        })
    }

    /// Prepare the currently initialized transaction without committing it.
    /// A failed prepare can return owned dependency/conflict diagnostics.
    pub fn prepare(&mut self) -> Result<(), String> {
        let _crypto = self.handle.crypto_context()?;
        if !self.active {
            return Err("libalpm transaction is no longer active".into());
        }
        if self.handle.transaction_poisoned.get() {
            return Err("libalpm handle poisoned: prepare refused".into());
        }
        if self.phase != AlpmTransactionPhase::Initialized {
            return Err(format!("libalpm prepare refused in {:?} phase", self.phase));
        }
        // Any attempted preparation is one-shot, including failed calls.
        self.phase = AlpmTransactionPhase::Failed;
        let mut diagnostics: *mut AlpmList = std::ptr::null_mut();
        let result = unsafe { alpm_trans_prepare(self.handle.raw.as_ptr(), &mut diagnostics) };
        // Capture errno before any other libalpm operation can change it.
        let error = if result != 0 {
            unsafe { alpm_errno(self.handle.raw.as_ptr()) }
        } else {
            0
        };
        let message = if result != 0 {
            let ptr = unsafe { alpm_strerror(error) };
            if ptr.is_null() {
                "unknown libalpm error".to_string()
            } else {
                unsafe { CStr::from_ptr(ptr) }
                    .to_string_lossy()
                    .into_owned()
            }
        } else {
            String::new()
        };

        if !diagnostics.is_null() {
            // The payload type depends on the error code. Never guess a destructor.
            let destructor: Option<unsafe extern "C" fn(*mut std::ffi::c_void)> = match error {
                ALPM_ERR_UNSATISFIED_DEPS => Some(alpm_depmissing_free),
                ALPM_ERR_CONFLICTING_DEPS => Some(alpm_conflict_free),
                _ => None,
            };
            if let Some(free_item) = destructor {
                let mut node = diagnostics;
                while !node.is_null() {
                    unsafe {
                        if !(*node).data.is_null() {
                            free_item((*node).data);
                        }
                        node = (*node).next;
                    }
                }
                unsafe { alpm_list_free(diagnostics) };
            } else {
                // Free only list nodes; payload ownership is unknown.
                // Never invoke an unverified destructor on foreign pointers.
                unsafe { alpm_list_free(diagnostics) };
                self.handle.transaction_poisoned.set(true);
                return Err(format!(
                    "libalpm prepare returned unexpected diagnostics (error {error}); \
                     cannot safely free unknown payload type; handle must be discarded"
                ));
            }
        }
        if result != 0 {
            return Err(format!(
                "libalpm transaction prepare failed ({error}): {message}"
            ));
        }
        self.phase = AlpmTransactionPhase::Prepared;
        Ok(())
    }

    /// Production commit is unavailable until authorization and error handling are complete.
    pub fn commit(&mut self) -> Result<(), String> {
        Err("libalpm COMMIT blocked: production authorization not implemented".into())
    }

    /// Laboratory commit remains denied until a verified sandbox authorization
    /// mechanism is implemented. IsolatedLab origin alone is not authorization.
    pub(crate) fn commit_isolated_lab(&mut self) -> Result<(), String> {
        if !self.active
            || self.phase != AlpmTransactionPhase::Prepared
            || self.handle.origin != AlpmHandleOrigin::IsolatedLab
            || self.handle.transaction_poisoned.get()
        {
            return Err("Laboratory COMMIT refused: invalid transaction state".into());
        }

        Err("Laboratory COMMIT refused: sandbox authorization unavailable".into())
    }

    /// Controlled COMMIT inside the isolated laboratory root only.
    /// Requires a verified sandbox attestation token; the origin check and
    /// token availability make the path unreachable outside the laboratory
    /// sandbox and for production handles.
    pub(crate) fn commit_isolated_lab_authorized(
        &mut self,
        _authorization: &LabCommitAuthorization,
    ) -> Result<(), String> {
        if !self.active
            || self.phase != AlpmTransactionPhase::Prepared
            || self.handle.origin != AlpmHandleOrigin::IsolatedLab
            || self.handle.transaction_poisoned.get()
        {
            return Err("Laboratory COMMIT refused: invalid authorized transaction state".into());
        }

        let plan = self.planned_packages()?;
        crate::alpm_lab::AlpmLab::verify_fixed_upgrade_plan(&plan)?;

        self.commit_ffi()
    }

    fn commit_ffi(&mut self) -> Result<(), String> {
        let _crypto = self.handle.crypto_context()?;
        // One-shot phase transition: a failed commit invalidates the
        // transaction exactly like a failed prepare.
        self.phase = AlpmTransactionPhase::Failed;
        let mut diagnostics: *mut AlpmList = std::ptr::null_mut();
        let result = unsafe { alpm_trans_commit(self.handle.raw.as_ptr(), &mut diagnostics) };

        if result != 0 {
            self.handle.transaction_poisoned.set(true);
            let error = transaction_error(self.handle, "laboratory COMMIT");
            let _ = free_commit_diagnostics(self.handle, diagnostics, unsafe {
                alpm_errno(self.handle.raw.as_ptr())
            });
            return Err(error);
        }

        self.phase = AlpmTransactionPhase::Committed;
        Ok(())
    }

    pub fn release(mut self) -> Result<(), String> {
        self.release_inner()
    }

    fn release_inner(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        // One release attempt only, even when libalpm reports an error.
        // The parent AlpmHandle owns the final alpm_release cleanup.
        self.active = false;
        if unsafe { alpm_trans_release(self.handle.raw.as_ptr()) } != 0 {
            self.handle.transaction_poisoned.set(true);
            return Err(transaction_error(self.handle, "release"));
        }
        Ok(())
    }
}

impl Drop for AlpmTransaction<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.release_inner() {
            eprintln!("RWR transaction cleanup error: {error}");
        }
    }
}

#[cfg(test)]
mod isolated_upgrade_selection_tests {
    use super::*;

    #[test]
    fn empty_isolated_upgrade_selection_is_one_shot() {
        let base = std::env::temp_dir().join(format!(
            "rwr-select-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let root = base.join("root");
        let db = base.join("db");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        {
            let handle = AlpmHandle::new(&root, &db).unwrap();
            let mut tx = AlpmTransaction::begin(&handle).unwrap();
            tx.select_system_upgrade().unwrap();
            assert!(tx.planned_packages().unwrap().add.is_empty());
            assert!(tx.select_system_upgrade().is_err());
            tx.prepare().unwrap();
            assert!(tx.select_system_upgrade().is_err());
            tx.release().unwrap();
        }
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn poisoned_handle_refuses_upgrade_selection() {
        let base = std::env::temp_dir().join(format!(
            "rwr-select-poison-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let root = base.join("root");
        let db = base.join("db");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        {
            let handle = AlpmHandle::new(&root, &db).unwrap();
            let mut tx = AlpmTransaction::begin(&handle).unwrap();
            handle.transaction_poisoned.set(true);
            assert!(tx.select_system_upgrade().is_err());
            tx.release().unwrap();
        }
        std::fs::remove_dir_all(base).unwrap();
    }
}

#[cfg(test)]
mod transaction_plan_snapshot_tests {
    use super::*;

    #[test]
    fn isolated_empty_plan_is_owned_and_read_only() {
        let base = std::env::temp_dir().join(format!(
            "rwr-plan-snapshot-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let root = base.join("root");
        let db = base.join("db");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        {
            let handle = AlpmHandle::new(&root, &db).unwrap();
            let mut transaction = AlpmTransaction::begin(&handle).unwrap();
            let before = transaction.planned_packages().unwrap();
            assert!(before.add.is_empty() && before.remove.is_empty());
            transaction.prepare().unwrap();
            let after = transaction.planned_packages().unwrap();
            assert_eq!(before, after);
            transaction.release().unwrap();
            assert!(after.add.is_empty() && after.remove.is_empty());
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn failed_transaction_refuses_plan_snapshot() {
        let base = std::env::temp_dir().join(format!(
            "rwr-plan-failed-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let root = base.join("root");
        let db = base.join("db");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        {
            let handle = AlpmHandle::new(&root, &db).unwrap();
            let mut transaction = AlpmTransaction::begin(&handle).unwrap();
            transaction.phase = AlpmTransactionPhase::Failed;
            assert!(transaction.planned_packages().is_err());
            transaction.release().unwrap();
        }
        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[cfg(test)]
mod transaction_phase_tests {
    use super::*;

    #[test]
    fn prepare_is_one_shot_and_release_remains_available() {
        let base = std::env::temp_dir().join(format!(
            "rwr-phase-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let root = base.join("root");
        let db = base.join("db");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        {
            let handle = AlpmHandle::new(&root, &db).unwrap();
            let mut transaction = AlpmTransaction::begin(&handle).unwrap();
            assert_eq!(transaction.phase, AlpmTransactionPhase::Initialized);
            transaction.prepare().unwrap();
            assert_eq!(transaction.phase, AlpmTransactionPhase::Prepared);
            assert!(transaction.prepare().is_err());
            transaction.release().unwrap();
            assert!(!handle.transaction_poisoned.get());
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn failed_phase_refuses_prepare_without_poisoning_handle() {
        let base = std::env::temp_dir().join(format!(
            "rwr-failed-phase-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let root = base.join("root");
        let db = base.join("db");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        {
            let handle = AlpmHandle::new(&root, &db).unwrap();
            let mut transaction = AlpmTransaction::begin(&handle).unwrap();
            transaction.phase = AlpmTransactionPhase::Failed;
            assert!(transaction.prepare().is_err());
            transaction.release().unwrap();
            assert!(!handle.transaction_poisoned.get());
        }
        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[cfg(test)]
mod transaction_poison_tests {
    use super::*;

    #[test]
    fn poisoned_handle_rejects_new_transaction() {
        let base = std::env::temp_dir().join(format!(
            "rwr-poison-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let root = base.join("root");
        let db = base.join("db");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        {
            let handle = AlpmHandle::new(&root, &db).unwrap();
            let mut transaction = AlpmTransaction::begin(&handle).unwrap();
            handle.transaction_poisoned.set(true);
            assert!(transaction.prepare().is_err());
            transaction.release().unwrap();
            assert!(AlpmTransaction::begin(&handle).is_err());
        }
        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[cfg(test)]
mod transaction_raii_tests {
    use super::*;

    #[test]
    fn isolated_transaction_releases_and_can_restart() {
        let base = std::env::temp_dir().join(format!(
            "rwr-raii-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let root = base.join("root");
        let db = base.join("db");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        {
            let handle = AlpmHandle::new(&root, &db).unwrap();
            let transaction = AlpmTransaction::begin(&handle).unwrap();
            assert!(AlpmTransaction::begin(&handle).is_err());
            transaction.release().unwrap();
            let transaction = AlpmTransaction::begin(&handle).unwrap();
            drop(transaction);
            AlpmTransaction::begin(&handle).unwrap().release().unwrap();
            assert_eq!(handle.local_package_count().unwrap(), 0);
        }
        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[cfg(test)]
mod isolated_transaction_lifecycle_tests {
    use super::*;

    #[link(name = "alpm")]
    unsafe extern "C" {
        fn alpm_trans_init(handle: *mut RawAlpmHandle, flags: i32) -> i32;
        fn alpm_trans_release(handle: *mut RawAlpmHandle) -> i32;
    }

    #[test]
    fn isolated_transaction_init_and_release() {
        let base =
            std::env::temp_dir().join(format!("rwr-alpm-transaction-{}", std::process::id()));
        let root = base.join("root");
        let db = base.join("db");

        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();

        {
            let handle = AlpmHandle::new(&root, &db).unwrap();

            assert_eq!(
                unsafe { alpm_trans_init(handle.raw.as_ptr(), 0) },
                0,
                "Cannot initialize isolated transaction"
            );

            assert_eq!(
                unsafe { alpm_trans_release(handle.raw.as_ptr()) },
                0,
                "Cannot release isolated transaction"
            );

            assert_eq!(handle.local_package_count().unwrap(), 0);
            println!("Transaction: initialized and released");
            println!("Installed packages: 0");
            println!("Commit: NOT CALLED");
        }

        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[cfg(test)]
mod commit_diagnostics_tests {
    use super::*;

    #[test]
    fn empty_commit_diagnostics_are_safe() {
        let base = std::env::temp_dir().join(format!(
            "rwr-commit-diagnostics-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let root = base.join("root");
        let db = base.join("db");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();

        {
            let handle = AlpmHandle::new(&root, &db).unwrap();
            let empty = std::ptr::null_mut();

            free_commit_diagnostics(&handle, empty, ALPM_ERR_FILE_CONFLICTS).unwrap();
            assert!(!handle.transaction_poisoned.get());

            free_commit_diagnostics(&handle, empty, -1).unwrap();
            assert!(!handle.transaction_poisoned.get());
        }

        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[cfg(test)]
mod commit_gate_tests {
    use super::*;

    #[test]
    fn prepared_transaction_refuses_commit() {
        let base = std::env::temp_dir().join(format!(
            "rwr-commit-gate-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let root = base.join("root");
        let db = base.join("db");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        let handle = AlpmHandle::new(&root, &db).unwrap();
        let mut tx = AlpmTransaction::begin(&handle).unwrap();
        tx.prepare().unwrap();
        assert_eq!(tx.phase, AlpmTransactionPhase::Prepared);
        let error = tx.commit().unwrap_err();
        assert!(error.contains("COMMIT blocked"));
        assert_eq!(tx.phase, AlpmTransactionPhase::Prepared);
        tx.release().unwrap();
        drop(handle);
        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[cfg(test)]
mod isolated_lab_commit_gate_tests {
    use super::*;

    #[test]
    fn isolated_lab_origin_does_not_authorize_commit() {
        let lab = crate::alpm_lab::AlpmLab::create().unwrap();

        {
            let handle = AlpmHandle::new_isolated_lab(&lab).unwrap();

            assert_eq!(handle.origin, AlpmHandleOrigin::IsolatedLab);

            let mut transaction = AlpmTransaction::begin(&handle).unwrap();

            transaction.prepare().unwrap();

            assert_eq!(transaction.phase, AlpmTransactionPhase::Prepared);

            let error = transaction.commit().unwrap_err();

            assert!(error.contains("COMMIT blocked"));
            assert_eq!(transaction.phase, AlpmTransactionPhase::Prepared);

            transaction.release().unwrap();
        }
    }
}

#[cfg(test)]
mod isolated_prepare_tests {
    use super::*;

    #[test]
    fn prepares_empty_isolated_transaction() {
        let base = std::env::temp_dir().join(format!(
            "rwr-alpm-prepare-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));

        let root = base.join("root");
        let db = base.join("db");

        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();

        {
            let handle = AlpmHandle::new(&root, &db).unwrap();

            let mut transaction = AlpmTransaction::begin(&handle).unwrap();
            transaction
                .prepare()
                .expect("Empty transaction preparation failed");
            assert_eq!(handle.local_package_count().unwrap(), 0);

            println!("INIT: PASS");
            println!("PREPARE: PASS");
            println!("PACKAGES: 0");
            println!("COMMIT: NOT CALLED");

            transaction.release().unwrap();
            println!("RELEASE: PASS");
        }

        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[cfg(test)]
mod isolated_transaction_state_tests {
    use super::*;

    #[link(name = "alpm")]
    unsafe extern "C" {
        fn alpm_trans_init(handle: *mut RawAlpmHandle, flags: i32) -> i32;
        fn alpm_trans_release(handle: *mut RawAlpmHandle) -> i32;
    }

    #[test]
    fn prevents_duplicate_transaction_and_allows_restart() {
        let base = std::env::temp_dir().join(format!(
            "rwr-alpm-state-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let root = base.join("root");
        let db = base.join("db");

        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();

        {
            let handle = AlpmHandle::new(&root, &db).unwrap();
            let raw = handle.raw.as_ptr();

            assert_eq!(unsafe { alpm_trans_init(raw, 0) }, 0);
            println!("FIRST INIT: PASS");

            assert_ne!(
                unsafe { alpm_trans_init(raw, 0) },
                0,
                "Duplicate transaction unexpectedly accepted"
            );
            println!("DUPLICATE INIT: REJECTED");

            assert_eq!(unsafe { alpm_trans_release(raw) }, 0);
            println!("RELEASE: PASS");

            assert_eq!(unsafe { alpm_trans_init(raw, 0) }, 0);
            println!("RESTART: PASS");

            assert_eq!(unsafe { alpm_trans_release(raw) }, 0);
            println!("FINAL RELEASE: PASS");

            assert_eq!(handle.local_package_count().unwrap(), 0);
            println!("COMMIT: NOT CALLED");
        }

        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacmanConfig {
    pub root: String,
    pub db_path: String,
    pub cache_dir: String,
    pub gpg_dir: String,
    pub check_space: bool,
    pub architecture: String,
    pub repositories: Vec<String>,
    pub repository_servers: Vec<(String, Vec<String>)>,
    pub signature_policy: Vec<String>,
    pub repository_signature_policies: Vec<(String, Vec<String>)>,
    pub ignore_pkg: Vec<String>,
    pub ignore_group: Vec<String>,
    pub no_upgrade: Vec<String>,
    pub no_extract: Vec<String>,
    pub hook_dirs: Vec<String>,
    pub log_file: String,
}

fn pacman_conf(args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("/usr/bin/pacman-conf")
        .args(args)
        .output()
        .map_err(|error| format!("Cannot execute pacman-conf: {error}"))?;

    if !output.status.success() {
        return Err(format!("pacman-conf failed: {}", output.status));
    }

    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|error| format!("Invalid pacman-conf output: {error}"))
}

impl PacmanConfig {
    /// Copy of this configuration restricted to HTTPS mirrors, in pacman's order.
    /// Every configured repository must keep at least one HTTPS mirror; all other
    /// settings (signature levels, paths, ignores, hooks) are left unchanged.
    pub(crate) fn https_only_execution(&self) -> Result<Self, String> {
        let mut config = self.clone();
        if config.repository_servers.len() != config.repositories.len() {
            return Err("System execution requires servers for every repository".into());
        }
        for (repo, servers) in &mut config.repository_servers {
            servers.retain(|url| url.starts_with("https://") && url.len() > "https://".len());
            if servers.is_empty() {
                return Err(format!(
                    "System execution requires an HTTPS mirror for repository: {repo}"
                ));
            }
        }
        Ok(config)
    }

    pub fn read() -> Result<Self, String> {
        let repositories: Vec<String> = pacman_conf(&["--repo-list"])?
            .lines()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .collect();

        Ok(Self {
            root: pacman_conf(&["RootDir"])?,
            db_path: pacman_conf(&["DBPath"])?,
            cache_dir: pacman_conf(&["CacheDir"])?,
            gpg_dir: pacman_conf(&["GPGDir"])?,
            check_space: pacman_conf(&["CheckSpace"])?
                .lines()
                .any(|line| line.trim() == "CheckSpace"),
            architecture: pacman_conf(&["Architecture"])?,
            repository_servers: repositories
                .iter()
                .map(|repo| {
                    let servers: Vec<String> = pacman_conf(&["--repo", repo, "Server"])?
                        .lines()
                        .map(str::trim)
                        .filter(|server| !server.is_empty())
                        .map(str::to_owned)
                        .collect();

                    if servers.is_empty() {
                        return Err(format!("No servers configured for repository: {repo}"));
                    }

                    Ok((repo.clone(), servers))
                })
                .collect::<Result<Vec<_>, String>>()?,
            signature_policy: pacman_conf(&["SigLevel"])?
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_owned)
                .collect(),
            repository_signature_policies: repositories
                .iter()
                .map(|repo| {
                    let policy = pacman_conf(&["--repo", repo, "SigLevel"])?
                        .lines()
                        .map(str::trim)
                        .filter(|line| !line.is_empty())
                        .map(str::to_owned)
                        .collect();
                    Ok((repo.clone(), policy))
                })
                .collect::<Result<Vec<_>, String>>()?,
            ignore_pkg: pacman_conf(&["IgnorePkg"])?
                .lines()
                .map(str::to_owned)
                .collect(),
            ignore_group: pacman_conf(&["IgnoreGroup"])?
                .lines()
                .map(str::to_owned)
                .collect(),
            no_upgrade: pacman_conf(&["NoUpgrade"])?
                .lines()
                .map(str::to_owned)
                .collect(),
            no_extract: pacman_conf(&["NoExtract"])?
                .lines()
                .map(str::to_owned)
                .collect(),
            hook_dirs: pacman_conf(&["HookDir"])?
                .lines()
                .map(str::to_owned)
                .collect(),
            log_file: pacman_conf(&["LogFile"])?,
            repositories,
        })
    }
}

#[cfg(test)]
mod config_tests {
    #[test]
    fn reads_real_pacman_configuration() {
        let config = super::PacmanConfig::read().unwrap();

        println!("Root: {}", config.root);
        println!("DB: {}", config.db_path);
        println!("Cache: {}", config.cache_dir);
        println!("Architecture: {}", config.architecture);
        println!("Repositories: {:?}", config.repositories);

        assert!(!config.root.is_empty());
        assert!(!config.db_path.is_empty());
        assert!(!config.architecture.is_empty());
        assert!(!config.repositories.is_empty());
    }
}

#[cfg(test)]
mod isolated_fixture_upgrade_tests {
    use super::*;

    #[test]
    fn isolated_fixture_selects_real_upgrade_1_0_to_1_1() {
        let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/alpm-upgrade-lab/local/var/lib/pacman");
        let base = std::env::temp_dir().join(format!(
            "rwr-alpm-fixture-upgrade-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        assert!(
            !base.exists(),
            "Refusing to overwrite an existing test directory"
        );
        let root = base.join("root");
        let db = root.join("var/lib/pacman");
        let local_dir = db.join("local/rwr-test-package-1.0-1");
        std::fs::create_dir_all(&local_dir).unwrap();
        std::fs::create_dir_all(db.join("sync")).unwrap();
        std::fs::copy(
            fixture.join("local/ALPM_DB_VERSION"),
            db.join("local/ALPM_DB_VERSION"),
        )
        .unwrap();
        std::fs::copy(
            fixture.join("local/rwr-test-package-1.0-1/desc"),
            local_dir.join("desc"),
        )
        .unwrap();
        std::fs::copy(
            fixture.join("local/rwr-test-package-1.0-1/files"),
            local_dir.join("files"),
        )
        .unwrap();
        std::fs::copy(
            fixture.join("sync/rwr-test.db"),
            db.join("sync/rwr-test.db"),
        )
        .unwrap();

        {
            let handle = AlpmHandle::new(&root, &db).unwrap();
            handle.set_architecture("x86_64").unwrap();
            assert_eq!(handle.local_package_count().unwrap(), 1);
            // Test-only unsigned repository; no production configuration is changed.
            let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/alpm-upgrade-lab/repository");
            let repository_url = format!("file://{}", repository.display());
            handle
                .register_test_repository("rwr-test", &repository_url)
                .unwrap();
            let mut tx = AlpmTransaction::begin(&handle).unwrap();
            tx.select_system_upgrade().unwrap();
            let before = tx.planned_packages().unwrap();
            assert_eq!(
                before.add,
                vec![AlpmPlannedPackage {
                    name: "rwr-test-package".into(),
                    version: "1.1-1".into(),
                }]
            );
            assert!(before.remove.is_empty());
            tx.prepare().unwrap();
            assert_eq!(tx.planned_packages().unwrap(), before);
            tx.release().unwrap();
            assert!(!handle.transaction_poisoned.get());
            // There is deliberately no alpm_trans_commit call.
        }
        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[cfg(test)]
mod laboratory_commit_authorization_tests {
    use super::*;

    #[test]
    fn prepared_laboratory_transaction_cannot_commit_without_authorization() {
        let lab = crate::alpm_lab::AlpmLab::create().unwrap();
        let handle = AlpmHandle::new_isolated_lab(&lab).unwrap();
        let mut transaction = AlpmTransaction::begin(&handle).unwrap();

        transaction.prepare().unwrap();

        let error = transaction.commit_isolated_lab().unwrap_err();
        assert!(error.contains("sandbox authorization unavailable"));
        assert_eq!(transaction.phase, AlpmTransactionPhase::Prepared);

        assert!(transaction.commit().is_err());
        transaction.release().unwrap();
    }

    #[test]
    fn unprepared_laboratory_transaction_is_refused() {
        let lab = crate::alpm_lab::AlpmLab::create().unwrap();
        let handle = AlpmHandle::new_isolated_lab(&lab).unwrap();
        let mut transaction = AlpmTransaction::begin(&handle).unwrap();

        let error = transaction.commit_isolated_lab().unwrap_err();
        assert!(error.contains("invalid transaction state"));

        transaction.release().unwrap();
    }
}

// ETAP 4.5Q-F: real libalpm callback registration test.
#[cfg(test)]
mod callback_registration_tests {
    use super::*;

    #[link(name = "alpm")]
    unsafe extern "C" {
        fn alpm_option_get_eventcb_ctx(handle: *mut RawAlpmHandle) -> *mut std::ffi::c_void;
    }

    #[test]
    fn isolated_lab_registers_stable_callback_context() {
        let lab = crate::alpm_lab::AlpmLab::create().unwrap();
        let mut handle = AlpmHandle::new_isolated_lab(&lab).unwrap();

        let expected =
            handle.callback_context.as_mut() as *mut CallbackContext as *mut std::ffi::c_void;

        assert!(!expected.is_null());

        handle.register_lab_event_callback().unwrap();

        let actual = unsafe { alpm_option_get_eventcb_ctx(handle.raw.as_ptr()) };

        assert_eq!(actual, expected);
        assert_eq!(handle.laboratory_event_count(), 0);

        // Drop unregisters callback before releasing libalpm.
    }

    #[test]
    fn untrusted_handle_cannot_register_lab_callback() {
        let lab = crate::alpm_lab::AlpmLab::create().unwrap();

        let handle_root = lab.root();
        let handle_db = lab.db();

        let mut handle = AlpmHandle::new(handle_root, handle_db).unwrap();

        assert!(handle.register_lab_event_callback().is_err());
        assert_eq!(handle.laboratory_event_count(), 0);
    }
}

// ETAP 4.5Q-G1: real event delivery from isolated libalpm.
#[cfg(test)]
mod callback_event_delivery_tests {
    use super::*;

    #[test]
    fn isolated_prepare_reports_actual_event_count() {
        let lab = crate::alpm_lab::AlpmLab::create().unwrap();
        let mut handle = AlpmHandle::new_isolated_lab(&lab).unwrap();

        handle.register_lab_event_callback().unwrap();

        let before = handle.laboratory_event_count();

        {
            let mut transaction = AlpmTransaction::begin(&handle).unwrap();

            transaction.prepare().unwrap();

            assert_eq!(transaction.phase, AlpmTransactionPhase::Prepared);

            transaction.release().unwrap();
        }

        let after = handle.laboratory_event_count();

        println!("EVENTS BEFORE: {before}");
        println!("EVENTS AFTER: {after}");
        println!("EVENTS DELIVERED: {}", after.saturating_sub(before));
        println!("COMMIT: NOT CALLED");

        // Empty PREPARE may legitimately produce zero events.
        // Do not claim delivery unless the counter increases.
        assert!(after >= before);
    }
}

// ETAP 4.5Q-J: real libalpm upgrade event delivery.
#[cfg(test)]
mod callback_upgrade_event_tests {
    use super::*;

    #[test]
    fn isolated_upgrade_delivers_real_libalpm_events() {
        let lab = crate::alpm_lab::AlpmLab::create().unwrap();
        let mut handle = AlpmHandle::new_isolated_lab(&lab).unwrap();

        handle.register_lab_event_callback().unwrap();
        handle.set_lab_architecture().unwrap();

        handle
            .register_fixed_lab_repository(&lab.repository())
            .unwrap();

        let before = handle.laboratory_event_count();

        {
            let mut tx = AlpmTransaction::begin(&handle).unwrap();

            tx.select_system_upgrade().unwrap();

            let plan = tx.planned_packages().unwrap();

            assert!(
                plan.add
                    .iter()
                    .any(|pkg| pkg.name == "rwr-test-package" && pkg.version == "1.1-1"),
                "Expected laboratory upgrade 1.0-1 -> 1.1-1"
            );

            tx.prepare().unwrap();

            assert_eq!(tx.phase, AlpmTransactionPhase::Prepared);

            tx.release().unwrap();
        }

        let after = handle.laboratory_event_count();
        let delivered = after.saturating_sub(before);

        println!("EVENTS BEFORE: {before}");
        println!("EVENTS AFTER: {after}");
        println!("EVENTS DELIVERED: {delivered}");
        println!(
            "CHECKDEPS EVENTS: {}",
            handle
                .callback_context
                .checkdeps_count
                .load(std::sync::atomic::Ordering::Relaxed)
        );
        println!(
            "RESOLVEDEPS EVENTS: {}",
            handle
                .callback_context
                .resolvedeps_count
                .load(std::sync::atomic::Ordering::Relaxed)
        );
        println!(
            "OTHER EVENTS: {}",
            handle
                .callback_context
                .other_event_count
                .load(std::sync::atomic::Ordering::Relaxed)
        );

        let classified = handle
            .callback_context
            .checkdeps_count
            .load(std::sync::atomic::Ordering::Relaxed)
            + handle
                .callback_context
                .resolvedeps_count
                .load(std::sync::atomic::Ordering::Relaxed)
            + handle
                .callback_context
                .other_event_count
                .load(std::sync::atomic::Ordering::Relaxed);

        assert_eq!(classified, after);

        for (event_type, counter) in handle.callback_context.event_types.iter().enumerate() {
            let count = counter.load(std::sync::atomic::Ordering::Relaxed);
            if count > 0 {
                println!("ALPM EVENT TYPE {event_type}: {count}");
                if let Some((pl, en)) = alpm_event_message(event_type as i32) {
                    println!("PL: {pl}");
                    println!("EN: {en}");
                }
            }
        }

        // O2: verify real callback observations after isolated PREPARE.
        let snapshot = handle.laboratory_event_snapshot();
        for code in [5, 6, 7, 8] {
            assert!(
                snapshot
                    .iter()
                    .any(|(observed, count)| *observed == code && *count > 0),
                "Missing expected libalpm event {code}"
            );
        }
        let sequence = handle.laboratory_event_sequence();
        assert!(!sequence.is_empty(), "Laboratory event sequence is empty");
        for code in [5, 6, 7, 8] {
            assert!(
                sequence.contains(&code),
                "Missing event {code} in laboratory sequence"
            );
        }
        println!("LAB EVENT SEQUENCE: {:?}", sequence);
        println!("LAB EVENT SEQUENCE: VERIFIED");

        println!("LAB CALLBACK SNAPSHOT: VERIFIED");

        println!("LAB UPGRADE: PREPARED");
        println!("COMMIT: NOT CALLED");

        assert!(
            delivered > 0,
            "libalpm did not deliver an event during laboratory upgrade"
        );
    }
}

// Owned PREPARE details for the production plan UI; no borrowed FFI pointers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlpmUpgradePackage {
    pub name: String,
    pub installed_version: Option<String>,
    /// Full `[epoch:]pkgver-pkgrel`.
    pub version: String,
    pub repository: String,
    pub arch: String,
    /// Archive identity: exact repository file name, SHA256 and embedded PGP
    /// signature. Download verification checks the archive against these.
    pub filename: String,
    pub sha256: String,
    pub signature: Option<String>,
    pub dependencies: Vec<String>,
    /// Relations that steer dependency resolution and conflict handling.
    pub provides: Vec<String>,
    pub conflicts: Vec<String>,
    pub replaces: Vec<String>,
    pub dependency_added: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlpmPreparedUpgrade {
    pub add: Vec<AlpmUpgradePackage>,
    pub remove: Vec<AlpmPlannedPackage>,
    pub decisions: Vec<i32>,
}

#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_get_syncdbs(handle: *mut RawAlpmHandle) -> *mut AlpmList;
    fn alpm_db_get_pkg(db: *mut RawAlpmDb, name: *const c_char) -> *mut RawAlpmPkg;
    fn alpm_db_get_name(db: *const RawAlpmDb) -> *const c_char;
    fn alpm_pkg_get_db(pkg: *mut RawAlpmPkg) -> *mut RawAlpmDb;
    fn alpm_pkg_get_sha256sum(pkg: *mut RawAlpmPkg) -> *const c_char;
    fn alpm_pkg_get_depends(pkg: *mut RawAlpmPkg) -> *mut AlpmList;
    fn alpm_pkg_get_provides(pkg: *mut RawAlpmPkg) -> *mut AlpmList;
    fn alpm_pkg_get_conflicts(pkg: *mut RawAlpmPkg) -> *mut AlpmList;
    fn alpm_pkg_get_replaces(pkg: *mut RawAlpmPkg) -> *mut AlpmList;
    fn alpm_dep_compute_string(dep: *const std::ffi::c_void) -> *mut c_char;
    fn alpm_option_set_questioncb(
        handle: *mut RawAlpmHandle,
        callback: Option<unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void)>,
        context: *mut std::ffi::c_void,
    ) -> i32;
}

// alpm_question_any_t's two fields are always accessible, per alpm.h.
#[repr(C)]
struct PlanQuestion {
    kind: i32,
    answer: i32,
}

unsafe extern "C" fn plan_question_callback(
    context: *mut std::ffi::c_void,
    question: *mut std::ffi::c_void,
) {
    if context.is_null() || question.is_null() {
        return;
    }
    let context = unsafe { &*(context as *const CallbackContext) };
    let question = unsafe { &mut *(question as *mut PlanQuestion) };
    // Preview replacements/conflict removals are included for explicit review.
    // Never ignore packages, skip unresolved targets, delete files or import keys.
    // Provider index 0 is recorded as a decision in the reviewed plan.
    question.answer = if matches!(question.kind, 2 | 4) {
        let bridge = context
            .interactive_questions
            .lock()
            .ok()
            .and_then(|bridge| bridge.clone());
        if let Some(bridge) = bridge {
            i32::from(bridge.ask(question.kind))
        } else {
            1
        }
    } else {
        0
    };
    if let Ok(mut questions) = context.plan_questions.lock() {
        if questions.len() < 1024 {
            questions.push(question.kind);
        }
    }
}

impl AlpmHandle {
    pub(crate) fn new_private_plan(root: &Path, private_base: &Path) -> Result<Self, String> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = std::fs::symlink_metadata(private_base).map_err(|e| e.to_string())?;
        if !metadata.is_dir()
            || metadata.permissions().mode() & 0o777 != 0o700
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err("Planning directory is not private and owned".into());
        }
        let mut handle = Self::new(root, &private_base.join("db"))?;
        handle.origin = AlpmHandleOrigin::PrivatePlan;
        Ok(handle)
    }

    /// Caller must use a private database path. Only repository databases are
    /// downloaded; no package payload, root filesystem or system db is changed.
    pub(crate) fn refresh_plan_databases(&self) -> Result<(), String> {
        if self.origin != AlpmHandleOrigin::PrivatePlan {
            return Err("Database refresh requires a private planning handle".into());
        }
        let _crypto = self.crypto_context()?;
        let databases = unsafe { alpm_get_syncdbs(self.raw.as_ptr()) };
        if databases.is_null() {
            return Err("No repositories configured for full upgrade".into());
        }
        if unsafe { alpm_db_update(self.raw.as_ptr(), databases, 1) } < 0 {
            return Err(transaction_error(
                self,
                "private repository synchronization",
            ));
        }
        Ok(())
    }

    pub(crate) fn configure_plan_questions(&self) -> Result<(), String> {
        if unsafe {
            alpm_option_set_questioncb(
                self.raw.as_ptr(),
                Some(plan_question_callback),
                (&*self.callback_context as *const CallbackContext)
                    .cast_mut()
                    .cast(),
            )
        } != 0
        {
            return Err("Cannot configure PREPARE questions".into());
        }
        Ok(())
    }
}

fn owned_alpm_string(pointer: *const c_char) -> Result<String, String> {
    if pointer.is_null() {
        return Err("Missing ALPM package metadata".into());
    }
    unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .map(str::to_owned)
        .map_err(|e| e.to_string())
}

impl AlpmTransaction<'_> {
    pub(crate) fn matches_plan_source(&self, root: &Path, database: &Path) -> Result<bool, String> {
        let actual_root =
            owned_alpm_string(unsafe { alpm_option_get_root(self.handle.raw.as_ptr()) })?;
        let actual_db =
            owned_alpm_string(unsafe { alpm_option_get_dbpath(self.handle.raw.as_ptr()) })?;
        Ok(self.active
            && self.phase == AlpmTransactionPhase::Prepared
            && Path::new(&actual_root)
                .canonicalize()
                .map_err(|e| e.to_string())?
                == root.canonicalize().map_err(|e| e.to_string())?
            && Path::new(&actual_db)
                .canonicalize()
                .map_err(|e| e.to_string())?
                == database.canonicalize().map_err(|e| e.to_string())?)
    }

    /// Requires successful dependency resolution; snapshots selection as well as
    /// installed versions, repositories, archive checksums and dependencies.
    pub fn prepared_upgrade_details(
        &self,
        initial: &AlpmTransactionPlan,
    ) -> Result<AlpmPreparedUpgrade, String> {
        if self.phase != AlpmTransactionPhase::Prepared
            || !self.active
            || self.handle.transaction_poisoned.get()
        {
            return Err("Upgrade details require a live, successful PREPARE".into());
        }
        let basic = self.planned_packages()?;
        let local = unsafe { alpm_get_localdb(self.handle.raw.as_ptr()) };
        if local.is_null() {
            return Err("Missing installed package database".into());
        }
        let mut add = Vec::new();
        let mut node = unsafe { alpm_trans_get_add(self.handle.raw.as_ptr()) };
        while !node.is_null() {
            let pkg = unsafe { (*node).data.cast::<RawAlpmPkg>() };
            if pkg.is_null() {
                return Err("Null package in prepared upgrade".into());
            }
            let name = owned_alpm_string(unsafe { alpm_pkg_get_name(pkg) })?;
            let name_c = CString::new(name.as_str()).map_err(|e| e.to_string())?;
            let installed = unsafe { alpm_db_get_pkg(local, name_c.as_ptr()) };
            let installed_version = if installed.is_null() {
                None
            } else {
                Some(owned_alpm_string(unsafe {
                    alpm_pkg_get_version(installed)
                })?)
            };
            let db = unsafe { alpm_pkg_get_db(pkg) };
            if db.is_null() {
                return Err("Prepared package has no repository".into());
            }
            let sha256 = owned_alpm_string(unsafe { alpm_pkg_get_sha256sum(pkg) })?;
            if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("Prepared package lacks valid archive SHA256".into());
            }
            fn dependency_strings(mut dep: *mut AlpmList) -> Result<Vec<String>, String> {
                let mut values = Vec::new();
                while !dep.is_null() {
                    if unsafe { (*dep).data.is_null() } {
                        return Err("Null ALPM dependency".into());
                    }
                    let raw = unsafe { alpm_dep_compute_string((*dep).data) };
                    let result = owned_alpm_string(raw);
                    unsafe {
                        libc::free(raw.cast());
                    }
                    values.push(result?);
                    dep = unsafe { (*dep).next };
                }
                values.sort();
                Ok(values)
            }
            let raw_signature = unsafe { alpm_pkg_get_base64_sig(pkg) };
            let signature = if raw_signature.is_null() {
                None
            } else {
                Some(owned_alpm_string(raw_signature)?)
            };
            add.push(AlpmUpgradePackage {
                dependency_added: !initial.add.iter().any(|p| p.name == name),
                name,
                installed_version,
                version: owned_alpm_string(unsafe { alpm_pkg_get_version(pkg) })?,
                repository: owned_alpm_string(unsafe { alpm_db_get_name(db) })?,
                arch: owned_alpm_string(unsafe { alpm_pkg_get_arch(pkg) })?,
                filename: owned_alpm_string(unsafe { alpm_pkg_get_filename(pkg) })?,
                sha256,
                signature,
                dependencies: dependency_strings(unsafe { alpm_pkg_get_depends(pkg) })?,
                provides: dependency_strings(unsafe { alpm_pkg_get_provides(pkg) })?,
                conflicts: dependency_strings(unsafe { alpm_pkg_get_conflicts(pkg) })?,
                replaces: dependency_strings(unsafe { alpm_pkg_get_replaces(pkg) })?,
            });
            node = unsafe { (*node).next };
        }
        add.sort_by(|a, b| a.name.cmp(&b.name));
        let mut remove = basic.remove;
        remove.sort_by(|a, b| a.name.cmp(&b.name));
        let decisions = self
            .handle
            .callback_context
            .plan_questions
            .lock()
            .map_err(|_| "PREPARE question log poisoned")?
            .clone();
        if decisions.len() >= 1024
            || decisions
                .iter()
                .any(|kind| !matches!(kind, 1 | 2 | 4 | 8 | 16 | 32 | 64))
        {
            return Err("Unsupported or excessive PREPARE questions".into());
        }
        Ok(AlpmPreparedUpgrade {
            add,
            remove,
            decisions,
        })
    }
}

/// libalpm's SHA256 implementation; the returned allocation belongs to caller.
pub(crate) fn plan_file_sha256(path: &Path) -> Result<String, String> {
    use std::os::unix::ffi::OsStrExt;
    #[link(name = "alpm")]
    unsafe extern "C" {
        fn alpm_compute_sha256sum(filename: *const c_char) -> *mut c_char;
    }
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let raw = unsafe { alpm_compute_sha256sum(path.as_ptr()) };
    let result = owned_alpm_string(raw);
    unsafe {
        libc::free(raw.cast());
    }
    result
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DownloadTarget {
    name: String,
    version: String,
    filename: String,
    sha256: String,
    signature: String,
}

/// Opaque receipt: only libalpm's required/trusted PGP verification creates it.
pub(crate) struct VerifiedDownloads {
    cache: std::path::PathBuf,
    targets: Vec<DownloadTarget>,
}

#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_pkg_get_filename(pkg: *mut RawAlpmPkg) -> *const c_char;
    fn alpm_pkg_get_arch(pkg: *mut RawAlpmPkg) -> *const c_char;
    fn alpm_pkg_get_base64_sig(pkg: *mut RawAlpmPkg) -> *const c_char;
    fn alpm_decode_signature(base64: *const c_char, data: *mut *mut u8, length: *mut usize) -> i32;
    fn alpm_pkg_load(
        handle: *mut RawAlpmHandle,
        path: *const c_char,
        full: i32,
        level: i32,
        pkg: *mut *mut RawAlpmPkg,
    ) -> i32;
    fn alpm_pkg_get_validation(pkg: *mut RawAlpmPkg) -> i32;
    fn alpm_pkg_free(pkg: *mut RawAlpmPkg) -> i32;
    fn alpm_trans_interrupt(handle: *mut RawAlpmHandle) -> i32;
}

/// Archive extensions repo-add/pacman produce for packages.
const PACKAGE_ARCHIVE_EXTENSIONS: [&str; 8] = [
    ".pkg.tar.zst",
    ".pkg.tar.xz",
    ".pkg.tar.gz",
    ".pkg.tar.bz2",
    ".pkg.tar.lz4",
    ".pkg.tar.lzo",
    ".pkg.tar.lrz",
    ".pkg.tar.Z",
];

/// A repository archive name is joined to the cache directory, so it must be a
/// single safe path component AND exactly `{name}-{version}-{arch}{ext}` for
/// the package ALPM selected. `version` is `[epoch:]pkgver-pkgrel`; the only
/// ':' allowed is the numeric epoch separator.
fn validate_package_archive_filename(
    filename: &str,
    name: &str,
    version: &str,
    arch: &str,
) -> Result<(), String> {
    let unsafe_name = || Err("Unsafe package archive filename".to_string());
    if filename.is_empty()
        || filename.len() > 255
        || filename.starts_with('.')
        || !filename
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._+-:".contains(&b))
    {
        return unsafe_name();
    }
    // Package names never contain ':' (makepkg); arch is a plain word.
    if name.is_empty()
        || name.starts_with(['.', '-'])
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._+-".contains(&b))
        || arch.is_empty()
        || !arch.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return unsafe_name();
    }
    // Only a numeric epoch may carry ':'; pkgver/pkgrel never do.
    let unversioned = match version.split_once(':') {
        Some((epoch, rest)) => {
            if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) {
                return unsafe_name();
            }
            rest
        }
        None => version,
    };
    if unversioned.is_empty() || unversioned.contains(':') || !unversioned.contains('-') {
        return unsafe_name();
    }
    let stem = format!("{name}-{version}-{arch}");
    match filename.strip_prefix(stem.as_str()) {
        Some(extension) if PACKAGE_ARCHIVE_EXTENSIONS.contains(&extension) => Ok(()),
        _ => unsafe_name(),
    }
}

#[cfg(test)]
mod package_archive_filename_tests {
    use super::validate_package_archive_filename as check;

    #[test]
    fn accepts_real_arch_names_including_epoch() {
        for (file, name, version, arch) in [
            (
                "zlib-1:1.4-1-x86_64.pkg.tar.zst",
                "zlib",
                "1:1.4-1",
                "x86_64",
            ),
            (
                "fakeroot-2:1.37.2-1-x86_64.pkg.tar.zst",
                "fakeroot",
                "2:1.37.2-1",
                "x86_64",
            ),
            (
                "containers-common-1:0.70.0-2-any.pkg.tar.zst",
                "containers-common",
                "1:0.70.0-2",
                "any",
            ),
            (
                "linux-6.17.8.arch1-1-x86_64.pkg.tar.zst",
                "linux",
                "6.17.8.arch1-1",
                "x86_64",
            ),
            (
                "lib32-gcc-libs-15.2.1+r22-1.1-x86_64.pkg.tar.zst",
                "lib32-gcc-libs",
                "15.2.1+r22-1.1",
                "x86_64",
            ),
            (
                "python-pip-25.3_1-1-any.pkg.tar.xz",
                "python-pip",
                "25.3_1-1",
                "any",
            ),
            (
                "gtk4-1:4.20.2-1-x86_64.pkg.tar.zst",
                "gtk4",
                "1:4.20.2-1",
                "x86_64",
            ),
        ] {
            assert!(check(file, name, version, arch).is_ok(), "{file}");
        }
    }

    #[test]
    fn rejects_traversal_separators_and_unsafe_bytes() {
        for file in [
            "../zlib-1:1.4-1-x86_64.pkg.tar.zst",
            "zlib-1:1.4-1-x86_64.pkg.tar.zst/../../etc/passwd",
            "dir/zlib-1:1.4-1-x86_64.pkg.tar.zst",
            ".zlib-1:1.4-1-x86_64.pkg.tar.zst",
            "zlib-1:1.4-1-x86_64.pkg.tar.zst\0",
            "zlib-1:1.4-1-x86_64.pkg.tar.zst\n",
            "zlib 1:1.4-1-x86_64.pkg.tar.zst",
            "zlib-1:1.4-1-x86_64.pkg.tar.zst;rm",
            "zlib-1:1.4-1-x86_64.pkg.tar.zst\\",
            "",
        ] {
            assert!(
                check(file, "zlib", "1:1.4-1", "x86_64").is_err(),
                "{file:?}"
            );
        }
        assert!(check(&"a".repeat(256), "zlib", "1:1.4-1", "x86_64").is_err());
    }

    #[test]
    fn rejects_wrong_extension_or_identity() {
        for file in [
            "zlib-1:1.4-1-x86_64.pkg.tar",
            "zlib-1:1.4-1-x86_64.pkg.tar.zst.sig",
            "zlib-1:1.4-1-x86_64.tar.zst",
            "zlib-1:1.4-1-x86_64.pkg.tar.zst.part",
            "zlib-1:1.4-1-x86_64.so",
            "zlib-1:1.5-1-x86_64.pkg.tar.zst",
            "zlib-1.4-1-x86_64.pkg.tar.zst",
            "zlib-1:1.4-1-any.pkg.tar.zst",
            "zlibx-1:1.4-1-x86_64.pkg.tar.zst",
        ] {
            assert!(check(file, "zlib", "1:1.4-1", "x86_64").is_err(), "{file}");
        }
    }

    /// Compatibility check against real repository metadata exported as TSV
    /// (FILENAME, NAME, VERSION, ARCH). Run explicitly with --ignored.
    #[test]
    #[ignore]
    fn accepts_every_exported_repository_archive_name() {
        let path = std::env::var("RWR_ARCHIVE_NAMES_TSV").expect("RWR_ARCHIVE_NAMES_TSV");
        let data = std::fs::read_to_string(path).unwrap();
        let mut count = 0;
        for line in data.lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 4, "{line}");
            assert!(
                check(fields[0], fields[1], fields[2], fields[3]).is_ok(),
                "{line}"
            );
            count += 1;
        }
        assert!(count > 0);
        eprintln!("accepted {count} repository archive names");
    }

    #[test]
    fn colon_is_only_valid_as_numeric_epoch() {
        assert!(
            check(
                "zlib-a:1.4-1-x86_64.pkg.tar.zst",
                "zlib",
                "a:1.4-1",
                "x86_64"
            )
            .is_err()
        );
        assert!(check("zlib-:1.4-1-x86_64.pkg.tar.zst", "zlib", ":1.4-1", "x86_64").is_err());
        assert!(
            check(
                "zlib-1:1:4-1-x86_64.pkg.tar.zst",
                "zlib",
                "1:1:4-1",
                "x86_64"
            )
            .is_err()
        );
        assert!(
            check(
                "zlib-1.4:1-1-x86_64.pkg.tar.zst",
                "zlib",
                "1.4:1-1",
                "x86_64"
            )
            .is_err()
        );
        assert!(check("z:lib-1.4-1-x86_64.pkg.tar.zst", "z:lib", "1.4-1", "x86_64").is_err());
        assert!(
            check(
                "zlib-1:1.4-1-x86:64.pkg.tar.zst",
                "zlib",
                "1:1.4-1",
                "x86:64"
            )
            .is_err()
        );
    }
}

impl AlpmTransaction<'_> {
    pub(crate) fn signed_download_targets(&self) -> Result<Vec<DownloadTarget>, String> {
        if !self.active || self.phase != AlpmTransactionPhase::Prepared {
            return Err("Download targets require PREPARE".into());
        }
        let mut targets = Vec::new();
        let mut node = unsafe { alpm_trans_get_add(self.handle.raw.as_ptr()) };
        while !node.is_null() {
            let pkg = unsafe { (*node).data.cast::<RawAlpmPkg>() };
            if pkg.is_null() {
                return Err("Null download package".into());
            }
            let db = unsafe { alpm_pkg_get_db(pkg) };
            if db.is_null() {
                return Err("Download package is not from a configured repository".into());
            }
            let level = unsafe { alpm_db_get_siglevel(db) };
            // Never accept optional, marginal or unknown package signatures.
            if level & ALPM_SIG_PACKAGE == 0
                || level & (ALPM_SIG_PACKAGE_OPTIONAL | (1 << 2) | (1 << 3)) != 0
            {
                return Err("Package signature policy is not Required/TrustedOnly".into());
            }
            let filename = owned_alpm_string(unsafe { alpm_pkg_get_filename(pkg) })?;
            validate_package_archive_filename(
                &filename,
                &owned_alpm_string(unsafe { alpm_pkg_get_name(pkg) })?,
                &owned_alpm_string(unsafe { alpm_pkg_get_version(pkg) })?,
                &owned_alpm_string(unsafe { alpm_pkg_get_arch(pkg) })?,
            )?;
            let sha256 = owned_alpm_string(unsafe { alpm_pkg_get_sha256sum(pkg) })?;
            if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("Package lacks SHA256".into());
            }
            let raw_signature = unsafe { alpm_pkg_get_base64_sig(pkg) };
            if raw_signature.is_null() {
                return Err("Required package PGP signature missing".into());
            }
            let signature = owned_alpm_string(raw_signature)?;
            if signature.is_empty() || signature.len() > 64 * 1024 {
                return Err("Package lacks bounded embedded PGP signature".into());
            }
            targets.push(DownloadTarget {
                name: owned_alpm_string(unsafe { alpm_pkg_get_name(pkg) })?,
                version: owned_alpm_string(unsafe { alpm_pkg_get_version(pkg) })?,
                filename,
                sha256,
                signature,
            });
            node = unsafe { (*node).next };
        }
        targets.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(targets)
    }

    pub(crate) fn commit_signed_lab(
        &mut self,
        authorization: &LabCommitAuthorization,
        verified: &VerifiedDownloads,
    ) -> Result<(), String> {
        if self.download_only {
            return Err("Installation cannot use a download-only transaction".into());
        }
        let targets = self.signed_download_targets()?;
        if targets != verified.targets {
            return Err("Prepared transaction differs from verified packages".into());
        }
        self.handle.verify_downloads(&targets, &verified.cache)?;
        self.commit_isolated_lab_authorized(authorization)
    }

    pub fn request_interrupt(&mut self) -> Result<(), String> {
        if !self.active {
            return Err("No active transaction to interrupt".into());
        }
        if unsafe { alpm_trans_interrupt(self.handle.raw.as_ptr()) } != 0 {
            return Err(transaction_error(self.handle, "interrupt"));
        }
        Ok(())
    }
}

impl AlpmHandle {
    pub(crate) fn verify_downloads(
        &self,
        targets: &[DownloadTarget],
        cache: &Path,
    ) -> Result<VerifiedDownloads, String> {
        use std::io::{Read, Write};
        use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
        let _crypto = self.crypto_context()?;
        for target in targets {
            let path = cache.join(&target.filename);
            let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if !meta.is_file() || plan_file_sha256(&path)? != target.sha256 {
                return Err("Downloaded archive checksum mismatch".into());
            }
            let encoded = CString::new(target.signature.as_str()).map_err(|e| e.to_string())?;
            let mut raw = std::ptr::null_mut();
            let mut length = 0usize;
            if unsafe { alpm_decode_signature(encoded.as_ptr(), &mut raw, &mut length) } != 0
                || raw.is_null()
            {
                return Err("Cannot decode package PGP signature".into());
            }
            if length == 0 || length > 1024 * 1024 {
                unsafe {
                    libc::free(raw.cast());
                }
                return Err("Invalid PGP signature size".into());
            }
            let signature = unsafe { std::slice::from_raw_parts(raw, length) }.to_vec();
            unsafe {
                libc::free(raw.cast());
            }
            let sidecar = cache.join(format!("{}.sig", target.filename));
            match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&sidecar)
            {
                Ok(file) => {
                    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
                        return Err("Unsafe signature cache entry".into());
                    }
                    let mut existing = Vec::new();
                    file.take(1024 * 1024 + 1)
                        .read_to_end(&mut existing)
                        .map_err(|e| e.to_string())?;
                    if existing != signature {
                        return Err("Cached PGP signature differs from repository".into());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&sidecar)
                        .map_err(|e| e.to_string())?;
                    file.write_all(&signature)
                        .and_then(|_| file.sync_all())
                        .map_err(|e| e.to_string())?;
                }
                Err(e) => return Err(e.to_string()),
            }
            let path = CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
            let mut package = std::ptr::null_mut();
            if unsafe {
                alpm_pkg_load(
                    self.raw.as_ptr(),
                    path.as_ptr(),
                    1,
                    ALPM_SIG_PACKAGE,
                    &mut package,
                )
            } != 0
                || package.is_null()
            {
                return Err(transaction_error(self, "required package PGP verification"));
            }
            let valid = unsafe { alpm_pkg_get_validation(package) } & (1 << 3) != 0;
            let identity =
                owned_alpm_string(unsafe { alpm_pkg_get_name(package) }).and_then(|name| {
                    let version = owned_alpm_string(unsafe { alpm_pkg_get_version(package) })?;
                    if name != target.name || version != target.version {
                        return Err("Signed archive identity differs from PREPARE".into());
                    }
                    Ok(())
                });
            unsafe {
                alpm_pkg_free(package);
            }
            identity?;
            if !valid {
                return Err("ALPM did not report verified PGP signature".into());
            }
        }
        Ok(VerifiedDownloads {
            cache: cache.into(),
            targets: targets.to_vec(),
        })
    }
}

impl AlpmHandle {
    pub fn cancellation_request(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.callback_context.interrupt.clone()
    }
    pub fn interruption_delivered(&self) -> bool {
        self.callback_context
            .interrupt_delivered
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl AlpmHandle {
    pub(crate) fn open_authorized_system(
        auth: &crate::production_alpm_flow::SystemCommitAuthorization,
    ) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt;
        auth.require_enabled()?;
        let config = PacmanConfig::read()?;
        if Path::new(&config.root)
            .canonicalize()
            .map_err(|e| e.to_string())?
            != Path::new("/")
        {
            return Err("System update requires the verified system root".into());
        }
        for path in [&config.db_path, &config.cache_dir, &config.gpg_dir] {
            let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(
                    "System database/cache/keyring must be root-owned and protected".into(),
                );
            }
        }
        if !config.check_space {
            return Err("System execution requires enabled ALPM disk-space checking".into());
        }
        // Execution transport policy: only HTTPS mirrors are registered with ALPM.
        // Mixed mirrorlists are accepted; a repository without any HTTPS mirror is refused.
        let config = config.https_only_execution()?;
        let mut handle = Self::new(Path::new(&config.root), Path::new(&config.db_path))?;
        if handle.configure(&config)? != config.repositories.len() {
            return Err("System execution repository registration count mismatch".into());
        }
        handle.origin = AlpmHandleOrigin::AuthorizedSystem;
        handle.configure_plan_questions()?;
        Ok(handle)
    }
    pub(crate) fn refresh_authorized_databases(
        &self,
        auth: &crate::production_alpm_flow::SystemCommitAuthorization,
    ) -> Result<(), String> {
        auth.require_enabled()?;
        if self.origin != AlpmHandleOrigin::AuthorizedSystem {
            return Err("Untrusted system handle".into());
        }
        let _crypto = self.crypto_context()?;
        let databases = unsafe { alpm_get_syncdbs(self.raw.as_ptr()) };
        if databases.is_null() || unsafe { alpm_db_update(self.raw.as_ptr(), databases, 1) } < 0 {
            return Err(transaction_error(self, "system repository synchronization"));
        }
        Ok(())
    }
    pub(crate) fn register_authorized_events(
        &mut self,
        auth: &crate::production_alpm_flow::SystemCommitAuthorization,
    ) -> Result<(), String> {
        auth.require_enabled()?;
        if self.origin != AlpmHandleOrigin::AuthorizedSystem {
            return Err("Untrusted system handle".into());
        }
        self.callback_context
            .callback_handle
            .store(self.raw.as_ptr(), std::sync::atomic::Ordering::Relaxed);
        if unsafe {
            alpm_option_set_eventcb(
                self.raw.as_ptr(),
                Some(rwr_alpm_event_callback),
                (&*self.callback_context as *const CallbackContext)
                    .cast_mut()
                    .cast(),
            )
        } != 0
        {
            return Err("Cannot register system transaction events".into());
        }
        Ok(())
    }
    pub(crate) fn verify_installed_upgrade(
        &self,
        expected: &AlpmPreparedUpgrade,
    ) -> Result<(), String> {
        let db = unsafe { alpm_get_localdb(self.raw.as_ptr()) };
        if db.is_null() {
            return Err("Installed database unavailable after COMMIT".into());
        }
        for p in &expected.add {
            let name = CString::new(p.name.as_str()).map_err(|e| e.to_string())?;
            let pkg = unsafe { alpm_db_get_pkg(db, name.as_ptr()) };
            if pkg.is_null()
                || owned_alpm_string(unsafe { alpm_pkg_get_version(pkg) })? != p.version
            {
                return Err(
                    "Installed versions differ from committed plan; recovery required".into(),
                );
            }
        }
        for p in &expected.remove {
            if expected.add.iter().any(|a| a.name == p.name) {
                continue;
            }
            let name = CString::new(p.name.as_str()).map_err(|e| e.to_string())?;
            if !unsafe { alpm_db_get_pkg(db, name.as_ptr()) }.is_null() {
                return Err("Planned removal did not complete".into());
            }
        }
        Ok(())
    }
}
impl AlpmTransaction<'_> {
    pub(crate) fn download_system_authorized(
        &mut self,
        auth: &crate::production_alpm_flow::SystemCommitAuthorization,
        confirmation: &crate::production_alpm_flow::ConfirmedUpgrade,
    ) -> Result<(), String> {
        auth.verify_confirmation(confirmation)?;
        if self.handle.origin != AlpmHandleOrigin::AuthorizedSystem || !self.download_only {
            return Err("Invalid system download transaction".into());
        }
        confirmation.verify_transaction(self)?;
        self.signed_download_targets()?;
        self.commit_ffi()
    }
    pub(crate) fn commit_system_authorized(
        &mut self,
        auth: &crate::production_alpm_flow::SystemCommitAuthorization,
        confirmation: &crate::production_alpm_flow::ConfirmedUpgrade,
        verified: &VerifiedDownloads,
    ) -> Result<(), String> {
        auth.verify_confirmation(confirmation)?;
        if self.handle.origin != AlpmHandleOrigin::AuthorizedSystem || self.download_only {
            return Err("Invalid system installation transaction".into());
        }
        confirmation.verify_transaction(self)?;
        let targets = self.signed_download_targets()?;
        if targets != verified.targets {
            return Err("System targets differ from verified packages".into());
        }
        self.handle.verify_downloads(&targets, &verified.cache)?;
        self.commit_ffi()
    }
}

#[cfg(test)]
mod abi_error_number_tests {
    use super::*;
    #[test]
    fn linked_alpm_error_numbers_match_header_and_destructor_dispatch() {
        use std::os::unix::fs::DirBuilderExt;
        let base = std::env::temp_dir().join(format!("rwr-alpm-abi-{}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&base)
            .unwrap();
        let c = base.join("probe.c");
        let executable = base.join("probe");
        let names = [
            "ALPM_ERR_DB_INVALID_SIG",
            "ALPM_ERR_PKG_INVALID_SIG",
            "ALPM_ERR_PKG_MISSING_SIG",
            "ALPM_ERR_SIG_MISSING",
            "ALPM_ERR_SIG_INVALID",
            "ALPM_ERR_UNSATISFIED_DEPS",
            "ALPM_ERR_CONFLICTING_DEPS",
            "ALPM_ERR_FILE_CONFLICTS",
            "ALPM_ERR_RETRIEVE_PREPARE",
            "ALPM_ERR_RETRIEVE",
        ];
        std::fs::write(&c,format!("#include <alpm.h>\n#include <stdio.h>\nint main(void){{ printf(\"{}\",{}); return 0; }}\n","%d ".repeat(names.len()),names.join(","))).unwrap();
        let compiled = std::process::Command::new("cc")
            .arg(&c)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let result = std::process::Command::new(executable).output().unwrap();
        assert!(result.status.success());
        let numbers: Vec<i32> = String::from_utf8(result.stdout)
            .unwrap()
            .split_whitespace()
            .map(|v| v.parse().unwrap())
            .collect();
        assert_eq!(
            numbers,
            [
                ALPM_ERR_DB_INVALID_SIG,
                ALPM_ERR_PKG_INVALID_SIG,
                ALPM_ERR_PKG_MISSING_SIG,
                ALPM_ERR_SIG_MISSING,
                ALPM_ERR_SIG_INVALID,
                ALPM_ERR_UNSATISFIED_DEPS,
                ALPM_ERR_CONFLICTING_DEPS,
                ALPM_ERR_FILE_CONFLICTS,
                ALPM_ERR_RETRIEVE_PREPARE,
                ALPM_ERR_RETRIEVE
            ]
        );
        assert_eq!(version().unwrap(), "16.0.1");
        std::fs::remove_dir_all(base).unwrap();
    }
}

impl AlpmHandle {
    pub(crate) fn set_cancellation_request(
        &mut self,
        request: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        self.callback_context.interrupt = request;
    }
}

// libalpm 16 uses process-global GPGME engine defaults. Private PREPARE
// keyrings must not leak into the next handle or race another ALPM thread.
// All crypto-capable ALPM calls select their handle's home under this lock.
static ALPM_CRYPTO_CONTEXT: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[link(name = "gpgme")]
unsafe extern "C" {
    fn gpgme_check_version(required: *const c_char) -> *const c_char;
    fn gpgme_set_engine_info(protocol: i32, file: *const c_char, home: *const c_char) -> u32;
}
impl AlpmHandle {
    fn crypto_context(&self) -> Result<std::sync::MutexGuard<'static, ()>, String> {
        let guard = ALPM_CRYPTO_CONTEXT
            .lock()
            .map_err(|_| "ALPM crypto context poisoned")?;
        let home = unsafe { alpm_option_get_gpgdir(self.raw.as_ptr()) };
        if home.is_null()
            || unsafe { gpgme_check_version(std::ptr::null()) }.is_null()
            || unsafe { gpgme_set_engine_info(0, std::ptr::null(), home) } != 0
        {
            return Err("Cannot select the verified ALPM keyring context".into());
        }
        Ok(guard)
    }
}

/// Answers only reviewed replacement/conflict decisions. Key import, ignored
/// targets and unresolved dependencies retain the existing fail-closed policy.
#[derive(Debug)]
pub struct ExecutionQuestions {
    events: std::sync::mpsc::SyncSender<serde_json::Value>,
    replies: std::sync::Mutex<std::sync::mpsc::Receiver<(u64, bool)>>,
    next: std::sync::atomic::AtomicU64,
    connected: std::sync::Arc<std::sync::atomic::AtomicBool>,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl ExecutionQuestions {
    pub fn new(
        events: std::sync::mpsc::SyncSender<serde_json::Value>,
        replies: std::sync::mpsc::Receiver<(u64, bool)>,
        connected: std::sync::Arc<std::sync::atomic::AtomicBool>,
        cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            events,
            replies: std::sync::Mutex::new(replies),
            next: std::sync::atomic::AtomicU64::new(1),
            connected,
            cancel,
        }
    }
    fn ask(&self, kind: i32) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        if !matches!(kind, 2 | 4) || !self.connected.load(Relaxed) || self.cancel.load(Relaxed) {
            return false;
        }
        let approved = self.ask_reviewed(kind);
        if !approved {
            self.cancel.store(true, Relaxed);
        }
        approved
    }
    fn ask_reviewed(&self, kind: i32) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let id = self.next.fetch_add(1, Relaxed);
        if id == 0 || !matches!(kind, 2 | 4) {
            return false;
        }
        let text = if kind == 2 {
            "Potwierdzić zastąpienie z zatwierdzonego planu? / Confirm the replacement in the approved plan?"
        } else {
            "Potwierdzić usunięcie konfliktu z zatwierdzonego planu? / Confirm the conflict removal in the approved plan?"
        };
        if self
            .events
            .try_send(serde_json::json!({"type":"question","id":id,"text":text}))
            .is_err()
        {
            return false;
        }
        let Ok(replies) = self.replies.lock() else {
            return false;
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(900);
        while self.connected.load(Relaxed)
            && !self.cancel.load(Relaxed)
            && std::time::Instant::now() < deadline
        {
            match replies.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok((answer, approved)) if answer == id => return approved,
                Ok(_) => return false,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                _ => return false,
            }
        }
        false
    }
}

#[link(name = "alpm")]
unsafe extern "C" {
    fn alpm_option_set_progresscb(
        handle: *mut RawAlpmHandle,
        callback: Option<
            unsafe extern "C" fn(*mut std::ffi::c_void, i32, *const c_char, i32, usize, usize),
        >,
        context: *mut std::ffi::c_void,
    ) -> i32;
    fn alpm_option_set_dlcb(
        handle: *mut RawAlpmHandle,
        callback: Option<
            unsafe extern "C" fn(*mut std::ffi::c_void, *const c_char, i32, *mut std::ffi::c_void),
        >,
        context: *mut std::ffi::c_void,
    ) -> i32;
}
fn send_callback_progress(context: &CallbackContext, value: serde_json::Value) {
    if let Ok(sender) = context.progress_stream.lock() {
        if let Some(sender) = sender.as_ref() {
            let _ =
                sender.try_send(serde_json::json!({"type":"progress","text":value.to_string()}));
        }
    }
}
unsafe extern "C" fn execution_progress_callback(
    ctx: *mut std::ffi::c_void,
    kind: i32,
    package: *const c_char,
    percent: i32,
    total: usize,
    current: usize,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if ctx.is_null() {
            return;
        }
        let context = unsafe { &*(ctx as *const CallbackContext) };
        let package = if package.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(package) }
                .to_string_lossy()
                .chars()
                .take(512)
                .collect()
        };
        send_callback_progress(
            context,
            serde_json::json!({"stage":"alpm-progress","kind":kind,"package":package,"percent":percent.clamp(0,100),"current":current,"total":total}),
        );
    }));
}
#[repr(C)]
struct DownloadProgressData {
    downloaded: libc::off_t,
    total: libc::off_t,
}
unsafe extern "C" fn execution_download_callback(
    ctx: *mut std::ffi::c_void,
    filename: *const c_char,
    event: i32,
    data: *mut std::ffi::c_void,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if ctx.is_null() {
            return;
        }
        let context = unsafe { &*(ctx as *const CallbackContext) };
        let filename = if filename.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(filename) }
                .to_string_lossy()
                .chars()
                .take(512)
                .collect()
        };
        let mut value = serde_json::json!({"stage":"download","event":event,"filename":filename});
        if event == 1 && !data.is_null() {
            let progress = unsafe { &*(data as *const DownloadProgressData) };
            value["downloaded"] = progress.downloaded.into();
            value["total"] = progress.total.into();
        }
        send_callback_progress(context, value);
    }));
}
impl AlpmHandle {
    fn install_progress_stream(
        &self,
        sender: std::sync::mpsc::SyncSender<serde_json::Value>,
    ) -> Result<(), String> {
        *self
            .callback_context
            .progress_stream
            .lock()
            .map_err(|_| "Progress stream poisoned")? = Some(sender);
        let context = (&*self.callback_context as *const CallbackContext)
            .cast_mut()
            .cast();
        if unsafe {
            alpm_option_set_progresscb(
                self.raw.as_ptr(),
                Some(execution_progress_callback),
                context,
            )
        } != 0
            || unsafe {
                alpm_option_set_dlcb(
                    self.raw.as_ptr(),
                    Some(execution_download_callback),
                    context,
                )
            } != 0
        {
            return Err("Cannot register ALPM execution progress".into());
        }
        Ok(())
    }
    pub(crate) fn configure_execution_stream(
        &self,
        auth: &crate::production_alpm_flow::SystemCommitAuthorization,
        sender: std::sync::mpsc::SyncSender<serde_json::Value>,
        questions: std::sync::Arc<ExecutionQuestions>,
    ) -> Result<(), String> {
        auth.require_enabled()?;
        if self.origin != AlpmHandleOrigin::AuthorizedSystem {
            return Err("Untrusted execution callback handle".into());
        }
        self.install_progress_stream(sender)?;
        *self
            .callback_context
            .interactive_questions
            .lock()
            .map_err(|_| "Execution questions poisoned")? = Some(questions);
        Ok(())
    }
    pub(crate) fn configure_signed_lab_progress(
        &self,
        sender: std::sync::mpsc::SyncSender<serde_json::Value>,
    ) -> Result<(), String> {
        if self.origin != AlpmHandleOrigin::IsolatedLab {
            return Err("Laboratory handle required".into());
        }
        self.install_progress_stream(sender)
    }
}

#[cfg(test)]
mod execution_question_routing_tests {
    use super::*;
    #[test]
    fn reviewed_question_routes_answer_and_unknown_key_is_denied() {
        let (events, received) = std::sync::mpsc::sync_channel(4);
        let (replies, answers) = std::sync::mpsc::channel();
        let bridge = std::sync::Arc::new(ExecutionQuestions::new(
            events,
            answers,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        ));
        // Decision routing only; this never grants SystemCommitAuthorization.
        assert!(!bridge.ask(64)); // importing a key is never a GUI decision
        let callback = bridge.clone();
        let waiting = std::thread::spawn(move || callback.ask(2));
        let question = received
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert_eq!(question["type"], "question");
        replies
            .send((question["id"].as_u64().unwrap(), true))
            .unwrap();
        assert!(waiting.join().unwrap());
        let callback = bridge.clone();
        let waiting = std::thread::spawn(move || callback.ask(4));
        let question = received
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        replies
            .send((question["id"].as_u64().unwrap() + 1, true))
            .unwrap();
        assert!(!waiting.join().unwrap());
    }
}

#[cfg(test)]
mod https_execution_policy_tests {
    use super::PacmanConfig;

    fn config(servers: Vec<(&str, Vec<&str>)>) -> PacmanConfig {
        PacmanConfig {
            root: "/".into(),
            db_path: "/var/lib/pacman/".into(),
            cache_dir: "/var/cache/pacman/pkg/".into(),
            gpg_dir: "/etc/pacman.d/gnupg/".into(),
            check_space: true,
            architecture: "x86_64".into(),
            repositories: servers.iter().map(|(repo, _)| (*repo).into()).collect(),
            repository_servers: servers
                .into_iter()
                .map(|(repo, urls)| (repo.into(), urls.into_iter().map(Into::into).collect()))
                .collect(),
            signature_policy: vec!["Required".into(), "DatabaseOptional".into()],
            repository_signature_policies: vec![("core".into(), vec!["PackageRequired".into()])],
            ignore_pkg: vec!["linux-lts".into()],
            ignore_group: Vec::new(),
            no_upgrade: vec!["etc/pacman.conf".into()],
            no_extract: Vec::new(),
            hook_dirs: vec!["/usr/share/libalpm/hooks/".into()],
            log_file: "/var/log/pacman.log".into(),
        }
    }

    #[test]
    fn mixed_mirrors_keep_only_https_in_original_order() {
        let original = config(vec![
            (
                "core",
                vec![
                    "http://a.example/core/os/x86_64",
                    "https://b.example/core/os/x86_64",
                    "http://c.example/core/os/x86_64",
                    "https://d.example/core/os/x86_64",
                ],
            ),
            (
                "extra",
                vec![
                    "https://b.example/extra/os/x86_64",
                    "http://a.example/extra/os/x86_64",
                ],
            ),
        ]);
        let effective = original.https_only_execution().unwrap();
        assert_eq!(
            effective.repository_servers,
            vec![
                (
                    "core".to_string(),
                    vec![
                        "https://b.example/core/os/x86_64".to_string(),
                        "https://d.example/core/os/x86_64".to_string(),
                    ],
                ),
                (
                    "extra".to_string(),
                    vec!["https://b.example/extra/os/x86_64".to_string()]
                ),
            ]
        );
        assert!(
            effective
                .repository_servers
                .iter()
                .flat_map(|(_, servers)| servers)
                .all(|url| url.starts_with("https://"))
        );
    }

    #[test]
    fn only_servers_change_signatures_and_paths_are_preserved() {
        let original = config(vec![(
            "core",
            vec!["http://a.example/x", "https://b.example/x"],
        )]);
        let mut effective = original.https_only_execution().unwrap();
        effective.repository_servers = original.repository_servers.clone();
        assert_eq!(effective, original);
        // The source configuration (used for the plan digest) is not mutated.
        assert_eq!(original.repository_servers[0].1.len(), 2);
    }

    #[test]
    fn repository_without_https_mirror_is_refused() {
        let error = config(vec![
            ("core", vec!["https://b.example/core"]),
            (
                "extra",
                vec!["http://a.example/extra", "http://c.example/extra"],
            ),
        ])
        .https_only_execution()
        .unwrap_err();
        assert!(error.contains("extra"), "{error}");
    }

    #[test]
    fn non_https_schemes_and_lookalikes_are_dropped() {
        let error = config(vec![(
            "core",
            vec![
                "http://https://evil.example/core",
                "HTTPS-like://x",
                "ftp://a.example/core",
                "file:///var/cache/core",
                "https://",
                " https://leading-space.example/core",
            ],
        )])
        .https_only_execution()
        .unwrap_err();
        assert!(error.contains("core"), "{error}");
    }

    #[test]
    fn repository_without_server_entry_is_refused() {
        let mut broken = config(vec![("core", vec!["https://b.example/core"])]);
        broken.repositories.push("extra".into());
        assert!(broken.https_only_execution().is_err());
    }

    #[test]
    fn current_system_mirrorlist_passes_policy_when_each_repo_has_https() {
        // Read-only: pacman-conf only. Skips silently where pacman-conf is absent.
        let Ok(system) = PacmanConfig::read() else {
            return;
        };
        let has_https_everywhere = system
            .repository_servers
            .iter()
            .all(|(_, servers)| servers.iter().any(|url| url.starts_with("https://")));
        assert_eq!(system.https_only_execution().is_ok(), has_https_everywhere);
    }
}
