//! Diagnostic-only trust policy. Trusts root or the supervisor's own UID, never
//! authorizes privileged execution. The opened ELF is pinned across path changes.
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub const SYSTEM_HELPER: &str = "/usr/lib/rwr-package-intelligence/rwr-update-helper";

/// Pin the deployed executable, never a GUI/environment supplied path.
pub fn open_system_helper() -> Result<File, String> {
    crate::test_isolation::refuse("system helper")?;
    open_system_binary(Path::new(SYSTEM_HELPER))
}

pub const SYSTEM_SUPERVISOR: &str = "/usr/lib/rwr-package-intelligence/rwr-transaction-supervisor";
pub const SYSTEM_SOCKET: &str = "/run/rwr-package-intelligence/system.sock";

pub fn open_system_supervisor() -> Result<File, String> {
    open_system_binary(Path::new(SYSTEM_SUPERVISOR))
}

fn open_system_binary(path: &Path) -> Result<File, String> {
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|e| e.to_string())?;
        if metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || (ancestor != path && !metadata.is_dir())
            || metadata.file_type().is_symlink()
        {
            return Err("Untrusted system helper path".into());
        }
    }
    let file = open_diagnostic_helper(path, path)?;
    if file.metadata().map_err(|e| e.to_string())?.uid() != 0 {
        return Err("System helper must be root-owned".into());
    }
    Ok(file)
}

pub const PROTOCOL_VERSION: u64 = 1;

pub fn open_diagnostic_helper(requested: &Path, expected: &Path) -> Result<File, String> {
    let canonical = expected.canonicalize().map_err(|e| e.to_string())?;
    if !requested.is_absolute() || requested != canonical {
        return Err("Untrusted diagnostic helper path".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(requested)
        .map_err(|e| format!("Cannot open trusted helper: {e}"))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    let uid = unsafe { libc::geteuid() };
    validate_file_metadata(&metadata, uid)?;
    for parent in canonical.ancestors().skip(1) {
        let meta = parent.metadata().map_err(|e| e.to_string())?;
        if !meta.is_dir() || (meta.uid() != 0 && meta.uid() != uid) || meta.mode() & 0o022 != 0 {
            return Err("Untrusted helper directory".into());
        }
    }
    let mut magic = [0; 4];
    file.read_exact(&mut magic).map_err(|e| e.to_string())?;
    if magic != *b"\x7fELF" {
        return Err("Diagnostic helper must be an ELF executable".into());
    }
    Ok(file)
}

fn validate_file_metadata(metadata: &std::fs::Metadata, uid: u32) -> Result<(), String> {
    if !metadata.is_file()
        || !matches!(metadata.uid(), owner if owner == 0 || owner == uid)
        || metadata.mode() & 0o6022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err("Untrusted diagnostic helper owner or permissions".into());
    }
    Ok(())
}

/// Must be the first frame; legacy/missing versions are refused before replies.
pub fn verify_hello(line: &str) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
    if value.as_object().is_none_or(|object| object.len() != 4)
        || value["type"] != "hello"
        || value["component"] != "rwr-ipc-test-helper"
        || value["protocol_version"].as_u64() != Some(PROTOCOL_VERSION)
        || value["real_execution_enabled"] != false
    {
        return Err("Untrusted helper identity or incompatible IPC version".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_hello_requires_identity_version_and_disabled_real_mode() {
        let valid = serde_json::json!({"type":"hello","component":"rwr-ipc-test-helper",
            "protocol_version":1,"real_execution_enabled":false});
        verify_hello(&valid.to_string()).unwrap();
        for (field, value) in [
            ("component", serde_json::json!("other")),
            ("protocol_version", serde_json::json!(2)),
            ("protocol_version", serde_json::json!("1")),
            ("real_execution_enabled", serde_json::json!(true)),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(verify_hello(&invalid.to_string()).is_err());
        }
        assert!(verify_hello(r#"{"type":"started"}"#).is_err());
        assert!(verify_hello("{}").is_err());
    }

    #[test]
    fn trust_rejects_unlisted_executable_and_symlink() {
        let current = std::env::current_exe().unwrap().canonicalize().unwrap();
        assert!(open_diagnostic_helper(Path::new("/bin/false"), &current).is_err());
        assert!(open_diagnostic_helper(Path::new("relative-helper"), &current).is_err());
        // /proc/self/exe is an alias, not the allowlisted canonical path.
        assert!(open_diagnostic_helper(Path::new("/proc/self/exe"), &current).is_err());
    }

    #[test]
    fn trust_checks_permissions_before_execution() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("rwr-untrusted-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&path)
            .unwrap();
        use std::io::Write;
        file.write_all(b"\x7fELF").unwrap();
        let uid = unsafe { libc::geteuid() };
        validate_file_metadata(&file.metadata().unwrap(), uid).unwrap();
        assert!(
            validate_file_metadata(&file.metadata().unwrap(), uid.wrapping_add(1)).is_err()
                || uid == 0
        );
        for mode in [0o777, 0o644, 0o4755] {
            file.set_permissions(std::fs::Permissions::from_mode(mode))
                .unwrap();
            assert!(validate_file_metadata(&file.metadata().unwrap(), uid).is_err());
        }
        std::fs::remove_file(path).unwrap();
    }
}

/// A kernel-issued peer pidfd pins the ORIGINAL socket peer, unlike looking up
/// SO_PEERCRED.pid later. Unsupported kernels fail closed, never fall back to PID.
pub struct PeerProcess {
    credentials: libc::ucred,
    pidfd: std::os::fd::OwnedFd,
}
impl PeerProcess {
    pub fn from_socket(socket: &std::os::unix::net::UnixStream) -> Result<Self, String> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
        let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                credentials.as_mut_ptr().cast(),
                &mut size,
            )
        } != 0
            || size as usize != std::mem::size_of::<libc::ucred>()
        {
            return Err("Cannot identify Unix socket peer".into());
        }
        let mut fd = -1;
        size = std::mem::size_of::<i32>() as libc::socklen_t;
        // Linux SO_PEERPIDFD, as defined by asm-generic/socket.h (kernel >= 6.5).
        if unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                77,
                (&mut fd as *mut i32).cast(),
                &mut size,
            )
        } != 0
        {
            return Err(format!(
                "Kernel peer pidfd required: {}",
                std::io::Error::last_os_error()
            ));
        }
        if fd < 0 {
            return Err("Invalid peer pidfd".into());
        }
        let pidfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err("Cannot protect peer pidfd".into());
        }
        if size as usize != std::mem::size_of::<i32>() {
            return Err("Invalid peer pidfd size".into());
        }
        let peer = Self {
            credentials: unsafe { credentials.assume_init() },
            pidfd,
        };
        if !peer.is_alive()? {
            return Err("Socket peer has exited".into());
        }
        Ok(peer)
    }
    pub fn credentials(&self) -> libc::ucred {
        self.credentials
    }
    pub fn is_alive(&self) -> Result<bool, String> {
        use std::os::fd::AsRawFd;
        let mut poll = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, 0) };
        if result < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(result == 0)
    }
}

pub fn verify_system_supervisor_peer(
    socket: &std::os::unix::net::UnixStream,
) -> Result<(), String> {
    let peer = PeerProcess::from_socket(socket)?;
    if peer.credentials().uid != 0 {
        return Err("System supervisor must run as root".into());
    }
    let expected = open_system_supervisor()?
        .metadata()
        .map_err(|e| e.to_string())?;
    let running = std::fs::metadata(format!("/proc/{}/exe", peer.credentials().pid))
        .map_err(|e| e.to_string())?;
    if expected.dev() != running.dev() || expected.ino() != running.ino() || !peer.is_alive()? {
        return Err("System supervisor executable identity changed".into());
    }
    Ok(())
}

#[cfg(test)]
mod peer_pidfd_tests {
    #[test]
    fn kernel_peer_pidfd_detects_original_peer_exit() {
        use std::io::Write;
        use std::os::unix::fs::DirBuilderExt;
        let directory = std::env::temp_dir().join(format!("rwr-peer-pidfd-{}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("peer.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let mut child=std::process::Command::new("/usr/bin/python3").args(["-c","import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); sys.stdin.buffer.read(1)"]).arg(&path).stdin(std::process::Stdio::piped()).spawn().unwrap();
        let (socket, _) = listener.accept().unwrap();
        let peer = super::PeerProcess::from_socket(&socket).unwrap();
        assert_eq!(peer.credentials().pid, child.id() as i32);
        assert!(peer.is_alive().unwrap());
        child.stdin.take().unwrap().write_all(b"x").unwrap();
        assert!(child.wait().unwrap().success());
        assert!(!peer.is_alive().unwrap());
        drop((socket, listener));
        std::fs::remove_dir_all(directory).unwrap();
    }
}

/// Socket activation may make SO_PEERCRED identify systemd, not the accepting
/// process. Authenticate the actual sender using kernel SCM_CREDENTIALS/PIDFD.
pub fn receive_system_server_hello(
    socket: &mut std::os::unix::net::UnixStream,
) -> Result<(), String> {
    // SO_PEERCRED may identify systemd (the listener creator), so it is
    // necessary but not sufficient. Authenticate the actual sender below.
    let listener = PeerProcess::from_socket(socket)?;
    if listener.credentials().uid != 0 {
        return Err("System listener must belong to root".into());
    }
    let peer = receive_sender_hello(socket)?;
    verify_system_process(&peer)
}
/// false means a clean disconnect/idle timeout BEFORE a request, not a failed
/// transaction. Malformed handshakes still fail closed with an error.
pub fn send_system_server_hello(
    socket: &mut std::os::unix::net::UnixStream,
) -> Result<bool, String> {
    use std::io::{ErrorKind, Read, Write};
    let mut byte = [0];
    loop {
        match socket.read(&mut byte) {
            Ok(0) => return Ok(false),
            Ok(_) => break,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    if byte != [b'R'] {
        return Err("Invalid system handshake".into());
    }
    match socket.write_all(b"R") {
        Ok(()) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error.to_string()),
    }
}

fn receive_sender_hello(
    socket: &mut std::os::unix::net::UnixStream,
) -> Result<PeerProcess, String> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let fd = socket.as_raw_fd();
    for option in [libc::SO_PASSCRED, 76] {
        // Linux SO_PASSPIDFD
        let enabled = 1i32;
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&enabled as *const i32).cast(),
                std::mem::size_of::<i32>() as _,
            )
        } != 0
        {
            return Err(format!(
                "Kernel sender identity required: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    socket.write_all(b"R").map_err(|e| e.to_string())?;
    let mut byte = 0u8;
    let mut control = [0usize; 64];
    let mut vector = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control);
    let result = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_CMSG_CLOEXEC) };
    if result < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut credentials = None;
    let mut pidfd = None;
    let mut extra = false;
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            let h = &*header;
            if h.cmsg_level == libc::SOL_SOCKET
                && h.cmsg_type == libc::SCM_CREDENTIALS
                && h.cmsg_len == libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as _) as usize
            {
                if credentials.is_some() {
                    extra = true;
                }
                credentials = Some(std::ptr::read_unaligned(
                    libc::CMSG_DATA(header).cast::<libc::ucred>(),
                ));
            } else if h.cmsg_level==libc::SOL_SOCKET && h.cmsg_type==4 // SCM_PIDFD
                && h.cmsg_len==libc::CMSG_LEN(std::mem::size_of::<i32>() as _) as usize
            {
                let raw = std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>());
                if raw >= 0 {
                    if pidfd.is_some() {
                        extra = true;
                    }
                    pidfd = Some(OwnedFd::from_raw_fd(raw));
                } else {
                    extra = true;
                }
            } else if h.cmsg_level == libc::SOL_SOCKET && h.cmsg_type == libc::SCM_RIGHTS {
                extra = true;
                let length = h.cmsg_len.saturating_sub(libc::CMSG_LEN(0) as usize)
                    / std::mem::size_of::<i32>();
                for index in 0..length {
                    let raw =
                        std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>().add(index));
                    if raw >= 0 {
                        drop(OwnedFd::from_raw_fd(raw));
                    }
                }
            } else {
                extra = true;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    for option in [libc::SO_PASSCRED, 76] {
        let disabled = 0i32;
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&disabled as *const i32).cast(),
                std::mem::size_of::<i32>() as _,
            )
        } != 0
        {
            return Err("Cannot finish sender handshake".into());
        }
    }
    if result != 1
        || byte != b'R'
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        || extra
    {
        return Err("Invalid/truncated sender handshake".into());
    }
    let peer = PeerProcess {
        credentials: credentials.ok_or("Missing sender credentials")?,
        pidfd: pidfd.ok_or("Missing sender pidfd")?,
    };
    if !peer.is_alive()? {
        return Err("Supervisor sender exited".into());
    }
    Ok(peer)
}
const SYSTEM_UNIT: &str = "rwr-package-intelligence-system.service";
const SYSTEM_UNIT_FILE: &str = "/usr/lib/systemd/system/rwr-package-intelligence-system.service";
const SYSTEM_BUS_SOCKET: &str = "/run/dbus/system_bus_socket";

fn verify_root_service_path(path: &Path, socket: bool) -> Result<(), String> {
    for ancestor in path.ancestors() {
        let meta = std::fs::symlink_metadata(ancestor).map_err(|e| e.to_string())?;
        use std::os::unix::fs::FileTypeExt;
        if meta.uid() != 0
            || meta.file_type().is_symlink()
            || (ancestor != path && (!meta.is_dir() || meta.mode() & 0o022 != 0))
            || (ancestor == path
                && if socket {
                    !meta.file_type().is_socket()
                } else {
                    !meta.is_file() || meta.mode() & 0o022 != 0
                })
        {
            return Err("Untrusted system bus/unit path".into());
        }
    }
    Ok(())
}

#[derive(Clone)]
struct SystemdSupervisorIdentity {
    unit: String,
    fragment: String,
    loaded: String,
    active: String,
    transient: bool,
    main_pid: u32,
    started_usec: u64,
    user: String,
    nnp: bool,
    executable: String,
    arguments: Vec<String>,
}
impl SystemdSupervisorIdentity {
    fn validate(&self, sender_pid: i32, executable_changed_usec: u64) -> Result<(), String> {
        if sender_pid <= 1
            || self.main_pid != sender_pid as u32
            || self.unit != SYSTEM_UNIT
            || self.fragment != SYSTEM_UNIT_FILE
            || self.loaded != "loaded"
            || self.active != "active"
            || self.transient
            || self.user != "root"
            || !self.nnp
            || self.executable != SYSTEM_SUPERVISOR
            || self.arguments != [SYSTEM_SUPERVISOR, "--serve-system"]
            || self.started_usec == 0
            || executable_changed_usec > self.started_usec
        {
            return Err("Systemd supervisor identity/start/executable mismatch; restart after deployment may be required".into());
        }
        Ok(())
    }
}

fn systemd_supervisor_identity(pid: u32) -> Result<SystemdSupervisorIdentity, String> {
    use gtk4::{gio, glib, glib::variant::ToVariant};
    use std::collections::HashMap;
    // Do not use bus_get_sync here: DBUS_SYSTEM_BUS_ADDRESS is caller-controlled.
    verify_root_service_path(Path::new(SYSTEM_BUS_SOCKET), true)?;
    verify_root_service_path(Path::new(SYSTEM_UNIT_FILE), false)?;
    let bus = gio::DBusConnection::for_address_sync(
        "unix:path=/run/dbus/system_bus_socket",
        gio::DBusConnectionFlags::AUTHENTICATION_CLIENT
            | gio::DBusConnectionFlags::MESSAGE_BUS_CONNECTION,
        None,
        gio::Cancellable::NONE,
    )
    .map_err(|e| format!("Cannot authenticate through system D-Bus: {e}"))?;
    bus.set_exit_on_close(false);
    let reply = bus
        .call_sync(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "GetUnitByPID",
            Some(&(pid,).to_variant()),
            None,
            gio::DBusCallFlags::NONE,
            5000,
            gio::Cancellable::NONE,
        )
        .map_err(|e| format!("Cannot bind sender to systemd unit: {e}"))?;
    let (path,) = reply
        .get::<(glib::variant::ObjectPath,)>()
        .ok_or("Invalid systemd unit path reply")?;
    let properties = |interface: &str| -> Result<HashMap<String, glib::Variant>, String> {
        let reply = bus
            .call_sync(
                Some("org.freedesktop.systemd1"),
                path.as_str(),
                "org.freedesktop.DBus.Properties",
                "GetAll",
                Some(&(interface,).to_variant()),
                None,
                gio::DBusCallFlags::NONE,
                5000,
                gio::Cancellable::NONE,
            )
            .map_err(|e| format!("Cannot verify systemd properties: {e}"))?;
        reply
            .get::<(HashMap<String, glib::Variant>,)>()
            .map(|v| v.0)
            .ok_or("Invalid systemd properties reply".into())
    };
    let unit = properties("org.freedesktop.systemd1.Unit")?;
    let service = properties("org.freedesktop.systemd1.Service")?;
    let text = |p: &HashMap<String, glib::Variant>, k: &str| -> Result<String, String> {
        p.get(k)
            .and_then(|v| v.get::<String>())
            .ok_or_else(|| format!("Missing systemd {k}"))
    };
    let boolean = |p: &HashMap<String, glib::Variant>, k: &str| -> Result<bool, String> {
        p.get(k)
            .and_then(|v| v.get::<bool>())
            .ok_or_else(|| format!("Missing systemd {k}"))
    };
    let commands = service.get("ExecStart").ok_or("Missing ExecStart")?;
    if commands.type_().as_str() != "a(sasbttttuii)" || commands.n_children() != 1 {
        return Err("Unexpected systemd execution specification".into());
    }
    let command = commands.child_value(0);
    Ok(SystemdSupervisorIdentity {
        unit: text(&unit, "Id")?,
        fragment: text(&unit, "FragmentPath")?,
        loaded: text(&unit, "LoadState")?,
        active: text(&unit, "ActiveState")?,
        transient: boolean(&unit, "Transient")?,
        user: text(&service, "User")?,
        nnp: boolean(&service, "NoNewPrivileges")?,
        main_pid: service
            .get("MainPID")
            .and_then(|v| v.get::<u32>())
            .ok_or("Missing MainPID")?,
        started_usec: service
            .get("ExecMainStartTimestamp")
            .and_then(|v| v.get::<u64>())
            .ok_or("Missing process start timestamp")?,
        executable: command
            .child_value(0)
            .get::<String>()
            .ok_or("Invalid executable")?,
        arguments: command
            .child_value(1)
            .get::<Vec<String>>()
            .ok_or("Invalid arguments")?,
    })
}

fn verify_system_process(peer: &PeerProcess) -> Result<(), String> {
    if peer.credentials().uid != 0 || !peer.is_alive()? {
        return Err("System supervisor must be a live root process".into());
    }
    let pinned = open_system_supervisor()?;
    let expected = pinned.metadata().map_err(|e| e.to_string())?;
    let changed_usec = u64::try_from(expected.ctime())
        .ok()
        .and_then(|v| v.checked_mul(1_000_000))
        .and_then(|v| v.checked_add(u64::try_from(expected.ctime_nsec()).ok()? / 1000))
        .ok_or("Invalid executable change timestamp")?;
    let identity = systemd_supervisor_identity(peer.credentials().pid as u32)?;
    identity.validate(peer.credentials().pid, changed_usec)?;
    let after = open_system_supervisor()?
        .metadata()
        .map_err(|e| e.to_string())?;
    if expected.dev() != after.dev()
        || expected.ino() != after.ino()
        || expected.ctime() != after.ctime()
        || expected.ctime_nsec() != after.ctime_nsec()
        || !peer.is_alive()?
    {
        return Err("Supervisor exited or executable changed during authentication".into());
    }
    Ok(())
}

#[cfg(test)]
mod activated_sender_tests {
    #[test]
    fn handshake_identifies_acceptor_not_listener_creator() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::DirBuilderExt;
        let directory =
            std::env::temp_dir().join(format!("rwr-activated-sender-{}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("socket");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let listener_fd = listener.as_raw_fd();
        // Only async-signal-safe C calls in the forked child. This tests kernel
        // credentials, not a positive Polkit decision or an update transaction.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe {
                let fd = libc::accept4(
                    listener_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                );
                if fd < 0 {
                    libc::_exit(2);
                }
                let mut byte = 0u8;
                if libc::read(fd, (&mut byte as *mut u8).cast(), 1) != 1 {
                    libc::_exit(3);
                }
                if libc::write(fd, (&byte as *const u8).cast(), 1) != 1 {
                    libc::_exit(4);
                }
                libc::read(fd, (&mut byte as *mut u8).cast(), 1);
                libc::_exit(0);
            }
        }
        let mut socket = std::os::unix::net::UnixStream::connect(&path).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let listener_peer = super::PeerProcess::from_socket(&socket).unwrap();
        assert_eq!(listener_peer.credentials().pid, std::process::id() as i32);
        let sender = super::receive_sender_hello(&mut socket).unwrap();
        assert_eq!(sender.credentials().pid, child);
        assert!(sender.is_alive().unwrap());
        assert!(super::verify_system_process(&sender).is_err()); // ordinary UID, never authority
        socket.write_all(b"x").unwrap();
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(status, 0);
        assert!(!sender.is_alive().unwrap());
        drop((socket, listener));
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(test)]
mod server_hello_tests {
    use super::*;
    use std::io::{Read, Write};
    #[test]
    fn empty_disconnect_is_not_a_failed_session() {
        let (mut server, client) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(client);
        assert!(!send_system_server_hello(&mut server).unwrap());
    }
    #[test]
    fn idle_timeout_is_not_a_failed_session() {
        let (mut server, _client) = std::os::unix::net::UnixStream::pair().unwrap();
        server
            .set_read_timeout(Some(std::time::Duration::from_millis(20)))
            .unwrap();
        assert!(!send_system_server_hello(&mut server).unwrap());
    }
    #[test]
    fn invalid_hello_remains_rejected() {
        let (mut server, mut client) = std::os::unix::net::UnixStream::pair().unwrap();
        client.write_all(b"X").unwrap();
        assert!(
            send_system_server_hello(&mut server)
                .unwrap_err()
                .contains("Invalid system handshake")
        );
    }
    #[test]
    fn valid_transport_hello_is_unchanged() {
        let (mut server, mut client) = std::os::unix::net::UnixStream::pair().unwrap();
        client.write_all(b"R").unwrap();
        assert!(send_system_server_hello(&mut server).unwrap());
        let mut reply = [0];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [b'R']);
    }
}

/// Deployment opt-in only. This is never transaction authorization.
/// No environment override and no caller-selected path exist.
pub const SYSTEM_EXECUTION_POLICY: &str = "/etc/rwr-package-intelligence/execution-policy.json";

fn parse_execution_policy(bytes: &[u8]) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| "Invalid execution policy JSON")?;
    if value.as_object().is_none_or(|v| v.len() != 2)
        || value["schema"] != 1
        || value["allow_system_upgrade"] != true
    {
        return Err("System execution policy is disabled or incompatible".into());
    }
    Ok(())
}

/// Rechecked at privileged boundaries; missing/untrusted policy fails closed.
/// Root control of deployment does not grant a GUI subject a Polkit capability.
pub fn require_system_execution_policy() -> Result<(), String> {
    if crate::test_isolation::active() {
        // Tests never observe the host policy: REAL stays locked for them.
        return Err("REAL MODE locked: test isolation ignores host execution policy".into());
    }
    let check = || -> Result<(), String> {
        let path = Path::new(SYSTEM_EXECUTION_POLICY);
        for ancestor in path.ancestors() {
            let meta = std::fs::symlink_metadata(ancestor).map_err(|e| e.to_string())?;
            if meta.uid() != 0
                || meta.mode() & 0o022 != 0
                || (ancestor != path && !meta.is_dir())
                || meta.file_type().is_symlink()
            {
                return Err("Untrusted execution policy path".into());
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| e.to_string())?;
        let meta = file.metadata().map_err(|e| e.to_string())?;
        if !meta.is_file()
            || meta.uid() != 0
            || meta.nlink() != 1
            || meta.mode() & 0o7777 != 0o644
            || meta.len() > 4096
        {
            return Err("Untrusted execution policy owner/type/mode/size".into());
        }
        let mut bytes = Vec::new();
        file.take(4097)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 4096 {
            return Err("Execution policy too large".into());
        }
        parse_execution_policy(&bytes)
    };
    check().map_err(|e| format!("REAL MODE locked: {e}"))
}

/// Runtime observation, deliberately not a const or compile-time feature.
pub fn system_execution_enabled() -> bool {
    require_system_execution_policy().is_ok()
}

#[cfg(test)]
mod execution_policy_tests {
    use super::*;
    #[test]
    fn explicit_policy_is_a_deployment_choice_only() {
        assert!(parse_execution_policy(br#"{"schema":1,"allow_system_upgrade":true}"#).is_ok());
        // Parsing grants no SystemCommitAuthorization; its fields stay private.
    }
    #[test]
    fn missing_false_malformed_and_unknown_policy_fields_fail_closed() {
        for bytes in [
            b"".as_slice(),
            b"{}",
            b"null",
            br#"{"schema":1,"allow_system_upgrade":false}"#,
            br#"{"schema":2,"allow_system_upgrade":true}"#,
            br#"{"schema":1,"allow_system_upgrade":"true"}"#,
            br#"{"schema":1,"allow_system_upgrade":true,"uid":0}"#,
        ] {
            assert!(parse_execution_policy(bytes).is_err());
        }
    }
    #[test]
    fn prepared_deployment_policy_matches_strict_runtime_schema() {
        let policy = include_bytes!("../tests/fixtures/execution-policy.enabled.json");
        assert!(parse_execution_policy(policy).is_ok());
        let value: serde_json::Value = serde_json::from_slice(policy).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 2);
        assert_eq!(value["schema"], 1);
        assert_eq!(value["allow_system_upgrade"], true);
    }
    #[test]
    fn host_execution_remains_disabled() {
        assert!(
            !system_execution_enabled(),
            "do not run tests against an enabled host"
        );
        assert!(
            require_system_execution_policy()
                .unwrap_err()
                .contains("REAL MODE locked")
        );
    }
}

#[cfg(test)]
mod systemd_identity_tests {
    use super::*;
    fn identity() -> SystemdSupervisorIdentity {
        SystemdSupervisorIdentity {
            unit: SYSTEM_UNIT.into(),
            fragment: SYSTEM_UNIT_FILE.into(),
            loaded: "loaded".into(),
            active: "active".into(),
            transient: false,
            main_pid: 42,
            started_usec: 200,
            user: "root".into(),
            nnp: true,
            executable: SYSTEM_SUPERVISOR.into(),
            arguments: vec![SYSTEM_SUPERVISOR.into(), "--serve-system".into()],
        }
    }
    #[test]
    fn exact_unit_main_process_is_required() {
        let valid = identity();
        valid.validate(42, 100).unwrap();
        assert!(valid.validate(43, 100).is_err());
        for field in [
            "unit",
            "fragment",
            "active",
            "loaded",
            "user",
            "executable",
            "arguments",
            "nnp",
            "transient",
        ] {
            let mut value = valid.clone();
            match field {
                "unit" => value.unit = "other.service".into(),
                "fragment" => value.fragment = "/tmp/service".into(),
                "active" => value.active = "inactive".into(),
                "loaded" => value.loaded = "not-found".into(),
                "user" => value.user = "user".into(),
                "executable" => value.executable = "/tmp/helper".into(),
                "arguments" => value.arguments.push("--unexpected".into()),
                "nnp" => value.nnp = false,
                _ => value.transient = true,
            }
            assert!(value.validate(42, 100).is_err(), "{field}");
        }
    }
    #[test]
    fn executable_replaced_after_start_fails_closed() {
        assert!(identity().validate(42, 201).is_err());
        let mut value = identity();
        value.started_usec = 0;
        assert!(value.validate(42, 100).is_err());
    }
}
