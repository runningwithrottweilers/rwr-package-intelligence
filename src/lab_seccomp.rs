//! Seccomp profile for the isolated ALPM PREPARE laboratory.
//! Denylist, not a production allowlist. Never authorizes COMMIT.

use std::ffi::{CString, c_void};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};

const SCMP_ACT_ALLOW: u32 = 0x7fff0000;
const SCMP_ACT_ERRNO: u32 = 0x00050000;

#[link(name = "seccomp")]
unsafe extern "C" {
    fn seccomp_init(default_action: u32) -> *mut c_void;
    fn seccomp_release(ctx: *mut c_void);
    fn seccomp_rule_add(ctx: *mut c_void, action: u32, syscall: i32, arg_cnt: u32, ...) -> i32;
    fn seccomp_export_bpf(ctx: *mut c_void, fd: i32) -> i32;
}

struct FilterContext(*mut c_void);

impl Drop for FilterContext {
    fn drop(&mut self) {
        unsafe { seccomp_release(self.0) };
    }
}

pub fn prepare_filter() -> Result<File, String> {
    let name = CString::new("rwr-lab-seccomp").map_err(|e| e.to_string())?;

    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };

    if fd < 0 {
        return Err(format!(
            "Cannot create seccomp memfd: {}",
            std::io::Error::last_os_error()
        ));
    }

    let file = unsafe { File::from_raw_fd(fd) };

    let ptr = unsafe { seccomp_init(SCMP_ACT_ALLOW) };

    if ptr.is_null() {
        return Err("seccomp_init failed".into());
    }

    let ctx = FilterContext(ptr);

    let denied = [
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_ptrace,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_reboot,
    ];

    for syscall in denied {
        let rc = unsafe {
            seccomp_rule_add(
                ctx.0,
                SCMP_ACT_ERRNO | libc::EPERM as u32,
                syscall as i32,
                0,
            )
        };

        if rc < 0 {
            return Err(format!(
                "Cannot add seccomp rule for syscall {syscall}: {rc}"
            ));
        }
    }

    let rc = unsafe { seccomp_export_bpf(ctx.0, file.as_raw_fd()) };

    if rc < 0 {
        return Err(format!("Cannot export seccomp BPF: {rc}"));
    }

    let seek = unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_SET) };

    if seek < 0 {
        return Err(format!(
            "Cannot rewind seccomp BPF: {}",
            std::io::Error::last_os_error()
        ));
    }

    // The bwrap process must inherit this descriptor.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };

    if flags < 0 {
        return Err(format!(
            "Cannot inspect seccomp FD flags: {}",
            std::io::Error::last_os_error()
        ));
    }

    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) };

    if rc < 0 {
        return Err(format!(
            "Cannot pass seccomp FD to bwrap: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(file)
}
