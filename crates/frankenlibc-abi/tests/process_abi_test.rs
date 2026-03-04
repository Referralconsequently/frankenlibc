#![cfg(target_os = "linux")]

//! Integration tests for `<spawn.h>` and process ABI entrypoints.
//!
//! Tests cover posix_spawn attribute and file action lifecycle:
//! init/destroy, flag get/set, signal set get/set, pgroup, sched params,
//! file actions (addclose, adddup2, addopen, addchdir_np, addfchdir_np).
//!
//! Fork/exec/wait tests are in separate integration test suites
//! because they require child process creation.

use std::ffi::{c_int, CString};

use frankenlibc_abi::process_abi::*;

// ===========================================================================
// posix_spawnattr lifecycle: init / destroy
// ===========================================================================

// The opaque posix_spawnattr_t struct needs enough space for magic + pointer.
// On glibc it's typically 336 bytes. We use 512 to be safe.
// Must be 8-byte aligned because process_abi writes u64 at offset 0.
#[repr(C, align(8))]
struct AlignedBuf([u8; 512]);

impl AlignedBuf {
    fn new() -> Self {
        Self([0u8; 512])
    }
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }
    fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }
}

#[test]
fn spawnattr_init_destroy() {
    let mut attr = AlignedBuf::new();
    let rc = unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };
    assert_eq!(rc, 0, "init should succeed");

    let rc = unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
    assert_eq!(rc, 0, "destroy should succeed");
}

#[test]
fn spawnattr_init_null_returns_einval() {
    let rc = unsafe { posix_spawnattr_init(std::ptr::null_mut()) };
    assert_eq!(rc, libc::EINVAL);
}

#[test]
fn spawnattr_destroy_null_returns_einval() {
    let rc = unsafe { posix_spawnattr_destroy(std::ptr::null_mut()) };
    assert_eq!(rc, libc::EINVAL);
}

#[test]
fn spawnattr_destroy_uninitialized_returns_einval() {
    let mut attr = AlignedBuf::new();
    let rc = unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
    assert_eq!(rc, libc::EINVAL, "destroy uninitialized should return EINVAL");
}

// ===========================================================================
// posix_spawnattr flags
// ===========================================================================

#[test]
fn spawnattr_flags_default_zero() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let mut flags: libc::c_short = -1;
    let rc = unsafe { posix_spawnattr_getflags(attr.as_ptr().cast(), &mut flags) };
    assert_eq!(rc, 0);
    assert_eq!(flags, 0, "default flags should be 0");

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

#[test]
fn spawnattr_flags_roundtrip() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawnattr_setflags(attr.as_mut_ptr().cast(), 0x1234) };
    assert_eq!(rc, 0);

    let mut flags: libc::c_short = 0;
    let rc = unsafe { posix_spawnattr_getflags(attr.as_ptr().cast(), &mut flags) };
    assert_eq!(rc, 0);
    assert_eq!(flags, 0x1234);

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

// ===========================================================================
// posix_spawnattr pgroup
// ===========================================================================

#[test]
fn spawnattr_pgroup_default_zero() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let mut pgroup: libc::pid_t = -1;
    let rc = unsafe { posix_spawnattr_getpgroup(attr.as_ptr().cast(), &mut pgroup) };
    assert_eq!(rc, 0);
    assert_eq!(pgroup, 0, "default pgroup should be 0");

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

#[test]
fn spawnattr_pgroup_roundtrip() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawnattr_setpgroup(attr.as_mut_ptr().cast(), 42) };
    assert_eq!(rc, 0);

    let mut pgroup: libc::pid_t = 0;
    let rc = unsafe { posix_spawnattr_getpgroup(attr.as_ptr().cast(), &mut pgroup) };
    assert_eq!(rc, 0);
    assert_eq!(pgroup, 42);

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

// ===========================================================================
// posix_spawnattr sched policy
// ===========================================================================

#[test]
fn spawnattr_schedpolicy_default_zero() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let mut policy: c_int = -1;
    let rc = unsafe { posix_spawnattr_getschedpolicy(attr.as_ptr().cast(), &mut policy) };
    assert_eq!(rc, 0);
    assert_eq!(policy, 0);

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

#[test]
fn spawnattr_schedpolicy_roundtrip() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawnattr_setschedpolicy(attr.as_mut_ptr().cast(), libc::SCHED_RR) };
    assert_eq!(rc, 0);

    let mut policy: c_int = 0;
    let rc = unsafe { posix_spawnattr_getschedpolicy(attr.as_ptr().cast(), &mut policy) };
    assert_eq!(rc, 0);
    assert_eq!(policy, libc::SCHED_RR);

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

// ===========================================================================
// posix_spawnattr schedparam
// ===========================================================================

#[test]
fn spawnattr_schedparam_roundtrip() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let param_in = libc::sched_param { sched_priority: 10 };
    let rc = unsafe { posix_spawnattr_setschedparam(attr.as_mut_ptr().cast(), &param_in) };
    assert_eq!(rc, 0);

    let mut param_out: libc::sched_param = unsafe { std::mem::zeroed() };
    let rc = unsafe { posix_spawnattr_getschedparam(attr.as_ptr().cast(), &mut param_out) };
    assert_eq!(rc, 0);
    assert_eq!(param_out.sched_priority, 10);

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

// ===========================================================================
// posix_spawnattr signal sets
// ===========================================================================

#[test]
fn spawnattr_sigdefault_roundtrip() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    // Set SIGCHLD in sigdefault
    let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut sigset);
        libc::sigaddset(&mut sigset, libc::SIGCHLD);
    }
    let rc = unsafe { posix_spawnattr_setsigdefault(attr.as_mut_ptr().cast(), &sigset) };
    assert_eq!(rc, 0);

    // Read it back
    let mut out: libc::sigset_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { posix_spawnattr_getsigdefault(attr.as_ptr().cast(), &mut out) };
    assert_eq!(rc, 0);
    assert_eq!(
        unsafe { libc::sigismember(&out, libc::SIGCHLD) },
        1,
        "SIGCHLD should be in sigdefault"
    );
    assert_eq!(
        unsafe { libc::sigismember(&out, libc::SIGTERM) },
        0,
        "SIGTERM should NOT be in sigdefault"
    );

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

#[test]
fn spawnattr_sigmask_roundtrip() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut sigset);
        libc::sigaddset(&mut sigset, libc::SIGUSR1);
        libc::sigaddset(&mut sigset, libc::SIGUSR2);
    }
    let rc = unsafe { posix_spawnattr_setsigmask(attr.as_mut_ptr().cast(), &sigset) };
    assert_eq!(rc, 0);

    let mut out: libc::sigset_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { posix_spawnattr_getsigmask(attr.as_ptr().cast(), &mut out) };
    assert_eq!(rc, 0);
    assert_eq!(unsafe { libc::sigismember(&out, libc::SIGUSR1) }, 1);
    assert_eq!(unsafe { libc::sigismember(&out, libc::SIGUSR2) }, 1);
    assert_eq!(unsafe { libc::sigismember(&out, libc::SIGINT) }, 0);

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

// ===========================================================================
// posix_spawn_file_actions lifecycle: init / destroy
// ===========================================================================

#[test]
fn file_actions_init_destroy() {
    let mut fa = AlignedBuf::new();
    let rc = unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };
    assert_eq!(rc, 0);

    let rc = unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
    assert_eq!(rc, 0);
}

#[test]
fn file_actions_init_null_returns_einval() {
    let rc = unsafe { posix_spawn_file_actions_init(std::ptr::null_mut()) };
    assert_eq!(rc, libc::EINVAL);
}

// ===========================================================================
// posix_spawn_file_actions_add*
// ===========================================================================

#[test]
fn file_actions_addclose() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawn_file_actions_addclose(fa.as_mut_ptr().cast(), 3) };
    assert_eq!(rc, 0, "addclose should succeed");

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

#[test]
fn file_actions_adddup2() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawn_file_actions_adddup2(fa.as_mut_ptr().cast(), 1, 2) };
    assert_eq!(rc, 0, "adddup2 should succeed");

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

#[test]
fn file_actions_addopen() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    let path = CString::new("/dev/null").unwrap();
    let rc = unsafe {
        posix_spawn_file_actions_addopen(
            fa.as_mut_ptr().cast(),
            3,
            path.as_ptr(),
            libc::O_RDONLY,
            0o644,
        )
    };
    assert_eq!(rc, 0, "addopen should succeed");

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

#[test]
fn file_actions_addchdir_np() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    let path = CString::new("/tmp").unwrap();
    let rc = unsafe {
        posix_spawn_file_actions_addchdir_np(fa.as_mut_ptr().cast(), path.as_ptr())
    };
    assert_eq!(rc, 0, "addchdir_np should succeed");

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

#[test]
fn file_actions_addfchdir_np() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawn_file_actions_addfchdir_np(fa.as_mut_ptr().cast(), 0) };
    assert_eq!(rc, 0, "addfchdir_np should succeed");

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

#[test]
fn file_actions_multiple() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    // Chain multiple actions
    let path = CString::new("/dev/null").unwrap();
    assert_eq!(
        unsafe { posix_spawn_file_actions_addclose(fa.as_mut_ptr().cast(), 3) },
        0
    );
    assert_eq!(
        unsafe { posix_spawn_file_actions_adddup2(fa.as_mut_ptr().cast(), 1, 2) },
        0
    );
    assert_eq!(
        unsafe {
            posix_spawn_file_actions_addopen(
                fa.as_mut_ptr().cast(),
                4,
                path.as_ptr(),
                libc::O_RDONLY,
                0,
            )
        },
        0
    );

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

// ===========================================================================
// Null safety for accessors
// ===========================================================================

#[test]
fn spawnattr_getflags_null_attr() {
    let mut flags: libc::c_short = 0;
    let rc = unsafe { posix_spawnattr_getflags(std::ptr::null(), &mut flags) };
    assert_eq!(rc, libc::EINVAL);
}

#[test]
fn spawnattr_getpgroup_null_out() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawnattr_getpgroup(attr.as_ptr().cast(), std::ptr::null_mut()) };
    assert_eq!(rc, libc::EINVAL);

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

// ===========================================================================
// posix_spawnp (smoke test with /bin/true)
// ===========================================================================

#[test]
fn posix_spawnp_true() {
    let cmd = CString::new("/bin/true").unwrap();
    let argv: [*const std::ffi::c_char; 2] = [cmd.as_ptr(), std::ptr::null()];
    let mut pid: libc::pid_t = 0;

    let rc = unsafe {
        posix_spawnp(
            &mut pid,
            cmd.as_ptr(),
            std::ptr::null(),      // file_actions
            std::ptr::null(),      // attrp
            argv.as_ptr().cast(),  // argv
            std::ptr::null(),      // envp (inherit)
        )
    };
    assert_eq!(rc, 0, "posix_spawnp(/bin/true) should succeed");
    assert!(pid > 0, "child pid should be positive");

    // Wait for child
    let mut status: c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child should exit 0"
    );
}
