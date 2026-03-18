//! ABI layer for `<dlfcn.h>` functions.
//!
//! Dynamic linker interface: `dlopen`, `dlsym`, `dlclose`, `dlerror`.
//! Delegates to system `libdl` via `libc`, with membrane validation
//! and flag checking via `frankenlibc_core::dlfcn`.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_core::dlfcn as dlfcn_core;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

// ---------------------------------------------------------------------------
// Thread-local dlerror state
// ---------------------------------------------------------------------------

use std::cell::RefCell;

std::thread_local! {
    /// Current error message (not yet seen by dlerror).
    static PENDING_ERROR: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
    /// Last error message returned by dlerror (valid until next dlfcn call).
    static STABLE_ERROR: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

/// Set the thread-local dlerror message from a static byte slice.
fn set_dlerror(msg: &'static [u8]) {
    PENDING_ERROR.with(|cell| {
        *cell.borrow_mut() = Some(msg.to_vec());
    });
}

/// Set the thread-local dlerror message from a raw C string (performing a deep copy).
unsafe fn set_dlerror_raw(msg: *const c_char) {
    if msg.is_null() {
        clear_dlerror();
        return;
    }
    // SAFETY: caller guarantees msg is a valid NUL-terminated C string.
    let c_str = unsafe { std::ffi::CStr::from_ptr(msg) };
    let bytes = c_str.to_bytes_with_nul().to_vec();
    PENDING_ERROR.with(|cell| {
        *cell.borrow_mut() = Some(bytes);
    });
}

/// Clear the thread-local dlerror message.
fn clear_dlerror() {
    PENDING_ERROR.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

#[inline]
pub(crate) unsafe fn dlvsym_next(symbol: *const c_char, version: *const c_char) -> *mut c_void {
    unsafe { libc::dlvsym(libc::RTLD_NEXT, symbol, version) }
}

use std::sync::atomic::{AtomicPtr, Ordering};

macro_rules! host_delegate {
    ($name:ident, $sym:expr, $ty:ty) => {
        #[inline(always)]
        unsafe fn $name() -> Option<$ty> {
            // SAFETY: dlvsym_next and transmute require unsafe context.
            unsafe {
                static PTR: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
                let mut ptr = PTR.load(Ordering::Relaxed);
                if ptr.is_null() {
                    let sym_bytes = concat!($sym, "\0").as_bytes();
                    let v34 = b"GLIBC_2.34\0";
                    let v225 = b"GLIBC_2.2.5\0";
                    let v217 = b"GLIBC_2.17\0";
                    ptr = dlvsym_next(
                        sym_bytes.as_ptr().cast::<c_char>(),
                        v34.as_ptr().cast::<c_char>(),
                    );
                    if ptr.is_null() {
                        ptr = dlvsym_next(
                            sym_bytes.as_ptr().cast::<c_char>(),
                            v225.as_ptr().cast::<c_char>(),
                        );
                    }
                    if ptr.is_null() {
                        ptr = dlvsym_next(
                            sym_bytes.as_ptr().cast::<c_char>(),
                            v217.as_ptr().cast::<c_char>(),
                        );
                    }
                    if !ptr.is_null() {
                        PTR.store(ptr, Ordering::Relaxed);
                    }
                }
                if ptr.is_null() {
                    None
                } else {
                    Some(std::mem::transmute::<*mut c_void, $ty>(ptr))
                }
            }
        }
    };
}

type DlopenFn = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
host_delegate!(host_dlopen, "dlopen", DlopenFn);

type DlsymFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
host_delegate!(host_dlsym, "dlsym", DlsymFn);

type DlcloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;
host_delegate!(host_dlclose, "dlclose", DlcloseFn);

type DlvsymFn = unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut c_void;
host_delegate!(host_dlvsym, "dlvsym", DlvsymFn);

// ---------------------------------------------------------------------------
// dlopen
// ---------------------------------------------------------------------------

/// Open a shared object.
///
/// If `filename` is null, returns a handle to the main program. Otherwise
/// loads the named shared object. `flags` must have exactly one of
/// `RTLD_LAZY` or `RTLD_NOW` set; additional modifier flags are allowed.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Loader, filename as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        set_dlerror(dlfcn_core::ERR_NOT_FOUND);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    // Validate flags via core.
    if !dlfcn_core::valid_flags(flags) {
        if mode.heals_enabled() {
            // Hardened mode: default to RTLD_NOW | RTLD_LOCAL.
            let healed_flags = dlfcn_core::RTLD_NOW;
            clear_dlerror();
            let handle = unsafe {
                host_dlopen().map_or(std::ptr::null_mut(), |f| f(filename, healed_flags))
            };
            let adverse = handle.is_null();
            if adverse {
                let host_err = unsafe { libc::dlerror() };
                if !host_err.is_null() {
                    unsafe { set_dlerror_raw(host_err) };
                } else {
                    set_dlerror(dlfcn_core::ERR_NOT_FOUND);
                }
            }
            runtime_policy::observe(ApiFamily::Loader, decision.profile, 12, adverse);
            return handle;
        }
        set_dlerror(dlfcn_core::ERR_INVALID_FLAGS);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    clear_dlerror();
    let handle = unsafe { host_dlopen().map_or(std::ptr::null_mut(), |f| f(filename, flags)) };
    let adverse = handle.is_null();
    if adverse {
        let host_err = unsafe { libc::dlerror() };
        if !host_err.is_null() {
            unsafe { set_dlerror_raw(host_err) };
        } else {
            set_dlerror(dlfcn_core::ERR_NOT_FOUND);
        }
    }
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 12, adverse);
    handle
}

// ---------------------------------------------------------------------------
// dlsym
// ---------------------------------------------------------------------------

thread_local! {
    static DLSYM_REENTRY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Find a symbol in a shared object.
///
/// `handle` may be a real handle from `dlopen`, or one of the pseudo-handles
/// `RTLD_DEFAULT` / `RTLD_NEXT`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void {
    if DLSYM_REENTRY.try_with(|r| r.get()).unwrap_or(true) {
        return unsafe { host_dlsym().map_or(std::ptr::null_mut(), |f| f(handle, symbol)) };
    }

    struct DlsymGuard;
    impl Drop for DlsymGuard {
        fn drop(&mut self) {
            let _ = DLSYM_REENTRY.try_with(|r| r.set(false));
        }
    }
    let _guard = DlsymGuard;
    let _ = DLSYM_REENTRY.try_with(|r| r.set(true));

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Loader, handle as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    if symbol.is_null() {
        set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    clear_dlerror();
    let sym = unsafe { host_dlsym().map_or(std::ptr::null_mut(), |f| f(handle, symbol)) };
    let adverse = sym.is_null();
    if adverse {
        let host_err = unsafe { libc::dlerror() };
        if !host_err.is_null() {
            unsafe { set_dlerror_raw(host_err) };
        } else {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        }
    }
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
    sym
}

/// Find a symbol with a specific version in a shared object.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dlvsym(
    handle: *mut c_void,
    symbol: *const c_char,
    version: *const c_char,
) -> *mut c_void {
    if DLSYM_REENTRY.try_with(|r| r.get()).unwrap_or(true) {
        return unsafe {
            host_dlvsym().map_or(std::ptr::null_mut(), |f| f(handle, symbol, version))
        };
    }

    struct DlsymGuard;
    impl Drop for DlsymGuard {
        fn drop(&mut self) {
            let _ = DLSYM_REENTRY.try_with(|r| r.set(false));
        }
    }
    let _guard = DlsymGuard;
    let _ = DLSYM_REENTRY.try_with(|r| r.set(true));

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Loader, handle as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    if symbol.is_null() || version.is_null() {
        set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    clear_dlerror();
    let sym = unsafe { host_dlvsym().map_or(std::ptr::null_mut(), |f| f(handle, symbol, version)) };
    let adverse = sym.is_null();
    if adverse {
        let host_err = unsafe { libc::dlerror() };
        if !host_err.is_null() {
            unsafe { set_dlerror_raw(host_err) };
        } else {
            set_dlerror(dlfcn_core::ERR_SYMBOL_NOT_FOUND);
        }
    }
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
    sym
}

// ---------------------------------------------------------------------------
// dlclose
// ---------------------------------------------------------------------------

/// Close a shared object handle.
///
/// Returns 0 on success, non-zero on error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dlclose(handle: *mut c_void) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Loader, handle as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe {
            let p = super::errno_abi::__errno_location();
            *p = libc::EPERM;
        }
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return -1;
    }

    if handle.is_null() {
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return -1;
    }

    clear_dlerror();
    let rc = unsafe { host_dlclose().map_or(-1, |f| f(handle)) };
    let adverse = rc != 0;
    if adverse {
        let host_err = unsafe { libc::dlerror() };
        if !host_err.is_null() {
            unsafe { set_dlerror_raw(host_err) };
        } else {
            set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        }
    }
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
    rc
}

/// Return a human-readable error message for the last `dlopen`, `dlsym`,
/// or `dlclose` failure. Returns null if no error has occurred since the
/// last call to `dlerror`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dlerror() -> *const c_char {
    let pending = PENDING_ERROR.with(|cell| cell.borrow_mut().take());
    if let Some(msg) = pending {
        STABLE_ERROR.with(|cell| {
            let mut stable = cell.borrow_mut();
            *stable = Some(msg);
            stable.as_ref().unwrap().as_ptr() as *const c_char
        })
    } else {
        std::ptr::null()
    }
}

// ---------------------------------------------------------------------------
// dl_iterate_phdr / dladdr — native fallback (no host call-through)
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dl_iterate_phdr(
    callback: Option<unsafe extern "C" fn(*mut c_void, usize, *mut c_void) -> c_int>,
    data: *mut c_void,
) -> c_int {
    let callback_addr = callback.map_or(0usize, |cb| cb as usize);
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Loader,
        callback_addr,
        data as usize,
        false,
        true,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        set_dlerror(dlfcn_core::ERR_OPERATION_UNAVAILABLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return -1;
    }

    // Phase-1 native replacement-safe fallback: report no entries instead of
    // calling into host loader internals.
    let _ = callback;
    let _ = data;
    clear_dlerror();
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 6, false);
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dladdr(addr: *const c_void, info: *mut c_void) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Loader,
        addr as usize,
        info as usize,
        false,
        true,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        set_dlerror(dlfcn_core::ERR_OPERATION_UNAVAILABLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return 0;
    }

    if addr.is_null() {
        set_dlerror(dlfcn_core::ERR_INVALID_HANDLE);
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return 0;
    }

    if info.is_null() {
        // POSIX does not define behavior for null info, but returning 0 (failure)
        // is the safest path for libc replacement.
        runtime_policy::observe(ApiFamily::Loader, decision.profile, 5, true);
        return 0;
    }

    // Native fallback currently does not expose loader metadata.
    set_dlerror(dlfcn_core::ERR_OPERATION_UNAVAILABLE);
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 6, true);
    0
}
