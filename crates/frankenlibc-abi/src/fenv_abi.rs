//! ABI layer for `<fenv.h>` functions.
//!
//! Floating-point environment control: rounding modes, exception flags,
//! and environment save/restore. Delegates to host glibc since these
//! functions manipulate hardware FPU state (x87 control word, MXCSR).

use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::dlfcn_abi::dlvsym_next;

// ---------------------------------------------------------------------------
// Host delegation helpers
// ---------------------------------------------------------------------------

macro_rules! fenv_delegate {
    ($name:ident, $sym:expr, $ty:ty) => {
        #[inline(always)]
        unsafe fn $name() -> Option<$ty> {
            static PTR: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
            let mut ptr = PTR.load(Ordering::Relaxed);
            if ptr.is_null() {
                let sym_bytes = concat!($sym, "\0").as_bytes();
                let v34 = b"GLIBC_2.34\0";
                let v225 = b"GLIBC_2.2.5\0";
                unsafe {
                    ptr = dlvsym_next(sym_bytes.as_ptr().cast(), v34.as_ptr().cast());
                    if ptr.is_null() {
                        ptr = dlvsym_next(sym_bytes.as_ptr().cast(), v225.as_ptr().cast());
                    }
                }
                if !ptr.is_null() {
                    PTR.store(ptr, Ordering::Relaxed);
                }
            }
            if ptr.is_null() {
                None
            } else {
                Some(unsafe { std::mem::transmute::<*mut c_void, $ty>(ptr) })
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Function type declarations
// ---------------------------------------------------------------------------

type FeVoidToIntFn = unsafe extern "C" fn() -> c_int;
type FeIntToIntFn = unsafe extern "C" fn(c_int) -> c_int;
type FeGetEnvFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type FeSetEnvFn = unsafe extern "C" fn(*const c_void) -> c_int;
type FeGetFlagFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type FeSetFlagFn = unsafe extern "C" fn(*const c_void, c_int) -> c_int;

fenv_delegate!(host_fegetround, "fegetround", FeVoidToIntFn);
fenv_delegate!(host_fesetround, "fesetround", FeIntToIntFn);
fenv_delegate!(host_feclearexcept, "feclearexcept", FeIntToIntFn);
fenv_delegate!(host_fetestexcept, "fetestexcept", FeIntToIntFn);
fenv_delegate!(host_feraiseexcept, "feraiseexcept", FeIntToIntFn);
fenv_delegate!(host_fegetenv, "fegetenv", FeGetEnvFn);
fenv_delegate!(host_fesetenv, "fesetenv", FeSetEnvFn);
fenv_delegate!(host_feholdexcept, "feholdexcept", FeGetEnvFn);
fenv_delegate!(host_feupdateenv, "feupdateenv", FeSetEnvFn);
fenv_delegate!(host_fegetexceptflag, "fegetexceptflag", FeGetFlagFn);
fenv_delegate!(host_fesetexceptflag, "fesetexceptflag", FeSetFlagFn);

// ---------------------------------------------------------------------------
// Rounding mode control
// ---------------------------------------------------------------------------

/// Get the current rounding direction mode.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fegetround() -> c_int {
    unsafe { host_fegetround().map_or(-1, |f| f()) }
}

/// Set the rounding direction mode.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fesetround(rnd: c_int) -> c_int {
    unsafe { host_fesetround().map_or(-1, |f| f(rnd)) }
}

// ---------------------------------------------------------------------------
// Exception flag manipulation
// ---------------------------------------------------------------------------

/// Clear the specified floating-point exception flags.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn feclearexcept(excepts: c_int) -> c_int {
    unsafe { host_feclearexcept().map_or(-1, |f| f(excepts)) }
}

/// Test the specified floating-point exception flags.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fetestexcept(excepts: c_int) -> c_int {
    unsafe { host_fetestexcept().map_or(0, |f| f(excepts)) }
}

/// Raise the specified floating-point exceptions.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn feraiseexcept(excepts: c_int) -> c_int {
    unsafe { host_feraiseexcept().map_or(-1, |f| f(excepts)) }
}

/// Get the floating-point exception flags.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fegetexceptflag(flagp: *mut c_void, excepts: c_int) -> c_int {
    if flagp.is_null() {
        return -1;
    }
    unsafe { host_fegetexceptflag().map_or(-1, |f| f(flagp, excepts)) }
}

/// Set the floating-point exception flags.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fesetexceptflag(flagp: *const c_void, excepts: c_int) -> c_int {
    if flagp.is_null() {
        return -1;
    }
    unsafe { host_fesetexceptflag().map_or(-1, |f| f(flagp, excepts)) }
}

// ---------------------------------------------------------------------------
// Environment save/restore
// ---------------------------------------------------------------------------

/// Save the current floating-point environment.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fegetenv(envp: *mut c_void) -> c_int {
    if envp.is_null() {
        return -1;
    }
    unsafe { host_fegetenv().map_or(-1, |f| f(envp)) }
}

/// Set the floating-point environment.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fesetenv(envp: *const c_void) -> c_int {
    unsafe { host_fesetenv().map_or(-1, |f| f(envp)) }
}

/// Save the current floating-point environment and clear all exceptions.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn feholdexcept(envp: *mut c_void) -> c_int {
    if envp.is_null() {
        return -1;
    }
    unsafe { host_feholdexcept().map_or(-1, |f| f(envp)) }
}

/// Install the floating-point environment and raise saved exceptions.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn feupdateenv(envp: *const c_void) -> c_int {
    unsafe { host_feupdateenv().map_or(-1, |f| f(envp)) }
}
