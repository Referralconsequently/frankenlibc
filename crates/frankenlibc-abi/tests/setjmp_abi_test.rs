#![cfg(target_os = "linux")]

//! Integration tests for `<setjmp.h>` ABI entrypoints.
//!
//! In integration test mode (not `#[cfg(test)]` from the library crate's
//! perspective), `longjmp`/`siglongjmp` call `abort()` rather than panicking.
//! Therefore we can only exercise the capture path (`setjmp`, `_setjmp`,
//! `sigsetjmp`) and verify null-pointer error handling.

use std::ffi::c_void;
use std::ptr;

use frankenlibc_abi::setjmp_abi::{_setjmp, setjmp, sigsetjmp};

// ---------------------------------------------------------------------------
// setjmp — capture returns 0
// ---------------------------------------------------------------------------

#[test]
fn setjmp_returns_zero_on_capture() {
    let mut env = [0u64; 32]; // generous buffer for jmp_buf
    let env_ptr = env.as_mut_ptr().cast::<c_void>();
    let rc = unsafe { setjmp(env_ptr) };
    assert_eq!(rc, 0, "setjmp should return 0 on first (capture) call");
}

#[test]
fn setjmp_null_env_returns_negative() {
    let rc = unsafe { setjmp(ptr::null_mut()) };
    assert_eq!(rc, -1, "setjmp(NULL) should return -1");
}

// ---------------------------------------------------------------------------
// _setjmp — BSD variant, same contract
// ---------------------------------------------------------------------------

#[test]
fn _setjmp_returns_zero_on_capture() {
    let mut env = [0u64; 32];
    let env_ptr = env.as_mut_ptr().cast::<c_void>();
    let rc = unsafe { _setjmp(env_ptr) };
    assert_eq!(rc, 0, "_setjmp should return 0 on first (capture) call");
}

#[test]
fn _setjmp_null_env_returns_negative() {
    let rc = unsafe { _setjmp(ptr::null_mut()) };
    assert_eq!(rc, -1, "_setjmp(NULL) should return -1");
}

// ---------------------------------------------------------------------------
// sigsetjmp — with and without signal mask save
// ---------------------------------------------------------------------------

#[test]
fn sigsetjmp_no_mask_returns_zero() {
    let mut env = [0u64; 32];
    let env_ptr = env.as_mut_ptr().cast::<c_void>();
    let rc = unsafe { sigsetjmp(env_ptr, 0) };
    assert_eq!(rc, 0, "sigsetjmp(env, 0) should return 0 on capture");
}

#[test]
fn sigsetjmp_with_mask_returns_zero() {
    let mut env = [0u64; 32];
    let env_ptr = env.as_mut_ptr().cast::<c_void>();
    let rc = unsafe { sigsetjmp(env_ptr, 1) };
    assert_eq!(rc, 0, "sigsetjmp(env, 1) should return 0 on capture");
}

#[test]
fn sigsetjmp_null_env_returns_negative() {
    let rc = unsafe { sigsetjmp(ptr::null_mut(), 0) };
    assert_eq!(rc, -1, "sigsetjmp(NULL, 0) should return -1");
}

// ---------------------------------------------------------------------------
// Multiple captures don't interfere
// ---------------------------------------------------------------------------

#[test]
fn multiple_captures_independent() {
    let mut env_a = [0u64; 32];
    let mut env_b = [0u64; 32];
    let rc_a = unsafe { setjmp(env_a.as_mut_ptr().cast::<c_void>()) };
    let rc_b = unsafe { sigsetjmp(env_b.as_mut_ptr().cast::<c_void>(), 1) };
    assert_eq!(rc_a, 0);
    assert_eq!(rc_b, 0);
}

// ---------------------------------------------------------------------------
// Repeated capture on same buffer succeeds
// ---------------------------------------------------------------------------

#[test]
fn setjmp_repeated_capture_same_buffer() {
    let mut env = [0u64; 32];
    let env_ptr = env.as_mut_ptr().cast::<c_void>();
    for _ in 0..5 {
        let rc = unsafe { setjmp(env_ptr) };
        assert_eq!(rc, 0, "repeated setjmp on same buffer should return 0");
    }
}

// ---------------------------------------------------------------------------
// sigsetjmp with various savemask values
// ---------------------------------------------------------------------------

#[test]
fn sigsetjmp_nonzero_savemask_treated_as_true() {
    let mut env = [0u64; 32];
    let env_ptr = env.as_mut_ptr().cast::<c_void>();
    // Any nonzero savemask should be treated as "save mask"
    for mask in [1i32, 42, -1, i32::MAX] {
        let rc = unsafe { sigsetjmp(env_ptr, mask) };
        assert_eq!(rc, 0, "sigsetjmp(env, {mask}) should return 0");
    }
}
