//! ABI layer for ISO C99/C23 internal-linkage aliases.
//!
//! GCC and Clang emit `__isoc99_*` and `__isoc23_*` symbol references when
//! compiling with `-std=c99`/`-std=c23` (or later). These are ABI-identical to
//! their base counterparts; they exist solely for binary compatibility with
//! glibc's versioned symbol scheme.
//!
//! This module consolidates all 38 such wrappers in one place:
//!
//! - 12 narrow scanf variants (C23)
//! - 6 wide scanf variants (C23)
//! - 6 wide scanf variants (C99)
//! - 10 strtol-family variants (C23)
//! - 4 wcstol/wcstoul/wcstoll/wcstoull + imaxabs variants (C23, 6 total)
//! - 4 wcstol_l locale variants (C23)

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, c_long, c_longlong, c_void};

type c_ulong = u64;
type c_ulonglong = u64;

/// Wide character type — `wchar_t` is i32 on Linux/glibc (UTF-32).
type WcharT = i32;

// ---------------------------------------------------------------------------
// Extern declarations for base functions we delegate to.
//
// These are already exported by stdio_abi, wchar_abi, and stdlib_abi as
// #[no_mangle] symbols. We reference them here via extern "C" blocks.
// ---------------------------------------------------------------------------

unsafe extern "C" {
    // ── narrow scanf family (stdio_abi) ──
    fn vscanf(format: *const c_char, ap: *mut c_void) -> c_int;
    fn vfscanf(stream: *mut c_void, format: *const c_char, ap: *mut c_void) -> c_int;
    fn vsscanf(s: *const c_char, format: *const c_char, ap: *mut c_void) -> c_int;

    // ── wide scanf family (wchar_abi) ──
    fn vwscanf(format: *const WcharT, ap: *mut c_void) -> c_int;
    fn vfwscanf(stream: *mut c_void, format: *const WcharT, ap: *mut c_void) -> c_int;
    fn vswscanf(s: *const WcharT, format: *const WcharT, ap: *mut c_void) -> c_int;

    // ── strtol family (stdlib_abi) ──
    fn strtol(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int) -> c_long;
    fn strtoul(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int) -> c_ulong;
    fn strtoll(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int) -> c_longlong;
    fn strtoull(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int) -> c_ulonglong;
    fn strtoimax(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int) -> i64;
    fn strtoumax(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int) -> u64;

    // ── wcstol family (wchar_abi) ──
    fn wcstol(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int) -> c_long;
    fn wcstoul(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int) -> c_ulong;
    fn wcstoll(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int) -> c_longlong;
    fn wcstoull(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int) -> c_ulonglong;
    fn wcstoimax(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int) -> i64;
    fn wcstoumax(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int) -> u64;
}

// ===========================================================================
// C23 __isoc23_* narrow scanf aliases (6 variadic + 6 va_list)
// ===========================================================================

/// `__isoc23_scanf` — C23 alias for scanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_scanf(format: *const c_char, mut args: ...) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vscanf(format, ap) }
}

/// `__isoc23_fscanf` — C23 alias for fscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_fscanf(
    stream: *mut c_void,
    format: *const c_char,
    mut args: ...
) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vfscanf(stream, format, ap) }
}

/// `__isoc23_sscanf` — C23 alias for sscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_sscanf(
    s: *const c_char,
    format: *const c_char,
    mut args: ...
) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vsscanf(s, format, ap) }
}

/// `__isoc23_wscanf` — C23 alias for wscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wscanf(format: *const WcharT, mut args: ...) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vwscanf(format, ap) }
}

/// `__isoc23_fwscanf` — C23 alias for fwscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_fwscanf(
    stream: *mut c_void,
    format: *const WcharT,
    mut args: ...
) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vfwscanf(stream, format, ap) }
}

/// `__isoc23_swscanf` — C23 alias for swscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_swscanf(
    s: *const WcharT,
    format: *const WcharT,
    mut args: ...
) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vswscanf(s, format, ap) }
}

/// `__isoc23_vscanf` — C23 alias for vscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_vscanf(format: *const c_char, ap: *mut c_void) -> c_int {
    unsafe { vscanf(format, ap) }
}

/// `__isoc23_vfscanf` — C23 alias for vfscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_vfscanf(
    stream: *mut c_void,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { vfscanf(stream, format, ap) }
}

/// `__isoc23_vsscanf` — C23 alias for vsscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_vsscanf(
    s: *const c_char,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { vsscanf(s, format, ap) }
}

/// `__isoc23_vwscanf` — C23 alias for vwscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_vwscanf(format: *const WcharT, ap: *mut c_void) -> c_int {
    unsafe { vwscanf(format, ap) }
}

/// `__isoc23_vfwscanf` — C23 alias for vfwscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_vfwscanf(
    stream: *mut c_void,
    format: *const WcharT,
    ap: *mut c_void,
) -> c_int {
    unsafe { vfwscanf(stream, format, ap) }
}

/// `__isoc23_vswscanf` — C23 alias for vswscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_vswscanf(
    s: *const WcharT,
    format: *const WcharT,
    ap: *mut c_void,
) -> c_int {
    unsafe { vswscanf(s, format, ap) }
}

// ===========================================================================
// C23 __isoc23_* strtol family (6 base + 4 locale)
// ===========================================================================

/// `__isoc23_strtol` — C23 alias for strtol.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtol(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_long {
    unsafe { strtol(nptr, endptr, base) }
}

/// `__isoc23_strtoul` — C23 alias for strtoul.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtoul(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_ulong {
    unsafe { strtoul(nptr, endptr, base) }
}

/// `__isoc23_strtoll` — C23 alias for strtoll.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtoll(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_longlong {
    unsafe { strtoll(nptr, endptr, base) }
}

/// `__isoc23_strtoull` — C23 alias for strtoull.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtoull(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_ulonglong {
    unsafe { strtoull(nptr, endptr, base) }
}

/// `__isoc23_strtoimax` — C23 alias for strtoimax.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtoimax(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> i64 {
    unsafe { strtoimax(nptr, endptr, base) }
}

/// `__isoc23_strtoumax` — C23 alias for strtoumax.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtoumax(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> u64 {
    unsafe { strtoumax(nptr, endptr, base) }
}

/// `__isoc23_strtol_l` — C23 locale alias for strtol (locale ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtol_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _locale: *mut c_void,
) -> c_long {
    unsafe { strtol(nptr, endptr, base) }
}

/// `__isoc23_strtoul_l` — C23 locale alias for strtoul (locale ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtoul_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _locale: *mut c_void,
) -> c_ulong {
    unsafe { strtoul(nptr, endptr, base) }
}

/// `__isoc23_strtoll_l` — C23 locale alias for strtoll (locale ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtoll_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _locale: *mut c_void,
) -> c_longlong {
    unsafe { strtoll(nptr, endptr, base) }
}

/// `__isoc23_strtoull_l` — C23 locale alias for strtoull (locale ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_strtoull_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _locale: *mut c_void,
) -> c_ulonglong {
    unsafe { strtoull(nptr, endptr, base) }
}

// ===========================================================================
// C23 __isoc23_* wcstol family (6 base + 4 locale)
// ===========================================================================

/// `__isoc23_wcstol` — C23 alias for wcstol.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstol(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
) -> c_long {
    unsafe { wcstol(nptr, endptr, base) }
}

/// `__isoc23_wcstoul` — C23 alias for wcstoul.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstoul(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
) -> c_ulong {
    unsafe { wcstoul(nptr, endptr, base) }
}

/// `__isoc23_wcstoll` — C23 alias for wcstoll.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstoll(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
) -> c_longlong {
    unsafe { wcstoll(nptr, endptr, base) }
}

/// `__isoc23_wcstoull` — C23 alias for wcstoull.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstoull(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
) -> c_ulonglong {
    unsafe { wcstoull(nptr, endptr, base) }
}

/// `__isoc23_wcstoimax` — C23 alias for wcstoimax.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstoimax(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
) -> i64 {
    unsafe { wcstoimax(nptr, endptr, base) }
}

/// `__isoc23_wcstoumax` — C23 alias for wcstoumax.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstoumax(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
) -> u64 {
    unsafe { wcstoumax(nptr, endptr, base) }
}

/// `__isoc23_wcstol_l` — C23 locale alias for wcstol (locale ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstol_l(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
    _locale: *mut c_void,
) -> c_long {
    unsafe { wcstol(nptr, endptr, base) }
}

/// `__isoc23_wcstoul_l` — C23 locale alias for wcstoul (locale ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstoul_l(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
    _locale: *mut c_void,
) -> c_ulong {
    unsafe { wcstoul(nptr, endptr, base) }
}

/// `__isoc23_wcstoll_l` — C23 locale alias for wcstoll (locale ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstoll_l(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
    _locale: *mut c_void,
) -> c_longlong {
    unsafe { wcstoll(nptr, endptr, base) }
}

/// `__isoc23_wcstoull_l` — C23 locale alias for wcstoull (locale ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc23_wcstoull_l(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
    _locale: *mut c_void,
) -> c_ulonglong {
    unsafe { wcstoull(nptr, endptr, base) }
}

// ===========================================================================
// C99 __isoc99_* wide scanf aliases (3 variadic + 3 va_list)
// ===========================================================================

/// `__isoc99_wscanf` — C99 alias for wscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_wscanf(format: *const WcharT, mut args: ...) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vwscanf(format, ap) }
}

/// `__isoc99_fwscanf` — C99 alias for fwscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_fwscanf(
    stream: *mut c_void,
    format: *const WcharT,
    mut args: ...
) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vfwscanf(stream, format, ap) }
}

/// `__isoc99_swscanf` — C99 alias for swscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_swscanf(
    s: *const WcharT,
    format: *const WcharT,
    mut args: ...
) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vswscanf(s, format, ap) }
}

/// `__isoc99_vwscanf` — C99 alias for vwscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_vwscanf(format: *const WcharT, ap: *mut c_void) -> c_int {
    unsafe { vwscanf(format, ap) }
}

/// `__isoc99_vfwscanf` — C99 alias for vfwscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_vfwscanf(
    stream: *mut c_void,
    format: *const WcharT,
    ap: *mut c_void,
) -> c_int {
    unsafe { vfwscanf(stream, format, ap) }
}

/// `__isoc99_vswscanf` — C99 alias for vswscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_vswscanf(
    s: *const WcharT,
    format: *const WcharT,
    ap: *mut c_void,
) -> c_int {
    unsafe { vswscanf(s, format, ap) }
}
