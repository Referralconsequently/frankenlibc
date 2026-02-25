#![cfg(target_os = "linux")]

//! Integration tests for `strptime` native implementation.

use frankenlibc_abi::time_abi::strptime;

#[test]
fn strptime_iso_date() {
    let input = b"2026-02-25\0";
    let fmt = b"%Y-%m-%d\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe {
        strptime(
            input.as_ptr() as *const std::ffi::c_char,
            fmt.as_ptr() as *const std::ffi::c_char,
            &mut tm,
        )
    };
    assert!(!result.is_null());
    assert_eq!(tm.tm_year, 126); // 2026 - 1900
    assert_eq!(tm.tm_mon, 1); // February (0-indexed)
    assert_eq!(tm.tm_mday, 25);
}

#[test]
fn strptime_time_24h() {
    let input = b"14:30:45\0";
    let fmt = b"%H:%M:%S\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe {
        strptime(
            input.as_ptr() as *const std::ffi::c_char,
            fmt.as_ptr() as *const std::ffi::c_char,
            &mut tm,
        )
    };
    assert!(!result.is_null());
    assert_eq!(tm.tm_hour, 14);
    assert_eq!(tm.tm_min, 30);
    assert_eq!(tm.tm_sec, 45);
}

#[test]
fn strptime_month_name() {
    let input = b"Jan 15\0";
    let fmt = b"%b %d\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe {
        strptime(
            input.as_ptr() as *const std::ffi::c_char,
            fmt.as_ptr() as *const std::ffi::c_char,
            &mut tm,
        )
    };
    assert!(!result.is_null());
    assert_eq!(tm.tm_mon, 0); // January
    assert_eq!(tm.tm_mday, 15);
}

#[test]
fn strptime_composite_t() {
    let input = b"09:15:30\0";
    let fmt = b"%T\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe {
        strptime(
            input.as_ptr() as *const std::ffi::c_char,
            fmt.as_ptr() as *const std::ffi::c_char,
            &mut tm,
        )
    };
    assert!(!result.is_null());
    assert_eq!(tm.tm_hour, 9);
    assert_eq!(tm.tm_min, 15);
    assert_eq!(tm.tm_sec, 30);
}

#[test]
fn strptime_am_pm() {
    let input = b"03:30 PM\0";
    let fmt = b"%I:%M %p\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe {
        strptime(
            input.as_ptr() as *const std::ffi::c_char,
            fmt.as_ptr() as *const std::ffi::c_char,
            &mut tm,
        )
    };
    assert!(!result.is_null());
    assert_eq!(tm.tm_hour, 15); // 3 PM = 15
    assert_eq!(tm.tm_min, 30);
}

#[test]
fn strptime_returns_null_on_mismatch() {
    let input = b"not-a-date\0";
    let fmt = b"%Y-%m-%d\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe {
        strptime(
            input.as_ptr() as *const std::ffi::c_char,
            fmt.as_ptr() as *const std::ffi::c_char,
            &mut tm,
        )
    };
    assert!(result.is_null());
}

#[test]
fn strptime_returns_position_after_parsed() {
    let input = b"2026-01-01 remaining\0";
    let fmt = b"%Y-%m-%d\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe {
        strptime(
            input.as_ptr() as *const std::ffi::c_char,
            fmt.as_ptr() as *const std::ffi::c_char,
            &mut tm,
        )
    };
    assert!(!result.is_null());
    // result should point to " remaining"
    let offset = unsafe { result.offset_from(input.as_ptr() as *const std::ffi::c_char) } as usize;
    assert_eq!(offset, 10); // "2026-01-01" = 10 chars
}

#[test]
fn strptime_weekday_name() {
    let input = b"Monday\0";
    let fmt = b"%A\0";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe {
        strptime(
            input.as_ptr() as *const std::ffi::c_char,
            fmt.as_ptr() as *const std::ffi::c_char,
            &mut tm,
        )
    };
    assert!(!result.is_null());
    assert_eq!(tm.tm_wday, 1); // Monday
}
