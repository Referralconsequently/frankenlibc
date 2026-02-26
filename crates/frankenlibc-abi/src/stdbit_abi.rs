//! C23 `<stdbit.h>` — type-generic bit manipulation utilities.
//!
//! 14 operations × 5 unsigned integer types = 70 functions.
//! All are pure Rust with zero dependencies.

use std::ffi::{c_uchar, c_uint, c_ulong, c_ulonglong, c_ushort};

// ── leading_zeros ──────────────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_leading_zeros_uc(value: c_uchar) -> c_uint {
    value.leading_zeros()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_leading_zeros_us(value: c_ushort) -> c_uint {
    value.leading_zeros()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_leading_zeros_ui(value: c_uint) -> c_uint {
    value.leading_zeros()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_leading_zeros_ul(value: c_ulong) -> c_uint {
    value.leading_zeros()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_leading_zeros_ull(value: c_ulonglong) -> c_uint {
    value.leading_zeros()
}

// ── leading_ones ───────────────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_leading_ones_uc(value: c_uchar) -> c_uint {
    value.leading_ones()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_leading_ones_us(value: c_ushort) -> c_uint {
    value.leading_ones()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_leading_ones_ui(value: c_uint) -> c_uint {
    value.leading_ones()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_leading_ones_ul(value: c_ulong) -> c_uint {
    value.leading_ones()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_leading_ones_ull(value: c_ulonglong) -> c_uint {
    value.leading_ones()
}

// ── trailing_zeros ─────────────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_trailing_zeros_uc(value: c_uchar) -> c_uint {
    if value == 0 {
        8
    } else {
        value.trailing_zeros()
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_trailing_zeros_us(value: c_ushort) -> c_uint {
    if value == 0 {
        16
    } else {
        value.trailing_zeros()
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_trailing_zeros_ui(value: c_uint) -> c_uint {
    if value == 0 {
        32
    } else {
        value.trailing_zeros()
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_trailing_zeros_ul(value: c_ulong) -> c_uint {
    if value == 0 {
        64
    } else {
        value.trailing_zeros()
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_trailing_zeros_ull(value: c_ulonglong) -> c_uint {
    if value == 0 {
        64
    } else {
        value.trailing_zeros()
    }
}

// ── trailing_ones ──────────────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_trailing_ones_uc(value: c_uchar) -> c_uint {
    value.trailing_ones()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_trailing_ones_us(value: c_ushort) -> c_uint {
    value.trailing_ones()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_trailing_ones_ui(value: c_uint) -> c_uint {
    value.trailing_ones()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_trailing_ones_ul(value: c_ulong) -> c_uint {
    value.trailing_ones()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_trailing_ones_ull(value: c_ulonglong) -> c_uint {
    value.trailing_ones()
}

// ── first_leading_zero (1-indexed from MSB, 0 if none) ────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_leading_zero_uc(value: c_uchar) -> c_uint {
    let v = value;
    let lo = v.leading_ones();
    if lo == 8 { 0 } else { lo + 1 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_leading_zero_us(value: c_ushort) -> c_uint {
    let v = value;
    let lo = v.leading_ones();
    if lo == 16 { 0 } else { lo + 1 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_leading_zero_ui(value: c_uint) -> c_uint {
    let v = value;
    let lo = v.leading_ones();
    if lo == 32 { 0 } else { lo + 1 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_leading_zero_ul(value: c_ulong) -> c_uint {
    let v = value;
    let lo = v.leading_ones();
    if lo == 64 { 0 } else { lo + 1 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_leading_zero_ull(value: c_ulonglong) -> c_uint {
    let v = value;
    let lo = v.leading_ones();
    if lo == 64 { 0 } else { lo + 1 }
}

// ── first_leading_one (1-indexed from MSB, 0 if none) ─────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_leading_one_uc(value: c_uchar) -> c_uint {
    let v = value;
    if v == 0 { 0 } else { v.leading_zeros() + 1 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_leading_one_us(value: c_ushort) -> c_uint {
    let v = value;
    if v == 0 { 0 } else { v.leading_zeros() + 1 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_leading_one_ui(value: c_uint) -> c_uint {
    let v = value;
    if v == 0 { 0 } else { v.leading_zeros() + 1 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_leading_one_ul(value: c_ulong) -> c_uint {
    let v = value;
    if v == 0 { 0 } else { v.leading_zeros() + 1 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_leading_one_ull(value: c_ulonglong) -> c_uint {
    let v = value;
    if v == 0 { 0 } else { v.leading_zeros() + 1 }
}

// ── first_trailing_zero (1-indexed from LSB, 0 if none) ───────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_trailing_zero_uc(value: c_uchar) -> c_uint {
    let v = value;
    let to = v.trailing_ones();
    if to == 8 { 0 } else { to + 1 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_trailing_zero_us(value: c_ushort) -> c_uint {
    let v = value;
    let to = v.trailing_ones();
    if to == 16 { 0 } else { to + 1 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_trailing_zero_ui(value: c_uint) -> c_uint {
    let v = value;
    let to = v.trailing_ones();
    if to == 32 { 0 } else { to + 1 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_trailing_zero_ul(value: c_ulong) -> c_uint {
    let v = value;
    let to = v.trailing_ones();
    if to == 64 { 0 } else { to + 1 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_trailing_zero_ull(value: c_ulonglong) -> c_uint {
    let v = value;
    let to = v.trailing_ones();
    if to == 64 { 0 } else { to + 1 }
}

// ── first_trailing_one (1-indexed from LSB, 0 if none) ────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_trailing_one_uc(value: c_uchar) -> c_uint {
    let v = value;
    if v == 0 { 0 } else { v.trailing_zeros() + 1 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_trailing_one_us(value: c_ushort) -> c_uint {
    let v = value;
    if v == 0 { 0 } else { v.trailing_zeros() + 1 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_trailing_one_ui(value: c_uint) -> c_uint {
    let v = value;
    if v == 0 { 0 } else { v.trailing_zeros() + 1 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_trailing_one_ul(value: c_ulong) -> c_uint {
    let v = value;
    if v == 0 { 0 } else { v.trailing_zeros() + 1 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_first_trailing_one_ull(value: c_ulonglong) -> c_uint {
    let v = value;
    if v == 0 { 0 } else { v.trailing_zeros() + 1 }
}

// ── count_ones (popcount) ──────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_count_ones_uc(value: c_uchar) -> c_uint {
    value.count_ones()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_count_ones_us(value: c_ushort) -> c_uint {
    value.count_ones()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_count_ones_ui(value: c_uint) -> c_uint {
    value.count_ones()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_count_ones_ul(value: c_ulong) -> c_uint {
    value.count_ones()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_count_ones_ull(value: c_ulonglong) -> c_uint {
    value.count_ones()
}

// ── count_zeros ────────────────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_count_zeros_uc(value: c_uchar) -> c_uint {
    value.count_zeros()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_count_zeros_us(value: c_ushort) -> c_uint {
    value.count_zeros()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_count_zeros_ui(value: c_uint) -> c_uint {
    value.count_zeros()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_count_zeros_ul(value: c_ulong) -> c_uint {
    value.count_zeros()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_count_zeros_ull(value: c_ulonglong) -> c_uint {
    value.count_zeros()
}

// ── has_single_bit (power-of-two check) ────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_has_single_bit_uc(value: c_uchar) -> bool {
    let v = value;
    v != 0 && v.is_power_of_two()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_has_single_bit_us(value: c_ushort) -> bool {
    let v = value;
    v != 0 && v.is_power_of_two()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_has_single_bit_ui(value: c_uint) -> bool {
    let v = value;
    v != 0 && v.is_power_of_two()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_has_single_bit_ul(value: c_ulong) -> bool {
    let v = value;
    v != 0 && v.is_power_of_two()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_has_single_bit_ull(value: c_ulonglong) -> bool {
    let v = value;
    v != 0 && v.is_power_of_two()
}

// ── bit_width (floor(log2(x))+1, or 0 for 0) ─────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_bit_width_uc(value: c_uchar) -> c_uint {
    let v = value;
    if v == 0 { 0 } else { 8 - v.leading_zeros() }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_bit_width_us(value: c_ushort) -> c_uint {
    let v = value;
    if v == 0 { 0 } else { 16 - v.leading_zeros() }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_bit_width_ui(value: c_uint) -> c_uint {
    let v = value;
    if v == 0 { 0 } else { 32 - v.leading_zeros() }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_bit_width_ul(value: c_ulong) -> c_uint {
    let v = value;
    if v == 0 { 0 } else { 64 - v.leading_zeros() }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_bit_width_ull(value: c_ulonglong) -> c_uint {
    let v = value;
    if v == 0 { 0 } else { 64 - v.leading_zeros() }
}

// ── bit_floor (largest power-of-2 ≤ value, 0 for 0) ──────────────────────

fn bit_floor_u8(v: u8) -> u8 {
    if v == 0 {
        0
    } else {
        1u8 << (7 - v.leading_zeros())
    }
}
fn bit_floor_u16(v: u16) -> u16 {
    if v == 0 {
        0
    } else {
        1u16 << (15 - v.leading_zeros())
    }
}
fn bit_floor_u32(v: u32) -> u32 {
    if v == 0 {
        0
    } else {
        1u32 << (31 - v.leading_zeros())
    }
}
fn bit_floor_u64(v: u64) -> u64 {
    if v == 0 {
        0
    } else {
        1u64 << (63 - v.leading_zeros())
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_bit_floor_uc(value: c_uchar) -> c_uchar {
    bit_floor_u8(value)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_bit_floor_us(value: c_ushort) -> c_ushort {
    bit_floor_u16(value)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_bit_floor_ui(value: c_uint) -> c_uint {
    bit_floor_u32(value)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_bit_floor_ul(value: c_ulong) -> c_ulong {
    bit_floor_u64(value)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_bit_floor_ull(value: c_ulonglong) -> c_ulonglong {
    bit_floor_u64(value)
}

// ── bit_ceil (smallest power-of-2 ≥ value, 1 for 0) ──────────────────────

fn bit_ceil_u8(v: u8) -> u8 {
    if v <= 1 {
        return 1;
    }
    1u8.checked_shl(8 - (v - 1).leading_zeros()).unwrap_or(0)
}
fn bit_ceil_u16(v: u16) -> u16 {
    if v <= 1 {
        return 1;
    }
    1u16.checked_shl(16 - (v - 1).leading_zeros()).unwrap_or(0)
}
fn bit_ceil_u32(v: u32) -> u32 {
    if v <= 1 {
        return 1;
    }
    1u32.checked_shl(32 - (v - 1).leading_zeros()).unwrap_or(0)
}
fn bit_ceil_u64(v: u64) -> u64 {
    if v <= 1 {
        return 1;
    }
    1u64.checked_shl(64 - (v - 1).leading_zeros()).unwrap_or(0)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_bit_ceil_uc(value: c_uchar) -> c_uchar {
    bit_ceil_u8(value)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_bit_ceil_us(value: c_ushort) -> c_ushort {
    bit_ceil_u16(value)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_bit_ceil_ui(value: c_uint) -> c_uint {
    bit_ceil_u32(value)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_bit_ceil_ul(value: c_ulong) -> c_ulong {
    bit_ceil_u64(value)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn stdc_bit_ceil_ull(value: c_ulonglong) -> c_ulonglong {
    bit_ceil_u64(value)
}
