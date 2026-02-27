#![cfg(target_os = "linux")]

//! Integration tests for C23 `<stdbit.h>` ABI entrypoints.
//!
//! 14 operations × 5 unsigned types = 70 functions, all pure computation.

use frankenlibc_abi::stdbit_abi::*;

// ===========================================================================
// leading_zeros
// ===========================================================================

#[test]
fn leading_zeros_zero() {
    assert_eq!(stdc_leading_zeros_uc(0), 8);
    assert_eq!(stdc_leading_zeros_us(0), 16);
    assert_eq!(stdc_leading_zeros_ui(0), 32);
    assert_eq!(stdc_leading_zeros_ul(0), 64);
    assert_eq!(stdc_leading_zeros_ull(0), 64);
}

#[test]
fn leading_zeros_one() {
    assert_eq!(stdc_leading_zeros_uc(1), 7);
    assert_eq!(stdc_leading_zeros_us(1), 15);
    assert_eq!(stdc_leading_zeros_ui(1), 31);
    assert_eq!(stdc_leading_zeros_ul(1), 63);
    assert_eq!(stdc_leading_zeros_ull(1), 63);
}

#[test]
fn leading_zeros_max() {
    assert_eq!(stdc_leading_zeros_uc(u8::MAX), 0);
    assert_eq!(stdc_leading_zeros_us(u16::MAX), 0);
    assert_eq!(stdc_leading_zeros_ui(u32::MAX), 0);
    assert_eq!(stdc_leading_zeros_ul(u64::MAX), 0);
    assert_eq!(stdc_leading_zeros_ull(u64::MAX), 0);
}

#[test]
fn leading_zeros_high_bit() {
    assert_eq!(stdc_leading_zeros_uc(0x80), 0);
    assert_eq!(stdc_leading_zeros_us(0x8000), 0);
    assert_eq!(stdc_leading_zeros_ui(0x80000000), 0);
    assert_eq!(stdc_leading_zeros_ul(0x8000000000000000), 0);
}

// ===========================================================================
// leading_ones
// ===========================================================================

#[test]
fn leading_ones_zero() {
    assert_eq!(stdc_leading_ones_uc(0), 0);
    assert_eq!(stdc_leading_ones_us(0), 0);
    assert_eq!(stdc_leading_ones_ui(0), 0);
    assert_eq!(stdc_leading_ones_ul(0), 0);
    assert_eq!(stdc_leading_ones_ull(0), 0);
}

#[test]
fn leading_ones_max() {
    assert_eq!(stdc_leading_ones_uc(u8::MAX), 8);
    assert_eq!(stdc_leading_ones_us(u16::MAX), 16);
    assert_eq!(stdc_leading_ones_ui(u32::MAX), 32);
    assert_eq!(stdc_leading_ones_ul(u64::MAX), 64);
    assert_eq!(stdc_leading_ones_ull(u64::MAX), 64);
}

#[test]
fn leading_ones_pattern() {
    assert_eq!(stdc_leading_ones_uc(0b11100000), 3);
    assert_eq!(stdc_leading_ones_us(0xFF00), 8);
    assert_eq!(stdc_leading_ones_ui(0xFFF00000), 12);
}

// ===========================================================================
// trailing_zeros
// ===========================================================================

#[test]
fn trailing_zeros_zero() {
    assert_eq!(stdc_trailing_zeros_uc(0), 8);
    assert_eq!(stdc_trailing_zeros_us(0), 16);
    assert_eq!(stdc_trailing_zeros_ui(0), 32);
    assert_eq!(stdc_trailing_zeros_ul(0), 64);
    assert_eq!(stdc_trailing_zeros_ull(0), 64);
}

#[test]
fn trailing_zeros_one() {
    assert_eq!(stdc_trailing_zeros_uc(1), 0);
    assert_eq!(stdc_trailing_zeros_us(1), 0);
    assert_eq!(stdc_trailing_zeros_ui(1), 0);
    assert_eq!(stdc_trailing_zeros_ul(1), 0);
    assert_eq!(stdc_trailing_zeros_ull(1), 0);
}

#[test]
fn trailing_zeros_power_of_two() {
    assert_eq!(stdc_trailing_zeros_uc(0x10), 4);
    assert_eq!(stdc_trailing_zeros_us(0x100), 8);
    assert_eq!(stdc_trailing_zeros_ui(0x10000), 16);
    assert_eq!(stdc_trailing_zeros_ul(0x100000000), 32);
}

// ===========================================================================
// trailing_ones
// ===========================================================================

#[test]
fn trailing_ones_zero() {
    assert_eq!(stdc_trailing_ones_uc(0), 0);
    assert_eq!(stdc_trailing_ones_us(0), 0);
    assert_eq!(stdc_trailing_ones_ui(0), 0);
    assert_eq!(stdc_trailing_ones_ul(0), 0);
    assert_eq!(stdc_trailing_ones_ull(0), 0);
}

#[test]
fn trailing_ones_max() {
    assert_eq!(stdc_trailing_ones_uc(u8::MAX), 8);
    assert_eq!(stdc_trailing_ones_us(u16::MAX), 16);
    assert_eq!(stdc_trailing_ones_ui(u32::MAX), 32);
    assert_eq!(stdc_trailing_ones_ul(u64::MAX), 64);
    assert_eq!(stdc_trailing_ones_ull(u64::MAX), 64);
}

#[test]
fn trailing_ones_pattern() {
    assert_eq!(stdc_trailing_ones_uc(0x0F), 4);
    assert_eq!(stdc_trailing_ones_us(0x00FF), 8);
    assert_eq!(stdc_trailing_ones_ui(0x0000FFFF), 16);
}

// ===========================================================================
// first_leading_zero (1-indexed from MSB, 0 if none)
// ===========================================================================

#[test]
fn first_leading_zero_all_ones() {
    assert_eq!(stdc_first_leading_zero_uc(u8::MAX), 0);
    assert_eq!(stdc_first_leading_zero_us(u16::MAX), 0);
    assert_eq!(stdc_first_leading_zero_ui(u32::MAX), 0);
    assert_eq!(stdc_first_leading_zero_ul(u64::MAX), 0);
    assert_eq!(stdc_first_leading_zero_ull(u64::MAX), 0);
}

#[test]
fn first_leading_zero_zero() {
    assert_eq!(stdc_first_leading_zero_uc(0), 1);
    assert_eq!(stdc_first_leading_zero_us(0), 1);
    assert_eq!(stdc_first_leading_zero_ui(0), 1);
    assert_eq!(stdc_first_leading_zero_ul(0), 1);
    assert_eq!(stdc_first_leading_zero_ull(0), 1);
}

#[test]
fn first_leading_zero_pattern() {
    // 0b11100000 for u8: 3 leading ones, first zero at position 4
    assert_eq!(stdc_first_leading_zero_uc(0b11100000), 4);
    assert_eq!(stdc_first_leading_zero_us(0xFF00), 9);
}

// ===========================================================================
// first_leading_one (1-indexed from MSB, 0 if none)
// ===========================================================================

#[test]
fn first_leading_one_zero() {
    assert_eq!(stdc_first_leading_one_uc(0), 0);
    assert_eq!(stdc_first_leading_one_us(0), 0);
    assert_eq!(stdc_first_leading_one_ui(0), 0);
    assert_eq!(stdc_first_leading_one_ul(0), 0);
    assert_eq!(stdc_first_leading_one_ull(0), 0);
}

#[test]
fn first_leading_one_one() {
    assert_eq!(stdc_first_leading_one_uc(1), 8);
    assert_eq!(stdc_first_leading_one_us(1), 16);
    assert_eq!(stdc_first_leading_one_ui(1), 32);
    assert_eq!(stdc_first_leading_one_ul(1), 64);
    assert_eq!(stdc_first_leading_one_ull(1), 64);
}

#[test]
fn first_leading_one_high_bit() {
    assert_eq!(stdc_first_leading_one_uc(0x80), 1);
    assert_eq!(stdc_first_leading_one_us(0x8000), 1);
    assert_eq!(stdc_first_leading_one_ui(0x80000000), 1);
    assert_eq!(stdc_first_leading_one_ul(0x8000000000000000), 1);
}

// ===========================================================================
// first_trailing_zero (1-indexed from LSB, 0 if none)
// ===========================================================================

#[test]
fn first_trailing_zero_all_ones() {
    assert_eq!(stdc_first_trailing_zero_uc(u8::MAX), 0);
    assert_eq!(stdc_first_trailing_zero_us(u16::MAX), 0);
    assert_eq!(stdc_first_trailing_zero_ui(u32::MAX), 0);
    assert_eq!(stdc_first_trailing_zero_ul(u64::MAX), 0);
    assert_eq!(stdc_first_trailing_zero_ull(u64::MAX), 0);
}

#[test]
fn first_trailing_zero_zero() {
    assert_eq!(stdc_first_trailing_zero_uc(0), 1);
    assert_eq!(stdc_first_trailing_zero_us(0), 1);
    assert_eq!(stdc_first_trailing_zero_ui(0), 1);
    assert_eq!(stdc_first_trailing_zero_ul(0), 1);
    assert_eq!(stdc_first_trailing_zero_ull(0), 1);
}

#[test]
fn first_trailing_zero_pattern() {
    // 0x0F = 0b00001111: 4 trailing ones, first zero at position 5
    assert_eq!(stdc_first_trailing_zero_uc(0x0F), 5);
    assert_eq!(stdc_first_trailing_zero_us(0x00FF), 9);
}

// ===========================================================================
// first_trailing_one (1-indexed from LSB, 0 if none)
// ===========================================================================

#[test]
fn first_trailing_one_zero() {
    assert_eq!(stdc_first_trailing_one_uc(0), 0);
    assert_eq!(stdc_first_trailing_one_us(0), 0);
    assert_eq!(stdc_first_trailing_one_ui(0), 0);
    assert_eq!(stdc_first_trailing_one_ul(0), 0);
    assert_eq!(stdc_first_trailing_one_ull(0), 0);
}

#[test]
fn first_trailing_one_one() {
    assert_eq!(stdc_first_trailing_one_uc(1), 1);
    assert_eq!(stdc_first_trailing_one_us(1), 1);
    assert_eq!(stdc_first_trailing_one_ui(1), 1);
    assert_eq!(stdc_first_trailing_one_ul(1), 1);
    assert_eq!(stdc_first_trailing_one_ull(1), 1);
}

#[test]
fn first_trailing_one_even() {
    // 0x10 = 0b00010000: trailing zeros = 4, first trailing one at 5
    assert_eq!(stdc_first_trailing_one_uc(0x10), 5);
    assert_eq!(stdc_first_trailing_one_us(0x100), 9);
    assert_eq!(stdc_first_trailing_one_ui(0x10000), 17);
}

// ===========================================================================
// count_ones (popcount)
// ===========================================================================

#[test]
fn count_ones_zero() {
    assert_eq!(stdc_count_ones_uc(0), 0);
    assert_eq!(stdc_count_ones_us(0), 0);
    assert_eq!(stdc_count_ones_ui(0), 0);
    assert_eq!(stdc_count_ones_ul(0), 0);
    assert_eq!(stdc_count_ones_ull(0), 0);
}

#[test]
fn count_ones_max() {
    assert_eq!(stdc_count_ones_uc(u8::MAX), 8);
    assert_eq!(stdc_count_ones_us(u16::MAX), 16);
    assert_eq!(stdc_count_ones_ui(u32::MAX), 32);
    assert_eq!(stdc_count_ones_ul(u64::MAX), 64);
    assert_eq!(stdc_count_ones_ull(u64::MAX), 64);
}

#[test]
fn count_ones_alternating() {
    assert_eq!(stdc_count_ones_uc(0xAA), 4); // 10101010
    assert_eq!(stdc_count_ones_us(0xAAAA), 8);
    assert_eq!(stdc_count_ones_ui(0xAAAAAAAA), 16);
}

// ===========================================================================
// count_zeros
// ===========================================================================

#[test]
fn count_zeros_zero() {
    assert_eq!(stdc_count_zeros_uc(0), 8);
    assert_eq!(stdc_count_zeros_us(0), 16);
    assert_eq!(stdc_count_zeros_ui(0), 32);
    assert_eq!(stdc_count_zeros_ul(0), 64);
    assert_eq!(stdc_count_zeros_ull(0), 64);
}

#[test]
fn count_zeros_max() {
    assert_eq!(stdc_count_zeros_uc(u8::MAX), 0);
    assert_eq!(stdc_count_zeros_us(u16::MAX), 0);
    assert_eq!(stdc_count_zeros_ui(u32::MAX), 0);
    assert_eq!(stdc_count_zeros_ul(u64::MAX), 0);
    assert_eq!(stdc_count_zeros_ull(u64::MAX), 0);
}

#[test]
fn count_zeros_alternating() {
    assert_eq!(stdc_count_zeros_uc(0x55), 4); // 01010101
    assert_eq!(stdc_count_zeros_us(0x5555), 8);
}

// ===========================================================================
// has_single_bit (power-of-two check)
// ===========================================================================

#[test]
fn has_single_bit_zero() {
    assert!(!stdc_has_single_bit_uc(0));
    assert!(!stdc_has_single_bit_us(0));
    assert!(!stdc_has_single_bit_ui(0));
    assert!(!stdc_has_single_bit_ul(0));
    assert!(!stdc_has_single_bit_ull(0));
}

#[test]
fn has_single_bit_powers_of_two() {
    assert!(stdc_has_single_bit_uc(1));
    assert!(stdc_has_single_bit_uc(2));
    assert!(stdc_has_single_bit_uc(4));
    assert!(stdc_has_single_bit_uc(128));
    assert!(stdc_has_single_bit_us(256));
    assert!(stdc_has_single_bit_ui(1 << 20));
    assert!(stdc_has_single_bit_ul(1 << 40));
    assert!(stdc_has_single_bit_ull(1 << 60));
}

#[test]
fn has_single_bit_non_powers() {
    assert!(!stdc_has_single_bit_uc(3));
    assert!(!stdc_has_single_bit_uc(6));
    assert!(!stdc_has_single_bit_us(0xFFFF));
    assert!(!stdc_has_single_bit_ui(0xFFFFFFFF));
}

// ===========================================================================
// bit_width (floor(log2(x))+1, or 0 for 0)
// ===========================================================================

#[test]
fn bit_width_zero() {
    assert_eq!(stdc_bit_width_uc(0), 0);
    assert_eq!(stdc_bit_width_us(0), 0);
    assert_eq!(stdc_bit_width_ui(0), 0);
    assert_eq!(stdc_bit_width_ul(0), 0);
    assert_eq!(stdc_bit_width_ull(0), 0);
}

#[test]
fn bit_width_one() {
    assert_eq!(stdc_bit_width_uc(1), 1);
    assert_eq!(stdc_bit_width_us(1), 1);
    assert_eq!(stdc_bit_width_ui(1), 1);
    assert_eq!(stdc_bit_width_ul(1), 1);
    assert_eq!(stdc_bit_width_ull(1), 1);
}

#[test]
fn bit_width_values() {
    assert_eq!(stdc_bit_width_uc(0xFF), 8);
    assert_eq!(stdc_bit_width_uc(0x80), 8);
    assert_eq!(stdc_bit_width_uc(0x7F), 7);
    assert_eq!(stdc_bit_width_us(0xFFFF), 16);
    assert_eq!(stdc_bit_width_ui(0xFFFFFFFF), 32);
    assert_eq!(stdc_bit_width_ul(u64::MAX), 64);
}

// ===========================================================================
// bit_floor (largest power-of-2 <= value, 0 for 0)
// ===========================================================================

#[test]
fn bit_floor_zero() {
    assert_eq!(stdc_bit_floor_uc(0), 0);
    assert_eq!(stdc_bit_floor_us(0), 0);
    assert_eq!(stdc_bit_floor_ui(0), 0);
    assert_eq!(stdc_bit_floor_ul(0), 0);
    assert_eq!(stdc_bit_floor_ull(0), 0);
}

#[test]
fn bit_floor_powers() {
    assert_eq!(stdc_bit_floor_uc(1), 1);
    assert_eq!(stdc_bit_floor_uc(4), 4);
    assert_eq!(stdc_bit_floor_uc(128), 128);
    assert_eq!(stdc_bit_floor_us(256), 256);
    assert_eq!(stdc_bit_floor_ui(1024), 1024);
}

#[test]
fn bit_floor_non_powers() {
    assert_eq!(stdc_bit_floor_uc(3), 2);
    assert_eq!(stdc_bit_floor_uc(5), 4);
    assert_eq!(stdc_bit_floor_uc(0xFF), 128);
    assert_eq!(stdc_bit_floor_us(0xFFFF), 0x8000);
    assert_eq!(stdc_bit_floor_ui(0xFFFFFFFF), 0x80000000);
    assert_eq!(stdc_bit_floor_ul(u64::MAX), 0x8000000000000000);
}

// ===========================================================================
// bit_ceil (smallest power-of-2 >= value, 1 for 0)
// ===========================================================================

#[test]
fn bit_ceil_zero_and_one() {
    assert_eq!(stdc_bit_ceil_uc(0), 1);
    assert_eq!(stdc_bit_ceil_uc(1), 1);
    assert_eq!(stdc_bit_ceil_us(0), 1);
    assert_eq!(stdc_bit_ceil_us(1), 1);
    assert_eq!(stdc_bit_ceil_ui(0), 1);
    assert_eq!(stdc_bit_ceil_ui(1), 1);
    assert_eq!(stdc_bit_ceil_ul(0), 1);
    assert_eq!(stdc_bit_ceil_ul(1), 1);
    assert_eq!(stdc_bit_ceil_ull(0), 1);
    assert_eq!(stdc_bit_ceil_ull(1), 1);
}

#[test]
fn bit_ceil_powers() {
    assert_eq!(stdc_bit_ceil_uc(2), 2);
    assert_eq!(stdc_bit_ceil_uc(4), 4);
    assert_eq!(stdc_bit_ceil_uc(64), 64);
    assert_eq!(stdc_bit_ceil_us(256), 256);
    assert_eq!(stdc_bit_ceil_ui(1024), 1024);
    assert_eq!(stdc_bit_ceil_ul(1 << 32), 1 << 32);
}

#[test]
fn bit_ceil_non_powers() {
    assert_eq!(stdc_bit_ceil_uc(3), 4);
    assert_eq!(stdc_bit_ceil_uc(5), 8);
    assert_eq!(stdc_bit_ceil_uc(65), 128);
    assert_eq!(stdc_bit_ceil_us(257), 512);
    assert_eq!(stdc_bit_ceil_ui(1025), 2048);
}

#[test]
fn bit_ceil_overflow_returns_zero() {
    // C23: if the result is not representable, behavior is implementation-defined.
    // Our implementation returns 0 on overflow.
    assert_eq!(stdc_bit_ceil_uc(129), 0); // 256 doesn't fit in u8
    assert_eq!(stdc_bit_ceil_us(0x8001), 0); // 0x10000 doesn't fit in u16
}

// ===========================================================================
// Cross-type consistency checks
// ===========================================================================

#[test]
fn count_ones_plus_zeros_equals_width() {
    for val in [0u8, 1, 42, 127, 255] {
        let ones = stdc_count_ones_uc(val);
        let zeros = stdc_count_zeros_uc(val);
        assert_eq!(ones + zeros, 8, "val={val}");
    }

    for val in [0u32, 1, 42, 0xDEADBEEF, u32::MAX] {
        let ones = stdc_count_ones_ui(val);
        let zeros = stdc_count_zeros_ui(val);
        assert_eq!(ones + zeros, 32, "val={val}");
    }
}

#[test]
fn leading_ones_plus_leading_zeros_consistency() {
    // For any value, leading_ones(v) == leading_zeros(!v) (same bit width)
    for val in [0u8, 1, 42, 127, 255] {
        assert_eq!(
            stdc_leading_ones_uc(val),
            stdc_leading_zeros_uc(!val),
            "val={val}"
        );
    }
}

#[test]
fn bit_floor_le_value_and_bit_ceil_ge_value() {
    for val in [1u32, 2, 3, 5, 15, 16, 17, 255, 256, 1000] {
        let floor = stdc_bit_floor_ui(val);
        let ceil = stdc_bit_ceil_ui(val);
        assert!(floor <= val, "bit_floor({val}) = {floor}");
        assert!(ceil >= val, "bit_ceil({val}) = {ceil}");
        assert!(stdc_has_single_bit_ui(floor), "floor {floor} is power of 2");
        assert!(stdc_has_single_bit_ui(ceil), "ceil {ceil} is power of 2");
    }
}
