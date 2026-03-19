//! Baseline performance capture for implemented symbol families (bd-3h1u.1).
//!
//! Captures p50/p95/p99 latencies for ctype, math, stdlib, and errno families.
//! Complements existing benches (string_bench, malloc_bench, stdio_bench,
//! mutex_bench, condvar_bench) to achieve coverage across all major families.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

// ═══════════════════════════════════════════════════════════════════
// CTYPE FAMILY BENCHMARKS
// ═══════════════════════════════════════════════════════════════════

fn bench_ctype_isalpha(c: &mut Criterion) {
    use frankenlibc_core::ctype::is_alpha;

    c.bench_function("ctype/isalpha/ascii_letter", |b| {
        b.iter(|| black_box(is_alpha(black_box(b'A'))))
    });

    c.bench_function("ctype/isalpha/digit", |b| {
        b.iter(|| black_box(is_alpha(black_box(b'5'))))
    });
}

fn bench_ctype_isdigit(c: &mut Criterion) {
    use frankenlibc_core::ctype::is_digit;

    c.bench_function("ctype/isdigit/digit", |b| {
        b.iter(|| black_box(is_digit(black_box(b'7'))))
    });

    c.bench_function("ctype/isdigit/letter", |b| {
        b.iter(|| black_box(is_digit(black_box(b'z'))))
    });
}

fn bench_ctype_toupper(c: &mut Criterion) {
    use frankenlibc_core::ctype::to_upper;

    c.bench_function("ctype/toupper/lowercase", |b| {
        b.iter(|| black_box(to_upper(black_box(b'a'))))
    });

    c.bench_function("ctype/toupper/already_upper", |b| {
        b.iter(|| black_box(to_upper(black_box(b'A'))))
    });
}

fn bench_ctype_isspace(c: &mut Criterion) {
    use frankenlibc_core::ctype::is_space;

    c.bench_function("ctype/isspace/space", |b| {
        b.iter(|| black_box(is_space(black_box(b' '))))
    });

    c.bench_function("ctype/isspace/non_space", |b| {
        b.iter(|| black_box(is_space(black_box(b'x'))))
    });
}

// ═══════════════════════════════════════════════════════════════════
// MATH FAMILY BENCHMARKS
// ═══════════════════════════════════════════════════════════════════

fn bench_math_trig(c: &mut Criterion) {
    use frankenlibc_core::math::{cos, sin, tan};

    c.bench_function("math/sin/small", |b| {
        b.iter(|| black_box(sin(black_box(0.5))))
    });

    c.bench_function("math/cos/small", |b| {
        b.iter(|| black_box(cos(black_box(0.5))))
    });

    c.bench_function("math/tan/small", |b| {
        b.iter(|| black_box(tan(black_box(0.5))))
    });
}

fn bench_math_exp_log(c: &mut Criterion) {
    use frankenlibc_core::math::{exp, log};

    c.bench_function("math/exp/small", |b| {
        b.iter(|| black_box(exp(black_box(1.5))))
    });

    c.bench_function("math/log/small", |b| {
        b.iter(|| black_box(log(black_box(2.5))))
    });
}

fn bench_math_sqrt(c: &mut Criterion) {
    use frankenlibc_core::math::sqrt;

    c.bench_function("math/sqrt/integer", |b| {
        b.iter(|| black_box(sqrt(black_box(144.0))))
    });

    c.bench_function("math/sqrt/large", |b| {
        b.iter(|| black_box(sqrt(black_box(1e12))))
    });
}

fn bench_math_pow(c: &mut Criterion) {
    use frankenlibc_core::math::pow;

    c.bench_function("math/pow/integer_exp", |b| {
        b.iter(|| black_box(pow(black_box(2.0), black_box(10.0))))
    });

    c.bench_function("math/pow/fractional_exp", |b| {
        b.iter(|| black_box(pow(black_box(2.0), black_box(0.5))))
    });
}

// ═══════════════════════════════════════════════════════════════════
// STDLIB FAMILY BENCHMARKS
// ═══════════════════════════════════════════════════════════════════

fn bench_stdlib_atoi(c: &mut Criterion) {
    use frankenlibc_core::stdlib::atoi;

    c.bench_function("stdlib/atoi/small", |b| {
        b.iter(|| black_box(atoi(black_box(b"42\0"))))
    });

    c.bench_function("stdlib/atoi/large", |b| {
        b.iter(|| black_box(atoi(black_box(b"2147483647\0"))))
    });

    c.bench_function("stdlib/atoi/negative", |b| {
        b.iter(|| black_box(atoi(black_box(b"-999\0"))))
    });
}

fn bench_stdlib_abs(c: &mut Criterion) {
    use frankenlibc_core::stdlib::abs;

    c.bench_function("stdlib/abs/positive", |b| {
        b.iter(|| black_box(abs(black_box(42))))
    });

    c.bench_function("stdlib/abs/negative", |b| {
        b.iter(|| black_box(abs(black_box(-42))))
    });
}

// ═══════════════════════════════════════════════════════════════════
// ERRNO FAMILY BENCHMARKS
// ═══════════════════════════════════════════════════════════════════

fn bench_errno_location(c: &mut Criterion) {
    use frankenlibc_core::errno::{get_errno, set_errno};

    set_errno(0);

    c.bench_function("errno/__errno_location", |b| {
        b.iter(|| black_box(get_errno()))
    });
}

// ═══════════════════════════════════════════════════════════════════
// STRING FAMILY — additional sizes not in string_bench.rs
// ═══════════════════════════════════════════════════════════════════

fn bench_strlen_varied(c: &mut Criterion) {
    use frankenlibc_core::string::strlen;

    for len in [1, 8, 32, 128, 512] {
        let mut s = vec![b'x'; len];
        s.push(0);
        let label = format!("string/strlen/{len}");
        c.bench_function(&label, |b| {
            b.iter(|| black_box(strlen(black_box(s.as_slice()))))
        });
    }
}

fn bench_strcmp_varied(c: &mut Criterion) {
    use frankenlibc_core::string::strcmp;

    for len in [4, 32, 256] {
        let mut a = vec![b'a'; len];
        a.push(0);
        let b_equal = a.clone();
        let label_eq = format!("string/strcmp/equal_{len}");
        c.bench_function(&label_eq, |bench| {
            bench.iter(|| {
                black_box(strcmp(
                    black_box(a.as_slice()),
                    black_box(b_equal.as_slice()),
                ))
            })
        });

        // Differ at last byte
        let mut b_diff = a.clone();
        b_diff[len - 1] = b'b';
        let label_diff = format!("string/strcmp/differ_last_{len}");
        c.bench_function(&label_diff, |bench| {
            bench.iter(|| {
                black_box(strcmp(
                    black_box(a.as_slice()),
                    black_box(b_diff.as_slice()),
                ))
            })
        });
    }
}

criterion_group!(
    ctype_benches,
    bench_ctype_isalpha,
    bench_ctype_isdigit,
    bench_ctype_toupper,
    bench_ctype_isspace,
);

criterion_group!(
    math_benches,
    bench_math_trig,
    bench_math_exp_log,
    bench_math_sqrt,
    bench_math_pow,
);

criterion_group!(stdlib_benches, bench_stdlib_atoi, bench_stdlib_abs,);

criterion_group!(errno_benches, bench_errno_location,);

criterion_group!(
    string_extended_benches,
    bench_strlen_varied,
    bench_strcmp_varied,
);

criterion_main!(
    ctype_benches,
    math_benches,
    stdlib_benches,
    errno_benches,
    string_extended_benches,
);
