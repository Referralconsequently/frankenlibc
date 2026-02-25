//! Special mathematical functions.

#[inline]
pub fn erf(x: f64) -> f64 {
    libm::erf(x)
}

#[inline]
pub fn tgamma(x: f64) -> f64 {
    libm::tgamma(x)
}

#[inline]
pub fn lgamma(x: f64) -> f64 {
    libm::lgamma(x)
}

/// Complementary error function: 1 - erf(x).
#[inline]
pub fn erfc(x: f64) -> f64 {
    libm::erfc(x)
}

/// Reentrant lgamma: returns `(lgamma(x), signgam)` where `signgam` is +1 or -1.
#[inline]
pub fn lgamma_r(x: f64) -> (f64, i32) {
    libm::lgamma_r(x)
}

// ---------------------------------------------------------------------------
// Bessel functions
// ---------------------------------------------------------------------------

/// Bessel function of the first kind, order 0.
#[inline]
pub fn j0(x: f64) -> f64 {
    libm::j0(x)
}

/// Bessel function of the first kind, order 1.
#[inline]
pub fn j1(x: f64) -> f64 {
    libm::j1(x)
}

/// Bessel function of the first kind, order `n`.
#[inline]
pub fn jn(n: i32, x: f64) -> f64 {
    libm::jn(n, x)
}

/// Bessel function of the second kind, order 0.
#[inline]
pub fn y0(x: f64) -> f64 {
    libm::y0(x)
}

/// Bessel function of the second kind, order 1.
#[inline]
pub fn y1(x: f64) -> f64 {
    libm::y1(x)
}

/// Bessel function of the second kind, order `n`.
#[inline]
pub fn yn(n: i32, x: f64) -> f64 {
    libm::yn(n, x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erf_sanity() {
        assert!(erf(0.0).abs() < 1e-12);
        assert!((erf(1.0) - 0.8427).abs() < 5e-4);
    }

    #[test]
    fn gamma_sanity() {
        assert!((tgamma(5.0) - 24.0).abs() < 1e-8);
        assert!((lgamma(5.0) - 24.0_f64.ln()).abs() < 1e-8);
    }

    #[test]
    fn erfc_sanity() {
        // erfc(x) = 1 - erf(x)
        assert!((erfc(0.0) - 1.0).abs() < 1e-12);
        assert!((erfc(1.0) - (1.0 - erf(1.0))).abs() < 1e-12);
    }

    #[test]
    fn lgamma_r_sanity() {
        // lgamma_r(5) = ln(24) with positive sign
        let (val, sign) = lgamma_r(5.0);
        assert!((val - 24.0_f64.ln()).abs() < 1e-8);
        assert_eq!(sign, 1);
        // lgamma_r(-0.5) has negative Gamma, so sign = -1
        let (_, sign2) = lgamma_r(-0.5);
        assert_eq!(sign2, -1);
    }

    #[test]
    fn bessel_j_sanity() {
        // J0(0) = 1
        assert!((j0(0.0) - 1.0).abs() < 1e-12);
        // J1(0) = 0
        assert!(j1(0.0).abs() < 1e-12);
        // Jn(0, x) == J0(x)
        assert!((jn(0, 2.5) - j0(2.5)).abs() < 1e-12);
        // Jn(1, x) == J1(x)
        assert!((jn(1, 2.5) - j1(2.5)).abs() < 1e-12);
    }

    #[test]
    fn bessel_y_sanity() {
        // Y0 and Y1 at x=1 are well-known values
        // Y0(1) ≈ 0.08825696
        assert!((y0(1.0) - 0.08825696).abs() < 1e-5);
        // Y1(1) ≈ -0.78121282
        assert!((y1(1.0) - (-0.78121282)).abs() < 1e-5);
        // Yn(0, x) == Y0(x)
        assert!((yn(0, 1.0) - y0(1.0)).abs() < 1e-12);
        // Y0(0) = -inf (pole)
        assert!(y0(0.0).is_infinite() && y0(0.0).is_sign_negative());
    }
}
