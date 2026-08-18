//! The Miller loop, on its own.
//!
//! A multi-pairing is `FinalExp(∏ᵢ MillerLoop(Pᵢ,Qᵢ))`. The Miller loops are
//! independent of each other and cost 39,299,490 each; the final exponentiation
//! is one shared 169,455,773. Splitting them is what lets a streaming proof do
//! its share of the signature work as attestations arrive and hand a partial
//! product to whichever proof closes the epoch.
//!
//! zisklib computes both halves but only exports them fused, as
//! `pairing_batch_bls12_381` and `pairing_check_safe_bls12_381`:
//! `bls12_381/mod.rs` re-exports `pairing::*` and `final_exp::*` but not
//! `miller_loop::*`. The loop below is therefore zisklib's
//! `miller_loop_batch_bls12_381` transcribed against the parts it does export —
//! same algorithm, same hinted line coefficients, so the same measured cost.
//! Everything it stands on (`fp`, `fp2`, `fp12`, the two `fcall` hints) is
//! public API; only the two curve constants had to be copied.
//!
//! `miller_batch_matches_zisklib` pins the transcription to the original: it
//! runs the final exponentiation over this loop's output and requires the result
//! to equal `pairing_batch_bls12_381` over the same points. If a Zisk bump
//! changes the loop, that test fails rather than the proof silently disagreeing
//! with `pairing_check_safe_bls12_381`.

use alloc::vec::Vec;

use ziskos::zisklib::{
    add_fp2_bls12_381, conjugate_fp12_bls12_381, dbl_fp2_bls12_381, eq,
    fcall_bls12_381_twist_add_line_coeffs, fcall_bls12_381_twist_dbl_line_coeffs, inv_fp_bls12_381,
    is_zero, mul_fp2_bls12_381, mul_fp_bls12_381, neg_fp2_bls12_381, neg_fp_bls12_381,
    scalar_mul_fp2_bls12_381, sparse_mul_fp12_bls12_381, square_fp12_bls12_381,
    square_fp2_bls12_381, sub_fp2_bls12_381,
};

/// Bits of |x| for BLS12-381, most significant first. `x = -0xd201000000010000`.
const X_ABS_BIN_BE: [u8; 64] = [
    1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// `1/(1+u)` in Fp2, in Montgomery-free little-endian limbs.
const EXT_U_INV: [u64; 12] = [
    0xDCFF_7FFF_FFFF_D556,
    0x0F55_FFFF_58A9_FFFF,
    0xB398_6950_7B58_7B12,
    0xB23B_A5C2_79C2_895F,
    0x258D_D3DB_21A5_D66B,
    0x0D00_88F5_1CBF_F34D,
    0xDCFF_7FFF_FFFF_D555,
    0x0F55_FFFF_58A9_FFFF,
    0xB398_6950_7B58_7B12,
    0xB23B_A5C2_79C2_895F,
    0x258D_D3DB_21A5_D66B,
    0x0D00_88F5_1CBF_F34D,
];

/// Miller loop over a batch of pairs, without the final exponentiation.
///
/// # Soundness
/// Every point must be non-identity, canonical, and in its subgroup. The caller
/// establishes that — see [`crate::bls::miller_accumulator`], which documents
/// what stands in for each of `pairing_check_safe_bls12_381`'s checks.
pub fn miller_loop_batch(g1_points: &[[u64; 12]], g2_points: &[[u64; 24]]) -> [u64; 72] {
    assert_eq!(
        g1_points.len(),
        g2_points.len(),
        "miller_loop_batch: unequal number of G1 and G2 points",
    );

    // xp' = (-xp/yp)·1/(1+u) and yp' = (1/yp)·1/(1+u), once per G1 point.
    let n = g1_points.len();
    let mut xp_primes: Vec<[u64; 12]> = Vec::with_capacity(n);
    let mut yp_primes: Vec<[u64; 12]> = Vec::with_capacity(n);
    for p in g1_points.iter() {
        let mut xp: [u64; 6] = p[0..6].try_into().unwrap();
        let mut yp: [u64; 6] = p[6..12].try_into().unwrap();
        yp = inv_fp_bls12_381(&yp);
        xp = neg_fp_bls12_381(&xp);
        xp = mul_fp_bls12_381(&xp, &yp);

        xp_primes.push(scalar_mul_fp2_bls12_381(&EXT_U_INV, &xp));
        yp_primes.push(scalar_mul_fp2_bls12_381(&EXT_U_INV, &yp));
    }

    // r_i = q_i, f = 1.
    let mut r: Vec<[u64; 24]> = g2_points.to_vec();
    let mut f = [0u64; 72];
    f[0] = 1;

    for &bit in X_ABS_BIN_BE.iter().skip(1) {
        f = square_fp12_bls12_381(&f);

        for i in 0..n {
            let r_i = &mut r[i];
            let xp_prime = &xp_primes[i];
            let yp_prime = &yp_primes[i];

            // The line's coefficients (λ,μ) are hinted and checked rather than
            // solved for, which is what makes a step cost a handful of
            // multiplications instead of an inversion.
            let (lambda, mu) = fcall_bls12_381_twist_dbl_line_coeffs(r_i);
            assert!(is_tangent_twist(r_i, &lambda, &mu), "tangent check failed");

            let l = line_eval_twist(&lambda, &mu, xp_prime, yp_prime);
            f = sparse_mul_fp12_bls12_381(&f, &l);
            *r_i = dbl_twist_with_hints(r_i, &lambda, &mu);

            if bit == 1 {
                let q = &g2_points[i];
                let (lambda, mu) = fcall_bls12_381_twist_add_line_coeffs(r_i, q);
                assert!(is_line_twist(r_i, q, &lambda, &mu), "line check failed");

                let l = line_eval_twist(&lambda, &mu, xp_prime, yp_prime);
                f = sparse_mul_fp12_bls12_381(&f, &l);
                *r_i = add_twist_with_hints(r_i, q, &lambda, &mu);
            }
        }
    }

    // x is negative, so the loop's result is conjugated.
    conjugate_fp12_bls12_381(&f)
}

/// Does the line through (λ,μ) pass through both non-zero G2 points?
fn is_line_twist(q1: &[u64; 24], q2: &[u64; 24], lambda: &[u64; 12], mu: &[u64; 12]) -> bool {
    // A chord is only determined when the two points have distinct x.
    if eq(&q1[0..12], &q2[0..12]) {
        return false;
    }
    line_check_twist(q1, lambda, mu) && line_check_twist(q2, lambda, mu)
}

/// Is the line through (λ,μ) tangent to the twist at `q`?
fn is_tangent_twist(q: &[u64; 24], lambda: &[u64; 12], mu: &[u64; 12]) -> bool {
    let x: &[u64; 12] = &q[0..12].try_into().unwrap();
    let y: &[u64; 12] = &q[12..24].try_into().unwrap();

    // A tangent is only determined when y != 0, which also rejects 2-torsion.
    if is_zero(y) {
        return false;
    }

    let on_line = line_check_twist(q, lambda, mu);

    // Tangency: 2λy = 3x².
    let lhs = dbl_fp2_bls12_381(&mul_fp2_bls12_381(lambda, y));
    let rhs = scalar_mul_fp2_bls12_381(&square_fp2_bls12_381(x), &[3, 0, 0, 0, 0, 0]);

    on_line && eq(&lhs, &rhs)
}

/// Does `y = λx + μ` hold at `q`?
fn line_check_twist(q: &[u64; 24], lambda: &[u64; 12], mu: &[u64; 12]) -> bool {
    let x: &[u64; 12] = &q[0..12].try_into().unwrap();
    let y: &[u64; 12] = &q[12..24].try_into().unwrap();
    eq(&add_fp2_bls12_381(&mul_fp2_bls12_381(lambda, x), mu), y)
}

/// Evaluate `l(x,y) := (1 + 0·v + 0·v²) + (0 - μy·v + λx·v²)·w`.
fn line_eval_twist(lambda: &[u64; 12], mu: &[u64; 12], x: &[u64; 12], y: &[u64; 12]) -> [u64; 24] {
    let coeff1 = mul_fp2_bls12_381(mu, &neg_fp2_bls12_381(y));
    let coeff2 = mul_fp2_bls12_381(lambda, x);

    let mut result = [0u64; 24];
    result[0..12].copy_from_slice(&coeff1);
    result[12..24].copy_from_slice(&coeff2);
    result
}

/// `q1 + q2` on the twist, given the chord's coefficients. Assumes `q1 != ±q2`.
fn add_twist_with_hints(
    q1: &[u64; 24],
    q2: &[u64; 24],
    lambda: &[u64; 12],
    mu: &[u64; 12],
) -> [u64; 24] {
    let x1: &[u64; 12] = &q1[0..12].try_into().unwrap();
    let x2: &[u64; 12] = &q2[0..12].try_into().unwrap();

    // x3 = λ² - x1 - x2, y3 = -(λx3 + μ)
    let x3 = sub_fp2_bls12_381(&sub_fp2_bls12_381(&square_fp2_bls12_381(lambda), x1), x2);
    let y3 = neg_fp2_bls12_381(&add_fp2_bls12_381(mu, &mul_fp2_bls12_381(lambda, &x3)));

    let mut result = [0u64; 24];
    result[0..12].copy_from_slice(&x3);
    result[12..24].copy_from_slice(&y3);
    result
}

/// `2q` on the twist, given the tangent's coefficients.
fn dbl_twist_with_hints(q: &[u64; 24], lambda: &[u64; 12], mu: &[u64; 12]) -> [u64; 24] {
    let x: &[u64; 12] = &q[0..12].try_into().unwrap();

    // x3 = λ² - 2x, y3 = -(λx3 + μ)
    let x3 = sub_fp2_bls12_381(&square_fp2_bls12_381(lambda), &dbl_fp2_bls12_381(x));
    let y3 = neg_fp2_bls12_381(&add_fp2_bls12_381(mu, &mul_fp2_bls12_381(lambda, &x3)));

    let mut result = [0u64; 24];
    result[0..12].copy_from_slice(&x3);
    result[12..24].copy_from_slice(&y3);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ziskos::zisklib::{
        decompress_bls12_381, final_exp_bls12_381, hash_to_curve_g2_bls12_381, is_one,
        neg_bls12_381, pairing_batch_bls12_381,
    };

    /// Compressed G1 generator.
    const G1_GENERATOR_COMPRESSED: [u8; 48] = [
        0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac,
        0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b,
        0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb,
        0x22, 0xc6, 0xbb,
    ];

    fn generator() -> [u64; 12] {
        decompress_bls12_381(&G1_GENERATOR_COMPRESSED)
            .expect("decompress")
            .0
    }

    fn point_g2(tag: &[u8]) -> [u64; 24] {
        hash_to_curve_g2_bls12_381(tag, crate::bls::ETH_BLS_DST)
    }

    /// The transcription has to agree with the library it came from, batch size
    /// by batch size, or every cost figure derived from `pairing_batch` is a
    /// figure for a different computation.
    #[test]
    fn miller_batch_matches_zisklib() {
        let g = generator();
        let neg_g = neg_bls12_381(&g);
        let q1 = point_g2(b"zkasper-miller-1");
        let q2 = point_g2(b"zkasper-miller-2");

        for (g1, g2) in [
            (vec![g], vec![q1]),
            (vec![g, neg_g], vec![q1, q1]),
            (vec![g, neg_g, g], vec![q1, q2, q2]),
        ] {
            assert_eq!(
                final_exp_bls12_381(&miller_loop_batch(&g1, &g2)),
                pairing_batch_bls12_381(&g1, &g2),
                "batch of {} disagrees with pairing_batch_bls12_381",
                g1.len(),
            );
        }
    }

    /// The property the streaming pipeline rests on: Miller accumulators from
    /// separate batches multiply, and one final exponentiation over the product
    /// says what a single batch over everything would have said.
    #[test]
    fn products_of_miller_loops_compose() {
        let g = generator();
        let neg_g = neg_bls12_381(&g);
        let q1 = point_g2(b"zkasper-compose-1");
        let q2 = point_g2(b"zkasper-compose-2");

        let split = crate::bls::fp12_mul(
            &miller_loop_batch(&[g, neg_g], &[q1, q1]),
            &miller_loop_batch(&[g, neg_g], &[q2, q2]),
        );
        assert!(is_one(&final_exp_bls12_381(&split)));

        // And it agrees with proving all four pairs in one batch.
        assert_eq!(
            final_exp_bls12_381(&split),
            pairing_batch_bls12_381(&[g, neg_g, g, neg_g], &[q1, q1, q2, q2]),
        );
    }
}
