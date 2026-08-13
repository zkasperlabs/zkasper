//! Host-side public key decompression.
//!
//! The accumulator leaf commits to the decompressed G1 point, so building a
//! tree means decompressing every validator's key — millions of them at mainnet
//! scale. zisklib's decompression is designed for the guest, where the square
//! root arrives as a hint; on the host that hint has to be computed with
//! `num-bigint`, which is far too slow in bulk. `blst` does the same job in
//! optimised assembly.
//!
//! `decompress_matches_zisklib` pins the two implementations together, so the
//! host tree and the in-circuit tree cannot drift.

use zkasper_common::acc::G1Point;

/// Decompress a 48-byte public key into zisklib's limb layout.
///
/// Returns `None` for keys that are malformed, the point at infinity, or
/// outside the G1 subgroup — `blst` validates the subgroup on deserialize.
pub fn decompress(compressed: &[u8; 48]) -> Option<G1Point> {
    let pk = blst::min_pk::PublicKey::from_bytes(compressed).ok()?;
    let uncompressed = pk.serialize(); // 96 bytes: x || y, big-endian
    let mut point = [0u64; 12];
    point[0..6].copy_from_slice(&be_bytes_to_limbs(&uncompressed[..48]));
    point[6..12].copy_from_slice(&be_bytes_to_limbs(&uncompressed[48..]));
    Some(point)
}

/// Big-endian field element to the little-endian 64-bit limbs zisklib uses.
fn be_bytes_to_limbs(bytes: &[u8]) -> [u64; 6] {
    let mut limbs = [0u64; 6];
    for (i, limb) in limbs.iter_mut().rev().enumerate() {
        *limb = u64::from_be_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
    }
    limbs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey(seed: u8) -> [u8; 48] {
        let ikm = [seed; 32];
        blst::min_pk::SecretKey::key_gen(&ikm, &[])
            .unwrap()
            .sk_to_pk()
            .compress()
    }

    /// The host path and the guest path must agree bit for bit, or the tree the
    /// witness generator builds will not be the tree the circuit rebuilds.
    #[test]
    fn decompress_matches_zisklib() {
        for seed in 0..8u8 {
            let compressed = test_pubkey(seed);
            assert_eq!(
                decompress(&compressed),
                zkasper_common::bls::decompress_pubkey(&compressed),
                "mismatch for seed {seed}",
            );
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(decompress(&[0xFFu8; 48]).is_none());
    }
}
