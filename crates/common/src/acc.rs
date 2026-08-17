//! Accumulator hashing: Poseidon2 over Goldilocks, width 16.
//!
//! The accumulator digest is 4 Goldilocks field elements rather than 32 bytes.
//! Every hash below is exactly one `syscall_poseidon2` invocation, which the
//! Zisk prover charges as 14 trace clocks. `ziskos` runs the same permutation in
//! software on native targets, so host and guest agree by construction.
//!
//! State layout: elements 0..8 are the rate, 8..16 the capacity. Element 15
//! carries a domain separator so a leaf preimage can never be reinterpreted as
//! an internal node.

use ziskos::syscalls::syscall_poseidon2;

/// Accumulator digest: 4 Goldilocks elements (~2^256 space, 128-bit birthday bound).
pub type Digest = [u64; 4];

/// Digest of an empty tree slot.
pub const ZERO: Digest = [0; 4];

const DOMAIN_NODE: u64 = 0;
const DOMAIN_LEAF: u64 = 1;
const DOMAIN_COMMITMENT: u64 = 2;
const DOMAIN_INDEX_LIST: u64 = 3;

#[inline(always)]
fn permute(state: &mut [u64; 16]) {
    #[cfg(feature = "count-ops")]
    crate::op_counter::inc_poseidon2();
    permute_uncounted(state);
}

/// The permutation without the counter, for call sites that charge themselves.
#[inline(always)]
fn permute_uncounted(state: &mut [u64; 16]) {
    unsafe { syscall_poseidon2(state as *mut [u64; 16]) };
}

/// Compress two child digests into their parent.
#[inline]
pub fn compress(left: &Digest, right: &Digest) -> Digest {
    let mut st = [0u64; 16];
    st[0..4].copy_from_slice(left);
    st[4..8].copy_from_slice(right);
    st[15] = DOMAIN_NODE;
    permute(&mut st);
    [st[0], st[1], st[2], st[3]]
}

/// A G1 point in the little-endian limb layout zisklib uses: x then y, six
/// 64-bit limbs each.
pub type G1Point = [u64; 12];

/// Number of Goldilocks elements a G1 point packs into.
const POINT_ELEMENTS: usize = 13;

/// Bits per packed element. Any value below 2^60 is below the Goldilocks
/// modulus, so the packing is canonical; 64-bit limbs would not be.
const PACK_BITS: u32 = 60;

/// Repack a G1 point's 768 bits into 13 disjoint 60-bit windows.
///
/// Injective because the windows tile the input: every bit lands in exactly one
/// element, and 13 * 60 = 780 covers all 768.
#[inline]
fn pack_point(point: &G1Point) -> [u64; POINT_ELEMENTS] {
    let mut out = [0u64; POINT_ELEMENTS];
    for (i, slot) in out.iter_mut().enumerate() {
        let bit = i * PACK_BITS as usize;
        let limb = bit / 64;
        let offset = (bit % 64) as u32;

        let mut v = point[limb] >> offset;
        if offset + PACK_BITS > 64 && limb + 1 < point.len() {
            v |= point[limb + 1] << (64 - offset);
        }
        *slot = v & ((1u64 << PACK_BITS) - 1);
    }
    out
}

/// Accumulator leaf for one validator:
/// `H(uncompressed_pubkey, active_effective_balance)`.
///
/// The leaf commits to the *decompressed* G1 point rather than the 48-byte
/// compressed key the beacon state stores. Decompression is cheap but not free —
/// 49,395 cost units — and a compressed leaf makes every slot proof decompress
/// every key it touches, which at mainnet scale is every active validator, once
/// per epoch. Committing the point instead moves that work into the epoch-diff
/// proof, which only touches validators that actually changed.
///
/// The point packs into 13 elements and the balance into 2, so this is still a
/// single permutation.
#[inline]
pub fn leaf(point: &G1Point, active_effective_balance: u64) -> Digest {
    let mut st = [0u64; 16];
    st[..POINT_ELEMENTS].copy_from_slice(&pack_point(point));
    st[13] = active_effective_balance & 0xFFFF_FFFF;
    st[14] = active_effective_balance >> 32;
    st[15] = DOMAIN_LEAF;
    #[cfg(feature = "count-ops")]
    {
        // Charged as ACC_LEAF, not POSEIDON2: the leaf marshals a packed G1
        // point into the state and measures 3,979 against a node's 3,033.
        crate::op_counter::inc_acc_leaf(1);
        crate::op_counter::inc_poseidon2_n(0);
    }
    permute_uncounted(&mut st);
    [st[0], st[1], st[2], st[3]]
}

/// Bind the accumulator root to the total active balance in a single value,
/// so the on-chain contract stores one word instead of two.
#[inline]
pub fn commitment(root: &Digest, total_active_balance: u64) -> Digest {
    let mut st = [0u64; 16];
    st[0..4].copy_from_slice(root);
    st[4] = total_active_balance & 0xFFFF_FFFF;
    st[5] = total_active_balance >> 32;
    st[15] = DOMAIN_COMMITMENT;
    permute(&mut st);
    [st[0], st[1], st[2], st[3]]
}

/// Sponge commitment over a sorted list of validator indices, used to detect
/// double-counting across slot proofs.
///
/// Absorbs 8 indices per permutation. The length is bound in the capacity, so
/// lists of different lengths cannot collide through padding.
pub fn commit_indices(sorted_indices: &[u64]) -> Digest {
    let mut st = [0u64; 16];
    st[8] = DOMAIN_INDEX_LIST;
    st[9] = sorted_indices.len() as u64;

    let mut i = 0usize;
    loop {
        let n = core::cmp::min(8, sorted_indices.len().saturating_sub(i));
        let mut rate = [0u64; 8];
        rate[..n].copy_from_slice(&sorted_indices[i..i + n]);
        st[0..8].copy_from_slice(&rate);
        permute(&mut st);
        i += 8;
        if i >= sorted_indices.len() {
            break;
        }
    }
    [st[0], st[1], st[2], st[3]]
}

/// Serialize a digest for public output or on-chain storage.
#[inline]
pub fn to_bytes(d: &Digest) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[8 * i..8 * i + 8].copy_from_slice(&d[i].to_le_bytes());
    }
    out
}

/// Inverse of [`to_bytes`]. Only sound for bytes produced by [`to_bytes`] —
/// arbitrary bytes may decode to non-canonical field elements.
#[inline]
pub fn from_bytes(b: &[u8; 32]) -> Digest {
    let mut d = [0u64; 4];
    for i in 0..4 {
        d[i] = u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap());
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    #[test]
    fn compress_is_order_dependent() {
        let a = [1, 2, 3, 4];
        let b = [5, 6, 7, 8];
        assert_ne!(compress(&a, &b), compress(&b, &a));
    }

    #[test]
    fn leaf_binds_balance() {
        let p = [42u64; 12];
        assert_ne!(leaf(&p, 32_000_000_000), leaf(&p, 0));
    }

    /// Every bit of the point must reach exactly one packed element, or two
    /// distinct public keys could share a leaf.
    #[test]
    fn pack_point_is_injective_over_single_bits() {
        let mut seen = alloc::vec::Vec::new();
        for limb in 0..12 {
            for bit in 0..64 {
                let mut p = [0u64; 12];
                p[limb] = 1u64 << bit;
                let packed = pack_point(&p);
                assert_eq!(
                    packed.iter().filter(|&&v| v != 0).count(),
                    1,
                    "limb {limb} bit {bit} did not land in exactly one element",
                );
                assert!(!seen.contains(&packed), "limb {limb} bit {bit} collided");
                seen.push(packed);
            }
        }
    }

    #[test]
    fn packed_elements_are_canonical() {
        let packed = pack_point(&[u64::MAX; 12]);
        for v in packed {
            assert!(v < 1u64 << PACK_BITS);
        }
    }

    #[test]
    fn leaf_binds_every_point_limb() {
        let base = [7u64; 12];
        let baseline = leaf(&base, 32_000_000_000);
        for limb in 0..12 {
            let mut p = base;
            p[limb] ^= 1;
            assert_ne!(leaf(&p, 32_000_000_000), baseline, "limb {limb} not bound");
        }
    }

    /// A leaf whose packed tail and balance are all zero must not collide with
    /// the internal-node compression of the same leading elements.
    #[test]
    fn leaf_and_node_domains_are_separated() {
        let mut p = [0u64; 12];
        p[0] = 0x0707_0707_0707;
        let packed = pack_point(&p);
        assert_ne!(
            leaf(&p, 0),
            compress(&[packed[0], packed[1], packed[2], packed[3]], &ZERO),
        );
    }

    #[test]
    fn index_commitment_binds_length() {
        assert_ne!(commit_indices(&[1, 2, 3]), commit_indices(&[1, 2, 3, 0]));
    }

    #[test]
    fn byte_roundtrip() {
        let d = compress(&[1, 2, 3, 4], &[5, 6, 7, 8]);
        assert_eq!(from_bytes(&to_bytes(&d)), d);
    }
}
