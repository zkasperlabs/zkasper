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

/// Accumulator leaf for one validator: `H(pubkey, active_effective_balance)`.
///
/// The 48-byte pubkey is split into twelve 32-bit limbs and the balance into
/// two. A 32-bit limb is always below the Goldilocks modulus, so the byte to
/// field map is injective — packing 8 bytes per element would not be.
#[inline]
pub fn leaf(pubkey: &[u8; 48], active_effective_balance: u64) -> Digest {
    let mut st = [0u64; 16];
    for i in 0..12 {
        st[i] = u32::from_le_bytes([
            pubkey[4 * i],
            pubkey[4 * i + 1],
            pubkey[4 * i + 2],
            pubkey[4 * i + 3],
        ]) as u64;
    }
    st[12] = active_effective_balance & 0xFFFF_FFFF;
    st[13] = active_effective_balance >> 32;
    st[15] = DOMAIN_LEAF;
    permute(&mut st);
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

    #[test]
    fn compress_is_order_dependent() {
        let a = [1, 2, 3, 4];
        let b = [5, 6, 7, 8];
        assert_ne!(compress(&a, &b), compress(&b, &a));
    }

    #[test]
    fn leaf_binds_balance() {
        let pk = [42u8; 48];
        assert_ne!(leaf(&pk, 32_000_000_000), leaf(&pk, 0));
    }

    /// A leaf whose trailing pubkey limbs and balance are all zero must not
    /// collide with the internal-node compression of its first two limb groups.
    #[test]
    fn leaf_and_node_domains_are_separated() {
        let mut pk = [0u8; 48];
        pk[..16].copy_from_slice(&[7u8; 16]);
        let l = leaf(&pk, 0);
        let n = compress(
            &[7 * 0x0101_0101, 0x0707_0707, 0x0707_0707, 0x0707_0707],
            &ZERO,
        );
        assert_ne!(l, n);
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
