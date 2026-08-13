//! BLS12-381 verification through the Zisk BLS library.
//!
//! zisklib ships a full pairing stack (`arith384_mod` + Fp2/Fp6/Fp12 towers,
//! Miller loop, final exponentiation, hash-to-curve). Its own
//! `bls_verify_bls12_381` uses the Basic-scheme DST, so we compose the
//! primitives directly to get Ethereum's proof-of-possession ciphersuite and
//! the FastAggregateVerify shape that attestations need.

use alloc::vec::Vec;
use ziskos::syscalls::{
    syscall_bls12_381_curve_add, SyscallBls12_381CurveAddParams, SyscallPoint384,
};
use ziskos::zisklib::{
    add_complete_safe_twist_bls12_381, decompress_bls12_381, decompress_twist_bls12_381,
    hash_to_curve_g2_bls12_381, is_on_subgroup_twist_bls12_381, neg_bls12_381,
    pairing_check_safe_bls12_381,
};

use crate::acc::G1Point;

use crate::ssz::sha256_pair;

/// Ethereum's BLS ciphersuite (proof-of-possession variant).
pub const ETH_BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// DOMAIN_BEACON_ATTESTER as defined in the Ethereum consensus spec.
pub const DOMAIN_BEACON_ATTESTER: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// Generator of G1, in the little-endian limb layout zisklib expects.
const G1_GENERATOR: [u64; 12] = [
    0xFB3A_F00A_DB22_C6BB,
    0x6C55_E83F_F97A_1AEF,
    0xA14E_3A3F_171B_AC58,
    0xC368_8C4F_9774_B905,
    0x2695_638C_4FA9_AC0F,
    0x17F1_D3A7_3197_D794,
    0x0CAA_2329_46C5_E7E1,
    0xD03C_C744_A288_8AE4,
    0x00DB_18CB_2C04_B3ED,
    0xFCF5_E095_D5D0_0AF6,
    0xA09E_30ED_741D_8AE4,
    0x08B3_F481_E3AA_A0F1,
];

/// Compute `signing_root = sha256(attestation_data_root || domain)`.
pub fn compute_signing_root(attestation_data_root: &[u8; 32], domain: &[u8; 32]) -> [u8; 32] {
    sha256_pair(attestation_data_root, domain)
}

/// Compute the Ethereum signing domain for a given domain type, fork version,
/// and genesis validators root.
///
/// `domain = domain_type[0..4] || fork_data_root[0..28]`
/// where `fork_data_root = hash_tree_root(ForkData{current_version, genesis_validators_root})`
///                        = sha256(pad32(current_version) || genesis_validators_root)
pub fn compute_domain(
    domain_type: &[u8; 4],
    fork_version: &[u8; 4],
    genesis_validators_root: &[u8; 32],
) -> [u8; 32] {
    let mut version_chunk = [0u8; 32];
    version_chunk[..4].copy_from_slice(fork_version);
    let fork_data_root = sha256_pair(&version_chunk, genesis_validators_root);

    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(domain_type);
    domain[4..32].copy_from_slice(&fork_data_root[..28]);
    domain
}

/// Aggregate G1 public keys. Every attester in one aggregated attestation signs
/// the same message, so the whole committee collapses to a single pairing input.
///
/// The points come straight from the accumulator leaf preimage, which already
/// commits to the decompressed form, so there is nothing left to validate here:
/// a point that is not the committed one fails the accumulator check instead.
///
/// This drives `syscall_bls12_381_curve_add` directly rather than going through
/// `add_complete_safe_bls12_381`. That wrapper re-validates both operands on
/// every call — two `is_on_curve` checks, four range comparisons, and the array
/// shuffling around them — which costs 67,854 against 1,896 for the precompile
/// itself. All of it re-establishes facts the accumulator already guarantees:
/// the points are committed, and a sum of on-curve points is on-curve.
///
/// Public keys are not subgroup-checked. The consensus spec checks proof of
/// possession once at deposit time and skips the check when verifying
/// attestations; the accumulator only ever holds keys the beacon state already
/// accepted, so re-checking here would cost a scalar multiplication per attester
/// for no additional guarantee.
///
/// The precompile requires `p1 != p2` and `p1 != -p2`, both of which share an
/// x-coordinate. Validator public keys are distinct by construction, so a
/// collision means a partial sum landed exactly on the next point or its
/// negation — a discrete-log problem, not something a prover can arrange. It is
/// still checked, and rejected rather than assumed away.
pub fn aggregate_points(points: &[G1Point]) -> Option<G1Point> {
    #[cfg(feature = "count-ops")]
    crate::op_counter::inc_pubkey_aggregate(points.len() as u64);

    let (first, rest) = points.split_first()?;

    let mut acc = SyscallPoint384 {
        x: first[0..6].try_into().ok()?,
        y: first[6..12].try_into().ok()?,
    };

    for point in rest {
        if acc.x[..] == point[0..6] {
            return None;
        }
        let addend = SyscallPoint384 {
            x: point[0..6].try_into().ok()?,
            y: point[6..12].try_into().ok()?,
        };
        syscall_bls12_381_curve_add(&mut SyscallBls12_381CurveAddParams {
            p1: &mut acc,
            p2: &addend,
        });
    }

    let mut out = [0u64; 12];
    out[0..6].copy_from_slice(&acc.x);
    out[6..12].copy_from_slice(&acc.y);
    Some(out)
}

/// Decompress a 48-byte public key into the form the accumulator leaf commits to.
///
/// Only the bootstrap and epoch-diff proofs call this — once per validator that
/// enters or changes, rather than once per attester per slot.
pub fn decompress_pubkey(compressed: &[u8; 48]) -> Option<G1Point> {
    #[cfg(feature = "count-ops")]
    crate::op_counter::inc_decompress(1);

    let (point, is_infinity) = decompress_bls12_381(compressed).ok()?;
    if is_infinity {
        return None;
    }
    Some(point)
}

/// FastAggregateVerify: one aggregate signature over one message signed by all
/// of `pubkeys`.
///
/// Checks `e(-aggregate_pubkey, H(msg)) * e(G1, signature) == 1`, which is one
/// hash-to-curve, two Miller loops and one final exponentiation regardless of
/// how many keys were aggregated.
pub fn fast_aggregate_verify(
    pubkeys: &[G1Point],
    signing_root: &[u8; 32],
    signature: &[u8; 96],
) -> bool {
    if pubkeys.is_empty() {
        return false;
    }

    let Some(agg) = aggregate_points(pubkeys) else {
        return false;
    };

    let Ok((sig, sig_is_infinity)) = decompress_twist_bls12_381(signature) else {
        return false;
    };
    if sig_is_infinity || !is_on_subgroup_twist_bls12_381(&sig) {
        return false;
    }

    #[cfg(feature = "count-ops")]
    {
        crate::op_counter::inc_hash_to_curve(1);
        crate::op_counter::inc_miller_loop(2);
        crate::op_counter::inc_final_exp(1);
    }

    let q = hash_to_curve_g2_bls12_381(signing_root, ETH_BLS_DST);
    let neg_agg = neg_bls12_381(&agg);

    matches!(
        pairing_check_safe_bls12_381(&[neg_agg, G1_GENERATOR], &[q, sig]),
        Ok(true)
    )
}

/// Verify an aggregate signature, panicking on failure.
pub fn verify_aggregate_signature(
    pubkeys: &[G1Point],
    signing_root: &[u8; 32],
    signature: &[u8; 96],
) {
    assert!(
        fast_aggregate_verify(pubkeys, signing_root, signature),
        "BLS aggregate signature verification failed"
    );
}

/// Identity element of G2.
const G2_IDENTITY: [u64; 24] = [0; 24];

/// One attestation's signature check: a committee, the message they signed, and
/// their aggregate signature.
pub struct SignedMessage<'a> {
    /// Decompressed public keys, as committed by the accumulator leaves.
    pub pubkeys: &'a [G1Point],
    pub signing_root: &'a [u8; 32],
    pub signature: &'a [u8; 96],
}

/// Verify many attestations with a single multi-pairing.
///
/// Checking each attestation on its own costs two Miller loops and a final
/// exponentiation. The final exponentiation is by far the most expensive part
/// and only has to happen once, so folding `n` attestations into one check
/// costs `n + 1` Miller loops and a single final exponentiation:
///
/// ```text
/// prod_i e(-aggregate_pubkey_i, H(msg_i)) * e(G1, sum_i signature_i) == 1
/// ```
///
/// Messages must be pairwise distinct, which is what stops a rogue-key attack
/// from cancelling one attestation against another. Attestations within a slot
/// carry different `AttestationData`, so their signing roots differ; the check
/// is enforced here rather than assumed.
pub fn verify_attestation_batch(messages: &[SignedMessage]) -> bool {
    if messages.is_empty() {
        return false;
    }

    for (i, a) in messages.iter().enumerate() {
        for b in &messages[i + 1..] {
            if a.signing_root == b.signing_root {
                return false;
            }
        }
    }

    let mut g1_points: Vec<[u64; 12]> = Vec::with_capacity(messages.len() + 1);
    let mut g2_points: Vec<[u64; 24]> = Vec::with_capacity(messages.len() + 1);
    let mut signature_sum = G2_IDENTITY;

    for m in messages {
        if m.pubkeys.is_empty() {
            return false;
        }
        let Some(agg) = aggregate_points(m.pubkeys) else {
            return false;
        };
        let Ok((sig, sig_is_infinity)) = decompress_twist_bls12_381(m.signature) else {
            return false;
        };
        if sig_is_infinity {
            return false;
        }
        let Ok(sum) = add_complete_safe_twist_bls12_381(&signature_sum, &sig) else {
            return false;
        };
        signature_sum = sum;

        #[cfg(feature = "count-ops")]
        crate::op_counter::inc_hash_to_curve(1);

        g1_points.push(neg_bls12_381(&agg));
        g2_points.push(hash_to_curve_g2_bls12_381(m.signing_root, ETH_BLS_DST));
    }

    // The individual signatures need no subgroup check of their own: the
    // equation only ever involves their sum, so checking the sum is what binds.
    if !is_on_subgroup_twist_bls12_381(&signature_sum) {
        return false;
    }

    g1_points.push(G1_GENERATOR);
    g2_points.push(signature_sum);

    #[cfg(feature = "count-ops")]
    {
        crate::op_counter::inc_miller_loop(g1_points.len() as u64);
        crate::op_counter::inc_final_exp(1);
    }

    matches!(
        pairing_check_safe_bls12_381(&g1_points, &g2_points),
        Ok(true)
    )
}
