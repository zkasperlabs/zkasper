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
    add_complete_safe_bls12_381, add_complete_safe_twist_bls12_381, decompress_bls12_381,
    decompress_twist_bls12_381, final_exp_bls12_381, hash_to_curve_g2_bls12_381,
    is_on_subgroup_twist_bls12_381, is_one, mul_fp12_bls12_381, neg_bls12_381,
};

use crate::miller::miller_loop_batch;

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
    let mut sum = PointSum::default();
    for point in points {
        sum.add(point)?;
    }
    sum.get()
}

/// A running sum of public keys, addition and subtraction both.
///
/// Complement proving needs the subtraction: a slot's attesters are its
/// committee aggregate minus the keys of everyone who did not sign the primary
/// message, so the sum walks downwards from a value it never enumerates.
/// Negating a G1 point is a field negation of `y`, so a subtraction costs the
/// same as an addition.
///
/// See [`aggregate_points`] for why the raw precompile is safe here and what its
/// preconditions are.
#[derive(Clone, Copy, Debug, Default)]
pub struct PointSum(Option<G1Point>);

impl PointSum {
    /// Start from a point that is already a sum — a committee aggregate, say.
    pub fn from_point(point: G1Point) -> Self {
        Self(Some(point))
    }

    pub fn add(&mut self, point: &G1Point) -> Option<()> {
        #[cfg(feature = "count-ops")]
        crate::op_counter::inc_pubkey_aggregate(1);

        let Some(current) = self.0.as_mut() else {
            self.0 = Some(*point);
            return Some(());
        };

        // A shared x-coordinate is either `p1 == p2` or `p1 == -p2`, and the
        // precompile is undefined on both.
        if current[0..6] == point[0..6] {
            return None;
        }

        // `SyscallPoint384` is `#[repr(C)] { x: [u64; 6], y: [u64; 6] }`, which
        // is the layout `G1Point` already has: same size, same alignment, no
        // padding, every bit pattern inhabiting both. So the precompile reads
        // the running sum and the key where they lie, instead of both being
        // copied into syscall structs and the result copied back — 48 loads and
        // 24 stores around a syscall that is 1,896 cost units. Measured at 6,655
        // cost units a validator by `scripts/committee_bench.py`, 6% of the
        // committee proof, and the same saving on every key a slot proof names.
        syscall_bls12_381_curve_add(&mut SyscallBls12_381CurveAddParams {
            p1: unsafe { &mut *(current.as_mut_ptr() as *mut SyscallPoint384) },
            p2: unsafe { &*(point.as_ptr() as *const SyscallPoint384) },
        });
        Some(())
    }

    pub fn sub(&mut self, point: &G1Point) -> Option<()> {
        self.add(&neg_bls12_381(point))
    }

    /// The sum so far, or `None` if nothing was ever added.
    pub fn get(&self) -> Option<G1Point> {
        self.0
    }
}

/// Decompress a 48-byte public key into the form the accumulator leaf commits to.
///
/// Only the epoch-diff proof calls this — once per validator that enters or
/// changes, rather than once per attester per slot.
pub fn decompress_pubkey(compressed: &[u8; 48]) -> Option<G1Point> {
    #[cfg(feature = "count-ops")]
    crate::op_counter::inc_decompress(1);

    let (point, is_infinity) = decompress_bls12_381(compressed).ok()?;
    if is_infinity {
        return None;
    }
    Some(point)
}

/// Identity element of G2.
const G2_IDENTITY: [u64; 24] = [0; 24];

/// Identity element of G1.
const G1_IDENTITY: [u64; 12] = [0; 12];

/// One message's signature check: who signed it, what they signed, and the
/// aggregate signatures over it.
///
/// `signatures` is a list rather than one value because a slot's attesters
/// routinely arrive as several aggregates carrying byte-identical
/// `AttestationData`. Their signer sets are disjoint, so summing the signatures
/// and pairing them against one aggregate public key is both correct and one
/// Miller loop instead of several — and under complement proving that key is
/// derived from the committee, so it could not be split across aggregates
/// anyway.
pub struct SignedMessage<'a> {
    /// Decompressed public keys, as committed by the accumulator leaves.
    pub pubkeys: &'a [G1Point],
    pub signing_root: &'a [u8; 32],
    pub signatures: &'a [[u8; 96]],
}

// ---------------------------------------------------------------------------
// The pairing, split into its two halves
// ---------------------------------------------------------------------------

/// An element of Fp12: twelve base-field coefficients, six 64-bit limbs each.
///
/// This is what a multi-pairing looks like *before* the final exponentiation,
/// and it is the value a streaming group proof hands to its parent. 576 bytes,
/// which is more than the 256 a proof can commit publicly, so it travels as
/// private witness and is bound by [`crate::acc::commit_fp12`].
pub type Fp12 = [u64; 72];

/// Multiplicative identity of Fp12 — an empty Miller-loop accumulator.
pub const FP12_ONE: Fp12 = {
    let mut one = [0u64; 72];
    one[0] = 1;
    one
};

/// Multiply two Miller-loop accumulators.
///
/// `∏ᵢ e(Pᵢ,Qᵢ) = FinalExp(∏ᵢ MillerLoop(Pᵢ,Qᵢ))`, so accumulators computed by
/// different proofs over disjoint pair sets combine with a plain Fp12
/// multiplication and one shared final exponentiation. This is the operation
/// that lets the expensive half of every signature check happen before the last
/// attestation arrives.
pub fn fp12_mul(a: &Fp12, b: &Fp12) -> Fp12 {
    #[cfg(feature = "count-ops")]
    crate::op_counter::inc_fp12_mul(1);

    mul_fp12_bls12_381(a, b)
}

/// Final exponentiation, and the check that the multi-pairing came out at 1.
///
/// 169,455,773 against 39,299,490 for a Miller loop: this is 81% of a two-pair
/// pairing check and it is paid once, however many pairs the accumulator
/// covers. Deferring it to a single proof at the end of the epoch is the whole
/// point of the split.
pub fn final_exp_is_one(f: &Fp12) -> bool {
    #[cfg(feature = "count-ops")]
    crate::op_counter::inc_final_exp(1);

    is_one(&final_exp_bls12_381(f))
}

/// The Miller-loop half of [`verify_attestation_batch`]: everything except the
/// final exponentiation.
///
/// Returns `∏ᵢ ML(-aggregate_pubkeyᵢ, H(msgᵢ)) · ML(G1, Σᵢ signatureᵢ)` over the
/// messages given. The caller multiplies accumulators from other groups into
/// this one and runs [`final_exp_is_one`] over the product exactly once.
///
/// Each group pays its own `ML(G1, Σ signature)` term rather than carrying a
/// running G2 signature sum between proofs, which costs one extra Miller loop
/// per group and keeps every group self-contained: nothing but an Fp12 crosses
/// a proof boundary.
///
/// # Validation
///
/// `pairing_check_safe_bls12_381` re-derives canonical-form, on-curve and
/// subgroup checks for every input. Going straight to the Miller loop drops
/// them, so what replaces each one is stated here:
///
/// - **Public keys** are on-curve and canonical because they come out of an
///   accumulator leaf that commits to them, and the sum of on-curve points is
///   on-curve. They are not subgroup-checked, deliberately: the consensus spec
///   checks proof of possession once at deposit time, and a component outside
///   the r-torsion pairs to 1 against a G2 element of order r, so it cannot
///   affect the equation.
/// - **Message points** come from `hash_to_curve_g2`, which clears the cofactor,
///   so they are in G2 by construction.
/// - **The signature sum** is the one input an attacker controls freely, and it
///   *is* subgroup-checked, right here. Without it a signature outside G2 could
///   satisfy the equation without a discrete log.
/// - **Identity inputs** are rejected rather than skipped: a Miller loop over an
///   identity point is undefined, and `pairing_check_safe` silently dropping the
///   pair would weaken what the remaining pairs have to prove.
pub fn miller_accumulator(messages: &[SignedMessage]) -> Option<Fp12> {
    if messages.is_empty() {
        return None;
    }

    // Group by signing root, then fold each group into one pairing input.
    //
    // Post-Electra, `AttestationData.index` is pinned to 0 and committee
    // identity lives in `committee_bits`, so two aggregates in the same block
    // covering different committees carry byte-identical `AttestationData` and
    // therefore the same signing root. Rejecting that case rejects real
    // mainnet blocks — measured, 4 of 34 slots in epoch 430529.
    //
    // Merging is sound and is what the distinctness rule is actually for. The
    // rogue-key concern is about a signer's key appearing against a message
    // nobody committed to; summing two aggregates over the *same* message adds
    // their public keys and their signatures in step, so the pairing equation
    // stays balanced:
    //   e(P1 + P2, H(m)) == e(G1, s1 + s2)
    // It is also strictly cheaper — one Miller loop per distinct message rather
    // than per aggregate.
    let mut roots: Vec<[u8; 32]> = Vec::with_capacity(messages.len());
    let mut aggs: Vec<[u64; 12]> = Vec::with_capacity(messages.len());
    let mut signature_sum = G2_IDENTITY;

    for m in messages {
        if m.pubkeys.is_empty() {
            return None;
        }
        let agg = aggregate_points(m.pubkeys)?;
        if m.signatures.is_empty() {
            return None;
        }
        for signature in m.signatures {
            let Ok((sig, sig_is_infinity)) = decompress_twist_bls12_381(signature) else {
                return None;
            };
            if sig_is_infinity {
                return None;
            }
            let Ok(sum) = add_complete_safe_twist_bls12_381(&signature_sum, &sig) else {
                return None;
            };
            signature_sum = sum;
        }

        match roots.iter().position(|r| r == m.signing_root) {
            Some(i) => {
                // Same message as an earlier aggregate: fold the public keys.
                let Ok(merged) = add_complete_safe_bls12_381(&aggs[i], &agg) else {
                    return None;
                };
                aggs[i] = merged;
            }
            None => {
                roots.push(*m.signing_root);
                aggs.push(agg);
            }
        }
    }

    // The individual signatures need no subgroup check of their own: the
    // equation only ever involves their sum, so checking the sum is what binds.
    #[cfg(feature = "count-ops")]
    crate::op_counter::inc_g2_subgroup(1);

    if signature_sum == G2_IDENTITY || !is_on_subgroup_twist_bls12_381(&signature_sum) {
        return None;
    }

    let mut g1_points: Vec<[u64; 12]> = Vec::with_capacity(roots.len() + 1);
    let mut g2_points: Vec<[u64; 24]> = Vec::with_capacity(roots.len() + 1);
    for (root, agg) in roots.iter().zip(&aggs) {
        if *agg == G1_IDENTITY {
            return None;
        }
        #[cfg(feature = "count-ops")]
        crate::op_counter::inc_hash_to_curve(1);
        g1_points.push(neg_bls12_381(agg));
        g2_points.push(hash_to_curve_g2_bls12_381(root, ETH_BLS_DST));
    }

    g1_points.push(G1_GENERATOR);
    g2_points.push(signature_sum);

    #[cfg(feature = "count-ops")]
    {
        crate::op_counter::inc_miller_batch(1);
        crate::op_counter::inc_miller_loop(g1_points.len() as u64);
    }

    Some(miller_loop_batch(&g1_points, &g2_points))
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
/// This is [`miller_accumulator`] followed immediately by [`final_exp_is_one`],
/// for callers that verify a whole batch in one proof. Streaming callers keep
/// the two apart.
pub fn verify_attestation_batch(messages: &[SignedMessage]) -> bool {
    match miller_accumulator(messages) {
        Some(f) => final_exp_is_one(&f),
        None => false,
    }
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
    verify_attestation_batch(&[SignedMessage {
        pubkeys,
        signing_root,
        signatures: core::slice::from_ref(signature),
    }])
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
