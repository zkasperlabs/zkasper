extern crate alloc;

use alloc::vec::Vec;
use zkasper_common::acc::Digest;
use zkasper_common::bls::Fp12;
use zkasper_common::types::{
    AccMultiProof, AttestationWitness, GroupProofOutput, SlotProofOutput, SlotProofWitness,
};

/// What verifying a set of attestations establishes.
pub struct Attested {
    /// Sum of `active_effective_balance` over validators marked `count_balance`.
    pub attesting_balance: u64,
    /// Those validators' indices, sorted and strictly increasing.
    pub counted_indices: Vec<u64>,
    /// The Miller-loop half of the signature check over every attestation.
    ///
    /// The final exponentiation is *not* done here. Nothing is proven about
    /// these signatures until some proof runs it over the product of this and
    /// every other accumulator in the epoch.
    pub miller: Fp12,
}

/// Verify a single slot's attestations and produce a SlotProofOutput.
///
/// This is the whole-slot form: it finishes the pairing itself, so its output
/// stands alone. Streaming callers want [`verify_group_proof`] instead.
pub fn verify_slot_proof(witness: &SlotProofWitness) -> SlotProofOutput {
    verify_slot_proof_with_depth(witness, zkasper_common::constants::ACC_TREE_DEPTH)
}

/// Slot-proof verification with a configurable accumulator tree depth.
pub fn verify_slot_proof_with_depth(witness: &SlotProofWitness, acc_depth: u32) -> SlotProofOutput {
    let attested = attest(witness, acc_depth);

    assert!(
        zkasper_common::bls::final_exp_is_one(&attested.miller),
        "BLS aggregate signature verification failed",
    );

    SlotProofOutput {
        accumulator_commitment: witness.accumulator_commitment,
        target_epoch: witness.target_epoch,
        target_root: witness.target_root,
        attesting_balance: attested.attesting_balance,
        counted_validators_commitment: zkasper_common::acc::commit_indices(
            &attested.counted_indices,
        ),
        num_counted_validators: attested.counted_indices.len() as u64,
    }
}

/// Verify a group of slots' attestations and stop before the final exponentiation.
///
/// A group proof is the streaming form of a slot proof. It does the same
/// membership and aggregation work over as many slots as the caller chose to
/// group together, and publishes a commitment to its Miller-loop accumulator
/// instead of a verdict on the signatures.
///
/// # Why the signatures are not checked here
///
/// The final exponentiation costs 169,455,773 against 39,299,490 for a Miller
/// loop — 81% of a two-pair pairing check — and one of them settles a product of
/// any number of Miller loops. Charging every group for its own would spend that
/// once per group for no gain, since the epoch's proof chain has to run one
/// anyway over whatever the last attestation contributes.
///
/// The consequence is that a group proof alone proves nothing about signatures.
/// It is a claim of the form "these attesters are in the accumulator, and *if*
/// the product of everyone's accumulators exponentiates to 1, these are their
/// balances". The proof that closes the epoch is what discharges the *if*, and
/// it must cover every group whose balance it counts.
pub fn verify_group_proof(witness: &SlotProofWitness) -> GroupProofOutput {
    verify_group_proof_with_depth(witness, zkasper_common::constants::ACC_TREE_DEPTH)
}

/// Group-proof verification with a configurable accumulator tree depth.
pub fn verify_group_proof_with_depth(
    witness: &SlotProofWitness,
    acc_depth: u32,
) -> GroupProofOutput {
    let attested = attest(witness, acc_depth);

    GroupProofOutput {
        accumulator_commitment: witness.accumulator_commitment,
        target_epoch: witness.target_epoch,
        target_root: witness.target_root,
        attesting_balance: attested.attesting_balance,
        counted_validators_commitment: zkasper_common::acc::commit_indices(
            &attested.counted_indices,
        ),
        num_counted_validators: attested.counted_indices.len() as u64,
        miller_commitment: zkasper_common::acc::commit_fp12(&attested.miller),
    }
}

/// Run a slot/group witness's checks and return what they established, Miller
/// accumulator included.
///
/// The accumulator never appears in a proof's public outputs — it is 576 bytes
/// against a 256-byte budget — so the host recomputes it here, natively, to feed
/// the parent proof as witness. Recomputing is safe: the parent checks it
/// against the commitment the child published, so a host that got it wrong
/// produces a proof that fails rather than one that lies.
pub fn attest(witness: &SlotProofWitness, acc_depth: u32) -> Attested {
    // Verify the accumulator commitment binds acc_root + total_active_balance
    assert_eq!(
        zkasper_common::acc::commitment(&witness.acc_root, witness.total_active_balance),
        witness.accumulator_commitment,
        "accumulator commitment mismatch",
    );

    verify_attestations(
        &witness.attestations,
        &witness.acc_root,
        &witness.acc_multi_proof,
        witness.target_epoch,
        &witness.target_root,
        &witness.signing_domain,
        acc_depth,
    )
}

/// Verify attestations against the accumulator and accumulate their pairings.
///
/// Shared by the slot proof, the group proof, and the marginal attestations the
/// final proof of an epoch does inline — the last of which is the only place
/// this work sits on the critical path, so there is exactly one implementation
/// of it.
///
/// 1. Opens every attester's accumulator leaf in one batched multi-proof.
/// 2. Sums the balances of validators marked `count_balance`, rejecting
///    duplicates.
/// 3. Recomputes each `AttestationData` root and folds every signature into one
///    Miller-loop accumulator.
pub fn verify_attestations(
    attestations: &[AttestationWitness],
    acc_root: &Digest,
    acc_multi_proof: &AccMultiProof,
    target_epoch: u64,
    target_root: &[u8; 32],
    signing_domain: &[u8; 32],
    acc_depth: u32,
) -> Attested {
    use zkasper_common::acc;
    use zkasper_common::bls::{compute_signing_root, miller_accumulator, SignedMessage};

    // Phase 1: Collect the accumulator leaves the attestations claim.
    //
    // Membership is proven for *every* attester, not just the ones whose
    // balance is counted. Two reasons. The witness generator builds the
    // multi-proof over every attester, so proving a subset leaves auxiliaries
    // unconsumed and the batch aborts. More importantly, Phase 3 aggregates the
    // public keys of every attester: a key that is never opened against the
    // accumulator is a key the prover chose freely, which is a rogue-key
    // opening. `count_balance` governs the balance sum only.
    let mut attesting_balance: u64 = 0;
    let mut multi_proof_leaves: Vec<(acc::Digest, u64)> = Vec::new();
    let mut counted_indices: Vec<u64> = Vec::new();

    for attestation in attestations {
        let mut last_index: Option<u64> = None;

        for v in &attestation.attesting_validators {
            // Enforce strictly increasing validator indices within each attestation
            if let Some(prev) = last_index {
                assert!(
                    v.validator_index > prev,
                    "validator indices must be strictly increasing: {} followed {}",
                    v.validator_index,
                    prev,
                );
            }
            last_index = Some(v.validator_index);

            multi_proof_leaves.push((
                acc::leaf(&v.pubkey, v.active_effective_balance),
                v.validator_index,
            ));

            if v.count_balance {
                attesting_balance += v.active_effective_balance;
                counted_indices.push(v.validator_index);
            }
        }
    }

    // A validator may appear in more than one aggregate in the same group. The
    // accumulator leaf is a function of the validator alone, so duplicates are
    // identical and collapse; the batch scan requires strictly increasing
    // indices.
    multi_proof_leaves.sort_unstable_by_key(|&(_, idx)| idx);
    multi_proof_leaves.dedup_by_key(|&mut (_, idx)| idx);

    // Every counted validator must be distinct — this is what stops a balance
    // from being counted twice inside the group. Across groups, the counted-set
    // tree does the same job.
    counted_indices.sort_unstable();
    for i in 1..counted_indices.len() {
        assert!(
            counted_indices[i] > counted_indices[i - 1],
            "duplicate validator counted: {}",
            counted_indices[i],
        );
    }

    // Phase 2: Check every claimed leaf against the accumulator root at once
    assert_eq!(
        zkasper_common::merkle::batch_root(
            acc::compress,
            &multi_proof_leaves,
            &acc_multi_proof.auxiliaries,
            acc_depth,
        ),
        *acc_root,
        "accumulator root mismatch",
    );

    // Phase 3: Fold every attestation's signature into one Miller accumulator.
    //
    // Each distinct message contributes one Miller loop, plus one for the
    // group's summed signature.
    let mut pubkeys_per_attestation: Vec<Vec<acc::G1Point>> =
        Vec::with_capacity(attestations.len());
    let mut signing_roots: Vec<[u8; 32]> = Vec::with_capacity(attestations.len());

    for attestation in attestations {
        assert_eq!(
            attestation.data_target_epoch, target_epoch,
            "attestation target_epoch mismatch",
        );
        assert_eq!(
            attestation.data_target_root, *target_root,
            "attestation target_root mismatch",
        );

        let data_root = zkasper_common::ssz::attestation_data_root(
            attestation.data_slot,
            attestation.data_index,
            &attestation.data_beacon_block_root,
            attestation.data_source_epoch,
            &attestation.data_source_root,
            attestation.data_target_epoch,
            &attestation.data_target_root,
        );

        signing_roots.push(compute_signing_root(&data_root, signing_domain));
        pubkeys_per_attestation.push(
            attestation
                .attesting_validators
                .iter()
                .map(|v| v.pubkey)
                .collect(),
        );
    }

    let messages: Vec<SignedMessage> = attestations
        .iter()
        .enumerate()
        .map(|(i, a)| SignedMessage {
            pubkeys: &pubkeys_per_attestation[i],
            signing_root: &signing_roots[i],
            signature: &a.signature.0,
        })
        .collect();

    let miller = miller_accumulator(&messages).expect("BLS pairing inputs rejected");

    Attested {
        attesting_balance,
        counted_indices,
        miller,
    }
}
