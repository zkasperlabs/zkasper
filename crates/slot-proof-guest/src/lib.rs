extern crate alloc;

use alloc::vec::Vec;
use zkasper_common::types::{SlotProofOutput, SlotProofWitness};

/// Verify a single slot's attestations and produce a SlotProofOutput.
///
/// This is the core slot-proof circuit logic. It:
/// 1. Verifies the accumulator commitment
/// 2. Verifies each validator against the accumulator in one batched proof
/// 3. Verifies every attestation signature in a single multi-pairing
/// 4. Computes a commitment over counted validator indices (for cross-slot dedup)
///
/// Does NOT check supermajority — that's the justification proof's job.
pub fn verify_slot_proof(witness: &SlotProofWitness) -> SlotProofOutput {
    verify_slot_proof_with_depth(witness, zkasper_common::constants::ACC_TREE_DEPTH)
}

/// Slot-proof verification with a configurable accumulator tree depth.
pub fn verify_slot_proof_with_depth(witness: &SlotProofWitness, acc_depth: u32) -> SlotProofOutput {
    use zkasper_common::acc;
    use zkasper_common::bls::{compute_signing_root, verify_attestation_batch, SignedMessage};

    // Verify the accumulator commitment binds acc_root + total_active_balance
    let expected_commitment = acc::commitment(&witness.acc_root, witness.total_active_balance);
    assert_eq!(
        expected_commitment, witness.accumulator_commitment,
        "accumulator commitment mismatch",
    );

    // Phase 1: Collect the accumulator leaves the attestations claim.
    let mut attesting_balance: u64 = 0;
    let mut multi_proof_leaves: Vec<(zkasper_common::acc::Digest, u64)> = Vec::new();
    let mut counted_indices: Vec<u64> = Vec::new();

    for attestation in &witness.attestations {
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

            if v.count_balance {
                attesting_balance += v.active_effective_balance;
                counted_indices.push(v.validator_index);

                let leaf = acc::leaf(&v.pubkey.0, v.active_effective_balance);
                multi_proof_leaves.push((leaf, v.validator_index));
            }
        }
    }

    // Sort multi-proof leaves by validator index
    multi_proof_leaves.sort_unstable_by_key(|&(_, idx)| idx);

    // Verify no duplicate validator was counted
    for i in 1..multi_proof_leaves.len() {
        assert!(
            multi_proof_leaves[i].1 > multi_proof_leaves[i - 1].1,
            "duplicate validator counted: {}",
            multi_proof_leaves[i].1,
        );
    }

    // Phase 2: Check every claimed leaf against the accumulator root at once
    let computed_root = zkasper_common::merkle::batch_root(
        acc::compress,
        &multi_proof_leaves,
        &witness.acc_multi_proof.auxiliaries,
        acc_depth,
    );
    assert_eq!(computed_root, witness.acc_root, "accumulator root mismatch",);

    // Phase 3: Verify every attestation's signature in one multi-pairing.
    //
    // Each attestation contributes one Miller loop; the final exponentiation —
    // the dominant cost by a wide margin — happens once for the whole slot.
    let mut pubkeys_per_attestation: Vec<Vec<[u8; 48]>> =
        Vec::with_capacity(witness.attestations.len());
    let mut signing_roots: Vec<[u8; 32]> = Vec::with_capacity(witness.attestations.len());

    for attestation in &witness.attestations {
        assert_eq!(
            attestation.data_target_epoch, witness.target_epoch,
            "attestation target_epoch mismatch",
        );
        assert_eq!(
            attestation.data_target_root, witness.target_root,
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

        signing_roots.push(compute_signing_root(&data_root, &witness.signing_domain));
        pubkeys_per_attestation.push(
            attestation
                .attesting_validators
                .iter()
                .map(|v| v.pubkey.0)
                .collect(),
        );
    }

    let messages: Vec<SignedMessage> = witness
        .attestations
        .iter()
        .enumerate()
        .map(|(i, a)| SignedMessage {
            pubkeys: &pubkeys_per_attestation[i],
            signing_root: &signing_roots[i],
            signature: &a.signature.0,
        })
        .collect();

    assert!(
        verify_attestation_batch(&messages),
        "BLS aggregate signature verification failed",
    );

    // Phase 4: Compute counted validators commitment
    counted_indices.sort_unstable();
    let commitment = acc::commit_indices(&counted_indices);

    SlotProofOutput {
        accumulator_commitment: witness.accumulator_commitment,
        target_epoch: witness.target_epoch,
        target_root: witness.target_root,
        attesting_balance,
        counted_validators_commitment: commitment,
        num_counted_validators: counted_indices.len() as u64,
    }
}
