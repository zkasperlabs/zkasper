extern crate alloc;

use alloc::vec::Vec;
use zkasper_common::types::{JustificationOutput, JustificationWitness};

/// Verify a justification: aggregate slot proofs, dedup validators, check 2/3.
pub fn verify_justification(witness: &JustificationWitness) -> JustificationOutput {
    use zkasper_common::acc;
    use zkasper_common::recursion::verify_child;

    assert!(
        !witness.slot_proof_outputs.is_empty(),
        "no slot proofs provided",
    );
    assert_eq!(
        witness.slot_proof_outputs.len(),
        witness.counted_indices_per_slot.len(),
        "slot_proof_outputs and counted_indices_per_slot length mismatch",
    );

    let mut total_attesting_balance: u64 = 0;

    // Phase 1: Verify each slot proof and its counted-validators commitment
    for (i, slot_output) in witness.slot_proof_outputs.iter().enumerate() {
        // Verify the slot proof, and bind it to this exact program and these
        // exact outputs — a proof of a different slot must not be accepted.
        assert!(
            verify_child(
                &witness.slot_proofs[i],
                &witness.slot_program_vk,
                &slot_output.public_bytes(),
            ),
            "slot proof {} failed recursive verification",
            i,
        );

        // Verify all slot proofs target the same checkpoint and accumulator
        assert_eq!(
            slot_output.accumulator_commitment, witness.accumulator_commitment,
            "slot proof {} accumulator mismatch",
            i,
        );
        assert_eq!(
            slot_output.target_epoch, witness.target_epoch,
            "slot proof {} target_epoch mismatch",
            i,
        );
        assert_eq!(
            slot_output.target_root, witness.target_root,
            "slot proof {} target_root mismatch",
            i,
        );

        // Re-hash the counted indices to verify they match the slot's commitment
        let indices = &witness.counted_indices_per_slot[i];
        assert_eq!(
            indices.len() as u64,
            slot_output.num_counted_validators,
            "slot proof {} counted validator count mismatch",
            i,
        );
        let recomputed = acc::commit_indices(indices);
        assert_eq!(
            recomputed, slot_output.counted_validators_commitment,
            "slot proof {} counted validators commitment mismatch",
            i,
        );

        // Verify indices are sorted within this slot
        for j in 1..indices.len() {
            assert!(
                indices[j] > indices[j - 1],
                "slot proof {} indices not strictly increasing: {} followed {}",
                i,
                indices[j - 1],
                indices[j],
            );
        }

        total_attesting_balance += slot_output.attesting_balance;
    }

    // Phase 2: Cross-slot dedup — merge sorted per-slot indices, verify globally unique
    let mut all_indices: Vec<u64> = Vec::new();
    for indices in &witness.counted_indices_per_slot {
        all_indices.extend_from_slice(indices);
    }
    all_indices.sort_unstable();

    for i in 1..all_indices.len() {
        assert!(
            all_indices[i] > all_indices[i - 1],
            "cross-slot duplicate validator: {}",
            all_indices[i],
        );
    }

    // Phase 3: Supermajority check
    assert!(
        total_attesting_balance as u128 * 3 >= witness.total_active_balance as u128 * 2,
        "insufficient attesting balance: {} / {} ({:.1}%)",
        total_attesting_balance,
        witness.total_active_balance,
        total_attesting_balance as f64 / witness.total_active_balance as f64 * 100.0,
    );

    JustificationOutput {
        accumulator_commitment: witness.accumulator_commitment,
        target_epoch: witness.target_epoch,
        target_root: witness.target_root,
    }
}
