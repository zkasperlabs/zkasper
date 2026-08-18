extern crate alloc;

use zkasper_common::types::{JustificationOutput, JustificationWitness};

/// Verify a justification: aggregate slot proofs, dedup slots, check 2/3.
pub fn verify_justification(witness: &JustificationWitness) -> JustificationOutput {
    use zkasper_common::recursion::verify_child;

    assert!(
        !witness.slot_proof_outputs.is_empty(),
        "no slot proofs provided",
    );

    // Every slot proof counted against this committee proof, which is what makes
    // the slot mask below a deduplication of validators rather than of slots.
    let committee_root = zkasper_aggregation_guest::committee_link(
        Some(&witness.committee),
        &witness.committee_proof,
        &witness.committee_program_vk,
        &witness.accumulator_commitment,
        witness.target_epoch,
    );

    let mut total_attesting_balance: u64 = 0;
    let mut slots_mask: u64 = 0;

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

        // Verify all slot proofs target the same checkpoint, accumulator and
        // committee partition
        assert_eq!(
            slot_output.accumulator_commitment, witness.accumulator_commitment,
            "slot proof {} accumulator mismatch",
            i,
        );
        assert_eq!(
            slot_output.committee_root, committee_root,
            "slot proof {} committee mismatch",
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

        // Cross-slot deduplication. A committee proof assigns every validator to
        // exactly one slot, so a slot counted once is a validator counted once.
        assert_eq!(
            slots_mask & slot_output.slots_mask,
            0,
            "slot proof {i} counts a slot that was already counted",
        );
        slots_mask |= slot_output.slots_mask;

        total_attesting_balance += slot_output.attesting_balance;
    }

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
