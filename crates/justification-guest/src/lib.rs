//! Justification: extend an epoch's running claim with finished slot proofs.
//!
//! # Why this is a chain and not one proof
//!
//! It used to be one proof over the whole epoch: ~22 slot proofs verified
//! recursively in a single circuit. Measured on an RTX 5090 that cost
//! **1,221,655 ms** against a 384 s epoch — 90.6% of everything the epoch spent
//! on proving, and more than twenty times the next stage. Recursion is not free
//! and it is not linear: `BENCHMARKS.md` has the curve.
//!
//! So this is shaped like [`zkasper_aggregation_guest`], which had the same
//! problem and solved it first. Each proof verifies its predecessor and a
//! bounded number of slot proofs, and publishes the running state — balance,
//! slot mask, and whether two thirds is behind them yet. The work per proof is
//! a function of what is folded, never of what has already accumulated, so the
//! epoch's size leaves the trace of any one proof.
//!
//! # What holds the chain together
//!
//! Three things, and each is the reason a fold cannot be reordered or forged:
//!
//! - **The balance is bound to the accumulator.** Every link rehashes
//!   `acc::commitment(acc_root, total_active_balance)` against the commitment it
//!   was proven under, and requires the predecessor to carry the same
//!   commitment. The two-thirds gate therefore divides by the balance the
//!   accumulator commits to, in every link, and not one the prover chose.
//! - **One committee proof partitions the epoch.** The opening fold verifies it
//!   and publishes its root; later folds inherit that root and require every
//!   slot proof to have counted against it. Two committee proofs of one epoch
//!   assign validators differently, and a chain that took slot 3 from one and
//!   slot 7 from the other could count a validator twice.
//! - **A slot is counted once.** `slots_mask` is a 32-bit union across the whole
//!   chain, checked with an `AND` against zero. Because the committee proof puts
//!   each validator in exactly one slot, a slot counted once is a validator
//!   counted once.
//!
//! # `justified` is computed, and the consumer checks it
//!
//! A partial fold is a valid proof — the chain would have no middle otherwise —
//! so "a justification proof exists" no longer means "the epoch is justified".
//! The supermajority is therefore a published output rather than an assert, and
//! it is *computed* from the bound balance, so a set flag claims exactly what
//! the old assert claimed. See [`JustificationOutput::justified`].

extern crate alloc;

use zkasper_common::types::{JustificationOutput, JustificationWitness};

/// Fold slot proofs into a running justification.
pub fn verify_justification(witness: &JustificationWitness) -> JustificationOutput {
    use zkasper_common::recursion::verify_child;

    assert!(
        !witness.slot_proof_outputs.is_empty(),
        "justification proof folds no slot proofs",
    );
    assert_eq!(
        witness.slot_proof_outputs.len(),
        witness.slot_proofs.len(),
        "slot outputs and proofs length mismatch",
    );

    // The two-thirds gate divides by `total_active_balance`, so it has to be the
    // balance the accumulator commits to and not one the prover picked. The slot
    // proofs bind their own copy; this binds the copy this proof divides by.
    assert_eq!(
        zkasper_common::acc::commitment(&witness.acc_root, witness.total_active_balance),
        witness.accumulator_commitment,
        "accumulator commitment mismatch",
    );

    // Every slot proof counted against this committee proof, which is what makes
    // the slot mask below a deduplication of validators rather than of slots.
    let committee_root = match &witness.previous {
        Some(previous) => previous.committee_root,
        None => zkasper_aggregation_guest::committee_link(
            witness.committee.as_ref(),
            &witness.committee_proof,
            &witness.committee_program_vk,
            &witness.accumulator_commitment,
            witness.target_epoch,
        ),
    };

    let (mut total_attesting_balance, mut slots_mask) = match &witness.previous {
        Some(previous) => {
            assert!(
                verify_child(
                    &witness.previous_proof,
                    &witness.justification_program_vk,
                    &previous.public_bytes(),
                ),
                "previous justification failed recursive verification",
            );
            assert_eq!(
                previous.accumulator_commitment, witness.accumulator_commitment,
                "previous justification accumulator mismatch",
            );
            assert_eq!(
                previous.target_epoch, witness.target_epoch,
                "previous justification target_epoch mismatch",
            );
            assert_eq!(
                previous.target_root, witness.target_root,
                "previous justification target_root mismatch",
            );
            (previous.attesting_balance, previous.slots_mask)
        }
        None => (0u64, 0u64),
    };

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

        // Cross-slot deduplication, across the whole chain and not only this
        // fold. A committee proof assigns every validator to exactly one slot,
        // so a slot counted once is a validator counted once.
        assert_eq!(
            slots_mask & slot_output.slots_mask,
            0,
            "slot proof {i} counts a slot that was already counted",
        );
        slots_mask |= slot_output.slots_mask;

        total_attesting_balance += slot_output.attesting_balance;
    }

    JustificationOutput {
        accumulator_commitment: witness.accumulator_commitment,
        committee_root,
        target_epoch: witness.target_epoch,
        target_root: witness.target_root,
        attesting_balance: total_attesting_balance,
        slots_mask,
        justified: total_attesting_balance as u128 * 3 >= witness.total_active_balance as u128 * 2,
    }
}
