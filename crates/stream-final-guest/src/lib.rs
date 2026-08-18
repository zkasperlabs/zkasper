//! The final proof of an epoch — the only one on the critical path.
//!
//! # What T2 − T is
//!
//! Call `T` the moment the network has published enough attestations to justify
//! the target, and `T2` the moment a postable proof exists. Everything between
//! them is latency a bridge cannot avoid paying, so the pipeline is built to put
//! as little as possible there. Everything else — accumulator membership for
//! 99% of attesters, every Miller loop but the last few, every fold of the
//! running aggregate — happens before `T`, against attestations that arrived
//! earlier.
//!
//! What is irreducibly left is this proof, and it does four things at once
//! rather than as four proofs:
//!
//! 1. verifies the running aggregate for this epoch,
//! 2. verifies the marginal attestations that carried it over the threshold,
//!    **inline** — no separate group proof, no extra recursion,
//! 3. runs the one final exponentiation that settles every signature in the
//!    epoch, and checks the supermajority,
//! 4. verifies the previous epoch's justification and emits the finalization.
//!
//! Done as a chain of four proofs — group, justification, finalization, wrap —
//! this would cost four per-proof floors of 293,601,280 and four sequential
//! prover startups. Collapsed, it costs one.
//!
//! # What it does not do
//!
//! It does not enumerate a single attester. The marginal slot arrives as a
//! committee aggregate minus its ~90 absentees, which is 790 accumulator nodes
//! where opening every attester was 190,706.

extern crate alloc;

pub mod child_vks;

use zkasper_common::acc;
use zkasper_common::bls::{fp12_mul, FP12_ONE};
use zkasper_common::recursion::{verify_baked_child, verify_child};
use zkasper_common::types::{PreviousJustification, StreamFinalOutput, StreamFinalWitness};

/// Verify the final proof of an epoch.
pub fn verify_stream_final(witness: &StreamFinalWitness) -> StreamFinalOutput {
    verify_stream_final_with_depth(witness, zkasper_common::constants::ACC_TREE_DEPTH)
}

/// Final-proof verification with a configurable accumulator tree depth.
pub fn verify_stream_final_with_depth(
    witness: &StreamFinalWitness,
    acc_depth: u32,
) -> StreamFinalOutput {
    verify_stream_final_with(
        witness,
        acc_depth,
        zkasper_common::constants::SLOTS_PER_EPOCH,
    )
}

/// The same, on a chain whose epoch is not 32 slots long.
pub fn verify_stream_final_with(
    witness: &StreamFinalWitness,
    acc_depth: u32,
    slots_per_epoch: u64,
) -> StreamFinalOutput {
    assert_eq!(
        acc::commitment(&witness.acc_root, witness.total_active_balance),
        witness.accumulator_commitment,
        "accumulator commitment mismatch",
    );

    // -- the running aggregate ------------------------------------------------
    //
    // The epoch diff that links the previous epoch's accumulator to this one's
    // was verified by the fold that opened the epoch, so all that is left here
    // is to read the link off the aggregate. An epoch with no aggregate at all —
    // one unit crossed the threshold on its own — has to verify the diff here
    // instead, which is the only path where that recursion is on the critical
    // path.
    let (previous_accumulator_commitment, anchor_state_root, committee_root) =
        match &witness.aggregate {
            Some(aggregate) => (
                aggregate.previous_accumulator_commitment,
                aggregate.anchor_state_root,
                aggregate.committee_root,
            ),
            None => {
                let (previous_accumulator_commitment, anchor_state_root) =
                    zkasper_aggregation_guest::epoch_link(
                        witness.epoch_diff.as_ref(),
                        &witness.epoch_diff_proof,
                        &witness.accumulator_commitment,
                        witness.target_epoch,
                    );
                (
                    previous_accumulator_commitment,
                    anchor_state_root,
                    zkasper_aggregation_guest::committee_link(
                        witness.committee.as_ref(),
                        &witness.committee_proof,
                        &witness.accumulator_commitment,
                        witness.target_epoch,
                    ),
                )
            }
        };

    let (mut attesting_balance, mut slots_mask, mut miller) = match &witness.aggregate {
        Some(aggregate) => {
            assert!(
                verify_baked_child(
                    &witness.aggregate_proof,
                    &child_vks::AGGREGATE_PROGRAM_VK,
                    &aggregate.public_bytes(),
                ),
                "aggregate failed recursive verification",
            );
            // The aggregate is itself the head of a fold chain that verified
            // its own links under a key it carries. Requiring that key to be
            // the constant this guest was compiled with is what pins every fold
            // below it to `aggregation-guest`.
            assert_eq!(
                aggregate.program_vk,
                child_vks::AGGREGATE_PROGRAM_VK,
                "the aggregate folds a chain pinned to a different program",
            );
            assert_eq!(
                aggregate.accumulator_commitment, witness.accumulator_commitment,
                "aggregate accumulator mismatch",
            );
            assert_eq!(
                aggregate.target_epoch, witness.target_epoch,
                "aggregate target_epoch mismatch",
            );
            assert_eq!(
                aggregate.target_root, witness.target_root,
                "aggregate target_root mismatch",
            );
            assert_eq!(
                acc::commit_fp12(&witness.aggregate_miller.0),
                aggregate.miller_commitment,
                "aggregate Miller accumulator does not match its commitment",
            );
            (
                aggregate.attesting_balance,
                aggregate.slots_mask,
                witness.aggregate_miller.0,
            )
        }
        None => (0u64, 0u64, FP12_ONE),
    };

    // -- group proofs that finished too late to be folded ---------------------
    assert_eq!(
        witness.groups.len(),
        witness.group_proofs.len(),
        "groups and proofs length mismatch",
    );
    assert_eq!(
        witness.groups.len(),
        witness.group_millers.len(),
        "groups and Miller accumulators length mismatch",
    );

    for (i, group) in witness.groups.iter().enumerate() {
        let miller_i = &witness.group_millers[i].0;

        zkasper_aggregation_guest::verify_group(
            group,
            &witness.group_proofs[i],
            witness.accumulator_commitment,
            committee_root,
            witness.target_epoch,
            &witness.target_root,
            miller_i,
            i,
        );

        assert_eq!(
            slots_mask & group.slots_mask,
            0,
            "group proof {i} counts a slot that was already counted",
        );
        slots_mask |= group.slots_mask;

        attesting_balance += group.attesting_balance;
        miller = fp12_mul(&miller, miller_i);
    }

    // -- the marginal slot, inline --------------------------------------------
    //
    // This is the work that genuinely depends on the last attestation: opening
    // the slot's committee aggregate and its absentees against the accumulator,
    // subtracting them, hashing the message to G2 and running two Miller loops.
    // Everything else in this proof is either recursion or arithmetic on values
    // that were already fixed.
    if !witness.tail.is_empty() {
        let tail = zkasper_slot_proof_guest::verify_attestations(
            &witness.tail,
            &witness.acc_root,
            &witness.tail_acc_multi_proof,
            &committee_root,
            &witness.tail_committee_multi_proof,
            witness.target_epoch,
            &witness.target_root,
            &witness.signing_domain,
            acc_depth,
        );

        assert_eq!(
            slots_mask & tail.slots_mask,
            0,
            "the marginal slot was already counted",
        );

        attesting_balance += tail.attesting_balance;
        miller = fp12_mul(&miller, &tail.miller);
    }

    // -- the one final exponentiation -----------------------------------------
    //
    // Until this line nothing in the epoch has proven a signature. Every group
    // proof, and the running aggregate that folded them, published a
    // Miller-loop accumulator and asserted nothing about it. `∏ e(Pᵢ,Qᵢ) =
    // FinalExp(∏ MillerLoop(Pᵢ,Qᵢ))`, so exponentiating the product settles all
    // of them at once — and it is only sound because the product covers every
    // group whose balance was added above. A group counted without its
    // accumulator, or an accumulator multiplied in without its balance, would
    // break the correspondence, which is why `verify_group` binds the two
    // together and why the running aggregate carries both.
    assert!(
        zkasper_common::bls::final_exp_is_one(&miller),
        "BLS aggregate signature verification failed",
    );

    // -- Casper's supermajority ----------------------------------------------
    //
    // Fixed at 2/3 in the circuit. The pipeline triggers this proof at a
    // configurable margin above it, but that is a scheduling choice made by the
    // witness generator; a prover that aimed lower would fail here.
    assert!(
        attesting_balance as u128 * 3 >= witness.total_active_balance as u128 * 2,
        "insufficient attesting balance: {} / {}",
        attesting_balance,
        witness.total_active_balance,
    );

    // -- and the previous epoch turns it into a finalization ------------------
    //
    // Which program proved the previous epoch depends on which pipeline ran it.
    // A batch justification is another guest, so its key is a constant here. A
    // stream final proof is *this* guest, and a program cannot contain its own
    // key, so that one key is still read from the witness — and published, so
    // that a verifier holding this program's key can require the two to agree.
    // See [`StreamFinalOutput::program_vk`].
    let previous = &witness.previous_justification;
    match previous {
        PreviousJustification::Batch(batch) => {
            assert!(
                verify_baked_child(
                    &witness.previous_justification_proof,
                    &child_vks::JUSTIFICATION_PROGRAM_VK,
                    &previous.public_bytes(),
                ),
                "previous justification failed recursive verification",
            );
            assert_eq!(
                batch.program_vk,
                child_vks::JUSTIFICATION_PROGRAM_VK,
                "the previous justification folds a chain pinned to a different program",
            );
        }
        PreviousJustification::Stream(stream) => {
            assert!(
                verify_child(
                    &witness.previous_justification_proof,
                    &witness.stream_program_vk,
                    &previous.public_bytes(),
                ),
                "previous justification failed recursive verification",
            );
            assert_eq!(
                stream.program_vk, witness.stream_program_vk,
                "the previous epoch's final proof names a different program",
            );
        }
    }
    // A batch justification is a link in a fold chain, and the partial links are
    // valid proofs of a partial count. Only a link that says two thirds is
    // behind it justifies anything.
    assert!(
        previous.is_justified(),
        "the previous epoch's justification is a partial fold, not a supermajority",
    );
    assert_eq!(
        previous.target_epoch() + 1,
        witness.target_epoch,
        "justification epochs not consecutive: {} and {}",
        previous.target_epoch(),
        witness.target_epoch,
    );
    assert_eq!(
        previous.accumulator_commitment(),
        previous_accumulator_commitment,
        "the finalized epoch was justified against an accumulator the epoch diff does not start from",
    );

    // Open the finalized epoch's boundary out of this epoch's checkpoint state.
    //
    // This is what anchors the accumulator chain. epoch-diff proves a registry
    // delta between two claimed state roots but never proves the second is the
    // canonical successor of the first, so a prover can branch the accumulator
    // onto a fabricated validator set. Publishing the state root of a boundary
    // that 2/3 of the real validator set attested past lets a consumer reject
    // any branch.
    //
    // The state opened is the one the previous epoch's accumulator was built
    // from, which the epoch diff published as `state_root_1`. Pinning them
    // together is what lets a client check the accumulator chain against the
    // finalizations it sees, without a third source.
    zkasper_common::ssz::open_boundary(
        &witness.boundary,
        previous.target_epoch(),
        &previous.target_root(),
        &witness.target_root,
        &anchor_state_root,
        slots_per_epoch,
    );

    StreamFinalOutput {
        accumulator_commitment: previous_accumulator_commitment,
        next_accumulator_commitment: witness.accumulator_commitment,
        finalized_epoch: previous.target_epoch(),
        finalized_root: previous.target_root(),
        finalized_state_root: anchor_state_root,
        justified_epoch: witness.target_epoch,
        justified_root: witness.target_root,
        program_vk: witness.stream_program_vk,
    }
}
