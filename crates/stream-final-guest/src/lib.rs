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
//! It does not update the counted-set tree. Nothing is added after it, so the
//! new root would be thrown away; it only proves the attesters it counts were
//! not counted already, which is half the hashing.

extern crate alloc;

use alloc::vec::Vec;

use zkasper_common::acc;
use zkasper_common::bls::{fp12_mul, FP12_ONE};
use zkasper_common::dedup;
use zkasper_common::recursion::verify_child;
use zkasper_common::types::{StreamFinalOutput, StreamFinalWitness};

/// Verify the final proof of an epoch.
pub fn verify_stream_final(witness: &StreamFinalWitness) -> StreamFinalOutput {
    verify_stream_final_with_depth(witness, zkasper_common::constants::ACC_TREE_DEPTH)
}

/// Final-proof verification with a configurable accumulator tree depth.
pub fn verify_stream_final_with_depth(
    witness: &StreamFinalWitness,
    acc_depth: u32,
) -> StreamFinalOutput {
    let dedup_depth = dedup::tree_depth(acc_depth);

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
    let (previous_accumulator_commitment, anchor_state_root) = match &witness.aggregate {
        Some(aggregate) => (
            aggregate.previous_accumulator_commitment,
            aggregate.anchor_state_root,
        ),
        None => zkasper_aggregation_guest::epoch_link(
            witness.epoch_diff.as_ref(),
            &witness.epoch_diff_proof,
            &witness.epoch_diff_program_vk,
            &witness.accumulator_commitment,
            witness.target_epoch,
        ),
    };

    let (mut attesting_balance, dedup_root, mut miller) = match &witness.aggregate {
        Some(aggregate) => {
            assert!(
                verify_child(
                    &witness.aggregate_proof,
                    &witness.aggregate_program_vk,
                    &aggregate.public_bytes(),
                ),
                "aggregate failed recursive verification",
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
                aggregate.dedup_root,
                witness.aggregate_miller.0,
            )
        }
        None => (0u64, dedup::empty_root(dedup_depth), FP12_ONE),
    };

    let mut counted: Vec<u64> = Vec::new();

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
    assert_eq!(
        witness.groups.len(),
        witness.counted_indices_per_group.len(),
        "groups and counted index lists length mismatch",
    );

    for (i, group) in witness.groups.iter().enumerate() {
        let indices = &witness.counted_indices_per_group[i];
        let miller_i = &witness.group_millers[i].0;

        zkasper_aggregation_guest::verify_group(
            group,
            &witness.group_proofs[i],
            &witness.group_program_vk,
            witness.accumulator_commitment,
            witness.target_epoch,
            &witness.target_root,
            indices,
            miller_i,
            i,
        );

        attesting_balance += group.attesting_balance;
        miller = fp12_mul(&miller, miller_i);
        counted.extend_from_slice(indices);
    }

    // -- the marginal attestations, inline ------------------------------------
    //
    // This is the work that genuinely depends on the last attestation: opening
    // its attesters against the accumulator, aggregating their keys, hashing
    // their message to G2 and running two Miller loops. Everything else in this
    // proof is either recursion or arithmetic on values that were already fixed.
    if !witness.tail.is_empty() {
        let tail = zkasper_slot_proof_guest::verify_attestations(
            &witness.tail,
            &witness.acc_root,
            &witness.tail_acc_multi_proof,
            witness.target_epoch,
            &witness.target_root,
            &witness.signing_domain,
            acc_depth,
        );

        attesting_balance += tail.attesting_balance;
        miller = fp12_mul(&miller, &tail.miller);
        counted.extend_from_slice(&tail.counted_indices);
    }

    // -- nothing counted here was counted before ------------------------------
    counted.sort_unstable();
    assert!(
        dedup::verify_absent(&dedup_root, &counted, &witness.dedup_proof, dedup_depth),
        "validator counted twice, or malformed counted-set proof",
    );

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
    let previous = &witness.previous_justification;
    assert!(
        verify_child(
            &witness.previous_justification_proof,
            &witness.previous_program_vk,
            &previous.public_bytes(),
        ),
        "previous justification failed recursive verification",
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

    // Open the finalized block's header to recover its beacon state root.
    //
    // This is what anchors the accumulator chain. epoch-diff proves a registry
    // delta between two claimed state roots but never proves the second is the
    // canonical successor of the first, so a prover can branch the accumulator
    // onto a fabricated validator set. Publishing the state root of a block that
    // 2/3 of the real validator set attested to lets a consumer reject any
    // branch.
    let h = &witness.finalized_header;
    assert_eq!(
        zkasper_common::ssz::block_header_root(
            h.slot,
            h.proposer_index,
            &h.parent_root,
            &h.state_root,
            &h.body_root,
        ),
        previous.target_root(),
        "finalized header does not hash to the finalized root",
    );

    // ...and that state root must be the one the previous epoch's accumulator
    // was built from, which the epoch diff published as `state_root_1`. Pinning
    // them together is what lets a client check the accumulator chain against
    // the finalizations it sees, without a third source.
    assert_eq!(
        anchor_state_root, h.state_root,
        "the finalized epoch's accumulator was built from a different state than its block produced",
    );

    StreamFinalOutput {
        accumulator_commitment: previous_accumulator_commitment,
        next_accumulator_commitment: witness.accumulator_commitment,
        finalized_epoch: previous.target_epoch(),
        finalized_root: previous.target_root(),
        finalized_state_root: h.state_root,
        justified_epoch: witness.target_epoch,
        justified_root: witness.target_root,
    }
}
