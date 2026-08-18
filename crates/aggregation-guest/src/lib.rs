//! Aggregation: extend an epoch's running state with finished group proofs.
//!
//! # What a running aggregate is
//!
//! An epoch's attestations arrive over 384 seconds and are proven in groups as
//! they land. This proof is the join: it takes the aggregate produced by the
//! previous join and however many group proofs have finished since, and
//! produces the next aggregate. Its output is three running values —
//!
//! - `attesting_balance`, the deduplicated weight behind the target,
//! - `dedup_root`, which validators that weight came from,
//! - `miller_commitment`, the product of every folded group's Miller-loop
//!   accumulator,
//!
//! — plus the checkpoint they are all about.
//!
//! # Why the work here is proportional to what is added
//!
//! Everything in the fold scales with the groups being folded, not with what
//! has already accumulated. Balances add. Miller accumulators multiply, at
//! 141,090 each. The counted set is a bitmap tree, so marking a group's
//! attesters opens only the leaves they fall in.
//!
//! That is the property the pipeline needs: the join that runs after the last
//! attestation of the epoch must not be a function of the whole epoch, or the
//! epoch's size would be back on the critical path.

extern crate alloc;

use alloc::vec::Vec;

use zkasper_common::acc;
use zkasper_common::bls::{fp12_mul, Fp12, FP12_ONE};
use zkasper_common::dedup;
use zkasper_common::recursion::verify_child;
use zkasper_common::types::{AggregateOutput, AggregateWitness, EpochDiffOutput, GroupProofOutput};

/// Fold group proofs into a running aggregate.
pub fn verify_aggregate(witness: &AggregateWitness) -> AggregateOutput {
    verify_aggregate_with_depth(
        witness,
        dedup::tree_depth(zkasper_common::constants::ACC_TREE_DEPTH),
    )
}

/// Aggregation with a configurable counted-set tree depth.
pub fn verify_aggregate_with_depth(
    witness: &AggregateWitness,
    dedup_depth: u32,
) -> AggregateOutput {
    assert!(
        !witness.groups.is_empty(),
        "aggregation proof folds no groups",
    );
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

    // The aggregate being extended. Absent means the epoch opens here: nothing
    // counted, an empty counted-set tree, an empty product of pairings, and the
    // epoch diff still to be verified.
    let (previous_accumulator_commitment, anchor_state_root) = match &witness.previous {
        Some(previous) => (
            previous.previous_accumulator_commitment,
            previous.anchor_state_root,
        ),
        None => epoch_link(
            witness.epoch_diff.as_ref(),
            &witness.epoch_diff_proof,
            &witness.epoch_diff_program_vk,
            &witness.accumulator_commitment,
            witness.target_epoch,
        ),
    };

    let (mut attesting_balance, mut dedup_root, mut num_counted, mut miller) =
        match &witness.previous {
            Some(previous) => {
                assert!(
                    verify_child(
                        &witness.previous_proof,
                        &witness.aggregate_program_vk,
                        &previous.public_bytes(),
                    ),
                    "previous aggregate failed recursive verification",
                );
                assert_eq!(
                    previous.accumulator_commitment, witness.accumulator_commitment,
                    "previous aggregate accumulator mismatch",
                );
                assert_eq!(
                    previous.target_epoch, witness.target_epoch,
                    "previous aggregate target_epoch mismatch",
                );
                assert_eq!(
                    previous.target_root, witness.target_root,
                    "previous aggregate target_root mismatch",
                );
                assert_eq!(
                    acc::commit_fp12(&witness.previous_miller.0),
                    previous.miller_commitment,
                    "previous aggregate Miller accumulator does not match its commitment",
                );
                (
                    previous.attesting_balance,
                    previous.dedup_root,
                    previous.num_counted_validators,
                    witness.previous_miller.0,
                )
            }
            None => (0u64, dedup::empty_root(dedup_depth), 0u64, FP12_ONE),
        };

    let mut added: Vec<u64> = Vec::new();

    for (i, group) in witness.groups.iter().enumerate() {
        let indices = &witness.counted_indices_per_group[i];
        let miller_i = &witness.group_millers[i].0;

        verify_group(
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
        num_counted += group.num_counted_validators;
        miller = fp12_mul(&miller, miller_i);
        added.extend_from_slice(indices);
    }

    // Mark every validator counted here. `apply` proves each one was clear
    // beforehand, which is what makes the balances additive across the whole
    // chain of aggregates: a validator already counted by an earlier fold, or by
    // another group in this one, fails here.
    added.sort_unstable();
    let update = dedup::apply(&added, &witness.dedup_proof, dedup_depth)
        .expect("validator counted twice, or malformed counted-set proof");
    assert_eq!(
        update.old_root, dedup_root,
        "counted-set proof does not open the running root",
    );
    dedup_root = update.new_root;

    AggregateOutput {
        accumulator_commitment: witness.accumulator_commitment,
        previous_accumulator_commitment,
        anchor_state_root,
        target_epoch: witness.target_epoch,
        target_root: witness.target_root,
        attesting_balance,
        dedup_root,
        num_counted_validators: num_counted,
        miller_commitment: acc::commit_fp12(&miller),
    }
}

/// Verify one group proof and everything the parent needs to bind about it.
///
/// Shared with the final proof, which absorbs group proofs that finished too
/// late to be folded.
#[allow(clippy::too_many_arguments)]
pub fn verify_group(
    group: &GroupProofOutput,
    proof: &[u64],
    program_vk: &zkasper_common::recursion::ProgramVk,
    accumulator_commitment: acc::Digest,
    target_epoch: u64,
    target_root: &[u8; 32],
    counted_indices: &[u64],
    miller: &Fp12,
    position: usize,
) {
    assert!(
        verify_child(proof, program_vk, &group.public_bytes()),
        "group proof {position} failed recursive verification",
    );
    assert_eq!(
        group.accumulator_commitment, accumulator_commitment,
        "group proof {position} accumulator mismatch",
    );
    assert_eq!(
        group.target_epoch, target_epoch,
        "group proof {position} target_epoch mismatch",
    );
    assert_eq!(
        group.target_root, *target_root,
        "group proof {position} target_root mismatch",
    );

    // The group's Miller accumulator travels as witness because 576 bytes do not
    // fit in a proof's public outputs. Binding it to the commitment the group
    // published is what makes it the group's accumulator rather than one the
    // prover picked.
    assert_eq!(
        acc::commit_fp12(miller),
        group.miller_commitment,
        "group proof {position} Miller accumulator does not match its commitment",
    );

    // Same for the counted indices: the group published a sponge over them.
    assert_eq!(
        counted_indices.len() as u64,
        group.num_counted_validators,
        "group proof {position} counted validator count mismatch",
    );
    assert_eq!(
        acc::commit_indices(counted_indices),
        group.counted_validators_commitment,
        "group proof {position} counted validators commitment mismatch",
    );
    for j in 1..counted_indices.len() {
        assert!(
            counted_indices[j] > counted_indices[j - 1],
            "group proof {position} indices not strictly increasing",
        );
    }
}

/// Verify the epoch diff that carries the previous epoch's accumulator to this
/// one's, and return what the finalization will need from it.
///
/// The accumulator leaf commits an *effective balance*, which the beacon chain
/// rewrites at every epoch transition, so the two justifications of a finalizing
/// pair are never proved against the same accumulator on a live chain. The diff
/// is what makes the pair meaningful: without it a prover could pair an honest
/// justification of E+1 with a justification of E made against a fabricated
/// validator set.
///
/// It is verified here, in the fold that opens the epoch, rather than in the
/// final proof, because the diff exists at the epoch boundary and waiting until
/// the last attestation would put a recursive verification on the critical path
/// for no reason.
pub fn epoch_link(
    diff: Option<&EpochDiffOutput>,
    proof: &[u64],
    program_vk: &zkasper_common::recursion::ProgramVk,
    accumulator_commitment: &acc::Digest,
    target_epoch: u64,
) -> (acc::Digest, [u8; 32]) {
    let diff = diff.expect("an epoch's first aggregation must carry the epoch diff");

    assert!(
        verify_child(proof, program_vk, &diff.public_bytes()),
        "epoch diff proof failed recursive verification",
    );
    assert_eq!(
        diff.accumulator_commitment, *accumulator_commitment,
        "epoch diff does not end at the accumulator this epoch is proven against",
    );

    // The diff's epoch labels decide which validators it treats as active, so a
    // prover who mislabels them gets a different accumulator. They are pinned to
    // this epoch and the one before it; the target epoch is signed over by every
    // attester, so it is not something a prover picks.
    assert_eq!(
        diff.epoch_2, target_epoch,
        "epoch diff ends at epoch {} but epoch {target_epoch} is being proven",
        diff.epoch_2,
    );
    assert_eq!(
        diff.epoch_1 + 1,
        target_epoch,
        "epoch diff starts at epoch {} rather than the epoch before {target_epoch}",
        diff.epoch_1,
    );

    (diff.prev_accumulator_commitment, diff.state_root_1)
}
