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
//! - `slots_mask`, which attestation slots that weight came from,
//! - `miller_commitment`, the product of every folded group's Miller-loop
//!   accumulator,
//!
//! — plus the checkpoint they are all about.
//!
//! # Why the work here is proportional to what is added
//!
//! Everything in the fold scales with the groups being folded, not with what
//! has already accumulated. Balances add. Miller accumulators multiply, at
//! 737,503 each. Deduplication is a 32-bit mask, because the committee proof
//! assigns every validator to exactly one slot: counting a slot at most once is
//! counting a validator at most once, and the check is an `AND` against zero.
//!
//! That is the property the pipeline needs: the join that runs after the last
//! attestation of the epoch must not be a function of the whole epoch, or the
//! epoch's size would be back on the critical path.
//!
//! # Why the committee root is carried
//!
//! The disjointness that makes the mask sufficient is a property of *one*
//! committee proof. Two committee proofs of the same epoch partition the same
//! validators differently, and a fold that took slot 3 from one and slot 7 from
//! the other could count a validator twice. Every group therefore publishes the
//! committee root it counted against, and the fold requires them all equal.

extern crate alloc;

pub mod child_vks;

use zkasper_common::acc;
use zkasper_common::bls::{fp12_mul, Fp12, FP12_ONE};
use zkasper_common::recursion::{verify_baked_child, verify_child};
use zkasper_common::types::{
    AggregateOutput, AggregateWitness, CommitteeOutput, EpochDiffOutput, GroupProofOutput,
};

/// Fold group proofs into a running aggregate.
pub fn verify_aggregate(witness: &AggregateWitness) -> AggregateOutput {
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

    let checkpoint_digest = zkasper_common::ssz::checkpoint_digest(
        witness.source_epoch,
        &witness.source_root,
        witness.target_epoch,
        &witness.target_root,
    );

    // The aggregate being extended. Absent means the epoch opens here: nothing
    // counted, an empty slot mask, an empty product of pairings, and the epoch
    // diff still to be verified.
    let (previous_accumulator_commitment, anchor_state_root, committee_root) =
        match &witness.previous {
            Some(previous) => (
                previous.previous_accumulator_commitment,
                previous.anchor_state_root,
                previous.committee_root,
            ),
            None => {
                let (previous_accumulator_commitment, anchor_state_root) = epoch_link(
                    witness.epoch_diff.as_ref(),
                    &witness.epoch_diff_proof,
                    &witness.accumulator_commitment,
                    witness.target_epoch,
                );
                (
                    previous_accumulator_commitment,
                    anchor_state_root,
                    committee_link(
                        witness.committee.as_ref(),
                        &witness.committee_proof,
                        &witness.accumulator_commitment,
                        witness.target_epoch,
                    ),
                )
            }
        };

    let (mut attesting_balance, mut slots_mask, mut miller) = match &witness.previous {
        Some(previous) => {
            assert!(
                verify_child(
                    &witness.previous_proof,
                    &witness.aggregate_program_vk,
                    &previous.public_bytes(),
                ),
                "previous aggregate failed recursive verification",
            );
            // The one key a program cannot bake is its own, so the chain agrees
            // on one instead and publishes it. `stream-final-guest` bakes this
            // key and compares the published value against it, which is what
            // ties the agreed key to the real program.
            assert_eq!(
                previous.program_vk, witness.aggregate_program_vk,
                "previous aggregate was produced by a different program",
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
                previous.checkpoint_digest, checkpoint_digest,
                "previous aggregate checkpoint mismatch",
            );
            assert_eq!(
                acc::commit_fp12(&witness.previous_miller.0),
                previous.miller_commitment,
                "previous aggregate Miller accumulator does not match its commitment",
            );
            (
                previous.attesting_balance,
                previous.slots_mask,
                witness.previous_miller.0,
            )
        }
        None => (0u64, 0u64, FP12_ONE),
    };

    for (i, group) in witness.groups.iter().enumerate() {
        let miller_i = &witness.group_millers[i].0;

        verify_group(
            group,
            &witness.group_proofs[i],
            witness.accumulator_commitment,
            committee_root,
            witness.source_epoch,
            &witness.source_root,
            witness.target_epoch,
            &witness.target_root,
            miller_i,
            i,
        );

        // A slot already counted, by an earlier fold or by another group in this
        // one, is what makes balances additive across the whole chain — and it
        // is a validator counted twice, because the committee proof gave that
        // validator exactly one slot.
        assert_eq!(
            slots_mask & group.slots_mask,
            0,
            "group proof {i} counts a slot that was already counted",
        );
        slots_mask |= group.slots_mask;

        attesting_balance += group.attesting_balance;
        miller = fp12_mul(&miller, miller_i);
    }

    AggregateOutput {
        accumulator_commitment: witness.accumulator_commitment,
        committee_root,
        previous_accumulator_commitment,
        anchor_state_root,
        target_epoch: witness.target_epoch,
        checkpoint_digest,
        attesting_balance,
        slots_mask,
        miller_commitment: acc::commit_fp12(&miller),
        program_vk: witness.aggregate_program_vk,
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
    accumulator_commitment: acc::Digest,
    committee_root: acc::Digest,
    source_epoch: u64,
    source_root: &[u8; 32],
    target_epoch: u64,
    target_root: &[u8; 32],
    miller: &Fp12,
    position: usize,
) {
    assert!(
        verify_baked_child(proof, &child_vks::GROUP_PROGRAM_VK, &group.public_bytes(),),
        "group proof {position} failed recursive verification",
    );
    assert_eq!(
        group.accumulator_commitment, accumulator_commitment,
        "group proof {position} accumulator mismatch",
    );
    assert_eq!(
        group.committee_root, committee_root,
        "group proof {position} committee mismatch",
    );
    assert_eq!(
        group.source_epoch, source_epoch,
        "group proof {position} source_epoch mismatch",
    );
    assert_eq!(
        group.source_root, *source_root,
        "group proof {position} source_root mismatch",
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
    accumulator_commitment: &acc::Digest,
    target_epoch: u64,
) -> (acc::Digest, [u8; 32]) {
    let diff = diff.expect("an epoch's first aggregation must carry the epoch diff");

    assert!(
        verify_baked_child(
            proof,
            &child_vks::EPOCH_DIFF_PROGRAM_VK,
            &diff.public_bytes(),
        ),
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

/// Verify the committee proof this epoch's slot buckets came from, and return
/// the root every group has to have counted against.
///
/// Verified once, in the fold that opens the epoch, for the same reason the diff
/// is: the committee for an epoch is fixed two epochs earlier, so waiting until
/// the last attestation would put a recursive verification on the critical path
/// for nothing.
///
/// One proof is not a detail. The slot mask deduplicates validators only because
/// a single committee proof puts each validator in exactly one slot; two
/// partitions of the same epoch overlap, so exactly one of them may be in play.
pub fn committee_link(
    committee: Option<&CommitteeOutput>,
    proof: &[u64],
    accumulator_commitment: &acc::Digest,
    target_epoch: u64,
) -> acc::Digest {
    let committee = committee.expect("an epoch's first aggregation must carry the committee proof");

    assert!(
        verify_baked_child(
            proof,
            &child_vks::COMMITTEE_PROGRAM_VK,
            &committee.public_bytes(),
        ),
        "committee proof failed recursive verification",
    );
    assert_eq!(
        committee.accumulator_commitment, *accumulator_commitment,
        "committee proof was built against a different accumulator",
    );
    assert_eq!(
        committee.target_epoch, target_epoch,
        "committee proof covers epoch {} but epoch {target_epoch} is being proven",
        committee.target_epoch,
    );

    committee.committee_root
}
