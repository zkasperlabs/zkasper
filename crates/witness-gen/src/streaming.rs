//! Streaming: cut an epoch into groups that shrink toward the threshold.
//!
//! # The quantity being minimised
//!
//! `T` is when the chain has published enough attestations to justify the
//! target. `T2` is when a postable proof exists. `T2 − T` is the only latency a
//! consumer sees, and it is *not* the cost of proving an epoch — it is the cost
//! of whatever still depends on the last attestation.
//!
//! Three things follow, and this module implements all three.
//!
//! **Groups shrink geometrically.** A fixed group of eight slots means eight
//! slots of work cannot begin until the eighth arrives, so eight slots of work
//! land on the critical path. Groups of 12, 6, 3, 1, 1, 1 cover the same span
//! and leave one slot there. The early groups are large because their work
//! starts early and has the rest of the epoch to finish; the late ones are small
//! because they have nothing but `T2 − T` to finish in. The premium is the
//! per-proof floor of the extra groups.
//!
//! **The epoch stops at the threshold, not at slot 32.** Justification needs 2/3
//! of the stake, and at mainnet participation that crosses around slot 22, with
//! inclusion delay pushing it a slot or two later. Attestations after that point
//! change nothing, and proving them is a quarter of the epoch's cost spent on
//! nothing. The trigger is measured accumulated weight, never a slot number: a
//! low-participation epoch simply keeps going.
//!
//! **The last unit is not a group at all.** It is handed to the final proof and
//! proven inline, which saves a per-proof floor and a recursive verification
//! from the critical path.
//!
//! # Margin
//!
//! [`StreamPolicy::threshold`] is the *scheduling* threshold and defaults above
//! 2/3, because attestations already collected can turn out not to count —
//! duplicates across slots, a validator that appears in two aggregates. The
//! circuit enforces exactly 2/3 and does not know what margin the schedule used,
//! so a margin that is too thin costs a retry, never soundness.

use std::collections::BTreeSet;

use zkasper_common::acc::{self, Digest};
use zkasper_common::bls::Fp12;
use zkasper_common::dedup::{self, Bitmap, DedupProof, EMPTY_BITMAP, LEAF_BITS};
use zkasper_common::recursion::ProgramVk;
use zkasper_common::types::{
    AccMultiProof, AggregateOutput, AggregateWitness, AttestationWitness, BlockHeaderFields,
    EpochDiffOutput, GroupProofOutput, MillerAccumulator, PreviousJustification, SlotProofWitness,
    StreamFinalWitness,
};

use crate::acc_tree::AccTree;

// ---------------------------------------------------------------------------
// The counted-set tree, host side
// ---------------------------------------------------------------------------

/// Host-side counted-set tree: one bit per validator, 256 bits to a leaf.
///
/// Dense, because the whole thing is 2^14 leaves for a 2^22 index space — half a
/// megabyte — and rebuilding it costs 32,768 permutations, which is nothing next
/// to the proof it feeds.
#[derive(Clone)]
pub struct DedupTree {
    depth: u32,
    bitmaps: Vec<Bitmap>,
    /// `levels[0]` are leaf digests, `levels[depth]` the root.
    levels: Vec<Vec<Digest>>,
}

impl DedupTree {
    pub fn new(depth: u32) -> Self {
        let mut this = Self {
            depth,
            bitmaps: vec![EMPTY_BITMAP; 1usize << depth],
            levels: Vec::new(),
        };
        this.rebuild();
        this
    }

    fn rebuild(&mut self) {
        let mut levels: Vec<Vec<Digest>> = vec![self.bitmaps.iter().map(dedup::leaf).collect()];
        for d in 0..self.depth as usize {
            let parents = levels[d]
                .chunks_exact(2)
                .map(|pair| acc::compress(&pair[0], &pair[1]))
                .collect();
            levels.push(parents);
        }
        self.levels = levels;
    }

    pub fn root(&self) -> Digest {
        self.levels[self.depth as usize][0]
    }

    /// Is this validator already counted?
    pub fn is_counted(&self, index: u64) -> bool {
        let bit = (index % LEAF_BITS) as usize;
        self.bitmaps[(index / LEAF_BITS) as usize][bit / 32] & (1u32 << (bit % 32)) != 0
    }

    /// Build the opening a proof needs for `indices`, which must be sorted.
    ///
    /// Auxiliaries come out bottom-up, left child before right, ascending parent
    /// order — the order [`zkasper_common::merkle::batch_root`] consumes them in.
    /// The loop below deliberately mirrors that scan.
    pub fn proof(&self, indices: &[u64]) -> DedupProof {
        let mut idx: Vec<u64> = indices.iter().map(|i| i / LEAF_BITS).collect();
        idx.dedup();

        let bitmaps = idx.iter().map(|&l| self.bitmaps[l as usize]).collect();

        let mut auxiliaries = Vec::new();
        let mut next: Vec<u64> = Vec::with_capacity(idx.len());
        for level in 0..self.depth as usize {
            next.clear();
            let mut i = 0usize;
            while i < idx.len() {
                let k = idx[i];
                if k & 1 == 0 {
                    if i + 1 < idx.len() && idx[i + 1] == k + 1 {
                        i += 2;
                    } else {
                        auxiliaries.push(self.levels[level][(k + 1) as usize]);
                        i += 1;
                    }
                } else {
                    auxiliaries.push(self.levels[level][(k - 1) as usize]);
                    i += 1;
                }
                next.push(k >> 1);
            }
            std::mem::swap(&mut idx, &mut next);
        }

        DedupProof {
            bitmaps,
            auxiliaries,
        }
    }

    /// Mark `indices` counted.
    pub fn apply(&mut self, indices: &[u64]) {
        for &index in indices {
            let bit = (index % LEAF_BITS) as usize;
            self.bitmaps[(index / LEAF_BITS) as usize][bit / 32] |= 1u32 << (bit % 32);
        }
        self.rebuild();
    }
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

/// One aggregate attestation, and what proving it would add to the epoch.
#[derive(Clone, Debug)]
pub struct StreamUnit {
    /// Slot of the block that included it — when the prover could start, which
    /// is what the schedule is about. Not the slot it attests to.
    pub slot: u64,
    pub attestation: AttestationWitness,
    /// Balance of the attesters this unit is the first to count.
    pub marginal_balance: u64,
}

impl StreamUnit {
    /// Wrap an attestation, reading its marginal weight off the `count_balance`
    /// flags the collector already set.
    pub fn new(slot: u64, attestation: AttestationWitness) -> Self {
        let marginal_balance = attestation
            .attesting_validators
            .iter()
            .filter(|v| v.count_balance)
            .map(|v| v.active_effective_balance)
            .sum();
        Self {
            slot,
            attestation,
            marginal_balance,
        }
    }

    pub fn counted_indices(&self) -> Vec<u64> {
        self.attestation
            .attesting_validators
            .iter()
            .filter(|v| v.count_balance)
            .map(|v| v.validator_index)
            .collect()
    }

    pub fn all_indices(&self) -> Vec<u64> {
        self.attestation
            .attesting_validators
            .iter()
            .map(|v| v.validator_index)
            .collect()
    }
}

/// How to cut an epoch.
#[derive(Clone, Debug)]
pub struct StreamPolicy {
    /// Each group covers `remaining / shrink` slots, so groups shrink toward the
    /// threshold. 2 halves the remaining span every time.
    pub shrink: u64,
    /// Stop collecting once this fraction of the total active balance has
    /// attested. Above 2/3 by default; see the module docs on margin.
    pub threshold_numerator: u64,
    pub threshold_denominator: u64,
}

impl Default for StreamPolicy {
    fn default() -> Self {
        Self {
            shrink: 2,
            threshold_numerator: 70,
            threshold_denominator: 100,
        }
    }
}

impl StreamPolicy {
    /// Balance at which the schedule stops collecting.
    pub fn target_balance(&self, total_active_balance: u64) -> u128 {
        (total_active_balance as u128 * self.threshold_numerator as u128)
            .div_ceil(self.threshold_denominator as u128)
    }
}

/// Which units go into which proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamPlan {
    /// Units per group proof, as indices into the unit list.
    pub groups: Vec<Vec<usize>>,
    /// Units the final proof verifies inline. Empty only if the epoch never
    /// reached the threshold.
    pub tail: Vec<usize>,
    /// Balance the plan expects to have counted, groups and tail together.
    pub attesting_balance: u64,
    /// True if `attesting_balance` reached the policy's threshold.
    pub threshold_reached: bool,
}

/// Cut a stream of units into geometrically shrinking groups plus an inline tail.
///
/// Units must be in ascending slot order — the order a node publishes them.
pub fn plan(units: &[StreamUnit], total_active_balance: u64, policy: &StreamPolicy) -> StreamPlan {
    let target = policy.target_balance(total_active_balance);

    // Where the threshold actually crosses, from measured weight. This is the
    // unit the final proof will verify inline.
    let mut running = 0u128;
    let mut crossing = None;
    for (i, unit) in units.iter().enumerate() {
        running += unit.marginal_balance as u128;
        if running >= target {
            crossing = Some(i);
            break;
        }
    }

    let (last, threshold_reached) = match crossing {
        Some(i) => (i, true),
        // Never crossed: prove everything there is and let the caller decide
        // whether to wait for more blocks.
        None => {
            if units.is_empty() {
                return StreamPlan {
                    groups: Vec::new(),
                    tail: Vec::new(),
                    attesting_balance: 0,
                    threshold_reached: false,
                };
            }
            (units.len() - 1, false)
        }
    };

    // Groups cover everything before the crossing unit, cut by slot: a group is
    // only provable once every block it covers has been published, so a group
    // boundary inside a slot would buy nothing.
    let first_slot = units[0].slot;
    let end_slot = units[last].slot;

    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut cursor = 0usize;
    let mut start = first_slot;

    while cursor < last {
        let remaining = end_slot.saturating_sub(start);
        let span = (remaining / policy.shrink).max(1);
        let stop = start + span;

        let mut group = Vec::new();
        while cursor < last && units[cursor].slot < stop {
            group.push(cursor);
            cursor += 1;
        }
        if !group.is_empty() {
            groups.push(group);
        }
        start = stop;

        // The crossing unit's own slot is never a whole group: what is left of
        // it goes into the last group and the crossing unit into the tail.
        if start > end_slot {
            let mut rest = Vec::new();
            while cursor < last {
                rest.push(cursor);
                cursor += 1;
            }
            if !rest.is_empty() {
                groups.push(rest);
            }
        }
    }

    let attesting_balance = units[..=last].iter().map(|u| u.marginal_balance).sum();

    StreamPlan {
        groups,
        tail: vec![last],
        attesting_balance,
        threshold_reached,
    }
}

// ---------------------------------------------------------------------------
// Witness builders
// ---------------------------------------------------------------------------

/// Everything a group, aggregate or final witness needs that does not change
/// within an epoch.
#[derive(Clone)]
pub struct StreamContext {
    pub accumulator_commitment: Digest,
    pub acc_root: Digest,
    pub total_active_balance: u64,
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    pub signing_domain: [u8; 32],
    pub group_program_vk: ProgramVk,
    pub aggregate_program_vk: ProgramVk,
    pub previous_program_vk: ProgramVk,
    pub epoch_diff_program_vk: ProgramVk,
    /// The diff that carried the accumulator into this epoch, with its proof.
    ///
    /// Verified by the fold that opens the epoch, which is as early as it can
    /// be: the diff exists at the epoch boundary, and every later proof
    /// inherits the link rather than re-verifying it.
    pub epoch_diff: EpochDiffOutput,
    pub epoch_diff_proof: Vec<u64>,
    pub acc_depth: u32,
}

impl StreamContext {
    pub fn dedup_depth(&self) -> u32 {
        dedup::tree_depth(self.acc_depth)
    }
}

/// Build the witness for one group proof.
pub fn group_witness(
    context: &StreamContext,
    tree: &AccTree,
    units: &[&StreamUnit],
) -> SlotProofWitness {
    let attestations: Vec<AttestationWitness> =
        units.iter().map(|u| u.attestation.clone()).collect();

    SlotProofWitness {
        accumulator_commitment: context.accumulator_commitment,
        target_epoch: context.target_epoch,
        target_root: context.target_root,
        signing_domain: context.signing_domain,
        acc_root: context.acc_root,
        total_active_balance: context.total_active_balance,
        acc_multi_proof: multi_proof(tree, units),
        attestations,
    }
}

/// Accumulator opening over every attester the units name, counted or not.
fn multi_proof(tree: &AccTree, units: &[&StreamUnit]) -> AccMultiProof {
    let indices: BTreeSet<u64> = units.iter().flat_map(|u| u.all_indices()).collect();
    tree.build_multi_proof(&indices.into_iter().collect::<Vec<_>>())
}

/// Sorted counted indices for a set of units.
pub fn counted_indices(units: &[&StreamUnit]) -> Vec<u64> {
    let set: BTreeSet<u64> = units.iter().flat_map(|u| u.counted_indices()).collect();
    set.into_iter().collect()
}

/// Build the witness that folds finished group proofs into the running aggregate.
///
/// `dedup` is advanced by this call, because the aggregate the witness produces
/// commits to the tree *after* the insert.
#[allow(clippy::too_many_arguments)]
pub fn aggregate_witness(
    context: &StreamContext,
    dedup_tree: &mut DedupTree,
    previous: Option<AggregateOutput>,
    previous_proof: Vec<u64>,
    previous_miller: Fp12,
    groups: Vec<GroupProofOutput>,
    group_proofs: Vec<Vec<u64>>,
    group_millers: Vec<Fp12>,
    counted_indices_per_group: Vec<Vec<u64>>,
) -> AggregateWitness {
    let mut added: Vec<u64> = counted_indices_per_group.concat();
    added.sort_unstable();

    let dedup_proof = dedup_tree.proof(&added);
    dedup_tree.apply(&added);

    // Only the fold that opens the epoch needs the diff; the rest inherit the
    // link from the aggregate they extend.
    let opens_the_epoch = previous.is_none();

    AggregateWitness {
        accumulator_commitment: context.accumulator_commitment,
        target_epoch: context.target_epoch,
        target_root: context.target_root,
        group_program_vk: context.group_program_vk,
        aggregate_program_vk: context.aggregate_program_vk,
        epoch_diff_program_vk: context.epoch_diff_program_vk,
        epoch_diff: opens_the_epoch.then(|| context.epoch_diff.clone()),
        epoch_diff_proof: if opens_the_epoch {
            context.epoch_diff_proof.clone()
        } else {
            Vec::new()
        },
        previous,
        previous_proof,
        previous_miller: MillerAccumulator(previous_miller),
        groups,
        group_proofs,
        group_millers: group_millers.into_iter().map(MillerAccumulator).collect(),
        counted_indices_per_group,
        dedup_proof,
    }
}

/// Build the witness for the final proof of an epoch.
///
/// Everything here that is not the tail was already fixed before the last
/// attestation arrived; the tail is the only part that could not have been.
#[allow(clippy::too_many_arguments)]
pub fn final_witness(
    context: &StreamContext,
    tree: &AccTree,
    dedup_tree: &DedupTree,
    aggregate: Option<AggregateOutput>,
    aggregate_proof: Vec<u64>,
    aggregate_miller: Fp12,
    groups: Vec<GroupProofOutput>,
    group_proofs: Vec<Vec<u64>>,
    group_millers: Vec<Fp12>,
    counted_indices_per_group: Vec<Vec<u64>>,
    tail: &[&StreamUnit],
    previous_justification: PreviousJustification,
    previous_justification_proof: Vec<u64>,
    finalized_header: BlockHeaderFields,
) -> StreamFinalWitness {
    let mut counted: Vec<u64> = counted_indices_per_group.concat();
    counted.extend(counted_indices(tail));
    counted.sort_unstable();

    StreamFinalWitness {
        accumulator_commitment: context.accumulator_commitment,
        target_epoch: context.target_epoch,
        target_root: context.target_root,
        signing_domain: context.signing_domain,
        acc_root: context.acc_root,
        total_active_balance: context.total_active_balance,
        group_program_vk: context.group_program_vk,
        aggregate_program_vk: context.aggregate_program_vk,
        previous_program_vk: context.previous_program_vk,
        epoch_diff_program_vk: context.epoch_diff_program_vk,
        // Needed only when there is no aggregate to inherit the link from.
        epoch_diff: aggregate.is_none().then(|| context.epoch_diff.clone()),
        epoch_diff_proof: if aggregate.is_none() {
            context.epoch_diff_proof.clone()
        } else {
            Vec::new()
        },
        aggregate,
        aggregate_proof,
        aggregate_miller: MillerAccumulator(aggregate_miller),
        groups,
        group_proofs,
        group_millers: group_millers.into_iter().map(MillerAccumulator).collect(),
        counted_indices_per_group,
        tail: tail.iter().map(|u| u.attestation.clone()).collect(),
        tail_acc_multi_proof: multi_proof(tree, tail),
        dedup_proof: dedup_tree.proof(&counted),
        previous_justification,
        previous_justification_proof,
        finalized_header,
    }
}

// ---------------------------------------------------------------------------
// Running the pipeline
// ---------------------------------------------------------------------------

/// Everything one epoch's stream produced.
pub struct StreamRun {
    pub group_witnesses: Vec<SlotProofWitness>,
    pub group_outputs: Vec<GroupProofOutput>,
    pub aggregate_witnesses: Vec<AggregateWitness>,
    pub aggregate_outputs: Vec<AggregateOutput>,
    pub final_witness: StreamFinalWitness,
    pub final_output: zkasper_common::types::StreamFinalOutput,
}

/// Drive a whole epoch through the streaming pipeline with the circuits run
/// natively and no prover behind them.
///
/// Every witness this produces is one a prover could be handed unchanged; what
/// is missing is the proofs, which are empty here and which
/// [`zkasper_common::recursion::verify_child`] accepts only on native targets.
/// The shape of the schedule — which units go to which proof, in what order, and
/// what each proof has to be given — is exactly the shape a real run has, so
/// this is what pins the design in tests.
///
/// One fold per group, which is the worst case for proof count. A real run folds
/// whatever has finished since the last tick, and can hand unfolded groups
/// straight to the final proof.
#[allow(clippy::too_many_arguments)]
pub fn run_native(
    context: &StreamContext,
    tree: &AccTree,
    units: &[StreamUnit],
    plan: &StreamPlan,
    previous_justification: PreviousJustification,
    finalized_header: BlockHeaderFields,
) -> StreamRun {
    let mut dedup_tree = DedupTree::new(context.dedup_depth());

    let mut group_witnesses = Vec::new();
    let mut group_outputs = Vec::new();
    let mut aggregate_witnesses = Vec::new();
    let mut aggregate_outputs = Vec::new();

    let mut aggregate: Option<AggregateOutput> = None;
    let mut aggregate_miller = zkasper_common::bls::FP12_ONE;

    for group in &plan.groups {
        let members: Vec<&StreamUnit> = group.iter().map(|&i| &units[i]).collect();
        let witness = group_witness(context, tree, &members);

        // The circuit produces the output; the host keeps the Miller
        // accumulator, which the output only commits to.
        let attested = zkasper_slot_proof_guest::attest(&witness, context.acc_depth);
        let output =
            zkasper_slot_proof_guest::verify_group_proof_with_depth(&witness, context.acc_depth);

        let aggregate_witness = aggregate_witness(
            context,
            &mut dedup_tree,
            aggregate.clone(),
            Vec::new(),
            aggregate_miller,
            vec![output.clone()],
            vec![Vec::new()],
            vec![attested.miller],
            vec![counted_indices(&members)],
        );
        let next = zkasper_aggregation_guest::verify_aggregate_with_depth(
            &aggregate_witness,
            context.dedup_depth(),
        );

        aggregate_miller = zkasper_common::bls::fp12_mul(&aggregate_miller, &attested.miller);
        aggregate = Some(next.clone());

        group_witnesses.push(witness);
        group_outputs.push(output);
        aggregate_witnesses.push(aggregate_witness);
        aggregate_outputs.push(next);
    }

    let tail: Vec<&StreamUnit> = plan.tail.iter().map(|&i| &units[i]).collect();
    let final_witness = final_witness(
        context,
        tree,
        &dedup_tree,
        aggregate,
        Vec::new(),
        aggregate_miller,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        &tail,
        previous_justification,
        Vec::new(),
        finalized_header,
    );

    let final_output = zkasper_stream_final_guest::verify_stream_final_with_depth(
        &final_witness,
        context.acc_depth,
    );

    StreamRun {
        group_witnesses,
        group_outputs,
        aggregate_witnesses,
        aggregate_outputs,
        final_witness,
        final_output,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkasper_common::types::{AttestingValidator, BlsSignature};

    fn unit(slot: u64, balance: u64, indices: &[u64]) -> StreamUnit {
        StreamUnit {
            slot,
            marginal_balance: balance,
            attestation: AttestationWitness {
                data_slot: slot,
                data_index: 0,
                data_beacon_block_root: [0; 32],
                data_source_epoch: 0,
                data_source_root: [0; 32],
                data_target_epoch: 1,
                data_target_root: [0; 32],
                signature: BlsSignature([0; 96]),
                attesting_validators: indices
                    .iter()
                    .map(|&i| AttestingValidator {
                        validator_index: i,
                        pubkey: [0; 12],
                        active_effective_balance: balance / indices.len().max(1) as u64,
                        count_balance: true,
                    })
                    .collect(),
            },
        }
    }

    /// One unit per slot, each worth 4% of the stake: the threshold at 70%
    /// crosses at slot 17, and nothing past it is planned.
    fn even_epoch() -> Vec<StreamUnit> {
        (0..32).map(|s| unit(s, 4, &[s])).collect()
    }

    #[test]
    fn groups_shrink_toward_the_threshold() {
        let plan = plan(&even_epoch(), 100, &StreamPolicy::default());

        assert!(plan.threshold_reached);
        assert_eq!(plan.tail, vec![17]);

        let sizes: Vec<usize> = plan.groups.iter().map(|g| g.len()).collect();
        assert_eq!(sizes, vec![8, 4, 2, 1, 1, 1]);

        // Every unit before the crossing is proven exactly once.
        let covered: Vec<usize> = plan.groups.concat();
        assert_eq!(covered, (0..17).collect::<Vec<_>>());
    }

    #[test]
    fn the_critical_path_holds_one_unit_however_big_the_epoch() {
        for shrink in [2, 3, 4] {
            let policy = StreamPolicy {
                shrink,
                ..StreamPolicy::default()
            };
            let plan = plan(&even_epoch(), 100, &policy);
            assert_eq!(plan.tail.len(), 1, "shrink {shrink}");
            assert_eq!(*plan.groups.last().unwrap(), vec![16], "shrink {shrink}");
        }
    }

    #[test]
    fn nothing_past_the_threshold_is_planned() {
        let plan = plan(&even_epoch(), 100, &StreamPolicy::default());
        let last = plan.groups.concat().into_iter().chain(plan.tail).max();
        assert_eq!(last, Some(17));
        assert_eq!(plan.attesting_balance, 72);
    }

    /// A quarter of the validators offline: the threshold is never reached, and
    /// the plan says so rather than pretending.
    #[test]
    fn a_low_participation_epoch_is_reported_not_faked() {
        let units: Vec<StreamUnit> = (0..32).map(|s| unit(s, 2, &[s])).collect();
        let plan = plan(&units, 100, &StreamPolicy::default());

        assert!(!plan.threshold_reached);
        assert_eq!(plan.attesting_balance, 64);
        assert_eq!(plan.tail, vec![31]);
    }

    #[test]
    fn several_aggregates_in_one_slot_stay_in_one_group() {
        let mut units = Vec::new();
        for slot in 0..8u64 {
            for k in 0..4u64 {
                units.push(unit(slot, 3, &[slot * 4 + k]));
            }
        }
        let plan = plan(&units, 100, &StreamPolicy::default());

        // Groups are cut on slot boundaries, so no group holds part of a slot
        // except the one that ends at the crossing unit.
        for group in plan.groups.iter().take(plan.groups.len() - 1) {
            let slots: BTreeSet<u64> = group.iter().map(|&i| units[i].slot).collect();
            let first = *slots.iter().next().unwrap();
            let last = *slots.iter().next_back().unwrap();
            for slot in first..=last {
                assert_eq!(
                    group.iter().filter(|&&i| units[i].slot == slot).count(),
                    4,
                    "slot {slot} split across groups",
                );
            }
        }
    }

    #[test]
    fn the_counted_set_tree_agrees_with_a_plain_set() {
        let mut tree = DedupTree::new(4);
        let mut reference: BTreeSet<u64> = BTreeSet::new();

        for batch in [vec![0u64, 300, 4000], vec![1, 2, 299, 301]] {
            let proof = tree.proof(&batch);
            let update = dedup::apply(&batch, &proof, 4).expect("apply");
            assert_eq!(update.old_root, tree.root());

            tree.apply(&batch);
            reference.extend(&batch);
            assert_eq!(update.new_root, tree.root());
        }

        for i in 0..4096u64 {
            assert_eq!(tree.is_counted(i), reference.contains(&i), "index {i}");
        }
    }
}
