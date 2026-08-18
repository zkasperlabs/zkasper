//! Streaming: cut an epoch into groups a fixed set of GPUs can finish in time.
//!
//! # The quantity being minimised
//!
//! `T` is when the chain has published enough attestations to justify the
//! target. `T2` is when a postable proof exists. `T2 − T` is the only latency a
//! consumer sees, and it is *not* the cost of proving an epoch — it is the cost
//! of whatever still depends on the last attestation.
//!
//! # What the schedule is up against is arrival time, not throughput
//!
//! A mainnet block carries one aggregate covering the whole of the previous
//! slot's committees — around 29,900 attesters — plus a handful of
//! re-aggregations worth a validator or two each. Proving that one aggregate
//! alone costs about 19s of warm GPU against a 12s slot, and most of that is the
//! accumulator multi-proof, which no amount of hardware shortens. So the epoch's
//! last two aggregates are a chain nothing can parallelise: the one the epoch
//! crosses 2/3 on cannot start before it exists, and the one before it has a
//! single slot of slack for 19s of work.
//!
//! Adding GPUs buys the *bulk* of the epoch, never the end of it. That is why
//! this module solves a deadline problem — every group must land before `T` —
//! rather than a packing one, and why the lane a proof runs on is an output of
//! [`schedule`] rather than something a caller arranges afterwards.
//!
//! # Three decisions, and all three are the opposite of the obvious one
//!
//! **Groups are large early and single-slot late.** Not geometric: geometric
//! sizing is indexed on the span left to cover, and what actually matters is the
//! slack a group has between its last attestation and `T`. Early groups have
//! minutes and should amortise as many per-proof floors and as much accumulator
//! batching as they can; the last two have one slot each and must be alone.
//!
//! **The last aggregate is a group, not an inline tail.** Proving it inline
//! saves a per-proof floor, but it also serialises 19s of attestation work
//! behind `T` that a second lane could have run concurrently with the group
//! before it. Paying the floor to move that work off the critical path is worth
//! about 2s.
//!
//! **Aggregates that add nothing are not proven.** Roughly a quarter of an
//! epoch's attesters arrive inside re-aggregations that repeat 25,000 attesters
//! to contribute one. [`select`] keeps units in descending weight-per-cost order
//! until the threshold is met, so that work is never scheduled at all.
//!
//! # Margin
//!
//! [`StreamPolicy::threshold_numerator`] is the *scheduling* threshold and
//! defaults above 2/3, because attestations already collected can turn out not
//! to count — duplicates across slots, a validator that appears in two
//! aggregates. The circuit enforces exactly 2/3 and does not know what margin
//! the schedule used, so a margin that is too thin costs a retry, never
//! soundness. It is not free: weight arrives one slot's committees at a time, so
//! any margin that pushes the crossing into the next slot costs a whole slot of
//! absolute latency. [`Schedule::threshold_s`] is measured at 2/3 regardless, so
//! that cost shows up in `T2 − T` rather than hiding in the choice of `T`.

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

    /// Attesters the proof pays for, counted or not: every one of them needs an
    /// accumulator leaf opened and a public key added.
    pub fn attesters(&self) -> usize {
        self.attestation.attesting_validators.len()
    }

    /// Attesters this unit is the first to count, which is all it is worth.
    pub fn counted(&self) -> usize {
        self.attestation
            .attesting_validators
            .iter()
            .filter(|v| v.count_balance)
            .count()
    }
}

/// Measured Zisk costs, in cost units. See BENCHMARKS.md.
mod cost {
    pub const ACC_NODE: f64 = 3_033.0;
    pub const ACC_LEAF: f64 = 3_979.0;
    pub const G1_ADD: f64 = 2_428.0;
    pub const HASH_TO_CURVE: f64 = 18_594_521.0;
    /// Marginal cost of one more pair in a multi-Miller-loop.
    pub const MILLER_PAIR: f64 = 33_222_822.0;
    /// Fixed cost of any multi-Miller-loop: 63 Fp12 squarings the pairs share.
    pub const MILLER_BATCH: f64 = 39_633_399.0;
    pub const FINAL_EXP: f64 = 132_665_557.0;
    pub const FP12_MUL: f64 = 737_503.0;
    pub const COMMIT_FP12: f64 = 78_002.0;
    pub const G2_SUBGROUP: f64 = 8_219_617.0;
}

/// Internal compressions a multi-proof over `leaves` random leaves needs.
///
/// A node at level `k` covers 2^k leaves, so it is touched unless every one of
/// those slots is empty. Near the bottom almost every touched node is distinct;
/// higher up the set collapses and the whole level is rebuilt. This is what
/// makes a group of eight aggregates far cheaper than eight groups of one, and
/// so it is what the optimiser is trading against arrival time.
fn batched_nodes(leaves: f64, depth: u32) -> f64 {
    let capacity = (1u64 << depth) as f64;
    (1..=depth)
        .map(|k| {
            let covered = (1u64 << k) as f64;
            capacity / covered * (1.0 - (1.0 - covered / capacity).powf(leaves))
        })
        .sum()
}

/// Opening `attesters` leaves against the accumulator.
fn accumulator_cost(attesters: f64, acc_depth: u32) -> f64 {
    attesters * cost::ACC_LEAF + batched_nodes(attesters, acc_depth) * cost::ACC_NODE
}

/// Opening the counted-set tree over `indices`, 256 indices to a leaf.
fn dedup_cost(indices: f64, dedup_depth: u32) -> f64 {
    let capacity = (1u64 << dedup_depth) as f64;
    let leaves = capacity * (1.0 - (1.0 - 1.0 / capacity).powf(indices));
    (leaves + batched_nodes(leaves, dedup_depth)) * cost::ACC_NODE
}

/// Everything an attestation set costs short of the final exponentiation.
fn attestation_work(attesters: f64, aggregates: f64, acc_depth: u32) -> f64 {
    accumulator_cost(attesters, acc_depth)
        + attesters * cost::G1_ADD
        + aggregates * cost::HASH_TO_CURVE
        + cost::MILLER_BATCH
        + (aggregates + 1.0) * cost::MILLER_PAIR
        + cost::G2_SUBGROUP
}

/// What the prover charges and how fast it discharges it.
///
/// Parameters rather than constants: `proof_base` is a display value in Zisk
/// that does not match the shipped AIR layout and is being re-measured, and
/// `units_per_second` moves with the card. The schedule is sensitive to both, so
/// they belong in the input.
#[derive(Clone, Debug, PartialEq)]
pub struct ProverModel {
    /// Cost units every proof pays before it does anything.
    pub proof_base: f64,
    /// Cost units a warm prover discharges per second.
    pub units_per_second: f64,
    /// Seconds a warm prover spends per invocation whatever the cost.
    pub warm_fixed_s: f64,
    /// SNARK compression of the final proof, one more invocation.
    pub wrap_s: f64,
    /// Cost of verifying one child proof recursively.
    ///
    /// Unmeasured — `scripts/bench.py` has no figure for it, and the existing
    /// cost model folds it into the floor. It decides whether folds are worth
    /// their own proofs at all, so it is a parameter and not a zero baked in.
    pub recursion_verify: f64,
    pub acc_depth: u32,
}

impl Default for ProverModel {
    fn default() -> Self {
        Self {
            proof_base: 293_601_280.0,
            units_per_second: 67_452_592.0,
            warm_fixed_s: 0.5,
            wrap_s: 0.192,
            recursion_verify: 0.0,
            acc_depth: zkasper_common::constants::ACC_TREE_DEPTH,
        }
    }
}

impl ProverModel {
    fn dedup_depth(&self) -> u32 {
        dedup::tree_depth(self.acc_depth)
    }

    /// Wall-clock a warm prover takes over `cost`.
    pub fn seconds(&self, cost: f64) -> f64 {
        self.warm_fixed_s + cost / self.units_per_second
    }

    /// One group proof: attestations verified as far as the Miller loop, which
    /// the final exponentiation is deliberately not part of.
    pub fn group_cost(&self, attesters: f64, aggregates: f64) -> f64 {
        self.proof_base + attestation_work(attesters, aggregates, self.acc_depth)
    }

    /// One fold, absorbing `groups` finished group proofs.
    pub fn fold_cost(&self, groups: f64, counted: f64) -> f64 {
        self.proof_base
            + dedup_cost(counted, self.dedup_depth())
            + (groups + 1.0) * self.recursion_verify
            + groups * (cost::FP12_MUL + cost::COMMIT_FP12)
    }

    /// The final proof: the tail inline, `absorbed` group proofs taken directly,
    /// and the epoch's one final exponentiation.
    pub fn final_cost(
        &self,
        tail_attesters: f64,
        tail_aggregates: f64,
        counted: f64,
        absorbed: f64,
        folded: bool,
    ) -> f64 {
        let attestations = if tail_aggregates > 0.0 {
            attestation_work(tail_attesters, tail_aggregates, self.acc_depth)
        } else {
            0.0
        };
        self.proof_base
            + attestations
            + dedup_cost(counted, self.dedup_depth())
            + cost::FINAL_EXP
            + (absorbed + if folded { 1.0 } else { 0.0 }) * self.recursion_verify
            + (absorbed + 1.0) * (cost::FP12_MUL + cost::COMMIT_FP12)
    }
}

/// Whether a warm prover can run any stage or is pinned to one program.
///
/// `cargo-zisk setup` is per-program, so a prover holding a proving key open may
/// only be able to run the ELF it was set up for. That is not a detail: it
/// decides whether the fold chain can borrow an idle group lane or needs a card
/// of its own sitting idle for most of an epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanePool {
    /// One ELF branching on a mode discriminant: any lane runs any stage.
    Fungible,
    /// A lane per program. One is reserved for folds and one for the final
    /// proof and its wrap; the rest run group proofs.
    Specialised,
}

/// How to cut an epoch.
#[derive(Clone, Debug)]
pub struct StreamPolicy {
    /// Stop collecting once this fraction of the total active balance has
    /// attested. Above 2/3 by default; see the module docs on margin.
    pub threshold_numerator: u64,
    pub threshold_denominator: u64,
    /// Wall-clock between block arrivals. What turns a partition into a
    /// schedule: a group cannot start before the slot its last unit came in.
    pub seconds_per_slot: f64,
    /// Warm provers available. One saturates a card — a warm prover pins about
    /// 30 GB against an RTX 5090's 32.6 GB — so this is a GPU count.
    pub lanes: usize,
    pub lane_pool: LanePool,
    pub prover: ProverModel,
}

impl Default for StreamPolicy {
    fn default() -> Self {
        Self {
            threshold_numerator: 70,
            threshold_denominator: 100,
            seconds_per_slot: 12.0,
            lanes: 3,
            lane_pool: LanePool::Fungible,
            prover: ProverModel::default(),
        }
    }
}

impl StreamPolicy {
    /// Balance at which the schedule stops collecting.
    pub fn target_balance(&self, total_active_balance: u64) -> u128 {
        (total_active_balance as u128 * self.threshold_numerator as u128)
            .div_ceil(self.threshold_denominator as u128)
    }

    /// Balance the circuit itself insists on, which is what "enough
    /// attestations exist" means and so what `T` is measured at.
    fn quorum_balance(&self, total_active_balance: u64) -> u128 {
        (total_active_balance as u128 * 2).div_ceil(3)
    }

    /// Lanes each stage may run on.
    fn eligible(&self, stage: Stage) -> std::ops::Range<usize> {
        if self.lane_pool == LanePool::Fungible {
            return 0..self.lanes;
        }
        // The reserved lanes are the last two, so a group lane's index is stable
        // as the pool grows. Below three lanes they overlap, which is the honest
        // answer: a specialised pool of two cannot separate three programs.
        let last = self.lanes.saturating_sub(1);
        let fold = last.saturating_sub(1);
        match stage {
            Stage::Group(_) => 0..fold.max(1),
            Stage::Fold(_) => fold..fold + 1,
            _ => last..last + 1,
        }
    }
}

/// Which units go into which proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamPlan {
    /// Units per group proof, as indices into the unit list.
    pub groups: Vec<Vec<usize>>,
    /// Groups each fold absorbs, as indices into `groups`. The folds form a
    /// chain: each extends the aggregate the one before it produced.
    pub folds: Vec<Vec<usize>>,
    /// Groups the final proof verifies directly, because no fold could have
    /// finished them in time. Also indices into `groups`.
    pub absorbed: Vec<usize>,
    /// Units the final proof verifies inline, with no group proof of their own.
    pub tail: Vec<usize>,
    /// Balance the plan expects to have counted, groups and tail together.
    pub attesting_balance: u64,
    /// True if `attesting_balance` reached the policy's threshold.
    pub threshold_reached: bool,
}

/// Which stage of the pipeline a scheduled proof is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Index into [`StreamPlan::groups`].
    Group(usize),
    /// Index into [`StreamPlan::folds`].
    Fold(usize),
    Final,
    Wrap,
}

/// One proof, and the lane and wall-clock window it runs in.
#[derive(Clone, Debug, PartialEq)]
pub struct ScheduledProof {
    pub stage: Stage,
    pub lane: usize,
    pub start_s: f64,
    pub end_s: f64,
    pub cost: f64,
}

/// A plan, placed on lanes and on the clock.
#[derive(Clone, Debug)]
pub struct Schedule {
    pub plan: StreamPlan,
    /// Every proof the epoch runs, in start order.
    pub proofs: Vec<ScheduledProof>,
    /// GPUs the schedule occupies, which is at most the policy's lane count.
    pub lanes: usize,
    /// `T`: when the chain has published 2/3 of the stake.
    pub threshold_s: f64,
    /// `T2`: when the wrapped proof exists.
    pub postable_s: f64,
    pub total_cost: f64,
}

impl Schedule {
    /// `T2 − T`, the only latency a consumer sees.
    pub fn latency_s(&self) -> f64 {
        self.postable_s - self.threshold_s
    }
}

/// Which units are worth proving at all.
///
/// A block frequently carries a re-aggregation of committees an earlier block
/// already covered — on mainnet an epoch holds aggregates that repeat 25,000
/// attesters to add one. Every one of those attesters still costs an
/// accumulator leaf and a public key addition, so proving them is around a
/// quarter of the epoch's cost for none of its weight.
///
/// Taking units in descending weight-per-cost order and stopping the moment the
/// threshold is met drops exactly those, and drops nothing the threshold needs.
/// Ties break toward the earlier unit, so the units that end up on the critical
/// path are the fewest and latest possible.
///
/// Dropping is safe against the `count_balance` flags rather than in spite of
/// them: a flag says a *previous* unit already counted that validator, so
/// removing a unit can only leave later units understating their weight, never
/// overstating it.
pub fn select(units: &[StreamUnit], through: usize, target: u128, model: &ProverModel) -> Vec<usize> {
    let weight_per_cost = |i: usize| {
        units[i].marginal_balance as f64 / model.group_cost(units[i].attesters() as f64, 1.0)
    };

    let mut order: Vec<usize> = (0..=through)
        .filter(|&i| units[i].marginal_balance > 0)
        .collect();
    order.sort_by(|&a, &b| weight_per_cost(b).total_cmp(&weight_per_cost(a)).then(a.cmp(&b)));

    let mut taken = Vec::new();
    let mut running = 0u128;
    for i in order {
        if running >= target {
            break;
        }
        running += units[i].marginal_balance as u128;
        taken.push(i);
    }
    taken.sort_unstable();
    taken
}

/// Cut a stream of units into groups, and say which lane each proof runs on.
///
/// Units must be in ascending slot order — the order a node publishes them.
pub fn plan(units: &[StreamUnit], total_active_balance: u64, policy: &StreamPolicy) -> StreamPlan {
    schedule(units, total_active_balance, policy).plan
}

/// Plan an epoch and place every proof on a lane and on the clock.
///
/// `policy.lanes` is a budget, not a target: a card that buys no latency is a
/// card the schedule declines to use, which is what makes [`Schedule::lanes`]
/// readable as the GPU count the epoch actually needs.
pub fn schedule(
    units: &[StreamUnit],
    total_active_balance: u64,
    policy: &StreamPolicy,
) -> Schedule {
    (1..=policy.lanes.max(1))
        .map(|lanes| {
            with_lanes(
                units,
                total_active_balance,
                &StreamPolicy {
                    lanes,
                    ..policy.clone()
                },
            )
        })
        .min_by(better)
        .expect("at least one lane")
}

/// The objective, in the order it is meant to be read: latency, then GPUs, then
/// cost. Latency is compared in tenths of a second, because the constants
/// underneath are not good to a hundredth and a schedule should not buy a card
/// or an extra proof with noise.
fn better(a: &Schedule, b: &Schedule) -> std::cmp::Ordering {
    let tenths = |s: &Schedule| (s.latency_s() * 10.0).round() as i64;
    tenths(a)
        .cmp(&tenths(b))
        .then(a.lanes.cmp(&b.lanes))
        .then(a.total_cost.total_cmp(&b.total_cost))
}

fn with_lanes(units: &[StreamUnit], total_active_balance: u64, policy: &StreamPolicy) -> Schedule {
    if units.is_empty() {
        return Schedule {
            plan: StreamPlan {
                groups: Vec::new(),
                folds: Vec::new(),
                absorbed: Vec::new(),
                tail: Vec::new(),
                attesting_balance: 0,
                threshold_reached: false,
            },
            proofs: Vec::new(),
            lanes: 0,
            threshold_s: 0.0,
            postable_s: 0.0,
            total_cost: 0.0,
        };
    }

    let first_slot = units[0].slot;
    let arrival = |i: usize| (units[i].slot - first_slot) as f64 * policy.seconds_per_slot;

    let target = policy.target_balance(total_active_balance);
    let quorum = policy.quorum_balance(total_active_balance);
    let mut running = 0u128;
    let mut crossing = None;
    let mut threshold_s = arrival(units.len() - 1);
    for (i, unit) in units.iter().enumerate() {
        running += unit.marginal_balance as u128;
        if crossing.is_none() && running >= quorum {
            threshold_s = arrival(i);
        }
        if running >= target {
            crossing = Some(i);
            break;
        }
    }

    // Everything published in the crossing unit's slot is a candidate, not just
    // what precedes it: they all arrive together, and the cheapest way over the
    // line is often the aggregate after the one that happens to cross it.
    let threshold_reached = crossing.is_some();
    let crossing = crossing.unwrap_or(units.len() - 1);
    let deadline_slot = units[crossing].slot;
    let through = units
        .iter()
        .rposition(|u| u.slot <= deadline_slot)
        .expect("crossing unit is its own witness");

    let selected = select(units, through, target, &policy.prover);
    let attesting_balance = selected.iter().map(|&i| units[i].marginal_balance).sum();

    // Groups are cut on slot boundaries: a group is only provable once every
    // block it covers has been published, so a boundary inside a slot buys
    // nothing but a per-proof floor.
    let mut buckets: Vec<Vec<usize>> = Vec::new();
    for &i in &selected {
        match buckets.last() {
            Some(last) if units[last[0]].slot == units[i].slot => {
                buckets.last_mut().expect("just matched").push(i)
            }
            _ => buckets.push(vec![i]),
        }
    }

    let deadline_s = arrival(*selected.last().expect("threshold needs a unit"));
    let bulk = search(units, &buckets, &arrival, policy);

    // The crossing slot either goes inline into the final proof, which saves a
    // per-proof floor, or takes a group of its own, which lets its attestation
    // work run beside the group before it instead of behind `T`. Which wins
    // depends on how big the aggregate is, so try both.
    let best = bulk
        .iter()
        .flat_map(|partition| {
            let inline = partition.split_last().map(|(tail, rest)| {
                simulate(units, rest, tail, &arrival, deadline_s, threshold_s, policy)
            });
            [
                inline,
                Some(simulate(
                    units,
                    partition,
                    &[],
                    &arrival,
                    deadline_s,
                    threshold_s,
                    policy,
                )),
            ]
        })
        .flatten()
        .min_by(better)
        .expect("the search always yields the one-group partition");

    Schedule {
        plan: StreamPlan {
            attesting_balance,
            threshold_reached,
            ..best.plan
        },
        ..best
    }
}

/// Every group partition worth simulating, as lists of unit groups.
///
/// A dynamic program over slot buckets: the state after cutting a prefix is the
/// lanes' finish times and the cost paid so far, and a state that is no worse on
/// every lane *and* cheaper dominates. That is exact for the group stage — group
/// releases only increase, so a later group never wants an earlier lane gap —
/// and it collapses 2^22 partitions of a mainnet epoch to a few dozen.
fn search(
    units: &[StreamUnit],
    buckets: &[Vec<usize>],
    arrival: &impl Fn(usize) -> f64,
    policy: &StreamPolicy,
) -> Vec<Vec<Vec<usize>>> {
    /// Enough that widening it changes no schedule on a mainnet epoch; only
    /// there so a pathological arrival pattern cannot make the search blow up.
    const FRONTIER: usize = 256;

    let group_lanes = policy.eligible(Stage::Group(0)).len();
    let mut levels: Vec<Vec<Partial>> = vec![Vec::new(); buckets.len() + 1];
    levels[0].push(Partial {
        ends: vec![0.0; group_lanes],
        cost: 0.0,
        groups: Vec::new(),
    });

    for at in 0..buckets.len() {
        for state in prune(std::mem::take(&mut levels[at]), FRONTIER) {
            for end in at + 1..=buckets.len() {
                let members: Vec<usize> = buckets[at..end].concat();
                let release = arrival(*members.last().expect("a bucket is never empty"));
                let attesters = members.iter().map(|&i| units[i].attesters()).sum::<usize>() as f64;
                let cost = policy.prover.group_cost(attesters, members.len() as f64);

                let mut ends = state.ends.clone();
                let lane = ends
                    .iter()
                    .enumerate()
                    .min_by(|a, b| a.1.total_cmp(b.1))
                    .map(|(i, _)| i)
                    .expect("a group always has a lane");
                ends[lane] = release.max(ends[lane]) + policy.prover.seconds(cost);
                ends.sort_by(|a, b| a.total_cmp(b));

                let mut groups = state.groups.clone();
                groups.push(members);
                levels[end].push(Partial {
                    ends,
                    cost: state.cost + cost,
                    groups,
                });
            }
        }
    }

    prune(std::mem::take(&mut levels[buckets.len()]), FRONTIER)
        .into_iter()
        .map(|state| state.groups)
        .collect()
}

/// A prefix of the epoch cut into groups, and where that left the lanes.
#[derive(Clone)]
struct Partial {
    /// Lane finish times, ascending.
    ends: Vec<f64>,
    cost: f64,
    groups: Vec<Vec<usize>>,
}

/// Drop states another state beats on cost and on every lane.
///
/// The cap keeps both ends of the trade: the cheapest states, which is what the
/// bulk of the epoch is chosen on, and the earliest-finishing ones, which is
/// what the deadline is met on.
fn prune(mut states: Vec<Partial>, cap: usize) -> Vec<Partial> {
    states.sort_by(|a, b| a.cost.total_cmp(&b.cost));
    let mut kept: Vec<Partial> = Vec::new();
    for state in states {
        let dominated = kept
            .iter()
            .any(|other| other.ends.iter().zip(&state.ends).all(|(a, b)| a <= b));
        if !dominated {
            kept.push(state);
        }
    }
    if kept.len() > cap {
        let mut by_finish: Vec<Partial> = kept.clone();
        let finish = |state: &Partial| state.ends.last().copied().unwrap_or(0.0);
        by_finish.sort_by(|a, b| finish(a).total_cmp(&finish(b)));
        kept.truncate(cap / 2);
        kept.extend(by_finish.into_iter().take(cap / 2));
    }
    kept
}

/// Place one partition's proofs on lanes and read off `T2`.
fn simulate(
    units: &[StreamUnit],
    groups: &[Vec<usize>],
    tail: &[usize],
    arrival: &impl Fn(usize) -> f64,
    deadline_s: f64,
    threshold_s: f64,
    policy: &StreamPolicy,
) -> Schedule {
    let model = &policy.prover;
    let mut lanes = Lanes::new(policy.lanes);
    let mut proofs: Vec<ScheduledProof> = Vec::new();
    let attesters = |members: &[usize]| members.iter().map(|&i| units[i].attesters()).sum::<usize>();
    let counted = |members: &[usize]| members.iter().map(|&i| units[i].counted()).sum::<usize>();

    let mut group_end = Vec::with_capacity(groups.len());
    for (i, members) in groups.iter().enumerate() {
        let release = arrival(*members.last().expect("a group is never empty"));
        let cost = model.group_cost(attesters(members) as f64, members.len() as f64);
        let (lane, start) = lanes.place(policy.eligible(Stage::Group(i)), release, model.seconds(cost));
        let end = start + model.seconds(cost);
        group_end.push(end);
        proofs.push(ScheduledProof {
            stage: Stage::Group(i),
            lane,
            start_s: start,
            end_s: end,
            cost,
        });
    }

    // Fold whatever has finished since the last fold. A fold that cannot land
    // before the final proof wants it is not worth running: the groups under it
    // go straight to the final proof, which is what `StreamFinalWitness::groups`
    // is for and costs it an Fp12 multiply each rather than a whole proof.
    let mut order: Vec<usize> = (0..groups.len()).collect();
    order.sort_by(|&a, &b| group_end[a].total_cmp(&group_end[b]));

    let mut folds: Vec<Vec<usize>> = Vec::new();
    let mut chain_free = 0.0f64;
    let mut cursor = 0usize;
    while cursor < order.len() {
        let first = cursor;
        let ready = group_end[order[cursor]].max(chain_free);
        while cursor < order.len() && group_end[order[cursor]] <= ready {
            cursor += 1;
        }
        let absorbed: Vec<usize> = order[first..cursor].to_vec();
        let members: Vec<usize> = absorbed.iter().flat_map(|&g| groups[g].clone()).collect();
        let cost = model.fold_cost(absorbed.len() as f64, counted(&members) as f64);
        let duration = model.seconds(cost);
        let (lane, start) = lanes.peek(policy.eligible(Stage::Fold(folds.len())), ready, duration);
        if start + duration > deadline_s {
            cursor = first;
            break;
        }
        lanes.commit(lane, start, duration);
        chain_free = start + duration;
        proofs.push(ScheduledProof {
            stage: Stage::Fold(folds.len()),
            lane,
            start_s: start,
            end_s: chain_free,
            cost,
        });
        folds.push(absorbed);
    }

    let unfolded: Vec<usize> = order[cursor..].to_vec();
    let mut release = deadline_s.max(chain_free);
    for &g in &unfolded {
        release = release.max(group_end[g]);
    }

    let mut inline: Vec<usize> = unfolded.iter().flat_map(|&g| groups[g].clone()).collect();
    inline.extend_from_slice(tail);
    let cost = model.final_cost(
        attesters(tail) as f64,
        tail.len() as f64,
        counted(&inline) as f64,
        unfolded.len() as f64,
        !folds.is_empty(),
    );
    let duration = model.seconds(cost);
    let (lane, start) = lanes.place(policy.eligible(Stage::Final), release, duration);
    proofs.push(ScheduledProof {
        stage: Stage::Final,
        lane,
        start_s: start,
        end_s: start + duration,
        cost,
    });

    let wrap = model.warm_fixed_s + model.wrap_s;
    lanes.commit(lane, start + duration, wrap);
    proofs.push(ScheduledProof {
        stage: Stage::Wrap,
        lane,
        start_s: start + duration,
        end_s: start + duration + wrap,
        cost: 0.0,
    });

    let postable_s = start + duration + wrap;
    proofs.sort_by(|a, b| a.start_s.total_cmp(&b.start_s));
    let occupied: BTreeSet<usize> = proofs.iter().map(|p| p.lane).collect();

    Schedule {
        plan: StreamPlan {
            groups: groups.to_vec(),
            folds,
            absorbed: unfolded,
            tail: tail.to_vec(),
            attesting_balance: 0,
            threshold_reached: false,
        },
        total_cost: proofs.iter().map(|p| p.cost).sum(),
        lanes: occupied.len(),
        proofs,
        threshold_s,
        postable_s,
    }
}

/// Busy windows per lane, so a proof can drop into a gap between two others
/// rather than only onto the end of a queue. The fold chain lives in those gaps.
struct Lanes(Vec<Vec<(f64, f64)>>);

impl Lanes {
    fn new(lanes: usize) -> Self {
        Self(vec![Vec::new(); lanes])
    }

    /// Earliest start at or after `release` that leaves `duration` clear.
    fn earliest(&self, lane: usize, release: f64, duration: f64) -> f64 {
        let mut start = release;
        for &(busy_start, busy_end) in &self.0[lane] {
            if busy_start < start + duration && start < busy_end {
                start = busy_end;
            }
        }
        start
    }

    /// Whichever eligible lane could start it first, and when.
    fn peek(&self, eligible: std::ops::Range<usize>, release: f64, duration: f64) -> (usize, f64) {
        eligible
            .map(|lane| (lane, self.earliest(lane, release, duration)))
            .min_by(|a, b| a.1.total_cmp(&b.1).then(a.0.cmp(&b.0)))
            .expect("every stage has at least one lane")
    }

    fn commit(&mut self, lane: usize, start: f64, duration: f64) {
        let at = self.0[lane].partition_point(|&(s, _)| s < start);
        self.0[lane].insert(at, (start, start + duration));
    }

    fn place(&mut self, eligible: std::ops::Range<usize>, release: f64, duration: f64) -> (usize, f64) {
        let (lane, start) = self.peek(eligible, release, duration);
        self.commit(lane, start, duration);
        (lane, start)
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
/// Folds and absorptions follow the plan, so a run here has the same proof count
/// and the same critical path as the scheduled one, not a worst case.
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
    let mut group_millers = Vec::new();
    let mut aggregate_witnesses = Vec::new();
    let mut aggregate_outputs = Vec::new();

    for group in &plan.groups {
        let members: Vec<&StreamUnit> = group.iter().map(|&i| &units[i]).collect();
        let witness = group_witness(context, tree, &members);

        // The circuit produces the output; the host keeps the Miller
        // accumulator, which the output only commits to.
        let attested = zkasper_slot_proof_guest::attest(&witness, context.acc_depth);
        group_outputs.push(zkasper_slot_proof_guest::verify_group_proof_with_depth(
            &witness,
            context.acc_depth,
        ));
        group_witnesses.push(witness);
        group_millers.push(attested.miller);
    }

    let members = |group: usize| -> Vec<&StreamUnit> {
        plan.groups[group].iter().map(|&i| &units[i]).collect()
    };

    let mut aggregate: Option<AggregateOutput> = None;
    let mut aggregate_miller = zkasper_common::bls::FP12_ONE;

    for fold in &plan.folds {
        let aggregate_witness = aggregate_witness(
            context,
            &mut dedup_tree,
            aggregate.clone(),
            Vec::new(),
            aggregate_miller,
            fold.iter().map(|&g| group_outputs[g].clone()).collect(),
            fold.iter().map(|_| Vec::new()).collect(),
            fold.iter().map(|&g| group_millers[g]).collect(),
            fold.iter().map(|&g| counted_indices(&members(g))).collect(),
        );
        let next = zkasper_aggregation_guest::verify_aggregate_with_depth(
            &aggregate_witness,
            context.dedup_depth(),
        );

        for &g in fold {
            aggregate_miller = zkasper_common::bls::fp12_mul(&aggregate_miller, &group_millers[g]);
        }
        aggregate = Some(next.clone());

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
        plan.absorbed
            .iter()
            .map(|&g| group_outputs[g].clone())
            .collect(),
        plan.absorbed.iter().map(|_| Vec::new()).collect(),
        plan.absorbed.iter().map(|&g| group_millers[g]).collect(),
        plan.absorbed
            .iter()
            .map(|&g| counted_indices(&members(g)))
            .collect(),
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
