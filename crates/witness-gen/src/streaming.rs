//! Streaming: cut an epoch into groups a fixed set of GPUs can finish in time.
//!
//! # The quantity being minimised
//!
//! `T` is when the chain has published enough attestations to justify the
//! target. `T2` is when a postable proof exists. `T2 − T` is the only latency a
//! consumer sees, and it is *not* the cost of proving an epoch — it is the cost
//! of whatever still depends on the last attestation.
//!
//! # Since complement proving, the floor is the schedule
//!
//! A slot proof names absentees rather than attesters, so the hundred-odd
//! leaves it opens cost about 7M — against a per-proof floor of 789M, and
//! against 52M for every *distinct message* the slot's aggregates carry.
//! Epoch 430529 averages 2.8 messages a slot, so minority head votes, not
//! absentees, are what a slot costs; and the floor is what a *proof* costs.
//! Two things follow and they point the same way.
//!
//! **Every proof is mostly floor, so there should be as few as possible.** A
//! group of twenty slots costs about twice a group of one. Group size is barely
//! a cost trade any more; it is a deadline trade, and outside the last few slots
//! the answer is always "one more group is a wasted floor".
//!
//! **Exactly one floor belongs between `T` and `T2`.** The epoch's last
//! complement cannot be proven before it exists, and whatever else is proven
//! after `T` is a second floor in series with it. So the crossing slot goes
//! inline into the final proof rather than into a group of its own — and so does
//! every slot behind it that a group could not have finished in a slot's time,
//! which is what [`StreamPlan::tail`] is for. At a 789M floor a one-slot group
//! takes around 16s against a 12s slot, so that is two slots; below about 620M
//! it is one, and the schedule finds the boundary rather than assuming it.
//!
//! # What the schedule is up against is arrival time, not throughput
//!
//! A slot's marginal work is now near a second, against twelve seconds of
//! wall-clock to do it in, so a single warm prover keeps up with the epoch
//! comfortably. What it cannot do is start before the attestations exist. Extra
//! GPUs buy the *bulk* of the epoch — and the committee proof the next epoch
//! needs — but never the end of it, which is why [`Schedule::lanes`] settles low
//! and [`schedule`] treats `lanes` as a budget it is free not to spend.
//!
//! # Margin
//!
//! [`StreamPolicy::threshold_numerator`] is the *scheduling* threshold and
//! defaults above 2/3, because attestations already collected can turn out not
//! to count. The circuit enforces exactly 2/3 and does not know what margin the
//! schedule used, so a margin that is too thin costs a retry, never soundness.
//! It is not free: weight arrives one slot's committee at a time, about 3.1% of
//! the stake, so any margin that pushes the crossing into the next slot costs a
//! whole slot. [`Schedule::threshold_s`] is measured at 2/3 regardless, so that
//! cost shows up in `T2 − T` rather than hiding in the choice of `T`.

use zkasper_common::acc::Digest;
use zkasper_common::bls::Fp12;
use zkasper_common::recursion::ProgramVk;
use zkasper_common::types::{
    AccMultiProof, AggregateOutput, AggregateWitness, BlockHeaderFields, CommitteeOutput,
    EpochDiffOutput, GroupProofOutput, MillerAccumulator, PreviousJustification, SlotProofWitness,
    StreamFinalWitness,
};

use crate::acc_tree::AccTree;
use crate::attestation_collector::SlotComplement;
use crate::committee::EpochCommittees;

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

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
    /// One committee leaf per slot, 32 slots to an epoch.
    pub const COMMITTEE_DEPTH: u32 = 5;
}

/// Internal compressions a multi-proof over `leaves` random leaves needs.
///
/// A node at level `k` covers 2^k leaves, so it is touched unless every one of
/// those slots is empty. Near the bottom almost every touched node is distinct;
/// higher up the set collapses and the whole level is rebuilt.
fn batched_nodes(leaves: f64, depth: u32) -> f64 {
    let capacity = (1u64 << depth) as f64;
    (1..=depth)
        .map(|k| {
            let covered = (1u64 << k) as f64;
            capacity / covered * (1.0 - (1.0 - covered / capacity).powf(leaves))
        })
        .sum()
}

fn open_leaves(leaves: f64, depth: u32) -> f64 {
    leaves * cost::ACC_LEAF + batched_nodes(leaves, depth) * cost::ACC_NODE
}

/// Rebuilding the 32-leaf committee tree from its summed buckets.
fn committee_tree() -> f64 {
    (1u64 << cost::COMMITTEE_DEPTH) as f64 * cost::ACC_LEAF
        + ((1u64 << cost::COMMITTEE_DEPTH) - 1) as f64 * cost::ACC_NODE
}

/// Hash-to-curve, Miller loops and the subgroup check for `messages`.
fn bls(messages: f64) -> f64 {
    messages * cost::HASH_TO_CURVE
        + cost::MILLER_BATCH
        + (messages + 1.0) * cost::MILLER_PAIR
        + cost::G2_SUBGROUP
}

/// What a set of slot complements costs short of the final exponentiation.
///
/// `named` is what the group opens against the accumulator: its absentees, one
/// curve subtraction each, and the signers of any minority head vote, which cost
/// one addition more apiece than this charges them. `messages` is distinct
/// signing roots, because the Miller accumulator keys on the root — extra
/// aggregates over one message cost a G2 add and nothing else.
fn complement_work(named: f64, slots: f64, messages: f64, acc_depth: u32) -> f64 {
    open_leaves(named, acc_depth)
        + named * cost::G1_ADD
        + open_leaves(slots, cost::COMMITTEE_DEPTH)
        + bls(messages)
}

/// What the prover charges and how fast it discharges it.
///
/// Parameters rather than constants: `proof_base` is a display value in Zisk
/// that does not match the shipped AIR layout and is being re-measured, and
/// `units_per_second` moves with the card. Complement proving left the floor as
/// most of every proof, so the schedule is now more sensitive to these two than
/// to anything it can decide, and they belong in the input.
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
    /// Unmeasured — `scripts/bench.py` has no figure for it and the rest of the
    /// cost model folds it into the floor. It is the only thing that makes a
    /// fold worth its own proof now that the counted set is a `slots_mask`, so
    /// it is a parameter and not a zero baked in.
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
    /// Wall-clock a warm prover takes over `cost`.
    pub fn seconds(&self, cost: f64) -> f64 {
        self.warm_fixed_s + cost / self.units_per_second
    }

    /// One group proof: slot complements verified as far as the Miller loop,
    /// which the final exponentiation is deliberately not part of.
    pub fn group_cost(&self, named: f64, slots: f64, messages: f64) -> f64 {
        self.proof_base + complement_work(named, slots, messages, self.acc_depth)
    }

    /// One fold, absorbing `groups` finished group proofs.
    ///
    /// Nothing but the floor and an Fp12 multiply each: cross-slot deduplication
    /// is a `slots_mask` now, so a fold no longer opens a counted-set tree.
    pub fn fold_cost(&self, groups: f64) -> f64 {
        self.proof_base
            + (groups + 1.0) * self.recursion_verify
            + groups * (cost::FP12_MUL + cost::COMMIT_FP12)
    }

    /// The final proof: the tail's complements inline, `absorbed` group proofs
    /// taken directly, and the epoch's one final exponentiation.
    pub fn final_cost(
        &self,
        named: f64,
        slots: f64,
        messages: f64,
        absorbed: f64,
        folded: bool,
    ) -> f64 {
        self.proof_base
            + if slots > 0.0 {
                complement_work(named, slots, messages, self.acc_depth)
            } else {
                0.0
            }
            + cost::FINAL_EXP
            // With no fold to inherit from, the final proof verifies the epoch
            // diff and the committee proof itself, on the critical path.
            + (absorbed + if folded { 1.0 } else { 2.0 }) * self.recursion_verify
            + (absorbed + 1.0) * (cost::FP12_MUL + cost::COMMIT_FP12)
    }

    /// One chunk of the per-epoch committee proof, which sums every slot's
    /// committee out of the accumulator.
    ///
    /// Chunks are independent: a validator lands in exactly one index range and
    /// bucket sums add, so `chunks` of them plus a fold produce the same
    /// committee root as one proof over the whole registry. A chunk publishes
    /// the 32 partial buckets rather than a root, so only the last proof in the
    /// chain builds the tree.
    pub fn committee_chunk_cost(&self, validators: f64, chunks: f64) -> f64 {
        let share = validators / chunks;
        self.proof_base
            + open_leaves(share, self.acc_depth)
            + share * cost::G1_ADD
            + if chunks == 1.0 { committee_tree() } else { 0.0 }
    }

    /// The fold that adds committee chunks together and builds the tree.
    pub fn committee_fold_cost(&self, chunks: f64) -> f64 {
        self.proof_base
            + (chunks + 1.0) * self.recursion_verify
            + chunks * (1u64 << cost::COMMITTEE_DEPTH) as f64 * cost::G1_ADD
            + committee_tree()
    }
}

/// Whether a warm prover can run any stage or is pinned to one program.
///
/// `cargo-zisk setup` is per-program, so a prover holding a proving key open may
/// only be able to run the ELF it was set up for. That is not a detail: it
/// decides whether the fold chain and the committee proof can borrow an idle
/// group lane or need cards of their own sitting idle for most of an epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanePool {
    /// One ELF branching on a mode discriminant: any lane runs any stage.
    Fungible,
    /// A lane per program. One is reserved for folds and one for the final
    /// proof and its wrap; the rest run group and committee proofs.
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
    /// schedule: a group cannot start before the last slot it covers closed.
    pub seconds_per_slot: f64,
    pub slots_per_epoch: u64,
    /// Warm provers available. One saturates a card — a warm prover pins about
    /// 30 GB against an RTX 5090's 32.6 GB — so this is a GPU count, and the
    /// schedule treats it as a budget rather than a target.
    pub lanes: usize,
    pub lane_pool: LanePool,
    /// Active validators, for the committee proof this epoch owes the next one.
    /// Zero leaves it out of the schedule.
    pub validators: f64,
    /// Chunks that committee proof is cut into.
    pub committee_chunks: usize,
    pub prover: ProverModel,
}

impl Default for StreamPolicy {
    fn default() -> Self {
        Self {
            threshold_numerator: 70,
            threshold_denominator: 100,
            seconds_per_slot: 12.0,
            slots_per_epoch: 32,
            lanes: 3,
            lane_pool: LanePool::Fungible,
            validators: 0.0,
            committee_chunks: 1,
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

    /// Lanes each stage may run on, in the order it should prefer them.
    ///
    /// Deadline work packs from the bottom so that it leaves whole cards clear;
    /// the committee proof fills from the top, because it is one contiguous
    /// block longer than any gap the epoch's own work leaves and it wants a card
    /// to itself rather than the first hole it fits in.
    fn eligible(&self, stage: Stage) -> Vec<usize> {
        let committee = matches!(stage, Stage::Committee(_) | Stage::CommitteeFold);
        let lanes: Vec<usize> = if self.lane_pool == LanePool::Fungible {
            (0..self.lanes).collect()
        } else {
            // The reserved lanes are the last two, so a group lane's index is
            // stable as the pool grows. Below three lanes they overlap, which is
            // the honest answer: a specialised pool of two cannot separate three
            // programs.
            let last = self.lanes.saturating_sub(1);
            let fold = last.saturating_sub(1);
            match stage {
                Stage::Group(_) | Stage::Committee(_) => (0..fold.max(1)).collect(),
                Stage::Fold(_) | Stage::CommitteeFold => vec![fold],
                _ => vec![last],
            }
        };
        if committee {
            lanes.into_iter().rev().collect()
        } else {
            lanes
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
    /// One chunk of the committee proof the next epoch needs, and then the fold
    /// that adds the chunks up.
    Committee(usize),
    CommitteeFold,
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
    /// GPUs the schedule occupies, which is at most the policy's lane budget.
    pub lanes: usize,
    /// `T`: when the chain has published 2/3 of the stake.
    pub threshold_s: f64,
    /// `T2`: when the wrapped proof exists.
    pub postable_s: f64,
    /// When the last committee chunk for the next epoch lands, against the
    /// epoch it has to land inside. That is a throughput bound and not a latency
    /// one — the committee is fixed two epochs before it is used — but it is the
    /// bound that decides how many cards the fleet needs.
    pub committee_done_s: f64,
    pub epoch_s: f64,
    pub total_cost: f64,
}

impl Schedule {
    /// `T2 − T`, the only latency a consumer sees.
    pub fn latency_s(&self) -> f64 {
        self.postable_s - self.threshold_s
    }

    /// How far the committee proof runs past the epoch that owes it.
    pub fn committee_overrun_s(&self) -> f64 {
        (self.committee_done_s - self.epoch_s).max(0.0)
    }
}

/// Cut a stream of slot complements into groups plus an inline tail.
///
/// Units must be in ascending attestation-slot order, which is also the order a
/// node publishes the blocks that carry them.
pub fn plan(
    units: &[SlotComplement],
    total_active_balance: u64,
    policy: &StreamPolicy,
) -> StreamPlan {
    schedule(units, total_active_balance, policy).plan
}

/// Plan an epoch and place every proof on a lane and on the clock.
///
/// `policy.lanes` is a budget, not a target: a card that buys no latency is a
/// card the schedule declines to use, which is what makes [`Schedule::lanes`]
/// readable as the GPU count the epoch actually needs.
pub fn schedule(
    units: &[SlotComplement],
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

/// The objective: latency, then GPUs, then cost — behind the one hard
/// constraint, which is that an epoch owes the next one a committee proof and a
/// schedule that does not deliver it is not a schedule at all.
///
/// Latency is compared in tenths of a second, because the constants underneath
/// are not good to a hundredth and a schedule should not buy a card or an extra
/// proof with noise.
fn better(a: &Schedule, b: &Schedule) -> std::cmp::Ordering {
    let tenths = |s: &Schedule| (s.latency_s() * 10.0).round() as i64;
    let overrun = |s: &Schedule| (s.committee_overrun_s() * 10.0).round() as i64;
    overrun(a)
        .cmp(&overrun(b))
        .then(tenths(a).cmp(&tenths(b)))
        .then(a.lanes.cmp(&b.lanes))
        .then(a.total_cost.total_cmp(&b.total_cost))
}

fn with_lanes(
    units: &[SlotComplement],
    total_active_balance: u64,
    policy: &StreamPolicy,
) -> Schedule {
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
            committee_done_s: 0.0,
            epoch_s: 0.0,
            total_cost: 0.0,
        };
    }

    let first_slot = units[0].slot;
    // Absolute arrival is at least a slot later than this: an attestation for
    // slot `s` cannot appear before the block at `s + 1`. Every unit shifts by
    // the same delay and `T2 − T` is a difference, so the schedule is unaffected
    // — closing a slot early is safe, because a member whose aggregate has not
    // arrived is simply an absentee and costs that slot a little weight.
    let arrival = |i: usize| (units[i].slot - first_slot) as f64 * policy.seconds_per_slot;

    let target = policy.target_balance(total_active_balance);
    let quorum = policy.quorum_balance(total_active_balance);
    let mut running = 0u128;
    let mut quorum_at = None;
    let mut crossing = None;
    for (i, unit) in units.iter().enumerate() {
        running += unit.marginal_balance as u128;
        quorum_at = quorum_at.or((running >= quorum).then_some(i));
        if running >= target {
            crossing = Some(i);
            break;
        }
    }
    let threshold_s = arrival(quorum_at.unwrap_or(units.len() - 1));

    let threshold_reached = crossing.is_some();
    let last = crossing.unwrap_or(units.len() - 1);
    let attesting_balance = units[..=last].iter().map(|u| u.marginal_balance).sum();

    // How much of the epoch's end the final proof swallows whole. Past four
    // slots the tail is always worse than a group: the group has slack the tail
    // does not, and a group is one floor either way.
    const MAX_TAIL: usize = 4;

    let best = (0..=MAX_TAIL.min(last))
        .flat_map(|inline| {
            let head: Vec<usize> = (0..=last - inline).collect();
            let tail: Vec<usize> = (last + 1 - inline..=last).collect();
            search(units, &head, &arrival, policy)
                .into_iter()
                .map(move |partition| (partition, tail.clone()))
        })
        .map(|(partition, tail)| simulate(units, &partition, &tail, &arrival, threshold_s, policy))
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
/// A dynamic program over slots: the state after cutting a prefix is the lanes'
/// finish times and the cost paid so far, and a state that is no worse on every
/// lane *and* cheaper dominates. That is exact for the group stage — group
/// releases only increase, so a later group never wants an earlier lane gap —
/// and it collapses the 2^21 partitions of a mainnet epoch to a few dozen.
fn search(
    units: &[SlotComplement],
    head: &[usize],
    arrival: &impl Fn(usize) -> f64,
    policy: &StreamPolicy,
) -> Vec<Vec<Vec<usize>>> {
    /// Enough that widening it changes no schedule on a mainnet epoch; only
    /// there so a pathological arrival pattern cannot make the search blow up.
    const FRONTIER: usize = 256;

    if head.is_empty() {
        return vec![Vec::new()];
    }

    // Once per width, because the width the partition is *cut* for and the width
    // it eventually *runs* on are not the same thing: a cut made for one lane
    // stacks the epoch on one card and leaves the others clear for the committee
    // proof, which is the schedule that actually wins.
    (1..=policy.eligible(Stage::Group(0)).len())
        .flat_map(|width| cuts(units, head, arrival, policy, width, FRONTIER))
        .collect()
}

fn cuts(
    units: &[SlotComplement],
    head: &[usize],
    arrival: &impl Fn(usize) -> f64,
    policy: &StreamPolicy,
    group_lanes: usize,
    frontier: usize,
) -> Vec<Vec<Vec<usize>>> {
    let mut levels: Vec<Vec<Partial>> = vec![Vec::new(); head.len() + 1];
    levels[0].push(Partial {
        ends: vec![0.0; group_lanes],
        cost: 0.0,
        groups: Vec::new(),
    });

    for at in 0..head.len() {
        for state in prune(std::mem::take(&mut levels[at]), frontier) {
            for end in at + 1..=head.len() {
                let members = head[at..end].to_vec();
                let release = arrival(*members.last().expect("a group is never empty"));
                let cost = policy.prover.group_cost(
                    named(units, &members),
                    members.len() as f64,
                    messages(units, &members),
                );

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

    prune(std::mem::take(&mut levels[head.len()]), frontier)
        .into_iter()
        .map(|state| state.groups)
        .collect()
}

/// Accumulator leaves a set of units opens: their absentees and whatever
/// minority-message signers they name.
fn named(units: &[SlotComplement], members: &[usize]) -> f64 {
    members
        .iter()
        .map(|&i| units[i].named_indices.len())
        .sum::<usize>() as f64
}

/// Distinct messages a set of units pairs against: one per slot, plus one for
/// every minority head vote.
fn messages(units: &[SlotComplement], members: &[usize]) -> f64 {
    members
        .iter()
        .map(|&i| 1 + units[i].witness.secondary.len())
        .sum::<usize>() as f64
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
        let finish = |state: &Partial| state.ends.last().copied().unwrap_or(0.0);
        let mut by_finish: Vec<Partial> = kept.clone();
        by_finish.sort_by(|a, b| finish(a).total_cmp(&finish(b)));
        kept.truncate(cap / 2);
        kept.extend(by_finish.into_iter().take(cap / 2));
    }
    kept
}

/// Place one partition's proofs on lanes and read off `T2`.
fn simulate(
    units: &[SlotComplement],
    groups: &[Vec<usize>],
    tail: &[usize],
    arrival: &impl Fn(usize) -> f64,
    threshold_s: f64,
    policy: &StreamPolicy,
) -> Schedule {
    let model = &policy.prover;
    let mut lanes = Lanes::new(policy.lanes);
    let mut proofs: Vec<ScheduledProof> = Vec::new();

    let deadline_s = tail
        .iter()
        .chain(groups.concat().iter())
        .map(|&i| arrival(i))
        .fold(0.0, f64::max);

    let mut group_end = Vec::with_capacity(groups.len());
    for (i, members) in groups.iter().enumerate() {
        let cost = model.group_cost(
            named(units, members),
            members.len() as f64,
            messages(units, members),
        );
        let (lane, start) = lanes.place(
            &policy.eligible(Stage::Group(i)),
            arrival(*members.last().expect("a group is never empty")),
            model.seconds(cost),
        );
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
    // is for and costs an Fp12 multiply each rather than a whole proof.
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
        let cost = model.fold_cost((cursor - first) as f64);
        let duration = model.seconds(cost);
        let (lane, start) = lanes.peek(&policy.eligible(Stage::Fold(folds.len())), ready, duration);
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
        folds.push(order[first..cursor].to_vec());
    }

    let unfolded: Vec<usize> = order[cursor..].to_vec();
    let mut release = deadline_s.max(chain_free);
    for &g in &unfolded {
        release = release.max(group_end[g]);
    }

    let cost = model.final_cost(
        named(units, tail),
        tail.len() as f64,
        messages(units, tail),
        unfolded.len() as f64,
        !folds.is_empty(),
    );
    let duration = model.seconds(cost);
    let (lane, start) = lanes.place(&policy.eligible(Stage::Final), release, duration);
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

    // The committee proof the next epoch needs is fixed two epochs before it is
    // used, so it is scheduled last: it takes whatever the deadline work leaves,
    // and what it costs the fleet is a card's worth of idle time, not latency.
    let mut committee_done_s = 0.0f64;
    if policy.validators > 0.0 {
        for chunk in 0..policy.committee_chunks {
            let cost =
                model.committee_chunk_cost(policy.validators, policy.committee_chunks as f64);
            let duration = model.seconds(cost);
            let (lane, start) =
                lanes.place(&policy.eligible(Stage::Committee(chunk)), 0.0, duration);
            committee_done_s = committee_done_s.max(start + duration);
            proofs.push(ScheduledProof {
                stage: Stage::Committee(chunk),
                lane,
                start_s: start,
                end_s: start + duration,
                cost,
            });
        }
        if policy.committee_chunks > 1 {
            let cost = model.committee_fold_cost(policy.committee_chunks as f64);
            let duration = model.seconds(cost);
            let (lane, start) = lanes.place(
                &policy.eligible(Stage::CommitteeFold),
                committee_done_s,
                duration,
            );
            committee_done_s = start + duration;
            proofs.push(ScheduledProof {
                stage: Stage::CommitteeFold,
                lane,
                start_s: start,
                end_s: committee_done_s,
                cost,
            });
        }
    }

    proofs.sort_by(|a, b| a.start_s.total_cmp(&b.start_s));
    let occupied: std::collections::BTreeSet<usize> = proofs.iter().map(|p| p.lane).collect();

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
        committee_done_s,
        epoch_s: policy.slots_per_epoch as f64 * policy.seconds_per_slot,
    }
}

/// Busy windows per lane, so a proof can drop into a gap between two others
/// rather than only onto the end of a queue. The fold chain and the committee
/// proof live in those gaps.
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

    /// Whichever eligible lane could start it first, ties going to whichever the
    /// stage listed first.
    fn peek(&self, eligible: &[usize], release: f64, duration: f64) -> (usize, f64) {
        eligible
            .iter()
            .map(|&lane| (lane, self.earliest(lane, release, duration)))
            .enumerate()
            .min_by(|a, b| a.1 .1.total_cmp(&b.1 .1).then(a.0.cmp(&b.0)))
            .map(|(_, placed)| placed)
            .expect("every stage has at least one lane")
    }

    fn commit(&mut self, lane: usize, start: f64, duration: f64) {
        let at = self.0[lane].partition_point(|&(s, _)| s < start);
        self.0[lane].insert(at, (start, start + duration));
    }

    fn place(&mut self, eligible: &[usize], release: f64, duration: f64) -> (usize, f64) {
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
    pub committee_program_vk: ProgramVk,
    /// The diff that carried the accumulator into this epoch, with its proof.
    ///
    /// Verified by the fold that opens the epoch, which is as early as it can
    /// be: the diff exists at the epoch boundary, and every later proof
    /// inherits the link rather than re-verifying it.
    pub epoch_diff: EpochDiffOutput,
    pub epoch_diff_proof: Vec<u64>,
    /// This epoch's committee proof, on the same terms: known an epoch ahead,
    /// verified once by the fold that opens the epoch.
    pub committee: CommitteeOutput,
    pub committee_proof: Vec<u64>,
    pub acc_depth: u32,
}

/// Build the witness for one group proof.
pub fn group_witness(
    context: &StreamContext,
    tree: &AccTree,
    committees: &EpochCommittees,
    units: &[&SlotComplement],
) -> SlotProofWitness {
    SlotProofWitness {
        accumulator_commitment: context.accumulator_commitment,
        committee_root: committees.root(),
        target_epoch: context.target_epoch,
        target_root: context.target_root,
        signing_domain: context.signing_domain,
        acc_root: context.acc_root,
        total_active_balance: context.total_active_balance,
        acc_multi_proof: acc_multi_proof(tree, units),
        committee_multi_proof: committee_multi_proof(committees, units),
        slots: units.iter().map(|u| u.witness.clone()).collect(),
    }
}

/// Accumulator opening over every validator the units name — their absentees and
/// whatever minority-message signers they enumerate. Not their attesters, which
/// is the point.
fn acc_multi_proof(tree: &AccTree, units: &[&SlotComplement]) -> AccMultiProof {
    let indices: Vec<u64> = units
        .iter()
        .flat_map(|u| u.named_indices.iter().copied())
        .collect();
    tree.build_multi_proof(&indices)
}

/// Committee-tree opening over the slots the units cover.
fn committee_multi_proof(committees: &EpochCommittees, units: &[&SlotComplement]) -> AccMultiProof {
    let slots: Vec<u64> = units.iter().map(|u| u.witness.slot_in_epoch).collect();
    committees.multi_proof(&slots)
}

/// Build the witness that folds finished group proofs into the running aggregate.
#[allow(clippy::too_many_arguments)]
pub fn aggregate_witness(
    context: &StreamContext,
    previous: Option<AggregateOutput>,
    previous_proof: Vec<u64>,
    previous_miller: Fp12,
    groups: Vec<GroupProofOutput>,
    group_proofs: Vec<Vec<u64>>,
    group_millers: Vec<Fp12>,
) -> AggregateWitness {
    // Only the fold that opens the epoch needs the diff and the committee proof;
    // the rest inherit both from the aggregate they extend.
    let opens_the_epoch = previous.is_none();

    AggregateWitness {
        accumulator_commitment: context.accumulator_commitment,
        target_epoch: context.target_epoch,
        target_root: context.target_root,
        group_program_vk: context.group_program_vk,
        aggregate_program_vk: context.aggregate_program_vk,
        epoch_diff_program_vk: context.epoch_diff_program_vk,
        committee_program_vk: context.committee_program_vk,
        epoch_diff: opens_the_epoch.then(|| context.epoch_diff.clone()),
        epoch_diff_proof: if opens_the_epoch {
            context.epoch_diff_proof.clone()
        } else {
            Vec::new()
        },
        committee: opens_the_epoch.then(|| context.committee.clone()),
        committee_proof: if opens_the_epoch {
            context.committee_proof.clone()
        } else {
            Vec::new()
        },
        previous,
        previous_proof,
        previous_miller: MillerAccumulator(previous_miller),
        groups,
        group_proofs,
        group_millers: group_millers.into_iter().map(MillerAccumulator).collect(),
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
    committees: &EpochCommittees,
    aggregate: Option<AggregateOutput>,
    aggregate_proof: Vec<u64>,
    aggregate_miller: Fp12,
    groups: Vec<GroupProofOutput>,
    group_proofs: Vec<Vec<u64>>,
    group_millers: Vec<Fp12>,
    tail: &[&SlotComplement],
    previous_justification: PreviousJustification,
    previous_justification_proof: Vec<u64>,
    finalized_header: BlockHeaderFields,
) -> StreamFinalWitness {
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
        committee_program_vk: context.committee_program_vk,
        // Needed only when there is no aggregate to inherit the links from.
        epoch_diff: aggregate.is_none().then(|| context.epoch_diff.clone()),
        epoch_diff_proof: if aggregate.is_none() {
            context.epoch_diff_proof.clone()
        } else {
            Vec::new()
        },
        committee: aggregate.is_none().then(|| context.committee.clone()),
        committee_proof: if aggregate.is_none() {
            context.committee_proof.clone()
        } else {
            Vec::new()
        },
        aggregate,
        aggregate_proof,
        aggregate_miller: MillerAccumulator(aggregate_miller),
        groups,
        group_proofs,
        group_millers: group_millers.into_iter().map(MillerAccumulator).collect(),
        tail: tail.iter().map(|u| u.witness.clone()).collect(),
        tail_acc_multi_proof: acc_multi_proof(tree, tail),
        tail_committee_multi_proof: committee_multi_proof(committees, tail),
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
/// and the same critical path the scheduled one does, not a worst case.
#[allow(clippy::too_many_arguments)]
pub fn run_native(
    context: &StreamContext,
    tree: &AccTree,
    committees: &EpochCommittees,
    units: &[SlotComplement],
    plan: &StreamPlan,
    previous_justification: PreviousJustification,
    finalized_header: BlockHeaderFields,
) -> StreamRun {
    let mut group_witnesses = Vec::new();
    let mut group_outputs = Vec::new();
    let mut aggregate_witnesses = Vec::new();
    let mut aggregate_outputs = Vec::new();

    let mut group_millers = Vec::new();

    for group in &plan.groups {
        let members: Vec<&SlotComplement> = group.iter().map(|&i| &units[i]).collect();
        let witness = group_witness(context, tree, committees, &members);

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

    let mut aggregate: Option<AggregateOutput> = None;
    let mut aggregate_miller = zkasper_common::bls::FP12_ONE;

    for fold in &plan.folds {
        let aggregate_witness = aggregate_witness(
            context,
            aggregate.clone(),
            Vec::new(),
            aggregate_miller,
            fold.iter().map(|&g| group_outputs[g].clone()).collect(),
            fold.iter().map(|_| Vec::new()).collect(),
            fold.iter().map(|&g| group_millers[g]).collect(),
        );
        let next = zkasper_aggregation_guest::verify_aggregate(&aggregate_witness);

        for &g in fold {
            aggregate_miller = zkasper_common::bls::fp12_mul(&aggregate_miller, &group_millers[g]);
        }
        aggregate = Some(next.clone());

        aggregate_witnesses.push(aggregate_witness);
        aggregate_outputs.push(next);
    }

    let tail: Vec<&SlotComplement> = plan.tail.iter().map(|&i| &units[i]).collect();
    let final_witness = final_witness(
        context,
        tree,
        committees,
        aggregate,
        Vec::new(),
        aggregate_miller,
        plan.absorbed
            .iter()
            .map(|&g| group_outputs[g].clone())
            .collect(),
        plan.absorbed.iter().map(|_| Vec::new()).collect(),
        plan.absorbed.iter().map(|&g| group_millers[g]).collect(),
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
    use zkasper_common::types::{
        AttestationWitness, BlsSignature, CommitteeAggregate, SlotComplementWitness,
    };

    /// A complement worth `balance` that opens `named` accumulator leaves.
    ///
    /// Naming is what a complement costs — mainnet slots name 85 to 334 — so it
    /// is the one field of the witness the schedule reads besides the slot.
    fn unit(slot: u64, balance: u64, named: usize) -> SlotComplement {
        SlotComplement {
            slot,
            marginal_balance: balance,
            named_indices: (0..named as u64).collect(),
            witness: SlotComplementWitness {
                slot_in_epoch: slot % 32,
                committee: CommitteeAggregate {
                    pubkey: [0; 12],
                    balance,
                },
                primary: vec![AttestationWitness {
                    data_slot: slot,
                    data_index: 0,
                    data_beacon_block_root: [0; 32],
                    data_source_epoch: 0,
                    data_source_root: [0; 32],
                    data_target_epoch: 1,
                    data_target_root: [0; 32],
                    signature: BlsSignature([0; 96]),
                    attesting_validators: Vec::new(),
                }],
                secondary: Vec::new(),
                absentees: Vec::new(),
            },
        }
    }

    /// One slot per unit, each worth 4% of the stake: the threshold at 70%
    /// crosses at slot 17, and nothing past it is planned.
    fn even_epoch() -> Vec<SlotComplement> {
        (0..32).map(|s| unit(s, 4, 200)).collect()
    }

    fn with_floor(proof_base: f64) -> StreamPolicy {
        StreamPolicy {
            prover: ProverModel {
                proof_base,
                ..ProverModel::default()
            },
            ..StreamPolicy::default()
        }
    }

    /// The audited floor: what a proof really costs against the shipped proving
    /// key, rather than the constant Zisk displays.
    const AUDITED_FLOOR: f64 = 789_000_000.0;

    /// Slots with slack belong in as few groups as the deadline allows, because
    /// a group of twenty costs barely more than a group of one.
    #[test]
    fn the_bulk_of_the_epoch_is_one_group() {
        let schedule = schedule(&even_epoch(), 100, &with_floor(AUDITED_FLOOR));
        let sizes: Vec<usize> = schedule.plan.groups.iter().map(|g| g.len()).collect();
        assert!(sizes.len() <= 3, "the epoch was cut into {sizes:?}");
        assert!(
            sizes.windows(2).all(|w| w[0] >= w[1]),
            "groups are not large early and small late: {sizes:?}",
        );
        assert_eq!(
            schedule.plan.groups.concat().len() + schedule.plan.tail.len(),
            18,
        );
    }

    /// The point of the tail: a second floor in series after the last
    /// attestation costs more than proving that attestation inline ever saves.
    #[test]
    fn only_the_final_proof_starts_after_the_last_attestation() {
        let units = even_epoch();
        let schedule = schedule(&units, 100, &with_floor(AUDITED_FLOOR));
        let last = units[*schedule.plan.tail.last().expect("a tail")].slot;
        let arrival = (last - units[0].slot) as f64 * 12.0;

        let after: Vec<Stage> = schedule
            .proofs
            .iter()
            .filter(|p| p.start_s >= arrival)
            .map(|p| p.stage)
            .collect();
        assert_eq!(after, vec![Stage::Final, Stage::Wrap]);
    }

    /// A slot goes inline when no group could have finished it in the slot's
    /// worth of slack, so where the tail ends is a function of the floor.
    #[test]
    fn a_bigger_floor_pushes_another_slot_into_the_tail() {
        let units = even_epoch();
        let displayed = schedule(&units, 100, &with_floor(293_601_280.0));
        let audited = schedule(&units, 100, &with_floor(AUDITED_FLOOR));

        assert_eq!(displayed.plan.tail.len(), 1);
        assert_eq!(audited.plan.tail.len(), 2);
        assert!(audited.latency_s() > displayed.latency_s());
    }

    #[test]
    fn no_lane_runs_two_proofs_at_once() {
        let schedule = schedule(&even_epoch(), 100, &with_floor(AUDITED_FLOOR));
        for (i, a) in schedule.proofs.iter().enumerate() {
            for b in &schedule.proofs[i + 1..] {
                assert!(
                    a.lane != b.lane || a.end_s <= b.start_s || b.end_s <= a.start_s,
                    "lane {} runs {:?} and {:?} at once",
                    a.lane,
                    a.stage,
                    b.stage,
                );
            }
        }
    }

    /// The committee proof the next epoch needs is fixed two epochs ahead, so it
    /// is the one thing extra cards buy: it fills whatever the deadline work
    /// leaves and never moves `T2`.
    #[test]
    fn the_committee_proof_costs_throughput_and_not_latency() {
        let units = even_epoch();
        let policy = StreamPolicy {
            validators: 1_000_000.0,
            committee_chunks: 4,
            lanes: 4,
            ..with_floor(AUDITED_FLOOR)
        };
        let with = schedule(&units, 100, &policy);
        let without = schedule(&units, 100, &with_floor(AUDITED_FLOOR));

        assert_eq!(
            (with.latency_s() * 10.0).round(),
            (without.latency_s() * 10.0).round(),
        );
        assert!(with.committee_done_s > 0.0);
        assert!(
            with.lanes > without.lanes,
            "the chunks found no card to run on",
        );
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
        let units: Vec<SlotComplement> = (0..32).map(|s| unit(s, 2, 200)).collect();
        let plan = plan(&units, 100, &StreamPolicy::default());

        assert!(!plan.threshold_reached);
        assert_eq!(plan.attesting_balance, 64);
        assert!(plan.tail.contains(&31));
    }
}
