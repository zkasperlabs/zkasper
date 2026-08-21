//! Streaming: cut an epoch into groups a fixed set of GPUs can finish in time.
//!
//! # The quantity being minimised
//!
//! `T` is when the chain has published enough attestations to justify the
//! target. `T2` is when a postable proof exists. `T2 − T` is the only latency a
//! consumer sees, and it is *not* the cost of proving an epoch — it is the cost
//! of whatever still depends on the last attestation.
//!
//! # The model predicts seconds, because cost units are not a currency
//!
//! Everything here used to be denominated in Zisk cost units against one
//! throughput constant. An RTX 5090 campaign against Zisk v1.0.0-alpha
//! (`data/gpu_bench/`, `scripts/time_model.py`) disproved that: measured
//! effective throughput on real guests spans 18M to 249M units/s, and 83.6M
//! cost units of plain integer work bought 0.06 s. [`ProverModel`] is therefore
//! denominated in seconds, per work class, and every constant in it names the
//! measurement that set it.
//!
//! # Since complement proving, the floor is the schedule
//!
//! A slot proof names absentees rather than attesters, so the hundred-odd
//! leaves it opens cost about 0.15 s — against a **measured** stage floor of
//! 7.18 s, and against 0.25 s for every *distinct message* the slot's
//! aggregates carry. Epoch 430529 averages 2.8 messages a slot, so minority
//! head votes, not absentees, are what a slot costs; and the floor is what a
//! *proof* costs. Two things follow and they point the same way.
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
//! which is what [`StreamPlan::tail`] is for. How far back that reaches is a
//! floor question rather than a recursion one — see below — and the schedule
//! finds the boundary rather than assuming it: on mainnet 430529 at the measured
//! floor it inlines the last two slots.
//!
//! # And exactly two recursions do, which is now a third of `T2 − T`
//!
//! A child costs [`ProverModel::recursion_verify_s`] — **1.520 s** MEASURED on a
//! card once `fd9764d` stopped compressing children, the wrap having forced the
//! in-guest verifier onto a software Poseidon at 23x the cost — and any proof
//! with a child at all pays [`ProverModel::first_child_s`] once on top, 0.83 s,
//! for the Poseidon AIR instance that verifier builds. It was 35.629 s a child
//! and no step at all until 2026-08-19. **Everything below is re-derived at the
//! measured pair rather than rescaled**, because what moved is the shape of the
//! optimum and not only its price; `BENCHMARKS.md` has the before numbers.
//!
//! Against a 3.640 s floor, `T2 − T` on mainnet 430529 is **10.5 s** and it is
//! the final proof and nothing else: 3.64 s of floor, 3.87 s of recursion — the
//! running aggregate the epoch was folded into, the previous epoch's
//! justification, and the one Poseidon instance they share — 2.26 s for the two
//! slots it takes inline, and the epoch's one 0.66 s final exponentiation. Only
//! 0.21 s of that is leaves: a slot's absentees are the smallest term in the
//! proof they gate, which is the whole reason the trigger is cheap to fire. It
//! was 83.1 s at 35.629 s a child, and 112.4 s before the inline tail was
//! uncapped. The epoch's own work is one card: two groups, two folds and the
//! final proof, with the last fold landing 1.6 s before `T`. How to cut the
//! groups and how many cards to use is the rest, and it is small. Where the
//! tail begins is not: it decides whether a second floor lands after `T`.
//!
//! **Both of those numbers were right by accident until 2026-08-19, and one of
//! them still is.** `final_s` charged `absorbed + 1` on the folded path where
//! `stream-final-guest` verifies `absorbed + 2`, and `fold_s` charged the
//! epoch-opening fold one predecessor where `aggregation-guest` verifies the
//! epoch diff *and* the committee proof — one child short on every path — while
//! `recursion_verify_s` carried `justification-guest`'s 53.087 s, which is 1.49x
//! what these guests charge. `(n − 1) × 53.087 = n × 35.629` at `n = 3.04`, so
//! the capped shape's three children came out right to half a second and the
//! two-child shape the tail cap was lifted for did not: 67.8 s was 83.1 s —
//! both of them before numbers now. See `BENCHMARKS.md` for the live run that
//! separated them.
//!
//! Three things follow, and the first two are the opposite of what they were at
//! 35.629 s a child.
//!
//! **A slot is cheaper in a group than inline, and the tail is no longer about
//! the child.** A mainnet slot inline costs the final proof 0.93 s of
//! complement work and a child costs 1.520 s, so a child buys a slot and a
//! half: anything that can be *grouped* is the cheap side, and inlining eleven
//! slots to save one child now loses 7.8 s. What the tail still buys is the
//! floor it does not pay — a group covering the epoch's end can only run after
//! the last attestation, in series in front of the final proof — and that is
//! worth 5.2 s on 430529 against the 1.52 s child it saves. [`StreamPlan::tail`]
//! is two slots there rather than eight, and the 24-unit cap in [`schedule`]
//! never binds.
//!
//! **A fold is worth its floor, and only just.** A group absorbed after `T` is
//! 1.52 s on the critical path and the same group folded before it is 1.52 s
//! off it, for a floor and a Poseidon instance — 4.47 s — of prover time. That
//! is a latency-for-throughput trade rather than a saving, and the schedule
//! takes it because latency is the objective; at 35.629 s it was not a trade at
//! all. Folding a group that would have landed before `T` anyway still buys
//! nothing and costs a recursion for the fold's own predecessor.
//!
//! **The second irreducible recursion is not irreducible, and is no longer
//! worth moving.** The previous epoch's justification exists a full epoch before
//! this epoch's last attestation, exactly like the epoch diff and the committee
//! proof — both of which the fold that opens the epoch already verifies for
//! precisely this reason. Verifying it there too would take 1.52 s off `T2 − T`
//! rather than the 36 s that made it the largest term in this model, and 1.52 s
//! does not pay for a new obligation on the consumer.
//!
//! # What the schedule is up against is arrival time, not throughput
//!
//! A slot's marginal work is well under a second, against twelve seconds of
//! wall-clock to do it in, so a single warm prover keeps up with the epoch
//! comfortably. What it cannot do is start before the attestations exist. Extra
//! GPUs buy the *bulk* of the epoch — and the committee proof the next epoch
//! needs — but never the end of it, which is why [`Schedule::lanes`] settles low
//! and stays there.
//!
//! The committee proof used to be the exception that sized the fleet: 1,950 s
//! against a 384 s epoch, five cards' worth, cut into chunks to fit. It is
//! 146 s now — the model was charging it the whole registry rather than the
//! active set, and the guest was spending 94% of it deserialising a witness it
//! was handed in its own memory layout. One card, one chunk, inside the epoch.
//!
//! # The threshold is 2/3, because the estimate it hedged against is gone
//!
//! [`StreamPolicy::threshold_numerator`] used to default above 2/3, because the
//! attesting balance a slot contributed was an estimate that deduplication
//! across slots could shrink. It is not one any more: `slots_mask` puts a
//! validator in exactly one slot, and `marginal_balance` is committee balance
//! minus absentee balance, which is exact. The circuit enforces 2/3 and rejects
//! anything under it, so a thin margin can only ever waste a proof, never make
//! an unsound one — and it is expensive, because weight arrives a committee at a
//! time, 3.1% of the stake, so a margin that pushes the crossing into the next
//! slot costs a whole slot. The default is therefore 2/3 exactly, and the
//! numerator and denominator are configuration rather than constants.
//!
//! # Firing early is not free, which is what makes the trigger a choice
//!
//! Complement proving inverts the usual latency trade. A slot proof opens the
//! validators that did *not* attest, so an attestation still in flight when the
//! trigger fires is one more absentee to open — at [`ProverModel::named_s`],
//! 601 us each in a tail of 11,379 and 798 us in a tail of 157. Mainnet epoch
//! 430529 crosses 2/3 42.7% of the way through slot 21's arrivals, with 17,128
//! of that slot's attesters still in flight: firing on the instant would buy
//! back the wait and pay 9.98 s of extra proving for it.
//!
//! So there are two moments, and the objective is the second: the earliest
//! instant the circuit would accept, and the instant that minimises `T2`.
//! [`StreamPolicy::worth_waiting`] is the rule between them, and one 200 ms
//! interval of waiting pays for itself above 1,289 attesters a second at the
//! measured leaf price. What the rule cannot do is read that rate off one
//! interval and call it the future: a slot's gossip is two arrivals,
//! unaggregated and aggregate, with a silence between them, and a live mainnet
//! run stopped in that silence with thousands of attestations still to come.
//! [`Filling`] is what the rule reads instead. [`Schedule::threshold_s`] is
//! measured at 2/3 regardless, so any wait shows up in `T2 − T` rather than
//! hiding in the choice of `T`.
//!
//! 1,289 a second is a rate, and a rate cannot bound a wait. It is break-even by
//! construction — a second of waiting against a second of proving avoided — so
//! an arrival stream that merely keeps clearing it justifies a wait of any
//! length at all. The bound comes from the stock instead of the flow: the
//! validators still in flight are worth `named_s(in_flight)` and no more,
//! because that is what the final proof would pay to open every one of them, so
//! it is what the wait would save if all of them landed in the next instant.
//! [`StreamPolicy::wait_budget_s`] is that quantity and the rule spends against
//! it. A tail of 8,454 is worth 5.20 s; waiting 141 s for it loses 136 s on the
//! best outcome available, and would need roughly 314,000 in flight to break
//! even.

use zkasper_common::acc::Digest;
use zkasper_common::bls::Fp12;
use zkasper_common::recursion::ProgramVk;
use zkasper_common::types::{
    AccMultiProof, AggregateOutput, AggregateWitness, BoundaryAnchor, CommitteeOutput,
    EpochDiffOutput, GroupProofOutput, MillerAccumulator, PreviousJustification, SlotProofWitness,
    StreamFinalWitness,
};

use crate::acc_tree::AccTree;
use crate::attestation_collector::SlotComplement;
use crate::committee::EpochCommittees;

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

/// Measured Zisk cost units, used only as *ratios* inside the Fp2 tower.
///
/// They are trace area, not time: `scripts/time_model.py` shows the same
/// constant is wrong by 3.5x in one direction for `MAIN`-heavy guests and right
/// only for the poseidon2 workload it was fitted on. Within one work class the
/// ratios still hold, which is the only thing they are asked for here.
mod cost {
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

/// Internal compressions a multi-proof over `leaves` *scattered* leaves needs.
///
/// A node at level `k` covers 2^k leaves, so it is touched unless every one of
/// those slots is empty. This is the absentee case: a slot's absentees are
/// spread across the registry, so a hundred of them touch fifteen nodes apiece.
fn scattered_nodes(leaves: f64, depth: u32) -> f64 {
    let capacity = (1u64 << depth) as f64;
    (1..=depth)
        .map(|k| {
            let covered = (1u64 << k) as f64;
            capacity / covered * (1.0 - (1.0 - covered / capacity).powf(leaves))
        })
        .sum()
}

/// The same count when the leaves are one index range.
///
/// Barely more than one node per leaf at any size, against fifteen for a
/// scattered hundred. This is the committee proof, whose chunk owns a range of
/// validator indices — and it is also what the attester sweep measured, which is
/// why that sweep is linear in attesters to within 1%.
fn contiguous_nodes(leaves: f64, depth: u32) -> f64 {
    (1..=depth)
        .map(|k| (leaves / (1u64 << k) as f64).ceil())
        .sum()
}

/// What the prover charges, in seconds.
///
/// Every field is a measurement or a fit against one, and the campaign that
/// produced them is in `data/gpu_bench/` with `scripts/time_model.py`
/// reproducing the numbers. There is deliberately no per-invocation constant:
/// these are the prover's own `Proof generated` times, and a warm prover pays
/// exactly them. Adding a fixed cost on top is what the superseded model did
/// when it charged 19.52 s *and* a per-proof floor, counting the floor twice.
#[derive(Clone, Debug, PartialEq)]
pub struct ProverModel {
    /// Seconds any zkasper guest pays before it computes anything.
    ///
    /// MEASURED on Zisk v1.1.0-alpha: the committee proof over a 64-member
    /// witness — 21,680 executed steps — proves in 3.640 s +/- 0.053 over three
    /// warm runs. An *empty* guest is 2.429 s, so 1.21 s of this is the AIRs a
    /// poseidon2 guest instantiates and an empty one does not.
    ///
    /// It was 7.176 s on v1.0.0-alpha, measured on the aggregation guest with
    /// recursion removed. That guest can no longer stand in: stubbing
    /// `verify_child` leaves a later assert failing on the fixture's stub
    /// children, and a panicking guest never returns from `ziskemu`.
    pub stage_floor_s: f64,
    /// Seconds per validator opened out of the accumulator: its leaf, one curve
    /// addition, and the steps of walking its witness.
    ///
    /// MEASURED on the live mainnet run of 2026-08-19, epochs 469595 .. 469630
    /// — 31 final proofs under one guest ELF (`0x9535e00...`), with tails from
    /// 52 to 14,473 leaves. Least squares of the prover's own `prove_millis`
    /// against the epoch's published `tail_named` is
    /// **10.777 s + 595.5 us a leaf**, standard error 17.1 us on the slope and
    /// 67 ms on the intercept, R^2 0.977, worst residual 0.90 s on the largest
    /// tail. The intercept is fitted rather than assumed, because a final proof
    /// pays a floor and four recursions before it opens a single leaf.
    ///
    /// 595.5 us is the leaf *and* the internal nodes it drags in, so it is not
    /// this constant. Over that range `scattered_nodes` averages 8.263 nodes a
    /// leaf, which at [`ProverModel::acc_node_s`] leaves
    /// `595.5 - 8.263 x 31.9 = 325.8 us` for the validator itself, +/- 16.6.
    /// The two regressors correlate at 0.9991 over these tails, so the split
    /// needs `acc_node_s` from its own campaign and cannot be read off this fit;
    /// what the fit does settle without help is that no positive `acc_node_s`
    /// leaves room for more than 595.5 us here.
    ///
    /// **It was 834.7 us until 2026-08-19, which the data excludes outright.**
    /// At that price 14,473 leaves are 12.08 s of validator alone, against 8.24 s
    /// measured for the whole tail, nodes included. The figure came from the
    /// v1.0.0-alpha attester sweep, which priced a bincode witness;
    /// [`ProverModel::per_member_s`] fell 404.5 -> 101.2 us when its own witness
    /// stopped being self-describing and was re-derived, and this one never was.
    /// `per_member_s` is confirmed to 1.6% by the same run (see its docs), so
    /// what is wrong here is this constant and not the campaign's rate.
    pub per_validator_s: f64,
    /// Seconds per committee member: the same leaf and the same curve addition,
    /// out of a witness the guest does not parse.
    ///
    /// MEASURED under `ziskemu -X` on the committee guest itself, at 16,000,
    /// 32,000 and 64,000 members: 254.0 executed steps and 30,127 cost units a
    /// member, linear to five figures. Converted at the rate the attester sweep
    /// sets for this work class — 223,450 units bought 834.7 us — which is a
    /// within-class ratio and not a proving time of its own; the step ratio
    /// 254 / 2,311 puts it at 96.5 us, so the two yardsticks agree to 4.6%.
    ///
    /// It was 404.5 us while the witness travelled as bincode, which is what
    /// made this proof 94% of the fleet. A `CommitteeMember` is fifteen `u64`s
    /// in the layout the guest already wants, and decoding it as fifteen
    /// self-describing records cost 829 of the 1,157 steps a member took. The
    /// 328 that left took another 74 when `bls::PointSum` stopped copying the
    /// running sum into a syscall struct and back.
    ///
    /// STILL v1.0.0-alpha, for the same reason as `per_validator_s` — it is
    /// derived from that sweep's rate. Under `ziskemu -X` on v1.1.0-alpha a
    /// member is 208.0 steps and 36,406 cost units against 254.0 and 30,127, so
    /// the work fell 18% while its price rose 21%; converting that to seconds
    /// needs a committee sweep on hardware, which this campaign did not run.
    /// Carrying it forward unchanged is conservative.
    pub per_member_s: f64,
    /// Seconds per internal accumulator node above the opened leaves.
    ///
    /// MEASURED: the 29-point poseidon2 sweep gives 233,988,033 cost units/s on
    /// poseidon2 work, and an accumulator node is 7,462 of them. Both numbers
    /// grew against v1.0.0-alpha's 69,714,770 and 3,033 because
    /// `POSEIDON_COST` was re-based to match the Poseidon AIR's 392-column
    /// width; the node itself got 27% faster in seconds.
    pub acc_node_s: f64,
    /// Cost units of Fp2-tower work a second: hash-to-curve, Miller loops, the
    /// final exponentiation.
    ///
    /// FITTED, and the weakest number here — nothing in the campaign runs BLS at
    /// mainnet scale, so it is a within-family rate read off floor-dominated
    /// fixtures. The bracket around it is 162M to 268M units/s on v1.1.0-alpha,
    /// against 160M to 609M on v1.0.0-alpha.
    ///
    /// The rate itself did not move between the two versions. What moved is the
    /// work: the same Fp2-tower operations cost about a third fewer units, so
    /// BLS *time* falls with them.
    pub bls_units_per_second: f64,
    /// SNARK compression of the final proof.
    ///
    /// MEASURED: `GENERATE_VADCOP_FINAL_COMPRESSED_PROOF` is 46-52 ms over six
    /// warm wraps on v1.1.0-alpha, against 151-170 ms on v1.0.0-alpha. The 5.4 s
    /// of wall around it is process startup, which a long-lived prover does not
    /// pay.
    pub wrap_s: f64,
    /// Seconds to verify one child proof recursively.
    ///
    /// MEASURED on a rented RTX 5090, driver 580.159.03, CUDA 12.9.1,
    /// cargo-zisk v1.1.0-alpha [gpu], 2026-08-19, on a guest that verifies `n`
    /// children and does nothing else (`crates/recursion-bench-guest`) over
    /// real proofs at `n = 0, 1, 2, 3, 4`. Warm `Proof generated` seconds. Least
    /// squares over `n = 1..4` is `3.175 s + 1.520 s a child`, worst residual
    /// 0.042 s — 2.7% of one child. The zero-child point is 2.349 s, which
    /// reproduces the empty-guest floor measured in an unrelated campaign.
    ///
    /// **It was 35.629 s until `fd9764d`, and that was the compression.** Every
    /// child was wrapped to `VadcopFinalMinimal` before being verified. A
    /// compressed proof has Merkle arity 2, `proofman` fixes the verifier's hash
    /// width at `arity * 4`, and `syscall_poseidon1` only accepts width 16 — so
    /// every Merkle and FRI hash ran as software Hades inside the guest. 242.8 M
    /// RISC-V steps a child against 10.9 M. See BENCHMARKS.md.
    ///
    /// **A child is not the whole of what a recursion costs.** A proof also
    /// pays [`ProverModel::first_child_s`] once for having any child at all,
    /// which is more than half a child and is per proof rather than per child.
    ///
    /// **Seconds here are a property of the rental, not of the guest.** The same
    /// child, warm, one process, one card, spans 35.7 to 44.5 s under the old
    /// compression when only the CPU affinity mask changes — non-monotonically,
    /// widest mask slowest. The 1.49x that once separated this figure from
    /// `justification-guest`'s 53.087 s was that, and not a difference between
    /// guests: the work per child is identical to five decimal places whoever
    /// verifies it.
    ///
    /// **A recursion no longer costs ten proofs.** Against a 3.640 s stage floor
    /// a child is now under half a proof, which inverts what the 35.629 s
    /// implied: grouping slots to reduce child counts is close to free either
    /// way, and a fold that exists only to take children off another proof
    /// mostly buys latency at the cost of a floor.
    ///
    /// **The default was held at 35.629 until 2026-08-19**, because the measured
    /// value moves the schedule's optimum rather than only its price: four
    /// schedule tests assert a shape and all four assert a different one now —
    /// `inlining_the_unfoldable_slots_beats_absorbing_them_as_a_group`,
    /// `the_tail_cap_no_longer_binds_on_mainnet_430529`,
    /// `nothing_is_left_for_the_final_proof_to_absorb` and
    /// `a_bigger_floor_pushes_another_slot_into_the_tail`. They were re-derived
    /// against this constant rather than rescaled, and `T2 - T` on mainnet
    /// 430529 went from 83.1 s to 10.6 s with them.
    pub recursion_verify_s: f64,
    /// Seconds a proof pays once for having any child at all.
    ///
    /// MEASURED in the same ladder as [`ProverModel::recursion_verify_s`]: the
    /// `n = 1..4` fit's intercept is 3.175 s and the zero-child point is
    /// 2.349 s, so a guest that verifies one child pays **0.83 s** a guest that
    /// verifies none does not. It is the first `Poseidon` AIR instance the
    /// in-guest verifier builds: 3,877 permutations land in about 54,000 rows
    /// of a 131,072-row AIR, and the instance costs its floor whether it is
    /// filled or not. So the second child adds no more of it, and a second
    /// *proof* pays it again.
    ///
    /// **It does not overlap `stage_floor_s`, because the two floors are
    /// measured on childless guests.** 3.640 s is the committee guest, which
    /// verifies nothing; 2.349 s is the bench guest with `n = 0`. Neither
    /// contains a Poseidon instance, and the ladder's own intercept splits as
    /// `2.349 + 0.826` — the childless floor plus the step. The zkasper
    /// equivalent is therefore `3.640 + 0.83`: the floor unchanged, the step
    /// charged on top of it, and neither term counted twice. Charging any part
    /// of the 3.175 s to `stage_floor_s` would be charging the bench guest's
    /// floor to a guest that has its own.
    ///
    /// At 35.629 s a child this was noise. At 1.520 s it prices what the old
    /// constant made obvious and this one does not: splitting one proof's
    /// children across two proofs now buys a second floor and a second Poseidon
    /// instance — 4.47 s — to save 1.520 s a child moved.
    pub first_child_s: f64,
    pub acc_depth: u32,
}

impl Default for ProverModel {
    fn default() -> Self {
        Self {
            stage_floor_s: 3.640,
            per_validator_s: 325.8e-6,
            per_member_s: 101.2e-6,
            acc_node_s: 31.9e-6,
            bls_units_per_second: 200_000_000.0,
            wrap_s: 0.048,
            recursion_verify_s: 1.520,
            first_child_s: 0.83,
            acc_depth: zkasper_common::constants::ACC_TREE_DEPTH,
        }
    }
}

impl ProverModel {
    /// Seconds of Fp2-tower work worth `units` of trace area.
    fn bls_s(&self, units: f64) -> f64 {
        units / self.bls_units_per_second
    }

    /// Opening `leaves` scattered validators out of a depth-`depth` tree.
    fn open_scattered_s(&self, leaves: f64, depth: u32) -> f64 {
        leaves * self.per_validator_s + scattered_nodes(leaves, depth) * self.acc_node_s
    }

    /// Seconds the proof spends opening `named` more validators out of the
    /// accumulator: their leaves, and the internal nodes only they touch.
    ///
    /// This is the price of firing early, and the only number the trigger needs.
    /// It is `open_scattered_s`, which is what the planner already
    /// charges a tail, so the trigger and the schedule price one leaf alike.
    ///
    /// **It was a per-leaf constant of 1.5365 ms until 2026-08-19, and a leaf
    /// has no constant price.** Two things were wrong with it and they
    /// compounded. [`ProverModel::per_validator_s`] was 2.56x too big, and the
    /// node term charged `acc_depth` — every level of the tree, for every
    /// leaf — which `scattered_nodes` says only of a tail of exactly one. Its
    /// marginal is 20.4 nodes at one leaf, 13.4 at 157 and 6.9 at 14,473, so a
    /// tail deep enough to matter shares most of its path and was charged three
    /// times over for it. Against the run those tails came from the old constant
    /// is 1.50x high at one leaf and 2.64x at 17,128.
    ///
    /// So it is a curve: 1,027.6 us a leaf at one leaf, 798.4 at 157, 601.4 at
    /// 11,379. What that does to the trigger is move both of its bars. One
    /// 200 ms interval is now paid for by 258 leaves rather than 130 — **1,289
    /// validators a second, not 651** — and one second of waiting is worth
    /// 1,436. [`StreamPolicy::wait_budget_s`] reaches its 10 s cap at 17,168 in
    /// flight where it used to reach it at 6,508.
    pub fn named_s(&self, named: f64) -> f64 {
        self.open_scattered_s(named, self.acc_depth)
    }

    /// The same, when the leaves are one index range and the guest reads them
    /// in place rather than deserialising them — which is the committee proof
    /// and only the committee proof.
    fn open_contiguous_s(&self, leaves: f64, depth: u32) -> f64 {
        leaves * self.per_member_s + contiguous_nodes(leaves, depth) * self.acc_node_s
    }

    /// Rebuilding the 32-leaf committee tree from its summed buckets.
    fn committee_tree_s(&self) -> f64 {
        ((1u64 << cost::COMMITTEE_DEPTH) + (1u64 << cost::COMMITTEE_DEPTH) - 1) as f64
            * self.acc_node_s
    }

    /// What a set of slot complements costs short of the final exponentiation.
    ///
    /// `named` is what the proof opens against the accumulator: its absentees
    /// and the signers of any minority head vote. `messages` is distinct signing
    /// roots, because the Miller accumulator keys on the root — extra aggregates
    /// over one message cost a G2 add and nothing else.
    fn complement_s(&self, named: f64, slots: f64, messages: f64) -> f64 {
        self.open_scattered_s(named, self.acc_depth)
            + self.open_scattered_s(slots, cost::COMMITTEE_DEPTH)
            + self.bls_s(
                cost::MILLER_BATCH
                    + cost::G2_SUBGROUP
                    + messages * (cost::HASH_TO_CURVE + cost::MILLER_PAIR),
            )
    }

    /// One group proof: slot complements verified as far as the Miller loop,
    /// which the final exponentiation is deliberately not part of.
    pub fn group_s(&self, named: f64, slots: f64, messages: f64) -> f64 {
        self.stage_floor_s + self.complement_s(named, slots, messages)
    }

    /// One fold, absorbing `groups` finished group proofs.
    ///
    /// Nothing but the floor and an Fp12 multiply each: cross-slot deduplication
    /// is a `slots_mask` now, so a fold no longer opens a counted-set tree.
    ///
    /// `opening` is the fold that starts an epoch. `aggregation-guest` takes the
    /// `previous == None` branch there, which verifies the epoch diff and the
    /// committee proof rather than one predecessor — two children where every
    /// later fold has one. Either branch has a child, so `first_child_s` is
    /// unconditional here.
    pub fn fold_s(&self, groups: f64, opening: bool) -> f64 {
        self.stage_floor_s
            + self.first_child_s
            + (groups + if opening { 2.0 } else { 1.0 }) * self.recursion_verify_s
            + groups * self.bls_s(cost::FP12_MUL + cost::COMMIT_FP12)
    }

    /// The final proof: the tail's complements inline, `absorbed` group proofs
    /// taken directly, and the epoch's one final exponentiation.
    pub fn final_s(
        &self,
        named: f64,
        slots: f64,
        messages: f64,
        absorbed: f64,
        folded: bool,
    ) -> f64 {
        self.stage_floor_s
            + if slots > 0.0 {
                self.complement_s(named, slots, messages)
            } else {
                0.0
            }
            + self.bls_s(cost::FINAL_EXP)
            // The previous epoch's justification is a child on every path —
            // `stream-final-guest` verifies it unconditionally, and it is the
            // one recursion the guest's own module doc calls irreducible. On
            // top of it the folded path verifies the running aggregate; the
            // unfolded path has no fold to inherit from, so it verifies the
            // epoch diff and the committee proof itself instead. So there is
            // always a child, and always one `first_child_s`.
            + self.first_child_s
            + (absorbed + if folded { 2.0 } else { 3.0 }) * self.recursion_verify_s
            + (absorbed + 1.0) * self.bls_s(cost::FP12_MUL + cost::COMMIT_FP12)
    }

    /// One chunk of the per-epoch committee proof, which sums every slot's
    /// committee out of the accumulator.
    ///
    /// Chunks are independent: a validator lands in exactly one index range and
    /// bucket sums add, so `chunks` of them plus a fold produce the same
    /// committee root as one proof over the whole registry. A chunk publishes
    /// the 32 partial buckets rather than a root, so only the last proof in the
    /// chain builds the tree.
    ///
    /// `validators` is the *active* set, not the registry: committees are
    /// formed from active validators, and those are the only leaves this proof
    /// opens. At mainnet's 960,974 one chunk is about 169 s, which is inside
    /// the 384 s epoch that owes it, so the pipeline no longer needs the proof
    /// cut up at all. It was 1,950 s when the model charged the whole
    /// 2,212,792-entry registry at the bincode witness's 448 us a validator.
    pub fn committee_chunk_s(&self, validators: f64, chunks: f64) -> f64 {
        let share = validators / chunks;
        self.stage_floor_s
            + self.open_contiguous_s(share, self.acc_depth)
            + if chunks == 1.0 {
                self.committee_tree_s()
            } else {
                0.0
            }
    }

    /// The fold that adds committee chunks together and builds the tree.
    pub fn committee_fold_s(&self, chunks: f64) -> f64 {
        self.stage_floor_s
            + self.first_child_s
            + (chunks + 1.0) * self.recursion_verify_s
            + self.committee_tree_s()
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

/// What one trigger interval saw of the slot gossip is still filling.
///
/// Every field is a reading of that one slot, and the two counts are the same
/// quantity a tick apart: accumulator leaves the final proof would open if it
/// fired now, and how many of them the last interval took off that list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Filling {
    /// Leaves the final proof would open if the trigger fired on this tick.
    pub in_flight: usize,
    /// How many the last interval removed.
    pub removed: usize,
    /// How many the whole wait has removed so far, this interval included.
    ///
    /// `in_flight + taken` is what the tail held when the trigger first looked
    /// at this slot, and so what the wait set out to win. Kept because the
    /// prize and what is left of it are different numbers and the rule needs
    /// both: see [`StreamPolicy::worth_waiting`], which bounds the wait by the
    /// first and ends the silence by the second.
    pub taken: usize,
    /// Network aggregates the node has published for this slot.
    ///
    /// **Read, not acted on.** A count of aggregates once ended the wait: no new
    /// one in the last interval was taken to mean the slot had had both of its
    /// arrivals and was finished. It does not mean that. A mainnet slot is
    /// aggregated by up to 64 subnet aggregators and their aggregates arrive
    /// spread over several hundred milliseconds, so a quiet 200 ms tick in the
    /// middle of the wave is the common case and not the end of it — on
    /// 2026-08-20 mainnet epochs 469720 and 469721 fired on exactly that
    /// reading, with 9,961 and 2,432 leaves still in flight. What says the slot
    /// has finished delivering is the tail no longer moving, which is `removed`
    /// and the silence [`StreamPolicy::worth_waiting`] measures against the
    /// budget. These two stay because they are the cheapest way to see, from
    /// one published record, which half of a slot's gossip an epoch fired on.
    pub aggregates: usize,
    /// How many of those arrived in the last interval, on the same terms.
    pub new_aggregates: usize,
}

/// How to cut an epoch.
#[derive(Clone, Debug)]
pub struct StreamPolicy {
    /// Stop collecting once this fraction of the total active balance has
    /// attested. 2/3 by default — the circuit's own rule, and no more; see the
    /// module docs.
    pub threshold_numerator: u64,
    pub threshold_denominator: u64,
    /// How long the trigger may hold past the threshold while in-flight
    /// attestations are still shortening the proof. See
    /// [`StreamPolicy::worth_waiting`]; this is the guard on it, not the rule,
    /// and it is set above the whole useful range so that it stays one.
    pub max_wait_s: f64,
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
            threshold_numerator: 2,
            threshold_denominator: 3,
            max_wait_s: 10.0,
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

    /// What the trigger is aiming at, as a percentage. Published so a consumer
    /// can draw the line the weight is climbing towards.
    pub fn threshold_pct(&self) -> f64 {
        self.threshold_numerator as f64 * 100.0 / self.threshold_denominator as f64
    }

    /// Balance the circuit itself insists on, which is what "enough
    /// attestations exist" means and so what `T` is measured at.
    pub fn quorum_balance(&self, total_active_balance: u64) -> u128 {
        (total_active_balance as u128 * 2).div_ceil(3)
    }

    /// Whether one interval of waiting bought more than it cost.
    ///
    /// The objective is the earliest *postable* proof, not the earliest proof
    /// start, and complement proving separates the two: `interval_s` of waiting
    /// delays the start by exactly that, and removes `removed` absentees the
    /// final proof would otherwise have opened at [`ProverModel::named_s`]. So
    /// an interval pays for itself while arrivals run above 1,289 validators a
    /// second, at the 200 ms tick the daemon runs.
    ///
    /// A rate, so it is read off the leaves the interval actually removed. They
    /// are priced as a set rather than one at a time, because that is what they
    /// cost: `scattered_nodes` is concave, and 258 absentees share more of the
    /// tree than 258 times one absentee does.
    pub fn interval_paid(&self, removed: usize, interval_s: f64) -> bool {
        self.prover.named_s(removed as f64) > interval_s
    }

    /// Every second of latency the attestations still in flight could buy back.
    ///
    /// [`Self::interval_paid`] prices one interval against the arrivals it saw,
    /// which is a rate test and says nothing about how long the wait may run in
    /// total. This is the other half, and it is a *stock* rather than a rate:
    /// the final proof opens `in_flight` accumulator leaves if it fires now, and
    /// [`ProverModel::named_s`] of them is the entire prize — what the wait
    /// would save if every one of them arrived in the next instant and the tail
    /// went to zero.
    ///
    /// A second of waiting costs a second of `T2 - T` outright, so a wait longer
    /// than the prize loses on every outcome, including the best one. That makes
    /// this a budget and not a target: 8,454 leaves in flight are worth 5.20 s,
    /// so no rate, however fast, makes a 141 s wait for them rational. 112
    /// leaves are worth 91 ms and the trigger should barely pause at all.
    ///
    /// `max_wait_s` bounds it from the other side, for the case the prize is
    /// large but the arrivals never come.
    pub fn wait_budget_s(&self, in_flight: usize) -> f64 {
        self.prover.named_s(in_flight as f64).min(self.max_wait_s)
    }

    /// Whether the wait is still worth taking.
    ///
    /// Two questions, and the rule needs both of them.
    ///
    /// *Is the wait still collecting?* is a rate. [`Self::interval_paid`] reads
    /// it off the last interval, and a slot's gossip is **two arrivals, not
    /// one**: the unaggregated attestations burst and drain, then the aggregates
    /// land, and the silence between them says nothing at all about whether the
    /// slot is finished. A rule that reads only the last interval's rate stops
    /// in the first silence it meets, so the silence is carried by `stalled_s`
    /// against the same budget the wait as a whole is spent from.
    ///
    /// *Is the wait still affordable?* is [`Self::wait_budget_s`], and it is the
    /// half that was missing. The rate test is break-even by construction — one
    /// second of waiting against one second of proving avoided — so on its own
    /// it licenses a wait of any length whatever, provided each interval clears
    /// the bar. It never asks what the wait has cost in total against what is
    /// still left to win, and that second quantity is bounded: the tail in
    /// flight is worth `named_s(in_flight)` and not a millisecond more.
    ///
    /// So the budget is an `&&` over the whole rule rather than a clause inside
    /// one arm of it: the wait continues while it is collecting *and* while it
    /// has not already spent what the tail is worth.
    ///
    /// **Which tail.** The bound is what the tail held when the wait began —
    /// `in_flight + taken` — and not what is left of it. Pricing the whole wait
    /// against the remainder makes the rule cut a collection off in the middle
    /// of collecting: the wave delivers, `in_flight` falls, the budget falls
    /// with it, and the wait ends on the very intervals that were paying, with
    /// the rest of the wave still on the wire. Replayed over the profile of
    /// mainnet 469720 that fires at 1,900 leaves in flight one tick before the
    /// last of them lands — refusing a 0.2 s interval that was about to remove
    /// 1,750 leaves, which is 1.22 s of proving. The remainder is still what
    /// ends the *silence*, and it has to be: once the tail is small a quiet
    /// interval is quickly not worth another, and that is what fires the tick
    /// after the wave.
    ///
    /// Nothing here models *when* attestations arrive. Every input is read off
    /// the gossip itself — the rate off the last interval, the silence off how
    /// long the tail has not moved — so a chain that gossips earlier or later,
    /// or aggregates on a different schedule, moves the firing instant without
    /// moving this code.
    ///
    /// **The silence is measured on the tail and not on the aggregate count.**
    /// It was measured on the count until 2026-08-20: an interval with no new
    /// aggregate ended the wait outright, whatever the tail was doing. A
    /// mainnet slot's aggregates come from up to 64 subnet aggregators over
    /// several hundred milliseconds, so that reading arrives in the middle of
    /// the wave as often as at the end of it, and it arrives on the first sight
    /// of a slot the daemon was blocked through. Both happened on the first
    /// four epochs the rule ever ran on: 469720 fired 1.79 s into its wait with
    /// **9,961** leaves in flight and 469721 fired 29 ms into its with
    /// **2,432**, while 469722, whose silence happened to fall after its wave
    /// rather than inside it, fired on the budget with **113** and closed in
    /// 17.6 s. All three held budgets of 6.05 s, 1.64 s and 0.09 s against
    /// waits of 1.79 s, 0.03 s and 1.15 s, so on every one of them it was the
    /// aggregate count that ended the wait and never the bill.
    ///
    /// Dropping it costs nothing that was not already bounded. The budget is
    /// `named_s(in_flight)`, so a wait that collects nothing loses exactly what
    /// the tail it was chasing was worth and never more — that is what the
    /// budget was added for — and a wait that collects sees `in_flight` fall,
    /// the budget fall with it, and the outer clause fire on the next tick. A
    /// converged slot is therefore held one tick and no longer: 132 leaves are
    /// a 0.09 s budget.
    ///
    /// Replaying the rule against 23 measured mainnet epochs fires at a median
    /// 8.7 s into the filling slot, and the budget does not move that: a slot
    /// that is still filling holds thousands of leaves, so its budget is
    /// `max_wait_s` and the cap is what binds, exactly as before. What the
    /// budget changes is the case the replay never contained — a tail too small
    /// for waiting on it to repay the wait.
    ///
    /// The rule can only ever cost latency. `T` is measured at the threshold the
    /// circuit itself enforces, so waiting past it changes what a proof costs
    /// and never what it proves. It is also the only thing between `T` and the
    /// final proof that is a *decision*: the epoch's backlog group is work
    /// rather than waiting, it is far larger than any wait this rule can
    /// authorise, and it is measured on its own on both sides of the fire — see
    /// `EpochLatency::blocked_millis` and `EpochLatency::late_group_millis`.
    ///
    /// Which makes what this rule costs measurable, and on the four mainnet
    /// epochs that first ran it the wait it authorised was 1.79 s, 0.03 s and
    /// 1.15 s against tails of 9,961, 2,432 and 113 leaves — 5.9 s, 1.4 s and
    /// nothing of proving and wire, for waits an order of magnitude smaller.
    pub fn worth_waiting(
        &self,
        filling: Filling,
        interval_s: f64,
        stalled_s: f64,
        waited_s: f64,
    ) -> bool {
        // What the wait set out to win, and what is left of it.
        let prize_s = self.wait_budget_s(filling.in_flight + filling.taken);
        let left_s = self.wait_budget_s(filling.in_flight);
        waited_s < prize_s
            && (self.interval_paid(filling.removed, interval_s) || stalled_s < left_s)
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
    /// Seconds of prover time this proof occupies its lane for.
    pub duration_s: f64,
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
    /// Prover-seconds the whole epoch spends, summed over every lane. What the
    /// fleet is billed for, as against `latency_s`, which is what it sells.
    pub total_prover_s: f64,
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
    // 24, not unbounded, from 2026-08-19: an uncapped tail ran the stream_final
    // guest past DEFAULT_MAX_STEPS (~68.7e9) on epoch 469569 and killed the run.
    // That is a runaway rather than a budget overrun -- the whole fused shuffle
    // proof is ~841e6 steps -- so the cap is a guard, not the fix. It is a long
    // way above the optimum now: at 1.520 s a child the schedule wants two
    // inline slots on 430529 and one on a mainnet-shaped epoch, so nothing
    // between 2 and 24 changes a schedule and the cap only bounds the runaway.
    schedule_capped(units, total_active_balance, policy, 24)
}

/// The same, with the inline tail capped at `max_tail` units.
///
/// The cap is not a policy: nothing outside the tests sets one, because a group
/// the final proof has to absorb costs a recursion and inlining its slots does
/// not. It is here so the tests can price the shape the old bound forced against
/// the shape the search picks without one, on the same units.
fn schedule_capped(
    units: &[SlotComplement],
    total_active_balance: u64,
    policy: &StreamPolicy,
    max_tail: usize,
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
                max_tail,
            )
        })
        .min_by(better)
        .expect("at least one lane")
}

/// The objective: latency, then GPUs, then prover time — behind the one hard
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
        .then(a.total_prover_s.total_cmp(&b.total_prover_s))
}

fn with_lanes(
    units: &[SlotComplement],
    total_active_balance: u64,
    policy: &StreamPolicy,
    max_tail: usize,
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
            total_prover_s: 0.0,
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

    // How much of the epoch's end the final proof swallows whole. This stopped
    // at four slots, on the pre-recursion reasoning that a group has slack the
    // tail does not and a group is one floor either way. Both bounds were
    // guesses at where the boundary is, and it moves with every constant in the
    // model — a child is 1.520 s against 0.93 s for a mainnet slot inline, so
    // the trade is now the group's own floor rather than its child. Every split
    // is priced instead, up to the whole epoch inline.
    let best = (0..=max_tail.min(last + 1))
        .flat_map(|inline| {
            let head: Vec<usize> = (0..last + 1 - inline).collect();
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
/// finish times and the prover time paid so far, and a state that is no worse on
/// every lane *and* cheaper dominates. That is exact for the group stage — group
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
        prover_s: 0.0,
        groups: Vec::new(),
    });

    for at in 0..head.len() {
        for state in prune(std::mem::take(&mut levels[at]), frontier) {
            for end in at + 1..=head.len() {
                let members = head[at..end].to_vec();
                let release = arrival(*members.last().expect("a group is never empty"));
                let duration = policy.prover.group_s(
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
                ends[lane] = release.max(ends[lane]) + duration;
                ends.sort_by(|a, b| a.total_cmp(b));

                let mut groups = state.groups.clone();
                groups.push(members);
                levels[end].push(Partial {
                    ends,
                    prover_s: state.prover_s + duration,
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
    prover_s: f64,
    groups: Vec<Vec<usize>>,
}

/// Drop states another state beats on prover time and on every lane.
///
/// The cap keeps both ends of the trade: the cheapest states, which is what the
/// bulk of the epoch is chosen on, and the earliest-finishing ones, which is
/// what the deadline is met on.
fn prune(mut states: Vec<Partial>, cap: usize) -> Vec<Partial> {
    states.sort_by(|a, b| a.prover_s.total_cmp(&b.prover_s));
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
        let duration = model.group_s(
            named(units, members),
            members.len() as f64,
            messages(units, members),
        );
        let (lane, start) = lanes.place(
            &policy.eligible(Stage::Group(i)),
            arrival(*members.last().expect("a group is never empty")),
            duration,
        );
        let end = start + duration;
        group_end.push(end);
        proofs.push(ScheduledProof {
            stage: Stage::Group(i),
            lane,
            start_s: start,
            end_s: end,
            duration_s: duration,
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
        let duration = model.fold_s((cursor - first) as f64, folds.is_empty());
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
            duration_s: duration,
        });
        folds.push(order[first..cursor].to_vec());
    }

    let unfolded: Vec<usize> = order[cursor..].to_vec();
    let mut release = deadline_s.max(chain_free);
    for &g in &unfolded {
        release = release.max(group_end[g]);
    }

    let duration = model.final_s(
        named(units, tail),
        tail.len() as f64,
        messages(units, tail),
        unfolded.len() as f64,
        !folds.is_empty(),
    );
    let (lane, start) = lanes.place(&policy.eligible(Stage::Final), release, duration);
    proofs.push(ScheduledProof {
        stage: Stage::Final,
        lane,
        start_s: start,
        end_s: start + duration,
        duration_s: duration,
    });

    // The wrap runs on the client that proved the final proof, reusing its
    // setups and const pols, so it is one more call on a lane already held.
    let wrap = model.wrap_s;
    lanes.commit(lane, start + duration, wrap);
    proofs.push(ScheduledProof {
        stage: Stage::Wrap,
        lane,
        start_s: start + duration,
        end_s: start + duration + wrap,
        duration_s: wrap,
    });
    let postable_s = start + duration + wrap;

    // The committee proof the next epoch needs is fixed two epochs before it is
    // used, so it is scheduled last: it takes whatever the deadline work leaves,
    // and what it costs the fleet is a card's worth of idle time, not latency.
    let mut committee_done_s = 0.0f64;
    if policy.validators > 0.0 {
        for chunk in 0..policy.committee_chunks {
            let duration =
                model.committee_chunk_s(policy.validators, policy.committee_chunks as f64);
            let (lane, start) =
                lanes.place(&policy.eligible(Stage::Committee(chunk)), 0.0, duration);
            committee_done_s = committee_done_s.max(start + duration);
            proofs.push(ScheduledProof {
                stage: Stage::Committee(chunk),
                lane,
                start_s: start,
                end_s: start + duration,
                duration_s: duration,
            });
        }
        if policy.committee_chunks > 1 {
            let duration = model.committee_fold_s(policy.committee_chunks as f64);
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
                duration_s: duration,
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
        total_prover_s: proofs.iter().map(|p| p.duration_s).sum(),
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
    /// Checkpoint of the epoch before this one: the FFG source every counted
    /// attestation names, and the checkpoint the final proof finalizes.
    pub source_root: [u8; 32],
    pub signing_domain: [u8; 32],
    /// The key an aggregate chain's links verify each other under.
    pub aggregate_program_vk: ProgramVk,
    /// The same for the chain of epochs: a stream final proof verifies the
    /// previous epoch's under this. Both are here because a program cannot
    /// contain its own key; every other child key is a constant of the guest.
    pub stream_program_vk: ProgramVk,
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
#[tracing::instrument(name = "witness", skip_all, fields(stage = "group"))]
pub fn group_witness(
    context: &StreamContext,
    tree: &AccTree,
    committees: &EpochCommittees,
    units: &[&SlotComplement],
) -> SlotProofWitness {
    SlotProofWitness {
        accumulator_commitment: context.accumulator_commitment,
        committee_root: committees.root(),
        source_epoch: context.target_epoch.saturating_sub(1),
        source_root: context.source_root,
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
#[tracing::instrument(name = "witness", skip_all, fields(stage = "aggregate"))]
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
        source_epoch: context.target_epoch.saturating_sub(1),
        source_root: context.source_root,
        aggregate_program_vk: context.aggregate_program_vk,
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
#[tracing::instrument(name = "witness", skip_all, fields(stage = "stream_final"))]
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
    boundary: BoundaryAnchor,
) -> StreamFinalWitness {
    StreamFinalWitness {
        accumulator_commitment: context.accumulator_commitment,
        target_epoch: context.target_epoch,
        target_root: context.target_root,
        signing_domain: context.signing_domain,
        acc_root: context.acc_root,
        total_active_balance: context.total_active_balance,
        stream_program_vk: context.stream_program_vk,
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
        boundary,
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
    boundary: BoundaryAnchor,
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
        boundary,
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

    /// Seconds into a slot at which its network aggregates land, and so the
    /// earliest instant the trigger can fire without paying more in tail than
    /// the wait costs.
    ///
    /// MEASURED on 1.08M live mainnet gossip events of epoch 469606: the
    /// singles union reaches 60.3% at 5.0 s and stops at 76-77%, and the
    /// aggregates land in one piece at 8.1-8.2 s and carry the slot to 99.7%.
    /// The published epochs agree without being told — over 38 of them the
    /// eleven fires before 8.2 s left a median 8,456 named leaves and the
    /// twenty-seven from 8.2 s left 154.
    const AGGREGATE_WAVE_S: f64 = 8.2;

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

    /// One slot per unit, each worth 4% of the stake: 2/3 crosses at slot 16,
    /// and nothing past it is planned.
    fn even_epoch() -> Vec<SlotComplement> {
        (0..32).map(|s| unit(s, 4, 200)).collect()
    }

    /// Mainnet epoch 430529, as `test_ssz_file_streaming_schedule` collects it
    /// off the real state: per slot in order, the balance the slot adds, the
    /// accumulator leaves its complement opens, and the distinct messages its
    /// aggregates carry. Those three are everything the schedule reads.
    ///
    /// Slot 22 names 3,217 rather than the usual 130 because it is the slot
    /// after the crossing: its attestations were still arriving when the epoch
    /// had already reached 2/3, so almost the whole committee is an absentee.
    /// Nothing past the crossing is planned, so it never costs anything — it is
    /// here because the table is the epoch, not a selection from it.
    const EPOCH_430529: [(u64, usize, usize); 32] = [
        (1_158_202_000_000_000, 334, 1),
        (1_159_671_000_000_000, 164, 2),
        (1_153_285_000_000_000, 156, 3),
        (1_139_019_000_000_000, 163, 2),
        (1_133_502_000_000_000, 307, 2),
        (1_167_186_000_000_000, 148, 2),
        (1_169_663_000_000_000, 100, 3),
        (1_145_431_000_000_000, 131, 2),
        (1_159_051_000_000_000, 125, 2),
        (1_171_215_000_000_000, 137, 2),
        (1_168_928_000_000_000, 160, 5),
        (1_121_872_000_000_000, 156, 3),
        (1_171_665_000_000_000, 142, 5),
        (1_182_402_000_000_000, 121, 1),
        (1_167_144_000_000_000, 126, 3),
        (1_146_052_000_000_000, 106, 3),
        (1_152_138_000_000_000, 123, 2),
        (1_194_602_000_000_000, 150, 2),
        (1_152_297_000_000_000, 159, 2),
        (1_172_182_000_000_000, 133, 4),
        (1_114_103_000_000_000, 147, 4),
        (1_170_813_000_000_000, 124, 3),
        (1_156_845_000_000_000, 3217, 5),
        (1_131_775_000_000_000, 121, 6),
        (1_155_226_000_000_000, 112, 3),
        (1_180_905_000_000_000, 120, 4),
        (1_156_402_000_000_000, 108, 3),
        (1_176_109_000_000_000, 99, 3),
        (1_145_475_000_000_000, 95, 3),
        (1_178_040_000_000_000, 186, 2),
        (1_143_521_000_000_000, 102, 2),
        (1_151_313_000_000_000, 136, 2),
    ];

    /// Total active balance at epoch 430529: 37.17M ETH over 960,974 validators.
    const TOTAL_ACTIVE_BALANCE_430529: u64 = 37_172_277_000_000_000;

    fn epoch_430529() -> Vec<SlotComplement> {
        EPOCH_430529
            .iter()
            .enumerate()
            .map(|(slot, &(balance, named, messages))| {
                let mut unit = unit(slot as u64, balance, named);
                let primary = unit.witness.primary[0].clone();
                unit.witness.secondary = vec![primary; messages - 1];
                unit
            })
            .collect()
    }

    fn with_floor(stage_floor_s: f64) -> StreamPolicy {
        StreamPolicy {
            prover: ProverModel {
                stage_floor_s,
                ..ProverModel::default()
            },
            ..StreamPolicy::default()
        }
    }

    /// The measured floor: what the aggregation guest costs with nothing in it.
    const MEASURED_FLOOR_S: f64 = 7.176;

    /// Slots with slack belong in as few groups as the deadline allows, because
    /// a group of twenty costs barely more than a group of one — and, since
    /// recursion was measured, because every group is a child something has to
    /// verify at [`ProverModel::recursion_verify_s`].
    ///
    /// How the slots are shared *between* those groups is not asserted. Two
    /// cuts of the same slots into the same number of groups cost the same
    /// complement work and the same recursions, so the objective is indifferent
    /// and the tie falls where the search happens to leave it. What matters is
    /// the count.
    #[test]
    fn the_bulk_of_the_epoch_is_one_group() {
        let schedule = schedule(&even_epoch(), 100, &with_floor(MEASURED_FLOOR_S));
        let sizes: Vec<usize> = schedule.plan.groups.iter().map(|g| g.len()).collect();
        assert!(sizes.len() <= 3, "the epoch was cut into {sizes:?}");
        assert_eq!(
            schedule.plan.groups.concat().len() + schedule.plan.tail.len(),
            17,
        );
    }

    /// The point of the tail: a second floor in series after the last
    /// attestation costs more than proving that attestation inline ever saves.
    #[test]
    fn only_the_final_proof_starts_after_the_last_attestation() {
        let units = even_epoch();
        let schedule = schedule(&units, 100, &with_floor(MEASURED_FLOOR_S));
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

    /// Where the tail ends is still a function of the floor, for a different
    /// reason than it used to be. It was the slack a one-slot group needs; with
    /// nothing left for the final proof to absorb it is the fold chain's
    /// deadline instead — a dearer floor is a dearer group *and* a dearer fold,
    /// so the group has to cover less of the epoch to land before `T`, and what
    /// it gives up goes inline.
    ///
    /// Two slots and three, where it was eleven and twelve at 35.629 s a child.
    /// The sensitivity is the same and the mechanism is the same; what changed
    /// is where it starts, because inlining a slot no longer buys its way out of
    /// a child worth ten floors. The tail is now only what the fold chain cannot
    /// reach before `T`, which is why doubling the floor — the one constant the
    /// chain's deadline is made of — still moves it by exactly one slot.
    #[test]
    fn a_bigger_floor_pushes_another_slot_into_the_tail() {
        let units = even_epoch();
        let measured = schedule(&units, 100, &with_floor(MEASURED_FLOOR_S));
        let doubled = schedule(&units, 100, &with_floor(2.0 * MEASURED_FLOOR_S));

        assert_eq!(measured.plan.tail.len(), 2);
        assert_eq!(doubled.plan.tail.len(), 3);
        assert!(doubled.latency_s() > measured.latency_s());
    }

    #[test]
    fn no_lane_runs_two_proofs_at_once() {
        let schedule = schedule(&even_epoch(), 100, &with_floor(MEASURED_FLOOR_S));
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
    /// fills whatever the deadline work leaves and never moves `T2`.
    ///
    /// It used to need cards of its own on top of that, and does not any more:
    /// at a million members one chunk is 140 s against a 384 s epoch, so it
    /// lands inside the epoch that owes it, in one piece, on the card the
    /// deadline work had already idle.
    #[test]
    fn the_committee_proof_costs_throughput_and_not_latency() {
        let units = even_epoch();
        let policy = StreamPolicy {
            validators: 1_000_000.0,
            ..with_floor(MEASURED_FLOOR_S)
        };
        let with = schedule(&units, 100, &policy);
        let without = schedule(&units, 100, &with_floor(MEASURED_FLOOR_S));

        assert_eq!(
            (with.latency_s() * 10.0).round(),
            (without.latency_s() * 10.0).round(),
        );
        assert!(with.total_prover_s > without.total_prover_s);
        assert_eq!(
            with.committee_overrun_s(),
            0.0,
            "the committee proof is late"
        );
        // And it no longer takes a card of its own either, which is what the
        // measured leaf price changed here. The epoch's own work is one group,
        // one fold and one final proof in series, and at 325.8 us a validator
        // that series is short enough that a single card absorbs the 140 s chunk
        // in the stretch between the epoch's first fold and its last group
        // without moving `T2` at all: the one-, two- and three-lane candidates
        // all reach 12.8 s, so `better` takes the fewest cards.
        //
        // At 834.7 us the one-card candidate was 13.5 s against 13.0 s on two,
        // and `better` ranks latency above GPUs, so it bought the second card
        // for half a second. What it costs now is one card's idle time, not
        // `T2` — which is what the equality above says.
        assert_eq!(without.lanes, 1);
        assert_eq!(with.lanes, 1);
    }

    #[test]
    fn nothing_past_the_threshold_is_planned() {
        let plan = plan(&even_epoch(), 100, &StreamPolicy::default());
        let last = plan.groups.concat().into_iter().chain(plan.tail).max();
        assert_eq!(last, Some(16));
        assert_eq!(plan.attesting_balance, 68);
    }

    /// A slot whose gossip is finished: both halves seen, aggregates quiet.
    fn drained(in_flight: usize, removed: usize) -> Filling {
        Filling {
            in_flight,
            removed,
            taken: 0,
            aggregates: 64,
            new_aggregates: 0,
        }
    }

    /// The trigger's whole argument in the units it is made of: an arrival rate
    /// above the price of the leaves the interval removed shortens the proof by
    /// more than the wait costs, and below it does not.
    ///
    /// **There is no single break-even rate, and there never was one.** A tail
    /// is priced as a set, `scattered_nodes` is concave, so a longer interval
    /// collects leaves that share more of the tree and the bar it has to clear
    /// rises with it: 1,289 a second over one 200 ms tick, 1,436 over a whole
    /// second. The 651 this asserted until 2026-08-19 was one rate for every
    /// interval, from a constant per-leaf price that was 2.58x too cheap to
    /// begin with.
    #[test]
    fn waiting_pays_exactly_while_arrivals_outrun_the_per_leaf_price() {
        let policy = StreamPolicy::default();

        assert!(
            policy.interval_paid(1_500, 1.0),
            "1,500 a second did not pay"
        );
        assert!(!policy.interval_paid(1_400, 1.0), "1,400 a second paid");

        // The same rule over the tick the daemon actually runs, where the bar is
        // 1,289 a second and not the 1,436 a whole second asks for.
        assert!(policy.interval_paid(300, 0.2), "1,500 a second did not pay");
        assert!(!policy.interval_paid(200, 0.2), "1,000 a second paid");

        // The burst mainnet epoch 430529 actually crosses in: 17,128 attesters
        // still in flight, 9.98 s of absentee openings, against a wait measured
        // in hundreds of milliseconds.
        assert!(policy.worth_waiting(drained(17_128, 17_128), 0.3, 0.0, 0.3));
    }

    /// The rule the live run needed and did not have. A slot's unaggregated
    /// attestations drain seconds before its aggregates land, and the silence
    /// between them is not the slot finishing. Firing into it left a measured
    /// 6,563 leaves on the median epoch.
    #[test]
    fn a_silence_before_the_aggregates_is_not_the_slot_finishing() {
        let policy = StreamPolicy::default();
        let singles_drained = Filling {
            in_flight: 6_300,
            removed: 0,
            taken: 0,
            aggregates: 0,
            new_aggregates: 0,
        };
        assert!(
            policy.worth_waiting(singles_drained, 0.2, 2.0, 3.0),
            "fired into the silence before the aggregates",
        );

        // The aggregates land, and the interval that carries them pays for
        // itself many times over: 4,150 leaves are 2.69 s of proving against a
        // 0.2 s tick.
        let landing = Filling {
            in_flight: 2_150,
            removed: 4_150,
            taken: 0,
            aggregates: 64,
            new_aggregates: 64,
        };
        assert!(policy.interval_paid(4_150, 0.2));
        assert!(policy.worth_waiting(landing, 0.2, 0.0, 1.0));

        // The rate clause is not the whole rule, and this is where the measured
        // price changes the answer. By 3.2 s the wait has spent more than the
        // 2,150 still in flight can ever repay — they are worth 1.46 s — so the
        // budget ends it on the very interval that paid best. At 1.5365 ms a
        // leaf those 2,150 were worth 3.30 s and this held on.
        assert!(!policy.worth_waiting(landing, 0.2, 0.0, 3.2));

        // One quiet interval after them, and the slot's aggregate count has not
        // moved. That is **not** the slot finishing: 64 subnet aggregators
        // deliver a mainnet slot over several hundred milliseconds and a 200 ms
        // gap inside that wave is ordinary. Held, because 2,150 leaves are
        // worth 1.46 s and only 1.0 s has been spent.
        assert!(
            policy.worth_waiting(drained(2_150, 0), 0.2, 0.2, 1.0),
            "gave up inside the wave on a count of aggregates",
        );
        // What ends it is the bill, on the same reading, once the wait has
        // cost what the tail can repay.
        assert!(!policy.worth_waiting(drained(2_150, 0), 0.2, 1.5, 1.5));
    }

    /// The reading the first four live epochs fired on, in their own numbers.
    ///
    /// `drained` is a slot whose aggregates have been seen and did not move in
    /// the last interval, which is where the rule used to stop outright. On
    /// 2026-08-20 mainnet 469720 met it 1.79 s into its wait with 9,961 leaves
    /// still in flight and 469721 met it on the first sight of a slot it had
    /// been blocked through, with 2,432. Both are inside a budget those tails
    /// pay for many times over.
    #[test]
    fn the_wave_is_not_over_because_one_interval_of_it_was_quiet() {
        let policy = StreamPolicy::default();

        let epoch_469720 = drained(9_961, 0);
        assert!((policy.wait_budget_s(9_961) - 6.051).abs() < 1e-2);
        assert!(
            policy.worth_waiting(epoch_469720, 0.2, 1.79, 1.79),
            "fired with 9,961 leaves in flight and 4.3 s of budget unspent",
        );

        let epoch_469721 = drained(2_432, 0);
        assert!((policy.wait_budget_s(2_432) - 1.635).abs() < 1e-2);
        assert!(
            policy.worth_waiting(epoch_469721, 0.0, 0.0, 0.03),
            "fired 29 ms into a wait its tail was worth 1.6 s of",
        );

        // And 469722, whose silence fell after its wave rather than inside it,
        // is unchanged: 113 leaves are a 0.09 s budget and 1.15 s had gone.
        let epoch_469722 = drained(113, 0);
        assert!(policy.wait_budget_s(113) < 0.1);
        assert!(!policy.worth_waiting(epoch_469722, 0.2, 1.15, 1.15));
    }

    /// The whole wait, tick by tick, over the gossip profile the live run
    /// measured — which is the claim that matters and the one a clause-level
    /// test cannot make.
    ///
    /// The crossing slot of mainnet 469720: the daemon is freed by its backlog
    /// 6.18 s into the slot with 9,961 leaves in flight, nothing arrives until
    /// the aggregates start at 8.1 s, they land in pieces over the next 600 ms
    /// with quiet intervals between them, and the tail settles at 150. The
    /// firing instant is what this asserts, and it has to be *after* the wave
    /// and within a tick of it: later is latency spent for nothing and earlier
    /// is the 5.9 s of proving and 2.2 s of wire that epoch actually paid.
    #[test]
    fn the_wait_ends_on_the_tick_after_the_wave_and_not_before_it() {
        let policy = StreamPolicy::default();
        let interval_s = 0.2;

        // Leaves still in flight, as the wave delivers them in pieces.
        let in_flight = |t: f64| -> usize {
            match t {
                t if t < 8.1 => 9_961,
                t if t < 8.3 => 6_400,
                t if t < 8.5 => 6_400,
                t if t < 8.7 => 1_900,
                _ => 150,
            }
        };

        let (mut stalled_s, mut fired_at, mut taken) = (0.0, None, 0);
        let (freed_at, mut previous) = (6.18, in_flight(6.18));
        let mut t = freed_at;
        while t < 14.0 {
            let now = in_flight(t);
            let removed = previous.saturating_sub(now);
            taken += removed;
            let filling = Filling {
                in_flight: now,
                removed,
                taken,
                aggregates: usize::from(t >= 8.1) * 40,
                new_aggregates: 0,
            };
            stalled_s = if policy.interval_paid(filling.removed, interval_s) {
                0.0
            } else {
                stalled_s + interval_s
            };
            if !policy.worth_waiting(filling, interval_s, stalled_s, t - freed_at) {
                fired_at = Some(t);
                break;
            }
            previous = now;
            t += interval_s;
        }

        let fired_at = fired_at.expect("the wait must end");
        assert!(
            (8.7..=9.1).contains(&fired_at),
            "fired {fired_at} s into the slot, which is not the tick after the wave",
        );
        assert_eq!(
            in_flight(fired_at),
            150,
            "and it fired on the tail the wave left, not the one it found",
        );
    }

    /// A wave that never comes costs exactly what the tail it was waiting for
    /// was worth, and not a second more. That is the bound removing the
    /// aggregate clause leans on.
    #[test]
    fn a_wave_that_never_comes_costs_the_budget_and_stops() {
        let policy = StreamPolicy::default();
        let interval_s = 0.2;

        let (mut stalled_s, mut waited_s) = (0.0, 0.0);
        while policy.worth_waiting(drained(9_961, 0), interval_s, stalled_s, waited_s) {
            stalled_s += interval_s;
            waited_s += interval_s;
            assert!(waited_s < 7.0, "a wait with no arrivals ran away");
        }
        let budget_s = policy.wait_budget_s(9_961);
        assert!(
            waited_s >= budget_s && waited_s < budget_s + interval_s,
            "stopped at {waited_s} s against a {budget_s} s budget",
        );
    }

    /// A converged slot is held one tick and no longer, so the fix cannot
    /// delay an epoch that was already firing on a small tail.
    #[test]
    fn a_slot_that_has_already_converged_is_held_one_tick() {
        let policy = StreamPolicy::default();

        // Epoch 469716 fired on 132 leaves with 20 ms of wait behind it.
        assert!(policy.worth_waiting(drained(132, 0), 0.2, 0.0, 0.02));
        // One 200 ms tick later the budget is spent and it fires.
        assert!(!policy.worth_waiting(drained(132, 0), 0.2, 0.22, 0.22));
    }

    /// The hold is not unconditional: it costs latency, so it is taken only
    /// while what is in flight is worth more than the wait has already cost.
    ///
    /// This clause used to price the tail against `stalled_s` — the silence
    /// since the last interval that paid — rather than against the whole wait.
    /// `T2 - T` is charged the whole wait, so that let a hold which kept being
    /// refreshed run well past anything the tail could repay.
    #[test]
    fn a_converged_slot_does_not_wait_for_aggregates_it_cannot_use() {
        let policy = StreamPolicy::default();
        let converged = Filling {
            in_flight: 300,
            removed: 0,
            taken: 0,
            aggregates: 0,
            new_aggregates: 0,
        };
        // 300 leaves are 0.23 s of proving, and that is the whole budget.
        assert!(policy.worth_waiting(converged, 0.2, 0.2, 0.2));
        // Still only 0.2 s of silence, but the wait as a whole has now cost more
        // than these 300 could ever repay. The old rule held on here, because it
        // was looking at the silence rather than at the bill.
        assert!(!policy.worth_waiting(converged, 0.2, 0.2, 1.0));
        assert!(!policy.worth_waiting(converged, 0.2, 0.6, 1.4));
    }

    /// The bound the rule was missing: a rate test cannot cap a wait.
    ///
    /// [`StreamPolicy::interval_paid`] is break-even by construction — one
    /// second of waiting against one second of proving avoided — so arrivals
    /// that merely keep clearing the leaf price license a wait of any length,
    /// and the only thing that ever ended one was `max_wait_s`. What actually
    /// bounds it is the stock rather than the flow: a tail of `in_flight` leaves
    /// is worth `named_s(in_flight)` and no more, whatever rate delivers it.
    #[test]
    fn a_paying_rate_does_not_license_a_wait_past_what_the_tail_is_worth() {
        let policy = StreamPolicy::default();

        // 1,000 in flight: 0.71 s of proving, in total, for ever. It was 1.54 s
        // while a leaf was priced at a flat 1.5365 ms.
        let worth_s = policy.prover.named_s(1_000.0);
        assert!((worth_s - 0.7132).abs() < 1e-3, "{worth_s} s");

        // Arriving at 2,500 a second — nearly twice break-even over a 200 ms
        // tick — so the rate test clears on every interval and never ends the
        // wait itself.
        let pouring = drained(1_000, 500);
        assert!(policy.interval_paid(500, 0.2));

        assert!(
            policy.worth_waiting(pouring, 0.2, 0.0, 0.5),
            "half a second spent chasing 0.71 s of proving is still ahead",
        );
        assert!(
            !policy.worth_waiting(pouring, 0.2, 0.0, 1.0),
            "waited past what the whole tail could repay, because the arrivals \
             were still clearing a break-even rate",
        );
    }

    /// The budget, in the numbers from the epochs that exposed it.
    #[test]
    fn the_wait_budget_is_the_tail_priced_at_the_per_leaf_rate() {
        let policy = StreamPolicy::default();

        // Mainnet 469483 fired with 8,454 leaves still in its tail. That is
        // 5.20 s of proving: the most any wait for them could ever have saved,
        // against the 141.6 s that epoch was reported to have waited. It would
        // take 314,000 in flight to make that wait break even, and a mainnet
        // slot has 28,166 members in it.
        let worth_s = policy.prover.named_s(8_454.0);
        assert!((worth_s - 5.199).abs() < 0.01, "{worth_s} s");
        assert!(policy.prover.named_s(300_000.0) < 141.6, "break-even");

        // **Below `max_wait_s`, which is what the measured leaf price changed.**
        // At 1.5365 ms a leaf a tail this size was worth 13.0 s and the cap was
        // what ended the wait; at the measured price the budget ends it 4.8 s
        // sooner, and the cap does not bind until 17,168 leaves are in flight —
        // more than half a mainnet slot's committee.
        assert!(policy.wait_budget_s(8_454) < policy.max_wait_s);
        assert_eq!(policy.wait_budget_s(20_000), policy.max_wait_s);

        // 469480's tail was 112 leaves, worth 91 ms, and the budget says so.
        assert!((policy.wait_budget_s(112) - 0.0912).abs() < 0.001);

        // Nothing in flight is worth nothing, which is why an epoch that opens
        // past its own threshold fires on the instant.
        assert_eq!(policy.wait_budget_s(0), 0.0);
    }

    /// Nothing in flight is the catch-up case, and it must fire on the instant
    /// rather than inventing a wait it never observed.
    #[test]
    fn an_empty_slot_fires_immediately() {
        let policy = StreamPolicy::default();
        assert!(!policy.worth_waiting(Filling::default(), 0.2, 0.0, 0.0));
        assert!(!policy.worth_waiting(drained(0, 0), 0.2, 0.0, 0.0));
    }

    /// The guard, not the rule: a source that keeps trickling attestations must
    /// not be able to hold the epoch open for ever.
    #[test]
    fn the_wait_is_capped_however_fast_they_arrive() {
        let policy = StreamPolicy::default();
        assert!(!policy.worth_waiting(drained(1_000_000, 1_000_000), 0.2, 0.0, policy.max_wait_s));
    }

    /// Mainnet's shape: 32 slots, each a thirty-second of the stake, 130
    /// accumulator leaves apiece. 2/3 crosses on the 22nd, exactly as epoch
    /// 430529 does in `test_ssz_file_streaming_schedule`.
    fn mainnet_shaped() -> Vec<SlotComplement> {
        (0..32).map(|s| unit(s, 1_000_000, 130)).collect()
    }

    /// **`late_groups = 0` is the plan, and it used to be 1.** The optimum
    /// leaves the final proof nothing to absorb: every group is finished in time
    /// for the fold chain to take it, and the epoch's last slot goes inline
    /// instead of becoming a group of its own.
    ///
    /// The conclusion survived the repricing and its reason did not. At 35.629 s
    /// the tail was long — the whole end of the epoch went inline rather than be
    /// a child — and this test read the capped shape against it. At 1.520 s a
    /// child is the cheap side of that trade and the tail is one slot, so the
    /// four-slot cap is inert and the shape it used to force has to be asked for
    /// with a cap of zero. What the tail avoids is the group's own *floor*: the
    /// epoch's end can only be proven after the last attestation, in series in
    /// front of the final proof, and that is 5.2 s for a child worth 1.5.
    ///
    /// This is worth pinning from both sides because the field is named for the
    /// failure mode rather than for the design, and the reading of it has
    /// inverted: a daemon reporting `late_groups = 1` is now a daemon that fell
    /// behind the plan, not one running the shape the model chose.
    #[test]
    fn nothing_is_left_for_the_final_proof_to_absorb() {
        let units = mainnet_shaped();
        let schedule = schedule(&units, 32_000_000, &StreamPolicy::default());
        assert!(
            schedule.plan.absorbed.is_empty(),
            "the optimum absorbs nothing: {:?}",
            schedule.plan,
        );
        assert_eq!(schedule.plan.tail.len(), 1);
        assert_eq!(
            schedule.plan.folds.len(),
            3,
            "and folds everything below the tail"
        );

        let no_tail = schedule_capped(&units, 32_000_000, &StreamPolicy::default(), 0);
        assert_eq!(no_tail.plan.absorbed.len(), 1);
        assert!(
            no_tail.latency_s() - schedule.latency_s() > 5.0,
            "no inline tail {:.1}s against one inline slot {:.1}s",
            no_tail.latency_s(),
            schedule.latency_s(),
        );
    }

    /// Why it is absorbed rather than folded: a fold is a floor, a Poseidon
    /// instance and a recursion more expensive than the absorption it replaces,
    /// and it is serial in front of the final proof rather than inside it.
    ///
    /// A group whose last slot arrives within `fold_s(1)` of `T` therefore
    /// cannot be folded in time *and* would cost more if it could. Which is why
    /// the answer is neither: the slots go inline instead, and the test below is
    /// the one that decides the shape.
    #[test]
    fn folding_the_last_group_costs_a_floor_and_a_recursion_more() {
        let m = ProverModel::default();
        let absorbed = m.final_s(130.0, 1.0, 3.0, 1.0, true);
        let folded = m.fold_s(1.0, false) + m.final_s(130.0, 1.0, 3.0, 0.0, true);
        assert!(
            ((folded - absorbed) - (m.stage_floor_s + m.first_child_s + m.recursion_verify_s))
                .abs()
                < 0.01,
            "folding costs {:.2}s against absorbing's {absorbed:.2}s",
            folded,
        );
    }

    /// And why the fold that is running when the chain crosses is started
    /// anyway: it lands before the trigger could have fired.
    ///
    /// That fold is the whole of
    /// [`crate::artifacts::EpochLatency::blocked_millis`] — the epoch's last
    /// one, folding the group that covers the slot before the crossing slot.
    /// Over the eleven steady-state mainnet epochs of the 2026-08-20 run that
    /// reported a block, ten were this fold and one was a group; the folds ran
    /// 7.51-7.78 s against the 7.514 s below and started between 1.8 s before
    /// `T` and 3.5 s after it. It reads 4.5-7.1 s and looks like the largest
    /// term left.
    ///
    /// Declining one is a branch condition. What it buys is the gap between
    /// when the fold lands and when the trigger could fire, and the trigger
    /// cannot fire before [`AGGREGATE_WAVE_S`] — the daemon absorbs gossip
    /// above its in-flight early return, so the tail shrinks all through the
    /// block exactly as it would through a wait. A fold is shorter than that
    /// wait, so one started at the crossing is free; and what declining costs
    /// is not, because the group the fold would have taken becomes a child of
    /// the final proof instead.
    #[test]
    fn a_fold_started_at_the_crossing_lands_before_the_trigger_could_fire() {
        let m = ProverModel::default();
        let overhang = m.fold_s(1.0, false) - AGGREGATE_WAVE_S;
        assert!(
            overhang < 0.0,
            "a fold started at `T` runs {:.2}s into a wait of {AGGREGATE_WAVE_S}s;              a fold longer than the wait it runs inside is one worth declining",
            m.fold_s(1.0, false),
        );

        // And the price of declining it, which is what makes the margin above
        // worth a test rather than a comment: the final proof verifies the
        // group itself.
        let child = m.final_s(130.0, 1.0, 3.0, 1.0, true) - m.final_s(130.0, 1.0, 3.0, 0.0, true);
        assert!(
            child > overhang,
            "declining costs {child:.2}s of recursion to save {overhang:.2}s",
        );
    }

    /// And what beats both, for the slots no fold can reach: they are cheaper
    /// *inline* than as a group of their own — because a group is a floor, not
    /// because it is a child.
    ///
    /// The margin inverted with the constant, so the statement had to narrow. At
    /// 35.629 s the child settled it outright: eleven slots inline were 26 s
    /// cheaper than the same slots as a group the final proof absorbed, and the
    /// group's own proof never needed pricing. At 1.520 s that comparison runs
    /// the other way by 7.8 s — a child buys about a slot and a half of mainnet
    /// complement work — and the assertion below says so. What survives is the
    /// marginal statement about a slot at the *end* of the epoch, whose group
    /// could only be proven after `T`: 0.93 s inline against a whole floor and a
    /// child, which is why the tail exists and why it is short.
    #[test]
    fn inlining_the_unfoldable_slots_beats_absorbing_them_as_a_group() {
        let m = ProverModel::default();
        let alone = m.final_s(130.0, 1.0, 3.0, 0.0, true);
        let one_more_inline = m.final_s(260.0, 2.0, 6.0, 0.0, true) - alone;
        let as_its_own_group =
            m.group_s(130.0, 1.0, 3.0) + m.final_s(130.0, 1.0, 3.0, 1.0, true) - alone;
        assert!(
            as_its_own_group - one_more_inline > 5.0,
            "inline {one_more_inline:.2}s against {as_its_own_group:.2}s as a group",
        );

        // And the half that inverted: once a group exists and is finished, its
        // child is cheaper than the slots it covers.
        let absorbed = m.final_s(130.0, 1.0, 3.0, 1.0, true);
        let inline = m.final_s(1430.0, 11.0, 33.0, 0.0, true);
        assert!(
            inline - absorbed > 7.0,
            "inline {inline:.2}s against absorbed {absorbed:.2}s",
        );
    }

    /// The same thing on the real epoch rather than a shape like it, and the
    /// test that flipped hardest. Lifting the four-slot cap on the inline tail
    /// was worth 29.3 s at 35.629 s a child — 112.4 s capped against 83.1 s
    /// uncapped, eight slots inline and no group left to absorb. At 1.520 s it
    /// is worth nothing at all: the optimum tail is *two* slots, so a cap of
    /// four — or the 24 [`schedule`] carries as a runaway guard — never binds,
    /// and the two searches return the same plan.
    ///
    /// What the tail is still worth is the floor it keeps off the critical path,
    /// which is what a cap of zero prices: the epoch's end becomes a group no
    /// fold can reach, the final proof absorbs it, and `T2 - T` goes from 10.5 s
    /// to 15.7 s. Two slots is the whole of the win — a cap of one gives back
    /// 0.4 s of it — so the bound that mattered is the model's, not a policy's.
    ///
    /// `test_ssz_file_streaming_schedule` prints these numbers off the 320 MB
    /// state download that [`EPOCH_430529`] was taken from; this runs offline.
    #[test]
    fn the_tail_cap_no_longer_binds_on_mainnet_430529() {
        let units = epoch_430529();
        let policy = StreamPolicy {
            lanes: 4,
            validators: 960_974.0,
            ..StreamPolicy::default()
        };
        let capped = schedule_capped(&units, TOTAL_ACTIVE_BALANCE_430529, &policy, 4);
        let uncapped = schedule(&units, TOTAL_ACTIVE_BALANCE_430529, &policy);

        assert_eq!(uncapped.plan.tail.len(), 2);
        assert!(
            uncapped.plan.absorbed.is_empty(),
            "a group left to absorb: {:?}",
            uncapped.plan,
        );
        assert_eq!(capped.plan, uncapped.plan, "the cap changed the plan");

        // In tenths, because that is the precision the constants underneath
        // carry and the precision `better` compares at.
        assert_eq!((uncapped.latency_s() * 10.0).round(), 105.0);

        // The tail priced from the other side: forbid it and the epoch's end is
        // a proof of its own, in series after the last attestation.
        let no_tail = schedule_capped(&units, TOTAL_ACTIVE_BALANCE_430529, &policy, 0);
        assert_eq!(no_tail.plan.absorbed.len(), 1);
        assert_eq!((no_tail.latency_s() * 10.0).round(), 157.0);

        // And it is cheaper, not a latency-for-throughput trade: a group's floor
        // and its complement work both leave the epoch with the group.
        assert!(uncapped.total_prover_s < no_tail.total_prover_s);
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
