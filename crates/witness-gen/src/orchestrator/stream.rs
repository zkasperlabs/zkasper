//! The streaming pipeline: prove as attestations arrive, fire when enough have.
//!
//! # It reads gossip, not blocks
//!
//! An attestation is gossiped in the slot it is made and included in a block one
//! or more slots later, so [`super::batch`]'s block walk is a slot behind the
//! chain by construction. This pipeline follows [`crate::gossip`] instead and
//! keeps the block walk for what it is good for: filling the gap after a stream
//! outage, and being the whole source in the fixture-replay tests.
//!
//! That moves the trigger from a slot boundary to an instant, which is what
//! makes *when* to fire a decision rather than a consequence. A slot still
//! filling is priced as if it closed now — its missing members are absentees —
//! so the weight is honest at every instant and what waiting buys is a cheaper
//! proof. [`StreamAggregator::worth_waiting`] takes that trade, one trigger
//! interval at a time.
//!
//! # One proof on the critical path
//!
//! A group per tick, each folded into a running aggregate as it finishes, and
//! then justification, finalization and the epoch's one final exponentiation
//! collapsed into a single proof over the attestation that crossed the
//! threshold — see [`crate::streaming`]. That last proof is the only thing on
//! `T2 - T`, and the manifest publishes the measured value.
//!
//! # Proving does not happen on the drive loop
//!
//! Groups are still proved one at a time and in order — one prover, one GPU —
//! but each proof runs on a thread of its own and the tick that started it
//! returns. See [`Proving`] for what that is worth and what it cost not to have.
//! The aggregator does not depend on the order proofs are produced in, so
//! handing the prover to a pool of GPUs is still a change to this file only.
use std::ops::Range;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::task::JoinHandle;
use tracing::{info, info_span, instrument, warn, Instrument};

use zkasper_common::bls::{fp12_mul, Fp12, FP12_ONE};
use zkasper_common::types::{
    AggregateOutput, AggregateWitness, BoundaryAnchor, Checkpoint, GroupProofOutput,
    PreviousJustification, SlotProofWitness, StreamFinalOutput, StreamFinalWitness,
};

use crate::artifacts::{
    now_unix_millis, CheckpointStatus, CurrentEpoch, EpochLatency, StageTiming,
};
use crate::attestation_collector::{SlotComplement, SlotStream};
use crate::beacon_api::{BeaconApi, ChainStatusApi};
use crate::committee::EpochCommittees;
use crate::prover::{Proof, ProveCost, Prover, Stage};
use crate::publish::{self, ClosedEpoch, EpochProgress};
use crate::store::{StoreState, StreamFinalRecord};
use crate::streaming::{self, Filling, StreamContext, StreamPolicy};

use super::engine::{write_proof, Engine, OpenEpoch};
use super::pipeline::EpochPipeline;
use super::reporter::{acc_status, percent_of};
use super::{OrchestratorConfig, Tick};

/// One epoch's streaming aggregation, part-built.
///
/// Everything that arrives before the attestation which carries the epoch over
/// the threshold is proven and folded the tick it arrives, so what is left when
/// the threshold crosses is one attestation and one proof.
struct StreamAggregator {
    context: StreamContext,
    /// This epoch's committee proof, which every group counts against.
    committees: Arc<EpochCommittees>,
    stream: SlotStream,
    /// Next block to ask the node for while repairing from blocks.
    next_slot: u64,
    /// One past the last slot worth scanning for this checkpoint.
    scan_end: u64,
    /// Whether gossip has a hole in it that blocks have to fill. True when the
    /// epoch opens, because the daemon did not hear the gossip that happened
    /// before it got there, and again whenever the stream drops.
    gap: bool,
    /// Whether the node has reported a reorg that this epoch has not checked.
    reorged: bool,
    /// The last reading of the slot gossip was filling: when it was taken, which
    /// slot, how many accumulator leaves it would have opened, and how many
    /// network aggregates it had. The trigger is the difference between two of
    /// these.
    last_filling: Option<(Instant, u64, usize, usize)>,
    /// Seconds the wait has run without an interval paying for itself. Reset by
    /// any interval that does, and by anything that ends the wait.
    stalled_s: f64,
    /// Leaves the wait on the current filling slot has taken off the tail so
    /// far. Reset with `stalled_s` when the trigger first sees a slot, and what
    /// tells [`StreamPolicy::worth_waiting`] what this wait set out to win.
    taken_while_filling: usize,
    /// Attestation slots closed so far, in order.
    units: Vec<SlotComplement>,
    /// How many of them a group proof already covers.
    proved: usize,
    attesting_balance: u64,
    aggregate: Option<AggregateOutput>,
    aggregate_proof: Proof,
    /// Miller accumulator behind `aggregate.miller_commitment`. Too big to be a
    /// public output, so the host carries it and the circuit checks the digest.
    aggregate_miller: Fp12,
    folded_groups: usize,
    /// A group proof that has landed and has not been folded, with the unit
    /// count it carries the epoch to.
    ///
    /// A group is collected on a tick that has not evaluated the trigger yet, so
    /// what to do with it is decided below rather than where it lands: folded in
    /// the `!fire` branch, and handed whole to the final proof in the other. See
    /// [`StreamPipeline::drive`] for why the fold has to be the branch's and not
    /// the collection's.
    unfolded: Option<(usize, GroupProof)>,
    /// The epoch this one finalizes, captured when the epoch opened so that
    /// neither it nor the boundary below is opened on the critical path.
    previous: PreviousJustification,
    previous_proof: Proof,
    boundary: BoundaryAnchor,
    opened_unix_millis: u64,
    /// Unix ms at which the daemon first *saw* it held enough attestations to
    /// justify. Not `T` — see [`EpochLatency::threshold_unix_millis`], which
    /// takes that from the chain. This is only ever as early as the first tick
    /// with no proof in flight, so it is the observation and not the event.
    crossed_unix_millis: Option<u64>,
    /// Unix ms at which the proof now in flight was started, while one is.
    /// Cleared by the first tick that finds the prover free, which is the only
    /// place a tick can reach the trigger.
    proving_since: Option<u64>,
    /// Wall time since [`Self::crossed_unix_millis`] that a proof started
    /// before the trigger fired was still running — see
    /// [`EpochLatency::blocked_millis`]. Accumulated rather than taken as one
    /// difference, because the daemon can be blocked, freed and blocked again
    /// while a configured threshold above the circuit's own quorum has not been
    /// reached, and every one of those intervals is the prover and not the
    /// trigger.
    blocked_millis: u64,
}

/// A finished group proof, waiting to be folded or handed to the final proof.
struct GroupProof {
    output: GroupProofOutput,
    miller: Fp12,
    proof: Proof,
}

/// A [`Prover`] call running off the drive loop.
///
/// [`Prover`] is synchronous and one call holds a GPU for minutes. Proving on
/// the calling task therefore stopped the whole loop for the length of every
/// proof — and the loop is where the head is refreshed and where the next
/// epoch's opening proofs are asked for.
///
/// Measured on mainnet, 2026-08-19. The tick that closed epoch 469482 ran from
/// 02:11:31 to 02:16:53 and carried throughout it a head taken before epoch
/// 469483's first slot existed, five seconds later. So
/// [`super::engine::Engine::speculate`] bailed on `head_slot < slot_2` and was
/// never asked again, and 469483 proved its own epoch diff and committee — 153 s
/// — on its own opening path. A threshold is a wall clock and does not move, so
/// that 153 s came straight out of the epoch's open-to-threshold slack: 16.6 s,
/// where the epoch beside it had 236 s. An epoch with less slack than a group
/// proof has no tick on which to fold, so its whole backlog lands on `T2 - T`
/// as a late group. 469483 measured 299.7 s against 469486's 162.3 s.
///
/// One prover still proves one thing at a time — the pipeline holds at most one
/// of these — so nothing here is about proving in parallel. It is about the loop
/// continuing to run while the prover works.
struct Proving<T> {
    /// When the stage began, witness build included, so that what the manifest
    /// records does not change with where the proof runs.
    started: Instant,
    handle: JoinHandle<Proved<T>>,
    /// The answer, once a wait has had it. A [`JoinHandle`] must not be polled
    /// after it completes, so a wait that lands parks its result here for
    /// [`Self::take`] rather than dropping it.
    landed: Option<Proved<T>>,
}

/// What a proving task answers with: the stage's output, and what it cost.
type Proved<T> = Result<(T, Option<ProveCost>)>;

impl<T: Send + 'static> Proving<T> {
    fn spawn(
        started: Instant,
        prover: Arc<dyn Prover>,
        prove: impl FnOnce(&dyn Prover) -> Result<T> + Send + 'static,
    ) -> Self {
        Self {
            started,
            // The cost is read on the proving thread rather than after the fact:
            // by the time the loop collects this, the same prover has answered
            // the speculation's calls. Same reason as [`super::speculation`].
            handle: tokio::task::spawn_blocking(move || {
                let output = prove(prover.as_ref())?;
                Ok((output, prover.last_cost()))
            }),
            landed: None,
        }
    }

    /// Wait for the proof, but never past `within`.
    ///
    /// Both halves matter. Returning at the interval is what lets the loop
    /// refresh its head and ask again for the next epoch's opening proofs, which
    /// is the whole point of not proving here. Waking the instant the proof
    /// lands is what keeps that interval off the epoch's own clock, so a
    /// pipeline of short ticks costs the same as one long one.
    async fn settle(&mut self, within: Duration) -> bool {
        if self.landed.is_some() {
            return true;
        }
        let Ok(joined) = tokio::time::timeout(within, &mut self.handle).await else {
            return false;
        };
        self.landed = Some(match joined {
            Ok(proved) => proved,
            Err(e) => Err(e).context("the proving task did not finish"),
        });
        true
    }

    async fn take(mut self) -> Proved<T> {
        match self.landed.take() {
            Some(landed) => landed,
            None => self
                .handle
                .await
                .context("the proving task did not finish")?,
        }
    }
}

/// A proof this pipeline started and has not collected, and what the tick that
/// collects it will do with the result.
///
/// At most one exists at a time, so the ordering the circuits require is kept by
/// construction: a group is folded only once it has landed, and the final proof
/// binds an aggregate that is already finished.
enum Pending {
    /// A group off the critical path, folded when it lands.
    Group(GroupInFlight),
    /// The fold of a group that has landed.
    Fold {
        index: usize,
        /// What `proved` becomes once this lands. Captured at the start rather
        /// than read off `units` at the end, because the loop keeps running.
        proved: usize,
        witness: Arc<AggregateWitness>,
        proving: Proving<(AggregateOutput, Proof)>,
    },
    /// The backlog the trigger fired on top of. The final proof follows it.
    Late { group: GroupInFlight, fired: Fired },
    /// The one proof on `T2 - T`.
    Final {
        closing: Closing,
        witness: Arc<StreamFinalWitness>,
        proving: Proving<(StreamFinalOutput, Proof, u64)>,
    },
}

/// A group proof in flight, and what the tick that collects it will need.
struct GroupInFlight {
    range: Range<usize>,
    witness: Arc<SlotProofWitness>,
    proving: Proving<(GroupProofOutput, Fp12, Proof)>,
}

impl Pending {
    async fn settle(&mut self, within: Duration) -> bool {
        match self {
            Pending::Group(group) | Pending::Late { group, .. } => {
                group.proving.settle(within).await
            }
            Pending::Fold { proving, .. } => proving.settle(within).await,
            Pending::Final { proving, .. } => proving.settle(within).await,
        }
    }
}

/// What the trigger decided, carried from the instant it fired to the proof that
/// closes the epoch.
struct Fired {
    unix_millis: u64,
    /// Units the final proof carries inline, as [`streaming::plan`] cut them,
    /// clamped to what the running aggregate does not already cover. Always ends
    /// at the unit that carried the epoch over the threshold.
    tail: Range<usize>,
}

/// What the tick that collects the final proof needs in order to report the
/// epoch that produced it.
struct Closing {
    started: Instant,
    fired_unix_millis: u64,
    late_group_millis: u64,
    late_groups: usize,
    tail: usize,
    tail_named: usize,
}

/// What one evaluation of the trigger sees.
struct Held {
    /// Attested balance: closed units and still-filling slots together.
    balance: u64,
    /// The slot gossip is still filling that the proof would have to carry: the
    /// accumulator leaves it would open if the trigger fired now, and the
    /// network aggregates it has. Waiting buys the difference between two
    /// readings of it; nothing else moves.
    filling: Option<(u64, usize, usize)>,
    /// Every slot gossip has reached, priced as if it closed now.
    open: Vec<SlotComplement>,
}

impl StreamAggregator {
    fn exhausted(&self, head_slot: u64) -> bool {
        head_slot >= self.scan_end
    }

    /// The units the final proof carries inline, ending at the one that carries
    /// the epoch over the scheduling threshold.
    ///
    /// Goes through [`streaming::plan`] rather than recomputing the crossing, so
    /// the daemon and the schedule the tests pin can never disagree on where an
    /// epoch ends — nor on how much of it the final proof swallows whole, which
    /// this used to decide for itself by taking the crossing slot alone and
    /// throwing [`streaming::StreamPlan::tail`] away. That cost a recursion:
    /// everything between the aggregate and the crossing became a group the
    /// final proof had to absorb, at
    /// [`streaming::ProverModel::recursion_verify_s`], where inlining the same
    /// slots is complement work and no child at all.
    ///
    /// It starts at `proved`, not at the plan's cut, because the plan is cut for
    /// a prover that kept up and `proved` is what this one actually folded. A
    /// group for the difference is the same complement work plus a stage floor,
    /// a second Miller batch, a recursion in the final proof and a round trip to
    /// the card, and it runs entirely after `T` — so a daemon behind the plan
    /// inlines the difference for the same reason a daemon ahead of it does.
    ///
    /// An `unfolded` group displaces both. It is the group the final proof will
    /// absorb, and the fire path has no second group to bridge with, so the tail
    /// starts exactly where it ends rather than at the plan's cut — anything
    /// else leaves units under no child at all.
    fn tail(&self, policy: &StreamPolicy) -> Option<Range<usize>> {
        let plan = streaming::plan(&self.units, self.context.total_active_balance, policy);
        if !plan.threshold_reached {
            return None;
        }
        let crossing = plan
            .groups
            .concat()
            .into_iter()
            .chain(plan.tail.iter().copied())
            .max()?;
        let start = match &self.unfolded {
            Some((proved, _)) => *proved,
            None => self.proved,
        };
        Some(start.min(crossing + 1)..crossing + 1)
    }

    /// Price every slot gossip has reached as if it closed this instant.
    ///
    /// A slot contributes whole — `slots_mask` counts it once — so the members
    /// whose attestations are still in flight are counted as the absentees they
    /// would be. The weight is therefore honest at any instant, and what waiting
    /// buys is a cheaper proof rather than a valid one.
    fn held(&self, spe: u64, head_slot: u64, policy: &StreamPolicy) -> Held {
        let epoch = self.context.target_epoch;
        let open: Vec<SlotComplement> = self
            .stream
            .open_slots()
            .into_iter()
            .filter(|slot| *slot >= epoch * spe && *slot < (epoch + 1) * spe)
            .filter_map(|slot| self.stream.peek(slot))
            .collect();

        let target = policy.target_balance(self.context.total_active_balance);
        let mut balance = 0u64;
        let mut crossing = None;
        for (i, unit) in self.units.iter().chain(&open).enumerate() {
            balance += unit.marginal_balance;
            if crossing.is_none() && balance as u128 >= target {
                crossing = Some(i);
            }
        }

        // A slot is finished with once something later has arrived: gossip for a
        // later attestation slot, or a chain head past it. A straggler included
        // after that is an absentee, which costs a little weight and no
        // soundness — so only the frontier is still worth waiting on, and only
        // while the threshold still needs it.
        let frontier = open.last().map_or(head_slot, |u| u.slot.max(head_slot));
        let filling = open
            .last()
            .filter(|unit| unit.slot >= frontier)
            .filter(|_| crossing.is_none_or(|c| c + 1 == self.units.len() + open.len()))
            .map(|unit| {
                (
                    unit.slot,
                    unit.named_indices.len(),
                    self.stream.aggregates(unit.slot),
                )
            });

        Held {
            balance,
            filling,
            open,
        }
    }

    /// Whether waiting another interval is still worth it, which is the whole of
    /// the firing decision once the weight is there.
    ///
    /// Nothing still filling means fire: there is nothing in flight to wait for,
    /// and `held` only ever marks the frontier slot filling, so an epoch opened
    /// long after it crossed has no slot here and invents no wait.
    ///
    /// **A slot with no earlier reading of it is not the same as no slot.** Two
    /// readings are what a *rate* needs, and the rule is two questions, only one
    /// of which is a rate — [`StreamPolicy::worth_waiting`] also asks whether
    /// this slot's aggregates have landed, and one reading answers that. The
    /// first reading was treated as no reading until 2026-08-20, and on the live
    /// mainnet run that was every reading the trigger ever got: the ticks
    /// between the crossing and the fire are spent inside the settle that waits
    /// on the epoch's own backlog, and those return before this is reached, so
    /// the reading the fire tick compared against was from before that proof
    /// started and named an earlier slot. The rule bailed here, on its first
    /// line, on every epoch of the run.
    ///
    /// What that cost is the tail. Measured over 69 mainnet epochs on
    /// 2026-08-19/20, by the second of the crossing slot the trigger fired in:
    /// firing at 6-8 s leaves a median 7,524 named leaves and firing at 10-12 s
    /// leaves 130, because a slot's aggregates land in one piece at 8.1-8.2 s
    /// and carry its coverage from 76% to 99.7%. At
    /// [`streaming::ProverModel::per_named_s`] and the 1.026 s a megabyte the
    /// same run measured on the link, those 7,394 leaves are 6.1 s of `T2 - T`
    /// against the 2-4 s of waiting they cost.
    fn worth_waiting(
        &mut self,
        policy: &StreamPolicy,
        filling: Option<(u64, usize, usize)>,
    ) -> bool {
        let Some(now) = filling else {
            self.stalled_s = 0.0;
            return false;
        };
        // A reading of *this* slot. One of another slot says nothing about this
        // one, and is the same as none.
        let previous = self
            .last_filling
            .filter(|(_, was, _, _)| *was == now.0)
            .map(|(at, _, named, aggregates)| (at.elapsed().as_secs_f64(), named, aggregates));
        if previous.is_none() {
            self.stalled_s = 0.0;
            self.taken_while_filling = 0;
        }
        let (interval_s, filling) = reading(previous, now, self.taken_while_filling);
        self.taken_while_filling = filling.taken;
        self.stalled_s = if policy.interval_paid(filling.removed, interval_s) {
            0.0
        } else {
            self.stalled_s + interval_s
        };
        policy.worth_waiting(filling, interval_s, self.stalled_s, self.waited_s())
    }

    /// Seconds the trigger has held, which is what the budget on waiting is
    /// measured against.
    ///
    /// Since the crossing **less the prover's own backlog**. A proof that was
    /// already running when the chain crossed is work and not waiting: the
    /// trigger could not have fired during it whatever it decided, so charging
    /// it here spends a budget the trigger never got to use. On the live
    /// mainnet run that was 1.4-3.2 s of a 4.1 s budget gone before the trigger
    /// was consulted once, which left it a wait too short to reach the
    /// aggregates it exists to wait for.
    ///
    /// This is the same distinction [`EpochLatency::blocked_millis`] draws one
    /// layer up, for the same reason and against the same number. It was drawn
    /// there on 2026-08-19 and not here.
    fn waited_s(&self) -> f64 {
        held_for_s(
            self.crossed_unix_millis,
            self.blocked_millis,
            now_unix_millis(),
        )
    }
}

/// What the trigger saw, out of this tick's reading of the filling slot and the
/// last one's of the same slot.
///
/// `None` for the previous reading is the first sight of this slot, and the
/// answer is a zero interval with nothing removed: no arrivals were observed,
/// so [`StreamPolicy::interval_paid`] is false and the decision falls to the
/// half of the rule that one reading answers. See
/// [`StreamAggregator::worth_waiting`] for what treating that as no reading at
/// all cost.
fn reading(
    previous: Option<(f64, usize, usize)>,
    now: (u64, usize, usize),
    taken: usize,
) -> (f64, Filling) {
    let (_slot, named, aggregates) = now;
    let removed = previous.map_or(0, |(_, was, _)| was.saturating_sub(named));
    (
        previous.map_or(0.0, |(interval_s, _, _)| interval_s),
        Filling {
            in_flight: named,
            removed,
            taken: taken + removed,
            aggregates,
            new_aggregates: previous.map_or(0, |(_, _, was)| aggregates.saturating_sub(was)),
        },
    )
}

/// Seconds the trigger has held: since the crossing, less the prover's backlog.
fn held_for_s(crossed_unix_millis: Option<u64>, blocked_millis: u64, now: u64) -> f64 {
    crossed_unix_millis.map_or(0.0, |t| {
        now.saturating_sub(t).saturating_sub(blocked_millis) as f64 / 1000.0
    })
}

/// The streaming pipeline, and the one epoch it may have part-built.
#[derive(Default)]
pub(super) struct StreamPipeline {
    aggregator: Option<StreamAggregator>,
    /// The proof this epoch is waiting on, if any. See [`Proving`].
    pending: Option<Pending>,
}

impl EpochPipeline for StreamPipeline {
    async fn drive<A: BeaconApi + ChainStatusApi>(
        &mut self,
        engine: &mut Engine<A>,
        tick: &mut Tick,
    ) -> Result<()> {
        let target_epoch = engine.snapshot.state.cursor_epoch;

        let aggregator = match self.aggregator.take() {
            Some(aggregator) if aggregator.context.target_epoch == target_epoch => aggregator,
            _ => {
                // Every proof in flight was bound to the epoch being replaced,
                // so none of it is worth collecting.
                self.pending = None;
                Self::open(engine, target_epoch).await?
            }
        };

        // Instrumented rather than entered. Nearly all of a tick is the await
        // inside `settle`, and a guard held across an await is never exited, so
        // the wait was counted as `time.busy`: a sleeping loop logged 201 ms of
        // work five times a second, and read as a daemon burning a core.
        self.drive_epoch(engine, tick, aggregator)
            .instrument(info_span!("stream", target_epoch))
            .await
    }

    fn forget(&mut self) {
        self.aggregator = None;
        // Dropping the handle detaches the task rather than stopping it —
        // nothing interrupts a proof already on a blocking thread — but the
        // task writes nothing, so what it leaves behind is prover time.
        self.pending = None;
    }
}

impl StreamPipeline {
    /// One tick of the epoch in flight, under the span that names it.
    async fn drive_epoch<A: BeaconApi + ChainStatusApi>(
        &mut self,
        engine: &mut Engine<A>,
        tick: &mut Tick,
        mut aggregator: StreamAggregator,
    ) -> Result<()> {
        let target_epoch = aggregator.context.target_epoch;
        let spe = engine.config.chain.slots_per_epoch;

        // Gossip is the source. Blocks repair what an outage swallowed, and are
        // the whole source when there is no stream — the fixture-replay tests.
        if engine.gossip.is_none() {
            aggregator.gap = true;
        }
        Self::absorb_gossip(engine, &mut aggregator, spe)?;
        // Not once the trigger has fired. The fire closed every slot it took
        // and the tail is already cut, so a repair after it can only spend
        // round trips and committee resolution on the critical path for a
        // stream nothing will read again.
        if aggregator.gap && !self.fired() {
            Self::repair_from_blocks(engine, &mut aggregator, spe).await?;
        }

        let policy = engine.config.stream_policy.clone();
        let total = aggregator.context.total_active_balance;

        // Observe the crossing here, before anything can return. `held` reads
        // the stream this tick has just ingested, so the answer is available at
        // this point — and the in-flight branch below returns without ever
        // reaching the arm that used to ask. That return is why
        // `observation_millis` charged the daemon's own blindness to the chain:
        // over 29 steady-state mainnet epochs on 2026-08-19 the median gap
        // between the chain crossing two thirds and this process noticing was
        // 99 s, worst 549.6 s, and none of it was the chain being slow.
        // Stamping it here leaves `observation_millis` measuring gossip arrival
        // and moves the daemon's blocking into `wait_millis`, which is the term
        // the schedule owns and can shorten.
        //
        // Only while it has not crossed. `held` walks the epoch's units, and a
        // tick that already knows the answer must not pay to learn it again.
        if aggregator.crossed_unix_millis.is_none() {
            let held = aggregator.held(spe, engine.chain.head_slot(), &policy);
            Self::observe_crossing(engine, &mut aggregator, &policy, held.balance);
        }

        // A proof started on an earlier tick. Until it lands the pipeline must
        // not start another — one prover proves one thing at a time — so a tick
        // that finds one still running does the work that does not need the
        // prover and returns. Asking again for the next epoch's opening proofs
        // is the whole point of returning: this tick is short, so the head it
        // asks against is current, and a boundary that did not exist when the
        // epoch opened exists by now.
        //
        // A tick that *collects* a group carries on past this point instead of
        // returning, and that is what keeps the trigger from being consulted
        // only after the next proof has already been queued. `collect` used to
        // start the fold itself, one arm below the settle, so a group landing
        // on an epoch the chain had already carried over two thirds bought
        // another whole aggregate proof of blindness before anything looked.
        // Measured over 29 steady-state mainnet epochs on 2026-08-19: 42% of
        // the 2,500 s between the chain crossing and the daemon seeing it was
        // proofs *started* after the crossing, and nine of the ten were that
        // fold. The fold is worth running before `T` and never after it — the
        // final proof verifies the group directly if it is not folded — so the
        // decision belongs to the branch that knows whether the epoch is
        // justifiable, which is below.
        if let Some(mut pending) = self.pending.take() {
            if !pending.settle(engine.config.trigger_interval).await {
                engine.speculate(target_epoch + 1).await;
                self.pending = Some(pending);
                self.aggregator = Some(aggregator);
                return Ok(());
            }
            let Some(collected) = self.collect(engine, aggregator, pending, tick).await? else {
                return Ok(());
            };
            aggregator = collected;
        }

        // A reorg can take the checkpoint out from under an epoch that is
        // already half collected. Everything counted so far attested to a root
        // that is no longer canonical, so the epoch restarts against the new one
        // rather than proving the old one. Doing it here, off a node event,
        // keeps the round trip away from the critical path.
        if std::mem::take(&mut aggregator.reorged)
            && engine
                .chain
                .checkpoint_root(&engine.api, &engine.config, target_epoch)
                .await?
                != aggregator.context.target_root
        {
            warn!(
                target_epoch,
                "the checkpoint reorged out; reopening the epoch"
            );
            // The next epoch's committees were summed out of a boundary state
            // that may have moved with it. The accumulator has not, so the diff
            // would still adopt cleanly — but half a speculation is not worth
            // the reasoning, and the card that made it is otherwise idle.
            engine.ahead.forget();
            return Ok(());
        }

        // The prover is free here, and only here: every path that reaches this
        // line took `self.pending` above and collected whatever it held. So
        // this is the first instant since a proof started on which the trigger
        // could be asked anything, and everything between the crossing and it
        // is the prover working — the epoch's own backlog, still running when
        // the chain got there.
        //
        // Charging it to `wait_millis` is what made a 55 s group proof read as
        // a 55 s wait against a 10 s cap. The crossing is stamped above the
        // in-flight early return, deliberately, and the fire decision is below
        // it; the interval between the two belongs to neither the trigger nor
        // the daemon's blindness, and had no term of its own until 2026-08-19.
        if let (Some(crossed), Some(since)) = (
            aggregator.crossed_unix_millis,
            aggregator.proving_since.take(),
        ) {
            aggregator.blocked_millis += now_unix_millis().saturating_sub(since.max(crossed));
        }

        // Everything gossip has delivered *since the top of this tick* — the
        // block walk above, the proof settled below it, the reorg round trip —
        // so that the view the trigger decides on is as fresh as the decision
        // and not as fresh as the tick.
        //
        // Measured on 1.08M live mainnet gossip events, epoch 469606. The epoch
        // opened 4.05 s into its crossing slot; the tick then spent 8.01 s busy
        // walking 22 blocks without yielding and fired at 11.96 s on the drain
        // it had taken at ~4.5 s. A crossing slot's gossip arrives in two waves:
        // the singles union reaches 60.3% at 5.0 s and stops at 76-77%, and the
        // network aggregates land in one piece at 8.1-8.2 s and carry it to
        // 99.7%. The primary covered 59.6% — the singles union at ~5 s — three
        // seconds after the aggregates were on the wire. `named_indices.len()`
        // is exactly `committee size - primary coverage`, so that one drain
        // decided a tail of 11,379 leaves, every one of them
        // [`streaming::ProverModel::per_named_s`] on the critical path.
        Self::absorb_gossip(engine, &mut aggregator, spe)?;

        let held = aggregator.held(spe, engine.chain.head_slot(), &policy);
        // Again here, because the reading above is no longer the one the trigger
        // acts on: an epoch can cross on gossip that arrived after the hoist and
        // fire on the same tick, and a fire with no observation stamped has no
        // `T2 - T` to publish at all.
        Self::observe_crossing(engine, &mut aggregator, &policy, held.balance);

        let enough = held.balance as u128 >= policy.target_balance(total);
        let fire = enough && !aggregator.worth_waiting(&policy, held.filling);
        aggregator.last_filling = held
            .filling
            .map(|(slot, named, aggregates)| (Instant::now(), slot, named, aggregates));

        if !fire {
            if let Some(publish) = engine.report.publisher() {
                publish.epoch_progress(&EpochProgress {
                    epoch: target_epoch,
                    attesting_balance: held.balance,
                    total_active_balance: total,
                    threshold_pct: policy.threshold_pct(),
                    folded_groups: aggregator.folded_groups,
                    slots_held: aggregator.units.len(),
                    head_slot: engine.chain.head_slot(),
                });
            }
            // Slots gossip has finished with are proven and folded now, off the
            // critical path. The one it is still filling is left open: closing it
            // would count everyone still in flight as an absentee.
            let complete = held.open.len() - usize::from(held.filling.is_some());
            for unit in held.open.into_iter().take(complete) {
                aggregator.stream.forget(unit.slot);
                aggregator.attesting_balance += unit.marginal_balance;
                aggregator.units.push(unit);
            }
            // Nothing new goes to the prover once the epoch holds enough to
            // justify; only the wait for in-flight attestations is left, and it
            // is bounded by [`StreamPolicy::wait_budget_s`]. A fold started here
            // would sit between the chain crossing and the daemon seeing it and
            // take nothing off the critical path in exchange, and a group would
            // become a recursion child of slots the tail carries inline.
            if !enough {
                if let Some((proved, group)) = aggregator.unfolded.take() {
                    self.pending = Some(Self::start_fold(engine, &mut aggregator, proved, group));
                } else if aggregator.proved < aggregator.units.len() {
                    self.pending = Some(Pending::Group(Self::start_group(
                        engine,
                        &aggregator,
                        aggregator.proved..aggregator.units.len(),
                    )));
                }
                // The only proofs that can be running when the chain crosses
                // are started here, so this is the whole of what
                // `blocked_millis` measures from.
                if self.pending.is_some() {
                    aggregator.proving_since = Some(now_unix_millis());
                }
            }
            // Again here, and not only when the epoch opened. The boundary the
            // next epoch's diff needs does not exist until the chain reaches
            // it, so a daemon close to the head has none to start from at
            // `open_epoch` and would otherwise wait a whole epoch to ask
            // again. `covers` makes this free once one is running.
            engine.speculate(target_epoch + 1).await;
            if aggregator.exhausted(engine.chain.head_slot()) {
                warn!(
                    target_epoch,
                    attesting_balance = aggregator.attesting_balance,
                    total_active_balance = total,
                    "checkpoint never reached the threshold; giving up on this epoch",
                );
                if let Some(publish) = engine.report.publisher() {
                    publish.epoch_abandoned(target_epoch, "never reached the threshold");
                }
                engine.snapshot.state.attempted_epoch = Some(target_epoch);
                engine.store.save(&engine.snapshot)?;
                // Including whatever was being proved for it. An abandoned
                // epoch has nobody left to collect that proof, and a loop that
                // waits for one nothing will collect never returns.
                self.pending = None;
                tick.gave_up_on = Some(target_epoch);
            } else {
                self.aggregator = Some(aggregator);
            }
            return Ok(());
        }

        // Fire. `T2 - T` splits here, and the split is the whole reason this
        // timestamp is taken now rather than when the final proof starts: the
        // wait is over at this instant, and everything after it — the late group
        // proof below, then the final proof — is the prover working. Stamping it
        // in the closing proof instead charged the late group to the wait, which made a
        // 141 s group proof read as a 141 s trigger hold against a cap of 10 s.
        let fired_unix_millis = now_unix_millis();

        // Everything gossip has reached is closed, and the plan decides how much
        // of it the final proof carries inline; slots past the crossing are
        // simply never proven.
        for unit in held.open {
            aggregator.stream.forget(unit.slot);
            aggregator.attesting_balance += unit.marginal_balance;
            aggregator.units.push(unit);
        }
        let tail = aggregator
            .tail(&policy)
            .context("the threshold moved out from under the trigger")?;
        let fired = Fired {
            unix_millis: fired_unix_millis,
            tail: tail.clone(),
        };
        // A group held from this tick's collection is already the backlog the
        // final proof absorbs, so the fire path has nothing left to prove before
        // the one proof on `T2 - T`.
        let unfolded = aggregator.unfolded.take();
        self.pending = Some(match unfolded {
            Some((_, group)) => Self::start_final(engine, &aggregator, Some(group), fired)?,
            None if aggregator.proved < tail.start => Pending::Late {
                group: Self::start_group(engine, &aggregator, aggregator.proved..tail.start),
                fired,
            },
            None => Self::start_final(engine, &aggregator, None, fired)?,
        });
        self.aggregator = Some(aggregator);
        Ok(())
    }

    /// Whether the trigger has already fired on this epoch.
    ///
    /// Both of these hold the backlog the fire decided on, so nothing arriving
    /// after them can change what the epoch proves.
    fn fired(&self) -> bool {
        matches!(
            self.pending,
            Some(Pending::Late { .. } | Pending::Final { .. })
        )
    }

    /// Take everything gossip has delivered since the last call.
    ///
    /// Called wherever the epoch is about to be read rather than once at the
    /// top of the tick, because a drain is only as good as the instant it was
    /// taken and a tick is not an instant — see the call above
    /// [`StreamAggregator::held`] for what one stale drain cost.
    ///
    /// A gap rewinds the block walk rather than resuming it: an outage does not
    /// say what it swallowed, so the repair rescans the epoch.
    fn absorb_gossip<A: BeaconApi + ChainStatusApi>(
        engine: &Engine<A>,
        aggregator: &mut StreamAggregator,
        spe: u64,
    ) -> Result<()> {
        let Some(source) = &engine.gossip else {
            return Ok(());
        };
        aggregator.stream.ingest(&source.drain())?;
        aggregator.reorged |= source.took_reorg();
        if source.took_gap() {
            let target_epoch = aggregator.context.target_epoch;
            warn!(target_epoch, "gossip gap; repairing this epoch from blocks");
            aggregator.next_slot = target_epoch * spe;
            aggregator.gap = true;
        }
        Ok(())
    }

    /// Stamp the instant the daemon first saw the epoch hold what the circuit
    /// insists on, and tell the world.
    ///
    /// Read twice a tick off two different readings, because the placement of
    /// the first one is load-bearing and the second one is what the trigger
    /// actually acts on. The first is above the in-flight early return, so that
    /// a proof still running at the crossing is charged to
    /// [`EpochLatency::blocked_millis`] instead of to the wait. The second is
    /// beside the fire decision, so that an epoch which crosses on gossip that
    /// arrived after the first reading still has an observation to measure
    /// `T2 - T` from.
    fn observe_crossing<A: BeaconApi + ChainStatusApi>(
        engine: &Engine<A>,
        aggregator: &mut StreamAggregator,
        policy: &StreamPolicy,
        balance: u64,
    ) {
        let total = aggregator.context.total_active_balance;
        if aggregator.crossed_unix_millis.is_some()
            || (balance as u128) < policy.quorum_balance(total)
        {
            return;
        }
        let crossed = now_unix_millis();
        aggregator.crossed_unix_millis = Some(crossed);
        if let Some(publish) = engine.report.publisher() {
            publish.threshold_crossed(aggregator.context.target_epoch, crossed, balance, total);
        }
    }

    /// Fill in from blocks what gossip did not deliver.
    ///
    /// Only two things need it: an epoch that opened after its own attestations
    /// were gossiped, and a stream that dropped. Both are repairs — the union of
    /// a block and a gossip view of a slot is the gossip view, because the
    /// collector converges on an attester set rather than a list.
    ///
    /// It is the longest thing a tick does and almost none of it is the round
    /// trip: 22 blocks of a mainnet epoch measured 8.01 s busy against 17.3 ms
    /// idle, because a block's aggregates are resolved against committees of
    /// tens of thousands and none of that awaits. So the walk drains gossip and
    /// yields between blocks — the stream stays current across it instead of
    /// being 8 s behind at the end of it, and a reader task sharing the runtime
    /// is not off-core for its whole length.
    async fn repair_from_blocks<A: BeaconApi + ChainStatusApi>(
        engine: &mut Engine<A>,
        aggregator: &mut StreamAggregator,
        spe: u64,
    ) -> Result<()> {
        aggregator.gap = false;
        while !aggregator.gap
            && aggregator.next_slot <= engine.chain.head_slot()
            && aggregator.next_slot < aggregator.scan_end
        {
            let slot = aggregator.next_slot;
            aggregator.next_slot += 1;

            // A slot with no block is not an error; neither is one whose
            // attestations all point somewhere else.
            if let Ok(attestations) = engine.api.get_block_attestations(&slot.to_string()).await {
                aggregator.stream.ingest(&attestations)?;
            }

            // An outage announced mid-walk ends the walk rather than being
            // scanned over: the rewind above put the cursor back at the epoch's
            // first slot, and the next tick starts again from there.
            Self::absorb_gossip(engine, aggregator, spe)?;
            tokio::task::yield_now().await;
        }
        Ok(())
    }

    /// Open an epoch against the accumulator, the diff that carried it here, and
    /// the justification this epoch will finalize.
    ///
    /// Everything the final proof needs that is not an attestation is fetched
    /// here, an epoch ahead of when it is used, so that no round trip to the
    /// beacon node lands between `T` and `T2`.
    async fn open<A: BeaconApi + ChainStatusApi>(
        engine: &mut Engine<A>,
        target_epoch: u64,
    ) -> Result<StreamAggregator> {
        let spe = engine.config.chain.slots_per_epoch;
        let OpenEpoch {
            target_root,
            source_root,
            signing_domain,
            committees,
            committee_output,
            committee_proof,
            stream,
        } = engine.open_epoch(target_epoch).await?;

        let epoch_diff = engine
            .snapshot
            .state
            .last_epoch_diff
            .clone()
            .context("no epoch diff on record to open the epoch against")?;
        let (previous, previous_proof) = engine
            .snapshot
            .state
            .previous_justification(target_epoch)
            .context("no justification for the previous epoch to finalize")?;

        let boundary = crate::boundary::build(
            &engine.api,
            &engine.config.chain,
            &target_root,
            previous.target_epoch(),
            &previous.target_root(),
            &epoch_diff.output.state_root_1,
            &engine.snapshot.epoch_state,
        )
        .await
        .context("open the boundary of the epoch being finalized")?;

        let state = &engine.snapshot.state;
        let context = StreamContext {
            accumulator_commitment: state.acc_commitment,
            acc_root: state.acc_root,
            total_active_balance: state.total_active_balance,
            target_epoch,
            target_root,
            source_root,
            signing_domain,
            aggregate_program_vk: engine.prover.program_vk(Stage::Aggregate),
            stream_program_vk: engine.prover.program_vk(Stage::StreamFinal),
            epoch_diff: epoch_diff.output,
            epoch_diff_proof: epoch_diff.proof,
            committee: committee_output,
            committee_proof,
            acc_depth: engine.config.chain.acc_tree_depth,
        };

        if let Some(publish) = engine.report.publisher() {
            publish.epoch_opened(
                target_epoch,
                &target_root,
                previous.target_epoch(),
                state.total_active_balance,
                serde_json::to_value(acc_status(&engine.snapshot.state))?,
            );
        }
        info!(
            target_epoch,
            target_root = %crate::artifacts::hex0x(&target_root),
            finalizes = previous.target_epoch(),
            "opened epoch",
        );

        Ok(StreamAggregator {
            context,
            committees,
            stream,
            next_slot: target_epoch * spe,
            scan_end: (target_epoch + engine.config.attestation_lookahead_epochs) * spe,
            // The epoch's earlier slots were gossiped before the daemon reached
            // it, so it starts by repairing them out of blocks.
            gap: true,
            reorged: false,
            last_filling: None,
            stalled_s: 0.0,
            taken_while_filling: 0,
            units: Vec::new(),
            proved: 0,
            attesting_balance: 0,
            aggregate: None,
            aggregate_proof: Proof::new(),
            aggregate_miller: FP12_ONE,
            folded_groups: 0,
            unfolded: None,
            previous,
            previous_proof,
            boundary,
            opened_unix_millis: now_unix_millis(),
            crossed_unix_millis: None,
            proving_since: None,
            blocked_millis: 0,
        })
    }

    /// Build one group's witness and hand the proof to a thread of its own.
    ///
    /// Nothing about the epoch changes until [`Self::finish_group`] collects it,
    /// and nothing but the witness build happens on the loop.
    #[instrument(
        name = "stage",
        skip_all,
        fields(stage = "group", epoch = aggregator.context.target_epoch, index = range.start),
    )]
    fn start_group<A: BeaconApi + ChainStatusApi>(
        engine: &mut Engine<A>,
        aggregator: &StreamAggregator,
        range: Range<usize>,
    ) -> GroupInFlight {
        let started = Instant::now();
        let target_epoch = aggregator.context.target_epoch;
        engine
            .report
            .begin(Stage::Group, target_epoch, None, Some(range.start));
        let units: Vec<&SlotComplement> = aggregator.units[range.clone()].iter().collect();
        if let Some(last) = units.last() {
            engine
                .chain
                .observe_start_delay(&engine.config, Stage::Group, target_epoch, last.slot);
        }

        let witness = Arc::new(streaming::group_witness(
            &aggregator.context,
            &engine.snapshot.tree,
            &aggregator.committees,
            &units,
        ));
        let proving = Proving::spawn(started, engine.prover.clone(), {
            let witness = witness.clone();
            move |prover| prover.prove_group(&witness)
        });
        GroupInFlight {
            range,
            witness,
            proving,
        }
    }

    /// Collect a finished group proof: write it, time it, and hand it on to be
    /// folded or given to the final proof.
    #[instrument(
        name = "stage",
        skip_all,
        fields(stage = "group", epoch = aggregator.context.target_epoch, index = group.range.start),
    )]
    async fn finish_group<A: BeaconApi + ChainStatusApi>(
        engine: &mut Engine<A>,
        aggregator: &StreamAggregator,
        group: GroupInFlight,
        tick: &mut Tick,
    ) -> Result<GroupProof> {
        let GroupInFlight {
            range,
            witness,
            proving,
        } = group;
        let started = proving.started;
        let target_epoch = aggregator.context.target_epoch;
        let slots: Vec<u64> = aggregator.units[range.clone()]
            .iter()
            .map(|u| u.slot)
            .collect();
        let ((output, miller, proof), cost) = proving
            .take()
            .await
            .with_context(|| format!("group proof over slots {slots:?}"))?;

        let name = format!("group_{}", range.start);
        let artifact = engine.sink.write_witness(target_epoch, &name, &*witness)?;
        write_proof(&engine.sink, target_epoch, &name, &proof)?;

        info!(
            slots = ?slots,
            attesting_balance = output.attesting_balance,
            millis = started.elapsed().as_millis() as u64,
            "group proof",
        );
        engine.report.record(
            StageTiming::new(Stage::Group, target_epoch, started, cost, artifact)
                .at_index(range.start)
                .with_proof(&proof),
        );
        tick.slots_proved.extend(slots);

        Ok(GroupProof {
            output,
            miller,
            proof,
        })
    }

    /// Start folding a finished group into the running aggregate.
    #[instrument(
        name = "stage",
        skip_all,
        fields(stage = "aggregate", epoch = aggregator.context.target_epoch),
    )]
    fn start_fold<A: BeaconApi + ChainStatusApi>(
        engine: &mut Engine<A>,
        aggregator: &mut StreamAggregator,
        proved: usize,
        group: GroupProof,
    ) -> Pending {
        let started = Instant::now();
        let target_epoch = aggregator.context.target_epoch;
        if let Some(last) = aggregator.units.last() {
            engine.chain.observe_start_delay(
                &engine.config,
                Stage::Aggregate,
                target_epoch,
                last.slot,
            );
        }
        engine.report.begin(
            Stage::Aggregate,
            target_epoch,
            None,
            Some(aggregator.folded_groups),
        );

        let witness = Arc::new(streaming::aggregate_witness(
            &aggregator.context,
            aggregator.aggregate.clone(),
            std::mem::take(&mut aggregator.aggregate_proof),
            aggregator.aggregate_miller,
            vec![group.output],
            vec![group.proof],
            vec![group.miller],
        ));
        let proving = Proving::spawn(started, engine.prover.clone(), {
            let witness = witness.clone();
            move |prover| prover.prove_aggregate(&witness)
        });
        Pending::Fold {
            index: aggregator.folded_groups,
            proved,
            witness,
            proving,
        }
    }

    /// Adopt a finished fold: from here the aggregate covers `proved` units.
    #[instrument(
        name = "stage",
        skip_all,
        fields(stage = "aggregate", epoch = aggregator.context.target_epoch),
    )]
    async fn finish_fold<A: BeaconApi + ChainStatusApi>(
        engine: &mut Engine<A>,
        aggregator: &mut StreamAggregator,
        index: usize,
        proved: usize,
        witness: Arc<AggregateWitness>,
        proving: Proving<(AggregateOutput, Proof)>,
    ) -> Result<()> {
        let started = proving.started;
        let target_epoch = aggregator.context.target_epoch;
        let ((output, proof), cost) = proving.take().await?;

        let name = format!("aggregate_{index}");
        let artifact = engine.sink.write_witness(target_epoch, &name, &*witness)?;
        write_proof(&engine.sink, target_epoch, &name, &proof)?;

        // The groups' own Miller accumulators, read back off the witness this
        // fold was built against rather than carried a second time beside it.
        for miller in &witness.group_millers {
            aggregator.aggregate_miller = fp12_mul(&aggregator.aggregate_miller, &miller.0);
        }
        aggregator.attesting_balance = output.attesting_balance;
        aggregator.aggregate = Some(output);
        aggregator.aggregate_proof = proof;
        aggregator.folded_groups += 1;
        aggregator.proved = proved;

        info!(
            folded = aggregator.folded_groups,
            attesting_balance = aggregator.attesting_balance,
            pct = percent_of(
                aggregator.attesting_balance,
                aggregator.context.total_active_balance
            ),
            millis = started.elapsed().as_millis() as u64,
            "aggregate",
        );
        engine.report.record(
            StageTiming::new(Stage::Aggregate, target_epoch, started, cost, artifact)
                .at_index(index)
                .with_proof(&aggregator.aggregate_proof),
        );
        Ok(())
    }

    /// Take a finished proof and do the next thing the epoch needs.
    ///
    /// This is the only place a proof result enters the epoch, and it runs on
    /// the loop, so the ordering the circuits require is the ordering of these
    /// arms: a group is held once it has landed, the backlog the trigger fired
    /// on top of is folded into the final witness once it has landed, and the
    /// final proof binds an aggregate that is already finished.
    ///
    /// A landed group is the one result this does not act on. Whether it is
    /// folded or given to the final proof depends on the trigger, which the tick
    /// has not evaluated yet, so the aggregator is handed back to
    /// [`Self::drive`] instead of costing an aggregate proof to find out.
    /// Returning `None` means the tick is over.
    async fn collect<A: BeaconApi + ChainStatusApi>(
        &mut self,
        engine: &mut Engine<A>,
        mut aggregator: StreamAggregator,
        pending: Pending,
        tick: &mut Tick,
    ) -> Result<Option<StreamAggregator>> {
        match pending {
            Pending::Group(group) => {
                let proved = group.range.end;
                let group = Self::finish_group(engine, &aggregator, group, tick).await?;
                aggregator.unfolded = Some((proved, group));
                return Ok(Some(aggregator));
            }
            Pending::Fold {
                index,
                proved,
                witness,
                proving,
            } => {
                Self::finish_fold(engine, &mut aggregator, index, proved, witness, proving).await?;
            }
            Pending::Late { group, fired } => {
                let group = Self::finish_group(engine, &aggregator, group, tick).await?;
                self.pending = Some(Self::start_final(engine, &aggregator, Some(group), fired)?);
            }
            Pending::Final {
                closing,
                witness,
                proving,
            } => {
                self.finish_final(engine, aggregator, closing, witness, proving, tick)
                    .await?;
                return Ok(None);
            }
        }
        self.aggregator = Some(aggregator);
        Ok(None)
    }

    /// Start the only proof on the critical path: the marginal attestation, the
    /// one final exponentiation, and the previous epoch's justification, at
    /// once.
    #[instrument(
        name = "stage",
        skip_all,
        fields(stage = "stream_final", epoch = aggregator.context.target_epoch),
    )]
    fn start_final<A: BeaconApi + ChainStatusApi>(
        engine: &mut Engine<A>,
        aggregator: &StreamAggregator,
        late: Option<GroupProof>,
        fired: Fired,
    ) -> Result<Pending> {
        let started = Instant::now();
        // The late group proof is the only thing the fire path does between the
        // trigger firing and here, so this is exactly its cost. Zero whenever
        // the plan's tail covers everything the aggregate does not, which is the
        // shape the schedule picks; a daemon that fell behind its own plan is
        // what puts a group here, and then this is the largest term in `T2 - T`.
        let late_group_millis = now_unix_millis().saturating_sub(fired.unix_millis);
        let target_epoch = aggregator.context.target_epoch;
        let tail: Vec<&SlotComplement> = aggregator.units[fired.tail.clone()].iter().collect();
        let tail_named = tail.iter().map(|u| u.named_indices.len()).sum();

        let (groups, group_proofs, group_millers) = match late {
            Some(g) => (vec![g.output], vec![g.proof], vec![g.miller]),
            None => (Vec::new(), Vec::new(), Vec::new()),
        };
        let closing = Closing {
            started,
            fired_unix_millis: fired.unix_millis,
            late_group_millis,
            late_groups: groups.len(),
            tail: tail.len(),
            tail_named,
        };
        if let Some(publish) = engine.report.publisher() {
            publish.threshold_fired(&publish::ThresholdFired {
                epoch: target_epoch,
                fired_unix_millis: closing.fired_unix_millis,
                blocked_millis: aggregator.blocked_millis,
                wait_millis: closing
                    .fired_unix_millis
                    .saturating_sub(aggregator.crossed_unix_millis.unwrap_or_default())
                    .saturating_sub(aggregator.blocked_millis),
                late_group_millis,
                tail: closing.tail,
                tail_named,
                late_groups: closing.late_groups,
            });
            publish.stage_started(Stage::StreamFinal, target_epoch, None, None);
        }

        let witness = Arc::new(streaming::final_witness(
            &aggregator.context,
            &engine.snapshot.tree,
            &aggregator.committees,
            aggregator.aggregate.clone(),
            aggregator.aggregate_proof.clone(),
            aggregator.aggregate_miller,
            groups,
            group_proofs,
            group_millers,
            &tail,
            aggregator.previous.clone(),
            aggregator.previous_proof.clone(),
            aggregator.boundary.clone(),
        ));
        let proving = Proving::spawn(started, engine.prover.clone(), {
            let witness = witness.clone();
            // `T2` is stamped here rather than where the loop collects this, so
            // that the number the project exists to minimise is the instant the
            // proof existed and not the instant a poll noticed.
            move |prover| {
                let (output, proof) = prover.prove_stream_final(&witness)?;
                Ok((output, proof, now_unix_millis()))
            }
        });
        Ok(Pending::Final {
            closing,
            witness,
            proving,
        })
    }

    /// Adopt the final proof: verify it, publish it, and move the epoch on.
    #[instrument(
        name = "stage",
        skip_all,
        fields(stage = "stream_final", epoch = aggregator.context.target_epoch),
    )]
    async fn finish_final<A: BeaconApi + ChainStatusApi>(
        &mut self,
        engine: &mut Engine<A>,
        aggregator: StreamAggregator,
        closing: Closing,
        witness: Arc<StreamFinalWitness>,
        proving: Proving<(StreamFinalOutput, Proof, u64)>,
        tick: &mut Tick,
    ) -> Result<()> {
        let Closing {
            started,
            fired_unix_millis,
            late_group_millis,
            late_groups,
            tail,
            tail_named,
        } = closing;
        let target_epoch = aggregator.context.target_epoch;
        let ((output, proof, proof_unix_millis), cost) = proving.take().await?;

        // Everything from here is after `T2`, so none of it can inflate the
        // latency this pipeline exists to minimise — including checking that
        // the proof it just made actually verifies, which is the only place
        // anyone has ever timed the verifier.
        crate::verify::timed(
            Stage::StreamFinal,
            &proof,
            &engine.prover.program_vk(Stage::StreamFinal),
            &output.public_bytes(),
        );

        let artifact = engine
            .sink
            .write_witness(target_epoch, "stream_final", &*witness)?;
        write_proof(&engine.sink, target_epoch, "stream_final", &proof)?;

        info!(
            justified_epoch = output.justified_epoch,
            finalized_epoch = output.finalized_epoch,
            finalized_root = %crate::artifacts::hex0x(&output.finalized_root),
            millis = started.elapsed().as_millis() as u64,
            "epoch closed",
        );
        // The witnesses exist to debug the epoch that produced them. Once its
        // proof is out, the proof is the artifact, and an unbounded output
        // directory ends a long run whenever the disk happens to fill.
        let (epochs, bytes) = engine.sink.prune_old_epochs();
        crate::metrics::observe_output(epochs, bytes);
        engine.report.record(
            StageTiming::new(Stage::StreamFinal, target_epoch, started, cost, artifact)
                .with_proof(&proof),
        );

        // A proof of a checkpoint the chain no longer has is worse than no proof
        // at all, so the root is re-resolved before anything is published. This
        // is after `T2` by construction — the proof exists — so it costs
        // publication latency and never a stale publication.
        if engine
            .chain
            .checkpoint_root(&engine.api, &engine.config, target_epoch)
            .await?
            != aggregator.context.target_root
        {
            warn!(
                target_epoch,
                "the checkpoint reorged out while the final proof ran; discarding it",
            );
            if let Some(publish) = engine.report.publisher() {
                publish.epoch_abandoned(target_epoch, "the checkpoint reorged out");
            }
            crate::metrics::epoch_abandoned("reorg");
            self.aggregator = None;
            return Ok(());
        }

        // `T` is the chain's, not the daemon's. The crossing slot is the last one
        // the final proof carried inline — the plan stops at the unit that
        // crosses — and its boundary is genesis plus a slot count, so the number
        // a consumer is quoted no longer depends on when this process happened
        // to be free to look. It did until 2026-08-19, and that made every
        // published figure a lower bound by however long the prover had been
        // holding the tick: a median 99 s over this epoch's run.
        //
        // `crossed_unix_millis` is kept beside it rather than discarded. It is
        // still the honest origin for the trigger's own wait, and the difference
        // between the two is the one term a change to `drive` could remove.
        let threshold = witness
            .tail
            .last()
            .map(|unit| target_epoch * engine.config.chain.slots_per_epoch + unit.slot_in_epoch)
            .and_then(|slot| Some((slot, engine.chain.slot_unix_millis(&engine.config, slot)?)));
        if let (Some((threshold_slot, threshold_unix_millis)), Some(observed_unix_millis)) =
            (threshold, aggregator.crossed_unix_millis)
        {
            // The window the trigger owned, and how much of it it never got to
            // hold: the prover's own backlog, clamped to the window so that the
            // five terms sum to `t2_minus_t_millis` whatever the wall clock did
            // between the stamps.
            let held_back = fired_unix_millis.saturating_sub(observed_unix_millis);
            let blocked_millis = aggregator.blocked_millis.min(held_back);
            let latency = EpochLatency {
                epoch: target_epoch,
                threshold_slot,
                threshold_unix_millis,
                observed_unix_millis,
                observation_millis: observed_unix_millis.saturating_sub(threshold_unix_millis),
                blocked_millis,
                fired_unix_millis,
                proof_unix_millis,
                t2_minus_t_millis: proof_unix_millis.saturating_sub(threshold_unix_millis),
                wait_millis: held_back - blocked_millis,
                late_group_millis,
                final_proof_millis: proof_unix_millis
                    .saturating_sub(fired_unix_millis + late_group_millis),
                tail_named,
                folded_groups: aggregator.folded_groups,
                late_groups,
                tail,
            };
            info!(
                t2_minus_t_millis = latency.t2_minus_t_millis,
                threshold_slot = latency.threshold_slot,
                observation_millis = latency.observation_millis,
                blocked_millis = latency.blocked_millis,
                wait_millis = latency.wait_millis,
                late_group_millis = latency.late_group_millis,
                final_proof_millis = latency.final_proof_millis,
                tail_named = latency.tail_named,
                folded_groups = latency.folded_groups,
                late_groups = latency.late_groups,
                "measured T2 - T",
            );
            engine.report.record_latency(latency);
        }

        let finalized = Checkpoint {
            epoch: output.finalized_epoch,
            root: output.finalized_root,
        };
        let cost = engine.report.take_cost(target_epoch);
        if let Some(publish) = engine.report.publisher() {
            let vk = engine.prover.program_vk(Stage::StreamFinal);
            let publics = output.public_bytes();
            let reference = publish::proof_ref(
                target_epoch,
                Stage::StreamFinal,
                &proof,
                &vk,
                &publics,
                engine.prover.program_digest(Stage::StreamFinal).as_deref(),
            );
            let inputs = publish::stream_final_public_inputs(&output);
            let latency = engine
                .report
                .latency(target_epoch)
                .map(serde_json::to_value)
                .transpose()?;
            publish.proof_bytes(target_epoch, Stage::StreamFinal, &proof, &vk, &publics);
            publish.proof_landed(
                target_epoch,
                reference.clone(),
                inputs.clone(),
                latency.clone(),
            );
            publish.epoch_closed(&ClosedEpoch {
                epoch: target_epoch,
                cost,
                target_root: crate::artifacts::hex0x(&aggregator.context.target_root),
                finalizes_epoch: output.finalized_epoch,
                justified: serde_json::json!({
                    "epoch": output.justified_epoch,
                    "root": crate::artifacts::hex0x(&output.justified_root),
                }),
                finalized: serde_json::to_value(CheckpointStatus::from(&finalized))?,
                accumulator: serde_json::to_value(acc_status(&engine.snapshot.state))?,
                latency,
                proof: reference,
                public_inputs: inputs,
            });
        }
        crate::metrics::epoch_justified();
        crate::metrics::epoch_finalized();
        engine.snapshot.state.justified_through = Some(target_epoch);
        engine.snapshot.state.attempted_epoch = Some(target_epoch);
        engine.snapshot.state.last_stream_final = Some(StreamFinalRecord { output, proof });
        engine.snapshot.state.finalized = Some(finalized.clone());
        self.aggregator = None;
        engine.store.save(&engine.snapshot)?;

        tick.justified = Some(target_epoch);
        tick.finalized = Some(finalized);
        Ok(())
    }

    /// Whether the epoch the cursor sits on can be streamed.
    ///
    /// A final proof turns the previous epoch's justification into a
    /// finalization and inherits the accumulator link from the diff that opened
    /// the epoch, so an epoch with neither — the first of a run — has to go
    /// through the batch path, and the one after it streams.
    pub(super) fn can_stream(state: &StoreState) -> bool {
        state.last_epoch_diff.is_some()
            && state.previous_justification(state.cursor_epoch).is_some()
    }

    /// Whether an epoch is part-built. The loop watches this to know whether it
    /// is on the trigger's clock or the poll's.
    pub(super) fn in_flight(&self) -> bool {
        self.aggregator.is_some()
    }

    /// Whether a proof this pipeline started is still running. The loop watches
    /// this so that [`super::Orchestrator::catch_up`] waits for work it asked
    /// for rather than returning half-done.
    pub(super) fn proving(&self) -> bool {
        self.pending.is_some()
    }

    /// The epoch in flight, as the manifest reports it.
    pub(super) fn current_epoch(&self, config: &OrchestratorConfig) -> Option<CurrentEpoch> {
        let aggregator = self.aggregator.as_ref()?;
        let total = aggregator.context.total_active_balance;
        Some(CurrentEpoch {
            epoch: aggregator.context.target_epoch,
            target_root: crate::artifacts::hex0x(&aggregator.context.target_root),
            opened_unix_millis: aggregator.opened_unix_millis,
            state: match aggregator.crossed_unix_millis {
                Some(_) => "firing",
                None => "collecting",
            },
            attesting_balance: aggregator.attesting_balance,
            total_active_balance: total,
            attesting_pct: percent_of(aggregator.attesting_balance, total),
            threshold_pct: config.stream_policy.threshold_pct(),
            folded_groups: aggregator.folded_groups,
            slots_held: aggregator.units.len(),
            finalizes_epoch: aggregator.previous.target_epoch(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a mainnet crossing slot looks like to the trigger on the tick it
    /// first sees it: three quarters covered by the unaggregated burst, and no
    /// aggregate published yet.
    const CROSSING_SLOT: (u64, usize, usize) = (15_030_741, 7_183, 0);

    fn mainnet() -> StreamPolicy {
        StreamPolicy {
            validators: 960_974.0,
            ..StreamPolicy::default()
        }
    }

    /// The first reading of a slot answers the half of the rule that is a stock
    /// and leaves the half that is a rate unanswered — which is what says the
    /// aggregates for this slot have not landed.
    #[test]
    fn the_first_reading_of_a_slot_is_a_reading() {
        let (interval_s, filling) = reading(None, CROSSING_SLOT, 0);

        assert_eq!(
            interval_s, 0.0,
            "no interval was observed, so none is priced"
        );
        assert_eq!(filling.removed, 0);
        assert_eq!(filling.in_flight, 7_183);
        assert_eq!(filling.aggregates, 0, "no aggregate has been seen for it");
        assert!(
            !mainnet().interval_paid(filling.removed, interval_s),
            "and the rate half stays unanswered rather than being guessed at",
        );
    }

    /// A second reading of the same slot prices what the interval between them
    /// removed, exactly as it always did.
    #[test]
    fn a_second_reading_prices_what_the_interval_removed() {
        let (interval_s, filling) = reading(Some((0.2, 7_183, 0)), (15_030_741, 583, 4), 0);

        assert_eq!(interval_s, 0.2);
        assert_eq!(filling.removed, 6_600, "the aggregate wave landed");
        assert_eq!(filling.new_aggregates, 4);
        assert!(mainnet().interval_paid(filling.removed, interval_s));
    }

    /// The whole point: on its first sight of the crossing slot the trigger
    /// waits, and it waits because that slot's aggregates have not landed.
    #[test]
    fn the_trigger_waits_for_the_aggregates_of_a_slot_it_has_just_seen() {
        let policy = mainnet();
        let (interval_s, filling) = reading(None, CROSSING_SLOT, 0);

        assert!(
            policy.worth_waiting(filling, interval_s, 0.0, 0.02),
            "7,183 leaves in flight and no aggregate is the case this rule is for",
        );
        assert!(
            policy.wait_budget_s(filling.in_flight) > 4.0,
            "and they are worth over four seconds of it",
        );
    }

    /// A slot whose tail has stopped moving is fired on within a tick or two,
    /// because the silence is priced against what is *left* rather than against
    /// what the wait set out to win.
    ///
    /// It is not fired on because its aggregate count stopped moving. That
    /// reading is what mainnet 469720 and 469721 fired on with 9,961 and 2,432
    /// leaves in flight; the wave comes from up to 64 subnet aggregators and a
    /// quiet 200 ms tick inside it is ordinary. See
    /// [`StreamPolicy::worth_waiting`].
    #[test]
    fn a_slot_whose_tail_has_stopped_moving_is_fired_on() {
        let policy = mainnet();
        let (interval_s, filling) = reading(Some((0.2, 583, 4)), (15_030_741, 583, 4), 6_600);

        // 583 leaves are worth 0.42 s, so two quiet ticks are still inside it
        // and three are not.
        assert!(policy.worth_waiting(filling, interval_s, 0.4, 2.3));
        assert!(!policy.worth_waiting(filling, interval_s, 0.6, 2.5));

        // And the wait as a whole is still bounded by the 7,183 it began on,
        // which is what stops the remainder cutting off a wave mid-delivery.
        assert!(policy.wait_budget_s(filling.in_flight + filling.taken) > 4.0);
    }

    /// The budget is the trigger's own, so a prover that was still working when
    /// the chain crossed does not spend it.
    #[test]
    fn the_provers_backlog_does_not_spend_the_triggers_budget() {
        let crossed = Some(1_000_000u64);

        // Epoch 469710: 2,977 ms between the crossing and the fire, of which
        // 2,956 was a group proof the crossing landed in the middle of.
        assert_eq!(held_for_s(crossed, 2_956, 1_002_977), 0.021);
        assert_eq!(
            held_for_s(crossed, 0, 1_002_977),
            2.977,
            "and with nothing in flight it is the whole interval, as before",
        );
        assert_eq!(held_for_s(None, 0, 1_002_977), 0.0);
    }
}
