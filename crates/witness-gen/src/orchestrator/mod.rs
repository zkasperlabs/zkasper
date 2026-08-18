//! Continuous mode: follow the chain and keep the proof pipeline fed.
//!
//! # The shape of the loop
//!
//! The accumulator is a chain, and a slot proof binds the accumulator
//! commitment it was built against, so the two cannot be reordered: epoch E's
//! justification has to be finished while the accumulator still sits on E. That
//! gives a two-state machine per epoch, which is also exactly what resumption
//! needs, because both states are recorded on disk:
//!
//! ```text
//!   accumulator at E, epoch E not attempted   ->  stream slot proofs, justify
//!   accumulator at E, epoch E attempted       ->  epoch diff E -> E+1
//! ```
//!
//! # Streaming
//!
//! BENCHMARKS.md argues for proving slot groups as attestations arrive and
//! firing the aggregation the moment the 2/3 threshold crosses — around slot 22
//! of a mainnet epoch — rather than waiting for the epoch to end. Both
//! aggregators here are written that way: they hold the running dedup set and
//! attesting balance across ticks, consume whatever the node has published so
//! far, and stop the instant the threshold is crossed. Slots past that point are
//! never proven.
//!
//! # The streaming pipeline reads gossip, not blocks
//!
//! An attestation is gossiped in the slot it is made and included in a block one
//! or more slots later, so [`Pipeline::Batch`]'s block walk is a slot behind the
//! chain by construction. [`Pipeline::Streaming`] follows
//! [`crate::gossip`] instead and keeps the block walk for what it is good for:
//! filling the gap after a stream outage, and being the whole source in the
//! fixture-replay tests.
//!
//! That moves the trigger from a slot boundary to an instant, which is what
//! makes *when* to fire a decision rather than a consequence. A slot still
//! filling is priced as if it closed now — its missing members are absentees —
//! so the weight is honest at every instant and what waiting buys is a cheaper
//! proof. [`StreamAggregator::worth_waiting`] takes that trade, one trigger
//! interval at a time.
//!
//! [`Pipeline`] picks what happens to the slots. [`Pipeline::Batch`] proves one
//! slot proof each and folds them into a justification once the epoch is over,
//! which is three proofs deep and simple. [`Pipeline::Streaming`] proves a group
//! per tick, folds each into a running aggregate as it finishes, and collapses
//! justification, finalization and the epoch's one final exponentiation into a
//! single proof over the attestation that crossed the threshold — see
//! [`crate::streaming`]. Only the latter puts one proof on `T2 - T`, and the
//! manifest publishes the measured value.
//!
//! An epoch can only be streamed if the epoch before it left a justification and
//! an epoch diff behind, so the first epoch after a bootstrap always goes through
//! the batch path and the streaming run picks up from the next one.
//!
//! What is not here yet is parallelism: groups are proved one at a time, in
//! order, on the calling task. The aggregators do not depend on that — they take
//! outputs and proofs and do not care which order they were produced in — so
//! handing the prover to a pool of GPUs is a change to this file only.

mod accumulator;
mod chain_view;
mod config;
mod engine;
mod pipeline;
mod reporter;

pub use config::OrchestratorConfig;
pub use pipeline::Pipeline;

use std::ops::Range;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use tracing::{info, info_span, instrument, warn};

use zkasper_common::acc::Digest;
use zkasper_common::bls::{fp12_mul, Fp12, FP12_ONE};
use zkasper_common::types::{
    AggregateOutput, BoundaryAnchor, Checkpoint, CommitteeOutput, FinalizationWitness,
    GroupProofOutput, PreviousJustification, SlotProofOutput, SlotProofWitness,
};

use crate::acc_tree::AccTree;
use crate::artifacts::{
    hex_digest, now_unix_millis, ArtifactSink, CheckpointStatus, CurrentEpoch, EpochLatency,
    StageTiming,
};
use crate::attestation_collector::{SlotComplement, SlotStream};
use crate::beacon_api::{BeaconApi, ChainStatusApi, ValidatorResponse};
use crate::committee::EpochCommittees;
use crate::epoch_state::EpochState;
use crate::gossip::{AttestationSource, EventStreamSource};
use crate::prover::{Proof, Prover, Stage};
use crate::publish::{self, ClosedEpoch, EpochProgress, Publisher};
use crate::store::{JustificationRecord, Snapshot, Store, StoreState, StreamFinalRecord};

use crate::streaming::{self, Filling, StreamContext, StreamPolicy};
use crate::witness_justification;
use accumulator::{bootstrap, is_pruned_state};
use chain_view::ChainView;
use engine::{write_proof, Engine};
use reporter::{acc_status, justified_checkpoint, percent_of, Reporter};

/// How many stage timings the manifest keeps.
const RECENT_STAGES: usize = 64;

/// How far behind the head an epoch may be and still be called live, in epochs.
///
/// Two, because the daemon keeps looking for a checkpoint's attestations for
/// `attestation_lookahead_epochs` past it. Anything older is a catch-up.
const LIVE_EPOCHS: f64 = 2.0;

/// How many epochs' measured `T2 - T` the manifest keeps.
const RECENT_LATENCIES: usize = 16;
/// What one tick did. Returned so callers — and tests — can see the pipeline
/// move without reading the log.
#[derive(Clone, Debug, Default)]
pub struct Tick {
    pub head_slot: u64,
    pub advanced_to: Option<u64>,
    pub slots_proved: Vec<u64>,
    pub justified: Option<u64>,
    pub finalized: Option<Checkpoint>,
    /// Epoch abandoned because the chain never justified it.
    pub gave_up_on: Option<u64>,
}

impl Tick {
    pub fn made_progress(&self) -> bool {
        self.advanced_to.is_some()
            || !self.slots_proved.is_empty()
            || self.justified.is_some()
            || self.gave_up_on.is_some()
    }
}

/// One epoch's justification, part-built.
///
/// Lives across ticks: slots are folded in as the node publishes them, and the
/// epoch finishes the moment the counted balance crosses 2/3.
struct EpochAggregator {
    target_epoch: u64,
    target_root: [u8; 32],
    signing_domain: [u8; 32],
    /// Accumulator the slot proofs are bound to, captured when the epoch opened.
    acc_root: Digest,
    acc_commitment: Digest,
    total_active_balance: u64,
    /// This epoch's committee proof, which every slot proof counts against.
    committees: Arc<EpochCommittees>,
    committee_output: CommitteeOutput,
    committee_proof: Proof,
    stream: SlotStream,
    /// Next slot to ask the node for.
    next_slot: u64,
    /// One past the last slot worth scanning for this checkpoint.
    scan_end: u64,
    attesting_balance: u64,
    slot_outputs: Vec<SlotProofOutput>,
    slot_proofs: Vec<Proof>,
}

impl EpochAggregator {
    /// Casper's 2/3 rule, in u128 so a mainnet-sized balance cannot overflow.
    fn threshold_reached(&self) -> bool {
        self.attesting_balance as u128 * 3 >= self.total_active_balance as u128 * 2
    }

    fn exhausted(&self) -> bool {
        self.next_slot >= self.scan_end
    }
}

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
    /// The epoch this one finalizes, captured when the epoch opened so that
    /// neither it nor the boundary below is opened on the critical path.
    previous: PreviousJustification,
    previous_proof: Proof,
    boundary: BoundaryAnchor,
    opened_unix_millis: u64,
    /// Unix ms at which the daemon held enough attestations to justify — `T`.
    crossed_unix_millis: Option<u64>,
}

/// A finished group proof, waiting to be folded or handed to the final proof.
struct GroupProof {
    output: GroupProofOutput,
    miller: Fp12,
    proof: Proof,
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

    /// Index of the unit that carries the epoch over the scheduling threshold.
    ///
    /// Goes through [`streaming::plan`] rather than recomputing the crossing, so
    /// the daemon and the schedule the tests pin can never disagree on where an
    /// epoch ends.
    fn crossing(&self, policy: &StreamPolicy) -> Option<usize> {
        let plan = streaming::plan(&self.units, self.context.total_active_balance, policy);
        plan.threshold_reached
            .then(|| plan.groups.concat().into_iter().chain(plan.tail).max())
            .flatten()
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
    /// No reading to compare against — nothing still filling, or a different
    /// slot than last time — means fire. There is nothing in flight to wait for,
    /// and a daemon that opened an epoch already past the threshold must not
    /// invent a wait it never observed.
    fn worth_waiting(
        &mut self,
        policy: &StreamPolicy,
        filling: Option<(u64, usize, usize)>,
    ) -> bool {
        let (Some((at, was, named, aggregates)), Some((slot, now_named, now_aggregates))) =
            (self.last_filling, filling)
        else {
            self.stalled_s = 0.0;
            return false;
        };
        if was != slot {
            self.stalled_s = 0.0;
            return false;
        }
        let interval_s = at.elapsed().as_secs_f64();
        let filling = Filling {
            in_flight: now_named,
            removed: named.saturating_sub(now_named),
            aggregates: now_aggregates,
            new_aggregates: now_aggregates.saturating_sub(aggregates),
        };
        self.stalled_s = if policy.interval_paid(filling.removed, interval_s) {
            0.0
        } else {
            self.stalled_s + interval_s
        };
        policy.worth_waiting(filling, interval_s, self.stalled_s, self.waited_s())
    }

    /// Seconds since `T`, which is what the cap on waiting is measured against.
    fn waited_s(&self) -> f64 {
        self.crossed_unix_millis
            .map_or(0.0, |t| now_unix_millis().saturating_sub(t) as f64 / 1000.0)
    }
}

pub struct Orchestrator<A> {
    /// The node, the prover, the accumulator, and where results go — the half
    /// of the daemon that does not care which pipeline is running.
    engine: Engine<A>,
    pending: Option<EpochAggregator>,
    streaming: Option<StreamAggregator>,
}

impl<A: BeaconApi + ChainStatusApi> Orchestrator<A> {
    /// Resume from the persisted accumulator, or bootstrap if there is none.
    pub async fn open(api: A, config: OrchestratorConfig, prover: Box<dyn Prover>) -> Result<Self> {
        Self::open_with_publisher(api, config, prover, None).await
    }

    /// The same, mirroring every stage to the public API as it happens.
    pub async fn open_with_publisher(
        api: A,
        config: OrchestratorConfig,
        prover: Box<dyn Prover>,
        publish: Option<Arc<Publisher>>,
    ) -> Result<Self> {
        let store = Store::new(&config.db_path);
        let sink = ArtifactSink::new(&config.output_dir)?;

        let mut this = match store.load()? {
            Some(snapshot) => {
                if snapshot.state.chain != config.chain_name {
                    bail!(
                        "store at {} holds a {} accumulator, but this run is configured for {}",
                        config.db_path.display(),
                        snapshot.state.chain,
                        config.chain_name,
                    );
                }
                info!(
                    epoch = snapshot.state.cursor_epoch,
                    chain_digest = %hex_digest(&snapshot.state.acc_chain_digest),
                    "resuming",
                );
                Self::assemble(api, config, store, sink, prover, snapshot, publish)
            }
            None => {
                let (snapshot, timing) =
                    bootstrap(&api, &config, &sink, &*prover, publish.as_ref()).await?;
                let mut this = Self::assemble(api, config, store, sink, prover, snapshot, publish);
                this.engine.report.record(timing);
                this.engine.store.save(&this.engine.snapshot)?;
                this
            }
        };

        this.engine
            .chain
            .refresh(&this.engine.api, &this.engine.config)
            .await?;
        this.publish_status()?;
        Ok(this)
    }

    fn assemble(
        api: A,
        config: OrchestratorConfig,
        store: Store,
        sink: ArtifactSink,
        prover: Box<dyn Prover>,
        snapshot: Snapshot,
        publish: Option<Arc<Publisher>>,
    ) -> Self {
        Self {
            engine: Engine {
                chain: ChainView::new(&config),
                report: Reporter::new(&config, publish),
                gossip: config.gossip_url.as_deref().map(|url| {
                    Box::new(EventStreamSource::connect(url)) as Box<dyn AttestationSource>
                }),
                api,
                config,
                store,
                sink,
                prover,
                snapshot,
            },
            pending: None,
            streaming: None,
        }
    }

    /// Follow attestations from `source` instead of the node's event stream.
    ///
    /// The daemon only ever asks a source for whatever arrived since last time,
    /// so this is where a forked node, an in-process feed or a test's own
    /// arrival schedule goes in.
    pub fn with_gossip(mut self, source: Box<dyn AttestationSource>) -> Self {
        self.engine.gossip = Some(source);
        self
    }

    pub fn state(&self) -> &StoreState {
        &self.engine.snapshot.state
    }

    pub fn tree(&self) -> &AccTree {
        &self.engine.snapshot.tree
    }

    // -----------------------------------------------------------------
    // Driving
    // -----------------------------------------------------------------

    /// Follow the chain until stopped.
    ///
    /// A streaming epoch in flight is re-evaluated on the trigger's clock rather
    /// than the poll's: the whole point is to fire the instant enough has
    /// arrived, and a four-second poll would round that off to four seconds.
    pub async fn run(&mut self) -> Result<()> {
        loop {
            self.catch_up().await?;
            tokio::time::sleep(match self.streaming {
                Some(_) => self.engine.config.trigger_interval,
                None => self.engine.config.poll_interval,
            })
            .await;
        }
    }

    /// Do everything the node's current head makes possible, then return.
    pub async fn catch_up(&mut self) -> Result<Vec<Tick>> {
        let mut ticks = Vec::new();
        loop {
            let tick = self.tick().await?;
            let progressed = tick.made_progress();
            ticks.push(tick);
            if !progressed {
                return Ok(ticks);
            }
        }
    }

    /// One unit of work: justify the epoch the accumulator sits on, or move the
    /// accumulator to the next one.
    ///
    /// A tick that failed because the node has thrown the state away is not an
    /// error the caller can do anything with, so it is handled here: see
    /// [`is_pruned_state`].
    pub async fn tick(&mut self) -> Result<Tick> {
        match self.tick_once().await {
            Err(e) if is_pruned_state(&e) => {
                warn!(
                    epoch = self.engine.snapshot.state.cursor_epoch,
                    error = %format!("{e:#}"),
                    "the node no longer serves the state this epoch needs; \
                     bootstrapping forward to one it does",
                );
                self.engine.rebootstrap().await?;
                self.forget_epoch();
                Ok(Tick {
                    head_slot: self.engine.chain.head_slot(),
                    advanced_to: Some(self.engine.snapshot.state.cursor_epoch),
                    ..Tick::default()
                })
            }
            other => other,
        }
    }

    /// Drop whatever epoch is part-built.
    ///
    /// Every proof inside one is bound to the accumulator commitment the epoch
    /// opened against, so an accumulator that moves — forward by a diff, or
    /// sideways by a bootstrap — invalidates all of it.
    fn forget_epoch(&mut self) {
        self.pending = None;
        self.streaming = None;
    }

    async fn tick_once(&mut self) -> Result<Tick> {
        self.engine
            .chain
            .refresh(&self.engine.api, &self.engine.config)
            .await?;

        let mut tick = Tick {
            head_slot: self.engine.chain.head_slot(),
            ..Tick::default()
        };

        if self.engine.snapshot.state.needs_justification() {
            if self.engine.config.pipeline == Pipeline::Streaming && self.can_stream() {
                self.drive_stream(&mut tick).await?;
            } else {
                self.drive_aggregation(&mut tick).await?;
            }
        } else {
            let next = self.engine.snapshot.state.cursor_epoch + 1;
            if next <= self.engine.chain.head_slot() / self.engine.config.chain.slots_per_epoch {
                self.engine.advance_accumulator(next).await?;
                self.forget_epoch();
                tick.advanced_to = Some(next);
            }
        }

        self.publish_status()?;
        Ok(tick)
    }

    // -----------------------------------------------------------------
    // Stages: slot proofs, justification, finalization
    // -----------------------------------------------------------------

    async fn drive_aggregation(&mut self, tick: &mut Tick) -> Result<()> {
        let target_epoch = self.engine.snapshot.state.cursor_epoch;
        let spe = self.engine.config.chain.slots_per_epoch;

        let mut aggregator = match self.pending.take() {
            Some(aggregator) if aggregator.target_epoch == target_epoch => aggregator,
            _ => self.open_epoch(target_epoch).await?,
        };

        let _span = info_span!("aggregate", target_epoch).entered();

        while !aggregator.threshold_reached()
            && !aggregator.exhausted()
            && aggregator.next_slot <= self.engine.chain.head_slot()
        {
            let slot = aggregator.next_slot;
            aggregator.next_slot += 1;

            // A slot with no block is not an error; neither is one whose
            // attestations all point somewhere else.
            if let Ok(attestations) = self
                .engine
                .api
                .get_block_attestations(&slot.to_string())
                .await
            {
                aggregator.stream.ingest(&attestations)?;
            }

            // Attestations for slot `s` are included from block `s+1` onwards,
            // so closing `s` once `s+1` has been scanned keeps the schedule one
            // slot behind the chain. A straggler included later becomes an
            // absentee, which costs a little weight and no soundness.
            let Some(attestation_slot) = slot.checked_sub(1) else {
                continue;
            };
            if attestation_slot < target_epoch * spe || attestation_slot >= (target_epoch + 1) * spe
            {
                continue;
            }
            let Some(complement) = aggregator.stream.close(attestation_slot) else {
                continue;
            };

            let _span = info_span!(
                "stage",
                stage = "slot_proof",
                epoch = target_epoch,
                slot = attestation_slot,
            )
            .entered();
            self.engine.chain.observe_start_delay(
                &self.engine.config,
                Stage::SlotProof,
                target_epoch,
                attestation_slot,
            );
            let started = Instant::now();
            // Numbered as well as slotted. A slot proof is a repeat of a stage
            // inside one epoch, and a consumer that keys stages by
            // (epoch, stage, index) folds every unnumbered repeat onto one row —
            // which lost 21 of an epoch's 22 slot proofs, and with them most of
            // what the epoch cost.
            let index = aggregator.slot_proofs.len();
            self.engine.report.begin(
                Stage::SlotProof,
                target_epoch,
                Some(attestation_slot),
                Some(index),
            );
            let witness = SlotProofWitness {
                accumulator_commitment: aggregator.acc_commitment,
                committee_root: aggregator.committee_output.committee_root,
                target_epoch,
                target_root: aggregator.target_root,
                signing_domain: aggregator.signing_domain,
                acc_root: aggregator.acc_root,
                total_active_balance: aggregator.total_active_balance,
                acc_multi_proof: self
                    .engine
                    .snapshot
                    .tree
                    .build_multi_proof(&complement.named_indices),
                committee_multi_proof: aggregator
                    .committees
                    .multi_proof(&[complement.witness.slot_in_epoch]),
                slots: vec![complement.witness],
            };

            let (output, proof) =
                self.engine.prover.prove_slot(&witness).with_context(|| {
                    format!("slot proof for attestation slot {attestation_slot}")
                })?;

            let artifact = self.engine.sink.write_witness(
                target_epoch,
                &format!("slot_proof_{attestation_slot}"),
                &witness,
            )?;
            write_proof(
                &self.engine.sink,
                target_epoch,
                &format!("slot_proof_{attestation_slot}"),
                &proof,
            )?;

            aggregator.attesting_balance += output.attesting_balance;
            aggregator.slot_outputs.push(output);
            aggregator.slot_proofs.push(proof);

            let millis = started.elapsed().as_millis() as u64;
            info!(
                slot = attestation_slot,
                absentees = witness.slots[0].absentees.len(),
                attesting_balance = aggregator.attesting_balance,
                pct = percent_of(
                    aggregator.attesting_balance,
                    aggregator.total_active_balance
                ),
                millis,
                "slot proof",
            );
            self.engine.report.record(
                StageTiming::new(
                    Stage::SlotProof,
                    target_epoch,
                    started,
                    self.engine.prover.last_cost(),
                    artifact,
                )
                .at_slot(attestation_slot)
                .at_index(index)
                .with_proof(aggregator.slot_proofs.last().expect("just pushed")),
            );
            tick.slots_proved.push(attestation_slot);
        }

        if aggregator.threshold_reached() {
            self.close_epoch(aggregator, tick).await?;
        } else if aggregator.exhausted() {
            // Two epochs of blocks went by without 2/3 voting for this
            // checkpoint. The chain did not justify it, so neither can we.
            warn!(
                target_epoch,
                attesting_balance = aggregator.attesting_balance,
                total_active_balance = aggregator.total_active_balance,
                "checkpoint never reached the 2/3 threshold; giving up on this epoch",
            );
            if let Some(publish) = self.engine.report.publisher() {
                publish.epoch_abandoned(target_epoch, "never reached the threshold");
            }
            crate::metrics::epoch_abandoned("threshold");
            self.pending = None;
            self.engine.snapshot.state.attempted_epoch = Some(target_epoch);
            self.engine.store.save(&self.engine.snapshot)?;
            tick.gave_up_on = Some(target_epoch);
        } else {
            // Waiting for the node to publish more blocks. Keep the partial
            // aggregation so the next tick resumes mid-epoch.
            self.pending = Some(aggregator);
        }
        Ok(())
    }

    /// Start a new epoch's aggregation against the accumulator as it stands.
    async fn open_epoch(&mut self, target_epoch: u64) -> Result<EpochAggregator> {
        let spe = self.engine.config.chain.slots_per_epoch;
        let target_root = self
            .engine
            .chain
            .checkpoint_root(&self.engine.api, &self.engine.config, target_epoch)
            .await?;
        let signing_domain = self
            .engine
            .chain
            .signing_domain(&self.engine.api, &self.engine.config, target_epoch)
            .await?;
        let validators = self
            .engine
            .api
            .get_validators(&(target_epoch * spe).to_string())
            .await
            .context("fetch validators for the target epoch")?;

        let (committees, committee_output, committee_proof) =
            self.prove_committee(target_epoch, &validators).await?;

        let stream = SlotStream::new(
            &self.engine.config.chain,
            committees.clone(),
            target_epoch,
            target_root,
        );

        if let Some(publish) = self.engine.report.publisher() {
            publish.epoch_opened(
                target_epoch,
                &target_root,
                target_epoch.saturating_sub(1),
                self.engine.snapshot.state.total_active_balance,
                serde_json::to_value(acc_status(&self.engine.snapshot.state))?,
            );
        }
        info!(
            target_epoch,
            target_root = %crate::artifacts::hex0x(&target_root),
            committee_root = %hex_digest(&committee_output.committee_root),
            "opened epoch",
        );

        Ok(EpochAggregator {
            target_epoch,
            target_root,
            signing_domain,
            acc_root: self.engine.snapshot.state.acc_root,
            acc_commitment: self.engine.snapshot.state.acc_commitment,
            total_active_balance: self.engine.snapshot.state.total_active_balance,
            committees,
            committee_output,
            committee_proof,
            stream,
            next_slot: target_epoch * spe,
            scan_end: (target_epoch + self.engine.config.attestation_lookahead_epochs) * spe,
            attesting_balance: 0,
            slot_outputs: Vec::new(),
            slot_proofs: Vec::new(),
        })
    }

    /// Prove the epoch's committees, and time it like every other stage.
    #[instrument(
        name = "stage",
        skip_all,
        fields(stage = "committee", epoch = target_epoch),
    )]
    async fn prove_committee(
        &mut self,
        target_epoch: u64,
        validators: &[ValidatorResponse],
    ) -> Result<(Arc<EpochCommittees>, CommitteeOutput, Proof)> {
        // The schedule wants this finished before the epoch it serves opens, so
        // the epoch's own first slot is the latest it should ever start.
        self.engine.chain.observe_start_delay(
            &self.engine.config,
            Stage::Committee,
            target_epoch,
            target_epoch * self.engine.config.chain.slots_per_epoch,
        );
        let started = Instant::now();
        self.engine
            .report
            .begin(Stage::Committee, target_epoch, None, None);
        let committees = Arc::new(self.build_committees(target_epoch, validators).await?);
        let (output, proof) = self.engine.prover.prove_committee(&committees.witness)?;
        if output != committees.output {
            bail!(
                "committee circuit disagrees with the host committee tree at epoch {target_epoch}"
            );
        }
        let artifact =
            self.engine
                .sink
                .write_witness(target_epoch, "committee", &committees.witness)?;
        write_proof(&self.engine.sink, target_epoch, "committee", &proof)?;
        self.engine.report.record(
            StageTiming::new(
                Stage::Committee,
                target_epoch,
                started,
                self.engine.prover.last_cost(),
                artifact,
            )
            .with_proof(&proof),
        );
        Ok((committees, output, proof))
    }

    /// Sum this epoch's committees out of the accumulator.
    ///
    /// The shuffle that produced them is the node's; nothing here or in the
    /// circuit recomputes it, because a wrong assignment cannot be proven
    /// against the signatures it would have to match. See
    /// [`zkasper_common::committee`].
    async fn build_committees(
        &self,
        target_epoch: u64,
        validators: &[ValidatorResponse],
    ) -> Result<EpochCommittees> {
        let spe = self.engine.config.chain.slots_per_epoch;
        let committees = self
            .engine
            .api
            .get_committees(&(target_epoch * spe).to_string(), target_epoch)
            .await
            .context("fetch committees")?;

        crate::committee::build(
            &committees,
            validators,
            &self.engine.snapshot.tree,
            &self.engine.config.chain,
            target_epoch,
            target_epoch,
            self.engine.snapshot.state.total_active_balance,
        )
    }

    /// Fold the epoch's slot proofs into a justification, and pair it with the
    /// previous one into a finalization when the two are consecutive.
    #[instrument(
        name = "stage",
        skip_all,
        fields(stage = "justification", epoch = aggregator.target_epoch),
    )]
    async fn close_epoch(&mut self, aggregator: EpochAggregator, tick: &mut Tick) -> Result<()> {
        let target_epoch = aggregator.target_epoch;
        let started = Instant::now();
        self.engine
            .report
            .begin(Stage::Justification, target_epoch, None, None);

        let witness = witness_justification::build(
            aggregator.slot_outputs,
            aggregator.slot_proofs,
            aggregator.acc_commitment,
            self.engine.prover.program_vk(Stage::SlotProof),
            self.engine.prover.program_vk(Stage::Committee),
            aggregator.committee_output,
            aggregator.committee_proof,
            target_epoch,
            aggregator.target_root,
            aggregator.total_active_balance,
            aggregator.acc_root,
        );

        let slots = witness.slot_proof_outputs.len();
        let (output, proof) = self.engine.prover.prove_justification(&witness)?;
        let artifact = self
            .engine
            .sink
            .write_witness(target_epoch, "justification", &witness)?;
        write_proof(&self.engine.sink, target_epoch, "justification", &proof)?;

        let millis = started.elapsed().as_millis() as u64;
        info!(
            target_epoch,
            slots,
            attesting_balance = aggregator.attesting_balance,
            millis,
            "justified",
        );
        self.engine.report.record(
            StageTiming::new(
                Stage::Justification,
                target_epoch,
                started,
                self.engine.prover.last_cost(),
                artifact,
            )
            .with_proof(&proof),
        );

        let record = JustificationRecord {
            output: output.clone(),
            proof,
        };
        let finalized = self.try_finalize(&record).await?;

        // The first epoch of a run has nothing before it to finalize, so its
        // justification is the only proof it will ever have. Publishing it as
        // the epoch's proof is what keeps that epoch from sitting open forever.
        if finalized.is_none() {
            let cost = self.engine.report.take_cost(target_epoch);
            if let Some(publish) = self.engine.report.publisher() {
                let vk = self.engine.prover.program_vk(Stage::Justification);
                let publics = record.output.public_bytes();
                let reference = publish::proof_ref(
                    target_epoch,
                    Stage::Justification,
                    &record.proof,
                    &vk,
                    &publics,
                    self.engine
                        .prover
                        .program_digest(Stage::Justification)
                        .as_deref(),
                );
                let inputs = publish::justification_public_inputs(&record.output);
                publish.proof_bytes(
                    target_epoch,
                    Stage::Justification,
                    &record.proof,
                    &vk,
                    &publics,
                );
                publish.proof_landed(target_epoch, reference.clone(), inputs.clone(), None);
                publish.epoch_closed(&ClosedEpoch {
                    epoch: target_epoch,
                    cost,
                    target_root: crate::artifacts::hex0x(&record.output.target_root),
                    finalizes_epoch: target_epoch,
                    justified: serde_json::to_value(justified_checkpoint(&record.output))?,
                    finalized: serde_json::Value::Null,
                    accumulator: serde_json::to_value(acc_status(&self.engine.snapshot.state))?,
                    latency: None,
                    proof: reference,
                    public_inputs: inputs,
                });
            }
        }

        crate::metrics::epoch_justified();
        self.engine.snapshot.state.justified_through = Some(target_epoch);
        self.engine.snapshot.state.attempted_epoch = Some(target_epoch);
        self.engine.snapshot.state.last_justification = Some(record);
        if let Some(checkpoint) = &finalized {
            self.engine.snapshot.state.finalized = Some(checkpoint.clone());
        }
        self.engine.store.save(&self.engine.snapshot)?;

        tick.justified = Some(target_epoch);
        tick.finalized = finalized;
        Ok(())
    }

    /// Pair the new justification with the previous epoch's, if they can be.
    ///
    /// The two are proved against two different accumulators — effective
    /// balances move at every epoch transition — so the circuit also needs the
    /// epoch diff that carries one to the other. That is the diff this daemon
    /// ran between the two justifications, kept in the store for exactly this.
    async fn try_finalize(&mut self, current: &JustificationRecord) -> Result<Option<Checkpoint>> {
        let Some(previous) = self.engine.snapshot.state.last_justification.clone() else {
            return Ok(None);
        };
        let epoch = previous.output.target_epoch;
        if epoch + 1 != current.output.target_epoch {
            return Ok(None);
        }
        let Some(epoch_diff) = self.engine.snapshot.state.last_epoch_diff.clone() else {
            warn!(
                epoch,
                "no epoch diff on record to link the two accumulators"
            );
            return Ok(None);
        };
        if epoch_diff.output.epoch_1 != epoch
            || epoch_diff.output.epoch_2 != current.output.target_epoch
            || epoch_diff.output.prev_accumulator_commitment
                != previous.output.accumulator_commitment
            || epoch_diff.output.accumulator_commitment != current.output.accumulator_commitment
        {
            warn!(
                epoch,
                diff_epoch_1 = epoch_diff.output.epoch_1,
                diff_epoch_2 = epoch_diff.output.epoch_2,
                "the epoch diff on record does not link the two justified accumulators",
            );
            return Ok(None);
        }

        let boundary = crate::boundary::build(
            &self.engine.api,
            &self.engine.config.chain,
            &current.output.target_root,
            epoch,
            &previous.output.target_root,
            &epoch_diff.output.state_root_1,
            &self.engine.snapshot.epoch_state,
        )
        .await
        .with_context(|| format!("open the boundary of epoch {epoch}"))?;

        let _span = info_span!(
            "stage",
            stage = "finalization",
            epoch = current.output.target_epoch,
        )
        .entered();
        let started = Instant::now();
        self.engine
            .report
            .begin(Stage::Finalization, current.output.target_epoch, None, None);
        let witness = FinalizationWitness {
            justification_program_vk: self.engine.prover.program_vk(Stage::Justification),
            epoch_diff_program_vk: self.engine.prover.program_vk(Stage::EpochDiff),
            boundary,
            justification_outputs: vec![previous.output.clone(), current.output.clone()],
            justification_proofs: vec![previous.proof.clone(), current.proof.clone()],
            epoch_diff_output: epoch_diff.output,
            epoch_diff_proof: epoch_diff.proof,
        };

        let (output, proof) = self.engine.prover.prove_finalization(&witness)?;
        let artifact = self.engine.sink.write_witness(
            current.output.target_epoch,
            "finalization",
            &witness,
        )?;
        write_proof(
            &self.engine.sink,
            current.output.target_epoch,
            "finalization",
            &proof,
        )?;

        let millis = started.elapsed().as_millis() as u64;
        info!(
            finalized_epoch = output.finalized_epoch,
            finalized_root = %crate::artifacts::hex0x(&output.finalized_root),
            millis,
            "finalized",
        );
        self.engine.report.record(
            StageTiming::new(
                Stage::Finalization,
                current.output.target_epoch,
                started,
                self.engine.prover.last_cost(),
                artifact,
            )
            .with_proof(&proof),
        );

        let cost = self.engine.report.take_cost(current.output.target_epoch);
        if let Some(publish) = self.engine.report.publisher() {
            let epoch = current.output.target_epoch;
            let vk = self.engine.prover.program_vk(Stage::Finalization);
            let reference = publish::proof_ref(
                epoch,
                Stage::Finalization,
                &proof,
                &vk,
                &output.public_bytes(),
                self.engine
                    .prover
                    .program_digest(Stage::Finalization)
                    .as_deref(),
            );
            let inputs = publish::finalization_public_inputs(&output);
            publish.proof_bytes(
                epoch,
                Stage::Finalization,
                &proof,
                &vk,
                &output.public_bytes(),
            );
            publish.proof_landed(epoch, reference.clone(), inputs.clone(), None);
            publish.epoch_closed(&ClosedEpoch {
                epoch,
                cost,
                target_root: crate::artifacts::hex0x(&current.output.target_root),
                finalizes_epoch: output.finalized_epoch,
                justified: serde_json::to_value(justified_checkpoint(&current.output))?,
                finalized: serde_json::json!({
                    "epoch": output.finalized_epoch,
                    "root": crate::artifacts::hex0x(&output.finalized_root),
                }),
                accumulator: serde_json::to_value(acc_status(&self.engine.snapshot.state))?,
                latency: None,
                proof: reference,
                public_inputs: inputs,
            });
        }

        crate::metrics::epoch_finalized();
        Ok(Some(Checkpoint {
            epoch: output.finalized_epoch,
            root: output.finalized_root,
        }))
    }

    // -----------------------------------------------------------------
    // Stages: groups, aggregates, the final proof
    // -----------------------------------------------------------------

    /// Whether the epoch the cursor sits on can be streamed.
    ///
    /// A final proof turns the previous epoch's justification into a
    /// finalization and inherits the accumulator link from the diff that opened
    /// the epoch, so an epoch with neither — the first after a bootstrap — has
    /// to go through the batch path, and the one after it streams.
    fn can_stream(&self) -> bool {
        self.engine.snapshot.state.last_epoch_diff.is_some()
            && self
                .engine
                .snapshot
                .state
                .previous_justification(self.engine.snapshot.state.cursor_epoch)
                .is_some()
    }

    async fn drive_stream(&mut self, tick: &mut Tick) -> Result<()> {
        let target_epoch = self.engine.snapshot.state.cursor_epoch;

        let mut aggregator = match self.streaming.take() {
            Some(aggregator) if aggregator.context.target_epoch == target_epoch => aggregator,
            _ => self.open_stream_epoch(target_epoch).await?,
        };

        let _span = info_span!("stream", target_epoch).entered();
        let spe = self.engine.config.chain.slots_per_epoch;

        // Gossip is the source. Blocks repair what an outage swallowed, and are
        // the whole source when there is no stream — the fixture-replay tests.
        match &self.engine.gossip {
            Some(source) => {
                aggregator.stream.ingest(&source.drain())?;
                aggregator.reorged |= source.took_reorg();
                if source.took_gap() {
                    // An outage does not say what it swallowed, so the repair
                    // rescans the epoch rather than resuming from a cursor.
                    warn!(target_epoch, "gossip gap; repairing this epoch from blocks");
                    aggregator.next_slot = target_epoch * spe;
                    aggregator.gap = true;
                }
            }
            None => aggregator.gap = true,
        }
        if aggregator.gap {
            self.repair_from_blocks(&mut aggregator).await?;
        }

        // A reorg can take the checkpoint out from under an epoch that is
        // already half collected. Everything counted so far attested to a root
        // that is no longer canonical, so the epoch restarts against the new one
        // rather than proving the old one. Doing it here, off a node event,
        // keeps the round trip away from the critical path.
        if std::mem::take(&mut aggregator.reorged)
            && self
                .engine
                .chain
                .checkpoint_root(&self.engine.api, &self.engine.config, target_epoch)
                .await?
                != aggregator.context.target_root
        {
            warn!(
                target_epoch,
                "the checkpoint reorged out; reopening the epoch"
            );
            return Ok(());
        }

        let policy = self.engine.config.stream_policy.clone();
        let total = aggregator.context.total_active_balance;
        let held = aggregator.held(spe, self.engine.chain.head_slot(), &policy);

        // `T`: the first moment the daemon holds what the circuit would accept.
        // Everything after it is latency a consumer sees, the trigger's own wait
        // included, which is what keeps that wait honest.
        if held.balance as u128 >= policy.quorum_balance(total)
            && aggregator.crossed_unix_millis.is_none()
        {
            let crossed = now_unix_millis();
            aggregator.crossed_unix_millis = Some(crossed);
            if let Some(publish) = self.engine.report.publisher() {
                publish.threshold_crossed(target_epoch, crossed, held.balance, total);
            }
        }

        let fire = held.balance as u128 >= policy.target_balance(total)
            && !aggregator.worth_waiting(&policy, held.filling);
        aggregator.last_filling = held
            .filling
            .map(|(slot, named, aggregates)| (Instant::now(), slot, named, aggregates));

        if !fire {
            if let Some(publish) = self.engine.report.publisher() {
                publish.epoch_progress(&EpochProgress {
                    epoch: target_epoch,
                    attesting_balance: held.balance,
                    total_active_balance: total,
                    threshold_pct: policy.threshold_pct(),
                    folded_groups: aggregator.folded_groups,
                    slots_held: aggregator.units.len(),
                    head_slot: self.engine.chain.head_slot(),
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
            if aggregator.proved < aggregator.units.len() {
                let group =
                    self.prove_group(&aggregator, aggregator.proved..aggregator.units.len(), tick)?;
                self.fold_group(&mut aggregator, group)?;
            }
            if aggregator.exhausted(self.engine.chain.head_slot()) {
                warn!(
                    target_epoch,
                    attesting_balance = aggregator.attesting_balance,
                    total_active_balance = total,
                    "checkpoint never reached the threshold; giving up on this epoch",
                );
                if let Some(publish) = self.engine.report.publisher() {
                    publish.epoch_abandoned(target_epoch, "never reached the threshold");
                }
                self.engine.snapshot.state.attempted_epoch = Some(target_epoch);
                self.engine.store.save(&self.engine.snapshot)?;
                tick.gave_up_on = Some(target_epoch);
            } else {
                self.streaming = Some(aggregator);
            }
            return Ok(());
        }

        // Fire. Everything gossip has reached is closed, and the plan decides
        // how much of it the final proof carries inline; slots past the crossing
        // are simply never proven.
        for unit in held.open {
            aggregator.stream.forget(unit.slot);
            aggregator.attesting_balance += unit.marginal_balance;
            aggregator.units.push(unit);
        }
        let crossing = aggregator
            .crossing(&policy)
            .context("the threshold moved out from under the trigger")?;
        let late = (aggregator.proved < crossing)
            .then(|| self.prove_group(&aggregator, aggregator.proved..crossing, tick))
            .transpose()?;
        self.close_stream_epoch(aggregator, late, crossing, tick)
            .await
    }

    /// Fill in from blocks what gossip did not deliver.
    ///
    /// Only two things need it: an epoch that opened after its own attestations
    /// were gossiped, and a stream that dropped. Both are repairs — the union of
    /// a block and a gossip view of a slot is the gossip view, because the
    /// collector converges on an attester set rather than a list.
    async fn repair_from_blocks(&mut self, aggregator: &mut StreamAggregator) -> Result<()> {
        while aggregator.next_slot <= self.engine.chain.head_slot()
            && aggregator.next_slot < aggregator.scan_end
        {
            let slot = aggregator.next_slot;
            aggregator.next_slot += 1;

            // A slot with no block is not an error; neither is one whose
            // attestations all point somewhere else.
            if let Ok(attestations) = self
                .engine
                .api
                .get_block_attestations(&slot.to_string())
                .await
            {
                aggregator.stream.ingest(&attestations)?;
            }
        }
        aggregator.gap = false;
        Ok(())
    }

    /// Open an epoch against the accumulator, the diff that carried it here, and
    /// the justification this epoch will finalize.
    ///
    /// Everything the final proof needs that is not an attestation is fetched
    /// here, an epoch ahead of when it is used, so that no round trip to the
    /// beacon node lands between `T` and `T2`.
    async fn open_stream_epoch(&mut self, target_epoch: u64) -> Result<StreamAggregator> {
        let spe = self.engine.config.chain.slots_per_epoch;
        let target_root = self
            .engine
            .chain
            .checkpoint_root(&self.engine.api, &self.engine.config, target_epoch)
            .await?;
        let signing_domain = self
            .engine
            .chain
            .signing_domain(&self.engine.api, &self.engine.config, target_epoch)
            .await?;
        let validators = self
            .engine
            .api
            .get_validators(&(target_epoch * spe).to_string())
            .await
            .context("fetch validators for the target epoch")?;

        let (committees, committee_output, committee_proof) =
            self.prove_committee(target_epoch, &validators).await?;

        let stream = SlotStream::new(
            &self.engine.config.chain,
            committees.clone(),
            target_epoch,
            target_root,
        );

        let epoch_diff = self
            .engine
            .snapshot
            .state
            .last_epoch_diff
            .clone()
            .context("no epoch diff on record to open the epoch against")?;
        let (previous, previous_proof) = self
            .engine
            .snapshot
            .state
            .previous_justification(target_epoch)
            .context("no justification for the previous epoch to finalize")?;

        let boundary = crate::boundary::build(
            &self.engine.api,
            &self.engine.config.chain,
            &target_root,
            previous.target_epoch(),
            &previous.target_root(),
            &epoch_diff.output.state_root_1,
            &self.engine.snapshot.epoch_state,
        )
        .await
        .context("open the boundary of the epoch being finalized")?;

        let state = &self.engine.snapshot.state;
        let context = StreamContext {
            accumulator_commitment: state.acc_commitment,
            acc_root: state.acc_root,
            total_active_balance: state.total_active_balance,
            target_epoch,
            target_root,
            signing_domain,
            group_program_vk: self.engine.prover.program_vk(Stage::Group),
            aggregate_program_vk: self.engine.prover.program_vk(Stage::Aggregate),
            previous_program_vk: match previous {
                PreviousJustification::Batch(_) => {
                    self.engine.prover.program_vk(Stage::Justification)
                }
                PreviousJustification::Stream(_) => {
                    self.engine.prover.program_vk(Stage::StreamFinal)
                }
            },
            epoch_diff_program_vk: self.engine.prover.program_vk(Stage::EpochDiff),
            committee_program_vk: self.engine.prover.program_vk(Stage::Committee),
            epoch_diff: epoch_diff.output,
            epoch_diff_proof: epoch_diff.proof,
            committee: committee_output,
            committee_proof,
            acc_depth: self.engine.config.chain.acc_tree_depth,
        };

        if let Some(publish) = self.engine.report.publisher() {
            publish.epoch_opened(
                target_epoch,
                &target_root,
                previous.target_epoch(),
                state.total_active_balance,
                serde_json::to_value(acc_status(&self.engine.snapshot.state))?,
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
            scan_end: (target_epoch + self.engine.config.attestation_lookahead_epochs) * spe,
            // The epoch's earlier slots were gossiped before the daemon reached
            // it, so it starts by repairing them out of blocks.
            gap: true,
            reorged: false,
            last_filling: None,
            stalled_s: 0.0,
            units: Vec::new(),
            proved: 0,
            attesting_balance: 0,
            aggregate: None,
            aggregate_proof: Proof::new(),
            aggregate_miller: FP12_ONE,
            folded_groups: 0,
            previous,
            previous_proof,
            boundary,
            opened_unix_millis: now_unix_millis(),
            crossed_unix_millis: None,
        })
    }

    /// Prove one group of units. Nothing about the epoch changes until it is
    /// either folded or handed to the final proof.
    #[instrument(
        name = "stage",
        skip_all,
        fields(stage = "group", epoch = aggregator.context.target_epoch, index = range.start),
    )]
    fn prove_group(
        &mut self,
        aggregator: &StreamAggregator,
        range: Range<usize>,
        tick: &mut Tick,
    ) -> Result<GroupProof> {
        let started = Instant::now();
        let target_epoch = aggregator.context.target_epoch;
        self.engine
            .report
            .begin(Stage::Group, target_epoch, None, Some(range.start));
        let units: Vec<&SlotComplement> = aggregator.units[range.clone()].iter().collect();
        let slots: Vec<u64> = units.iter().map(|u| u.slot).collect();
        if let Some(&last) = slots.last() {
            self.engine.chain.observe_start_delay(
                &self.engine.config,
                Stage::Group,
                target_epoch,
                last,
            );
        }

        let witness = streaming::group_witness(
            &aggregator.context,
            &self.engine.snapshot.tree,
            &aggregator.committees,
            &units,
        );
        let (output, miller, proof) = self
            .engine
            .prover
            .prove_group(&witness)
            .with_context(|| format!("group proof over slots {slots:?}"))?;

        let name = format!("group_{}", range.start);
        let artifact = self
            .engine
            .sink
            .write_witness(target_epoch, &name, &witness)?;
        write_proof(&self.engine.sink, target_epoch, &name, &proof)?;

        info!(
            slots = ?slots,
            attesting_balance = output.attesting_balance,
            millis = started.elapsed().as_millis() as u64,
            "group proof",
        );
        self.engine.report.record(
            StageTiming::new(
                Stage::Group,
                target_epoch,
                started,
                self.engine.prover.last_cost(),
                artifact,
            )
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

    /// Fold a finished group into the running aggregate.
    #[instrument(
        name = "stage",
        skip_all,
        fields(stage = "aggregate", epoch = aggregator.context.target_epoch),
    )]
    fn fold_group(&mut self, aggregator: &mut StreamAggregator, group: GroupProof) -> Result<()> {
        let started = Instant::now();
        let target_epoch = aggregator.context.target_epoch;
        if let Some(last) = aggregator.units.last() {
            self.engine.chain.observe_start_delay(
                &self.engine.config,
                Stage::Aggregate,
                target_epoch,
                last.slot,
            );
        }
        self.engine.report.begin(
            Stage::Aggregate,
            target_epoch,
            None,
            Some(aggregator.folded_groups),
        );

        let witness = streaming::aggregate_witness(
            &aggregator.context,
            aggregator.aggregate.clone(),
            std::mem::take(&mut aggregator.aggregate_proof),
            aggregator.aggregate_miller,
            vec![group.output],
            vec![group.proof],
            vec![group.miller],
        );
        let (output, proof) = self.engine.prover.prove_aggregate(&witness)?;

        let name = format!("aggregate_{}", aggregator.folded_groups);
        let artifact = self
            .engine
            .sink
            .write_witness(target_epoch, &name, &witness)?;
        write_proof(&self.engine.sink, target_epoch, &name, &proof)?;

        aggregator.aggregate_miller = fp12_mul(&aggregator.aggregate_miller, &group.miller);
        aggregator.attesting_balance = output.attesting_balance;
        aggregator.aggregate = Some(output);
        aggregator.aggregate_proof = proof;
        aggregator.folded_groups += 1;
        aggregator.proved = aggregator.units.len();

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
        self.engine.report.record(
            StageTiming::new(
                Stage::Aggregate,
                target_epoch,
                started,
                self.engine.prover.last_cost(),
                artifact,
            )
            .at_index(aggregator.folded_groups - 1)
            .with_proof(&aggregator.aggregate_proof),
        );
        Ok(())
    }

    /// The only proof on the critical path: the marginal attestation, the one
    /// final exponentiation, and the previous epoch's justification, at once.
    #[instrument(
        name = "stage",
        skip_all,
        fields(stage = "stream_final", epoch = aggregator.context.target_epoch),
    )]
    async fn close_stream_epoch(
        &mut self,
        aggregator: StreamAggregator,
        late: Option<GroupProof>,
        crossing: usize,
        tick: &mut Tick,
    ) -> Result<()> {
        let started = Instant::now();
        let fired_unix_millis = now_unix_millis();
        let target_epoch = aggregator.context.target_epoch;
        let tail: Vec<&SlotComplement> = vec![&aggregator.units[crossing]];
        let tail_named = tail.iter().map(|u| u.named_indices.len()).sum();

        let (groups, group_proofs, group_millers) = match late {
            Some(g) => (vec![g.output], vec![g.proof], vec![g.miller]),
            None => (Vec::new(), Vec::new(), Vec::new()),
        };
        let late_groups = groups.len();
        if let Some(publish) = self.engine.report.publisher() {
            publish.threshold_fired(
                target_epoch,
                fired_unix_millis,
                fired_unix_millis
                    .saturating_sub(aggregator.crossed_unix_millis.unwrap_or_default()),
                tail.len(),
                tail_named,
                late_groups,
            );
            publish.stage_started(Stage::StreamFinal, target_epoch, None, None);
        }

        let witness = streaming::final_witness(
            &aggregator.context,
            &self.engine.snapshot.tree,
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
        );

        let (output, proof) = self.engine.prover.prove_stream_final(&witness)?;
        let proof_unix_millis = now_unix_millis();

        // Everything from here is after `T2`, so none of it can inflate the
        // latency this pipeline exists to minimise — including checking that
        // the proof it just made actually verifies, which is the only place
        // anyone has ever timed the verifier.
        crate::verify::timed(
            Stage::StreamFinal,
            &proof,
            &self.engine.prover.program_vk(Stage::StreamFinal),
            &output.public_bytes(),
        );

        let artifact = self
            .engine
            .sink
            .write_witness(target_epoch, "stream_final", &witness)?;
        write_proof(&self.engine.sink, target_epoch, "stream_final", &proof)?;

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
        let (epochs, bytes) = self.engine.sink.prune_old_epochs();
        crate::metrics::observe_output(epochs, bytes);
        self.engine.report.record(
            StageTiming::new(
                Stage::StreamFinal,
                target_epoch,
                started,
                self.engine.prover.last_cost(),
                artifact,
            )
            .with_proof(&proof),
        );

        // A proof of a checkpoint the chain no longer has is worse than no proof
        // at all, so the root is re-resolved before anything is published. This
        // is after `T2` by construction — the proof exists — so it costs
        // publication latency and never a stale publication.
        if self
            .engine
            .chain
            .checkpoint_root(&self.engine.api, &self.engine.config, target_epoch)
            .await?
            != aggregator.context.target_root
        {
            warn!(
                target_epoch,
                "the checkpoint reorged out while the final proof ran; discarding it",
            );
            if let Some(publish) = self.engine.report.publisher() {
                publish.epoch_abandoned(target_epoch, "the checkpoint reorged out");
            }
            crate::metrics::epoch_abandoned("reorg");
            self.streaming = None;
            return Ok(());
        }

        // `T` is when the daemon held enough attestations; if it was already
        // holding them when the epoch opened — a catch-up, not a live follow —
        // there is no latency to report and reporting one would flatter it.
        if let Some(threshold_unix_millis) = aggregator.crossed_unix_millis {
            let latency = EpochLatency {
                epoch: target_epoch,
                threshold_unix_millis,
                fired_unix_millis,
                proof_unix_millis,
                t2_minus_t_millis: proof_unix_millis.saturating_sub(threshold_unix_millis),
                wait_millis: fired_unix_millis.saturating_sub(threshold_unix_millis),
                tail_named,
                folded_groups: aggregator.folded_groups,
                late_groups,
                tail: tail.len(),
            };
            info!(
                t2_minus_t_millis = latency.t2_minus_t_millis,
                wait_millis = latency.wait_millis,
                tail_named = latency.tail_named,
                folded_groups = latency.folded_groups,
                late_groups = latency.late_groups,
                "measured T2 - T",
            );
            self.engine.report.record_latency(latency);
        }

        let finalized = Checkpoint {
            epoch: output.finalized_epoch,
            root: output.finalized_root,
        };
        let cost = self.engine.report.take_cost(target_epoch);
        if let Some(publish) = self.engine.report.publisher() {
            let vk = self.engine.prover.program_vk(Stage::StreamFinal);
            let publics = output.public_bytes();
            let reference = publish::proof_ref(
                target_epoch,
                Stage::StreamFinal,
                &proof,
                &vk,
                &publics,
                self.engine
                    .prover
                    .program_digest(Stage::StreamFinal)
                    .as_deref(),
            );
            let inputs = publish::stream_final_public_inputs(&output);
            let latency = self
                .engine
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
                accumulator: serde_json::to_value(acc_status(&self.engine.snapshot.state))?,
                latency,
                proof: reference,
                public_inputs: inputs,
            });
        }
        crate::metrics::epoch_justified();
        crate::metrics::epoch_finalized();
        self.engine.snapshot.state.justified_through = Some(target_epoch);
        self.engine.snapshot.state.attempted_epoch = Some(target_epoch);
        self.engine.snapshot.state.last_stream_final = Some(StreamFinalRecord { output, proof });
        self.engine.snapshot.state.finalized = Some(finalized.clone());
        self.streaming = None;
        self.engine.store.save(&self.engine.snapshot)?;

        tick.justified = Some(target_epoch);
        tick.finalized = Some(finalized);
        Ok(())
    }
}

/// Present the accumulator's cached SSZ view, for callers that want to inspect
/// what the next epoch diff will build on.
impl<A> Orchestrator<A> {
    /// The epoch in flight, as the manifest reports it.
    fn current_epoch(&self) -> Option<CurrentEpoch> {
        let aggregator = self.streaming.as_ref()?;
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
            threshold_pct: self.engine.config.stream_policy.threshold_pct(),
            folded_groups: aggregator.folded_groups,
            slots_held: aggregator.units.len(),
            finalizes_epoch: aggregator.previous.target_epoch(),
        })
    }

    pub fn epoch_state(&self) -> &EpochState {
        &self.engine.snapshot.epoch_state
    }

    pub fn api(&self) -> &A {
        &self.engine.api
    }
}
