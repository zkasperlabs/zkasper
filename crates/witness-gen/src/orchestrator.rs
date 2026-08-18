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

use std::collections::VecDeque;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tracing::{info, info_span, warn};

use zkasper_common::acc::Digest;
use zkasper_common::bls::{compute_domain, fp12_mul, Fp12, DOMAIN_BEACON_ATTESTER, FP12_ONE};
use zkasper_common::types::{
    AggregateOutput, BlockHeaderFields, Checkpoint, CommitteeOutput, FinalizationWitness,
    GroupProofOutput, JustificationOutput, PreviousJustification, SlotProofOutput,
    SlotProofWitness,
};
use zkasper_common::ChainConfig;

use crate::acc_tree::AccTree;
use crate::artifacts::{
    hex_digest, now_unix, now_unix_millis, AccStatus, ArtifactRef, ArtifactSink, CheckpointStatus,
    EpochLatency, GossipStatus, StageTiming, Status,
};
use crate::attestation_collector::{SlotComplement, SlotStream};
use crate::beacon_api::{BeaconApi, ChainStatusApi, ValidatorResponse};
use crate::committee::EpochCommittees;
use crate::epoch_state::EpochState;
use crate::gossip::{AttestationSource, EventStreamSource};
use crate::prover::{Proof, Prover, Stage};
use crate::store::{
    EpochDiffRecord, JustificationRecord, Snapshot, Store, StoreState, StreamFinalRecord,
};
use crate::streaming::{self, StreamContext, StreamPolicy};
use crate::{witness_bootstrap, witness_epoch_diff, witness_justification};

/// How many stage timings the manifest keeps.
const RECENT_STAGES: usize = 64;

/// How many epochs' measured `T2 - T` the manifest keeps.
const RECENT_LATENCIES: usize = 16;

/// Which pipeline an epoch is proven with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Pipeline {
    /// One slot proof per slot, folded into a justification once the epoch is
    /// over, paired with the previous epoch's into a finalization.
    #[default]
    Batch,
    /// Group proofs as attestations arrive, folded into a running aggregate,
    /// closed by one proof over the attestation that crossed the threshold.
    Streaming,
}

impl Pipeline {
    /// Stages a prover has to be able to produce for this pipeline.
    ///
    /// Streaming still needs the batch stages: the first epoch after a bootstrap
    /// has nothing to finalize and goes through them.
    pub fn stages(self) -> &'static [Stage] {
        match self {
            Pipeline::Batch => &[
                Stage::Bootstrap,
                Stage::EpochDiff,
                Stage::Committee,
                Stage::SlotProof,
                Stage::Justification,
                Stage::Finalization,
            ],
            Pipeline::Streaming => &[
                Stage::Bootstrap,
                Stage::EpochDiff,
                Stage::Committee,
                Stage::SlotProof,
                Stage::Justification,
                Stage::Finalization,
                Stage::Group,
                Stage::Aggregate,
                Stage::StreamFinal,
            ],
        }
    }
}

#[derive(Clone, Debug)]
pub struct OrchestratorConfig {
    pub chain: ChainConfig,
    /// Chain name, recorded in the store so it cannot be pointed at another one.
    pub chain_name: String,
    pub db_path: PathBuf,
    pub output_dir: PathBuf,
    /// Slot to bootstrap from. Defaults to the node's finalized checkpoint.
    pub bootstrap_slot: Option<u64>,
    /// Overrides the domain otherwise derived from the node's fork and genesis.
    pub signing_domain: Option<[u8; 32]>,
    /// How long to wait after a tick that could make no further progress.
    pub poll_interval: Duration,
    /// How often a streaming epoch re-reads gossip and re-evaluates the trigger.
    /// Sets the resolution of `T2 − T`: the daemon cannot fire between two
    /// evaluations, so this is the granularity of "the instant enough arrived".
    pub trigger_interval: Duration,
    /// How many epochs past the target to keep looking for its attestations.
    pub attestation_lookahead_epochs: u64,
    pub pipeline: Pipeline,
    /// When the streaming pipeline stops collecting, and how long the trigger
    /// may hold past it. See [`crate::streaming`].
    pub stream_policy: StreamPolicy,
    /// Beacon node to follow attestation gossip from. `None` sources
    /// attestations from blocks instead, which is a slot later and is only what
    /// the fixture-replay tests want.
    pub gossip_url: Option<String>,
}

impl OrchestratorConfig {
    pub fn new(chain: ChainConfig, chain_name: impl Into<String>) -> Self {
        Self {
            chain,
            chain_name: chain_name.into(),
            db_path: PathBuf::from("zkasper.db"),
            output_dir: PathBuf::from("zkasper-out"),
            bootstrap_slot: None,
            signing_domain: None,
            poll_interval: Duration::from_secs(4),
            trigger_interval: Duration::from_millis(200),
            attestation_lookahead_epochs: 2,
            pipeline: Pipeline::default(),
            stream_policy: StreamPolicy::default(),
            gossip_url: None,
        }
    }
}

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
    /// slot, and how many accumulator leaves it would have opened. The trigger
    /// is the difference between two of these.
    last_filling: Option<(Instant, u64, usize)>,
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
    /// neither it nor the header below is fetched on the critical path.
    previous: PreviousJustification,
    previous_proof: Proof,
    finalized_header: BlockHeaderFields,
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
    /// The slot gossip is still filling that the proof would have to carry, and
    /// the accumulator leaves it would open if the trigger fired now. Waiting
    /// buys the difference between two readings of it; nothing else moves.
    filling: Option<(u64, usize)>,
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
            .map(|unit| (unit.slot, unit.named_indices.len()));

        Held {
            balance,
            filling,
            open,
        }
    }

    /// Whether the last interval of waiting shortened the proof by more than it
    /// cost, which is the whole of the firing decision once the weight is there.
    ///
    /// No reading to compare against — nothing still filling, or a different
    /// slot than last time — means fire. There is nothing in flight to wait for,
    /// and a daemon that opened an epoch already past the threshold must not
    /// invent a wait it never observed.
    fn worth_waiting(&self, policy: &StreamPolicy, filling: Option<(u64, usize)>) -> bool {
        let (Some((at, was, before)), Some((slot, named))) = (self.last_filling, filling) else {
            return false;
        };
        was == slot
            && policy.worth_waiting(
                before.saturating_sub(named),
                at.elapsed().as_secs_f64(),
                self.waited_s(),
            )
    }

    /// Seconds since `T`, which is what the cap on waiting is measured against.
    fn waited_s(&self) -> f64 {
        self.crossed_unix_millis
            .map_or(0.0, |t| now_unix_millis().saturating_sub(t) as f64 / 1000.0)
    }
}

pub struct Orchestrator<A> {
    api: A,
    config: OrchestratorConfig,
    store: Store,
    sink: ArtifactSink,
    prover: Box<dyn Prover>,
    snapshot: Snapshot,
    pending: Option<EpochAggregator>,
    streaming: Option<StreamAggregator>,
    /// Attestation gossip, when the daemon was given a node to follow it from.
    gossip: Option<Box<dyn AttestationSource>>,
    recent: VecDeque<StageTiming>,
    latencies: VecDeque<EpochLatency>,
    head_slot: u64,
    /// When the chain view was last refreshed. The trigger runs several times a
    /// second and the node's head does not move that fast, so the two are not
    /// the same clock.
    viewed: Option<Instant>,
    node_finalized: Option<Checkpoint>,
    genesis_validators_root: Option<[u8; 32]>,
}

impl<A: BeaconApi + ChainStatusApi> Orchestrator<A> {
    /// Resume from the persisted accumulator, or bootstrap if there is none.
    pub async fn open(api: A, config: OrchestratorConfig, prover: Box<dyn Prover>) -> Result<Self> {
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
                Self::assemble(api, config, store, sink, prover, snapshot)
            }
            None => {
                let (snapshot, timing) = Self::bootstrap(&api, &config, &sink, &*prover).await?;
                let mut this = Self::assemble(api, config, store, sink, prover, snapshot);
                this.record(timing);
                this.store.save(&this.snapshot)?;
                this
            }
        };

        this.refresh_chain_view().await?;
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
    ) -> Self {
        Self {
            gossip: config
                .gossip_url
                .as_deref()
                .map(|url| Box::new(EventStreamSource::connect(url)) as Box<dyn AttestationSource>),
            api,
            config,
            store,
            sink,
            prover,
            snapshot,
            pending: None,
            streaming: None,
            recent: VecDeque::new(),
            latencies: VecDeque::new(),
            head_slot: 0,
            viewed: None,
            node_finalized: None,
            genesis_validators_root: None,
        }
    }

    /// Follow attestations from `source` instead of the node's event stream.
    ///
    /// The daemon only ever asks a source for whatever arrived since last time,
    /// so this is where a forked node, an in-process feed or a test's own
    /// arrival schedule goes in.
    pub fn with_gossip(mut self, source: Box<dyn AttestationSource>) -> Self {
        self.gossip = Some(source);
        self
    }

    pub fn state(&self) -> &StoreState {
        &self.snapshot.state
    }

    pub fn tree(&self) -> &AccTree {
        &self.snapshot.tree
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
                Some(_) => self.config.trigger_interval,
                None => self.config.poll_interval,
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
    pub async fn tick(&mut self) -> Result<Tick> {
        self.refresh_chain_view().await?;

        let mut tick = Tick {
            head_slot: self.head_slot,
            ..Tick::default()
        };

        if self.snapshot.state.needs_justification() {
            if self.config.pipeline == Pipeline::Streaming && self.can_stream() {
                self.drive_stream(&mut tick).await?;
            } else {
                self.drive_aggregation(&mut tick).await?;
            }
        } else {
            let next = self.snapshot.state.cursor_epoch + 1;
            if next <= self.head_slot / self.config.chain.slots_per_epoch {
                self.advance_accumulator(next).await?;
                tick.advanced_to = Some(next);
            }
        }

        self.publish_status()?;
        Ok(tick)
    }

    /// Ask the node where it is, at most once a poll interval.
    ///
    /// The trigger ticks several times a second and the head moves once a slot,
    /// so refreshing on every tick would be two round trips per evaluation to
    /// learn nothing.
    async fn refresh_chain_view(&mut self) -> Result<()> {
        if self
            .viewed
            .is_some_and(|at| at.elapsed() < self.config.poll_interval)
        {
            return Ok(());
        }
        self.viewed = Some(Instant::now());

        self.head_slot = self
            .api
            .get_header("head")
            .await
            .context("fetch chain head")?
            .slot;

        // Only used for the manifest, so a node that will not answer must not
        // stop the pipeline.
        match self.api.get_finality_checkpoints("head").await {
            Ok(checkpoints) => self.node_finalized = Some(checkpoints.finalized),
            Err(e) => warn!(error = %e, "could not read the node's finality checkpoints"),
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Stage: bootstrap
    // -----------------------------------------------------------------

    async fn bootstrap(
        api: &A,
        config: &OrchestratorConfig,
        sink: &ArtifactSink,
        prover: &dyn Prover,
    ) -> Result<(Snapshot, StageTiming)> {
        let slot = match config.bootstrap_slot {
            Some(slot) => slot,
            None => {
                let checkpoints = api
                    .get_finality_checkpoints("head")
                    .await
                    .context("fetch finality checkpoints to pick a bootstrap slot")?;
                checkpoints.finalized.epoch * config.chain.slots_per_epoch
            }
        };
        let epoch = slot / config.chain.slots_per_epoch;
        let _span = info_span!("bootstrap", epoch, slot).entered();
        let started = Instant::now();

        let (witness, tree, epoch_state, total_active_balance, num_validators) =
            witness_bootstrap::build(api, &config.chain, slot)
                .await
                .context("build bootstrap witness")?;

        let (output, proof) = prover.prove_bootstrap(&witness)?;
        if output.acc_root != tree.root() {
            bail!("bootstrap circuit disagrees with the host accumulator tree");
        }
        if output.total_active_balance != total_active_balance {
            bail!("bootstrap circuit disagrees on the total active balance");
        }

        let artifact = sink.write_witness(epoch, "bootstrap", &witness)?;
        write_proof(sink, epoch, "bootstrap", &proof)?;

        let state = StoreState::bootstrapped(
            config.chain_name.clone(),
            epoch,
            output.acc_root,
            total_active_balance,
            num_validators,
        );

        info!(
            num_validators,
            total_active_balance,
            acc_root = %hex_digest(&output.acc_root),
            millis = started.elapsed().as_millis() as u64,
            "bootstrapped",
        );

        Ok((
            Snapshot {
                state,
                tree,
                epoch_state,
            },
            StageTiming::new(
                Stage::Bootstrap,
                epoch,
                started,
                prover.last_cost(),
                artifact,
            ),
        ))
    }

    // -----------------------------------------------------------------
    // Stage: epoch diff
    // -----------------------------------------------------------------

    /// Move the accumulator one epoch forward, transactionally.
    ///
    /// Nothing here touches persistent state until the epoch diff circuit has
    /// confirmed the new root. The host tree is advanced on a clone, so a build
    /// that fails halfway leaves the in-memory accumulator untouched, and the
    /// clone is only adopted once the circuit agrees with it.
    async fn advance_accumulator(&mut self, to_epoch: u64) -> Result<()> {
        let _span = info_span!("epoch_diff", to_epoch).entered();
        let started = Instant::now();

        let mut tree = self.snapshot.tree.clone();
        let (witness, epoch_state, total_active_balance, num_validators) =
            witness_epoch_diff::build(
                &self.api,
                &self.config.chain,
                &mut tree,
                &self.snapshot.epoch_state,
                to_epoch * self.config.chain.slots_per_epoch,
                self.snapshot.state.total_active_balance,
            )
            .await
            .context("build epoch diff witness")?;

        if witness.epoch_1 != self.snapshot.state.cursor_epoch || witness.epoch_2 != to_epoch {
            bail!(
                "epoch diff spans {} -> {}, but the accumulator is at {} and must move to {to_epoch}",
                witness.epoch_1,
                witness.epoch_2,
                self.snapshot.state.cursor_epoch,
            );
        }

        let (output, proof) = self.prover.prove_epoch_diff(&witness)?;
        if output.acc_root != tree.root() {
            bail!(
                "epoch diff circuit disagrees with the host accumulator tree at epoch {to_epoch}"
            );
        }
        if output.total_active_balance != total_active_balance {
            bail!("epoch diff circuit disagrees on the total active balance at epoch {to_epoch}");
        }
        if output.prev_accumulator_commitment != self.snapshot.state.acc_commitment {
            bail!("epoch diff does not start from the accumulator the cursor sits on");
        }

        let mut state = self.snapshot.state.clone();
        let acc_root = output.acc_root;
        let commitment = output.accumulator_commitment;
        state.advance(
            to_epoch,
            acc_root,
            commitment,
            output.total_active_balance,
            num_validators,
            Some(EpochDiffRecord {
                output,
                proof: proof.clone(),
            }),
        )?;

        let artifact = self.sink.write_witness(to_epoch, "epoch_diff", &witness)?;
        write_proof(&self.sink, to_epoch, "epoch_diff", &proof)?;

        // Commit: in memory first, then to disk. A crash between the two is
        // harmless — the next start re-runs this epoch from the old cursor.
        self.snapshot = Snapshot {
            state,
            tree,
            epoch_state,
        };
        self.pending = None;
        self.streaming = None;
        self.store.save(&self.snapshot)?;

        let millis = started.elapsed().as_millis() as u64;
        info!(
            mutations = witness.mutations.len(),
            num_validators,
            total_active_balance,
            acc_root = %hex_digest(&acc_root),
            millis,
            "accumulator advanced",
        );
        self.record(StageTiming::new(
            Stage::EpochDiff,
            to_epoch,
            started,
            self.prover.last_cost(),
            artifact,
        ));
        Ok(())
    }

    // -----------------------------------------------------------------
    // Stages: slot proofs, justification, finalization
    // -----------------------------------------------------------------

    async fn drive_aggregation(&mut self, tick: &mut Tick) -> Result<()> {
        let target_epoch = self.snapshot.state.cursor_epoch;
        let spe = self.config.chain.slots_per_epoch;

        let mut aggregator = match self.pending.take() {
            Some(aggregator) if aggregator.target_epoch == target_epoch => aggregator,
            _ => self.open_epoch(target_epoch).await?,
        };

        let _span = info_span!("aggregate", target_epoch).entered();

        while !aggregator.threshold_reached()
            && !aggregator.exhausted()
            && aggregator.next_slot <= self.head_slot
        {
            let slot = aggregator.next_slot;
            aggregator.next_slot += 1;

            // A slot with no block is not an error; neither is one whose
            // attestations all point somewhere else.
            if let Ok(attestations) = self.api.get_block_attestations(&slot.to_string()).await {
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

            let started = Instant::now();
            let witness = SlotProofWitness {
                accumulator_commitment: aggregator.acc_commitment,
                committee_root: aggregator.committee_output.committee_root,
                target_epoch,
                target_root: aggregator.target_root,
                signing_domain: aggregator.signing_domain,
                acc_root: aggregator.acc_root,
                total_active_balance: aggregator.total_active_balance,
                acc_multi_proof: self
                    .snapshot
                    .tree
                    .build_multi_proof(&complement.named_indices),
                committee_multi_proof: aggregator
                    .committees
                    .multi_proof(&[complement.witness.slot_in_epoch]),
                slots: vec![complement.witness],
            };

            let (output, proof) = self
                .prover
                .prove_slot(&witness)
                .with_context(|| format!("slot proof for attestation slot {attestation_slot}"))?;

            let artifact = self.sink.write_witness(
                target_epoch,
                &format!("slot_proof_{attestation_slot}"),
                &witness,
            )?;
            write_proof(
                &self.sink,
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
            self.record(
                StageTiming::new(
                    Stage::SlotProof,
                    target_epoch,
                    started,
                    self.prover.last_cost(),
                    artifact,
                )
                .at_slot(attestation_slot),
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
            self.pending = None;
            self.snapshot.state.attempted_epoch = Some(target_epoch);
            self.store.save(&self.snapshot)?;
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
        let spe = self.config.chain.slots_per_epoch;
        let target_root = self.checkpoint_root(target_epoch).await?;
        let signing_domain = self.signing_domain(target_epoch).await?;
        let validators = self
            .api
            .get_validators(&(target_epoch * spe).to_string())
            .await
            .context("fetch validators for the target epoch")?;

        let committees = Arc::new(self.build_committees(target_epoch, &validators).await?);
        let (committee_output, committee_proof) =
            self.prover.prove_committee(&committees.witness)?;
        if committee_output != committees.output {
            bail!(
                "committee circuit disagrees with the host committee tree at epoch {target_epoch}"
            );
        }
        self.sink
            .write_witness(target_epoch, "committee", &committees.witness)?;
        write_proof(&self.sink, target_epoch, "committee", &committee_proof)?;

        let stream = SlotStream::new(
            &self.config.chain,
            committees.clone(),
            target_epoch,
            target_root,
        );

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
            acc_root: self.snapshot.state.acc_root,
            acc_commitment: self.snapshot.state.acc_commitment,
            total_active_balance: self.snapshot.state.total_active_balance,
            committees,
            committee_output,
            committee_proof,
            stream,
            next_slot: target_epoch * spe,
            scan_end: (target_epoch + self.config.attestation_lookahead_epochs) * spe,
            attesting_balance: 0,
            slot_outputs: Vec::new(),
            slot_proofs: Vec::new(),
        })
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
        let spe = self.config.chain.slots_per_epoch;
        let committees = self
            .api
            .get_committees(&(target_epoch * spe).to_string(), target_epoch)
            .await
            .context("fetch committees")?;

        crate::committee::build(
            &committees,
            validators,
            &self.snapshot.tree,
            &self.config.chain,
            target_epoch,
            target_epoch,
            self.snapshot.state.total_active_balance,
        )
    }

    /// Fold the epoch's slot proofs into a justification, and pair it with the
    /// previous one into a finalization when the two are consecutive.
    async fn close_epoch(&mut self, aggregator: EpochAggregator, tick: &mut Tick) -> Result<()> {
        let target_epoch = aggregator.target_epoch;
        let started = Instant::now();

        let witness = witness_justification::build(
            aggregator.slot_outputs,
            aggregator.slot_proofs,
            aggregator.acc_commitment,
            self.prover.program_vk(Stage::SlotProof),
            self.prover.program_vk(Stage::Committee),
            aggregator.committee_output,
            aggregator.committee_proof,
            target_epoch,
            aggregator.target_root,
            aggregator.total_active_balance,
        );

        let slots = witness.slot_proof_outputs.len();
        let (output, proof) = self.prover.prove_justification(&witness)?;
        let artifact = self
            .sink
            .write_witness(target_epoch, "justification", &witness)?;
        write_proof(&self.sink, target_epoch, "justification", &proof)?;

        let millis = started.elapsed().as_millis() as u64;
        info!(
            target_epoch,
            slots,
            attesting_balance = aggregator.attesting_balance,
            millis,
            "justified",
        );
        self.record(StageTiming::new(
            Stage::Justification,
            target_epoch,
            started,
            self.prover.last_cost(),
            artifact,
        ));

        let record = JustificationRecord {
            output: output.clone(),
            proof,
        };
        let finalized = self.try_finalize(&record).await?;

        self.snapshot.state.justified_through = Some(target_epoch);
        self.snapshot.state.attempted_epoch = Some(target_epoch);
        self.snapshot.state.last_justification = Some(record);
        if let Some(checkpoint) = &finalized {
            self.snapshot.state.finalized = Some(checkpoint.clone());
        }
        self.store.save(&self.snapshot)?;

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
        let Some(previous) = self.snapshot.state.last_justification.clone() else {
            return Ok(None);
        };
        let epoch = previous.output.target_epoch;
        if epoch + 1 != current.output.target_epoch {
            return Ok(None);
        }
        let Some(epoch_diff) = self.snapshot.state.last_epoch_diff.clone() else {
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

        // The finalized block's header, addressed by its own root. Fetching by
        // root rather than by slot is what makes this work for a checkpoint
        // whose first slot was skipped.
        let header = self
            .api
            .get_header(&crate::artifacts::hex0x(&previous.output.target_root))
            .await
            .with_context(|| format!("fetch the header of epoch {epoch}'s checkpoint block"))?;

        let started = Instant::now();
        let witness = FinalizationWitness {
            justification_program_vk: self.prover.program_vk(Stage::Justification),
            epoch_diff_program_vk: self.prover.program_vk(Stage::EpochDiff),
            finalized_header: header.fields(),
            justification_outputs: vec![previous.output.clone(), current.output.clone()],
            justification_proofs: vec![previous.proof.clone(), current.proof.clone()],
            epoch_diff_output: epoch_diff.output,
            epoch_diff_proof: epoch_diff.proof,
        };

        let (output, proof) = self.prover.prove_finalization(&witness)?;
        let artifact =
            self.sink
                .write_witness(current.output.target_epoch, "finalization", &witness)?;
        write_proof(
            &self.sink,
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
        self.record(StageTiming::new(
            Stage::Finalization,
            current.output.target_epoch,
            started,
            self.prover.last_cost(),
            artifact,
        ));

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
        self.snapshot.state.last_epoch_diff.is_some()
            && self
                .snapshot
                .state
                .previous_justification(self.snapshot.state.cursor_epoch)
                .is_some()
    }

    async fn drive_stream(&mut self, tick: &mut Tick) -> Result<()> {
        let target_epoch = self.snapshot.state.cursor_epoch;

        let mut aggregator = match self.streaming.take() {
            Some(aggregator) if aggregator.context.target_epoch == target_epoch => aggregator,
            _ => self.open_stream_epoch(target_epoch).await?,
        };

        let _span = info_span!("stream", target_epoch).entered();
        let spe = self.config.chain.slots_per_epoch;

        // Gossip is the source. Blocks repair what an outage swallowed, and are
        // the whole source when there is no stream — the fixture-replay tests.
        match &self.gossip {
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
            && self.checkpoint_root(target_epoch).await? != aggregator.context.target_root
        {
            warn!(
                target_epoch,
                "the checkpoint reorged out; reopening the epoch"
            );
            return Ok(());
        }

        let policy = self.config.stream_policy.clone();
        let total = aggregator.context.total_active_balance;
        let held = aggregator.held(spe, self.head_slot, &policy);

        // `T`: the first moment the daemon holds what the circuit would accept.
        // Everything after it is latency a consumer sees, the trigger's own wait
        // included, which is what keeps that wait honest.
        if held.balance as u128 >= policy.quorum_balance(total)
            && aggregator.crossed_unix_millis.is_none()
        {
            aggregator.crossed_unix_millis = Some(now_unix_millis());
        }

        let fire = held.balance as u128 >= policy.target_balance(total)
            && !aggregator.worth_waiting(&policy, held.filling);
        aggregator.last_filling = held
            .filling
            .map(|(slot, named)| (Instant::now(), slot, named));

        if !fire {
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
            if aggregator.exhausted(self.head_slot) {
                warn!(
                    target_epoch,
                    attesting_balance = aggregator.attesting_balance,
                    total_active_balance = total,
                    "checkpoint never reached the threshold; giving up on this epoch",
                );
                self.snapshot.state.attempted_epoch = Some(target_epoch);
                self.store.save(&self.snapshot)?;
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
        while aggregator.next_slot <= self.head_slot && aggregator.next_slot < aggregator.scan_end {
            let slot = aggregator.next_slot;
            aggregator.next_slot += 1;

            // A slot with no block is not an error; neither is one whose
            // attestations all point somewhere else.
            if let Ok(attestations) = self.api.get_block_attestations(&slot.to_string()).await {
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
        let spe = self.config.chain.slots_per_epoch;
        let target_root = self.checkpoint_root(target_epoch).await?;
        let signing_domain = self.signing_domain(target_epoch).await?;
        let validators = self
            .api
            .get_validators(&(target_epoch * spe).to_string())
            .await
            .context("fetch validators for the target epoch")?;

        let committees = Arc::new(self.build_committees(target_epoch, &validators).await?);
        let (committee_output, committee_proof) =
            self.prover.prove_committee(&committees.witness)?;
        if committee_output != committees.output {
            bail!(
                "committee circuit disagrees with the host committee tree at epoch {target_epoch}"
            );
        }
        self.sink
            .write_witness(target_epoch, "committee", &committees.witness)?;
        write_proof(&self.sink, target_epoch, "committee", &committee_proof)?;

        let stream = SlotStream::new(
            &self.config.chain,
            committees.clone(),
            target_epoch,
            target_root,
        );

        let epoch_diff = self
            .snapshot
            .state
            .last_epoch_diff
            .clone()
            .context("no epoch diff on record to open the epoch against")?;
        let (previous, previous_proof) =
            self.snapshot
                .state
                .previous_justification(target_epoch)
                .context("no justification for the previous epoch to finalize")?;

        let header = self
            .api
            .get_header(&crate::artifacts::hex0x(&previous.target_root()))
            .await
            .context("fetch the header of the epoch being finalized")?;

        let state = &self.snapshot.state;
        let context = StreamContext {
            accumulator_commitment: state.acc_commitment,
            acc_root: state.acc_root,
            total_active_balance: state.total_active_balance,
            target_epoch,
            target_root,
            signing_domain,
            group_program_vk: self.prover.program_vk(Stage::Group),
            aggregate_program_vk: self.prover.program_vk(Stage::Aggregate),
            previous_program_vk: match previous {
                PreviousJustification::Batch(_) => self.prover.program_vk(Stage::Justification),
                PreviousJustification::Stream(_) => self.prover.program_vk(Stage::StreamFinal),
            },
            epoch_diff_program_vk: self.prover.program_vk(Stage::EpochDiff),
            committee_program_vk: self.prover.program_vk(Stage::Committee),
            epoch_diff: epoch_diff.output,
            epoch_diff_proof: epoch_diff.proof,
            committee: committee_output,
            committee_proof,
            acc_depth: self.config.chain.acc_tree_depth,
        };

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
            scan_end: (target_epoch + self.config.attestation_lookahead_epochs) * spe,
            // The epoch's earlier slots were gossiped before the daemon reached
            // it, so it starts by repairing them out of blocks.
            gap: true,
            reorged: false,
            last_filling: None,
            units: Vec::new(),
            proved: 0,
            attesting_balance: 0,
            aggregate: None,
            aggregate_proof: Proof::new(),
            aggregate_miller: FP12_ONE,
            folded_groups: 0,
            previous,
            previous_proof,
            finalized_header: header.fields(),
            crossed_unix_millis: None,
        })
    }

    /// Prove one group of units. Nothing about the epoch changes until it is
    /// either folded or handed to the final proof.
    fn prove_group(
        &mut self,
        aggregator: &StreamAggregator,
        range: Range<usize>,
        tick: &mut Tick,
    ) -> Result<GroupProof> {
        let started = Instant::now();
        let target_epoch = aggregator.context.target_epoch;
        let units: Vec<&SlotComplement> = aggregator.units[range.clone()].iter().collect();
        let slots: Vec<u64> = units.iter().map(|u| u.slot).collect();

        let witness = streaming::group_witness(
            &aggregator.context,
            &self.snapshot.tree,
            &aggregator.committees,
            &units,
        );
        let (output, miller, proof) = self
            .prover
            .prove_group(&witness)
            .with_context(|| format!("group proof over slots {slots:?}"))?;

        let name = format!("group_{}", range.start);
        let artifact = self.sink.write_witness(target_epoch, &name, &witness)?;
        write_proof(&self.sink, target_epoch, &name, &proof)?;

        info!(
            slots = ?slots,
            attesting_balance = output.attesting_balance,
            millis = started.elapsed().as_millis() as u64,
            "group proof",
        );
        self.record(StageTiming::new(
            Stage::Group,
            target_epoch,
            started,
            self.prover.last_cost(),
            artifact,
        ));
        tick.slots_proved.extend(slots);

        Ok(GroupProof {
            output,
            miller,
            proof,
        })
    }

    /// Fold a finished group into the running aggregate.
    fn fold_group(&mut self, aggregator: &mut StreamAggregator, group: GroupProof) -> Result<()> {
        let started = Instant::now();
        let target_epoch = aggregator.context.target_epoch;

        let witness = streaming::aggregate_witness(
            &aggregator.context,
            aggregator.aggregate.clone(),
            std::mem::take(&mut aggregator.aggregate_proof),
            aggregator.aggregate_miller,
            vec![group.output],
            vec![group.proof],
            vec![group.miller],
        );
        let (output, proof) = self.prover.prove_aggregate(&witness)?;

        let name = format!("aggregate_{}", aggregator.folded_groups);
        let artifact = self.sink.write_witness(target_epoch, &name, &witness)?;
        write_proof(&self.sink, target_epoch, &name, &proof)?;

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
        self.record(StageTiming::new(
            Stage::Aggregate,
            target_epoch,
            started,
            self.prover.last_cost(),
            artifact,
        ));
        Ok(())
    }

    /// The only proof on the critical path: the marginal attestation, the one
    /// final exponentiation, and the previous epoch's justification, at once.
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

        let (groups, group_proofs, group_millers) = match late {
            Some(g) => (vec![g.output], vec![g.proof], vec![g.miller]),
            None => (Vec::new(), Vec::new(), Vec::new()),
        };
        let late_groups = groups.len();

        let witness = streaming::final_witness(
            &aggregator.context,
            &self.snapshot.tree,
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
            aggregator.finalized_header.clone(),
        );

        let (output, proof) = self.prover.prove_stream_final(&witness)?;
        let proof_unix_millis = now_unix_millis();

        let artifact = self
            .sink
            .write_witness(target_epoch, "stream_final", &witness)?;
        write_proof(&self.sink, target_epoch, "stream_final", &proof)?;

        info!(
            justified_epoch = output.justified_epoch,
            finalized_epoch = output.finalized_epoch,
            finalized_root = %crate::artifacts::hex0x(&output.finalized_root),
            millis = started.elapsed().as_millis() as u64,
            "epoch closed",
        );
        self.record(StageTiming::new(
            Stage::StreamFinal,
            target_epoch,
            started,
            self.prover.last_cost(),
            artifact,
        ));

        // A proof of a checkpoint the chain no longer has is worse than no proof
        // at all, so the root is re-resolved before anything is published. This
        // is after `T2` by construction — the proof exists — so it costs
        // publication latency and never a stale publication.
        if self.checkpoint_root(target_epoch).await? != aggregator.context.target_root {
            warn!(
                target_epoch,
                "the checkpoint reorged out while the final proof ran; discarding it",
            );
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
                tail_named: tail.iter().map(|u| u.named_indices.len()).sum(),
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
            if self.latencies.len() == RECENT_LATENCIES {
                self.latencies.pop_front();
            }
            self.latencies.push_back(latency);
        }

        let finalized = Checkpoint {
            epoch: output.finalized_epoch,
            root: output.finalized_root,
        };
        self.snapshot.state.justified_through = Some(target_epoch);
        self.snapshot.state.attempted_epoch = Some(target_epoch);
        self.snapshot.state.last_stream_final = Some(StreamFinalRecord { output, proof });
        self.snapshot.state.finalized = Some(finalized.clone());
        self.streaming = None;
        self.store.save(&self.snapshot)?;

        tick.justified = Some(target_epoch);
        tick.finalized = Some(finalized);
        Ok(())
    }

    // -----------------------------------------------------------------
    // Chain queries
    // -----------------------------------------------------------------

    /// Block root of the checkpoint for `epoch`.
    ///
    /// The checkpoint root is the block at the epoch's first slot, or — when
    /// that slot was skipped — the most recent block before it.
    async fn checkpoint_root(&self, epoch: u64) -> Result<[u8; 32]> {
        let spe = self.config.chain.slots_per_epoch;
        let first = epoch * spe;
        let floor = first.saturating_sub(spe);
        for slot in (floor..=first).rev() {
            if let Some(root) = self
                .api
                .get_block_root(&slot.to_string())
                .await
                .with_context(|| format!("fetch block root at slot {slot}"))?
            {
                return Ok(root);
            }
        }
        bail!("no block found in the epoch before slot {first}; cannot resolve the checkpoint root")
    }

    /// Domain attestations for `epoch` were signed under.
    async fn signing_domain(&mut self, epoch: u64) -> Result<[u8; 32]> {
        if let Some(domain) = self.config.signing_domain {
            return Ok(domain);
        }
        let state_id = (epoch * self.config.chain.slots_per_epoch).to_string();
        let genesis_validators_root = match self.genesis_validators_root {
            Some(root) => root,
            None => {
                let root = self
                    .api
                    .get_genesis_validators_root()
                    .await
                    .context("fetch genesis validators root")?;
                self.genesis_validators_root = Some(root);
                root
            }
        };
        let fork_version = self
            .api
            .get_fork_version(&state_id)
            .await
            .context("fetch fork version")?;
        Ok(compute_domain(
            &DOMAIN_BEACON_ATTESTER,
            &fork_version,
            &genesis_validators_root,
        ))
    }

    // -----------------------------------------------------------------
    // Manifest
    // -----------------------------------------------------------------

    fn record(&mut self, timing: StageTiming) {
        if self.recent.len() == RECENT_STAGES {
            self.recent.pop_front();
        }
        self.recent.push_back(timing);
    }

    pub fn publish_status(&self) -> Result<()> {
        let state = &self.snapshot.state;
        self.sink.write_status(&Status {
            version: 1,
            chain: state.chain.clone(),
            prover: self.prover.name().to_string(),
            updated_unix: now_unix(),
            head_slot: self.head_slot,
            bootstrap_epoch: state.bootstrap_epoch,
            accumulator: AccStatus {
                epoch: state.cursor_epoch,
                root: hex_digest(&state.acc_root),
                commitment: hex_digest(&state.acc_commitment),
                chain_digest: hex_digest(&state.acc_chain_digest),
                total_active_balance: state.total_active_balance,
                num_validators: state.num_validators,
            },
            justified_through: state.justified_through,
            last_justified: state
                .last_justification
                .as_ref()
                .map(|r| justified_checkpoint(&r.output)),
            last_finalized: state.finalized.as_ref().map(CheckpointStatus::from),
            node_finalized: self.node_finalized.as_ref().map(CheckpointStatus::from),
            recent_stages: self.recent.iter().cloned().collect(),
            recent_latencies: self.latencies.iter().cloned().collect(),
            gossip: self.gossip.as_ref().map(|source| {
                let counters = source.counters();
                GossipStatus {
                    attestations: counters.attestations,
                    reconnects: counters.reconnects,
                    dropped: counters.dropped,
                }
            }),
        })
    }
}

fn justified_checkpoint(output: &JustificationOutput) -> CheckpointStatus {
    CheckpointStatus {
        epoch: output.target_epoch,
        root: crate::artifacts::hex0x(&output.target_root),
    }
}

/// Persist a proof next to the witness it proves.
///
/// A witness-only run produces no proof words, so this writes nothing until a
/// real prover is wired into [`Prover`].
fn write_proof(sink: &ArtifactSink, epoch: u64, name: &str, proof: &Proof) -> Result<()> {
    if proof.is_empty() {
        return Ok(());
    }
    sink.write_witness(epoch, &format!("{name}_proof"), proof)
        .map(|_: ArtifactRef| ())
}

fn percent_of(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    part as f64 * 100.0 / whole as f64
}

/// Present the accumulator's cached SSZ view, for callers that want to inspect
/// what the next epoch diff will build on.
impl<A> Orchestrator<A> {
    pub fn epoch_state(&self) -> &EpochState {
        &self.snapshot.epoch_state
    }

    pub fn api(&self) -> &A {
        &self.api
    }
}
