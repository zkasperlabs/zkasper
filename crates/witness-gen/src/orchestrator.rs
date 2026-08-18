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
//! to 24 of a mainnet epoch — rather than waiting for the epoch to end. The
//! aggregation here is written that way: [`EpochAggregator`] holds the running
//! dedup set and attesting balance across ticks, consumes whatever slots the
//! node has published so far, and stops the instant the threshold is crossed.
//! Slots past that point are never fetched.
//!
//! What is not here yet is parallelism: slots are proved one at a time, in
//! order, on the calling task. The aggregator does not depend on that — it takes
//! `(slot, output, proof)` triples and does not care which order they were
//! produced in — so handing [`Prover::prove_slot`] to a pool of GPUs is a change
//! to this file only.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tracing::{info, info_span, warn};

use zkasper_common::acc::Digest;
use zkasper_common::bls::{compute_domain, DOMAIN_BEACON_ATTESTER};
use zkasper_common::types::{
    Checkpoint, CommitteeOutput, FinalizationWitness, JustificationOutput, SlotProofOutput,
    SlotProofWitness,
};
use zkasper_common::ChainConfig;

use crate::acc_tree::AccTree;
use crate::artifacts::{
    hex_digest, now_unix, AccStatus, ArtifactRef, ArtifactSink, CheckpointStatus, StageTiming,
    Status,
};
use crate::attestation_collector::SlotStream;
use crate::beacon_api::{BeaconApi, ChainStatusApi, ValidatorResponse};
use crate::committee::EpochCommittees;
use crate::epoch_state::EpochState;
use crate::prover::{Proof, Prover, Stage};
use crate::store::{EpochDiffRecord, JustificationRecord, Snapshot, Store, StoreState};
use crate::{witness_bootstrap, witness_epoch_diff, witness_justification};

/// How many stage timings the manifest keeps.
const RECENT_STAGES: usize = 64;

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
    /// How many epochs past the target to keep looking for its attestations.
    pub attestation_lookahead_epochs: u64,
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
            attestation_lookahead_epochs: 2,
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

pub struct Orchestrator<A> {
    api: A,
    config: OrchestratorConfig,
    store: Store,
    sink: ArtifactSink,
    prover: Box<dyn Prover>,
    snapshot: Snapshot,
    pending: Option<EpochAggregator>,
    recent: VecDeque<StageTiming>,
    head_slot: u64,
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
            api,
            config,
            store,
            sink,
            prover,
            snapshot,
            pending: None,
            recent: VecDeque::new(),
            head_slot: 0,
            node_finalized: None,
            genesis_validators_root: None,
        }
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
    pub async fn run(&mut self) -> Result<()> {
        loop {
            self.catch_up().await?;
            tokio::time::sleep(self.config.poll_interval).await;
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
            self.drive_aggregation(&mut tick).await?;
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

    async fn refresh_chain_view(&mut self) -> Result<()> {
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
            StageTiming {
                stage: Stage::Bootstrap.as_str().to_string(),
                epoch,
                slot: None,
                millis: started.elapsed().as_millis() as u64,
                artifact: Some(artifact),
            },
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
        self.record(StageTiming {
            stage: Stage::EpochDiff.as_str().to_string(),
            epoch: to_epoch,
            slot: None,
            millis,
            artifact: Some(artifact),
        });
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
            self.record(StageTiming {
                stage: Stage::SlotProof.as_str().to_string(),
                epoch: target_epoch,
                slot: Some(attestation_slot),
                millis,
                artifact: Some(artifact),
            });
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
        self.record(StageTiming {
            stage: Stage::Justification.as_str().to_string(),
            epoch: target_epoch,
            slot: None,
            millis,
            artifact: Some(artifact),
        });

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
        self.record(StageTiming {
            stage: Stage::Finalization.as_str().to_string(),
            epoch: current.output.target_epoch,
            slot: None,
            millis,
            artifact: Some(artifact),
        });

        Ok(Some(Checkpoint {
            epoch: output.finalized_epoch,
            root: output.finalized_root,
        }))
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
