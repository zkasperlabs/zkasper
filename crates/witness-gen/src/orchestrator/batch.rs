//! The batch pipeline: one slot proof per slot, folded when the epoch is over.
//!
//! Attestations come out of blocks here, which puts the walk a slot behind the
//! chain by construction — an attestation is gossiped in the slot it is made
//! and included one or more slots later. That is the price of needing nothing
//! but the beacon API, and it is why [`super::stream`] exists.
//!
//! It is also the only path an epoch with nothing before it can take: a
//! streaming epoch consumes the previous epoch's justification and the diff
//! that links the two accumulators, and the first epoch of a run has neither.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use tracing::{info, info_span, instrument, warn};

use zkasper_common::acc::Digest;
use zkasper_common::types::{
    Checkpoint, CommitteeOutput, FinalizationWitness, SlotProofOutput, SlotProofWitness,
};

use crate::artifacts::{hex_digest, StageTiming};
use crate::attestation_collector::SlotStream;
use crate::beacon_api::{BeaconApi, ChainStatusApi};
use crate::committee::EpochCommittees;
use crate::prover::{Proof, Prover, Stage};
use crate::publish::{self, ClosedEpoch};
use crate::store::JustificationRecord;
use crate::witness_justification;

use super::engine::{write_proof, Engine, OpenEpoch};
use super::pipeline::EpochPipeline;
use super::reporter::{acc_status, justified_checkpoint, percent_of};
use super::Tick;

/// One epoch's justification, part-built.
///
/// Lives across ticks: slots are folded in as the node publishes them, and the
/// epoch finishes the moment the counted balance crosses 2/3.
///
/// The fold is incremental. A slot proof joins `unfolded`, and once
/// [`OrchestratorConfig::justification_fold_width`] of them are waiting they
/// become one more link of the justification chain — during the epoch, against
/// attestations that already arrived. What is left when the threshold crosses
/// is one link over a handful of children rather than one proof over all of
/// them.
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
    /// The justification chain so far, absent until the first link is proven.
    justification: Option<JustificationRecord>,
    /// Slot proofs the chain has not absorbed yet.
    unfolded: Vec<SlotProofOutput>,
    unfolded_proofs: Vec<Proof>,
    /// Slot proofs proven for this epoch, counted rather than kept: it numbers
    /// their stage timings, and the proofs themselves leave for the chain.
    slots_proven: usize,
    /// Links of the justification chain proven so far, numbering theirs.
    folds: usize,
}

impl EpochAggregator {
    /// Casper's 2/3 rule, in u128 so a mainnet-sized balance cannot overflow.
    fn threshold_reached(&self) -> bool {
        self.attesting_balance as u128 * 3 >= self.total_active_balance as u128 * 2
    }

    fn exhausted(&self) -> bool {
        self.next_slot >= self.scan_end
    }

    /// What every link of this epoch's justification chain shares.
    fn justification_context(&self, prover: &dyn Prover) -> witness_justification::Context {
        witness_justification::Context {
            accumulator_commitment: self.acc_commitment,
            acc_root: self.acc_root,
            target_epoch: self.target_epoch,
            target_root: self.target_root,
            total_active_balance: self.total_active_balance,
            slot_program_vk: prover.program_vk(Stage::SlotProof),
            committee_program_vk: prover.program_vk(Stage::Committee),
            justification_program_vk: prover.program_vk(Stage::Justification),
        }
    }
}

/// The batch pipeline, and the one epoch it may have part-built.
#[derive(Default)]
pub(super) struct BatchPipeline {
    pending: Option<EpochAggregator>,
}

impl EpochPipeline for BatchPipeline {
    async fn drive<A: BeaconApi + ChainStatusApi>(
        &mut self,
        engine: &mut Engine<A>,
        tick: &mut Tick,
    ) -> Result<()> {
        let target_epoch = engine.snapshot.state.cursor_epoch;
        let spe = engine.config.chain.slots_per_epoch;

        let mut aggregator = match self.pending.take() {
            Some(aggregator) if aggregator.target_epoch == target_epoch => aggregator,
            _ => Self::open(engine, target_epoch).await?,
        };

        let _span = info_span!("aggregate", target_epoch).entered();

        while !aggregator.threshold_reached()
            && !aggregator.exhausted()
            && aggregator.next_slot <= engine.chain.head_slot()
        {
            let slot = aggregator.next_slot;
            aggregator.next_slot += 1;

            // A slot with no block is not an error; neither is one whose
            // attestations all point somewhere else.
            if let Ok(attestations) = engine.api.get_block_attestations(&slot.to_string()).await {
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
            engine.chain.observe_start_delay(
                &engine.config,
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
            let index = aggregator.slots_proven;
            engine.report.begin(
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
                acc_multi_proof: engine
                    .snapshot
                    .tree
                    .build_multi_proof(&complement.named_indices),
                committee_multi_proof: aggregator
                    .committees
                    .multi_proof(&[complement.witness.slot_in_epoch]),
                slots: vec![complement.witness],
            };

            let (output, proof) = engine
                .prover
                .prove_slot(&witness)
                .with_context(|| format!("slot proof for attestation slot {attestation_slot}"))?;

            let artifact = engine.sink.write_witness(
                target_epoch,
                &format!("slot_proof_{attestation_slot}"),
                &witness,
            )?;
            write_proof(
                &engine.sink,
                target_epoch,
                &format!("slot_proof_{attestation_slot}"),
                &proof,
            )?;

            aggregator.attesting_balance += output.attesting_balance;
            aggregator.unfolded.push(output);
            aggregator.unfolded_proofs.push(proof);
            aggregator.slots_proven += 1;

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
            engine.report.record(
                StageTiming::new(
                    Stage::SlotProof,
                    target_epoch,
                    started,
                    engine.prover.last_cost(),
                    artifact,
                )
                .at_slot(attestation_slot)
                .at_index(index)
                .with_proof(aggregator.unfolded_proofs.last().expect("just pushed")),
            );
            tick.slots_proved.push(attestation_slot);

            // Fold what has piled up, unless the epoch is over: the link that
            // closes it takes the rest, and one link is cheaper than two.
            if aggregator.unfolded.len() >= engine.config.justification_fold_width
                && !aggregator.threshold_reached()
            {
                Self::fold_justification(engine, &mut aggregator).await?;
            }
        }

        if aggregator.threshold_reached() {
            Self::close(engine, aggregator, tick).await?;
        } else if aggregator.exhausted() {
            // Two epochs of blocks went by without 2/3 voting for this
            // checkpoint. The chain did not justify it, so neither can we.
            warn!(
                target_epoch,
                attesting_balance = aggregator.attesting_balance,
                total_active_balance = aggregator.total_active_balance,
                "checkpoint never reached the 2/3 threshold; giving up on this epoch",
            );
            if let Some(publish) = engine.report.publisher() {
                publish.epoch_abandoned(target_epoch, "never reached the threshold");
            }
            crate::metrics::epoch_abandoned("threshold");
            self.pending = None;
            engine.snapshot.state.attempted_epoch = Some(target_epoch);
            engine.store.save(&engine.snapshot)?;
            tick.gave_up_on = Some(target_epoch);
        } else {
            // Waiting for the node to publish more blocks. Keep the partial
            // aggregation so the next tick resumes mid-epoch.
            self.pending = Some(aggregator);
        }
        Ok(())
    }

    fn forget(&mut self) {
        self.pending = None;
    }
}

impl BatchPipeline {
    /// Start a new epoch's aggregation against the accumulator as it stands.
    async fn open<A: BeaconApi + ChainStatusApi>(
        engine: &mut Engine<A>,
        target_epoch: u64,
    ) -> Result<EpochAggregator> {
        let spe = engine.config.chain.slots_per_epoch;
        let OpenEpoch {
            target_root,
            signing_domain,
            committees,
            committee_output,
            committee_proof,
            stream,
        } = engine.open_epoch(target_epoch).await?;

        if let Some(publish) = engine.report.publisher() {
            publish.epoch_opened(
                target_epoch,
                &target_root,
                target_epoch.saturating_sub(1),
                engine.snapshot.state.total_active_balance,
                serde_json::to_value(acc_status(&engine.snapshot.state))?,
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
            acc_root: engine.snapshot.state.acc_root,
            acc_commitment: engine.snapshot.state.acc_commitment,
            total_active_balance: engine.snapshot.state.total_active_balance,
            committees,
            committee_output,
            committee_proof,
            stream,
            next_slot: target_epoch * spe,
            scan_end: (target_epoch + engine.config.attestation_lookahead_epochs) * spe,
            attesting_balance: 0,
            justification: None,
            unfolded: Vec::new(),
            unfolded_proofs: Vec::new(),
            slots_proven: 0,
            folds: 0,
        })
    }

    /// Absorb the slot proofs waiting on the aggregator into its justification
    /// chain, and leave the chain one link longer.
    ///
    /// This is the whole of the incremental fold. It runs during the epoch
    /// rather than after it, so by the time the threshold crosses the chain is
    /// already most of the way built and the link that closes the epoch is the
    /// same size as every other.
    #[instrument(
        name = "stage",
        skip_all,
        fields(stage = "justification", epoch = aggregator.target_epoch),
    )]
    async fn fold_justification<A: BeaconApi + ChainStatusApi>(
        engine: &mut Engine<A>,
        aggregator: &mut EpochAggregator,
    ) -> Result<()> {
        let target_epoch = aggregator.target_epoch;
        let index = aggregator.folds;
        let started = Instant::now();
        engine
            .report
            .begin(Stage::Justification, target_epoch, None, Some(index));

        let previous = aggregator.justification.take();
        // Only the link that opens the epoch carries the committee proof; every
        // later one inherits the root it published.
        let (committee, committee_proof) = match &previous {
            Some(_) => (None, Vec::new()),
            None => (
                Some(aggregator.committee_output.clone()),
                aggregator.committee_proof.clone(),
            ),
        };
        let (previous_output, previous_proof) = match previous {
            Some(record) => (Some(record.output), record.proof),
            None => (None, Vec::new()),
        };

        let children = aggregator.unfolded.len();
        let witness = witness_justification::build(
            &aggregator.justification_context(engine.prover.as_ref()),
            committee,
            committee_proof,
            previous_output,
            previous_proof,
            std::mem::take(&mut aggregator.unfolded),
            std::mem::take(&mut aggregator.unfolded_proofs),
        );

        let (output, proof) = engine
            .prover
            .prove_justification(&witness)
            .with_context(|| format!("justification fold {index} of epoch {target_epoch}"))?;
        let name = format!("justification_{index}");
        let artifact = engine.sink.write_witness(target_epoch, &name, &witness)?;
        write_proof(&engine.sink, target_epoch, &name, &proof)?;

        let millis = started.elapsed().as_millis() as u64;
        info!(
            target_epoch,
            index,
            children,
            attesting_balance = output.attesting_balance,
            justified = output.justified,
            millis,
            "justification fold",
        );
        engine.report.record(
            StageTiming::new(
                Stage::Justification,
                target_epoch,
                started,
                engine.prover.last_cost(),
                artifact,
            )
            .at_index(index)
            .with_proof(&proof),
        );

        aggregator.justification = Some(JustificationRecord { output, proof });
        aggregator.folds += 1;
        Ok(())
    }

    /// Close the epoch's justification chain, and pair it with the previous
    /// epoch's into a finalization when the two are consecutive.
    async fn close<A: BeaconApi + ChainStatusApi>(
        engine: &mut Engine<A>,
        mut aggregator: EpochAggregator,
        tick: &mut Tick,
    ) -> Result<()> {
        let target_epoch = aggregator.target_epoch;

        // The link that crosses the threshold. Whatever the epoch proved since
        // the last fold is still waiting, so this always has something to
        // absorb — the loop stops folding once the balance is there.
        Self::fold_justification(engine, &mut aggregator).await?;
        let record = aggregator
            .justification
            .take()
            .expect("the closing fold leaves a justification");

        // The circuit computes the supermajority rather than asserting it, so
        // that a partial fold can be a valid proof. A closing fold that comes
        // back unjustified means the host counted a balance the circuit did
        // not, which is a bug rather than a chain event.
        if !record.output.justified {
            bail!(
                "epoch {target_epoch} closed with {} of {} attesting, which the circuit does \
                 not call a supermajority",
                record.output.attesting_balance,
                aggregator.total_active_balance,
            );
        }
        info!(
            target_epoch,
            slots = aggregator.slots_proven,
            folds = aggregator.folds,
            attesting_balance = record.output.attesting_balance,
            "justified",
        );

        let finalized = Self::try_finalize(engine, &record).await?;

        // The first epoch of a run has nothing before it to finalize, so its
        // justification is the only proof it will ever have. Publishing it as
        // the epoch's proof is what keeps that epoch from sitting open forever.
        if finalized.is_none() {
            let cost = engine.report.take_cost(target_epoch);
            if let Some(publish) = engine.report.publisher() {
                let vk = engine.prover.program_vk(Stage::Justification);
                let publics = record.output.public_bytes();
                let reference = publish::proof_ref(
                    target_epoch,
                    Stage::Justification,
                    &record.proof,
                    &vk,
                    &publics,
                    engine
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
                    accumulator: serde_json::to_value(acc_status(&engine.snapshot.state))?,
                    latency: None,
                    proof: reference,
                    public_inputs: inputs,
                });
            }
        }

        crate::metrics::epoch_justified();
        engine.snapshot.state.justified_through = Some(target_epoch);
        engine.snapshot.state.attempted_epoch = Some(target_epoch);
        engine.snapshot.state.last_justification = Some(record);
        if let Some(checkpoint) = &finalized {
            engine.snapshot.state.finalized = Some(checkpoint.clone());
        }
        engine.store.save(&engine.snapshot)?;

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
    async fn try_finalize<A: BeaconApi + ChainStatusApi>(
        engine: &mut Engine<A>,
        current: &JustificationRecord,
    ) -> Result<Option<Checkpoint>> {
        let Some(previous) = engine.snapshot.state.last_justification.clone() else {
            return Ok(None);
        };
        let epoch = previous.output.target_epoch;
        if epoch + 1 != current.output.target_epoch {
            return Ok(None);
        }
        let Some(epoch_diff) = engine.snapshot.state.last_epoch_diff.clone() else {
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
            &engine.api,
            &engine.config.chain,
            &current.output.target_root,
            epoch,
            &previous.output.target_root,
            &epoch_diff.output.state_root_1,
            &engine.snapshot.epoch_state,
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
        engine
            .report
            .begin(Stage::Finalization, current.output.target_epoch, None, None);
        let witness = FinalizationWitness {
            justification_program_vk: engine.prover.program_vk(Stage::Justification),
            epoch_diff_program_vk: engine.prover.program_vk(Stage::EpochDiff),
            boundary,
            justification_outputs: vec![previous.output.clone(), current.output.clone()],
            justification_proofs: vec![previous.proof.clone(), current.proof.clone()],
            epoch_diff_output: epoch_diff.output,
            epoch_diff_proof: epoch_diff.proof,
        };

        let (output, proof) = engine.prover.prove_finalization(&witness)?;
        let artifact =
            engine
                .sink
                .write_witness(current.output.target_epoch, "finalization", &witness)?;
        write_proof(
            &engine.sink,
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
        engine.report.record(
            StageTiming::new(
                Stage::Finalization,
                current.output.target_epoch,
                started,
                engine.prover.last_cost(),
                artifact,
            )
            .with_proof(&proof),
        );

        let cost = engine.report.take_cost(current.output.target_epoch);
        if let Some(publish) = engine.report.publisher() {
            let epoch = current.output.target_epoch;
            let vk = engine.prover.program_vk(Stage::Finalization);
            let reference = publish::proof_ref(
                epoch,
                Stage::Finalization,
                &proof,
                &vk,
                &output.public_bytes(),
                engine.prover.program_digest(Stage::Finalization).as_deref(),
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
                accumulator: serde_json::to_value(acc_status(&engine.snapshot.state))?,
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
}
