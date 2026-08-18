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
//! What is not here yet is parallelism: groups are proved one at a time, in
//! order, on the calling task. The aggregator does not depend on that — it takes
//! outputs and proofs and does not care which order they were produced in — so
//! handing the prover to a pool of GPUs is a change to this file only.
use std::ops::Range;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use tracing::{info, info_span, instrument, warn};

use zkasper_common::bls::{fp12_mul, Fp12, FP12_ONE};
use zkasper_common::types::{
    AggregateOutput, BoundaryAnchor, Checkpoint, GroupProofOutput, PreviousJustification,
};

use crate::artifacts::{
    now_unix_millis, CheckpointStatus, CurrentEpoch, EpochLatency, StageTiming,
};
use crate::attestation_collector::{SlotComplement, SlotStream};
use crate::beacon_api::{BeaconApi, ChainStatusApi};
use crate::committee::EpochCommittees;
use crate::prover::{Proof, Stage};
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

/// The streaming pipeline, and the one epoch it may have part-built.
#[derive(Default)]
pub(super) struct StreamPipeline {
    aggregator: Option<StreamAggregator>,
}

impl EpochPipeline for StreamPipeline {
    async fn drive<A: BeaconApi + ChainStatusApi>(
        &mut self,
        engine: &mut Engine<A>,
        tick: &mut Tick,
    ) -> Result<()> {
        let target_epoch = engine.snapshot.state.cursor_epoch;

        let mut aggregator = match self.aggregator.take() {
            Some(aggregator) if aggregator.context.target_epoch == target_epoch => aggregator,
            _ => Self::open(engine, target_epoch).await?,
        };

        let _span = info_span!("stream", target_epoch).entered();
        let spe = engine.config.chain.slots_per_epoch;

        // Gossip is the source. Blocks repair what an outage swallowed, and are
        // the whole source when there is no stream — the fixture-replay tests.
        match &engine.gossip {
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
            Self::repair_from_blocks(engine, &mut aggregator).await?;
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
            return Ok(());
        }

        let policy = engine.config.stream_policy.clone();
        let total = aggregator.context.total_active_balance;
        let held = aggregator.held(spe, engine.chain.head_slot(), &policy);

        // `T`: the first moment the daemon holds what the circuit would accept.
        // Everything after it is latency a consumer sees, the trigger's own wait
        // included, which is what keeps that wait honest.
        if held.balance as u128 >= policy.quorum_balance(total)
            && aggregator.crossed_unix_millis.is_none()
        {
            let crossed = now_unix_millis();
            aggregator.crossed_unix_millis = Some(crossed);
            if let Some(publish) = engine.report.publisher() {
                publish.threshold_crossed(target_epoch, crossed, held.balance, total);
            }
        }

        let fire = held.balance as u128 >= policy.target_balance(total)
            && !aggregator.worth_waiting(&policy, held.filling);
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
            if aggregator.proved < aggregator.units.len() {
                let group = Self::prove_group(
                    engine,
                    &aggregator,
                    aggregator.proved..aggregator.units.len(),
                    tick,
                )?;
                Self::fold_group(engine, &mut aggregator, group)?;
            }
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
                tick.gave_up_on = Some(target_epoch);
            } else {
                self.aggregator = Some(aggregator);
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
            .then(|| Self::prove_group(engine, &aggregator, aggregator.proved..crossing, tick))
            .transpose()?;
        self.close(engine, aggregator, late, crossing, tick).await
    }

    fn forget(&mut self) {
        self.aggregator = None;
    }
}

impl StreamPipeline {
    /// Fill in from blocks what gossip did not deliver.
    ///
    /// Only two things need it: an epoch that opened after its own attestations
    /// were gossiped, and a stream that dropped. Both are repairs — the union of
    /// a block and a gossip view of a slot is the gossip view, because the
    /// collector converges on an attester set rather than a list.
    async fn repair_from_blocks<A: BeaconApi + ChainStatusApi>(
        engine: &mut Engine<A>,
        aggregator: &mut StreamAggregator,
    ) -> Result<()> {
        while aggregator.next_slot <= engine.chain.head_slot()
            && aggregator.next_slot < aggregator.scan_end
        {
            let slot = aggregator.next_slot;
            aggregator.next_slot += 1;

            // A slot with no block is not an error; neither is one whose
            // attestations all point somewhere else.
            if let Ok(attestations) = engine.api.get_block_attestations(&slot.to_string()).await {
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
    async fn open<A: BeaconApi + ChainStatusApi>(
        engine: &mut Engine<A>,
        target_epoch: u64,
    ) -> Result<StreamAggregator> {
        let spe = engine.config.chain.slots_per_epoch;
        let OpenEpoch {
            target_root,
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
    fn prove_group<A: BeaconApi + ChainStatusApi>(
        engine: &mut Engine<A>,
        aggregator: &StreamAggregator,
        range: Range<usize>,
        tick: &mut Tick,
    ) -> Result<GroupProof> {
        let started = Instant::now();
        let target_epoch = aggregator.context.target_epoch;
        engine
            .report
            .begin(Stage::Group, target_epoch, None, Some(range.start));
        let units: Vec<&SlotComplement> = aggregator.units[range.clone()].iter().collect();
        let slots: Vec<u64> = units.iter().map(|u| u.slot).collect();
        if let Some(&last) = slots.last() {
            engine
                .chain
                .observe_start_delay(&engine.config, Stage::Group, target_epoch, last);
        }

        let witness = streaming::group_witness(
            &aggregator.context,
            &engine.snapshot.tree,
            &aggregator.committees,
            &units,
        );
        let (output, miller, proof) = engine
            .prover
            .prove_group(&witness)
            .with_context(|| format!("group proof over slots {slots:?}"))?;

        let name = format!("group_{}", range.start);
        let artifact = engine.sink.write_witness(target_epoch, &name, &witness)?;
        write_proof(&engine.sink, target_epoch, &name, &proof)?;

        info!(
            slots = ?slots,
            attesting_balance = output.attesting_balance,
            millis = started.elapsed().as_millis() as u64,
            "group proof",
        );
        engine.report.record(
            StageTiming::new(
                Stage::Group,
                target_epoch,
                started,
                engine.prover.last_cost(),
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
    fn fold_group<A: BeaconApi + ChainStatusApi>(
        engine: &mut Engine<A>,
        aggregator: &mut StreamAggregator,
        group: GroupProof,
    ) -> Result<()> {
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

        let witness = streaming::aggregate_witness(
            &aggregator.context,
            aggregator.aggregate.clone(),
            std::mem::take(&mut aggregator.aggregate_proof),
            aggregator.aggregate_miller,
            vec![group.output],
            vec![group.proof],
            vec![group.miller],
        );
        let (output, proof) = engine.prover.prove_aggregate(&witness)?;

        let name = format!("aggregate_{}", aggregator.folded_groups);
        let artifact = engine.sink.write_witness(target_epoch, &name, &witness)?;
        write_proof(&engine.sink, target_epoch, &name, &proof)?;

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
        engine.report.record(
            StageTiming::new(
                Stage::Aggregate,
                target_epoch,
                started,
                engine.prover.last_cost(),
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
    async fn close<A: BeaconApi + ChainStatusApi>(
        &mut self,
        engine: &mut Engine<A>,
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
        if let Some(publish) = engine.report.publisher() {
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
        );

        let (output, proof) = engine.prover.prove_stream_final(&witness)?;
        let proof_unix_millis = now_unix_millis();

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
            .write_witness(target_epoch, "stream_final", &witness)?;
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
            StageTiming::new(
                Stage::StreamFinal,
                target_epoch,
                started,
                engine.prover.last_cost(),
                artifact,
            )
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
