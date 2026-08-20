//! What every stage needs, whichever pipeline is driving.
//!
//! The node, the prover, the accumulator, and the two places a result goes.
//! Grouped here so that a pipeline can be handed all of it without also being
//! handed the other pipeline's half-built epoch: [`super::batch`] and
//! [`super::stream`] each own their own aggregation and share nothing but this.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use tracing::{info, instrument, warn};

use zkasper_common::types::CommitteeOutput;

use crate::artifacts::{ArtifactRef, ArtifactSink, StageTiming};
use crate::attestation_collector::SlotStream;
use crate::beacon_api::{BeaconApi, ChainStatusApi};
use crate::boundary_cache::{self, BoundaryCache, BoundaryInputs};
use crate::committee::EpochCommittees;
use crate::gossip::AttestationSource;
use crate::prover::{Proof, Prover, Stage};
use crate::store::{Snapshot, Store};
use crate::witness_epoch_diff;

use super::chain_view::ChainView;
use super::reporter::Reporter;
use super::speculation::{self, AheadCommittee, Speculation};
use super::OrchestratorConfig;

/// How many epoch boundaries one hold may take off the node.
///
/// Four. The cursor runs a couple of epochs behind the head by construction —
/// an epoch cannot be justified before its attestations exist — and a run that
/// stalls falls further, so taking one boundary a hold would never close the
/// gap. Taking every missing one would spend an epoch fetching after a long
/// outage, on a tick that is supposed to return.
const HOLD_AHEAD: usize = 4;

/// The wiring a stage runs on.
pub(super) struct Engine<A> {
    pub(super) api: A,
    pub(super) config: OrchestratorConfig,
    pub(super) store: Store,
    pub(super) sink: ArtifactSink,
    /// Shared rather than owned because [`Speculation`] proves the next epoch
    /// on a thread of its own, against the same prover.
    pub(super) prover: Arc<dyn Prover>,
    pub(super) snapshot: Snapshot,
    /// Where the node is, and the clock the schedule is measured against.
    pub(super) chain: ChainView,
    /// Where this run's own numbers go.
    pub(super) report: Reporter,
    /// Attestation gossip, when the daemon was given a node to follow it from.
    pub(super) gossip: Option<Box<dyn AttestationSource>>,
    /// Epoch boundaries this run took while the node still served them.
    pub(super) boundaries: BoundaryCache,
    /// The next epoch's diff and committee proof, in flight or waiting to be
    /// adopted. See [`super::speculation`].
    pub(super) ahead: Speculation,
}

/// Persist a proof next to the witness it proves.
///
/// A witness-only run produces no proof words, so this writes nothing until a
/// real prover is wired into [`Prover`].
pub(super) fn write_proof(
    sink: &ArtifactSink,
    epoch: u64,
    name: &str,
    proof: &Proof,
) -> Result<()> {
    if proof.is_empty() {
        return Ok(());
    }
    sink.write_witness(epoch, &format!("{name}_proof"), proof)
        .map(|_: ArtifactRef| ())
}

/// Everything an epoch needs before its first proof, whichever pipeline is
/// about to prove it: what the epoch is about, and the committee proof that
/// every later proof of it counts against.
pub(super) struct OpenEpoch {
    pub(super) target_root: [u8; 32],
    /// Checkpoint of the epoch before this one: the FFG source every
    /// attestation counted here has to name, and the checkpoint a proof of this
    /// epoch finalizes.
    pub(super) source_root: [u8; 32],
    pub(super) signing_domain: [u8; 32],
    pub(super) committees: Arc<EpochCommittees>,
    pub(super) committee_output: CommitteeOutput,
    pub(super) committee_proof: Proof,
    pub(super) stream: SlotStream,
}

impl<A: BeaconApi + ChainStatusApi> Engine<A> {
    /// The registry and the committees at `slot`, from what this run took while
    /// the node still had that state, or off the node if it never took it.
    ///
    /// The fallback is the old behaviour and the old failure: a boundary the
    /// node has migrated cannot be read back, and a stage that needs one it
    /// never held has nowhere else to go.
    pub(super) async fn boundary_at(&mut self, slot: u64) -> Result<Arc<BoundaryInputs>> {
        if let Some(held) = self.boundaries.get(slot) {
            return Ok(held);
        }
        let inputs = boundary_cache::read(&self.api, &self.config.chain, slot).await?;
        Ok(self.boundaries.put(inputs))
    }

    /// Take every boundary from `from_epoch` up to the head that is not held.
    ///
    /// Run once an epoch, straight after the committee proof: the epoch has just
    /// opened, its threshold is twenty-odd slots away, and nothing here lands
    /// between `T` and `T2`. That is also the point at which the newest boundary
    /// is at its youngest, which is the whole reason to take it now rather than
    /// when the epoch diff wants it, two epochs and one migration later.
    ///
    /// Best effort by construction: a boundary the node has already migrated
    /// cannot be taken and one the chain has not reached does not exist. Neither
    /// ends a tick. What ends a tick is a stage that needs a boundary and has
    /// none, and that is decided where it is needed.
    pub(super) async fn hold_boundaries(&mut self, from_epoch: u64) {
        let spe = self.config.chain.slots_per_epoch;
        let mut tried = 0;
        for epoch in from_epoch..=self.chain.head_slot() / spe {
            if tried >= HOLD_AHEAD {
                return;
            }
            let slot = epoch * spe;
            if self.boundaries.holds(slot) {
                continue;
            }
            tried += 1;
            match boundary_cache::read(&self.api, &self.config.chain, slot).await {
                Ok(inputs) => {
                    info!(
                        epoch,
                        slot,
                        validators = inputs.validators.len(),
                        "held an epoch boundary",
                    );
                    self.boundaries.put(inputs);
                }
                Err(e) => warn!(
                    epoch,
                    slot,
                    error = %format!("{e:#}"),
                    "could not take this epoch's boundary",
                ),
            }
        }
    }

    /// Resolve the epoch and prove its committees, against the accumulator as
    /// it stands.
    pub(super) async fn open_epoch(&mut self, target_epoch: u64) -> Result<OpenEpoch> {
        let spe = self.config.chain.slots_per_epoch;
        let target_root = self
            .chain
            .checkpoint_root(&self.api, &self.config, target_epoch)
            .await?;
        let source_root = self
            .chain
            .checkpoint_root(&self.api, &self.config, target_epoch.saturating_sub(1))
            .await?;
        let signing_domain = self
            .chain
            .signing_domain(&self.api, &self.config, target_epoch)
            .await?;
        let boundary = self
            .boundary_at(target_epoch * spe)
            .await
            .with_context(|| format!("open the boundary state of epoch {target_epoch}"))?;

        // Made an epoch ago if the daemon had the room, and merely awaited
        // here; proved on the spot if it did not. See [`super::speculation`].
        let (committees, committee_output, committee_proof) = match self
            .ahead
            .take_committee(target_epoch, self.snapshot.state.acc_commitment)
        {
            Some(ready) => self.adopt_committee(target_epoch, ready)?,
            None => self.prove_committee(target_epoch, &boundary).await?,
        };

        // The epoch after this one is the youngest boundary there is, and the
        // one the diff that closes this epoch will need. Take it now.
        self.hold_boundaries(target_epoch + 1).await;

        // And, having just taken it, start proving the next epoch's opening
        // against it. Here rather than on the trigger's `!fire` branch, because
        // a daemon that is behind opens every epoch past its own threshold and
        // fires on the tick it opens — so `!fire` is the one branch the daemon
        // this exists to rescue never runs. The witness build this costs is
        // ~0.8 s of a mainnet epoch; what it takes off the next epoch's chain
        // is the diff and the committee proof together, ~223 s.
        self.speculate(target_epoch + 1).await;

        let stream = SlotStream::new(
            &self.config.chain,
            committees.clone(),
            target_epoch,
            target_root,
            source_root,
        );

        Ok(OpenEpoch {
            target_root,
            source_root,
            signing_domain,
            committees,
            committee_output,
            committee_proof,
            stream,
        })
    }

    /// Record a committee proof made before its epoch opened as the stage it
    /// is, so that an epoch costs the same in the manifest wherever it was
    /// proved.
    fn adopt_committee(
        &mut self,
        target_epoch: u64,
        ready: AheadCommittee,
    ) -> Result<(Arc<EpochCommittees>, CommitteeOutput, Proof)> {
        self.chain.observe_start_delay(
            &self.config,
            Stage::Committee,
            target_epoch,
            target_epoch * self.config.chain.slots_per_epoch,
        );
        let artifact =
            self.sink
                .write_witness(target_epoch, "committee", &ready.committees.witness)?;
        write_proof(&self.sink, target_epoch, "committee", &ready.proof)?;
        info!(
            epoch = target_epoch,
            millis = ready.took.as_millis() as u64,
            "opened on a committee proof made before the epoch",
        );
        self.report.record(
            StageTiming::new(
                Stage::Committee,
                target_epoch,
                Instant::now() - ready.took,
                ready.cost,
                artifact,
            )
            .with_proof(&ready.proof),
        );
        Ok((ready.committees, ready.output, ready.proof))
    }

    /// Start proving the epoch after this one, if nothing is proving it.
    ///
    /// Best effort by construction and never fatal. A boundary the chain has not
    /// reached yet is one the next tick tries again for, and the worst outcome
    /// is an epoch that proves its own opening on the critical path — which is
    /// what every epoch did before this existed.
    pub(super) async fn speculate(&mut self, next_epoch: u64) {
        if self.ahead.covers(next_epoch) || !self.ahead.may_attempt(self.config.poll_interval) {
            return;
        }
        if let Err(e) = self.start_speculation(next_epoch).await {
            warn!(
                epoch = next_epoch,
                error = %format!("{e:#}"),
                "could not start the next epoch's proofs early; \
                 it will prove them on the critical path",
            );
        }
    }

    /// Build the next epoch's diff witness here — it needs the node — and hand
    /// it and the committees that follow from it to a task of their own.
    async fn start_speculation(&mut self, next_epoch: u64) -> Result<()> {
        let slot_2 = next_epoch * self.config.chain.slots_per_epoch;
        if self.chain.head_slot() < slot_2 {
            return Ok(());
        }
        let held_1 = self
            .boundary_at(self.snapshot.epoch_state.slot)
            .await
            .context("open the boundary the accumulator sits on")?;
        let held_2 = self
            .boundary_at(slot_2)
            .await
            .context("open the boundary the next epoch opens on")?;

        // On a clone, which is what makes this speculative: nothing the task
        // produces touches the accumulator until the cursor reaches the epoch.
        let mut tree = self.snapshot.tree.clone();
        let (witness, epoch_state, total_active_balance, num_validators) =
            witness_epoch_diff::build_held(
                &self.api,
                &self.config.chain,
                &mut tree,
                &self.snapshot.epoch_state,
                &held_1.validators,
                &held_2.validators,
                slot_2,
                self.snapshot.state.total_active_balance,
            )
            .await
            .context("build the next epoch's diff witness")?;
        if witness.epoch_1 != self.snapshot.state.cursor_epoch || witness.epoch_2 != next_epoch {
            bail!(
                "the next epoch's diff spans {} -> {}, but the accumulator is at {}",
                witness.epoch_1,
                witness.epoch_2,
                self.snapshot.state.cursor_epoch,
            );
        }

        self.chain
            .observe_start_delay(&self.config, Stage::EpochDiff, next_epoch, slot_2);
        self.report.begin(Stage::EpochDiff, next_epoch, None, None);
        self.report.begin(Stage::Committee, next_epoch, None, None);
        info!(epoch = next_epoch, "proving the next epoch ahead of it");
        self.ahead.start(
            next_epoch,
            self.snapshot.state.acc_commitment,
            speculation::spawn(
                self.prover.clone(),
                self.config.chain.clone(),
                next_epoch,
                witness,
                tree,
                epoch_state,
                total_active_balance,
                num_validators,
                held_2,
            ),
        );
        Ok(())
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
        boundary: &BoundaryInputs,
    ) -> Result<(Arc<EpochCommittees>, CommitteeOutput, Proof)> {
        // The schedule wants this finished before the epoch it serves opens, so
        // the epoch's own first slot is the latest it should ever start.
        self.chain.observe_start_delay(
            &self.config,
            Stage::Committee,
            target_epoch,
            target_epoch * self.config.chain.slots_per_epoch,
        );
        let started = Instant::now();
        self.report
            .begin(Stage::Committee, target_epoch, None, None);
        let committees = Arc::new(self.build_committees(target_epoch, boundary)?);
        let (output, proof) = self.prover.prove_committee(&committees.witness)?;
        if output != committees.output {
            bail!(
                "committee circuit disagrees with the host committee tree at epoch {target_epoch}"
            );
        }
        let artifact = self
            .sink
            .write_witness(target_epoch, "committee", &committees.witness)?;
        write_proof(&self.sink, target_epoch, "committee", &proof)?;
        self.report.record(
            StageTiming::new(
                Stage::Committee,
                target_epoch,
                started,
                self.prover.last_cost(),
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
    fn build_committees(
        &self,
        target_epoch: u64,
        boundary: &BoundaryInputs,
    ) -> Result<EpochCommittees> {
        crate::committee::build(
            &boundary.committees,
            &boundary.validators,
            &self.snapshot.tree,
            &self.config.chain,
            target_epoch,
            target_epoch,
            self.snapshot.state.total_active_balance,
        )
    }
}
