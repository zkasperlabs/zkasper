//! What every stage needs, whichever pipeline is driving.
//!
//! The node, the prover, the accumulator, and the two places a result goes.
//! Grouped here so that a pipeline can be handed all of it without also being
//! handed the other pipeline's half-built epoch: [`super::batch`] and
//! [`super::stream`] each own their own aggregation and share nothing but this.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use tracing::instrument;

use zkasper_common::types::CommitteeOutput;

use crate::artifacts::{ArtifactRef, ArtifactSink, StageTiming};
use crate::attestation_collector::SlotStream;
use crate::beacon_api::{BeaconApi, ChainStatusApi, ValidatorResponse};
use crate::committee::EpochCommittees;
use crate::gossip::AttestationSource;
use crate::prover::{Proof, Prover, Stage};
use crate::store::{Snapshot, Store};

use super::chain_view::ChainView;
use super::reporter::Reporter;
use super::OrchestratorConfig;

/// The wiring a stage runs on.
pub(super) struct Engine<A> {
    pub(super) api: A,
    pub(super) config: OrchestratorConfig,
    pub(super) store: Store,
    pub(super) sink: ArtifactSink,
    pub(super) prover: Box<dyn Prover>,
    pub(super) snapshot: Snapshot,
    /// Where the node is, and the clock the schedule is measured against.
    pub(super) chain: ChainView,
    /// Where this run's own numbers go.
    pub(super) report: Reporter,
    /// Attestation gossip, when the daemon was given a node to follow it from.
    pub(super) gossip: Option<Box<dyn AttestationSource>>,
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
    pub(super) signing_domain: [u8; 32],
    pub(super) committees: Arc<EpochCommittees>,
    pub(super) committee_output: CommitteeOutput,
    pub(super) committee_proof: Proof,
    pub(super) stream: SlotStream,
}

impl<A: BeaconApi + ChainStatusApi> Engine<A> {
    /// Resolve the epoch and prove its committees, against the accumulator as
    /// it stands.
    pub(super) async fn open_epoch(&mut self, target_epoch: u64) -> Result<OpenEpoch> {
        let spe = self.config.chain.slots_per_epoch;
        let target_root = self
            .chain
            .checkpoint_root(&self.api, &self.config, target_epoch)
            .await?;
        let signing_domain = self
            .chain
            .signing_domain(&self.api, &self.config, target_epoch)
            .await?;
        let validators = self
            .api
            .get_validators(&(target_epoch * spe).to_string())
            .await
            .context("fetch validators for the target epoch")?;

        let (committees, committee_output, committee_proof) =
            self.prove_committee(target_epoch, &validators).await?;

        let stream = SlotStream::new(
            &self.config.chain,
            committees.clone(),
            target_epoch,
            target_root,
        );

        Ok(OpenEpoch {
            target_root,
            signing_domain,
            committees,
            committee_output,
            committee_proof,
            stream,
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
        self.chain.observe_start_delay(
            &self.config,
            Stage::Committee,
            target_epoch,
            target_epoch * self.config.chain.slots_per_epoch,
        );
        let started = Instant::now();
        self.report
            .begin(Stage::Committee, target_epoch, None, None);
        let committees = Arc::new(self.build_committees(target_epoch, validators).await?);
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
}
