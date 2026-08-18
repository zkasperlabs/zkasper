//! What every stage needs, whichever pipeline is driving.
//!
//! The node, the prover, the accumulator, and the two places a result goes.
//! Grouped here so that a pipeline can be handed all of it without also being
//! handed the other pipeline's half-built epoch: [`super::batch`] and
//! [`super::stream`] each own their own aggregation and share nothing but this.

use anyhow::Result;

use crate::artifacts::{ArtifactRef, ArtifactSink};
use crate::gossip::AttestationSource;
use crate::prover::{Proof, Prover};
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
