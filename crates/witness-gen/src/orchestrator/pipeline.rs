//! Which pipeline proves an epoch, and what a pipeline is.
//!
//! [`Pipeline`] picks what happens to the slots. [`Pipeline::Batch`] proves them
//! in bounded groups and folds those, a couple at a time as they finish, into a
//! chain of justification links — the same incremental shape the streaming
//! aggregate has, and for the same reason: a proof that verified every slot of
//! the epoch at once cost 1,221 s of an epoch's 1,452 on an RTX 5090, and no
//! proof in this pipeline may grow with the epoch. [`Pipeline::Streaming`]
//! proves a group per tick, folds each into a running aggregate as it finishes,
//! and collapses
//! justification, finalization and the epoch's one final exponentiation into a
//! single proof over the attestation that crossed the threshold — see
//! [`crate::streaming`]. Only the latter puts one proof on `T2 - T`, and the
//! manifest publishes the measured value.
//!
//! An epoch can only be streamed if the epoch before it left a justification and
//! an epoch diff behind, so the first epoch of a run always goes through the
//! batch path and the streaming run picks up from the next one. The choice
//! is therefore configured once but re-made every tick, against what the
//! accumulator has behind it: see [`super::stream::StreamPipeline::can_stream`].

use anyhow::Result;

use crate::beacon_api::{BeaconApi, ChainStatusApi};
use crate::prover::Stage;

use super::engine::Engine;
use super::Tick;

/// Which pipeline an epoch is proven with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Pipeline {
    /// Bounded groups of slots, folded a few proofs at a time into a chain of
    /// justification links, paired with the previous epoch's into a
    /// finalization.
    #[default]
    Batch,
    /// Group proofs as attestations arrive, folded into a running aggregate,
    /// closed by one proof over the attestation that crossed the threshold.
    Streaming,
}

impl Pipeline {
    /// Stages a prover has to be able to produce for this pipeline.
    ///
    /// Streaming still needs the batch stages: the first epoch of a run has
    /// nothing to finalize and goes through them.
    pub fn stages(self) -> &'static [Stage] {
        match self {
            Pipeline::Batch => &[
                Stage::EpochDiff,
                Stage::Committee,
                Stage::SlotProof,
                Stage::Justification,
                Stage::Finalization,
            ],
            Pipeline::Streaming => &[
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

/// What a pipeline does with the epoch the accumulator sits on.
///
/// The two implementations are alternatives, never stages of one another: an
/// epoch is proven by one or by the other, and neither can reach the other's
/// half-built aggregation. All they share is [`Engine`], which is handed in
/// rather than held.
pub(super) trait EpochPipeline {
    /// Do whatever the node's head makes possible for the epoch the cursor sits
    /// on, and record in `tick` what that turned out to be.
    async fn drive<A: BeaconApi + ChainStatusApi>(
        &mut self,
        engine: &mut Engine<A>,
        tick: &mut Tick,
    ) -> Result<()>;

    /// Drop the epoch in flight, if there is one.
    fn forget(&mut self);
}
