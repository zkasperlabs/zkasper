//! Which pipeline proves an epoch.
//!
//! The choice is made once, from configuration, and re-made every tick against
//! what the accumulator has behind it: see [`super::Orchestrator::tick`].

use anyhow::Result;

use crate::beacon_api::{BeaconApi, ChainStatusApi};
use crate::prover::Stage;

use super::engine::Engine;
use super::Tick;

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
