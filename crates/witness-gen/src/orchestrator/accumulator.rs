//! How the accumulator moves.
//!
//! A run starts from a checked init point — see [`crate::init_point`] — and
//! every epoch after that is reached by an epoch diff, which proves the step
//! from the epoch the cursor sits on to the next one. That is what anchors each
//! epoch on the one before it, and it is also why a node that has thrown away
//! the state the next diff needs ends the run rather than restarting it: see
//! [`is_pruned_state`].

use std::time::Instant;

use anyhow::{bail, Context, Result};
use tracing::{info, instrument};

use crate::artifacts::{hex_digest, StageTiming};
use crate::beacon_api::{BeaconApi, ChainStatusApi};
use crate::prover::Stage;
use crate::store::{EpochDiffRecord, Snapshot};
use crate::witness_epoch_diff;

use super::engine::{write_proof, Engine};

/// Whether `error` means the node has thrown away a state this run still needs.
///
/// A checkpoint-synced node serves states from its finalized split forward, and
/// the split moves every epoch — measured on 2026-08-18, the window was about
/// the last 60 to 100 slots. An accumulator that falls behind therefore asks for
/// a state that no longer exists, and no number of restarts brings it back: the
/// window only moves further away.
///
/// The daemon used to bootstrap forward on its own here, which silently broke
/// the accumulator chain at the epoch it restarted on. It now stops and says
/// what to do, because a break a consumer cannot see is worse than an outage an
/// operator can.
///
/// Matched on the message because that is what a beacon node gives. The daemon
/// leans on the same string being distinctive that an operator does.
pub(super) fn is_pruned_state(error: &anyhow::Error) -> bool {
    format!("{error:#}").contains("NOT_FOUND: beacon state at slot")
}

impl<A: BeaconApi + ChainStatusApi> Engine<A> {
    /// Move the accumulator one epoch forward, transactionally.
    ///
    /// Nothing here touches persistent state until the epoch diff circuit has
    /// confirmed the new root. The host tree is advanced on a clone, so a build
    /// that fails halfway leaves the in-memory accumulator untouched, and the
    /// clone is only adopted once the circuit agrees with it.
    #[instrument(name = "stage", skip_all, fields(stage = "epoch_diff", epoch = to_epoch))]
    pub(super) async fn advance_accumulator(&mut self, to_epoch: u64) -> Result<()> {
        let started = Instant::now();
        self.report.begin(Stage::EpochDiff, to_epoch, None, None);

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
        self.report.record(
            StageTiming::new(
                Stage::EpochDiff,
                to_epoch,
                started,
                self.prover.last_cost(),
                artifact,
            )
            .with_proof(&proof),
        );
        Ok(())
    }
}
