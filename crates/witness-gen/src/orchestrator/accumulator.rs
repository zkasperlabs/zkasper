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
use super::speculation::AheadDiff;

/// Whether `error` means the node has thrown away a state this run still needs.
///
/// A checkpoint-synced node serves states from its finalized split forward, and
/// the split moves in batches, so retention sawtooths between about two epochs
/// and `--epochs-per-migration`. An accumulator that falls into the trough asks
/// for a state that no longer exists, and no number of restarts brings it back:
/// the window only moves further away.
///
/// This is now the failure of last resort rather than the ordinary one. Every
/// boundary a stage needs is taken while the epoch is still inside the window
/// and held in [`crate::boundary_cache`], so reaching here means the run was
/// pointed at an epoch it was never up to see — a stale init point, or a stall
/// longer than the cache's reach.
///
/// The daemon used to bootstrap forward on its own here, which silently broke
/// the accumulator chain at the epoch it restarted on. It now stops and says
/// what to do, because a break a consumer cannot see is worse than an outage an
/// operator can.
///
/// Matched on the message because that is what a beacon node gives. The daemon
/// leans on the same string being distinctive that an operator does.
pub(super) fn is_pruned_state(error: &anyhow::Error) -> bool {
    format!("{error:#}").contains(crate::beacon_api::STATE_NOT_SERVED)
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
        // Proved during the epoch before this one if the daemon had the room.
        // Awaited rather than started here, which is the whole point.
        if let Some(ahead) = self
            .ahead
            .take_diff(to_epoch, self.snapshot.state.acc_commitment)
            .await
        {
            return self.adopt_diff(to_epoch, ahead);
        }

        let started = Instant::now();
        self.report.begin(Stage::EpochDiff, to_epoch, None, None);

        // Both registries come out of what this run took while the node still
        // served them. The diff is the stage that used to ask for the older of
        // the two at the latest possible moment, which is how a run died one
        // epoch behind finalization.
        let slot_1 = self.snapshot.epoch_state.slot;
        let slot_2 = to_epoch * self.config.chain.slots_per_epoch;
        let held_1 = self
            .boundary_at(slot_1)
            .await
            .context("open the boundary state the accumulator sits on")?;
        let held_2 = self
            .boundary_at(slot_2)
            .await
            .context("open the boundary state the accumulator is moving to")?;

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

        // The boundary the accumulator just left is the oldest any later stage
        // can name, so everything behind it is dead weight on disk.
        self.boundaries.forget_before(slot_2);

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

    /// Move the accumulator onto a diff that was proved before the cursor
    /// reached it, with the same checks the inline path makes.
    ///
    /// Every side effect is here rather than on the task that did the proving,
    /// so a speculation that is never adopted leaves nothing to undo.
    fn adopt_diff(&mut self, to_epoch: u64, ahead: AheadDiff) -> Result<()> {
        if ahead.output.prev_accumulator_commitment != self.snapshot.state.acc_commitment {
            bail!("epoch diff does not start from the accumulator the cursor sits on");
        }
        let acc_root = ahead.output.acc_root;
        let total_active_balance = ahead.output.total_active_balance;
        let num_validators = ahead.num_validators;

        let artifact = self
            .sink
            .write_witness(to_epoch, "epoch_diff", &ahead.witness)?;
        write_proof(&self.sink, to_epoch, "epoch_diff", &ahead.proof)?;

        let mut state = self.snapshot.state.clone();
        state.advance(
            to_epoch,
            acc_root,
            ahead.output.accumulator_commitment,
            total_active_balance,
            num_validators,
            Some(EpochDiffRecord {
                output: ahead.output,
                proof: ahead.proof.clone(),
            }),
        )?;

        self.snapshot = Snapshot {
            state,
            tree: ahead.tree,
            epoch_state: ahead.epoch_state,
        };
        self.store.save(&self.snapshot)?;
        self.boundaries
            .forget_before(to_epoch * self.config.chain.slots_per_epoch);

        info!(
            mutations = ahead.witness.mutations.len(),
            num_validators,
            total_active_balance,
            acc_root = %hex_digest(&acc_root),
            millis = ahead.took.as_millis() as u64,
            "accumulator advanced on a diff proved before this epoch",
        );
        self.report.record(
            StageTiming::new(
                Stage::EpochDiff,
                to_epoch,
                Instant::now() - ahead.took,
                ahead.cost,
                artifact,
            )
            .with_proof(&ahead.proof),
        );
        Ok(())
    }
}
