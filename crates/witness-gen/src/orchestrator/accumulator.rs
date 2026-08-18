//! How the accumulator gets to where it is.
//!
//! Two ways in, and they are not equivalent. A bootstrap reads a beacon state
//! whole and starts a fresh chain of accumulators from it; an epoch diff proves
//! the step from the epoch the cursor sits on to the next one, so every epoch
//! after the first is anchored on the one before it. The daemon only bootstraps
//! twice over: once because it has no store, and once because the node threw
//! away the state the chain needed — see [`is_pruned_state`].

use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use tracing::{info, instrument};

use crate::artifacts::{hex_digest, ArtifactSink, StageTiming};
use crate::beacon_api::{BeaconApi, ChainStatusApi};
use crate::prover::{Prover, Stage};
use crate::publish::Publisher;
use crate::store::{EpochDiffRecord, Snapshot, StoreState};
use crate::{witness_bootstrap, witness_epoch_diff};

use super::engine::{write_proof, Engine};
use super::OrchestratorConfig;

/// Whether `error` means the node has thrown away a state this run still needs.
///
/// A checkpoint-synced node serves states from its finalized split forward, and
/// the split moves every epoch — measured on 2026-08-18, the window was about
/// the last 60 to 100 slots. An accumulator that falls behind therefore asks for
/// a state that no longer exists, and no number of restarts brings it back: the
/// window only moves further away. The daemon bootstraps forward instead of
/// exiting.
///
/// Matched on the message because that is what a beacon node gives. The daemon
/// leans on the same string being distinctive that an operator does.
pub(super) fn is_pruned_state(error: &anyhow::Error) -> bool {
    format!("{error:#}").contains("NOT_FOUND: beacon state at slot")
}

#[instrument(
    name = "stage",
    skip_all,
    fields(stage = "bootstrap", epoch = tracing::field::Empty, slot = tracing::field::Empty),
)]
pub(super) async fn bootstrap<A: BeaconApi + ChainStatusApi>(
    api: &A,
    config: &OrchestratorConfig,
    sink: &ArtifactSink,
    prover: &dyn Prover,
    publish: Option<&Arc<Publisher>>,
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
    let span = tracing::Span::current();
    span.record("epoch", epoch);
    span.record("slot", slot);
    let started = Instant::now();
    if let Some(publish) = publish {
        publish.stage_started(Stage::Bootstrap, epoch, Some(slot), None);
    }

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
        StageTiming::new(
            Stage::Bootstrap,
            epoch,
            started,
            prover.last_cost(),
            artifact,
        )
        .with_proof(&proof),
    ))
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

    /// Start again from a state the node still has.
    ///
    /// This breaks the accumulator chain: the epoch it restarts on is anchored
    /// on a bootstrap rather than on the epoch before it. That is the price of
    /// staying alive, and it is the same price the supervisor's `rm -f` paid
    /// more slowly and after several failed restarts.
    pub(super) async fn rebootstrap(&mut self) -> Result<()> {
        let (snapshot, timing) = bootstrap(
            &self.api,
            &self.config,
            &self.sink,
            &*self.prover,
            self.report.publisher(),
        )
        .await?;
        self.snapshot = snapshot;
        self.report.record(timing);
        self.store.save(&self.snapshot)
    }
}
