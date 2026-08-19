//! The next epoch's opening proofs, run while this one is still collecting.
//!
//! # What is on the chain, and why it does not have to be
//!
//! An epoch costs the daemon three serial proofs. Measured on mainnet against
//! two RTX 5090s, 2026-08-19, over the ten epochs before this module existed:
//! the epoch diff that moves the accumulator onto the epoch is 56 s, the
//! committee proof of that epoch is 167 s, and the final proof that closes it is
//! 152 s. That is 375 s of an epoch's 384, so the daemon paced the chain, never
//! gained the two epochs it was behind, and never had a tick on which to fold a
//! group: `folded_groups` was 0 on every epoch it ever proved.
//!
//! The first two of those proofs do not belong on the chain. Epoch E's
//! committees are fixed by a RANDAO mix from the end of epoch E-2, so they can
//! be known a full epoch before the epoch opens, and the diff that opens E
//! depends only on the two epoch boundaries around it — both of which
//! [`super::engine::Engine::hold_boundaries`] already takes an epoch early.
//! Neither touches `T2`. Only the final proof does.
//!
//! # The committee proof cannot be moved on its own
//!
//! This is the thing that is not obvious from the call graph, and it is why this
//! module proves two stages rather than the one the plan called for.
//!
//! A [`CommitteeWitness`] binds `acc_root` and `total_active_balance` — the
//! accumulator *after* the epoch diff has moved it onto the epoch, not before —
//! and carries a multi-proof of every committee member against that root. So the
//! committee proof of epoch E is a function of the diff into E, and starting it
//! early means running that diff early too. Speculating the committee alone is
//! not a smaller version of this change; it is not possible.
//!
//! The diff can be run early because it never mutates anything until it is
//! adopted: it is built on a clone of the accumulator tree, exactly as
//! [`super::accumulator`] already builds it, and the clone is only moved into
//! the snapshot when the cursor actually reaches that epoch.
//!
//! # What is left on the chain
//!
//! The critical path becomes the final proof and whatever groups were not folded
//! in time. What replaces it as the bound is this module's own chain — the diff
//! and then the committee, 223 s serial — which is a throughput bound rather
//! than a latency one, and is exactly the quantity
//! [`crate::streaming::Schedule::committee_done_s`] already models. Driving it
//! below 223 s needs the diff a further epoch ahead, not another card: the
//! committee proof cannot start until the diff it binds has finished.
//!
//! # Nothing here writes
//!
//! The task returns witnesses, outputs and proofs and touches neither the store,
//! the artifact sink nor the reporter. Everything with a side effect happens on
//! the calling task at the moment the result is adopted, so a speculation that
//! is abandoned — a reorg, an epoch that never opens, a prover that failed —
//! leaves nothing behind to clean up.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use zkasper_common::acc::Digest;
use zkasper_common::types::{CommitteeOutput, EpochDiffOutput, EpochDiffWitness};
use zkasper_common::ChainConfig;

use crate::acc_tree::AccTree;
use crate::boundary_cache::BoundaryInputs;
use crate::committee::EpochCommittees;
use crate::epoch_state::EpochState;
use crate::prover::{Proof, ProveCost, Prover};

/// The epoch diff that opens an epoch, proved before the cursor reached it.
pub(super) struct AheadDiff {
    pub(super) witness: EpochDiffWitness,
    pub(super) output: EpochDiffOutput,
    pub(super) proof: Proof,
    /// The accumulator this diff produced, ready to be adopted whole.
    pub(super) tree: AccTree,
    pub(super) epoch_state: EpochState,
    pub(super) num_validators: u64,
    /// What the proof cost, read on the proving thread rather than after the
    /// fact — by adoption time the prover has answered other calls.
    pub(super) cost: Option<ProveCost>,
    pub(super) took: Duration,
}

/// An epoch's committee proof, made before the epoch opened.
pub(super) struct AheadCommittee {
    pub(super) committees: Arc<EpochCommittees>,
    pub(super) output: CommitteeOutput,
    pub(super) proof: Proof,
    pub(super) cost: Option<ProveCost>,
    pub(super) took: Duration,
}

/// Both halves, as the task returns them.
pub(super) struct Ahead {
    diff: AheadDiff,
    committee: AheadCommittee,
}

/// The next epoch's opening proofs: one in flight, or one half-consumed.
///
/// The two halves are taken at different moments — the diff when the
/// accumulator moves, the committee when the epoch opens on the tick after —
/// so the committee is held here in between rather than handed to a caller that
/// has nowhere to put it.
#[derive(Default)]
pub(super) struct Speculation {
    /// The epoch being proved ahead, the accumulator commitment the diff starts
    /// from, and the task proving it.
    running: Option<(u64, Digest, JoinHandle<Result<Ahead>>)>,
    /// The committee half, kept back for the `open_epoch` that wants it.
    committee: Option<(u64, Digest, AheadCommittee)>,
    /// When a start was last attempted. The trigger runs five times a second
    /// and a boundary the node will not serve fails every time it is asked, so
    /// without this a pruned epoch would be several round trips per evaluation.
    attempted: Option<Instant>,
}

impl Speculation {
    /// Whether `epoch` is already proved ahead or being proved ahead, which is
    /// what stops a tick from starting a second one every 200 ms.
    pub(super) fn covers(&self, epoch: u64) -> bool {
        self.running.as_ref().is_some_and(|(e, _, _)| *e == epoch)
            || self.committee.as_ref().is_some_and(|(e, _, _)| *e == epoch)
    }

    /// Whether enough time has passed to try starting one again, recording the
    /// attempt if so.
    pub(super) fn may_attempt(&mut self, interval: Duration) -> bool {
        if self.attempted.is_some_and(|at| at.elapsed() < interval) {
            return false;
        }
        self.attempted = Some(Instant::now());
        true
    }

    pub(super) fn start(
        &mut self,
        epoch: u64,
        from_commitment: Digest,
        handle: JoinHandle<Result<Ahead>>,
    ) {
        self.forget();
        self.running = Some((epoch, from_commitment, handle));
    }

    /// Wait for the diff that opens `epoch`, if this is proving one and it
    /// starts where the accumulator now stands.
    ///
    /// `None` means the caller proves the epoch the old way, on the critical
    /// path. That is the answer for a first epoch, for a restart, for an
    /// accumulator that moved somewhere unexpected, and for a task that failed —
    /// none of which is an error, because inline proving is still correct and
    /// only slower.
    pub(super) async fn take_diff(&mut self, epoch: u64, commitment: Digest) -> Option<AheadDiff> {
        let (started_for, from, handle) = self.running.take()?;
        if started_for != epoch || from != commitment {
            warn!(
                proved_ahead = started_for,
                wanted = epoch,
                "the accumulator did not move where the speculation expected; \
                 dropping it and proving this epoch on the critical path",
            );
            handle.abort();
            self.committee = None;
            return None;
        }
        match handle.await {
            Ok(Ok(ahead)) => {
                self.committee = Some((
                    epoch,
                    ahead.diff.output.accumulator_commitment,
                    ahead.committee,
                ));
                Some(ahead.diff)
            }
            Ok(Err(e)) => {
                warn!(
                    epoch,
                    error = %format!("{e:#}"),
                    "proving the next epoch ahead failed; falling back to the critical path",
                );
                None
            }
            Err(e) => {
                warn!(epoch, error = %e, "the speculation task did not finish");
                None
            }
        }
    }

    /// The committee proof of `epoch`, if one was made ahead against the
    /// accumulator the epoch is actually opening on.
    pub(super) fn take_committee(
        &mut self,
        epoch: u64,
        commitment: Digest,
    ) -> Option<AheadCommittee> {
        let (made_for, against, _) = self.committee.as_ref()?;
        if *made_for != epoch || *against != commitment {
            self.committee = None;
            return None;
        }
        self.committee.take().map(|(_, _, c)| c)
    }

    /// Drop whatever is in flight or held.
    ///
    /// `abort` does not interrupt a proof already running on a blocking thread —
    /// nothing can — but the task writes nothing and its result is dropped, so
    /// what it leaves behind is prover time and no state.
    pub(super) fn forget(&mut self) {
        if let Some((epoch, _, handle)) = self.running.take() {
            info!(epoch, "dropping the epoch that was being proved ahead");
            handle.abort();
        }
        self.committee = None;
    }
}

/// Prove the diff that opens `epoch` and then that epoch's committees.
///
/// Serial by necessity: the committee witness binds the accumulator root the
/// diff produces. Both run on a blocking thread because [`Prover`] is
/// synchronous — a bare `tokio::spawn` would park the runtime for the ~223 s
/// the pair takes.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn(
    prover: Arc<dyn Prover>,
    chain: ChainConfig,
    epoch: u64,
    witness: EpochDiffWitness,
    tree: AccTree,
    epoch_state: EpochState,
    total_active_balance: u64,
    num_validators: u64,
    boundary: Arc<BoundaryInputs>,
) -> JoinHandle<Result<Ahead>> {
    tokio::task::spawn_blocking(move || {
        let started = Instant::now();
        let (output, proof) = prover.prove_epoch_diff(&witness)?;
        let cost = prover.last_cost();
        if output.acc_root != tree.root() {
            bail!("epoch diff circuit disagrees with the host accumulator tree at epoch {epoch}");
        }
        if output.total_active_balance != total_active_balance {
            bail!("epoch diff circuit disagrees on the total active balance at epoch {epoch}");
        }
        info!(
            epoch,
            millis = started.elapsed().as_millis() as u64,
            "proved the next epoch's diff ahead of it",
        );
        let diff_took = started.elapsed();

        // Against the accumulator the diff just produced, which is the whole
        // reason these two cannot be started at the same time.
        let started = Instant::now();
        let committees = crate::committee::build(
            &boundary.committees,
            &boundary.validators,
            &tree,
            &chain,
            epoch,
            epoch,
            total_active_balance,
        )?;
        let (committee_output, committee_proof) = prover.prove_committee(&committees.witness)?;
        let committee_cost = prover.last_cost();
        if committee_output != committees.output {
            bail!("committee circuit disagrees with the host committee tree at epoch {epoch}");
        }
        info!(
            epoch,
            millis = started.elapsed().as_millis() as u64,
            "proved the next epoch's committees ahead of it",
        );

        Ok(Ahead {
            diff: AheadDiff {
                witness,
                output,
                proof,
                tree,
                epoch_state,
                num_validators,
                cost,
                took: diff_took,
            },
            committee: AheadCommittee {
                committees: Arc::new(committees),
                output: committee_output,
                proof: committee_proof,
                cost: committee_cost,
                took: started.elapsed(),
            },
        })
    })
}
