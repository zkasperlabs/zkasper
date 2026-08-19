//! Where the chain is, and the clock the schedule is measured against.
//!
//! Nothing here is proof input. It is what the daemon has to ask the node for
//! to know whether there is work to do, and whether the work it did was on
//! time. Every field is therefore allowed to be missing: a node that will not
//! answer costs a metric, never an epoch.

use std::time::Instant;

use anyhow::{bail, Context, Result};
use tracing::warn;

use zkasper_common::bls::{compute_domain, DOMAIN_BEACON_ATTESTER};
use zkasper_common::types::Checkpoint;

use crate::artifacts::now_unix_millis;
use crate::beacon_api::{BeaconApi, ChainStatusApi};
use crate::prover::Stage;

use super::{OrchestratorConfig, MEASURED_EPOCHS};

/// The node's view of the chain, as of the last time the daemon looked.
#[derive(Default)]
pub(super) struct ChainView {
    head_slot: u64,
    /// When the chain view was last refreshed. The trigger runs several times a
    /// second and the node's head does not move that fast, so the two are not
    /// the same clock.
    viewed: Option<Instant>,
    node_finalized: Option<Checkpoint>,
    genesis_validators_root: Option<[u8; 32]>,
    /// Unix seconds of slot 0, asked for once. Without it a slot has no
    /// wall-clock time and no proof can be called late.
    genesis_time: Option<u64>,
}

impl ChainView {
    /// Starts from whatever the caller already resolved, which for the genesis
    /// validators root is the chain name it was given.
    pub(super) fn new(config: &OrchestratorConfig) -> Self {
        Self {
            genesis_validators_root: config.genesis_validators_root,
            ..Self::default()
        }
    }

    pub(super) fn head_slot(&self) -> u64 {
        self.head_slot
    }

    pub(super) fn node_finalized(&self) -> Option<&Checkpoint> {
        self.node_finalized.as_ref()
    }

    pub(super) fn genesis_validators_root(&self) -> Option<[u8; 32]> {
        self.genesis_validators_root
    }

    /// Ask the node where it is, at most once a poll interval.
    ///
    /// The trigger ticks several times a second and the head moves once a slot,
    /// so refreshing on every tick would be two round trips per evaluation to
    /// learn nothing.
    pub(super) async fn refresh<A: BeaconApi + ChainStatusApi>(
        &mut self,
        api: &A,
        config: &OrchestratorConfig,
    ) -> Result<()> {
        if self
            .viewed
            .is_some_and(|at| at.elapsed() < config.poll_interval)
        {
            return Ok(());
        }
        self.viewed = Some(Instant::now());

        self.head_slot = api
            .get_header("head")
            .await
            .context("fetch chain head")?
            .slot;

        // The clock every schedule comparison is made against. Asked for once,
        // and never fatal: without it the daemon simply records no start delays.
        if self.genesis_time.is_none() {
            match api.get_genesis_time().await {
                Ok(genesis) => self.genesis_time = Some(genesis),
                Err(e) => warn!(
                    error = %e,
                    "no genesis time from the node; proof start delays will not be recorded",
                ),
            }
        }

        // Only used for the manifest, so a node that will not answer must not
        // stop the pipeline.
        match api.get_finality_checkpoints("head").await {
            Ok(checkpoints) => self.node_finalized = Some(checkpoints.finalized),
            Err(e) => warn!(error = %e, "could not read the node's finality checkpoints"),
        }
        Ok(())
    }

    /// Block root of the checkpoint for `epoch`.
    ///
    /// The checkpoint root is the block at the epoch's first slot, or — when
    /// that slot was skipped — the most recent block before it.
    pub(super) async fn checkpoint_root<A: ChainStatusApi>(
        &self,
        api: &A,
        config: &OrchestratorConfig,
        epoch: u64,
    ) -> Result<[u8; 32]> {
        let spe = config.chain.slots_per_epoch;
        let first = epoch * spe;
        let floor = first.saturating_sub(spe);
        for slot in (floor..=first).rev() {
            if let Some(root) = api
                .get_block_root(&slot.to_string())
                .await
                .with_context(|| format!("fetch block root at slot {slot}"))?
            {
                return Ok(root);
            }
        }
        bail!("no block found in the epoch before slot {first}; cannot resolve the checkpoint root")
    }

    /// Domain attestations for `epoch` were signed under.
    pub(super) async fn signing_domain<A: ChainStatusApi>(
        &mut self,
        api: &A,
        config: &OrchestratorConfig,
        epoch: u64,
    ) -> Result<[u8; 32]> {
        if let Some(domain) = config.signing_domain {
            return Ok(domain);
        }
        let state_id = (epoch * config.chain.slots_per_epoch).to_string();
        let genesis_validators_root = match self.genesis_validators_root {
            Some(root) => root,
            None => {
                let root = api
                    .get_genesis_validators_root()
                    .await
                    .context("fetch genesis validators root")?;
                self.genesis_validators_root = Some(root);
                root
            }
        };
        // A checkpoint-synced node keeps only the states after its anchor, so the
        // first slot of an epoch it is still working through can be a 404 — which
        // would wedge the daemon on that epoch for as long as it ran. The fork
        // version is a property of the fork schedule rather than of the state, so
        // head answers for any epoch in the same fork period, which every epoch a
        // following daemon works on is. Pass `--signing-domain` to pin it across a
        // fork boundary.
        let fork_version = match api.get_fork_version(&state_id).await {
            Ok(version) => version,
            Err(e) => {
                warn!(
                    epoch,
                    state_id,
                    error = %e,
                    "no state to read the fork version from; taking head's",
                );
                api.get_fork_version("head")
                    .await
                    .context("fetch fork version at head")?
            }
        };
        Ok(compute_domain(
            &DOMAIN_BEACON_ATTESTER,
            &fork_version,
            &genesis_validators_root,
        ))
    }

    /// Unix millis at which `slot` began.
    ///
    /// `None` until the node has answered once. Every caller treats that as
    /// "no expectation to compare against" rather than an error: a missing
    /// metric is better than a wrong one, and nothing in the pipeline depends
    /// on this.
    pub(super) fn slot_unix_millis(&self, config: &OrchestratorConfig, slot: u64) -> Option<u64> {
        let seconds_per_slot = config.stream_policy.seconds_per_slot;
        self.genesis_time
            .map(|genesis| genesis * 1000 + (slot as f64 * seconds_per_slot * 1000.0) as u64)
    }

    /// Record how far a proof's start slipped from where the schedule put it.
    ///
    /// The schedule prices a proof over slots ending at `last_slot` as startable
    /// the moment that slot's attestations are in, which
    /// [`crate::streaming::schedule`] expresses as seconds from the epoch's
    /// first attesting slot. Both sides are converted to that origin here, so
    /// what is recorded is the same quantity the model plans against.
    ///
    /// Negative is early, and is kept: a proof that beat its slot is as much a
    /// fact about the schedule as one that missed it.
    pub(super) fn observe_start_delay(
        &self,
        config: &OrchestratorConfig,
        stage: Stage,
        target_epoch: u64,
        last_slot: u64,
    ) {
        let spe = config.chain.slots_per_epoch;
        let (Some(epoch_start), Some(expected)) = (
            self.slot_unix_millis(config, target_epoch * spe),
            self.slot_unix_millis(config, last_slot),
        ) else {
            return;
        };
        let elapsed = now_unix_millis().saturating_sub(epoch_start) as f64;
        let expected = expected.saturating_sub(epoch_start) as f64;

        // Replaying an epoch the chain left behind hours ago is a catch-up
        // rather than a missed schedule, so it is not recorded — but it is
        // counted, because a histogram that empties itself is indistinguishable
        // from a daemon that has stopped proving. See [`MEASURED_EPOCHS`].
        let epoch_millis =
            spe as f64 * config.stream_policy.seconds_per_slot * 1000.0 * MEASURED_EPOCHS;
        if elapsed > epoch_millis {
            crate::metrics::drop_proof_start(stage);
            return;
        }
        crate::metrics::observe_proof_start(stage, (elapsed - expected) / 1000.0);
    }
}
