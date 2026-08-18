//! What a run says about itself.
//!
//! Everything here is observation: the manifest on disk, the public API's view
//! of a stage, the Prometheus counters, and what the prover has cost per epoch.
//! None of it is load-bearing for a proof, which is why a publisher that will
//! not answer is stepped over rather than propagated.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use anyhow::Result;
use tracing::info;

use zkasper_common::types::JustificationOutput;

use crate::artifacts::{
    hex0x, hex_digest, now_unix, AccStatus, CheckpointStatus, EpochCost, EpochLatency,
    GossipStatus, PublishStatus, StageTiming, Status,
};
use crate::postings::PostingLog;
use crate::prover::Stage;
use crate::publish::Publisher;
use crate::store::StoreState;

use super::{Orchestrator, OrchestratorConfig, RECENT_LATENCIES, RECENT_STAGES};

/// Every number a run keeps about itself, and everywhere it sends them.
pub(super) struct Reporter {
    /// Where stages are mirrored as they happen. `None` runs the pipeline with
    /// no public surface but the manifest on disk.
    publish: Option<Arc<Publisher>>,
    /// Postings a submitter appended, when the daemon was given a file to read.
    postings: Option<PostingLog>,
    recent: VecDeque<StageTiming>,
    latencies: VecDeque<EpochLatency>,
    /// Prover time per epoch, accumulated as stages land. Keyed by epoch rather
    /// than reset at a boundary, because the committee proof of E+1 runs inside
    /// E and its cost belongs to E+1.
    costs: HashMap<u64, EpochCost>,
    /// What an hour of this deployment's proving hardware costs, taken from the
    /// configuration once. See [`OrchestratorConfig::prover_usd_per_hour`].
    usd_per_hour: Option<f64>,
}

impl Reporter {
    pub(super) fn new(config: &OrchestratorConfig, publish: Option<Arc<Publisher>>) -> Self {
        Self {
            publish,
            postings: config.postings_path.as_ref().map(PostingLog::new),
            recent: VecDeque::new(),
            latencies: VecDeque::new(),
            costs: HashMap::new(),
            usd_per_hour: config.prover_usd_per_hour,
        }
    }

    /// The public API this run mirrors stages to, if it has one.
    pub(super) fn publisher(&self) -> Option<&Arc<Publisher>> {
        self.publish.as_ref()
    }

    pub(super) fn record(&mut self, timing: StageTiming) {
        crate::metrics::observe_stage(&timing, self.usd_per_hour);
        if let Some(publish) = &self.publish {
            publish.stage_finished(&timing);
        }
        self.costs.entry(timing.epoch).or_default().absorb(&timing);
        if self.recent.len() == RECENT_STAGES {
            self.recent.pop_front();
        }
        self.recent.push_back(timing);
    }

    /// What `epoch` has cost the prover so far, and forget everything older.
    ///
    /// Called once, as the epoch closes: an epoch that is finished can still be
    /// followed by a stage of a later one, but never by another of its own.
    pub(super) fn take_cost(&mut self, epoch: u64) -> EpochCost {
        let cost = self.costs.remove(&epoch).unwrap_or_default();
        self.costs.retain(|&e, _| e > epoch);
        crate::metrics::observe_epoch_cost(&cost, self.usd_per_hour);
        cost
    }

    /// Announce a stage before it runs, so a consumer can show it in flight
    /// rather than only once it has landed.
    pub(super) fn begin(&self, stage: Stage, epoch: u64, slot: Option<u64>, index: Option<usize>) {
        if let Some(publish) = &self.publish {
            publish.stage_started(stage, epoch, slot, index);
        }
    }

    /// Keep a streaming epoch's measured `T2 - T`.
    pub(super) fn record_latency(&mut self, latency: EpochLatency) {
        crate::metrics::observe_proof_start(
            Stage::StreamFinal,
            latency.wait_millis as f64 / 1000.0,
        );
        crate::metrics::observe_latency(&latency);
        if self.latencies.len() == RECENT_LATENCIES {
            self.latencies.pop_front();
        }
        self.latencies.push_back(latency);
    }

    /// The latency of `epoch`, if it is the most recent one measured.
    pub(super) fn latency(&self, epoch: u64) -> Option<&EpochLatency> {
        self.latencies.back().filter(|l| l.epoch == epoch)
    }

    /// Announce postings the submitter has written since the last look.
    ///
    /// The submitter is a separate process, so this is the daemon noticing
    /// rather than the daemon doing. A posting that never arrives means nothing
    /// posted it; it never means the proof was not made.
    fn drain_postings(&self) {
        let Some(log) = &self.postings else {
            return;
        };
        for posting in log.refresh() {
            info!(
                chain = %posting.chain,
                epoch = posting.epoch,
                signature = %posting.signature,
                compute_units = posting.compute_units,
                lamports = posting.lamports_spent,
                "a finalization proof was verified on another chain",
            );
            if let Some(publish) = &self.publish {
                publish.posting_landed(&posting);
            }
        }
    }
}

impl<A> Orchestrator<A> {
    /// The manifest, as of now.
    pub fn status(&self) -> Status {
        let state = &self.engine.snapshot.state;
        let report = &self.engine.report;
        Status {
            version: 1,
            chain: state.chain.clone(),
            genesis_validators_root: self
                .engine
                .chain
                .genesis_validators_root()
                .as_ref()
                .map(|root| hex0x(root)),
            prover_usd_per_hour: self.engine.config.prover_usd_per_hour,
            prover_health: self.engine.prover.health(),
            prover: self.engine.prover.name().to_string(),
            updated_unix: now_unix(),
            head_slot: self.engine.chain.head_slot(),
            init_epoch: state.init_epoch,
            accumulator: acc_status(state),
            justified_through: state.justified_through,
            last_justified: state
                .last_justification
                .as_ref()
                .map(|r| justified_checkpoint(&r.output)),
            last_finalized: state.finalized.as_ref().map(CheckpointStatus::from),
            node_finalized: self
                .engine
                .chain
                .node_finalized()
                .map(CheckpointStatus::from),
            recent_stages: report.recent.iter().cloned().collect(),
            recent_latencies: report.latencies.iter().cloned().collect(),
            current_epoch: self.stream.current_epoch(&self.engine.config),
            gossip: self.engine.gossip.as_ref().map(|source| {
                let counters = source.counters();
                GossipStatus {
                    attestations: counters.attestations,
                    reconnects: counters.reconnects,
                    dropped: counters.dropped,
                }
            }),
            publish: report.publish.as_ref().map(|publish| {
                let counters = publish.counters();
                PublishStatus {
                    posted: counters.posted,
                    spooled: counters.spooled,
                    dropped: counters.dropped,
                    pending: counters.pending,
                }
            }),
            postings: report
                .postings
                .as_ref()
                .map(PostingLog::recent)
                .unwrap_or_default(),
        }
    }

    pub fn publish_status(&self) -> Result<()> {
        self.engine.report.drain_postings();
        crate::metrics::observe_state(
            &self.engine.snapshot.state,
            self.engine.chain.head_slot(),
            self.engine.chain.node_finalized().map(|c| c.epoch),
        );
        if let Some(source) = &self.engine.gossip {
            crate::metrics::observe_gossip(source.counters());
        }
        if let Some(publish) = self.engine.report.publisher() {
            crate::metrics::observe_publish(publish.counters());
        }
        let status = self.status();
        if let Some(publish) = self.engine.report.publisher() {
            publish.status(&status);
        }
        self.engine.sink.write_status(&status)
    }
}

/// The accumulator, as the manifest reports it.
pub(super) fn acc_status(state: &StoreState) -> AccStatus {
    AccStatus {
        epoch: state.cursor_epoch,
        root: hex_digest(&state.acc_root),
        commitment: hex_digest(&state.acc_commitment),
        chain_digest: hex_digest(&state.acc_chain_digest),
        total_active_balance: state.total_active_balance,
        num_validators: state.num_validators,
    }
}

pub(super) fn justified_checkpoint(output: &JustificationOutput) -> CheckpointStatus {
    CheckpointStatus {
        epoch: output.target_epoch,
        root: hex0x(&output.target_root),
    }
}

pub(super) fn percent_of(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    part as f64 * 100.0 / whole as f64
}
