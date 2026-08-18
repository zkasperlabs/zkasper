//! Continuous mode: follow the chain and keep the proof pipeline fed.
//!
//! # The shape of the loop
//!
//! The accumulator is a chain, and a slot proof binds the accumulator
//! commitment it was built against, so the two cannot be reordered: epoch E's
//! justification has to be finished while the accumulator still sits on E. That
//! gives a two-state machine per epoch, which is also exactly what resumption
//! needs, because both states are recorded on disk:
//!
//! ```text
//!   accumulator at E, epoch E not attempted   ->  stream slot proofs, justify
//!   accumulator at E, epoch E attempted       ->  epoch diff E -> E+1
//! ```
//!
//! # Streaming
//!
//! BENCHMARKS.md argues for proving slot groups as attestations arrive and
//! firing the aggregation the moment the 2/3 threshold crosses — around slot 22
//! of a mainnet epoch — rather than waiting for the epoch to end. Both
//! aggregators are written that way: they hold the running dedup set and
//! attesting balance across ticks, consume whatever the node has published so
//! far, and stop the instant the threshold is crossed. Slots past that point are
//! never proven.
//!
//! # Where the rest of it lives
//!
//! [`Orchestrator`] is the loop and the wiring, and owns no stage of its own.
//! Everything it drives lives beside it:
//!
//! - `engine` — the node, the prover, the accumulator and where results go:
//!   what every stage needs, whichever pipeline is driving.
//! - `accumulator` — the epoch diff that moves the accumulator, and the one
//!   failure that ends a run rather than being retried.
//! - `batch` and `stream` — the two pipelines. They are alternatives, never
//!   stages of one another, and neither can reach the other's half-built epoch.
//!   `pipeline` holds the choice between them and the contract they share.
//! - `chain_view` — where the node says the chain is, and the clock every
//!   schedule comparison is made against.
//! - `reporter` — the manifest, the metrics, and what an epoch cost.

mod accumulator;
mod batch;
mod chain_view;
mod config;
mod engine;
mod pipeline;
mod reporter;
mod stream;

pub use config::OrchestratorConfig;
pub use pipeline::Pipeline;

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tracing::info;

use zkasper_common::types::Checkpoint;

use crate::acc_tree::AccTree;
use crate::artifacts::{hex_digest, ArtifactSink};
use crate::beacon_api::{BeaconApi, ChainStatusApi};
use crate::epoch_state::EpochState;
use crate::gossip::{AttestationSource, EventStreamSource};
use crate::init_point;
use crate::prover::Prover;
use crate::publish::Publisher;
use crate::store::{Snapshot, Store, StoreState};

use accumulator::is_pruned_state;
use batch::BatchPipeline;
use chain_view::ChainView;
use engine::Engine;
use pipeline::EpochPipeline;
use reporter::Reporter;
use stream::StreamPipeline;

/// How many stage timings the manifest keeps.
const RECENT_STAGES: usize = 64;

/// How far behind the head an epoch may be and still be called live, in epochs.
///
/// Two, because the daemon keeps looking for a checkpoint's attestations for
/// `attestation_lookahead_epochs` past it. Anything older is a catch-up.
const LIVE_EPOCHS: f64 = 2.0;

/// How many epochs' measured `T2 - T` the manifest keeps.
const RECENT_LATENCIES: usize = 16;

/// What one tick did. Returned so callers — and tests — can see the pipeline
/// move without reading the log.
#[derive(Clone, Debug, Default)]
pub struct Tick {
    pub head_slot: u64,
    pub advanced_to: Option<u64>,
    pub slots_proved: Vec<u64>,
    pub justified: Option<u64>,
    pub finalized: Option<Checkpoint>,
    /// Epoch abandoned because the chain never justified it.
    pub gave_up_on: Option<u64>,
}

impl Tick {
    pub fn made_progress(&self) -> bool {
        self.advanced_to.is_some()
            || !self.slots_proved.is_empty()
            || self.justified.is_some()
            || self.gave_up_on.is_some()
    }
}

pub struct Orchestrator<A> {
    /// The node, the prover, the accumulator, and where results go — the half
    /// of the daemon that does not care which pipeline is running.
    engine: Engine<A>,
    batch: BatchPipeline,
    stream: StreamPipeline,
}

impl<A: BeaconApi + ChainStatusApi> Orchestrator<A> {
    /// Resume from the persisted accumulator, or start from the init point.
    pub async fn open(api: A, config: OrchestratorConfig, prover: Box<dyn Prover>) -> Result<Self> {
        Self::open_with_publisher(api, config, prover, None).await
    }

    /// The same, mirroring every stage to the public API as it happens.
    pub async fn open_with_publisher(
        api: A,
        config: OrchestratorConfig,
        prover: Box<dyn Prover>,
        publish: Option<Arc<Publisher>>,
    ) -> Result<Self> {
        let store = Store::new(&config.db_path);
        let sink = ArtifactSink::new(&config.output_dir)?;

        let mut this = match store.load()? {
            Some(snapshot) => {
                if snapshot.state.chain != config.chain_name {
                    bail!(
                        "store at {} holds a {} accumulator, but this run is configured for {}",
                        config.db_path.display(),
                        snapshot.state.chain,
                        config.chain_name,
                    );
                }
                info!(
                    epoch = snapshot.state.cursor_epoch,
                    chain_digest = %hex_digest(&snapshot.state.acc_chain_digest),
                    "resuming",
                );
                Self::assemble(api, config, store, sink, prover, snapshot, publish)
            }
            None => {
                let init = config.init_point.clone().context(
                    "no accumulator state file and no init point; \
                     generate one with `zkasper-init-point` and pass --init-point",
                )?;
                let snapshot = init_point::open(&api, &config.chain, &config.chain_name, &init)
                    .await
                    .context("start from the configured init point")?;
                let this = Self::assemble(api, config, store, sink, prover, snapshot, publish);
                this.engine.store.save(&this.engine.snapshot)?;
                this
            }
        };

        this.engine
            .chain
            .refresh(&this.engine.api, &this.engine.config)
            .await?;
        this.publish_status()?;
        Ok(this)
    }

    fn assemble(
        api: A,
        config: OrchestratorConfig,
        store: Store,
        sink: ArtifactSink,
        prover: Box<dyn Prover>,
        snapshot: Snapshot,
        publish: Option<Arc<Publisher>>,
    ) -> Self {
        Self {
            engine: Engine {
                chain: ChainView::new(&config),
                report: Reporter::new(&config, publish),
                gossip: config.gossip_url.as_deref().map(|url| {
                    Box::new(EventStreamSource::connect(url)) as Box<dyn AttestationSource>
                }),
                api,
                config,
                store,
                sink,
                prover,
                snapshot,
            },
            batch: BatchPipeline::default(),
            stream: StreamPipeline::default(),
        }
    }

    /// Follow attestations from `source` instead of the node's event stream.
    ///
    /// The daemon only ever asks a source for whatever arrived since last time,
    /// so this is where a forked node, an in-process feed or a test's own
    /// arrival schedule goes in.
    pub fn with_gossip(mut self, source: Box<dyn AttestationSource>) -> Self {
        self.engine.gossip = Some(source);
        self
    }

    pub fn state(&self) -> &StoreState {
        &self.engine.snapshot.state
    }

    pub fn tree(&self) -> &AccTree {
        &self.engine.snapshot.tree
    }

    // -----------------------------------------------------------------
    // Driving
    // -----------------------------------------------------------------

    /// Follow the chain until stopped.
    ///
    /// A streaming epoch in flight is re-evaluated on the trigger's clock rather
    /// than the poll's: the whole point is to fire the instant enough has
    /// arrived, and a four-second poll would round that off to four seconds.
    pub async fn run(&mut self) -> Result<()> {
        loop {
            self.catch_up().await?;
            tokio::time::sleep(match self.stream.in_flight() {
                true => self.engine.config.trigger_interval,
                false => self.engine.config.poll_interval,
            })
            .await;
        }
    }

    /// Do everything the node's current head makes possible, then return.
    pub async fn catch_up(&mut self) -> Result<Vec<Tick>> {
        let mut ticks = Vec::new();
        loop {
            let tick = self.tick().await?;
            let progressed = tick.made_progress();
            ticks.push(tick);
            if !progressed {
                return Ok(ticks);
            }
        }
    }

    /// One unit of work: justify the epoch the accumulator sits on, or move the
    /// accumulator to the next one.
    ///
    /// A tick that failed because the node has thrown the state away cannot be
    /// retried into success, so it is named rather than repeated: see
    /// [`is_pruned_state`].
    pub async fn tick(&mut self) -> Result<Tick> {
        self.tick_once().await.map_err(|e| {
            if is_pruned_state(&e) {
                return e.context(format!(
                    "the node no longer serves the state epoch {} needs. Restarting will not \
                     bring it back — the window only moves further away. Take a fresh init \
                     point near the node's finalized checkpoint, delete the state file and \
                     start again; the accumulator chain breaks at that epoch, so publish the \
                     new init point alongside it.",
                    self.engine.snapshot.state.cursor_epoch,
                ));
            }
            e
        })
    }

    /// Drop whatever epoch is part-built.
    ///
    /// Every proof inside one is bound to the accumulator commitment the epoch
    /// opened against, so moving the accumulator invalidates all of it.
    fn forget_epoch(&mut self) {
        self.batch.forget();
        self.stream.forget();
    }

    async fn tick_once(&mut self) -> Result<Tick> {
        self.engine
            .chain
            .refresh(&self.engine.api, &self.engine.config)
            .await?;

        let mut tick = Tick {
            head_slot: self.engine.chain.head_slot(),
            ..Tick::default()
        };

        if self.engine.snapshot.state.needs_justification() {
            if self.engine.config.pipeline == Pipeline::Streaming
                && StreamPipeline::can_stream(&self.engine.snapshot.state)
            {
                self.stream.drive(&mut self.engine, &mut tick).await?;
            } else {
                self.batch.drive(&mut self.engine, &mut tick).await?;
            }
        } else {
            let next = self.engine.snapshot.state.cursor_epoch + 1;
            if next <= self.engine.chain.head_slot() / self.engine.config.chain.slots_per_epoch {
                self.engine.advance_accumulator(next).await?;
                self.forget_epoch();
                tick.advanced_to = Some(next);
            }
        }

        self.publish_status()?;
        Ok(tick)
    }
}

/// Present the accumulator's cached SSZ view, for callers that want to inspect
/// what the next epoch diff will build on.
impl<A> Orchestrator<A> {
    pub fn epoch_state(&self) -> &EpochState {
        &self.engine.snapshot.epoch_state
    }

    pub fn api(&self) -> &A {
        &self.engine.api
    }
}
