//! How a run is configured.

use std::path::PathBuf;
use std::time::Duration;

use zkasper_common::ChainConfig;

use crate::streaming::StreamPolicy;

use super::Pipeline;

#[derive(Clone, Debug)]
pub struct OrchestratorConfig {
    pub chain: ChainConfig,
    /// Chain name, recorded in the store so it cannot be pointed at another one.
    pub chain_name: String,
    pub db_path: PathBuf,
    pub output_dir: PathBuf,
    /// Slot to bootstrap from. Defaults to the node's finalized checkpoint.
    pub bootstrap_slot: Option<u64>,
    /// Overrides the domain otherwise derived from the node's fork and genesis.
    pub signing_domain: Option<[u8; 32]>,
    /// How long to wait after a tick that could make no further progress.
    pub poll_interval: Duration,
    /// How often a streaming epoch re-reads gossip and re-evaluates the trigger.
    /// Sets the resolution of `T2 − T`: the daemon cannot fire between two
    /// evaluations, so this is the granularity of "the instant enough arrived".
    pub trigger_interval: Duration,
    /// How many epochs past the target to keep looking for its attestations.
    pub attestation_lookahead_epochs: u64,
    pub pipeline: Pipeline,
    /// When the streaming pipeline stops collecting, and how long the trigger
    /// may hold past it. See [`crate::streaming`].
    pub stream_policy: StreamPolicy,
    /// Beacon node to follow attestation gossip from. `None` sources
    /// attestations from blocks instead, which is a slot later and is only what
    /// the fixture-replay tests want.
    pub gossip_url: Option<String>,
    /// File a submitter appends postings to, as JSON lines. `None` means
    /// nothing is posting these proofs to a chain, which is the default.
    pub postings_path: Option<PathBuf>,
    /// The root the caller resolved `chain_name` from, published beside it so a
    /// reader can check the label rather than take it. `None` leaves the
    /// orchestrator to fetch it when a signing domain first needs it.
    pub genesis_validators_root: Option<[u8; 32]>,
    /// What an hour of this deployment's proving hardware costs. A deployment
    /// fact the daemon cannot observe, published so a reader can price the
    /// prover milliseconds it does measure. Nothing here multiplies by it.
    pub prover_usd_per_hour: Option<f64>,
}

impl OrchestratorConfig {
    pub fn new(chain: ChainConfig, chain_name: impl Into<String>) -> Self {
        Self {
            chain,
            chain_name: chain_name.into(),
            db_path: PathBuf::from("zkasper.db"),
            output_dir: PathBuf::from("zkasper-out"),
            bootstrap_slot: None,
            signing_domain: None,
            poll_interval: Duration::from_secs(4),
            trigger_interval: Duration::from_millis(200),
            attestation_lookahead_epochs: 2,
            pipeline: Pipeline::default(),
            stream_policy: StreamPolicy::default(),
            gossip_url: None,
            postings_path: None,
            genesis_validators_root: None,
            prover_usd_per_hour: None,
        }
    }
}
