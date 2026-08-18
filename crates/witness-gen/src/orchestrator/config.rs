//! How a run is configured.

use std::path::PathBuf;
use std::time::Duration;

use zkasper_common::ChainConfig;

use crate::init_point::InitPoint;
use crate::streaming::StreamPolicy;

use super::Pipeline;

/// Attestation slots one slot proof covers, by default.
///
/// **Eleven, and it is this large because a child is the expensive thing.**
/// A recursive verification is
/// [`crate::streaming::ProverModel::recursion_verify_s`] — 55.56 s, MEASURED —
/// against 1.01 s for a mainnet slot inside a proof that is already running and
/// 3.64 s for the proof itself. So a slot that shares a proof with ten others
/// costs a hundredth of a slot that brings its own recursion, and grouping is
/// the whole of the saving: a mainnet epoch's ~22 slots become two children
/// rather than twenty-two.
///
/// It is a bound and not a target. A group covers at most this many slots
/// whatever the epoch does, so no proof here grows with the chain — which is
/// the property that was lost when one justification verified the whole epoch.
pub const DEFAULT_SLOT_GROUP_WIDTH: usize = 11;

/// Slot proofs one link of the justification chain absorbs, by default.
///
/// Four, on the same reasoning and pointing the same way. A link costs a floor
/// plus a recursion for each slot proof it takes *and* one for the link before
/// it, so a narrow link is a chain of many links each paying that extra
/// recursion. On mainnet the two groups above fit in one link of three children
/// — the committee proof and both slot proofs — and the chain never forms at
/// all; it is here for the epochs where it has to.
const DEFAULT_JUSTIFICATION_FOLD_WIDTH: usize = 4;

#[derive(Clone, Debug)]
pub struct OrchestratorConfig {
    pub chain: ChainConfig,
    /// Chain name, recorded in the store so it cannot be pointed at another one.
    pub chain_name: String,
    pub db_path: PathBuf,
    pub output_dir: PathBuf,
    /// Where the accumulator chain starts, when there is no state file to
    /// resume from. See [`crate::init_point`]: the daemon checks it against a
    /// fresh walk of the registry and refuses to start on a mismatch.
    pub init_point: Option<InitPoint>,
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
    /// How many attestation slots one slot proof covers.
    ///
    /// The batch path used to prove one slot at a time, which spends a
    /// per-proof floor and a recursive verification on work that costs about a
    /// hundred accumulator leaves. Grouping them is what the streaming path
    /// already does, and it divides the recursion the justification chain has to
    /// do by this number.
    pub slot_group_width: usize,
    /// How many slot proofs one link of the justification chain absorbs.
    ///
    /// The batch path used to fold the whole epoch at once, which is where its
    /// 1,221 s justification came from — 23 children at
    /// [`crate::streaming::ProverModel::recursion_verify_s`] each. Bounding the
    /// link is what stops that number being the epoch's size; it is not what
    /// makes it small, because recursion is linear in children and a chain pays
    /// one more of them per link. Both widths are therefore bounds set as wide
    /// as the bound allows.
    pub justification_fold_width: usize,
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
            init_point: None,
            signing_domain: None,
            poll_interval: Duration::from_secs(4),
            trigger_interval: Duration::from_millis(200),
            attestation_lookahead_epochs: 2,
            slot_group_width: DEFAULT_SLOT_GROUP_WIDTH,
            justification_fold_width: DEFAULT_JUSTIFICATION_FOLD_WIDTH,
            pipeline: Pipeline::default(),
            stream_policy: StreamPolicy::default(),
            gossip_url: None,
            postings_path: None,
            genesis_validators_root: None,
            prover_usd_per_hour: None,
        }
    }
}
