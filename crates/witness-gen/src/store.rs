//! Crash-safe persistence for continuous mode.
//!
//! [`crate::db::Db`] is enough for one-shot commands: it holds a tree and a
//! cursor, and if it is wrong the operator finds out by looking. A daemon has
//! neither property. The accumulator is a chain — epoch N's root is derived from
//! N-1's — so an epoch diff applied twice, skipped, or half-written does not
//! fail, it silently produces a root that nothing downstream can detect as
//! wrong. Everything here exists to make that impossible:
//!
//! - **Atomic writes.** The state is written to a temporary file, fsynced, and
//!   renamed over the old one. A crash leaves either the previous state or the
//!   new one, never a torn mix.
//! - **Integrity check.** A magic, a format version and a SHA-256 over the
//!   payload are checked before the bytes are trusted.
//! - **Verified on load.** The tree is rehashed from its leaves and its root is
//!   compared against the recorded accumulator root and commitment. Bytes that
//!   deserialize are not the same thing as a well-formed tree.
//! - **Epoch monotonicity.** [`StoreState::advance`] refuses anything that is
//!   not exactly `cursor_epoch + 1`, so a repeated or skipped diff is an error
//!   at the point of application.
//! - **An audit chain.** Every advance folds `(epoch, acc_root)` into a running
//!   `acc_chain_digest`, which the manifest publishes. Two daemons that followed
//!   the same chain agree on it; one that missed an epoch does not.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tracing::info;

use zkasper_common::acc::{self, Digest};
use zkasper_common::types::{Checkpoint, JustificationOutput};

use crate::acc_tree::AccTree;
use crate::epoch_state::EpochState;
use crate::prover::Proof;

const MAGIC: &[u8; 8] = b"ZKASPRD\x01";
const FORMAT_VERSION: u32 = 1;

/// Everything the daemon needs to pick up exactly where it stopped.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoreState {
    /// Chain the accumulator was built for. Pointing a mainnet store at a
    /// gnosis node would otherwise produce a plausible-looking wrong chain.
    pub chain: String,
    /// Epoch the accumulator was bootstrapped at.
    pub bootstrap_epoch: u64,
    /// Epoch the accumulator currently represents.
    pub cursor_epoch: u64,
    pub acc_root: Digest,
    pub acc_commitment: Digest,
    /// Running hash over every `(epoch, acc_root)` since bootstrap.
    pub acc_chain_digest: Digest,
    pub total_active_balance: u64,
    pub num_validators: u64,
    /// Last epoch a justification was produced for.
    pub justified_through: Option<u64>,
    /// Last epoch the justification stage finished for, justified or not.
    ///
    /// Kept apart from `justified_through` so that an epoch the chain never
    /// justified does not stall the accumulator, and does not get claimed as
    /// justified either.
    pub attempted_epoch: Option<u64>,
    /// The most recent justification, kept so that the next one can be paired
    /// with it into a finalization across a restart.
    pub last_justification: Option<JustificationRecord>,
    /// Last checkpoint this daemon proved finalized.
    pub finalized: Option<Checkpoint>,
}

/// A justification output and the proof that backs it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JustificationRecord {
    pub output: JustificationOutput,
    pub proof: Proof,
}

impl StoreState {
    /// Initial state, straight out of bootstrap.
    pub fn bootstrapped(
        chain: String,
        epoch: u64,
        acc_root: Digest,
        total_active_balance: u64,
        num_validators: u64,
    ) -> Self {
        Self {
            chain,
            bootstrap_epoch: epoch,
            cursor_epoch: epoch,
            acc_root,
            acc_commitment: acc::commitment(&acc_root, total_active_balance),
            acc_chain_digest: chain_step(&acc::ZERO, epoch, &acc_root),
            total_active_balance,
            num_validators,
            justified_through: None,
            attempted_epoch: None,
            last_justification: None,
            finalized: None,
        }
    }

    /// Move the accumulator forward by exactly one epoch.
    ///
    /// Rejects a repeat or a skip. The caller is expected to have run the epoch
    /// diff circuit first and to pass the root it committed to, so a host tree
    /// that drifted from the circuit's view never reaches disk.
    pub fn advance(
        &mut self,
        to_epoch: u64,
        acc_root: Digest,
        commitment: Digest,
        total_active_balance: u64,
        num_validators: u64,
    ) -> Result<()> {
        if to_epoch != self.cursor_epoch + 1 {
            bail!(
                "epoch diff must advance the accumulator by exactly one epoch: \
                 cursor is {}, tried to move to {to_epoch}",
                self.cursor_epoch,
            );
        }
        let expected = acc::commitment(&acc_root, total_active_balance);
        if expected != commitment {
            bail!("accumulator commitment does not bind the root and total active balance");
        }

        self.cursor_epoch = to_epoch;
        self.acc_root = acc_root;
        self.acc_commitment = commitment;
        self.acc_chain_digest = chain_step(&self.acc_chain_digest, to_epoch, &acc_root);
        self.total_active_balance = total_active_balance;
        self.num_validators = num_validators;
        Ok(())
    }

    /// Whether the epoch the accumulator sits on still needs a justification.
    pub fn needs_justification(&self) -> bool {
        self.attempted_epoch != Some(self.cursor_epoch)
    }
}

/// Fold one accumulator root into the audit chain.
fn chain_step(previous: &Digest, epoch: u64, acc_root: &Digest) -> Digest {
    acc::compress(&acc::compress(previous, &[epoch, 0, 0, 0]), acc_root)
}

/// What a load produced: the state, the tree it describes, and the cached SSZ
/// view of the epoch the tree sits on.
pub struct Snapshot {
    pub state: StoreState,
    pub tree: AccTree,
    pub epoch_state: EpochState,
}

#[derive(Serialize, Deserialize)]
struct Payload {
    state: StoreState,
    epoch_state: EpochState,
    tree_levels: Vec<Vec<Digest>>,
    tree_depth: u32,
    dense_depth: u32,
}

/// The daemon's state file.
pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Read the state back, checking it every way it can be checked.
    ///
    /// Returns `None` only when there is no state file at all. Anything else —
    /// truncation, a bad hash, a tree that does not hash to its own root —
    /// is an error, because continuing from a damaged accumulator is worse than
    /// stopping.
    pub fn load(&self) -> Result<Option<Snapshot>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&self.path).context("read store")?;
        let payload = decode(&bytes).with_context(|| {
            format!(
                "store at {} is damaged; delete it to re-bootstrap",
                self.path.display(),
            )
        })?;

        let tree = AccTree::from_raw(payload.tree_levels, payload.tree_depth, payload.dense_depth);
        tree.verify_consistent()
            .map_err(|e| anyhow::anyhow!("persisted accumulator tree is not well formed: {e}"))?;

        let root = tree.root();
        if root != payload.state.acc_root {
            bail!(
                "persisted tree root does not match the recorded accumulator root at epoch {}",
                payload.state.cursor_epoch,
            );
        }
        let commitment = acc::commitment(&root, payload.state.total_active_balance);
        if commitment != payload.state.acc_commitment {
            bail!(
                "persisted accumulator commitment does not bind the root and total active balance",
            );
        }

        info!(
            epoch = payload.state.cursor_epoch,
            validators = payload.state.num_validators,
            justified_through = ?payload.state.justified_through,
            "loaded verified accumulator state",
        );

        Ok(Some(Snapshot {
            state: payload.state,
            tree,
            epoch_state: payload.epoch_state,
        }))
    }

    /// Write the state so that a crash cannot leave a half-written accumulator.
    pub fn save(&self, snapshot: &Snapshot) -> Result<()> {
        let payload = Payload {
            state: snapshot.state.clone(),
            epoch_state: snapshot.epoch_state.clone(),
            tree_levels: snapshot.tree.levels.clone(),
            tree_depth: snapshot.tree.depth,
            dense_depth: snapshot.tree.dense_depth,
        };
        crate::artifacts::write_atomic(&self.path, &encode(&payload)?)
            .context("write store atomically")
    }
}

fn encode(payload: &Payload) -> Result<Vec<u8>> {
    let body = bincode::serialize(payload).context("serialize store payload")?;
    let mut out = Vec::with_capacity(body.len() + 48);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(&Sha256::digest(&body));
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode(bytes: &[u8]) -> Result<Payload> {
    const HEADER: usize = 8 + 4 + 8 + 32;
    if bytes.len() < HEADER {
        bail!(
            "truncated: {} bytes is shorter than the header",
            bytes.len()
        );
    }
    if &bytes[..8] != MAGIC {
        bail!("not a zkasperd store (bad magic)");
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if version != FORMAT_VERSION {
        bail!("store format version {version}, expected {FORMAT_VERSION}");
    }
    let len = u64::from_le_bytes(bytes[12..20].try_into().unwrap()) as usize;
    let body = &bytes[HEADER..];
    if body.len() != len {
        bail!(
            "truncated: header declares {len} payload bytes, found {}",
            body.len()
        );
    }
    if Sha256::digest(body).as_slice() != &bytes[20..HEADER] {
        bail!("payload checksum mismatch");
    }
    bincode::deserialize(body).context("deserialize store payload")
}
