//! Output directory: witness files and the status manifest.
//!
//! One directory per epoch, plus a `status.json` at the root that is rewritten
//! after every stage. The manifest is the daemon's public surface — it is what a
//! prover fleet, a monitoring check or an operator reads to find out where the
//! chain of accumulators is and what is ready to prove.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

use zkasper_common::acc::{self, Digest};
use zkasper_common::types::Checkpoint;

/// A witness file that was written.
#[derive(Clone, Debug, Serialize)]
pub struct ArtifactRef {
    pub path: String,
    pub bytes: u64,
}

/// One stage that ran, with what it cost.
#[derive(Clone, Debug, Serialize)]
pub struct StageTiming {
    pub stage: String,
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<u64>,
    pub millis: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactRef>,
}

/// The accumulator, as published in the manifest.
#[derive(Clone, Debug, Serialize)]
pub struct AccStatus {
    pub epoch: u64,
    pub root: String,
    pub commitment: String,
    /// Running hash over every accumulator root since bootstrap.
    pub chain_digest: String,
    pub total_active_balance: u64,
    pub num_validators: u64,
}

/// A checkpoint, as published in the manifest.
#[derive(Clone, Debug, Serialize)]
pub struct CheckpointStatus {
    pub epoch: u64,
    pub root: String,
}

impl From<&Checkpoint> for CheckpointStatus {
    fn from(c: &Checkpoint) -> Self {
        Self {
            epoch: c.epoch,
            root: hex0x(&c.root),
        }
    }
}

/// `status.json`.
#[derive(Clone, Debug, Serialize)]
pub struct Status {
    pub version: u32,
    pub chain: String,
    /// Which prover produced the artifacts. Says so when there are none.
    pub prover: String,
    pub updated_unix: u64,
    /// Head slot as last reported by the beacon node.
    pub head_slot: u64,
    pub bootstrap_epoch: u64,
    pub accumulator: AccStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justified_through: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_justified: Option<CheckpointStatus>,
    /// Last checkpoint this daemon proved finalized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_finalized: Option<CheckpointStatus>,
    /// What the beacon node itself considers finalized, for comparison.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_finalized: Option<CheckpointStatus>,
    /// Most recent stages, newest last.
    pub recent_stages: Vec<StageTiming>,
}

/// Writes artifacts under an output directory.
pub struct ArtifactSink {
    root: PathBuf,
}

impl ArtifactSink {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)
            .with_context(|| format!("create output directory {}", root.display()))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn epoch_dir(&self, epoch: u64) -> PathBuf {
        self.root.join(format!("epoch-{epoch:09}"))
    }

    /// Serialize a witness into this epoch's directory.
    ///
    /// Overwriting is deliberate: an epoch that is redone after a restart must
    /// land on the same paths, so the output directory always describes the
    /// current run rather than accumulating half-finished attempts.
    pub fn write_witness<T: serde::Serialize>(
        &self,
        epoch: u64,
        name: &str,
        witness: &T,
    ) -> Result<ArtifactRef> {
        let dir = self.epoch_dir(epoch);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create epoch directory {}", dir.display()))?;
        let path = dir.join(format!("{name}.bin"));
        let bytes = bincode::serialize(witness).context("serialize witness")?;
        write_atomic(&path, &bytes)?;
        Ok(ArtifactRef {
            path: path.display().to_string(),
            bytes: bytes.len() as u64,
        })
    }

    /// Rewrite `status.json`.
    pub fn write_status(&self, status: &Status) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(status).context("serialize status")?;
        write_atomic(&self.root.join("status.json"), &bytes)
    }
}

/// Write a file so that readers see either the old contents or the new ones.
///
/// The temporary file is fsynced before the rename, and the directory after it,
/// so a crash cannot leave a rename that points at unwritten data.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .context("output path has no file name")?,
    ));
    {
        let mut file = File::create(&tmp)
            .with_context(|| format!("create temporary file {}", tmp.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("rename {} into place", tmp.display()))?;
    if let Some(dir) = path.parent() {
        if let Ok(dir) = File::open(dir) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

pub fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub fn hex_digest(digest: &Digest) -> String {
    hex0x(&acc::to_bytes(digest))
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}
