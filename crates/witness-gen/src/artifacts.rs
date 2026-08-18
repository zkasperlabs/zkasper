//! Output directory: witness files and the status manifest.
//!
//! One directory per epoch, plus a `status.json` at the root that is rewritten
//! after every stage. The manifest is the daemon's public surface — it is what a
//! prover fleet, a monitoring check or an operator reads to find out where the
//! chain of accumulators is and what is ready to prove.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

use zkasper_common::acc::{self, Digest};
use zkasper_common::types::Checkpoint;

use crate::prover::{ProveCost, Stage};

/// A witness file that was written.
#[derive(Clone, Debug, Serialize)]
pub struct ArtifactRef {
    pub path: String,
    pub bytes: u64,
}

/// One stage that ran, with what it cost.
///
/// `millis` is the whole stage, witness generation included; `prove_millis` and
/// `wrap_millis` are the part of it the prover charged for. Publishing them
/// apart is what makes the pipeline's latency claim checkable rather than
/// modelled; a witness-only run reports the first and omits the other two.
#[derive(Clone, Debug, Serialize)]
pub struct StageTiming {
    pub stage: String,
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<u64>,
    /// Orders repeats of the same stage inside an epoch: group 0, group 1, and
    /// so on. `None` for a stage that runs once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
    pub millis: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prove_millis: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrap_millis: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactRef>,
    /// Size of the proof this stage produced. Zero on a witness-only run.
    pub proof_bytes: u64,
}

/// What an epoch cost the prover, summed as its stages land.
///
/// Prover time is the only quantity a price can be built from, and the two
/// halves are kept apart because they are different work: `prove_millis` is the
/// VADCOP proof and `wrap_millis` is the compression after it. `prover_millis`
/// is what a rate per hour multiplies.
///
/// This is published rather than derived downstream, because the stages of two
/// epochs interleave — the committee proof of E+1 runs inside E — and only the
/// daemon knows which epoch a stage was for.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct EpochCost {
    /// Stages that produced a proof for this epoch.
    pub stage_count: u64,
    pub prove_millis: u64,
    pub wrap_millis: u64,
}

impl EpochCost {
    /// Prover time this epoch bought, proving and wrapping together.
    pub fn prover_millis(&self) -> u64 {
        self.prove_millis + self.wrap_millis
    }

    pub fn absorb(&mut self, timing: &StageTiming) {
        self.stage_count += 1;
        self.prove_millis += timing.prove_millis.unwrap_or(0);
        self.wrap_millis += timing.wrap_millis.unwrap_or(0);
    }
}

impl StageTiming {
    pub fn new(
        stage: Stage,
        epoch: u64,
        started: Instant,
        cost: Option<ProveCost>,
        artifact: ArtifactRef,
    ) -> Self {
        Self {
            stage: stage.as_str().to_string(),
            epoch,
            slot: None,
            index: None,
            millis: started.elapsed().as_millis() as u64,
            prove_millis: cost.map(|c| c.prove_millis),
            wrap_millis: cost.map(|c| c.wrap_millis),
            artifact: Some(artifact),
            proof_bytes: 0,
        }
    }

    pub fn at_slot(mut self, slot: u64) -> Self {
        self.slot = Some(slot);
        self
    }

    pub fn at_index(mut self, index: usize) -> Self {
        self.index = Some(index);
        self
    }

    pub fn with_proof(mut self, proof: &[u64]) -> Self {
        self.proof_bytes = (proof.len() * 8) as u64;
        self
    }
}

/// What the streaming pipeline's only latency actually was.
///
/// `T` is when the daemon held the attestation that carried the epoch over the
/// threshold; `T2` is when a proof of it existed. Everything else the pipeline
/// does happens before `T`, so this is the whole of what a consumer waits for.
#[derive(Clone, Debug, Serialize)]
pub struct EpochLatency {
    pub epoch: u64,
    pub threshold_unix_millis: u64,
    /// When the trigger actually started the final proof. Never before
    /// `threshold_unix_millis`, and later than it whenever waiting for in-flight
    /// attestations was the cheaper way to a postable proof.
    pub fired_unix_millis: u64,
    pub proof_unix_millis: u64,
    pub t2_minus_t_millis: u64,
    /// The part of `t2_minus_t_millis` that was the trigger holding back rather
    /// than the prover working. Reading it against `tail_named` is what says
    /// whether the wait bought what the model says it should have.
    pub wait_millis: u64,
    /// Accumulator leaves the final proof opened for its inline tail — the
    /// absentees the wait did not remove. Every one of them is
    /// `ProverModel::per_named_s` on the critical path.
    pub tail_named: usize,
    /// Group proofs folded into the running aggregate before `T`.
    pub folded_groups: usize,
    /// Groups the final proof had to verify itself, because they arrived too
    /// late to fold. Zero is the shape the design aims at, and anything else
    /// says the daemon was behind the chain.
    pub late_groups: usize,
    /// Attestations the final proof verified inline.
    pub tail: usize,
}

/// The accumulator, as published in the manifest.
#[derive(Clone, Debug, Serialize)]
pub struct AccStatus {
    pub epoch: u64,
    pub root: String,
    pub commitment: String,
    /// Running hash over every accumulator root since bootstrap.
    pub chain_digest: String,
    /// A string, not a number: mainnet's total active balance in gwei passed
    /// 2^53 long ago, and a JSON reader that parses it as a double silently
    /// rounds it. Every balance this manifest publishes is a string for the
    /// same reason.
    #[serde(with = "u64_string")]
    pub total_active_balance: u64,
    pub num_validators: u64,
}

/// Serializes a `u64` as a decimal string.
mod u64_string {
    pub fn serialize<S: serde::Serializer>(value: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }
}

/// The epoch being proven right now.
#[derive(Clone, Debug, Serialize)]
pub struct CurrentEpoch {
    pub epoch: u64,
    pub target_root: String,
    pub opened_unix_millis: u64,
    /// `collecting` below the threshold, `firing` once it has been crossed and
    /// the final proof is what is left.
    pub state: &'static str,
    #[serde(with = "u64_string")]
    pub attesting_balance: u64,
    #[serde(with = "u64_string")]
    pub total_active_balance: u64,
    pub attesting_pct: f64,
    pub threshold_pct: f64,
    pub folded_groups: usize,
    pub slots_held: usize,
    pub finalizes_epoch: u64,
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
    /// What network this daemon is on, resolved from the node's genesis
    /// validators root rather than from a flag. `unrecognised` means no known
    /// network claims that root, and the run is not claiming one either.
    pub chain: String,
    /// The root `chain` was resolved from, so a reader can check the label
    /// instead of trusting it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_validators_root: Option<String>,
    /// What an hour of the proving hardware costs, as the operator gave it. The
    /// daemon cannot know this and never multiplies by it — it is published so
    /// a reader can price `prover_millis` for themselves, at this rate or at
    /// their own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prover_usd_per_hour: Option<f64>,
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
    /// Measured `T2 - T` for the epochs this daemon streamed, newest last.
    pub recent_latencies: Vec<EpochLatency>,
    /// The epoch in flight. Absent between epochs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_epoch: Option<CurrentEpoch>,
    /// Attestation gossip, when the daemon is following it. Absent means the
    /// daemon is reading blocks, and is a slot behind the chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gossip: Option<GossipStatus>,
    /// How the prover is doing, when it is somewhere this daemon can lose.
    /// Absent for a prover in this process, which has nothing to report between
    /// calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prover_health: Option<crate::prover::ProverHealth>,
    /// How the mirror at the public API is keeping up. Absent when the daemon
    /// was not given one to publish to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publish: Option<PublishStatus>,
    /// Finalization proofs that reached another chain, oldest first. Written by
    /// whatever submitted them, not by the prover. Empty when the daemon was
    /// not given a postings file to read.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub postings: Vec<crate::postings::Posting>,
}

/// What publishing to the API has cost.
///
/// `pending` climbing is the API being unreachable, which the daemon rides out;
/// `dropped` climbing is the outage having outlasted the spool, which is the
/// only case where the published record has a hole in it.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct PublishStatus {
    pub posted: u64,
    pub spooled: u64,
    pub dropped: u64,
    pub pending: u64,
}

/// What the attestation event stream has delivered.
#[derive(Clone, Debug, Serialize)]
pub struct GossipStatus {
    pub attestations: u64,
    /// Reconnections. Each one is a hole in gossip that blocks had to repair, so
    /// a number that climbs says the epochs around it were not sourced live.
    pub reconnects: u64,
    /// Times the node reported dropping events because its own SSE channel
    /// overflowed. Anything but zero is a misconfigured node: raise
    /// `--http-sse-capacity-multiplier` until it stays at zero.
    pub dropped: u64,
}

/// Writes artifacts under an output directory.
pub struct ArtifactSink {
    root: PathBuf,
    keep_epochs: usize,
}

/// Epoch directories to keep before the oldest are deleted.
///
/// A mainnet epoch's witnesses are about 200 MB, so an unbounded output
/// directory fills a disk in a couple of days and ends a long run at whatever
/// hour it happens to run out. The witnesses exist to debug the epoch that
/// produced them; once a proof is published, the proof is the artifact.
pub const DEFAULT_KEEP_EPOCHS: usize = 8;

impl ArtifactSink {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)
            .with_context(|| format!("create output directory {}", root.display()))?;
        Ok(Self {
            root,
            keep_epochs: DEFAULT_KEEP_EPOCHS,
        })
    }

    /// Keep a different number of epoch directories. Zero keeps everything.
    pub fn keeping(mut self, epochs: usize) -> Self {
        self.keep_epochs = epochs;
        self
    }

    /// Delete the oldest epoch directories beyond `keep_epochs`.
    ///
    /// Called after an epoch closes rather than on a timer, so the bound holds
    /// without a background task and a crash cannot leave it disabled. Failing
    /// to prune is logged and never fatal: a full disk is a worse outcome than
    /// a stale directory, but neither is worth ending a run over.
    fn prune(&self) {
        if self.keep_epochs == 0 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return;
        };
        let mut dirs: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.is_dir()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("epoch-"))
            })
            .collect();
        if dirs.len() <= self.keep_epochs {
            return;
        }
        dirs.sort();
        for dir in &dirs[..dirs.len() - self.keep_epochs] {
            if let Err(e) = std::fs::remove_dir_all(dir) {
                tracing::warn!(path = %dir.display(), error = %e, "prune epoch directory");
            }
        }
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

    /// Drop the oldest epoch directories beyond the retention bound.
    pub fn prune_old_epochs(&self) {
        self.prune();
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

pub fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod prune_tests {
    use super::*;

    #[test]
    fn keeps_only_the_newest_epoch_directories() {
        let tmp = std::env::temp_dir().join(format!("zkasper-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let sink = ArtifactSink::new(&tmp).unwrap().keeping(3);
        for epoch in 100u64..110 {
            sink.write_witness(epoch, "committee", &epoch).unwrap();
            sink.prune_old_epochs();
        }
        let mut left: Vec<String> = std::fs::read_dir(&tmp)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("epoch-"))
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec![
                "epoch-000000107".to_string(),
                "epoch-000000108".to_string(),
                "epoch-000000109".to_string()
            ],
        );
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
