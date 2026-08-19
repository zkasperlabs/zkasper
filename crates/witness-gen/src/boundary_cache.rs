//! What an epoch boundary is read for, taken before the node forgets it.
//!
//! A checkpoint-synced node serves states from its finalized split forward. The
//! split moves in batches — Lighthouse's `--epochs-per-migration` decides how
//! big — so retention sawtooths between about two epochs and the batch size, and
//! the daemon's cursor runs a couple of epochs behind the head by construction:
//! an epoch cannot be justified before its attestations exist. Those two facts
//! meet in the trough, and on 2026-08-19 they ended a run: the epoch diff asked
//! for the registry at the boundary its accumulator sat on, one epoch behind
//! finalization, and got a 404 no restart could undo.
//!
//! Nothing about that state was unavailable. The daemon had already read it, one
//! stage earlier, to prove the same epoch's committees. What it lacked was
//! anywhere to keep it. So the boundary's two state-derived inputs — the
//! validator registry and the committee assignment — are read once, while the
//! epoch is still inside the node's window, and held here until the accumulator
//! has moved past them.
//!
//! # Why on disk
//!
//! A restart resumes a cursor that is already behind finalization, and the node
//! is under no obligation to still hold what that cursor needs. Keeping the
//! boundaries beside the store means a resumed run starts holding what it was
//! holding, rather than racing the split from a standing start.
//!
//! # Not [`crate::boundary`]
//!
//! That module opens the *finalized* epoch's boundary out of a justified
//! checkpoint's state, which is a proof input. This is a cache of node
//! responses, and nothing in it reaches a circuit.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use sha2::{Digest as _, Sha256};
use tracing::warn;

use zkasper_common::ChainConfig;

use crate::beacon_api::{BeaconApi, CommitteeResponse, ValidatorResponse};

const MAGIC: &[u8; 8] = b"ZKBOUND\x01";
const FORMAT_VERSION: u32 = 1;

/// How many boundaries are kept in memory.
///
/// Two, because that is what an epoch diff opens at once: the boundary the
/// accumulator sits on and the one it is moving to. The second becomes the first
/// of the next diff, so a run that keeps up never reads a file back.
const HOT: usize = 2;

/// The state-derived inputs one epoch boundary is read for.
///
/// Both are fatal to a stage that cannot get them, and both are only servable
/// while the node still holds the state — which is what makes them worth
/// keeping and the rest of the beacon API not. Block roots, headers and
/// attestations outlive the state they were produced with.
pub struct BoundaryInputs {
    pub slot: u64,
    pub validators: Vec<ValidatorResponse>,
    pub committees: Vec<CommitteeResponse>,
}

/// Read a boundary off the node.
pub async fn read(api: &impl BeaconApi, config: &ChainConfig, slot: u64) -> Result<BoundaryInputs> {
    let state_id = slot.to_string();
    let validators = api
        .get_validators(&state_id)
        .await
        .with_context(|| format!("fetch the validator registry at slot {slot}"))?;
    let committees = api
        .get_committees(&state_id, slot / config.slots_per_epoch)
        .await
        .with_context(|| format!("fetch the committees at slot {slot}"))?;
    Ok(BoundaryInputs {
        slot,
        validators,
        committees,
    })
}

/// Boundaries this run has taken, in memory and beside the store.
pub struct BoundaryCache {
    dir: PathBuf,
    hot: VecDeque<Arc<BoundaryInputs>>,
}

impl BoundaryCache {
    /// Beside the store, because the two are one run's state: a store resumed
    /// without its boundaries is a cursor pointed at states the node may have
    /// migrated while the daemon was down.
    pub fn beside(db_path: &Path) -> Self {
        let mut dir = db_path.as_os_str().to_owned();
        dir.push(".boundaries");
        Self {
            dir: PathBuf::from(dir),
            hot: VecDeque::new(),
        }
    }

    /// Whether the boundary at `slot` is held, without decoding it.
    pub fn holds(&self, slot: u64) -> bool {
        self.hot.iter().any(|held| held.slot == slot) || self.path(slot).exists()
    }

    /// The boundary at `slot`, from memory or from the file beside the store.
    ///
    /// A file that does not decode is deleted rather than trusted: it was
    /// written by this run and can be read again from the node if the node still
    /// has it, which is a better outcome than a registry that is subtly wrong.
    pub fn get(&mut self, slot: u64) -> Option<Arc<BoundaryInputs>> {
        if let Some(held) = self.hot.iter().find(|held| held.slot == slot) {
            return Some(held.clone());
        }
        let path = self.path(slot);
        if !path.exists() {
            return None;
        }
        match std::fs::read(&path)
            .context("read boundary file")
            .and_then(|bytes| decode(&bytes))
        {
            Ok(inputs) => Some(self.warm(Arc::new(inputs))),
            Err(e) => {
                warn!(slot, error = %format!("{e:#}"), "discarding a damaged boundary file");
                let _ = std::fs::remove_file(&path);
                None
            }
        }
    }

    /// Hold `inputs`, in memory and — best effort — beside the store.
    ///
    /// A disk that will not take the copy costs this run nothing until it
    /// restarts, so it is said once and not raised: an epoch that could be
    /// proven must not fail on a cache write.
    pub fn put(&mut self, inputs: BoundaryInputs) -> Arc<BoundaryInputs> {
        let slot = inputs.slot;
        if let Err(e) = self.write(&inputs) {
            warn!(slot, error = %format!("{e:#}"), "could not keep this boundary on disk");
        }
        self.warm(Arc::new(inputs))
    }

    /// Drop every boundary before `slot`, in memory and on disk.
    ///
    /// Called once the accumulator has moved onto `slot`, which is the oldest
    /// boundary any later stage can ask for.
    pub fn forget_before(&mut self, slot: u64) {
        self.hot.retain(|held| held.slot >= slot);
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            if slot_of(&entry.path()).is_some_and(|held| held < slot) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    fn path(&self, slot: u64) -> PathBuf {
        self.dir.join(format!("{slot:012}.bin"))
    }

    fn warm(&mut self, inputs: Arc<BoundaryInputs>) -> Arc<BoundaryInputs> {
        self.hot.retain(|held| held.slot != inputs.slot);
        self.hot.push_back(inputs.clone());
        while self.hot.len() > HOT {
            self.hot.pop_front();
        }
        inputs
    }

    fn write(&self, inputs: &BoundaryInputs) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("create {}", self.dir.display()))?;
        crate::artifacts::write_atomic(&self.path(inputs.slot), &encode(inputs))
    }
}

/// The slot a boundary file is named for.
fn slot_of(path: &Path) -> Option<u64> {
    path.file_name()?
        .to_str()?
        .strip_suffix(".bin")?
        .parse()
        .ok()
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------
//
// Flat and fixed-width rather than a derived codec: a mainnet registry is 2.3
// million validators, this is written once an epoch on the path between two
// proofs, and every byte of it is a fixed-size field already.

/// Bytes one validator takes: index, pubkey, credentials, five epochs and a flag.
const VALIDATOR_BYTES: usize = 8 + 48 + 32 + 8 * 5 + 1;

fn encode(inputs: &BoundaryInputs) -> Vec<u8> {
    let committee_bytes: usize = inputs
        .committees
        .iter()
        .map(|c| 24 + c.validators.len() * 8)
        .sum();
    let mut body =
        Vec::with_capacity(16 + inputs.validators.len() * VALIDATOR_BYTES + committee_bytes);

    body.extend_from_slice(&(inputs.validators.len() as u64).to_le_bytes());
    for v in &inputs.validators {
        body.extend_from_slice(&v.index.to_le_bytes());
        body.extend_from_slice(&v.pubkey);
        body.extend_from_slice(&v.withdrawal_credentials);
        body.extend_from_slice(&v.effective_balance.to_le_bytes());
        body.extend_from_slice(&v.activation_eligibility_epoch.to_le_bytes());
        body.extend_from_slice(&v.activation_epoch.to_le_bytes());
        body.extend_from_slice(&v.exit_epoch.to_le_bytes());
        body.extend_from_slice(&v.withdrawable_epoch.to_le_bytes());
        body.push(u8::from(v.slashed));
    }

    body.extend_from_slice(&(inputs.committees.len() as u64).to_le_bytes());
    for c in &inputs.committees {
        body.extend_from_slice(&c.slot.to_le_bytes());
        body.extend_from_slice(&c.index.to_le_bytes());
        body.extend_from_slice(&(c.validators.len() as u64).to_le_bytes());
        for index in &c.validators {
            body.extend_from_slice(&index.to_le_bytes());
        }
    }

    let mut out = Vec::with_capacity(body.len() + 52);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&inputs.slot.to_le_bytes());
    out.extend_from_slice(&Sha256::digest(&body));
    out.extend_from_slice(&body);
    out
}

fn decode(bytes: &[u8]) -> Result<BoundaryInputs> {
    const HEADER: usize = 8 + 4 + 8 + 32;
    if bytes.len() < HEADER {
        bail!(
            "truncated: {} bytes is shorter than the header",
            bytes.len()
        );
    }
    if &bytes[..8] != MAGIC {
        bail!("not a boundary file (bad magic)");
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if version != FORMAT_VERSION {
        bail!("boundary format version {version}, expected {FORMAT_VERSION}");
    }
    let slot = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
    let body = &bytes[HEADER..];
    if Sha256::digest(body).as_slice() != &bytes[20..HEADER] {
        bail!("payload checksum mismatch");
    }

    let mut at = Cursor { body, at: 0 };
    let count = at.u64()? as usize;
    let mut validators = Vec::with_capacity(count);
    for _ in 0..count {
        validators.push(ValidatorResponse {
            index: at.u64()?,
            pubkey: at.array::<48>()?,
            withdrawal_credentials: at.array::<32>()?,
            effective_balance: at.u64()?,
            activation_eligibility_epoch: at.u64()?,
            activation_epoch: at.u64()?,
            exit_epoch: at.u64()?,
            withdrawable_epoch: at.u64()?,
            slashed: at.byte()? == 1,
        });
    }

    let count = at.u64()? as usize;
    let mut committees = Vec::with_capacity(count);
    for _ in 0..count {
        let slot = at.u64()?;
        let index = at.u64()?;
        let members = at.u64()? as usize;
        let mut validators = Vec::with_capacity(members);
        for _ in 0..members {
            validators.push(at.u64()?);
        }
        committees.push(CommitteeResponse {
            slot,
            index,
            validators,
        });
    }
    if at.at != body.len() {
        bail!(
            "{} bytes left over after the last committee",
            body.len() - at.at
        );
    }

    Ok(BoundaryInputs {
        slot,
        validators,
        committees,
    })
}

struct Cursor<'a> {
    body: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self.at.checked_add(n).context("length overflow")?;
        if end > self.body.len() {
            bail!("truncated at byte {}", self.at);
        }
        let taken = &self.body[self.at..end];
        self.at = end;
        Ok(taken)
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(slot: u64) -> BoundaryInputs {
        BoundaryInputs {
            slot,
            validators: (0..3)
                .map(|i| ValidatorResponse {
                    index: i,
                    pubkey: [i as u8; 48],
                    effective_balance: 32_000_000_000 + i,
                    activation_epoch: i,
                    exit_epoch: u64::MAX,
                    withdrawal_credentials: [0x01; 32],
                    slashed: i == 1,
                    activation_eligibility_epoch: 0,
                    withdrawable_epoch: u64::MAX,
                })
                .collect(),
            committees: vec![
                CommitteeResponse {
                    slot,
                    index: 0,
                    validators: vec![0, 2],
                },
                CommitteeResponse {
                    slot: slot + 1,
                    index: 0,
                    validators: vec![1],
                },
            ],
        }
    }

    #[test]
    fn round_trips_a_boundary() {
        let original = inputs(320);
        let decoded = decode(&encode(&original)).expect("decodes");
        assert_eq!(decoded.slot, original.slot);
        assert_eq!(decoded.validators.len(), original.validators.len());
        for (got, want) in decoded.validators.iter().zip(&original.validators) {
            assert_eq!(got.index, want.index);
            assert_eq!(got.pubkey, want.pubkey);
            assert_eq!(got.withdrawal_credentials, want.withdrawal_credentials);
            assert_eq!(got.effective_balance, want.effective_balance);
            assert_eq!(got.activation_epoch, want.activation_epoch);
            assert_eq!(got.exit_epoch, want.exit_epoch);
            assert_eq!(got.withdrawable_epoch, want.withdrawable_epoch);
            assert_eq!(
                got.activation_eligibility_epoch,
                want.activation_eligibility_epoch
            );
            assert_eq!(got.slashed, want.slashed);
        }
        assert_eq!(decoded.committees.len(), 2);
        assert_eq!(decoded.committees[0].validators, vec![0, 2]);
        assert_eq!(decoded.committees[1].slot, 321);
    }

    #[test]
    fn refuses_a_corrupted_boundary() {
        let mut bytes = encode(&inputs(320));
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        assert!(decode(&bytes).is_err(), "a flipped byte has to be caught");
    }

    /// The disk copy is what a restart resumes onto, so it has to survive one.
    #[test]
    fn keeps_a_boundary_across_a_new_cache() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("zkasperd.db");

        let mut cache = BoundaryCache::beside(&db);
        cache.put(inputs(320));
        assert!(cache.holds(320));

        let mut reopened = BoundaryCache::beside(&db);
        let held = reopened
            .get(320)
            .expect("the file beside the store is read");
        assert_eq!(held.validators.len(), 3);

        reopened.forget_before(352);
        assert!(
            !reopened.holds(320),
            "a boundary behind the cursor is dropped"
        );
    }
}
