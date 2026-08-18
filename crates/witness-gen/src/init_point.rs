//! Where the accumulator chain starts, as configuration rather than as a proof.
//!
//! The daemon used to open by proving a bootstrap: read the whole validator
//! registry out of a beacon state, rebuild Ethereum's depth-40 SSZ tree and this
//! project's depth-22 accumulator over every validator, and prove in-circuit
//! that the two agree under a claimed `state_root`. That proof cost about two
//! minutes and a 320 MB state download, and it bought less than it looked like.
//!
//! It only ever proved the accumulator matched *a* state root. Whether that root
//! is canonical Ethereum was the operator's choice then and is the operator's
//! choice now — `docs/assumptions.md` has always said so. What the proof added
//! was a way to check the accumulator against the root without redoing the work.
//! Since the accumulator is a deterministic function of the validator list,
//! redoing the work is a thing anyone can do, and it is what this module does:
//! the daemon walks the registry at the configured epoch and refuses to start
//! unless everything it computes matches what it was told.
//!
//! So the trust delta is narrow. Accumulator-correctness moves from "verify this
//! proof" to "recompute it yourself", and the starting state root is trusted
//! exactly as much as it was before. What is gone is the two-minute window in
//! which a checkpoint-synced node could prune the very state the bootstrap was
//! reading — the failure mode that cost the accumulator chain a break every time
//! the supervisor deleted the store and tried again.
//!
//! # The tuple
//!
//! An init point is JSON, small enough to read and diff by eye:
//!
//! ```json
//! {
//!   "chain": "mainnet",
//!   "epoch": 401234,
//!   "state_root": "0x...",
//!   "num_validators": 2338764,
//!   "total_active_balance": 34103000000000000,
//!   "acc_root": "0x...",
//!   "accumulator_commitment": "0x...",
//!   "state_to_validators_siblings": ["0x...", "0x..."]
//! }
//! ```
//!
//! [`generate`] produces one from a beacon state and [`open`] consumes one, so a
//! third party can rebuild ours from the same state root and compare bytes.
//!
//! # Refusing a bad one
//!
//! `accumulator_commitment` is `acc::commitment(acc_root, total_active_balance)`
//! by definition, so a tuple whose three fields disagree is one nobody holds an
//! accumulator for. [`InitPoint::check`] catches that with no network at all and
//! runs before the first beacon call; [`open`] then checks the rest against a
//! registry walk. A wrong init point stops the daemon at startup rather than
//! producing proofs against an accumulator that does not exist.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

use zkasper_common::acc::{self, Digest};
use zkasper_common::ssz::{compute_ssz_merkle_root, list_hash_tree_root};
use zkasper_common::ChainConfig;

use crate::acc_tree::AccTree;
use crate::artifacts::{hex0x, hex_digest};
use crate::beacon_api::BeaconApi;
use crate::epoch_state::EpochState;
use crate::ssz_state;
use crate::state_diff::{
    build_validator_roots, build_validators_ssz_tree, make_state_proof, validator_response_to_data,
    SlotHistory,
};
use crate::store::{Snapshot, StoreState};

/// The trusted starting point of an accumulator chain.
///
/// Every field is what the deleted bootstrap circuit used to commit to, which is
/// why nothing downstream had to change: the daemon still begins epoch N holding
/// an accumulator whose root, commitment and total active balance it can name.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitPoint {
    /// Chain this was taken from. Checked against the chain the daemon resolved
    /// from the node's genesis validators root, so a mainnet init point cannot
    /// quietly start a gnosis run.
    pub chain: String,
    /// Epoch the accumulator represents. Its state is the one at the epoch's
    /// first slot.
    pub epoch: u64,
    /// The beacon state root the registry was read out of. This is the trusted
    /// input: nothing here proves it is canonical Ethereum, and nothing ever
    /// did.
    #[serde(with = "hex_bytes32")]
    pub state_root: [u8; 32],
    pub num_validators: u64,
    pub total_active_balance: u64,
    #[serde(with = "hex_digest_serde")]
    pub acc_root: Digest,
    #[serde(with = "hex_digest_serde")]
    pub accumulator_commitment: Digest,
    /// The Merkle branch from `state_root` down to the `validators` field, so
    /// the daemon can bind the registry it walks to the state root it was given
    /// without downloading the state itself.
    #[serde(with = "hex_bytes32_vec")]
    pub state_to_validators_siblings: Vec<[u8; 32]>,
}

impl InitPoint {
    /// Read and check an init point, without touching the network.
    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes =
            std::fs::read(path).with_context(|| format!("read init point {}", path.display()))?;
        let init: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse init point {}", path.display()))?;
        init.check()
            .with_context(|| format!("init point {} is not self-consistent", path.display()))?;
        Ok(init)
    }

    pub fn write(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let mut bytes = serde_json::to_vec_pretty(self).context("serialize init point")?;
        bytes.push(b'\n');
        std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
    }

    /// Everything that can be checked from the tuple alone.
    ///
    /// The commitment binds the root and the total active balance, so a tuple
    /// that fails here names an accumulator nobody has. Cheap, offline, and run
    /// before the daemon makes its first beacon call.
    pub fn check(&self) -> Result<()> {
        if self.chain.is_empty() {
            bail!("init point names no chain");
        }
        if self.num_validators == 0 {
            bail!("init point has no validators");
        }
        let expected = acc::commitment(&self.acc_root, self.total_active_balance);
        if expected != self.accumulator_commitment {
            bail!(
                "accumulator_commitment {} does not bind acc_root {} and total_active_balance {}; \
                 acc::commitment of those two is {}",
                hex_digest(&self.accumulator_commitment),
                hex_digest(&self.acc_root),
                self.total_active_balance,
                hex_digest(&expected),
            );
        }
        Ok(())
    }

    /// First slot of [`InitPoint::epoch`] — the state the registry was read at.
    pub fn slot(&self, config: &ChainConfig) -> u64 {
        self.epoch * config.slots_per_epoch
    }
}

/// What walking a state's validator registry produces.
struct Walk {
    tree: AccTree,
    validator_roots: Vec<[u8; 32]>,
    ssz_data_root: [u8; 32],
    num_validators: u64,
    total_active_balance: u64,
}

/// Build the accumulator and the SSZ view of the registry at `slot`.
///
/// The one expensive thing the daemon still does at startup, and the reason it
/// is honest to call the result checked rather than trusted: this is the same
/// deterministic function of the validator list that produced the init point.
async fn walk(api: &impl BeaconApi, config: &ChainConfig, slot: u64, epoch: u64) -> Result<Walk> {
    let validators = api
        .get_validators(&slot.to_string())
        .await
        .with_context(|| format!("fetch the validator registry at slot {slot}"))?;
    let num_validators = validators.len() as u64;
    anyhow::ensure!(num_validators > 0, "the registry at slot {slot} is empty");

    let validator_roots = build_validator_roots(&validators);
    let (ssz_data_root, _) =
        build_validators_ssz_tree(&validator_roots, config.validators_tree_depth, &[]);

    let data: Vec<_> = validators.iter().map(validator_response_to_data).collect();
    let tree = AccTree::build(&data, epoch, config.acc_tree_depth);
    let total_active_balance = data.iter().map(|v| v.active_effective_balance(epoch)).sum();

    Ok(Walk {
        tree,
        validator_roots,
        ssz_data_root,
        num_validators,
        total_active_balance,
    })
}

/// Take an init point from the beacon state at `slot`, and the snapshot a
/// daemon starting from it would hold.
///
/// One walk of the registry produces both, which is what a caller that wants the
/// accumulator as well as the tuple should use. [`generate`] is this with the
/// snapshot dropped.
pub async fn take(
    api: &impl BeaconApi,
    config: &ChainConfig,
    chain: impl Into<String>,
    slot: u64,
) -> Result<(InitPoint, Snapshot)> {
    anyhow::ensure!(
        slot.is_multiple_of(config.slots_per_epoch),
        "slot {slot} is not an epoch boundary",
    );
    let epoch = slot / config.slots_per_epoch;
    let walked = walk(api, config, slot, epoch).await?;
    let validators_htr = list_hash_tree_root(&walked.ssz_data_root, walked.num_validators);

    // A node that serves the debug state endpoint gives the real branch. The
    // fixture sources do not, and fall back to the synthetic state the rest of
    // the pipeline agrees on. An init point is the base of a synthetic chain, so
    // it records no boundary before it.
    let (state_root, state_to_validators_siblings) =
        match api.get_state_ssz(&slot.to_string()).await? {
            Some(raw) => {
                let proof = ssz_state::parse_state_proof(&raw, &validators_htr, config, slot)?;
                (proof.state_root, proof.siblings)
            }
            None => make_state_proof(
                &walked.ssz_data_root,
                walked.num_validators,
                &SlotHistory::default(),
            ),
        };

    // Whatever produced the branch, it has to open to the root the chain claims
    // for this slot, or the init point would name a state that does not exist.
    let claimed = match api.get_state_root(&slot.to_string()).await? {
        Some(root) => root,
        None => {
            api.get_header(&slot.to_string())
                .await
                .with_context(|| format!("fetch the header at slot {slot}"))?
                .state_root
        }
    };
    anyhow::ensure!(
        state_root == claimed,
        "the state root computed at slot {slot} is {} but the chain says {}",
        hex0x(&state_root),
        hex0x(&claimed),
    );

    let acc_root = walked.tree.root();
    let chain = chain.into();
    let init = InitPoint {
        chain: chain.clone(),
        epoch,
        state_root,
        num_validators: walked.num_validators,
        total_active_balance: walked.total_active_balance,
        acc_root,
        accumulator_commitment: acc::commitment(&acc_root, walked.total_active_balance),
        state_to_validators_siblings: state_to_validators_siblings.clone(),
    };
    let snapshot = Snapshot {
        state: StoreState::started(
            chain,
            epoch,
            acc_root,
            walked.total_active_balance,
            walked.num_validators,
        ),
        tree: walked.tree,
        epoch_state: EpochState {
            slot,
            state_root,
            state_to_validators_siblings,
            validator_roots: walked.validator_roots,
            ssz_data_root: walked.ssz_data_root,
            num_validators: walked.num_validators,
        },
    };
    Ok((init, snapshot))
}

/// Take an init point from the beacon state at `slot`.
///
/// This is the generator behind the `zkasper-init-point` binary. It is also what
/// the tests start a run from, so the path an operator takes is the path the
/// suite exercises.
pub async fn generate(
    api: &impl BeaconApi,
    config: &ChainConfig,
    chain: impl Into<String>,
    slot: u64,
) -> Result<InitPoint> {
    take(api, config, chain, slot).await.map(|(init, _)| init)
}

/// Start an accumulator chain from `init`, checking every field against a fresh
/// walk of the registry.
///
/// Four things have to agree, and each names itself when it does not: the
/// validator count, the total active balance, the accumulator root, and the
/// state root the branch opens to. An init point that survives all four
/// describes an accumulator this daemon has actually built.
pub async fn open(
    api: &impl BeaconApi,
    config: &ChainConfig,
    chain_name: &str,
    init: &InitPoint,
) -> Result<Snapshot> {
    init.check()?;
    if init.chain != chain_name {
        bail!(
            "init point is for {}, but this run is configured for {chain_name}",
            init.chain,
        );
    }

    let slot = init.slot(config);
    let walked = walk(api, config, slot, init.epoch)
        .await
        .with_context(|| format!("walk the registry the init point names, at slot {slot}"))?;

    if walked.num_validators != init.num_validators {
        bail!(
            "init point claims {} validators at epoch {}, but the state at slot {slot} has {}",
            init.num_validators,
            init.epoch,
            walked.num_validators,
        );
    }
    if walked.total_active_balance != init.total_active_balance {
        bail!(
            "init point claims a total active balance of {} at epoch {}, but the state at slot \
             {slot} gives {}",
            init.total_active_balance,
            init.epoch,
            walked.total_active_balance,
        );
    }
    let acc_root = walked.tree.root();
    if acc_root != init.acc_root {
        bail!(
            "init point claims accumulator root {} at epoch {}, but the state at slot {slot} \
             builds {}",
            hex_digest(&init.acc_root),
            init.epoch,
            hex_digest(&acc_root),
        );
    }
    let validators_htr = list_hash_tree_root(&walked.ssz_data_root, walked.num_validators);
    let opened = compute_ssz_merkle_root(
        &validators_htr,
        config.beacon_state_validators_field_index,
        &init.state_to_validators_siblings,
    );
    if opened != init.state_root {
        bail!(
            "the registry at slot {slot} and the init point's branch open to {}, not to the \
             init point's state root {}",
            hex0x(&opened),
            hex0x(&init.state_root),
        );
    }

    info!(
        epoch = init.epoch,
        num_validators = init.num_validators,
        total_active_balance = init.total_active_balance,
        acc_root = %hex_digest(&acc_root),
        state_root = %hex0x(&init.state_root),
        "started from a trusted init point",
    );

    Ok(Snapshot {
        state: StoreState::started(
            init.chain.clone(),
            init.epoch,
            acc_root,
            init.total_active_balance,
            init.num_validators,
        ),
        tree: walked.tree,
        epoch_state: EpochState {
            slot,
            state_root: init.state_root,
            state_to_validators_siblings: init.state_to_validators_siblings.clone(),
            validator_roots: walked.validator_roots,
            ssz_data_root: walked.ssz_data_root,
            num_validators: walked.num_validators,
        },
    })
}

/// `[u8; 32]` as `"0x…"`, so an init point can be read and diffed by eye.
mod hex_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::artifacts::hex0x(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        super::parse_bytes32(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

mod hex_bytes32_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(value.iter().map(|b| crate::artifacts::hex0x(b)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| super::parse_bytes32(s))
            .collect::<Result<_, _>>()
            .map_err(serde::de::Error::custom)
    }
}

/// An accumulator digest is four Goldilocks elements; it is written the way the
/// status manifest writes it, so the two can be compared without conversion.
mod hex_digest_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use zkasper_common::acc::{self, Digest};

    pub fn serialize<S: Serializer>(value: &Digest, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::artifacts::hex_digest(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Digest, D::Error> {
        super::parse_bytes32(&String::deserialize(d)?)
            .map(|b| acc::from_bytes(&b))
            .map_err(serde::de::Error::custom)
    }
}

fn parse_bytes32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| e.to_string())?;
    bytes
        .try_into()
        .map_err(|_| format!("expected 32 bytes, got {}", s.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> InitPoint {
        let acc_root = [1u64, 2, 3, 4];
        let total_active_balance = 32_000_000_000;
        InitPoint {
            chain: "mainnet".into(),
            epoch: 401_234,
            state_root: [7u8; 32],
            num_validators: 512,
            total_active_balance,
            acc_root,
            accumulator_commitment: acc::commitment(&acc_root, total_active_balance),
            state_to_validators_siblings: vec![[9u8; 32], [11u8; 32]],
        }
    }

    #[test]
    fn round_trips_through_json() {
        let init = sample();
        let json = serde_json::to_string_pretty(&init).unwrap();
        assert!(json.contains("\"0x"), "digests are written as hex: {json}");
        assert_eq!(serde_json::from_str::<InitPoint>(&json).unwrap(), init);
    }

    #[test]
    fn accepts_a_consistent_tuple() {
        sample().check().unwrap();
    }

    /// The whole point of checking at startup: a tuple whose commitment does not
    /// bind its root and balance names an accumulator nobody holds.
    #[test]
    fn rejects_a_commitment_that_binds_nothing() {
        let mut init = sample();
        init.accumulator_commitment = [0, 0, 0, 0];
        let error = init.check().unwrap_err().to_string();
        assert!(error.contains("does not bind"), "{error}");
    }

    /// Changing either bound value has to invalidate the commitment, or the
    /// check would pass for a different accumulator than the one described.
    #[test]
    fn rejects_a_balance_the_commitment_was_not_made_over() {
        let mut init = sample();
        init.total_active_balance += 1;
        assert!(init.check().is_err());

        let mut init = sample();
        init.acc_root[0] ^= 1;
        assert!(init.check().is_err());
    }

    #[test]
    fn rejects_an_empty_registry() {
        let mut init = sample();
        init.num_validators = 0;
        assert!(init.check().is_err());
    }

    #[test]
    fn read_rejects_an_inconsistent_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("init.json");
        let mut init = sample();
        init.total_active_balance += 1;
        // Written past `write`, which would have no reason to emit this.
        std::fs::write(&path, serde_json::to_vec_pretty(&init).unwrap()).unwrap();
        let error = format!("{:#}", InitPoint::read(&path).unwrap_err());
        assert!(error.contains("not self-consistent"), "{error}");
    }

    #[test]
    fn write_then_read_is_the_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("init.json");
        let init = sample();
        init.write(&path).unwrap();
        assert_eq!(InitPoint::read(&path).unwrap(), init);
    }
}
