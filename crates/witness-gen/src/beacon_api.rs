//! Beacon REST API client.
//!
//! Talks to a standard Ethereum beacon node via the Beacon API:
//! - `/eth/v1/beacon/states/{state_id}/validators` — validator list
//! - `/eth/v2/beacon/blocks/{block_id}/attestations` — block attestations
//! - `/eth/v1/beacon/states/{state_id}/committees` — committee assignments
//! - `/eth/v1/beacon/headers/{block_id}` — block header
//!
//! Continuous operation needs a few more, split out into [`ChainStatusApi`] so
//! that fixture-backed sources can keep implementing [`BeaconApi`] alone:
//! - `/eth/v1/beacon/blocks/{block_id}/root` — checkpoint roots
//! - `/eth/v1/beacon/genesis` — genesis validators root
//! - `/eth/v1/beacon/states/{state_id}/fork` — fork version
//! - `/eth/v1/beacon/states/{state_id}/finality_checkpoints` — where the node is

use anyhow::{bail, Context, Result};
use zkasper_common::types::{BlockHeaderFields, Checkpoint};

/// Trait abstracting beacon API access. Implement this for mock-based testing.
#[async_trait::async_trait]
pub trait BeaconApi {
    async fn get_validators(&self, state_id: &str) -> Result<Vec<ValidatorResponse>>;
    async fn get_block_attestations(&self, block_id: &str) -> Result<Vec<AttestationResponse>>;
    async fn get_committees(&self, state_id: &str, epoch: u64) -> Result<Vec<CommitteeResponse>>;
    async fn get_header(&self, block_id: &str) -> Result<HeaderResponse>;

    /// Fetch the raw SSZ-encoded BeaconState from the debug API endpoint.
    /// Returns `None` if the endpoint is not available (e.g., mock API).
    async fn get_state_ssz(&self, state_id: &str) -> Result<Option<Vec<u8>>>;

    /// State root at `state_id`, when the source can say so on its own.
    ///
    /// The epoch diff checks the state it parsed against what the chain says
    /// that slot's state root is. A block header carries one, but only when that
    /// slot has a block — and an epoch boundary slot is empty often enough that
    /// a daemon reading the header stops dead at the first one. A state root is
    /// defined for a skipped slot; a header is not.
    ///
    /// `None` means "read the header instead", which is what every
    /// fixture-backed source returns. It has no default body on purpose: a
    /// defaulted `async_trait` method requires `Self: Sync` at every call site,
    /// which would push a new bound through the orchestrator for nothing.
    async fn get_state_root(&self, state_id: &str) -> Result<Option<[u8; 32]>>;
}

/// The chain-following half of the beacon API.
///
/// [`BeaconApi`] is enough to build any single witness from data the caller
/// already knows how to address. A daemon does not know: it has to ask the node
/// where the chain is, which block a checkpoint refers to, and which domain
/// attestations were signed under. Those live here so that file-backed sources
/// used in tests are not forced to fake them.
#[async_trait::async_trait]
pub trait ChainStatusApi {
    /// Block root of `block_id`, or `None` when that slot holds no block.
    async fn get_block_root(&self, block_id: &str) -> Result<Option<[u8; 32]>>;

    /// Genesis validators root, one of the two inputs to the signing domain.
    async fn get_genesis_validators_root(&self) -> Result<[u8; 32]>;

    /// Unix seconds at which slot 0 began. What turns a slot into a wall-clock
    /// time, and therefore what lets "when should this proof have started" be
    /// compared against when it did.
    async fn get_genesis_time(&self) -> Result<u64>;

    /// Fork version in effect at `state_id`, the other input to the domain.
    async fn get_fork_version(&self, state_id: &str) -> Result<[u8; 4]>;

    /// The node's own view of justification and finalization.
    async fn get_finality_checkpoints(&self, state_id: &str) -> Result<FinalityCheckpoints>;
}

/// The node's `finality_checkpoints` response.
#[derive(Debug, Clone)]
pub struct FinalityCheckpoints {
    pub previous_justified: Checkpoint,
    pub current_justified: Checkpoint,
    pub finalized: Checkpoint,
}

pub struct BeaconApiClient {
    pub base_url: String,
    pub client: reqwest::Client,
}

impl BeaconApiClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl BeaconApi for BeaconApiClient {
    async fn get_validators(&self, state_id: &str) -> Result<Vec<ValidatorResponse>> {
        let url = format!(
            "{}/eth/v1/beacon/states/{}/validators",
            self.base_url, state_id
        );
        let resp = checked_json(self.client.get(&url).send().await?).await?;
        let data = resp["data"]
            .as_array()
            .context("missing data array in validators response")?;

        let mut validators = Vec::with_capacity(data.len());
        for entry in data {
            validators.push(parse_validator_entry(entry)?);
        }
        Ok(validators)
    }

    async fn get_block_attestations(&self, block_id: &str) -> Result<Vec<AttestationResponse>> {
        let url = format!(
            "{}/eth/v2/beacon/blocks/{}/attestations",
            self.base_url, block_id
        );
        let resp = checked_json(self.client.get(&url).send().await?).await?;
        let data = resp["data"]
            .as_array()
            .context("missing data array in attestations response")?;

        let mut attestations = Vec::with_capacity(data.len());
        for entry in data {
            attestations.push(parse_attestation_entry(entry)?);
        }
        Ok(attestations)
    }

    async fn get_committees(&self, state_id: &str, epoch: u64) -> Result<Vec<CommitteeResponse>> {
        let url = format!(
            "{}/eth/v1/beacon/states/{}/committees?epoch={}",
            self.base_url, state_id, epoch
        );
        let resp = checked_json(self.client.get(&url).send().await?).await?;
        let data = resp["data"]
            .as_array()
            .context("missing data array in committees response")?;

        let mut committees = Vec::with_capacity(data.len());
        for entry in data {
            committees.push(parse_committee_entry(entry)?);
        }
        Ok(committees)
    }

    async fn get_header(&self, block_id: &str) -> Result<HeaderResponse> {
        let url = format!("{}/eth/v1/beacon/headers/{}", self.base_url, block_id);
        let resp = checked_json(self.client.get(&url).send().await?).await?;
        let header = &resp["data"]["header"]["message"];

        Ok(HeaderResponse {
            slot: parse_u64_str(header, "slot")?,
            proposer_index: parse_u64_str(header, "proposer_index")?,
            state_root: parse_hex_bytes32(header, "state_root")?,
            parent_root: parse_hex_bytes32(header, "parent_root")?,
            body_root: parse_hex_bytes32(header, "body_root")?,
        })
    }

    async fn get_state_ssz(&self, state_id: &str) -> Result<Option<Vec<u8>>> {
        let url = format!("{}/eth/v2/debug/beacon/states/{}", self.base_url, state_id);
        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/octet-stream")
            .send()
            .await?;

        // `None` means "this node does not serve the endpoint", and the callers
        // answer it with a synthetic state proof. Only a node that says so may
        // be taken that way: 404/405/501 are the standard ways of saying it.
        // Anything else — a 5xx, a 403, a timeout — is one call failing, and
        // returning `None` for those would swap a real state root for a
        // fabricated one for as long as the failure lasted, without a log line.
        let status = resp.status();
        if matches!(status.as_u16(), 404 | 405 | 501) {
            return Ok(None);
        }
        if !status.is_success() {
            anyhow::bail!("{url} returned {status}");
        }

        let bytes = resp.bytes().await?;
        Ok(Some(bytes.to_vec()))
    }

    async fn get_state_root(&self, state_id: &str) -> Result<Option<[u8; 32]>> {
        let url = format!("{}/eth/v1/beacon/states/{}/root", self.base_url, state_id);
        let resp = self.client.get(&url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            // A node that will not answer for this slot is the `None` the trait
            // documents — read the header instead. Returning an error here would
            // make the `Option` unreachable for the one implementation that has
            // a network behind it.
            return Ok(None);
        }
        let resp: serde_json::Value = resp.error_for_status()?.json().await?;
        Ok(Some(parse_hex_bytes32(&resp["data"], "root")?))
    }
}

#[async_trait::async_trait]
impl ChainStatusApi for BeaconApiClient {
    async fn get_block_root(&self, block_id: &str) -> Result<Option<[u8; 32]>> {
        let url = format!("{}/eth/v1/beacon/blocks/{}/root", self.base_url, block_id);
        let resp = self.client.get(&url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            // A skipped slot has no block, which is not an error.
            return Ok(None);
        }
        let resp: serde_json::Value = resp.error_for_status()?.json().await?;
        Ok(Some(parse_hex_bytes32(&resp["data"], "root")?))
    }

    async fn get_genesis_validators_root(&self) -> Result<[u8; 32]> {
        let url = format!("{}/eth/v1/beacon/genesis", self.base_url);
        let resp = checked_json(self.client.get(&url).send().await?).await?;
        parse_hex_bytes32(&resp["data"], "genesis_validators_root")
    }

    async fn get_genesis_time(&self) -> Result<u64> {
        let url = format!("{}/eth/v1/beacon/genesis", self.base_url);
        let resp = checked_json(self.client.get(&url).send().await?).await?;
        resp["data"]["genesis_time"]
            .as_str()
            .context("genesis response has no genesis_time")?
            .parse()
            .context("genesis_time is not a number")
    }

    async fn get_fork_version(&self, state_id: &str) -> Result<[u8; 4]> {
        let url = format!("{}/eth/v1/beacon/states/{}/fork", self.base_url, state_id);
        let resp = checked_json(self.client.get(&url).send().await?).await?;
        parse_hex_bytes4(&resp["data"], "current_version")
    }

    async fn get_finality_checkpoints(&self, state_id: &str) -> Result<FinalityCheckpoints> {
        let url = format!(
            "{}/eth/v1/beacon/states/{}/finality_checkpoints",
            self.base_url, state_id
        );
        let resp = checked_json(self.client.get(&url).send().await?).await?;
        let data = &resp["data"];
        Ok(FinalityCheckpoints {
            previous_justified: parse_checkpoint(&data["previous_justified"])?,
            current_justified: parse_checkpoint(&data["current_justified"])?,
            finalized: parse_checkpoint(&data["finalized"])?,
        })
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ValidatorResponse {
    pub index: u64,
    pub pubkey: [u8; 48],
    pub effective_balance: u64,
    pub activation_epoch: u64,
    pub exit_epoch: u64,
    pub withdrawal_credentials: [u8; 32],
    pub slashed: bool,
    pub activation_eligibility_epoch: u64,
    pub withdrawable_epoch: u64,
}

/// The one validator an Electra `SingleAttestation` names, and the committee it
/// sits in. Resolving it needs no bitfield, which is why the bitfields are left
/// empty when this is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SingleAttester {
    pub committee_index: u64,
    pub attester_index: u64,
}

#[derive(Debug, Clone)]
pub struct AttestationResponse {
    pub aggregation_bits: Vec<u8>,
    pub committee_bits: Vec<u8>,
    /// Set when the node published this on the `single_attestation` topic
    /// rather than as an aggregate. See [`crate::gossip`].
    pub single_attester: Option<SingleAttester>,
    pub data_slot: u64,
    pub data_index: u64,
    pub data_beacon_block_root: [u8; 32],
    pub data_source_epoch: u64,
    pub data_source_root: [u8; 32],
    pub data_target_epoch: u64,
    pub data_target_root: [u8; 32],
    pub signature: [u8; 96],
}

#[derive(Debug, Clone)]
pub struct CommitteeResponse {
    pub slot: u64,
    pub index: u64,
    pub validators: Vec<u64>,
}

/// All five `BeaconBlockHeader` fields, so a caller can recompute the block
/// root the finalization circuit checks the header against.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HeaderResponse {
    pub slot: u64,
    pub proposer_index: u64,
    pub state_root: [u8; 32],
    pub parent_root: [u8; 32],
    pub body_root: [u8; 32],
}

impl HeaderResponse {
    pub fn fields(&self) -> BlockHeaderFields {
        BlockHeaderFields {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body_root: self.body_root,
        }
    }

    /// The block root this header hashes to.
    pub fn root(&self) -> [u8; 32] {
        zkasper_common::ssz::block_header_root(
            self.slot,
            self.proposer_index,
            &self.parent_root,
            &self.state_root,
            &self.body_root,
        )
    }
}

// ---------------------------------------------------------------------------
// JSON parsing helpers
// ---------------------------------------------------------------------------

/// Read a response body as JSON, refusing one the node did not say was an answer.
///
/// A beacon node reports a missing state as a JSON error object with a 404, and
/// that object parses. Without this the field lookup is what fails, so a node
/// that says `NOT_FOUND: beacon state at slot 15019808` reaches the operator as
/// `missing current_version` — which names the wrong endpoint, the wrong cause
/// and no slot.
async fn checked_json(resp: reqwest::Response) -> Result<serde_json::Value> {
    let status = resp.status();
    let url = resp.url().clone();
    let body = resp.text().await.context("read response body")?;
    if !status.is_success() {
        bail!("{url} returned {status}: {}", body.trim());
    }
    serde_json::from_str(&body).with_context(|| format!("parse the response from {url}"))
}

fn parse_u64_str(val: &serde_json::Value, field: &str) -> Result<u64> {
    val[field]
        .as_str()
        .context(format!("missing {field}"))?
        .parse::<u64>()
        .context(format!("invalid {field}"))
}

fn parse_hex_bytes32(val: &serde_json::Value, field: &str) -> Result<[u8; 32]> {
    let s = val[field].as_str().context(format!("missing {field}"))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context(format!("invalid hex in {field}"))?;
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

fn parse_hex_bytes4(val: &serde_json::Value, field: &str) -> Result<[u8; 4]> {
    let s = val[field].as_str().context(format!("missing {field}"))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context(format!("invalid hex in {field}"))?;
    anyhow::ensure!(
        bytes.len() == 4,
        "{field}: expected 4 bytes, got {}",
        bytes.len()
    );
    let mut result = [0u8; 4];
    result.copy_from_slice(&bytes);
    Ok(result)
}

fn parse_checkpoint(val: &serde_json::Value) -> Result<Checkpoint> {
    Ok(Checkpoint {
        epoch: parse_u64_str(val, "epoch")?,
        root: parse_hex_bytes32(val, "root")?,
    })
}

fn parse_hex_bytes48(val: &serde_json::Value, field: &str) -> Result<[u8; 48]> {
    let s = val[field].as_str().context(format!("missing {field}"))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context(format!("invalid hex in {field}"))?;
    let mut result = [0u8; 48];
    result.copy_from_slice(&bytes);
    Ok(result)
}

fn parse_hex_bytes96(val: &serde_json::Value, field: &str) -> Result<[u8; 96]> {
    let s = val[field].as_str().context(format!("missing {field}"))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context(format!("invalid hex in {field}"))?;
    let mut result = [0u8; 96];
    result.copy_from_slice(&bytes);
    Ok(result)
}

fn parse_hex_bitfield(val: &serde_json::Value, field: &str) -> Result<Vec<u8>> {
    let s = val[field].as_str().context(format!("missing {field}"))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).context(format!("invalid hex in {field}"))
}

fn parse_validator_entry(entry: &serde_json::Value) -> Result<ValidatorResponse> {
    let v = &entry["validator"];
    Ok(ValidatorResponse {
        index: parse_u64_str(entry, "index")?,
        pubkey: parse_hex_bytes48(v, "pubkey")?,
        effective_balance: parse_u64_str(v, "effective_balance")?,
        activation_epoch: parse_u64_str(v, "activation_epoch")?,
        exit_epoch: parse_u64_str(v, "exit_epoch")?,
        withdrawal_credentials: parse_hex_bytes32(v, "withdrawal_credentials")?,
        slashed: v["slashed"].as_bool().unwrap_or(false),
        activation_eligibility_epoch: parse_u64_str(v, "activation_eligibility_epoch")?,
        withdrawable_epoch: parse_u64_str(v, "withdrawable_epoch")?,
    })
}

pub fn parse_attestation_entry(entry: &serde_json::Value) -> Result<AttestationResponse> {
    let data = &entry["data"];
    Ok(AttestationResponse {
        aggregation_bits: parse_hex_bitfield(entry, "aggregation_bits")?,
        committee_bits: entry
            .get("committee_bits")
            .and_then(|v| v.as_str())
            .map(|s| {
                let s = s.strip_prefix("0x").unwrap_or(s);
                hex::decode(s).unwrap_or_default()
            })
            .unwrap_or_default(),
        data_slot: parse_u64_str(data, "slot")?,
        data_index: parse_u64_str(data, "index")?,
        data_beacon_block_root: parse_hex_bytes32(data, "beacon_block_root")?,
        data_source_epoch: parse_u64_str(&data["source"], "epoch")?,
        data_source_root: parse_hex_bytes32(&data["source"], "root")?,
        data_target_epoch: parse_u64_str(&data["target"], "epoch")?,
        data_target_root: parse_hex_bytes32(&data["target"], "root")?,
        signature: parse_hex_bytes96(entry, "signature")?,
        single_attester: None,
    })
}

/// One `SingleAttestation`, as Electra publishes unaggregated attestations.
///
/// It carries the same `AttestationData` an aggregate does — so it shares a
/// message with them and costs the proof nothing extra — plus the one validator
/// index that signed, in place of two bitfields.
pub fn parse_single_attestation_entry(entry: &serde_json::Value) -> Result<AttestationResponse> {
    Ok(AttestationResponse {
        single_attester: Some(SingleAttester {
            committee_index: parse_u64_str(entry, "committee_index")?,
            attester_index: parse_u64_str(entry, "attester_index")?,
        }),
        ..parse_attestation_entry(&serde_json::json!({
            "aggregation_bits": "0x",
            "data": entry["data"],
            "signature": entry["signature"],
        }))?
    })
}

pub fn parse_committee_entry(entry: &serde_json::Value) -> Result<CommitteeResponse> {
    let validators = entry["validators"]
        .as_array()
        .context("missing validators")?
        .iter()
        .map(|v| {
            v.as_str()
                .context("validator not string")?
                .parse::<u64>()
                .context("invalid validator index")
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(CommitteeResponse {
        slot: parse_u64_str(entry, "slot")?,
        index: parse_u64_str(entry, "index")?,
        validators,
    })
}
