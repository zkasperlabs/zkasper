// Shared test helpers; each test binary uses a different subset.
#![allow(dead_code)]

//! MockBeaconApi and test helpers for witness-gen integration tests.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::Result;

use zkasper_common::constants::FAR_FUTURE_EPOCH;
use zkasper_common::types::{Checkpoint, ValidatorData};

use zkasper_witness_gen::beacon_api::{
    AttestationResponse, BeaconApi, ChainStatusApi, CommitteeResponse, FinalityCheckpoints,
    HeaderResponse, ValidatorResponse,
};

/// A mock beacon API that returns synthetic data for testing.
pub struct MockBeaconApi {
    /// Validators per slot: slot -> validators
    pub validators: HashMap<String, Vec<ValidatorResponse>>,
    /// Headers per slot
    pub headers: HashMap<String, HeaderResponse>,
    /// Attestations per block
    pub attestations: HashMap<String, Vec<AttestationResponse>>,
    /// Committees per (state_id, epoch)
    pub committees: HashMap<(String, u64), Vec<CommitteeResponse>>,
    /// Block roots per block_id. A slot missing from here reads as skipped.
    pub block_roots: HashMap<String, [u8; 32]>,
    /// Finality checkpoints per state_id
    pub finality: HashMap<String, FinalityCheckpoints>,
    pub genesis_validators_root: [u8; 32],
    pub fork_version: [u8; 4],
    /// Every block_id `get_block_attestations` was called with, in order.
    ///
    /// Continuous mode is supposed to stop fetching blocks the moment the 2/3
    /// threshold is crossed, which is only observable by what it asked for.
    pub attestation_requests: Mutex<Vec<String>>,
}

impl MockBeaconApi {
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            headers: HashMap::new(),
            attestations: HashMap::new(),
            committees: HashMap::new(),
            block_roots: HashMap::new(),
            finality: HashMap::new(),
            genesis_validators_root: [0xAA; 32],
            fork_version: [0x04, 0x00, 0x00, 0x00],
            attestation_requests: Mutex::new(Vec::new()),
        }
    }

    /// Block ids `get_block_attestations` was called with.
    pub fn requested_blocks(&self) -> Vec<String> {
        self.attestation_requests.lock().unwrap().clone()
    }

    /// Report the same finality checkpoints for every state id.
    pub fn set_finality(&mut self, finalized_epoch: u64, root: [u8; 32]) {
        let checkpoint = Checkpoint {
            epoch: finalized_epoch,
            root,
        };
        self.finality.insert(
            "head".to_string(),
            FinalityCheckpoints {
                previous_justified: checkpoint.clone(),
                current_justified: checkpoint.clone(),
                finalized: checkpoint,
            },
        );
    }
}

#[async_trait::async_trait]
impl ChainStatusApi for MockBeaconApi {
    async fn get_block_root(&self, block_id: &str) -> Result<Option<[u8; 32]>> {
        Ok(self.block_roots.get(block_id).copied())
    }

    async fn get_genesis_validators_root(&self) -> Result<[u8; 32]> {
        Ok(self.genesis_validators_root)
    }

    async fn get_fork_version(&self, _state_id: &str) -> Result<[u8; 4]> {
        Ok(self.fork_version)
    }

    async fn get_finality_checkpoints(&self, state_id: &str) -> Result<FinalityCheckpoints> {
        self.finality
            .get(state_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no finality checkpoints for state_id={state_id}"))
    }
}

#[async_trait::async_trait]
impl BeaconApi for MockBeaconApi {
    async fn get_validators(&self, state_id: &str) -> Result<Vec<ValidatorResponse>> {
        self.validators
            .get(state_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no validators for state_id={state_id}"))
    }

    async fn get_block_attestations(&self, block_id: &str) -> Result<Vec<AttestationResponse>> {
        self.attestation_requests
            .lock()
            .unwrap()
            .push(block_id.to_string());
        self.attestations
            .get(block_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no attestations for block_id={block_id}"))
    }

    async fn get_committees(&self, state_id: &str, epoch: u64) -> Result<Vec<CommitteeResponse>> {
        self.committees
            .get(&(state_id.to_string(), epoch))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no committees for state_id={state_id}, epoch={epoch}"))
    }

    async fn get_header(&self, block_id: &str) -> Result<HeaderResponse> {
        self.headers
            .get(block_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no header for block_id={block_id}"))
    }

    async fn get_state_ssz(&self, _state_id: &str) -> Result<Option<Vec<u8>>> {
        // Mock API doesn't have raw SSZ state — triggers synthetic state proof fallback
        Ok(None)
    }
}

/// Convert a ValidatorData (test_utils format) to a ValidatorResponse (API format).
pub fn validator_data_to_response(data: &ValidatorData, index: u64) -> ValidatorResponse {
    ValidatorResponse {
        index,
        pubkey: data.pubkey.0,
        effective_balance: data.effective_balance,
        activation_epoch: data.activation_epoch,
        exit_epoch: data.exit_epoch,
        withdrawal_credentials: {
            let mut wc = [0u8; 32];
            wc[0] = 0x01; // ETH1 withdrawal prefix
            wc
        },
        slashed: false,
        activation_eligibility_epoch: 0,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    }
}

/// Build a HeaderResponse with a computed state root.
pub fn make_header(slot: u64, validators: &[ValidatorResponse], depth: u32) -> HeaderResponse {
    let state_root = compute_state_root_from_validators(validators, depth);
    HeaderResponse {
        slot,
        proposer_index: slot % 8,
        state_root,
        parent_root: [0u8; 32],
        body_root: [0u8; 32],
    }
}

/// The block root a header hashes to.
///
/// Checkpoint roots in these tests have to be the real roots of the headers the
/// mock serves: the finalization circuit opens the header and checks it against
/// the root the attesters signed, so an invented root would never verify.
pub fn header_root(header: &HeaderResponse) -> [u8; 32] {
    zkasper_common::ssz::block_header_root(
        header.slot,
        header.proposer_index,
        &header.parent_root,
        &header.state_root,
        &header.body_root,
    )
}

/// Compute the synthetic state root from a set of validator responses.
fn compute_state_root_from_validators(validators: &[ValidatorResponse], depth: u32) -> [u8; 32] {
    use zkasper_witness_gen::state_diff::{
        build_validator_roots, build_validators_ssz_tree, make_state_proof,
    };

    let validator_roots = build_validator_roots(validators);
    let (ssz_data_root, _) = build_validators_ssz_tree(&validator_roots, depth, &[]);
    let (state_root, _) = make_state_proof(&ssz_data_root, validators.len() as u64);
    state_root
}
