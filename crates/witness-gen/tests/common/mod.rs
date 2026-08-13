// Shared test helpers; each test binary uses a different subset.
#![allow(dead_code)]

//! MockBeaconApi and test helpers for witness-gen integration tests.

use std::collections::HashMap;

use anyhow::Result;

use zkasper_common::constants::FAR_FUTURE_EPOCH;
use zkasper_common::types::ValidatorData;

use zkasper_witness_gen::beacon_api::{
    AttestationResponse, BeaconApi, CommitteeResponse, HeaderResponse, ValidatorResponse,
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
}

impl MockBeaconApi {
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            headers: HashMap::new(),
            attestations: HashMap::new(),
            committees: HashMap::new(),
        }
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
        state_root,
        parent_root: [0u8; 32],
    }
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
