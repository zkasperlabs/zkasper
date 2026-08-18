// Shared test helpers; each test binary uses a different subset.
#![allow(dead_code)]

//! MockBeaconApi and test helpers for witness-gen integration tests.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::Result;

use std::collections::BTreeSet;

use zkasper_common::acc;
use zkasper_common::bls::{compute_domain, compute_signing_root, DOMAIN_BEACON_ATTESTER};
use zkasper_common::constants::FAR_FUTURE_EPOCH;
use zkasper_common::ssz::attestation_data_root;
use zkasper_common::types::{
    AttestationWitness, AttestingValidator, BlockHeaderFields, BlsPubkey, BlsSignature, Checkpoint,
    EpochDiffOutput, JustificationOutput, PreviousJustification, ValidatorData,
};

use zkasper_witness_gen::acc_tree::AccTree;
use zkasper_witness_gen::beacon_api::{
    AttestationResponse, BeaconApi, ChainStatusApi, CommitteeResponse, FinalityCheckpoints,
    HeaderResponse, ValidatorResponse,
};
use zkasper_witness_gen::streaming::{StreamContext, StreamUnit};

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
    /// Head header, when a test moves it between ticks. Takes precedence over
    /// `headers["head"]`.
    pub head: Mutex<Option<HeaderResponse>>,
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
            head: Mutex::new(None),
        }
    }

    /// Block ids `get_block_attestations` was called with.
    pub fn requested_blocks(&self) -> Vec<String> {
        self.attestation_requests.lock().unwrap().clone()
    }

    /// Move the head, the way a node does between polls.
    ///
    /// Streaming only exists across ticks, and what changes between them is how
    /// much of the epoch the node has published, so a test that never moves the
    /// head is testing catch-up rather than streaming.
    pub fn set_head(&self, header: HeaderResponse) {
        *self.head.lock().unwrap() = Some(header);
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
        if block_id == "head" {
            if let Some(header) = self.head.lock().unwrap().clone() {
                return Ok(header);
            }
        }
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

// ---------------------------------------------------------------------------
// Streaming fixture
// ---------------------------------------------------------------------------

pub const STREAM_VALIDATORS: usize = 16;
pub const STREAM_BALANCE_GWEI: u64 = 32_000_000_000;
pub const STREAM_EPOCH: u64 = 10;

/// One epoch of a synthetic chain, shaped for the streaming pipeline.
///
/// Sixteen validators, one aggregate per slot, real BLS signatures. The
/// accumulator depth is a parameter because the circuit tests want a tree small
/// enough to run in a second, while anything proven by a real guest ELF has to
/// use the depth that ELF was compiled with.
pub struct StreamFixture {
    pub keys: Vec<blst::min_pk::SecretKey>,
    pub tree: AccTree,
    pub context: StreamContext,
    pub units: Vec<StreamUnit>,
    pub finalized_header: BlockHeaderFields,
    pub previous: PreviousJustification,
}

pub fn stream_sign(sks: &[&blst::min_pk::SecretKey], msg: &[u8; 32]) -> [u8; 96] {
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let sigs: Vec<blst::min_pk::Signature> = sks.iter().map(|sk| sk.sign(msg, dst, &[])).collect();
    let refs: Vec<&blst::min_pk::Signature> = sigs.iter().collect();
    blst::min_pk::AggregateSignature::aggregate(&refs, true)
        .unwrap()
        .to_signature()
        .to_bytes()
}

/// One aggregate per slot, two validators each, eight slots.
pub fn stream_fixture(acc_depth: u32) -> StreamFixture {
    let keys: Vec<blst::min_pk::SecretKey> = (0..STREAM_VALIDATORS)
        .map(|i| {
            let mut ikm = [0u8; 32];
            ikm[0] = i as u8;
            ikm[1] = 0xAB;
            blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap()
        })
        .collect();

    let validators: Vec<ValidatorData> = keys
        .iter()
        .map(|sk| ValidatorData {
            pubkey: BlsPubkey(sk.sk_to_pk().to_bytes()),
            effective_balance: STREAM_BALANCE_GWEI,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect();

    let total_active_balance = STREAM_VALIDATORS as u64 * STREAM_BALANCE_GWEI;
    let tree = AccTree::build(&validators, STREAM_EPOCH, acc_depth);
    let signing_domain = compute_domain(&DOMAIN_BEACON_ATTESTER, &[0x04, 0, 0, 0], &[0xAA; 32]);

    // The finalized block is epoch E-1's checkpoint; the circuit opens its
    // header, so the root has to be the header's own root.
    let finalized_header = BlockHeaderFields {
        slot: (STREAM_EPOCH - 1) * 32,
        proposer_index: 7,
        parent_root: [0x06; 32],
        state_root: [0xAB; 32],
        body_root: [0x09; 32],
    };
    let previous_root = zkasper_common::ssz::block_header_root(
        finalized_header.slot,
        finalized_header.proposer_index,
        &finalized_header.parent_root,
        &finalized_header.state_root,
        &finalized_header.body_root,
    );

    // The diff that carried the accumulator from epoch E-1 to E. Its endpoints
    // are what tie the finalized epoch's justification to this one's.
    let previous_accumulator_commitment = acc::commitment(&[9, 9, 9, 9], total_active_balance);
    let epoch_diff = EpochDiffOutput {
        prev_accumulator_commitment: previous_accumulator_commitment,
        state_root_1: finalized_header.state_root,
        epoch_1: STREAM_EPOCH - 1,
        accumulator_commitment: acc::commitment(&tree.root(), total_active_balance),
        acc_root: tree.root(),
        total_active_balance,
        state_root_2: [0xCD; 32],
        epoch_2: STREAM_EPOCH,
    };

    let context = StreamContext {
        accumulator_commitment: acc::commitment(&tree.root(), total_active_balance),
        acc_root: tree.root(),
        total_active_balance,
        target_epoch: STREAM_EPOCH,
        target_root: [0x07; 32],
        signing_domain,
        group_program_vk: [1; 4],
        aggregate_program_vk: [2; 4],
        previous_program_vk: [3; 4],
        epoch_diff_program_vk: [4; 4],
        epoch_diff,
        epoch_diff_proof: Vec::new(),
        acc_depth,
    };

    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let units = (0..8u64)
        .map(|slot| {
            let members: Vec<usize> = vec![slot as usize * 2, slot as usize * 2 + 1];
            stream_unit(&keys, &validators, &context, slot, &members, &mut seen)
        })
        .collect();

    StreamFixture {
        keys,
        tree,
        context,
        units,
        finalized_header,
        previous: PreviousJustification::Batch(JustificationOutput {
            accumulator_commitment: previous_accumulator_commitment,
            target_epoch: STREAM_EPOCH - 1,
            target_root: previous_root,
        }),
    }
}

pub fn stream_unit(
    keys: &[blst::min_pk::SecretKey],
    validators: &[ValidatorData],
    context: &StreamContext,
    slot: u64,
    members: &[usize],
    seen: &mut BTreeSet<u64>,
) -> StreamUnit {
    let data_root = attestation_data_root(
        slot,
        0,
        &[0; 32],
        STREAM_EPOCH - 1,
        &[0x01; 32],
        STREAM_EPOCH,
        &context.target_root,
    );
    let signing_root = compute_signing_root(&data_root, &context.signing_domain);
    let sks: Vec<&blst::min_pk::SecretKey> = members.iter().map(|&i| &keys[i]).collect();

    let mut marginal_balance = 0;
    let attesting_validators = members
        .iter()
        .map(|&i| {
            let count_balance = seen.insert(i as u64);
            if count_balance {
                marginal_balance += validators[i].active_effective_balance(STREAM_EPOCH);
            }
            AttestingValidator {
                validator_index: i as u64,
                pubkey: zkasper_witness_gen::pubkey::decompress(&validators[i].pubkey.0).unwrap(),
                active_effective_balance: validators[i].active_effective_balance(STREAM_EPOCH),
                count_balance,
            }
        })
        .collect();

    StreamUnit {
        slot,
        marginal_balance,
        attestation: AttestationWitness {
            data_slot: slot,
            data_index: 0,
            data_beacon_block_root: [0; 32],
            data_source_epoch: STREAM_EPOCH - 1,
            data_source_root: [0x01; 32],
            data_target_epoch: STREAM_EPOCH,
            data_target_root: context.target_root,
            signature: BlsSignature(stream_sign(&sks, &signing_root)),
            attesting_validators,
        },
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
