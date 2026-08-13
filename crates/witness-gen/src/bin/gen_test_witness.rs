//! Generate test witness binary files for Zisk proof testing.
//!
//! Usage: cargo run --bin gen-test-witness -- <proof-type> <output-path>
//!   proof-type: bootstrap | epoch-diff | slot-proof | justification | finalization

use std::collections::HashMap;

use zkasper_common::acc::{self, Digest};
use zkasper_common::bls::{compute_domain, compute_signing_root, DOMAIN_BEACON_ATTESTER};
use zkasper_common::constants::FAR_FUTURE_EPOCH;
use zkasper_common::ssz::attestation_data_root;
use zkasper_common::test_utils::make_validator;
use zkasper_common::types::*;
use zkasper_common::ChainConfig;

use zkasper_witness_gen::acc_tree::AccTree;
use zkasper_witness_gen::beacon_api::{BeaconApi, HeaderResponse, ValidatorResponse};
use zkasper_witness_gen::state_diff::{
    build_validator_roots, build_validators_ssz_tree, make_state_proof,
};

// Use MAINNET config so the guest binary (which uses default production depths) works.
const CONFIG: ChainConfig = ChainConfig::MAINNET;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn validator_data_to_response(data: &ValidatorData, index: u64) -> ValidatorResponse {
    ValidatorResponse {
        index,
        pubkey: data.pubkey.0,
        effective_balance: data.effective_balance,
        activation_epoch: data.activation_epoch,
        exit_epoch: data.exit_epoch,
        withdrawal_credentials: {
            let mut wc = [0u8; 32];
            wc[0] = 0x01;
            wc
        },
        slashed: false,
        activation_eligibility_epoch: 0,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    }
}

fn make_header(slot: u64, validators: &[ValidatorResponse]) -> HeaderResponse {
    let validator_roots = build_validator_roots(validators);
    let (ssz_data_root, _) =
        build_validators_ssz_tree(&validator_roots, CONFIG.validators_tree_depth, &[]);
    let (state_root, _) = make_state_proof(&ssz_data_root, validators.len() as u64);
    HeaderResponse {
        slot,
        state_root,
        parent_root: [0u8; 32],
    }
}

/// In-memory mock beacon API
struct MockBeaconApi {
    validators: HashMap<String, Vec<ValidatorResponse>>,
    headers: HashMap<String, HeaderResponse>,
}

#[async_trait::async_trait]
impl BeaconApi for MockBeaconApi {
    async fn get_validators(&self, state_id: &str) -> anyhow::Result<Vec<ValidatorResponse>> {
        self.validators
            .get(state_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no validators for {state_id}"))
    }
    async fn get_block_attestations(
        &self,
        _block_id: &str,
    ) -> anyhow::Result<Vec<zkasper_witness_gen::beacon_api::AttestationResponse>> {
        Ok(vec![])
    }
    async fn get_committees(
        &self,
        _state_id: &str,
        _epoch: u64,
    ) -> anyhow::Result<Vec<zkasper_witness_gen::beacon_api::CommitteeResponse>> {
        Ok(vec![])
    }
    async fn get_header(&self, block_id: &str) -> anyhow::Result<HeaderResponse> {
        self.headers
            .get(block_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no header for {block_id}"))
    }
    async fn get_state_ssz(&self, _state_id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// BLS key generation and signing helpers
// ---------------------------------------------------------------------------

fn generate_test_keys(n: usize) -> Vec<(blst::min_pk::SecretKey, [u8; 48])> {
    (0..n)
        .map(|i| {
            let mut ikm = [0u8; 32];
            ikm[0] = i as u8;
            ikm[1] = 0xAB;
            let sk = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
            let pk = sk.sk_to_pk();
            let pk_bytes: [u8; 48] = pk.to_bytes();
            (sk, pk_bytes)
        })
        .collect()
}

fn sign_message(sks: &[&blst::min_pk::SecretKey], msg: &[u8; 32]) -> [u8; 96] {
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let sigs: Vec<blst::min_pk::Signature> = sks.iter().map(|sk| sk.sign(msg, dst, &[])).collect();
    let sig_refs: Vec<&blst::min_pk::Signature> = sigs.iter().collect();
    let agg = blst::min_pk::AggregateSignature::aggregate(&sig_refs, true).unwrap();
    agg.to_signature().to_bytes()
}

/// Synthetic signing domain for tests.
fn test_signing_domain() -> [u8; 32] {
    let fork_version = [0x04, 0x00, 0x00, 0x00];
    let genesis_validators_root = [0xAA; 32];
    compute_domain(
        &DOMAIN_BEACON_ATTESTER,
        &fork_version,
        &genesis_validators_root,
    )
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

fn gen_bootstrap(output_path: &str) {
    let slot = 3200u64;
    let validators: Vec<ValidatorData> = (0..4).map(|i| make_validator(i, 32)).collect();
    let responses: Vec<ValidatorResponse> = validators
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();

    let mut mock = MockBeaconApi {
        validators: HashMap::new(),
        headers: HashMap::new(),
    };
    let header = make_header(slot, &responses);
    mock.validators.insert(slot.to_string(), responses);
    mock.headers.insert(slot.to_string(), header);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (witness, _, _, _, _) = rt
        .block_on(zkasper_witness_gen::witness_bootstrap::build(
            &mock, &CONFIG, slot,
        ))
        .unwrap();

    let bytes = bincode::serialize(&witness).unwrap();
    std::fs::write(output_path, &bytes).unwrap();
    eprintln!(
        "wrote bootstrap witness: {} bytes -> {output_path}",
        bytes.len()
    );
}

// ---------------------------------------------------------------------------
// Epoch diff
// ---------------------------------------------------------------------------

fn gen_epoch_diff(output_path: &str) {
    let slot_1 = 3200u64;
    let slot_2 = 3232u64;

    let validators_1: Vec<ValidatorData> = (0..4).map(|i| make_validator(i, 32)).collect();
    let mut validators_2 = validators_1.clone();
    validators_2[1].effective_balance = 16_000_000_000;

    let responses_1: Vec<ValidatorResponse> = validators_1
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();
    let responses_2: Vec<ValidatorResponse> = validators_2
        .iter()
        .enumerate()
        .map(|(i, v)| validator_data_to_response(v, i as u64))
        .collect();

    let mut mock = MockBeaconApi {
        validators: HashMap::new(),
        headers: HashMap::new(),
    };
    let header_1 = make_header(slot_1, &responses_1);
    let header_2 = make_header(slot_2, &responses_2);
    mock.validators.insert(slot_1.to_string(), responses_1);
    mock.validators.insert(slot_2.to_string(), responses_2);
    mock.headers.insert(slot_1.to_string(), header_1);
    mock.headers.insert(slot_2.to_string(), header_2);

    let rt = tokio::runtime::Runtime::new().unwrap();

    let (_, mut tree, epoch_state, total_active_balance_1, _) = rt
        .block_on(zkasper_witness_gen::witness_bootstrap::build(
            &mock, &CONFIG, slot_1,
        ))
        .unwrap();

    let (witness, _, _, _) = rt
        .block_on(zkasper_witness_gen::witness_epoch_diff::build(
            &mock,
            &CONFIG,
            &mut tree,
            &epoch_state,
            slot_2,
            total_active_balance_1,
        ))
        .unwrap();

    let bytes = bincode::serialize(&witness).unwrap();
    std::fs::write(output_path, &bytes).unwrap();
    eprintln!(
        "wrote epoch-diff witness: {} bytes -> {output_path}",
        bytes.len()
    );
}

// ---------------------------------------------------------------------------
// Slot proof
// ---------------------------------------------------------------------------

/// Build test data shared between slot-proof, justification, and finalization generators.
struct SlotTestData {
    keys: Vec<(blst::min_pk::SecretKey, [u8; 48])>,
    validators: Vec<ValidatorData>,
    tree: AccTree,
    acc_root: Digest,
    total_active_balance: u64,
    commitment: Digest,
    signing_domain: [u8; 32],
}

fn build_slot_test_data() -> SlotTestData {
    let epoch = 100u64;
    let balance_gwei = 32_000_000_000u64;

    let keys = generate_test_keys(4);
    let validators: Vec<ValidatorData> = keys
        .iter()
        .map(|(_, pk)| ValidatorData {
            pubkey: BlsPubkey(*pk),
            effective_balance: balance_gwei,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect();

    let total_active_balance = 4 * balance_gwei;
    let tree = AccTree::build(&validators, epoch, CONFIG.acc_tree_depth);
    let acc_root = tree.root();
    let commitment = acc::commitment(&acc_root, total_active_balance);
    let signing_domain = test_signing_domain();

    SlotTestData {
        keys,
        validators,
        tree,
        acc_root,
        total_active_balance,
        commitment,
        signing_domain,
    }
}

/// Build a SlotProofWitness for a single attestation where `validator_indices` all sign.
fn build_slot_witness(
    data: &SlotTestData,
    epoch: u64,
    target_root: [u8; 32],
    data_slot: u64,
    validator_indices: &[usize],
    seen: &mut std::collections::BTreeSet<u64>,
) -> SlotProofWitness {
    let source_root = [0x01u8; 32];
    let beacon_block_root = [0u8; 32];

    let data_root = attestation_data_root(
        data_slot,
        0,
        &beacon_block_root,
        epoch.saturating_sub(1),
        &source_root,
        epoch,
        &target_root,
    );
    let sig_root = compute_signing_root(&data_root, &data.signing_domain);

    let sks: Vec<&blst::min_pk::SecretKey> =
        validator_indices.iter().map(|&i| &data.keys[i].0).collect();
    let signature = sign_message(&sks, &sig_root);

    let attesting_validators: Vec<AttestingValidator> = validator_indices
        .iter()
        .map(|&i| {
            let v = &data.validators[i];
            let count_balance = seen.insert(i as u64);
            AttestingValidator {
                validator_index: i as u64,
                pubkey: v.pubkey.clone(),
                active_effective_balance: v.active_effective_balance(epoch),
                count_balance,
            }
        })
        .collect();

    let attestation = AttestationWitness {
        data_slot,
        data_index: 0,
        data_beacon_block_root: beacon_block_root,
        data_source_epoch: epoch.saturating_sub(1),
        data_source_root: source_root,
        data_target_epoch: epoch,
        data_target_root: target_root,
        signature: BlsSignature(signature),
        attesting_validators,
    };

    // Collect leaf indices that have count_balance=true for the multi-proof
    let counted_leaf_indices: Vec<u64> = validator_indices
        .iter()
        .filter(|&&i| {
            attestation
                .attesting_validators
                .iter()
                .any(|v| v.validator_index == i as u64 && v.count_balance)
        })
        .map(|&i| i as u64)
        .collect();

    let multi_proof = data.tree.build_multi_proof(&counted_leaf_indices);

    SlotProofWitness {
        accumulator_commitment: data.commitment,
        target_epoch: epoch,
        target_root,
        signing_domain: data.signing_domain,
        acc_root: data.acc_root,
        total_active_balance: data.total_active_balance,
        attestations: vec![attestation],
        acc_multi_proof: multi_proof,
    }
}

/// Compute the expected SlotProofOutput without calling guest code.
fn compute_slot_output(
    data: &SlotTestData,
    epoch: u64,
    target_root: [u8; 32],
    validator_indices: &[usize],
) -> (SlotProofOutput, Vec<u64>) {
    let balance_per = data.validators[0].effective_balance;
    let attesting_balance = validator_indices.len() as u64 * balance_per;
    let mut sorted_indices: Vec<u64> = validator_indices.iter().map(|&i| i as u64).collect();
    sorted_indices.sort_unstable();
    let commitment = acc::commit_indices(&sorted_indices);

    let output = SlotProofOutput {
        accumulator_commitment: data.commitment,
        target_epoch: epoch,
        target_root,
        attesting_balance,
        counted_validators_commitment: commitment,
        num_counted_validators: sorted_indices.len() as u64,
    };
    (output, sorted_indices)
}

fn gen_slot_proof(output_path: &str) {
    let data = build_slot_test_data();
    let epoch = 100u64;
    let target_root = [0x07u8; 32];
    let data_slot = epoch * CONFIG.slots_per_epoch;

    let mut seen = std::collections::BTreeSet::new();
    let witness = build_slot_witness(
        &data,
        epoch,
        target_root,
        data_slot,
        &[0, 1, 2, 3],
        &mut seen,
    );

    let bytes = bincode::serialize(&witness).unwrap();
    std::fs::write(output_path, &bytes).unwrap();
    eprintln!(
        "wrote slot-proof witness: {} bytes -> {output_path}",
        bytes.len()
    );
}

// ---------------------------------------------------------------------------
// Justification
// ---------------------------------------------------------------------------

fn gen_justification(output_path: &str) {
    let data = build_slot_test_data();
    let epoch = 100u64;
    let target_root = [0x07u8; 32];

    // Two slots: validators [0,1] in slot 0, validators [2,3] in slot 1
    let (output_0, indices_0) = compute_slot_output(&data, epoch, target_root, &[0, 1]);
    let (output_1, indices_1) = compute_slot_output(&data, epoch, target_root, &[2, 3]);

    let witness = JustificationWitness {
        accumulator_commitment: data.commitment,
        target_epoch: epoch,
        target_root,
        total_active_balance: data.total_active_balance,
        slot_proof_outputs: vec![output_0, output_1],
        slot_program_vk: [0; 4],
        slot_proofs: vec![vec![], vec![]], // native mode: no real child proofs
        counted_indices_per_slot: vec![indices_0, indices_1],
    };

    let bytes = bincode::serialize(&witness).unwrap();
    std::fs::write(output_path, &bytes).unwrap();
    eprintln!(
        "wrote justification witness: {} bytes -> {output_path}",
        bytes.len()
    );
}

// ---------------------------------------------------------------------------
// Finalization
// ---------------------------------------------------------------------------

fn gen_finalization(output_path: &str) {
    let data = build_slot_test_data();
    let epoch_e = 100u64;
    let epoch_e1 = 101u64;
    let target_root_e = [0x07u8; 32];
    let target_root_e1 = [0x08u8; 32];

    let just_e = JustificationOutput {
        accumulator_commitment: data.commitment,
        target_epoch: epoch_e,
        target_root: target_root_e,
    };
    let just_e1 = JustificationOutput {
        accumulator_commitment: data.commitment,
        target_epoch: epoch_e1,
        target_root: target_root_e1,
    };

    let witness = FinalizationWitness {
        justification_program_vk: [0; 4],
        accumulator_commitment: data.commitment,
        justification_outputs: vec![just_e, just_e1],
        justification_proofs: vec![vec![], vec![]], // stub proofs
    };

    let bytes = bincode::serialize(&witness).unwrap();
    std::fs::write(output_path, &bytes).unwrap();
    eprintln!(
        "wrote finalization witness: {} bytes -> {output_path}",
        bytes.len()
    );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "usage: gen-test-witness <bootstrap|epoch-diff|slot-proof|justification|finalization> <output-path>"
        );
        std::process::exit(1);
    }

    match args[1].as_str() {
        "bootstrap" => gen_bootstrap(&args[2]),
        "epoch-diff" => gen_epoch_diff(&args[2]),
        "slot-proof" => gen_slot_proof(&args[2]),
        "justification" => gen_justification(&args[2]),
        "finalization" => gen_finalization(&args[2]),
        other => {
            eprintln!("unknown proof type: {other}");
            std::process::exit(1);
        }
    }
}
