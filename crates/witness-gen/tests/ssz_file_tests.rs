//! Integration tests using real SSZ beacon state files.
//!
//! State blobs are hosted as GitHub release assets and downloaded on first run.
//! Files are cached in `test_data/` to avoid re-downloading (~320MB each).
//!
//! Run with:
//! ```sh
//! cargo test --release --test ssz_file_tests -- --ignored --nocapture
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing_subscriber::fmt::format::FmtSpan;

use zkasper_common::constants::VALIDATORS_TREE_DEPTH;
use zkasper_common::ChainConfig;

use zkasper_witness_gen::beacon_api::{
    self, AttestationResponse, BeaconApi, CommitteeResponse, HeaderResponse, ValidatorResponse,
};
use zkasper_witness_gen::ssz_state;

// ---------------------------------------------------------------------------
// Tracing setup
// ---------------------------------------------------------------------------

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

// ---------------------------------------------------------------------------
// Test data definitions
// ---------------------------------------------------------------------------

const GITHUB_REPO: &str = "dapplion/zkasper";
const RELEASE_TAG: &str = "test-data-v1";

struct TestState {
    filename: &'static str,
    expected_root: &'static str,
}

const STATE_1: TestState = TestState {
    filename: "state_13776608.ssz",
    expected_root: "521d21fb0fffa1e7197ae149ae7c2d81bd66cd30be6cd5744f3a4f7105c5daef",
};

const STATE_2: TestState = TestState {
    filename: "state_13776928.ssz",
    expected_root: "3a9ab0228848b15f90fdd878cac181ab80e5109147a72534b7038b446ee1c8c9",
};

const GNOSIS_STATE: TestState = TestState {
    filename: "state_26696480.ssz",
    expected_root: "c68748b00517d0e8eeb61267df99315ec05e08789151186af0920ed571968fca",
};

// ---------------------------------------------------------------------------
// File-backed BeaconApi
// ---------------------------------------------------------------------------

struct SszFileApi {
    states: HashMap<String, Arc<StateData>>,
    /// Attestations loaded from finality JSON data, keyed by slot string.
    attestations_by_slot: HashMap<String, Vec<AttestationResponse>>,
    /// Committees loaded from finality JSON data, keyed by epoch.
    committees_by_epoch: HashMap<u64, Vec<CommitteeResponse>>,
}

struct StateData {
    raw_ssz: Vec<u8>,
    validators: Vec<ValidatorResponse>,
    header: HeaderResponse,
}

impl SszFileApi {
    fn load(entries: &[(&str, &str)], config: &ChainConfig) -> Self {
        let mut states = HashMap::new();

        for &(path, expected_root_hex) in entries {
            let raw_ssz = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));

            let (state_root, _num_validators) = ssz_state::compute_state_root(&raw_ssz, config)
                .unwrap_or_else(|e| panic!("compute state root for {path}: {e}"));

            let expected_bytes = hex::decode(expected_root_hex).unwrap();
            let mut expected_root = [0u8; 32];
            expected_root.copy_from_slice(&expected_bytes);
            assert_eq!(state_root, expected_root, "state root mismatch for {path}");

            let validators = ssz_state::extract_validators(&raw_ssz, config)
                .unwrap_or_else(|e| panic!("extract validators from {path}: {e}"));

            let mut header = ssz_state::extract_header(&raw_ssz, config)
                .unwrap_or_else(|e| panic!("extract header from {path}: {e}"));
            header.state_root = state_root;

            let slot_str = header.slot.to_string();

            states.insert(
                slot_str,
                Arc::new(StateData {
                    raw_ssz,
                    validators,
                    header,
                }),
            );
        }

        SszFileApi {
            states,
            attestations_by_slot: HashMap::new(),
            committees_by_epoch: HashMap::new(),
        }
    }

    /// Load finality JSON data (attestations + committees) from a gzipped JSON file.
    fn load_finality_data(&mut self, path: &str) -> (u64, [u8; 32]) {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("open {path}: {e}"));
        let mut decoder = GzDecoder::new(file);
        let mut json_str = String::new();
        decoder
            .read_to_string(&mut json_str)
            .unwrap_or_else(|e| panic!("decompress {path}: {e}"));
        let data: serde_json::Value =
            serde_json::from_str(&json_str).unwrap_or_else(|e| panic!("parse {path}: {e}"));

        let target_epoch = data["target_epoch"].as_u64().expect("missing target_epoch");
        let target_root_hex = data["target_root"]
            .as_str()
            .expect("missing target_root")
            .strip_prefix("0x")
            .unwrap();
        let target_root_bytes = hex::decode(target_root_hex).expect("invalid target_root hex");
        let mut target_root = [0u8; 32];
        target_root.copy_from_slice(&target_root_bytes);

        // Parse committees
        let committees_arr = data["committees"].as_array().expect("missing committees");
        let mut committees = Vec::with_capacity(committees_arr.len());
        for entry in committees_arr {
            committees.push(beacon_api::parse_committee_entry(entry).expect("parse committee"));
        }
        self.committees_by_epoch.insert(target_epoch, committees);

        // Parse attestations by slot
        let atts_obj = data["attestations_by_slot"]
            .as_object()
            .expect("missing attestations_by_slot");
        for (slot_str, atts_arr) in atts_obj {
            let atts = atts_arr
                .as_array()
                .expect("attestations not array")
                .iter()
                .map(|entry| beacon_api::parse_attestation_entry(entry).expect("parse attestation"))
                .collect::<Vec<_>>();
            self.attestations_by_slot.insert(slot_str.clone(), atts);
        }

        (target_epoch, target_root)
    }

    fn get_state(&self, state_id: &str) -> &StateData {
        self.states
            .get(state_id)
            .unwrap_or_else(|| panic!("no state loaded for id '{state_id}'"))
    }
}

#[async_trait::async_trait]
impl BeaconApi for SszFileApi {
    async fn get_validators(&self, state_id: &str) -> Result<Vec<ValidatorResponse>> {
        Ok(self.get_state(state_id).validators.clone())
    }

    async fn get_block_attestations(&self, block_id: &str) -> Result<Vec<AttestationResponse>> {
        self.attestations_by_slot
            .get(block_id)
            .cloned()
            .context(format!("no attestations for block {block_id}"))
    }

    async fn get_committees(&self, _state_id: &str, epoch: u64) -> Result<Vec<CommitteeResponse>> {
        self.committees_by_epoch
            .get(&epoch)
            .cloned()
            .context(format!("no committees for epoch {epoch}"))
    }

    async fn get_header(&self, block_id: &str) -> Result<HeaderResponse> {
        Ok(self.get_state(block_id).header.clone())
    }

    async fn get_state_ssz(&self, state_id: &str) -> Result<Option<Vec<u8>>> {
        Ok(Some(self.get_state(state_id).raw_ssz.clone()))
    }
}

// ---------------------------------------------------------------------------
// Download helpers
// ---------------------------------------------------------------------------

/// Get the path to the test_data directory (repo root / test_data).
fn test_data_dir() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test_data")
}

/// Ensure a file exists locally, downloading from GitHub release if needed.
fn ensure_file(filename: &str) -> String {
    let dir = test_data_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(filename);

    if path.exists() {
        return path.to_str().unwrap().to_string();
    }

    let url =
        format!("https://github.com/{GITHUB_REPO}/releases/download/{RELEASE_TAG}/{filename}",);
    eprintln!("downloading {url} ...");

    let status = std::process::Command::new("curl")
        .args(["-L", "-f", "-o", path.to_str().unwrap(), &url])
        .status()
        .expect("failed to run curl");

    assert!(status.success(), "failed to download {filename}");
    eprintln!("  saved to {}", path.display());

    path.to_str().unwrap().to_string()
}

fn ensure_state(state: &TestState) -> String {
    ensure_file(state.filename)
}

fn load_one_state() -> (SszFileApi, u64) {
    let path1 = ensure_state(&STATE_1);
    let api = SszFileApi::load(&[(&path1, STATE_1.expected_root)], &ChainConfig::MAINNET);
    let slot = api.states.values().next().unwrap().header.slot;
    (api, slot)
}

fn load_two_states() -> (SszFileApi, u64, u64) {
    let path1 = ensure_state(&STATE_1);
    let path2 = ensure_state(&STATE_2);
    let api = SszFileApi::load(
        &[
            (&path1, STATE_1.expected_root),
            (&path2, STATE_2.expected_root),
        ],
        &ChainConfig::MAINNET,
    );

    let slots: Vec<u64> = api.states.values().map(|s| s.header.slot).collect();
    let slot_1 = *slots.iter().min().unwrap();
    let slot_2 = *slots.iter().max().unwrap();

    (api, slot_1, slot_2)
}

// ---------------------------------------------------------------------------
// Test: bootstrap witness generation from SSZ file
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "downloads ~320MB, takes ~2min"]
async fn test_ssz_file_bootstrap() {
    init_tracing();
    const CONFIG: ChainConfig = ChainConfig::MAINNET;

    let (api, slot) = load_one_state();
    let epoch = slot / CONFIG.slots_per_epoch;
    eprintln!("testing bootstrap at slot {slot} (epoch {epoch})");

    let (witness, _tree, _epoch_state, total_active_balance, num_validators) =
        zkasper_witness_gen::witness_bootstrap::build(&api, &CONFIG, slot)
            .await
            .unwrap();

    assert!(num_validators > 0);
    assert!(total_active_balance > 0);
    assert_eq!(witness.epoch, epoch);
    assert_eq!(witness.validators.len(), num_validators as usize);
    assert_eq!(witness.state_to_validators_siblings.len(), 6);
}

// ---------------------------------------------------------------------------
// Test: epoch diff witness generation + guest verification
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "downloads ~640MB, takes ~3min"]
async fn test_ssz_file_epoch_diff() {
    init_tracing();
    const CONFIG: ChainConfig = ChainConfig::MAINNET;

    let (api, slot_1, slot_2) = load_two_states();
    let epoch_1 = slot_1 / CONFIG.slots_per_epoch;
    let epoch_2 = slot_2 / CONFIG.slots_per_epoch;
    eprintln!(
        "testing epoch diff: slot {slot_1} (epoch {epoch_1}) -> slot {slot_2} (epoch {epoch_2})"
    );

    // Bootstrap at slot_1
    let (_witness, mut tree, epoch_state, total_active_balance, _num_validators) =
        zkasper_witness_gen::witness_bootstrap::build(&api, &CONFIG, slot_1)
            .await
            .unwrap();

    // Epoch diff
    let (diff_witness, _new_epoch_state, new_balance, _new_num_validators) =
        zkasper_witness_gen::witness_epoch_diff::build(
            &api,
            &CONFIG,
            &mut tree,
            &epoch_state,
            slot_2,
            total_active_balance,
        )
        .await
        .unwrap();

    assert!(!diff_witness.mutations.is_empty());
    assert_eq!(diff_witness.state_to_validators_siblings_1.len(), 6);
    assert_eq!(diff_witness.state_to_validators_siblings_2.len(), 6);

    // Verify the witness through the guest circuit logic
    let diff = zkasper_epoch_diff_guest::verify_epoch_diff(&diff_witness);

    assert_eq!(
        diff.acc_root,
        tree.root(),
        "poseidon root mismatch after verify"
    );
    assert_eq!(
        diff.total_active_balance, new_balance,
        "total active balance mismatch"
    );
    assert_eq!(
        diff.accumulator_commitment,
        zkasper_common::acc::commitment(&diff.acc_root, diff.total_active_balance),
    );
}

// ---------------------------------------------------------------------------
// Benchmark: count circuit operations in epoch-diff guest
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "downloads ~640MB, takes ~3min"]
async fn bench_epoch_diff_guest_ops() {
    use zkasper_common::acc;
    use zkasper_common::op_counter;
    use zkasper_common::ssz::{
        compute_ssz_merkle_root, list_hash_tree_root, validator_hash_tree_root,
        validator_hash_tree_root_pair, verify_field_leaves, verify_field_leaves_no_pubkey_hash,
        verify_ssz_multi_proof,
    };

    init_tracing();
    const CONFIG: ChainConfig = ChainConfig::MAINNET;

    let (api, slot_1, slot_2) = load_two_states();
    let epoch_1 = slot_1 / CONFIG.slots_per_epoch;
    let epoch_2 = slot_2 / CONFIG.slots_per_epoch;

    // Build witness (host-side, not measured)
    let (_witness, mut tree, epoch_state, total_active_balance, _num_validators) =
        zkasper_witness_gen::witness_bootstrap::build(&api, &CONFIG, slot_1)
            .await
            .unwrap();

    let (diff_witness, _new_epoch_state, _new_balance, _new_num_validators) =
        zkasper_witness_gen::witness_epoch_diff::build(
            &api,
            &CONFIG,
            &mut tree,
            &epoch_state,
            slot_2,
            total_active_balance,
        )
        .await
        .unwrap();

    let num_mutations = diff_witness.mutations.len();
    eprintln!("\n=== epoch-diff guest op count ({num_mutations} mutations) ===\n");

    // --- Measure the full guest verification ---
    op_counter::reset();
    let before_total = op_counter::snapshot();
    let _ = zkasper_epoch_diff_guest::verify_epoch_diff(&diff_witness);
    let total = op_counter::snapshot().delta(&before_total);
    eprintln!("TOTAL:              {total}");

    // --- Per-phase breakdown: replay the guest logic manually ---
    // Phase 1: verify_field_leaves (old + new)
    // Old validators use no_pubkey_hash variant (saves 1 SHA-256 per non-new mutation)
    op_counter::reset();
    let s0 = op_counter::snapshot();
    for m in &diff_witness.mutations {
        if m.is_new {
            verify_field_leaves(&m.new_data, &m.new_field_leaves, &m.new_pubkey_chunks);
        } else {
            verify_field_leaves(&m.new_data, &m.new_field_leaves, &m.new_pubkey_chunks);
            verify_field_leaves_no_pubkey_hash(
                &m.old_data,
                &m.old_field_leaves,
                &m.old_pubkey_chunks,
            );
        }
    }
    let phase_field_leaves = op_counter::snapshot().delta(&s0);
    eprintln!("verify_field_leaves: {phase_field_leaves}");

    // Phase 2: validator_hash_tree_root (old + new)
    // Uses paired HTR for non-new mutations (shares work for identical subtrees)
    op_counter::reset();
    let s0 = op_counter::snapshot();
    for m in &diff_witness.mutations {
        if m.is_new {
            validator_hash_tree_root(&m.new_field_leaves);
        } else {
            validator_hash_tree_root_pair(&m.old_field_leaves, &m.new_field_leaves);
        }
    }
    let phase_htr = op_counter::snapshot().delta(&s0);
    eprintln!("validator_htr:       {phase_htr}");

    // Phase 3: SSZ multi-proof verification (old + new)
    // Compute leaves outside of measurement, then measure only the multi-proof
    let mut old_leaves: Vec<([u8; 32], u64)> = Vec::with_capacity(diff_witness.mutations.len());
    let mut new_leaves: Vec<([u8; 32], u64)> = Vec::with_capacity(diff_witness.mutations.len());
    for m in &diff_witness.mutations {
        let idx = m.validator_index;
        if m.is_new {
            old_leaves.push(([0u8; 32], idx));
            new_leaves.push((validator_hash_tree_root(&m.new_field_leaves), idx));
        } else {
            let (old_root, new_root) =
                validator_hash_tree_root_pair(&m.old_field_leaves, &m.new_field_leaves);
            old_leaves.push((old_root, idx));
            new_leaves.push((new_root, idx));
        }
    }
    op_counter::reset();
    let s0 = op_counter::snapshot();
    verify_ssz_multi_proof(
        &old_leaves,
        &diff_witness.ssz_multi_proof_1,
        VALIDATORS_TREE_DEPTH,
    );
    verify_ssz_multi_proof(
        &new_leaves,
        &diff_witness.ssz_multi_proof_2,
        VALIDATORS_TREE_DEPTH,
    );
    let phase_ssz_merkle = op_counter::snapshot().delta(&s0);
    let ssz_merkle_sha256 = phase_ssz_merkle.sha256f;
    eprintln!(
        "ssz_multi_proofs:    sha256: {} (~{}M constraints)",
        ssz_merkle_sha256,
        ssz_merkle_sha256 * 29_000 / 1_000_000,
    );

    // Phase 4: Poseidon leaf computation (old + new)
    op_counter::reset();
    let s0 = op_counter::snapshot();
    for m in &diff_witness.mutations {
        if !m.is_new {
            let old_balance = m.old_data.active_effective_balance(epoch_1);
            acc::leaf(
                &zkasper_witness_gen::pubkey::decompress(&m.old_data.pubkey.0).unwrap(),
                old_balance,
            );
        }
        let new_balance = m.new_data.active_effective_balance(epoch_2);
        acc::leaf(
            &zkasper_witness_gen::pubkey::decompress(&m.new_data.pubkey.0).unwrap(),
            new_balance,
        );
    }
    let phase_poseidon_leaf = op_counter::snapshot().delta(&s0);
    eprintln!("poseidon_leaf:       {phase_poseidon_leaf}");

    // Phase 5: Poseidon Merkle proofs (old + new)
    op_counter::reset();
    let s0 = op_counter::snapshot();
    for m in &diff_witness.mutations {
        let idx = m.validator_index;
        if m.is_new {
            zkasper_common::merkle::compute_root(acc::compress, &acc::ZERO, idx, &m.acc_siblings);
        } else {
            let old_balance = m.old_data.active_effective_balance(epoch_1);
            let old_leaf = acc::leaf(
                &zkasper_witness_gen::pubkey::decompress(&m.old_data.pubkey.0).unwrap(),
                old_balance,
            );
            zkasper_common::merkle::compute_root(acc::compress, &old_leaf, idx, &m.acc_siblings);
        }
        let new_balance = m.new_data.active_effective_balance(epoch_2);
        let new_leaf = acc::leaf(
            &zkasper_witness_gen::pubkey::decompress(&m.new_data.pubkey.0).unwrap(),
            new_balance,
        );
        zkasper_common::merkle::compute_root(acc::compress, &new_leaf, idx, &m.acc_siblings);
    }
    let phase_poseidon_merkle = op_counter::snapshot().delta(&s0);
    let poseidon_merkle_ops = phase_poseidon_merkle.poseidon2 - phase_poseidon_leaf.poseidon2;
    eprintln!(
        "poseidon_merkle:     poseidon_t3: {} (~{}k constraints), (leaf ops excluded)",
        poseidon_merkle_ops,
        poseidon_merkle_ops * 250 / 1_000,
    );

    // Phase 6: State proofs (2x list_hash_tree_root + 2x compute_ssz_merkle_root)
    op_counter::reset();
    let s0 = op_counter::snapshot();
    let ssz_dummy = [0u8; 32];
    list_hash_tree_root(&ssz_dummy, 100);
    list_hash_tree_root(&ssz_dummy, 100);
    compute_ssz_merkle_root(&ssz_dummy, 11, &diff_witness.state_to_validators_siblings_1);
    compute_ssz_merkle_root(&ssz_dummy, 11, &diff_witness.state_to_validators_siblings_2);
    let phase_state_proof = op_counter::snapshot().delta(&s0);
    eprintln!("state_proofs:        {phase_state_proof}");

    // Phase 7: accumulator_commitment (1 acc::compress)
    op_counter::reset();
    let s0 = op_counter::snapshot();
    zkasper_common::acc::commitment(&zkasper_common::acc::ZERO, 100);
    let phase_commit = op_counter::snapshot().delta(&s0);
    eprintln!("accumulator_commit:  {phase_commit}");

    // Summary
    eprintln!("\n=== constraint breakdown ===\n");
    let items: &[(&str, u64)] = &[
        ("verify_field_leaves", phase_field_leaves.cost()),
        ("validator_htr", phase_htr.cost()),
        ("ssz_multi_proofs", ssz_merkle_sha256 * 29_000),
        ("poseidon_leaf", phase_poseidon_leaf.cost()),
        ("poseidon_merkle", poseidon_merkle_ops * 250),
        ("state_proofs", phase_state_proof.cost()),
        ("accumulator_commit", phase_commit.cost()),
    ];
    let grand_total: u64 = items.iter().map(|(_, c)| c).sum();
    for (name, constraints) in items {
        let pct = (*constraints as f64 / grand_total as f64) * 100.0;
        eprintln!("  {name:24} {constraints:>12} ({pct:5.1}%)");
    }
    eprintln!("  {:24} {:>12}", "TOTAL", grand_total);
    eprintln!(
        "\n  per mutation: ~{} constraints",
        grand_total / num_mutations as u64
    );

    eprintln!(
        "\n  multi-proof auxiliaries: old={}, new={}",
        diff_witness.ssz_multi_proof_1.auxiliaries.len(),
        diff_witness.ssz_multi_proof_2.auxiliaries.len()
    );
}

// ---------------------------------------------------------------------------
// Test: finality proof with real mainnet attestations
// ---------------------------------------------------------------------------

const FINALITY_DATA: &str = "finality_epoch_430529.json.gz";

#[tokio::test]
#[ignore = "downloads ~320MB, takes ~3min"]
async fn test_ssz_file_finality() {
    init_tracing();
    const CONFIG: ChainConfig = ChainConfig::MAINNET;

    // Load the SSZ state at slot 13776928 (epoch 430529)
    let path2 = ensure_state(&STATE_2);
    let mut api = SszFileApi::load(&[(&path2, STATE_2.expected_root)], &ChainConfig::MAINNET);
    let slot = 13_776_928u64;
    let epoch = slot / CONFIG.slots_per_epoch;

    // Load finality attestation + committee data
    let finality_path = ensure_file(FINALITY_DATA);
    let (target_epoch, target_root) = api.load_finality_data(&finality_path);
    assert_eq!(target_epoch, epoch);
    eprintln!(
        "target_epoch={target_epoch}, target_root=0x{}",
        hex::encode(target_root)
    );

    // Bootstrap: build Poseidon tree + get total_active_balance
    let (_bootstrap_witness, tree, _epoch_state, total_active_balance, _num_validators) =
        zkasper_witness_gen::witness_bootstrap::build(&api, &CONFIG, slot)
            .await
            .unwrap();
    eprintln!("total_active_balance={total_active_balance}");

    // Extract genesis_validators_root and fork_version from SSZ state
    let raw_ssz = &api.get_state(&slot.to_string()).raw_ssz;
    let genesis_validators_root = ssz_state::extract_genesis_validators_root(raw_ssz);
    let fork_version = ssz_state::extract_fork_version(raw_ssz);
    eprintln!(
        "genesis_validators_root=0x{}",
        hex::encode(genesis_validators_root)
    );
    eprintln!("fork_version=0x{}", hex::encode(fork_version));

    // Compute signing domain
    let signing_domain = zkasper_common::bls::compute_domain(
        &zkasper_common::bls::DOMAIN_BEACON_ATTESTER,
        &fork_version,
        &genesis_validators_root,
    );
    eprintln!("signing_domain=0x{}", hex::encode(signing_domain));

    // Build one slot-proof witness per block slot, then aggregate.
    let slots = zkasper_witness_gen::witness_slot_proof::build_per_slot(
        &api,
        &CONFIG,
        &tree,
        target_epoch,
        target_root,
        total_active_balance,
        signing_domain,
    )
    .await
    .unwrap();

    let num_attestations: usize = slots.iter().map(|s| s.witness.attestations.len()).sum();
    let unique_counted: usize = slots.iter().map(|s| s.counted_indices.len()).sum();
    let auxiliaries: usize = slots
        .iter()
        .map(|s| s.witness.acc_multi_proof.auxiliaries.len())
        .sum();
    eprintln!(
        "slots={}, attestations={num_attestations}, unique_counted={unique_counted}, \
         multi_proof_auxiliaries={auxiliaries}",
        slots.len(),
    );

    // Run each slot proof, then fold them with the justification circuit.
    let mut outputs = Vec::with_capacity(slots.len());
    let mut counted_per_slot = Vec::with_capacity(slots.len());
    for s in &slots {
        outputs.push(zkasper_slot_proof_guest::verify_slot_proof(&s.witness));
        counted_per_slot.push(s.counted_indices.clone());
    }

    let attesting_balance: u64 = outputs.iter().map(|o| o.attesting_balance).sum();
    eprintln!(
        "attesting_balance={attesting_balance} ({:.1}%)",
        attesting_balance as f64 / total_active_balance as f64 * 100.0,
    );

    let commitment = zkasper_common::acc::commitment(&tree.root(), total_active_balance);
    let justification = zkasper_justification_guest::verify_justification(
        &zkasper_witness_gen::witness_justification::build(
            outputs,
            vec![Vec::new(); slots.len()],
            counted_per_slot,
            commitment,
            [0; 4],
            target_epoch,
            target_root,
            total_active_balance,
        ),
    );

    assert_eq!(justification.target_root, target_root);
    assert_eq!(justification.accumulator_commitment, commitment);
    eprintln!("justification proof verified successfully!");
}

// ---------------------------------------------------------------------------
// Gnosis Electra state root verification
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "downloads ~80MB"]
async fn test_ssz_file_gnosis_state_root() {
    init_tracing();

    let path = ensure_state(&GNOSIS_STATE);
    let config = ChainConfig::GNOSIS;
    let api = SszFileApi::load(&[(&path, GNOSIS_STATE.expected_root)], &config);
    let slot = api.states.values().next().unwrap().header.slot;
    let num_validators = api.states.values().next().unwrap().validators.len();

    eprintln!("gnosis state at slot {slot}, {num_validators} validators — state root OK");
}

// ---------------------------------------------------------------------------
// Streaming pipeline over the same mainnet epoch
// ---------------------------------------------------------------------------

/// The streaming schedule against epoch 430529's real attestations.
///
/// Same data as `test_ssz_file_finality`, proven the way the pipeline actually
/// proves it: groups that shrink toward the threshold, a running aggregate that
/// folds them as they finish, and one final proof that verifies the marginal
/// aggregate inline and runs the epoch's single final exponentiation.
///
/// What it is here to catch is everything the synthetic fixtures cannot — real
/// aggregate shapes, real duplicate attesters across slots, real participation
/// — and to print what the schedule chose, which is the number the cost model
/// is about.
#[tokio::test]
#[ignore = "downloads ~320MB"]
async fn test_ssz_file_streaming_finality() {
    use zkasper_common::types::{
        BlockHeaderFields, EpochDiffOutput, JustificationOutput, PreviousJustification,
    };
    use zkasper_witness_gen::streaming::{self, StreamContext, StreamPolicy, StreamUnit};

    init_tracing();
    const CONFIG: ChainConfig = ChainConfig::MAINNET;

    let path2 = ensure_state(&STATE_2);
    let mut api = SszFileApi::load(&[(&path2, STATE_2.expected_root)], &ChainConfig::MAINNET);
    let slot = 13_776_928u64;
    let epoch = slot / CONFIG.slots_per_epoch;

    let finality_path = ensure_file(FINALITY_DATA);
    let (target_epoch, target_root) = api.load_finality_data(&finality_path);
    assert_eq!(target_epoch, epoch);

    let (_bootstrap_witness, tree, _epoch_state, total_active_balance, _num_validators) =
        zkasper_witness_gen::witness_bootstrap::build(&api, &CONFIG, slot)
            .await
            .unwrap();

    let raw_ssz = &api.get_state(&slot.to_string()).raw_ssz;
    let signing_domain = zkasper_common::bls::compute_domain(
        &zkasper_common::bls::DOMAIN_BEACON_ATTESTER,
        &ssz_state::extract_fork_version(raw_ssz),
        &ssz_state::extract_genesis_validators_root(raw_ssz),
    );

    let slots = zkasper_witness_gen::witness_slot_proof::build_per_slot(
        &api,
        &CONFIG,
        &tree,
        target_epoch,
        target_root,
        total_active_balance,
        signing_domain,
    )
    .await
    .unwrap();

    // One unit per aggregate attestation, in the order the chain published them.
    let units: Vec<StreamUnit> = slots
        .iter()
        .flat_map(|s| {
            s.witness
                .attestations
                .iter()
                .map(move |a| StreamUnit::new(s.slot, a.clone()))
        })
        .collect();

    // The previous epoch's justification, and the diff that carried the
    // accumulator into this one. Their proofs are empty, which is what native
    // recursion accepts; their public values are what the circuit binds.
    let finalized_header = BlockHeaderFields {
        slot: (target_epoch - 1) * CONFIG.slots_per_epoch,
        proposer_index: 1,
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
    let previous_commitment = zkasper_common::acc::commitment(&[7, 7, 7, 7], total_active_balance);
    let commitment = zkasper_common::acc::commitment(&tree.root(), total_active_balance);

    let context = StreamContext {
        accumulator_commitment: commitment,
        acc_root: tree.root(),
        total_active_balance,
        target_epoch,
        target_root,
        signing_domain,
        group_program_vk: [1; 4],
        aggregate_program_vk: [2; 4],
        previous_program_vk: [3; 4],
        epoch_diff_program_vk: [4; 4],
        epoch_diff: EpochDiffOutput {
            prev_accumulator_commitment: previous_commitment,
            state_root_1: finalized_header.state_root,
            epoch_1: target_epoch - 1,
            accumulator_commitment: commitment,
            acc_root: tree.root(),
            total_active_balance,
            state_root_2: [0xCD; 32],
            epoch_2: target_epoch,
        },
        epoch_diff_proof: Vec::new(),
        acc_depth: CONFIG.acc_tree_depth,
    };

    let policy = StreamPolicy::default();
    let plan = streaming::plan(&units, total_active_balance, &policy);
    assert!(
        plan.threshold_reached,
        "epoch 430529 did not reach the scheduling threshold",
    );

    let proven_units = plan.groups.concat().len() + plan.tail.len();
    let tail_attesters: usize = plan
        .tail
        .iter()
        .map(|&i| units[i].attestation.attesting_validators.len())
        .sum();
    eprintln!(
        "units={} proven={} ({:.0}% skipped), groups={:?}, tail attesters={tail_attesters}",
        units.len(),
        proven_units,
        (1.0 - proven_units as f64 / units.len() as f64) * 100.0,
        plan.groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
    );
    eprintln!(
        "attesting_balance={} ({:.1}% of stake)",
        plan.attesting_balance,
        plan.attesting_balance as f64 / total_active_balance as f64 * 100.0,
    );

    let run = streaming::run_native(
        &context,
        &tree,
        &units,
        &plan,
        PreviousJustification::Batch(JustificationOutput {
            accumulator_commitment: previous_commitment,
            target_epoch: target_epoch - 1,
            target_root: previous_root,
        }),
        finalized_header.clone(),
    );

    assert_eq!(run.final_output.justified_epoch, target_epoch);
    assert_eq!(run.final_output.justified_root, target_root);
    assert_eq!(run.final_output.finalized_epoch, target_epoch - 1);
    assert_eq!(run.final_output.next_accumulator_commitment, commitment);
    assert_eq!(run.final_output.accumulator_commitment, previous_commitment);
    assert_eq!(
        run.final_output.finalized_state_root,
        finalized_header.state_root,
    );

    // The critical path: one proof, one aggregate's worth of attestation work.
    assert_eq!(run.final_witness.tail.len(), plan.tail.len());
    assert!(run.final_witness.groups.is_empty());
    eprintln!(
        "streaming finality proven: {} group proofs, {} folds, 1 final proof",
        run.group_outputs.len(),
        run.aggregate_outputs.len(),
    );
}

// ---------------------------------------------------------------------------
// Report: what the latency-aware schedule makes of a real epoch
// ---------------------------------------------------------------------------

/// Print the schedule real mainnet arrivals produce, against lane count and
/// against the per-proof floor.
///
/// This is a report and not an assertion. The floor is a display constant in
/// Zisk that does not match the shipped AIR layout and is being re-measured, so
/// every second here moves with it; what is stable is the shape, and the
/// assertions at the end pin only that.
#[tokio::test]
#[ignore = "downloads ~320MB"]
async fn test_ssz_file_streaming_schedule() {
    use zkasper_witness_gen::streaming::{
        self, LanePool, ProverModel, Stage, StreamPolicy, StreamUnit,
    };

    init_tracing();
    const CONFIG: ChainConfig = ChainConfig::MAINNET;

    let path2 = ensure_state(&STATE_2);
    let mut api = SszFileApi::load(&[(&path2, STATE_2.expected_root)], &CONFIG);
    let slot = 13_776_928u64;
    let epoch = slot / CONFIG.slots_per_epoch;

    let finality_path = ensure_file(FINALITY_DATA);
    let (target_epoch, target_root) = api.load_finality_data(&finality_path);
    assert_eq!(target_epoch, epoch);

    let validators = api.get_validators(&slot.to_string()).await.unwrap();
    let total_active_balance: u64 = validators
        .iter()
        .map(|v| {
            zkasper_witness_gen::state_diff::validator_response_to_data(v)
                .active_effective_balance(epoch)
        })
        .sum();

    let per_slot = zkasper_witness_gen::attestation_collector::collect_per_slot_for_checkpoint(
        &api,
        &CONFIG,
        target_epoch,
        &target_root,
        &validators,
        epoch,
    )
    .await
    .unwrap();

    let units: Vec<StreamUnit> = per_slot
        .iter()
        .flat_map(|s| {
            s.attestations
                .iter()
                .map(move |a| StreamUnit::new(s.slot, a.clone()))
        })
        .collect();

    eprintln!("\nepoch {epoch}: {} aggregates over 32 slots", units.len());
    eprintln!("{:>4}  {:>2}  {:>9}  {:>9}   per-aggregate attesters/counted", "slot", "n", "attesters", "counted");
    for slot_data in &per_slot {
        let here: Vec<&StreamUnit> = units.iter().filter(|u| u.slot == slot_data.slot).collect();
        eprintln!(
            "{:>4}  {:>2}  {:>9}  {:>9}   {}",
            slot_data.slot - units[0].slot,
            here.len(),
            here.iter().map(|u| u.attesters()).sum::<usize>(),
            here.iter().map(|u| u.counted()).sum::<usize>(),
            here.iter()
                .map(|u| format!("{}/{}", u.attesters(), u.counted()))
                .collect::<Vec<_>>()
                .join(" "),
        );
    }

    // The floor Zisk displays, and the floor a source-level audit of the shipped
    // proving key says it really is.
    const FLOORS: [(&str, f64); 2] = [("293.6M", 293_601_280.0), ("789M", 789_000_000.0)];

    for (label, proof_base) in FLOORS {
        eprintln!("\n=== per-proof floor {label} ({:.1}s warm) ===", proof_base / 67_452_592.0 + 0.5);
        eprintln!(
            "{:>5} {:>12} {:>8} {:>6} {:>9} {:>8}  {}",
            "lanes", "pool", "T2-T", "used", "cost", "proofs", "group sizes (slots)",
        );
        for lanes in 1..=6 {
            for lane_pool in [LanePool::Fungible, LanePool::Specialised] {
                let policy = StreamPolicy {
                    lanes,
                    lane_pool,
                    prover: ProverModel {
                        proof_base,
                        ..ProverModel::default()
                    },
                    ..StreamPolicy::default()
                };
                let schedule = streaming::schedule(&units, total_active_balance, &policy);
                let sizes: Vec<usize> = schedule
                    .plan
                    .groups
                    .iter()
                    .map(|g| {
                        g.iter()
                            .map(|&i| units[i].slot)
                            .collect::<std::collections::BTreeSet<_>>()
                            .len()
                    })
                    .collect();
                eprintln!(
                    "{lanes:>5} {:>12} {:>7.1}s {:>6} {:>8.1}B {:>8}  {sizes:?}{}",
                    format!("{lane_pool:?}"),
                    schedule.latency_s(),
                    schedule.lanes,
                    schedule.total_cost / 1e9,
                    schedule.proofs.len(),
                    if schedule.plan.tail.is_empty() {
                        " + no inline tail".to_string()
                    } else {
                        format!(" + {} inline", schedule.plan.tail.len())
                    },
                );
            }
        }
    }

    // The timeline of the schedule the frontier picks, which is the thing an
    // orchestrator has to execute.
    let policy = StreamPolicy {
        lanes: 3,
        prover: ProverModel {
            proof_base: 789_000_000.0,
            ..ProverModel::default()
        },
        ..StreamPolicy::default()
    };
    let schedule = streaming::schedule(&units, total_active_balance, &policy);
    let published: usize = units.iter().map(|u| u.attesters()).sum();
    let proven: usize = schedule
        .plan
        .groups
        .concat()
        .iter()
        .chain(&schedule.plan.tail)
        .map(|&i| units[i].attesters())
        .sum();
    eprintln!(
        "\n=== 3 fungible lanes, 789M floor: T = {:.0}s, T2 = {:.0}s, T2-T = {:.1}s ===",
        schedule.threshold_s,
        schedule.postable_s,
        schedule.latency_s(),
    );
    eprintln!(
        "proves {proven} attesters of the {published} published ({:.0}% of the epoch's attester work never scheduled)",
        (1.0 - proven as f64 / published as f64) * 100.0,
    );
    for proof in &schedule.proofs {
        let covers = match proof.stage {
            Stage::Group(g) => format!(
                "slots {:?}",
                schedule.plan.groups[g]
                    .iter()
                    .map(|&i| units[i].slot - units[0].slot)
                    .collect::<std::collections::BTreeSet<_>>(),
            ),
            Stage::Fold(f) => format!("groups {:?}", schedule.plan.folds[f]),
            Stage::Final => format!(
                "absorbs {:?}, {} inline",
                schedule.plan.absorbed,
                schedule.plan.tail.len(),
            ),
            Stage::Wrap => String::new(),
        };
        eprintln!(
            "  lane {}  {:>6.1}s -> {:>6.1}s  {:>10.3}B  {:?} {covers}",
            proof.lane, proof.start_s, proof.end_s, proof.cost / 1e9, proof.stage,
        );
    }

    // How much of the answer is the floor rather than the schedule.
    eprintln!("\n=== sensitivity to the floor, 3 fungible lanes ===");
    eprintln!("{:>8} {:>8} {:>9} {:>8}  {}", "floor", "T2-T", "cost", "proofs", "group sizes");
    for proof_base in [100e6, 200e6, 293.6e6, 400e6, 500e6, 650e6, 789e6, 1000e6, 1500e6] {
        let policy = StreamPolicy {
            lanes: 3,
            prover: ProverModel {
                proof_base,
                ..ProverModel::default()
            },
            ..StreamPolicy::default()
        };
        let schedule = streaming::schedule(&units, total_active_balance, &policy);
        let sizes: Vec<usize> = schedule
            .plan
            .groups
            .iter()
            .map(|g| {
                g.iter()
                    .map(|&i| units[i].slot)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            })
            .collect();
        eprintln!(
            "{:>7.0}M {:>7.1}s {:>8.1}B {:>8}  {sizes:?}",
            proof_base / 1e6,
            schedule.latency_s(),
            schedule.total_cost / 1e9,
            schedule.proofs.len(),
        );
    }

    // Whether the fold chain is worth its own proofs at all, which is the one
    // thing in the model nobody has measured.
    eprintln!("\n=== sensitivity to recursive verification, 3 fungible lanes, 789M floor ===");
    eprintln!("{:>10} {:>8} {:>9} {:>7} {:>9}", "verify", "T2-T", "cost", "folds", "absorbed");
    for recursion_verify in [0.0, 25e6, 50e6, 100e6, 200e6, 400e6] {
        let policy = StreamPolicy {
            lanes: 3,
            prover: ProverModel {
                proof_base: 789_000_000.0,
                recursion_verify,
                ..ProverModel::default()
            },
            ..StreamPolicy::default()
        };
        let schedule = streaming::schedule(&units, total_active_balance, &policy);
        eprintln!(
            "{:>9.0}M {:>7.1}s {:>8.1}B {:>7} {:>9}",
            recursion_verify / 1e6,
            schedule.latency_s(),
            schedule.total_cost / 1e9,
            schedule.plan.folds.len(),
            schedule.plan.absorbed.len(),
        );
    }

    // The shape, which does not move with the floor: the epoch's weight arrives
    // one slot of committees at a time, so the schedule ends with the last two
    // slots alone and every group lands before the threshold.
    assert!(schedule.plan.threshold_reached);
    let last_group = schedule.plan.groups.last().expect("groups");
    assert!(
        last_group.iter().all(|&i| units[i].slot == units[*last_group.last().unwrap()].slot),
        "the last group spans more than one slot",
    );
    assert!(
        schedule.plan.groups.concat().len() + schedule.plan.tail.len() < units.len(),
        "every aggregate was proven, including the ones worth nothing",
    );
}
