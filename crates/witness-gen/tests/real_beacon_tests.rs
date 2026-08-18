//! Integration tests using a real Ethereum beacon node.
//!
//! All tests require the `BEACON_API_URL` environment variable to be set
//! (e.g. `http://localhost:5052`) and are `#[ignore]`'d by default.
//!
//! Run with:
//! ```sh
//! BEACON_API_URL=http://localhost:5052 cargo test --test real_beacon_tests -- --ignored
//! ```

mod common;

use anyhow::Result;

use zkasper_common::acc;
use zkasper_common::constants::VALIDATORS_TREE_DEPTH;
use zkasper_common::ssz::list_hash_tree_root;
use zkasper_common::ChainConfig;

const CONFIG: ChainConfig = ChainConfig::MAINNET;

use zkasper_witness_gen::beacon_api::{BeaconApi, BeaconApiClient};
use zkasper_witness_gen::ssz_state;
use zkasper_witness_gen::state_diff::{build_validator_roots, build_validators_ssz_tree};

fn get_api() -> BeaconApiClient {
    let url = std::env::var("BEACON_API_URL").expect("BEACON_API_URL must be set");
    BeaconApiClient::new(&url)
}

/// Find the latest finalized slot (an epoch boundary).
async fn get_finalized_slot(api: &BeaconApiClient) -> Result<u64> {
    let header = api.get_header("finalized").await?;
    // Round down to epoch boundary
    let epoch = header.slot / CONFIG.slots_per_epoch;
    Ok(epoch * CONFIG.slots_per_epoch)
}

// -----------------------------------------------------------------------
// Test: SSZ state parsing produces state root matching block header
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires BEACON_API_URL"]
async fn test_ssz_state_parsing() {
    let api = get_api();
    let slot = get_finalized_slot(&api).await.unwrap();
    let slot_str = slot.to_string();

    eprintln!("testing SSZ state parsing at slot {slot}");

    // Fetch header
    let header = api.get_header(&slot_str).await.unwrap();
    eprintln!("  header state_root: 0x{}", hex::encode(header.state_root));

    // Fetch validators and compute their HTR
    let validators = api.get_validators(&slot_str).await.unwrap();
    let num_validators = validators.len() as u64;
    eprintln!("  validator count: {num_validators}");

    let validator_roots = build_validator_roots(&validators);
    let (data_root, _) = build_validators_ssz_tree(&validator_roots, VALIDATORS_TREE_DEPTH, &[]);
    let validators_htr = list_hash_tree_root(&data_root, num_validators);
    eprintln!("  validators HTR: 0x{}", hex::encode(validators_htr));

    // Fetch raw SSZ state
    let raw_ssz = api
        .get_state_ssz(&slot_str)
        .await
        .unwrap()
        .expect("beacon node should support debug/beacon/states SSZ endpoint");
    eprintln!("  SSZ state size: {} bytes", raw_ssz.len());

    // Parse and verify
    let proof = ssz_state::parse_state_proof(&raw_ssz, &validators_htr, &CONFIG, slot).unwrap();
    eprintln!("  computed state_root: 0x{}", hex::encode(proof.state_root));
    assert_eq!(
        proof.state_root, header.state_root,
        "parsed SSZ state root must match header"
    );
    assert_eq!(proof.siblings.len(), 6);
    eprintln!("  state proof has {} siblings — OK", proof.siblings.len());
}

// -----------------------------------------------------------------------
// Test: take an init point from real data and open it again
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires BEACON_API_URL"]
async fn test_real_init_point() {
    let api = get_api();
    let slot = get_finalized_slot(&api).await.unwrap();
    let epoch = slot / CONFIG.slots_per_epoch;

    eprintln!("taking a real init point at slot {slot} (epoch {epoch})");

    let (init, snapshot) = zkasper_witness_gen::init_point::take(&api, &CONFIG, "mainnet", slot)
        .await
        .unwrap();

    eprintln!("  validators: {}", init.num_validators);
    eprintln!("  total_active_balance: {}", init.total_active_balance);
    eprintln!(
        "  acc_root: 0x{}",
        hex::encode(zkasper_common::acc::to_bytes(&snapshot.tree.root()))
    );

    assert!(init.num_validators > 0, "should have validators");
    assert!(
        init.total_active_balance > 0,
        "should have non-zero balance"
    );
    assert_eq!(init.epoch, epoch);
    assert_eq!(init.acc_root, snapshot.tree.root());
    assert_eq!(
        init.accumulator_commitment,
        acc::commitment(&init.acc_root, init.total_active_balance),
    );

    // What a third party does with the file a deployment publishes: walk the
    // same registry and refuse it if anything disagrees.
    let reopened = zkasper_witness_gen::init_point::open(&api, &CONFIG, "mainnet", &init)
        .await
        .expect("the published init point describes the registry at its own state root");
    assert_eq!(reopened.tree.root(), init.acc_root);
    eprintln!("  init point re-derived from the registry");
}

// -----------------------------------------------------------------------
// Test: init point + epoch diff with real data
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires BEACON_API_URL"]
async fn test_real_epoch_diff() {
    let api = get_api();
    let slot_2 = get_finalized_slot(&api).await.unwrap();
    let epoch_2 = slot_2 / CONFIG.slots_per_epoch;

    // Go back one epoch for slot_1
    assert!(epoch_2 >= 1, "need at least epoch 1");
    let slot_1 = (epoch_2 - 1) * CONFIG.slots_per_epoch;

    eprintln!("testing real epoch diff: slot {slot_1} -> {slot_2}");

    // Start at slot_1
    let (init, snapshot) = zkasper_witness_gen::init_point::take(&api, &CONFIG, "mainnet", slot_1)
        .await
        .unwrap();
    let (mut tree, epoch_state, total_active_balance, num_validators) = (
        snapshot.tree,
        snapshot.epoch_state,
        init.total_active_balance,
        init.num_validators,
    );

    eprintln!("  init point: {num_validators} validators, balance={total_active_balance}");
    assert_eq!(init.acc_root, tree.root());

    // Epoch diff
    let (diff_witness, _new_epoch_state, new_balance, new_num_validators) =
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

    eprintln!(
        "  epoch diff: {} mutations, new_validators={new_num_validators}, new_balance={new_balance}",
        diff_witness.mutations.len()
    );

    // Verify epoch diff
    let diff = zkasper_epoch_diff_guest::verify_epoch_diff(&diff_witness);

    assert_eq!(diff.acc_root, tree.root());
    assert_eq!(diff.total_active_balance, new_balance);

    assert_eq!(
        diff.accumulator_commitment,
        acc::commitment(&diff.acc_root, new_balance),
    );
    eprintln!("  guest verification passed");
}

// -----------------------------------------------------------------------
// Test: full pipeline with DB persistence
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires BEACON_API_URL"]
async fn test_real_full_pipeline() {
    let api = get_api();
    let slot_2 = get_finalized_slot(&api).await.unwrap();
    let epoch_2 = slot_2 / CONFIG.slots_per_epoch;
    assert!(epoch_2 >= 1, "need at least epoch 1");
    let slot_1 = (epoch_2 - 1) * CONFIG.slots_per_epoch;

    eprintln!("testing real full pipeline: slot {slot_1} -> {slot_2}");

    // Start from an init point
    let (init, snapshot) = zkasper_witness_gen::init_point::take(&api, &CONFIG, "mainnet", slot_1)
        .await
        .unwrap();
    let (tree, total_active_balance, num_validators) = (
        snapshot.tree,
        init.total_active_balance,
        init.num_validators,
    );

    // Save to DB
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db = zkasper_witness_gen::db::Db::new(&db_path);
    db.save(&tree, epoch_2 - 1, total_active_balance, num_validators)
        .unwrap();

    // Load from DB
    let (mut loaded_tree, cursor_epoch, loaded_balance, loaded_count) =
        db.load().unwrap().expect("should load");
    assert_eq!(loaded_tree.root(), tree.root());
    assert_eq!(cursor_epoch, epoch_2 - 1);
    assert_eq!(loaded_balance, total_active_balance);
    assert_eq!(loaded_count, num_validators);
    eprintln!("  DB save/load verified");

    // Epoch diff from loaded state (no cached EpochState — uses slow path)
    let old_state = zkasper_witness_gen::EpochState::empty(slot_1, loaded_count);
    let (diff_witness, _new_epoch_state, new_balance, new_count) =
        zkasper_witness_gen::witness_epoch_diff::build(
            &api,
            &CONFIG,
            &mut loaded_tree,
            &old_state,
            slot_2,
            loaded_balance,
        )
        .await
        .unwrap();

    // Verify epoch diff
    let diff = zkasper_epoch_diff_guest::verify_epoch_diff(&diff_witness);

    assert_eq!(diff.acc_root, loaded_tree.root());
    assert_eq!(diff.total_active_balance, new_balance);

    // Verify accumulator commitment chain
    assert_eq!(
        diff.accumulator_commitment,
        acc::commitment(&diff.acc_root, new_balance),
    );

    eprintln!("  pipeline: {} -> {} validators", num_validators, new_count);
    eprintln!(
        "  pipeline: {} -> {} balance",
        total_active_balance, new_balance
    );
    eprintln!("  accumulator commitment chain verified");
}
