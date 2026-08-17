//! Continuous mode against a mock beacon node.
//!
//! Drives four epochs through the whole pipeline — bootstrap, epoch diff, slot
//! proofs, justification, finalization — with real BLS signatures, then kills
//! the daemon in the middle of an epoch and checks that a fresh one picks up
//! exactly where it stopped.
//!
//! The synthetic chain changes one SSZ-only validator field per epoch
//! (`withdrawable_epoch`), which is enough to make every epoch diff non-empty
//! while leaving the accumulator leaves alone. That keeps the accumulator
//! commitment stable across epochs, which is the only case the finalization
//! circuit can currently pair — see the note in the report.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{make_header, MockBeaconApi};

use zkasper_common::bls::{compute_domain, compute_signing_root, DOMAIN_BEACON_ATTESTER};
use zkasper_common::constants::FAR_FUTURE_EPOCH;
use zkasper_common::ssz::attestation_data_root;
use zkasper_common::ChainConfig;

use zkasper_witness_gen::beacon_api::{AttestationResponse, CommitteeResponse, ValidatorResponse};
use zkasper_witness_gen::orchestrator::{Orchestrator, OrchestratorConfig, Tick};
use zkasper_witness_gen::prover::NativeProver;
use zkasper_witness_gen::store::{Store, StoreState};

const TEST_CONFIG: ChainConfig = ChainConfig {
    slots_per_epoch: 4,
    validators_tree_depth: 2,
    acc_tree_depth: 2,
    beacon_state_validators_field_index: 11,
    fulu_fork_epoch: 0,
};
const TEST_DEPTH: u32 = 2;
const SPE: u64 = TEST_CONFIG.slots_per_epoch;

const FIRST_EPOCH: u64 = 10;
const LAST_EPOCH: u64 = 13;
const BALANCE_GWEI: u64 = 32_000_000_000;
const VALIDATORS: usize = 4;

/// Cumulative balance crosses 2/3 of 128 ETH at the third attesting validator,
/// so a streaming aggregator should stop after the epoch's third slot.
const SLOTS_TO_THRESHOLD: u64 = 3;

// ---------------------------------------------------------------------------
// Synthetic chain
// ---------------------------------------------------------------------------

type Key = (blst::min_pk::SecretKey, [u8; 48]);

fn generate_keys(n: usize) -> Vec<Key> {
    (0..n)
        .map(|i| {
            let mut ikm = [0u8; 32];
            ikm[0] = i as u8;
            ikm[1] = 0xAB;
            let sk = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
            let pk = sk.sk_to_pk().to_bytes();
            (sk, pk)
        })
        .collect()
}

fn checkpoint_root(epoch: u64) -> [u8; 32] {
    let mut root = [0u8; 32];
    root[0] = 0xC0;
    root[1..9].copy_from_slice(&epoch.to_le_bytes());
    root
}

/// Validator set as of `epoch`.
///
/// Validator 0's `withdrawable_epoch` tracks the epoch. It is an SSZ field the
/// accumulator leaf does not commit to, so every epoch has a mutation to diff
/// while the accumulator root stays put.
fn validators_at(epoch: u64, keys: &[Key]) -> Vec<ValidatorResponse> {
    keys.iter()
        .enumerate()
        .map(|(i, (_, pubkey))| ValidatorResponse {
            index: i as u64,
            pubkey: *pubkey,
            effective_balance: BALANCE_GWEI,
            activation_epoch: 0,
            exit_epoch: FAR_FUTURE_EPOCH,
            withdrawal_credentials: {
                let mut wc = [0u8; 32];
                wc[0] = 0x01;
                wc
            },
            slashed: false,
            activation_eligibility_epoch: 0,
            withdrawable_epoch: if i == 0 { epoch } else { FAR_FUTURE_EPOCH },
        })
        .collect()
}

/// One attestation from one validator, signed for real.
fn attestation_from(
    key: &Key,
    validator_slot_offset: usize,
    slot: u64,
    epoch: u64,
    domain: [u8; 32],
) -> AttestationResponse {
    let beacon_block_root = [0u8; 32];
    let data_root = attestation_data_root(
        slot,
        0,
        &beacon_block_root,
        epoch - 1,
        &checkpoint_root(epoch - 1),
        epoch,
        &checkpoint_root(epoch),
    );
    let signing_root = compute_signing_root(&data_root, &domain);
    let signature = key
        .0
        .sign(
            &signing_root,
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
            &[],
        )
        .to_bytes();

    // One validator per committee, so the aggregation bitfield is a single bit.
    let _ = validator_slot_offset;
    AttestationResponse {
        aggregation_bits: vec![0x01],
        committee_bits: vec![],
        data_slot: slot,
        data_index: 0,
        data_beacon_block_root: beacon_block_root,
        data_source_epoch: epoch - 1,
        data_source_root: checkpoint_root(epoch - 1),
        data_target_epoch: epoch,
        data_target_root: checkpoint_root(epoch),
        signature,
    }
}

/// Build a mock chain covering `FIRST_EPOCH..=LAST_EPOCH` with the head at
/// `head_slot`.
fn build_chain(keys: &[Key], head_slot: u64) -> (MockBeaconApi, [u8; 32]) {
    let mut mock = MockBeaconApi::new();
    let domain = compute_domain(
        &DOMAIN_BEACON_ATTESTER,
        &mock.fork_version,
        &mock.genesis_validators_root,
    );

    for epoch in FIRST_EPOCH..=LAST_EPOCH {
        let boundary = epoch * SPE;
        let responses = validators_at(epoch, keys);

        mock.validators
            .insert(boundary.to_string(), responses.clone());
        mock.headers.insert(
            boundary.to_string(),
            make_header(boundary, &responses, TEST_DEPTH),
        );
        mock.block_roots
            .insert(boundary.to_string(), checkpoint_root(epoch));

        // One committee per slot, holding one validator.
        mock.committees.insert(
            (boundary.to_string(), epoch),
            (0..VALIDATORS)
                .map(|i| CommitteeResponse {
                    slot: boundary + i as u64,
                    index: 0,
                    validators: vec![i as u64],
                })
                .collect(),
        );

        // Validator i attests in the block at slot boundary + i.
        for (i, key) in keys.iter().enumerate() {
            let slot = boundary + i as u64;
            mock.attestations.insert(
                slot.to_string(),
                vec![attestation_from(key, i, slot, epoch, domain)],
            );
        }
    }

    let head_validators = validators_at(head_slot / SPE, keys);
    mock.headers.insert(
        "head".to_string(),
        make_header(head_slot, &head_validators, TEST_DEPTH),
    );
    mock.set_finality(FIRST_EPOCH, checkpoint_root(FIRST_EPOCH));

    (mock, domain)
}

fn config(dir: &Path) -> OrchestratorConfig {
    OrchestratorConfig {
        db_path: dir.join("zkasperd.db"),
        output_dir: dir.join("out"),
        poll_interval: Duration::ZERO,
        ..OrchestratorConfig::new(TEST_CONFIG, "test")
    }
}

async fn open(dir: &Path, mock: MockBeaconApi) -> Orchestrator<MockBeaconApi> {
    Orchestrator::open(mock, config(dir), Box::new(NativeProver::new(TEST_CONFIG)))
        .await
        .expect("orchestrator opens")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_follows_four_epochs_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let keys = generate_keys(VALIDATORS);
    let (mock, _) = build_chain(&keys, LAST_EPOCH * SPE + 3);

    let mut daemon = open(dir.path(), mock).await;
    let ticks = daemon.catch_up().await.unwrap();

    // Bootstrapped at the node's finalized checkpoint, then walked to the head.
    assert_eq!(daemon.state().bootstrap_epoch, FIRST_EPOCH);
    assert_eq!(daemon.state().cursor_epoch, LAST_EPOCH);
    assert_eq!(daemon.state().justified_through, Some(LAST_EPOCH));

    // Every epoch after the first was reached by exactly one epoch diff.
    let advanced: Vec<u64> = ticks.iter().filter_map(|t| t.advanced_to).collect();
    assert_eq!(advanced, vec![11, 12, 13]);

    let justified: Vec<u64> = ticks.iter().filter_map(|t| t.justified).collect();
    assert_eq!(justified, vec![10, 11, 12, 13]);

    // Finalization lags justification by one epoch: it pairs E with E+1.
    let finalized: Vec<u64> = ticks
        .iter()
        .filter_map(|t| t.finalized.as_ref().map(|c| c.epoch))
        .collect();
    assert_eq!(finalized, vec![10, 11, 12]);
    let last = daemon
        .state()
        .finalized
        .clone()
        .expect("finalized something");
    assert_eq!(last.epoch, LAST_EPOCH - 1);
    assert_eq!(last.root, checkpoint_root(LAST_EPOCH - 1));

    // Streaming: each epoch stopped at the slot that crossed 2/3, and the
    // fourth slot's block was never even fetched.
    for epoch in FIRST_EPOCH..=LAST_EPOCH {
        let boundary = epoch * SPE;
        let proved: Vec<u64> = ticks
            .iter()
            .flat_map(|t| t.slots_proved.iter().copied())
            .filter(|s| *s / SPE == epoch)
            .collect();
        assert_eq!(
            proved,
            (0..SLOTS_TO_THRESHOLD)
                .map(|i| boundary + i)
                .collect::<Vec<_>>(),
            "epoch {epoch} should stop at the threshold",
        );
    }
    let requested = daemon.api().requested_blocks();
    for epoch in FIRST_EPOCH..=LAST_EPOCH {
        let unreached = (epoch * SPE + SLOTS_TO_THRESHOLD).to_string();
        assert!(
            !requested.contains(&unreached),
            "slot {unreached} was fetched after the threshold had been crossed",
        );
    }

    // Artifacts.
    let out = dir.path().join("out");
    assert!(out
        .join(format!("epoch-{FIRST_EPOCH:09}"))
        .join("bootstrap.bin")
        .exists());
    for epoch in FIRST_EPOCH..=LAST_EPOCH {
        let epoch_dir = out.join(format!("epoch-{epoch:09}"));
        assert!(
            epoch_dir.join("justification.bin").exists(),
            "epoch {epoch}"
        );
        for i in 0..SLOTS_TO_THRESHOLD {
            let slot = epoch * SPE + i;
            assert!(
                epoch_dir.join(format!("slot_proof_{slot}.bin")).exists(),
                "epoch {epoch} slot {slot}",
            );
        }
        if epoch > FIRST_EPOCH {
            assert!(epoch_dir.join("epoch_diff.bin").exists(), "epoch {epoch}");
            assert!(epoch_dir.join("finalization.bin").exists(), "epoch {epoch}");
        }
    }

    // Manifest.
    let status: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("status.json")).unwrap()).unwrap();
    assert_eq!(status["chain"], "test");
    assert_eq!(status["accumulator"]["epoch"], LAST_EPOCH);
    assert_eq!(status["justified_through"], LAST_EPOCH);
    assert_eq!(status["last_finalized"]["epoch"], LAST_EPOCH - 1);
    assert_eq!(
        status["accumulator"]["total_active_balance"],
        VALIDATORS as u64 * BALANCE_GWEI,
    );
    assert!(status["recent_stages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["stage"] == "slot_proof" && s["slot"].is_number()));
}

#[tokio::test]
async fn test_resumes_after_a_crash_mid_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let keys = generate_keys(VALIDATORS);

    // Reference: one uninterrupted run to the head.
    let reference = {
        let reference_dir = tempfile::tempdir().unwrap();
        let (mock, _) = build_chain(&keys, LAST_EPOCH * SPE + 3);
        let mut daemon = open(reference_dir.path(), mock).await;
        daemon.catch_up().await.unwrap();
        daemon.state().clone()
    };

    // Head one slot into epoch 12: the accumulator reaches 12, but only two of
    // the three slots it takes to justify 12 exist yet.
    let (mock, _) = build_chain(&keys, 12 * SPE + 1);
    let first_run = {
        let mut daemon = open(dir.path(), mock).await;
        daemon.catch_up().await.unwrap();
        daemon.state().clone()
    };
    assert_eq!(
        first_run.cursor_epoch, 12,
        "accumulator advanced into epoch 12"
    );
    assert_eq!(
        first_run.justified_through,
        Some(11),
        "epoch 12 is not justified yet",
    );
    assert!(first_run.needs_justification());

    // Crash. Nothing of the partial epoch survives except what was committed.
    let (mock, _) = build_chain(&keys, LAST_EPOCH * SPE + 3);
    let mut daemon = open(dir.path(), mock).await;
    let ticks = daemon.catch_up().await.unwrap();

    // Epoch 12's accumulator advance was already durable, so it is not redone.
    let advanced: Vec<u64> = ticks.iter().filter_map(|t| t.advanced_to).collect();
    assert_eq!(
        advanced,
        vec![13],
        "only the epochs still owed are advanced"
    );

    // The interrupted epoch is picked up from its first slot and finished.
    let justified: Vec<u64> = ticks.iter().filter_map(|t| t.justified).collect();
    assert_eq!(justified, vec![12, 13]);

    // And the accumulator ends up bit-identical to the uninterrupted run: same
    // root, and the same audit chain over every epoch since bootstrap.
    let resumed = daemon.state();
    assert_eq!(resumed.cursor_epoch, reference.cursor_epoch);
    assert_eq!(resumed.acc_root, reference.acc_root);
    assert_eq!(resumed.acc_commitment, reference.acc_commitment);
    assert_eq!(
        resumed.acc_chain_digest, reference.acc_chain_digest,
        "an epoch applied twice or skipped would show up here",
    );
    assert_eq!(resumed.justified_through, reference.justified_through);
    assert_eq!(
        resumed.finalized.as_ref().map(|c| c.epoch),
        reference.finalized.as_ref().map(|c| c.epoch),
    );
}

#[tokio::test]
async fn test_damaged_store_is_rejected_rather_than_resumed() {
    let dir = tempfile::tempdir().unwrap();
    let keys = generate_keys(VALIDATORS);
    let (mock, _) = build_chain(&keys, FIRST_EPOCH * SPE + 3);

    let db_path = {
        let mut daemon = open(dir.path(), mock).await;
        daemon.catch_up().await.unwrap();
        config(dir.path()).db_path
    };

    let mut bytes = std::fs::read(&db_path).unwrap();
    let midpoint = bytes.len() / 2;
    bytes[midpoint] ^= 0xFF;
    std::fs::write(&db_path, &bytes).unwrap();

    let error = Store::new(&db_path)
        .load()
        .err()
        .expect("a corrupted store must not load");
    assert!(
        format!("{error:#}").contains("checksum"),
        "expected a checksum failure, got: {error:#}",
    );

    // And the daemon refuses to start on it rather than rebuilding from a
    // damaged accumulator.
    let (mock, _) = build_chain(&keys, FIRST_EPOCH * SPE + 3);
    let error = Orchestrator::open(
        mock,
        config(dir.path()),
        Box::new(NativeProver::new(TEST_CONFIG)),
    )
    .await
    .err()
    .expect("daemon must not start on a damaged store");
    assert!(format!("{error:#}").contains("damaged"));
}

#[tokio::test]
async fn test_truncated_store_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let keys = generate_keys(VALIDATORS);
    let (mock, _) = build_chain(&keys, FIRST_EPOCH * SPE + 3);

    let db_path = {
        let mut daemon = open(dir.path(), mock).await;
        daemon.catch_up().await.unwrap();
        config(dir.path()).db_path
    };

    let bytes = std::fs::read(&db_path).unwrap();
    std::fs::write(&db_path, &bytes[..bytes.len() - 64]).unwrap();

    let error = Store::new(&db_path)
        .load()
        .err()
        .expect("truncated store must not load");
    assert!(format!("{error:#}").contains("truncated"), "got: {error:#}");
}

#[test]
fn test_accumulator_cannot_skip_or_repeat_an_epoch() {
    let root = [7u64; 4];
    let balance = 4 * BALANCE_GWEI;
    let mut state = StoreState::bootstrapped("test".into(), 100, root, balance, 4);
    let commitment = zkasper_common::acc::commitment(&root, balance);

    assert!(state
        .clone()
        .advance(102, root, commitment, balance, 4)
        .is_err());
    assert!(state
        .clone()
        .advance(100, root, commitment, balance, 4)
        .is_err());

    // A commitment that does not bind the root it is offered with is refused
    // even when the epoch is right.
    assert!(state
        .clone()
        .advance(101, root, [0u64; 4], balance, 4)
        .is_err());

    state.advance(101, root, commitment, balance, 4).unwrap();
    assert_eq!(state.cursor_epoch, 101);
}

#[test]
fn test_tick_progress_reporting() {
    assert!(!Tick::default().made_progress());
    assert!(Tick {
        advanced_to: Some(1),
        ..Tick::default()
    }
    .made_progress());
    assert!(Tick {
        slots_proved: vec![32],
        ..Tick::default()
    }
    .made_progress());
}
