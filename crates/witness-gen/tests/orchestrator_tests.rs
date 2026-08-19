//! Continuous mode against a mock beacon node.
//!
//! Drives four epochs through the whole pipeline — init point, epoch diff,
//! committee, slot proofs, justification, finalization — with real BLS
//! signatures, then kills the daemon in the middle of an epoch and checks that
//! a fresh one picks up exactly where it stopped.
//!
//! The synthetic chain drops one validator's effective balance by 1 ETH every
//! epoch, so the accumulator commitment and the total active balance are
//! different at every epoch — as they are on a live chain, where the epoch
//! transition rewrites effective balances. Finalization therefore has to pair
//! justifications proved against two different accumulators, which is only
//! possible because the circuit is handed the epoch diff that links them.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{FakeGossip, MockBeaconApi, SyntheticChain, BALANCE_GWEI};

use zkasper_common::ChainConfig;

use zkasper_witness_gen::init_point::InitPoint;
use zkasper_witness_gen::orchestrator::{Orchestrator, OrchestratorConfig, Pipeline, Tick};
use zkasper_witness_gen::prover::NativeProver;
use zkasper_witness_gen::store::{Store, StoreState};

const TEST_CONFIG: ChainConfig = ChainConfig {
    // Twice as many slots as there are validators to attest at them, so the
    // epoch still has blocks left when the threshold is crossed — otherwise
    // stopping early and running out of epoch look the same from outside.
    slots_per_epoch: 8,
    validators_tree_depth: 2,
    acc_tree_depth: 2,
    beacon_state_validators_field_index: 11,
    fulu_fork_epoch: 0,
};
const SPE: u64 = TEST_CONFIG.slots_per_epoch;

const FIRST_EPOCH: u64 = 10;
const LAST_EPOCH: u64 = 13;
const VALIDATORS: usize = 4;

/// Cumulative balance crosses 2/3 of 128 ETH at the third attesting validator,
/// so a streaming aggregator should stop after the epoch's third attestation
/// slot.
const SLOTS_TO_THRESHOLD: u64 = 3;

fn chain() -> SyntheticChain {
    SyntheticChain::new(TEST_CONFIG, VALIDATORS, FIRST_EPOCH, LAST_EPOCH)
}

fn config(dir: &Path) -> OrchestratorConfig {
    OrchestratorConfig {
        db_path: dir.join("zkasperd.db"),
        output_dir: dir.join("out"),
        poll_interval: Duration::ZERO,
        ..OrchestratorConfig::new(TEST_CONFIG, "test")
    }
}

/// The config, with an init point taken from the node the daemon will follow.
///
/// Taken rather than written by hand on purpose: the generator and the daemon
/// have to agree about what the accumulator at an epoch is, and a hard-coded
/// tuple would keep passing on the day they stopped agreeing.
async fn config_from(dir: &Path, mock: &MockBeaconApi) -> OrchestratorConfig {
    OrchestratorConfig {
        init_point: Some(
            zkasper_witness_gen::init_point::generate(
                mock,
                &TEST_CONFIG,
                "test",
                FIRST_EPOCH * SPE,
            )
            .await
            .expect("the node serves the epoch the run starts on"),
        ),
        ..config(dir)
    }
}

async fn open(dir: &Path, mock: MockBeaconApi) -> Orchestrator<MockBeaconApi> {
    let config = config_from(dir, &mock).await;
    Orchestrator::open(mock, config, Box::new(NativeProver::new(TEST_CONFIG)))
        .await
        .expect("orchestrator opens")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_follows_four_epochs_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();

    let mut daemon = open(dir.path(), chain.mock(LAST_EPOCH * SPE + 3)).await;
    let ticks = daemon.catch_up().await.unwrap();

    // Started at the init point's epoch, then walked to the head.
    assert_eq!(daemon.state().init_epoch, FIRST_EPOCH);
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
    assert_eq!(last.root, chain.checkpoint_root(LAST_EPOCH - 1));

    // Streaming: each epoch stopped at the attestation slot that crossed 2/3,
    // and the block carrying the fourth slot's attestations was never fetched.
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
        // Slot `s` is closed by the block at `s + 1`, so the first block the
        // aggregator had no reason to ask for is one past the threshold slot's.
        let unreached = (epoch * SPE + SLOTS_TO_THRESHOLD + 1).to_string();
        assert!(
            !requested.contains(&unreached),
            "slot {unreached} was fetched after the threshold had been crossed",
        );
    }

    // Artifacts. The epoch the run starts on has no witness of its own: it is
    // configured, checked against the registry and never proved, so the first
    // thing written for it is a stage that proves something.
    let out = dir.path().join("out");
    assert!(!out
        .join(format!("epoch-{FIRST_EPOCH:09}"))
        .join("epoch_diff.bin")
        .exists());
    for epoch in FIRST_EPOCH..=LAST_EPOCH {
        let epoch_dir = out.join(format!("epoch-{epoch:09}"));
        assert!(epoch_dir.join("committee.bin").exists(), "epoch {epoch}");
        // A justification is a chain of folds, and each link writes its own
        // witness. The link that opens the epoch is always there; how many
        // follow it depends on how many slots the epoch took.
        assert!(
            epoch_dir.join("justification_0.bin").exists(),
            "epoch {epoch}"
        );
        // Slots are proven in groups, and a group's proof is named after its
        // first slot.
        for i in (0..SLOTS_TO_THRESHOLD)
            .step_by(zkasper_witness_gen::orchestrator::DEFAULT_SLOT_GROUP_WIDTH)
        {
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
        chain.total_active_balance_at(LAST_EPOCH).to_string(),
    );
    assert!(status["recent_stages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["stage"] == "slot_proof" && s["slot"].is_number()));
}

/// The streaming pipeline, driven one slot at a time the way a live node feeds
/// it.
///
/// Epoch 10 has nothing to finalize, so it goes through the batch path; epoch 11
/// streams. The head is moved a slot per tick, which is the whole point: each
/// slot's attestation is proven and folded when it arrives, so when the third
/// one crosses the threshold the only thing left is one attestation and one
/// proof. Anything else — a group left unfolded, more than one unit in the tail
/// — shows up in the manifest, which is why the assertions read it back.
#[tokio::test]
async fn test_streams_an_epoch_and_measures_its_latency() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();

    let mock = chain.mock((FIRST_EPOCH + 1) * SPE);
    let config = OrchestratorConfig {
        pipeline: Pipeline::Streaming,
        ..config_from(dir.path(), &mock).await
    };
    let mut daemon = Orchestrator::open(mock, config, Box::new(NativeProver::new(TEST_CONFIG)))
        .await
        .expect("orchestrator opens");

    // Epoch 10 justified the batch way, and the accumulator moved to 11.
    daemon.catch_up().await.unwrap();
    assert_eq!(daemon.state().cursor_epoch, FIRST_EPOCH + 1);
    assert_eq!(daemon.state().justified_through, Some(FIRST_EPOCH));

    let stream_epoch = FIRST_EPOCH + 1;
    let boundary = stream_epoch * SPE;
    // The head has to lead the last counted slot by one: a slot's attestations
    // are carried by the block after it, so that is the earliest the daemon can
    // close it.
    let mut ticks = Vec::new();
    for slot in boundary..=boundary + SLOTS_TO_THRESHOLD {
        daemon.api().set_head(chain.header_at(slot));
        ticks.extend(daemon.catch_up().await.unwrap());
    }

    assert_eq!(
        ticks.iter().filter_map(|t| t.justified).collect::<Vec<_>>(),
        vec![stream_epoch],
    );
    let finalized = ticks
        .iter()
        .filter_map(|t| t.finalized.as_ref())
        .next_back()
        .expect("the final proof finalizes the epoch before it");
    assert_eq!(finalized.epoch, FIRST_EPOCH);
    assert_eq!(finalized.root, chain.checkpoint_root(FIRST_EPOCH));
    assert!(
        daemon.state().last_stream_final.is_some(),
        "the next epoch has to be able to consume this one",
    );

    let out = dir.path().join("out");
    let epoch_dir = out.join(format!("epoch-{stream_epoch:09}"));
    for name in ["group_0", "group_1", "aggregate_0", "aggregate_1"] {
        assert!(epoch_dir.join(format!("{name}.bin")).exists(), "{name}");
    }
    assert!(epoch_dir.join("stream_final.bin").exists());

    let status: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("status.json")).unwrap()).unwrap();
    let latency = &status["recent_latencies"][0];
    assert_eq!(latency["epoch"], stream_epoch);
    assert_eq!(latency["folded_groups"], 2);
    assert_eq!(
        latency["late_groups"], 0,
        "a daemon at the head has nothing left to fold when the threshold crosses",
    );
    assert_eq!(latency["tail"], 1, "one attestation on the critical path");
    assert!(latency["t2_minus_t_millis"].is_number());
}

/// The streaming pipeline proves an epoch out of gossip, without waiting for the
/// blocks that carry it.
///
/// This is the whole point of the event stream. An attestation for slot `s` is
/// gossiped during `s` and included in the block at `s+1` or later, so a daemon
/// that reads blocks is a slot behind by construction. Here every attestation is
/// published in its own slot and no block past the epoch boundary is ever asked
/// for — the epoch is justified from gossip alone.
#[tokio::test]
async fn test_streams_an_epoch_from_gossip_without_reading_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();

    let mock = chain.mock((FIRST_EPOCH + 1) * SPE);
    let config = OrchestratorConfig {
        pipeline: Pipeline::Streaming,
        ..config_from(dir.path(), &mock).await
    };
    let gossip = FakeGossip::default();
    let mut daemon = Orchestrator::open(mock, config, Box::new(NativeProver::new(TEST_CONFIG)))
        .await
        .expect("orchestrator opens")
        .with_gossip(Box::new(gossip.clone()));
    daemon.catch_up().await.unwrap();

    let stream_epoch = FIRST_EPOCH + 1;
    let boundary = stream_epoch * SPE;

    // Validator i attests to slot boundary + i, and it is gossiped in that slot
    // rather than in the block after it.
    let mut ticks = Vec::new();
    for index in 0..SLOTS_TO_THRESHOLD as usize {
        gossip.publish(vec![chain.attestation(stream_epoch, index)]);
        daemon
            .api()
            .set_head(chain.header_at(boundary + index as u64));
        ticks.extend(daemon.catch_up().await.unwrap());
    }

    assert_eq!(
        ticks.iter().filter_map(|t| t.justified).collect::<Vec<_>>(),
        vec![stream_epoch],
    );
    let past_the_boundary: Vec<String> = daemon
        .api()
        .requested_blocks()
        .into_iter()
        .filter(|id| id.parse::<u64>().is_ok_and(|slot| slot > boundary))
        .collect();
    assert!(
        past_the_boundary.is_empty(),
        "the epoch was read out of blocks after all: {past_the_boundary:?}",
    );
}

/// A checkpoint that reorgs out under a streaming epoch is a retry, never a
/// publication.
///
/// This is what makes firing at 2/3 safe. At the circuit's own threshold there
/// is no headroom: one slot carries about 3.1% of the stake, so a one-slot reorg
/// drops the epoch below what the circuit will accept, and a daemon that
/// published anyway would be publishing a proof of a checkpoint the chain no
/// longer has. The root is therefore re-resolved before anything is written, and
/// the epoch reopens against whatever is canonical now.
#[tokio::test]
async fn test_a_reorged_checkpoint_is_retried_and_never_published() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();

    let mock = chain.mock((FIRST_EPOCH + 1) * SPE);
    let config = OrchestratorConfig {
        pipeline: Pipeline::Streaming,
        ..config_from(dir.path(), &mock).await
    };
    let mut daemon = Orchestrator::open(mock, config, Box::new(NativeProver::new(TEST_CONFIG)))
        .await
        .expect("orchestrator opens");
    daemon.catch_up().await.unwrap();

    let stream_epoch = FIRST_EPOCH + 1;
    let boundary = stream_epoch * SPE;

    // The chain reorgs while the epoch is being collected: every checkpoint now
    // resolves to a root nobody attested to.
    daemon.api().set_reorg(Some([0xEE; 32]));
    let mut ticks = Vec::new();
    for slot in boundary..=boundary + SLOTS_TO_THRESHOLD {
        daemon.api().set_head(chain.header_at(slot));
        ticks.extend(daemon.catch_up().await.unwrap());
    }

    assert!(
        ticks.iter().all(|t| t.justified.is_none()),
        "a checkpoint that reorged out was justified anyway",
    );
    assert_eq!(daemon.state().justified_through, Some(FIRST_EPOCH));

    // Back on the canonical chain, the same epoch is proven on the next tick.
    daemon.api().set_reorg(None);
    let ticks = daemon.catch_up().await.unwrap();
    assert_eq!(
        ticks.iter().filter_map(|t| t.justified).collect::<Vec<_>>(),
        vec![stream_epoch],
    );
}

/// The node migrates the boundary between the daemon opening an epoch and
/// diffing it.
///
/// This is the run that died on 2026-08-19, in miniature. The daemon proved
/// epoch E's justification off the registry at E's boundary, spent three
/// minutes on the proof, and then asked for that same registry again to build
/// the diff out of E — by which time the node's split had moved past it. The
/// state was never unavailable; the daemon had nowhere to keep what it had
/// already read.
///
/// Nothing here waits for the split. The node stops serving the boundary the
/// instant the epoch is justified, which is the worst the trough can do, and
/// the diff still has to run.
#[tokio::test]
async fn test_diffs_a_boundary_the_node_has_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();
    let mut daemon = open(dir.path(), chain.mock(LAST_EPOCH * SPE + 3)).await;

    let tick = daemon.tick().await.unwrap();
    assert_eq!(tick.justified, Some(FIRST_EPOCH));

    // The split moves past the epoch the accumulator sits on — one epoch behind
    // what the node calls finalized, which is where the live run was.
    daemon.api().prune_state(FIRST_EPOCH * SPE);

    let tick = daemon
        .tick()
        .await
        .expect("the diff runs off the boundary this run took, not off the node");
    assert_eq!(tick.advanced_to, Some(FIRST_EPOCH + 1));
    assert_eq!(daemon.state().cursor_epoch, FIRST_EPOCH + 1);
    assert_eq!(
        daemon.state().init_epoch,
        FIRST_EPOCH,
        "the accumulator chain is unbroken: nothing re-anchored",
    );
}

/// A restart resumes onto boundaries the node has migrated in the meantime.
///
/// The cursor of a resumed run is already behind finalization, so a daemon that
/// held its boundaries in memory alone would come back needing exactly what the
/// node has just thrown away. They are kept beside the store for this.
#[tokio::test]
async fn test_resumes_onto_boundaries_the_node_has_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();

    let mut daemon = open(dir.path(), chain.mock(LAST_EPOCH * SPE + 3)).await;
    daemon.tick().await.unwrap();
    drop(daemon);

    // Both boundaries the next diff spans are gone from the node: the one the
    // accumulator sits on and the one it is moving to.
    let mock = chain.mock(LAST_EPOCH * SPE + 3);
    mock.prune_state(FIRST_EPOCH * SPE);
    mock.prune_state((FIRST_EPOCH + 1) * SPE);
    let mut daemon = Orchestrator::open(
        mock,
        config(dir.path()),
        Box::new(NativeProver::new(TEST_CONFIG)),
    )
    .await
    .expect("the store is enough to resume from");

    let tick = daemon
        .tick()
        .await
        .expect("what the run held before the restart is still held after it");
    assert_eq!(tick.advanced_to, Some(FIRST_EPOCH + 1));
}

/// The node throws away a state this run never held.
///
/// A checkpoint-synced node serves states from its finalized split forward, so
/// an accumulator pointed at an epoch the daemon was not up to see asks for a
/// state that is gone. Restarting cannot bring it back — the window only moves
/// further away — and a cache cannot produce a boundary it never took.
///
/// The daemon used to start again from a fresh bootstrap here, which kept it
/// alive at the cost of silently breaking the accumulator chain at the epoch it
/// restarted on. It still stops and names the remedy, because a break a
/// consumer cannot see is worse than an outage an operator can. The one place
/// it does skip forward is a run that has chained nothing yet — see
/// `test_anchors_itself_when_the_init_point_is_out_of_reach`.
#[tokio::test]
async fn test_stops_when_the_node_has_thrown_the_state_away() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();

    // Justify epoch 10 and move the accumulator onto epoch 11.
    let mut daemon = open(dir.path(), chain.mock(LAST_EPOCH * SPE + 3)).await;
    daemon.tick().await.unwrap();
    daemon.tick().await.unwrap();
    assert_eq!(daemon.state().cursor_epoch, FIRST_EPOCH + 1);
    drop(daemon);

    // A store carried somewhere without the boundaries beside it, which is the
    // only way a resumed run can need a state it never took.
    std::fs::remove_dir_all(dir.path().join("zkasperd.db.boundaries")).unwrap();

    // Reopen against a node that has stopped serving epoch 11's boundary state,
    // which is what the diff onto epoch 12 needs. It still holds the epoch it
    // reports as finalized, as a node always does.
    let mock = chain.mock(LAST_EPOCH * SPE + 3);
    let config = config_from(dir.path(), &mock).await;
    mock.prune_state((FIRST_EPOCH + 1) * SPE);
    let mut daemon = Orchestrator::open(mock, config, Box::new(NativeProver::new(TEST_CONFIG)))
        .await
        .unwrap();

    let error = daemon
        .tick()
        .await
        .expect_err("a pruned state has to stop the run, not be worked around");
    let error = format!("{error:#}");
    assert!(
        error.contains("no longer serves the state") && error.contains("init point"),
        "the operator has to be told what to do about it, got: {error}",
    );

    // And nothing moved: the accumulator is where it was, on a chain that is
    // still unbroken.
    assert_eq!(daemon.state().cursor_epoch, FIRST_EPOCH + 1);
    assert_eq!(daemon.state().init_epoch, FIRST_EPOCH);
}

/// The init point names an epoch the node has already migrated.
///
/// An init point is generated at the node's finalized checkpoint — the oldest
/// state it serves — so one migration between generating it and walking its
/// registry leaves a daemon that cannot start and cannot be retried into
/// starting. Nothing is chained yet at that point, so there is nothing for a
/// later starting epoch to break, and the run anchors itself on what the node
/// does serve rather than dying at startup.
#[tokio::test]
async fn test_anchors_itself_when_the_init_point_is_out_of_reach() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();
    let mut mock = chain.mock(LAST_EPOCH * SPE + 3);
    mock.set_finality(FIRST_EPOCH, chain.checkpoint_root(FIRST_EPOCH));

    // A tuple for an epoch behind the node's window, which is what a freshly
    // generated one becomes when the split moves while the daemon is starting.
    let stale = InitPoint {
        epoch: FIRST_EPOCH - 1,
        ..zkasper_witness_gen::init_point::generate(&mock, &TEST_CONFIG, "test", FIRST_EPOCH * SPE)
            .await
            .unwrap()
    };
    mock.prune_state((FIRST_EPOCH - 1) * SPE);

    let daemon = Orchestrator::open(
        mock,
        OrchestratorConfig {
            init_point: Some(stale),
            ..config(dir.path())
        },
        Box::new(NativeProver::new(TEST_CONFIG)),
    )
    .await
    .expect("a run that has chained nothing starts where the node can serve it");

    assert_eq!(daemon.state().init_epoch, FIRST_EPOCH);
    assert_eq!(daemon.state().cursor_epoch, FIRST_EPOCH);
    assert!(
        dir.path().join("zkasperd.init-point.json").exists(),
        "the tuple the run anchored on has to be somewhere an operator can publish it",
    );
}

#[tokio::test]
async fn test_resumes_after_a_crash_mid_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let chain = chain();

    // Reference: one uninterrupted run to the head.
    let reference = {
        let reference_dir = tempfile::tempdir().unwrap();
        let mut daemon = open(reference_dir.path(), chain.mock(LAST_EPOCH * SPE + 3)).await;
        daemon.catch_up().await.unwrap();
        daemon.state().clone()
    };

    // Head two slots into epoch 12: the accumulator reaches 12, but only two of
    // the three slots it takes to justify 12 have been closed yet.
    let first_run = {
        let mut daemon = open(dir.path(), chain.mock(12 * SPE + 2)).await;
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
    let mut daemon = open(dir.path(), chain.mock(LAST_EPOCH * SPE + 3)).await;
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
    // root, and the same audit chain over every epoch since the init point.
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
    let chain = chain();

    let db_path = {
        let mut daemon = open(dir.path(), chain.mock(FIRST_EPOCH * SPE + 3)).await;
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
    let error = Orchestrator::open(
        chain.mock(FIRST_EPOCH * SPE + 3),
        config(dir.path()),
        Box::new(NativeProver::new(TEST_CONFIG)),
    )
    .await
    .err()
    .expect("daemon must not start on a damaged store");
    // No init point is offered, which is also the point: a damaged store is a
    // damaged store, not an invitation to start a new chain over the top of it.
    assert!(format!("{error:#}").contains("damaged"));
}

#[tokio::test]
async fn test_truncated_store_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = {
        let mut daemon = open(dir.path(), chain().mock(FIRST_EPOCH * SPE + 3)).await;
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
    let mut state = StoreState::started("test".into(), 100, root, balance, 4);
    let commitment = zkasper_common::acc::commitment(&root, balance);

    assert!(state
        .clone()
        .advance(102, root, commitment, balance, 4, None)
        .is_err());
    assert!(state
        .clone()
        .advance(100, root, commitment, balance, 4, None)
        .is_err());

    // A commitment that does not bind the root it is offered with is refused
    // even when the epoch is right.
    assert!(state
        .clone()
        .advance(101, root, [0u64; 4], balance, 4, None)
        .is_err());

    state
        .advance(101, root, commitment, balance, 4, None)
        .unwrap();
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
