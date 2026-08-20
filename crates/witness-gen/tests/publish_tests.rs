//! The publishing path, against an API that is up, then down, then back.
//!
//! What is being tested is not that a POST works. It is the property the whole
//! design rests on: an API that is unreachable costs the daemon nothing and
//! loses nothing. A proving service that stalls because its dashboard is down
//! has the dependency backwards.

use std::sync::Arc;
use std::time::Duration;

mod common;

use common::stub_api::StubApi;

use zkasper_common::types::{JustificationOutput, StreamFinalOutput};
use zkasper_witness_gen::artifacts::{EpochCost, VerifyAnchor};
use zkasper_witness_gen::prover::Stage;
use zkasper_witness_gen::publish::{ClosedEpoch, DaemonInfo, PublishConfig, Publisher};

fn publisher(url: &str, spool: &std::path::Path) -> Arc<Publisher> {
    Publisher::spawn(
        PublishConfig {
            batch_interval: Duration::from_millis(50),
            progress_interval: Duration::from_millis(0),
            status_interval: Duration::from_millis(0),
            ..PublishConfig::new(url, "test-token", spool.to_path_buf())
        },
        DaemonInfo {
            id: "zkasperd-test".into(),
            chain: "mainnet".into(),
            prover: "native".into(),
            pipeline: "streaming".into(),
        },
    )
    .expect("spawn the publisher")
}

/// The happy path: events arrive in order, authenticated, with the daemon that
/// produced them, and a proof arrives as bytes rather than as JSON.
#[tokio::test]
async fn publishes_events_and_proof_bytes() {
    let stub = StubApi::start().await;
    let spool = tempfile::tempdir().expect("tempdir");
    let publisher = publisher(&stub.url(), spool.path());

    publisher.epoch_opened(100, &[7u8; 32], 99, 32_000_000_000, serde_json::json!({}));
    publisher.stage_started(Stage::Group, 100, None, Some(0));
    publisher.threshold_crossed(100, 1_700_000_000_000, 22_000_000_000, 32_000_000_000);
    publisher.proof_bytes(100, Stage::StreamFinal, &[1, 2, 3, 4], &[9; 4], &[0xAB; 8]);

    assert!(
        stub.wait_for(
            |s| s.events().len() >= 3 && s.requests().iter().any(|r| r.path.contains("/proof/"))
        )
        .await,
        "the stub never saw the events and the proof",
    );

    let events = stub.events();
    let kinds: Vec<&str> = events.iter().map(|e| e["type"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        ["epoch.opened", "stage.started", "threshold.crossed"],
        "events must arrive in the order they happened",
    );
    assert!(
        events
            .windows(2)
            .all(|w| w[0]["seq"].as_u64() < w[1]["seq"].as_u64()),
        "sequence numbers must be strictly increasing",
    );
    assert_eq!(events[0]["epoch"], 100);
    assert_eq!(events[2]["attesting_pct"].as_f64().unwrap().round(), 69.0);

    let batch = stub
        .requests()
        .into_iter()
        .find(|r| r.path.ends_with("/v1/ingest"))
        .expect("an ingest batch");
    assert_eq!(batch.authorization, "Bearer test-token");
    assert_eq!(batch.json()["daemon"]["id"], "zkasperd-test");
    assert_eq!(batch.json()["daemon"]["chain"], "mainnet");

    let proof = stub
        .requests()
        .into_iter()
        .find(|r| r.path.contains("/proof/"))
        .expect("a proof upload");
    assert!(proof.path.ends_with("/v1/ingest/proof/100"));
    assert_eq!(proof.header("x-zkasper-stage"), Some("stream_final"));
    assert_eq!(
        proof.header("x-zkasper-program-vk"),
        Some("0x0900000000000000090000000000000009000000000000000900000000000000"),
    );
    assert_eq!(
        proof.header("x-zkasper-public-bytes"),
        Some("0xabababababababab")
    );
    assert_eq!(
        proof.body,
        [1u64, 2, 3, 4]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<u8>>(),
        "proof bytes are the u64 words, little-endian",
    );
}

/// The API goes away mid-epoch. The daemon must not notice, and nothing may be
/// lost: what could not be posted is spooled and sent when the API comes back,
/// still in order.
#[tokio::test]
async fn an_unreachable_api_costs_nothing_and_loses_nothing() {
    let stub = StubApi::start().await;
    let spool = tempfile::tempdir().expect("tempdir");
    let publisher = publisher(&stub.url(), spool.path());

    publisher.stage_started(Stage::Group, 200, None, Some(0));
    assert!(stub.wait_for(|s| !s.events().is_empty()).await, "warm up");

    stub.take_down();
    for index in 1..=5 {
        publisher.stage_started(Stage::Group, 200, None, Some(index));
    }
    // Publishing is fire-and-forget, so the only thing to wait on is the spool
    // filling — which is exactly the evidence that the daemon carried on.
    assert!(
        stub.wait_for(|_| spool
            .path()
            .read_dir()
            .expect("read spool")
            .any(|entry| entry.is_ok()))
            .await,
        "an unreachable API should leave batches on disk",
    );
    let counters = publisher.counters();
    assert!(counters.spooled > 0, "batches should have been spooled");
    assert_eq!(counters.dropped, 0, "nothing should have been dropped");

    stub.bring_up();
    assert!(
        stub.wait_for(|s| s.events().len() >= 6).await,
        "the spool should be drained once the API answers again: saw {}",
        stub.events().len(),
    );

    let indices: Vec<u64> = stub
        .events()
        .iter()
        .filter_map(|e| e["index"].as_u64())
        .collect();
    assert_eq!(indices, [0, 1, 2, 3, 4, 5], "backfill must preserve order");
    assert!(
        spool
            .path()
            .read_dir()
            .expect("read spool")
            .next()
            .is_none()
            || publisher.counters().pending == 0,
        "a drained spool should be empty",
    );
}

/// An epoch whose prover returned nothing must not be published as `proven`.
///
/// This is the fault the whole doctrine is about. A missing epoch is a hole and
/// a hole can be seen; an epoch that says `proven` over no bytes cannot be
/// checked by the consumer it lies to — they ask for the proof, get nothing,
/// and cannot tell a broken service from a mistake of their own. Mainnet 469538
/// and 469539 shipped exactly that on 2026-08-19, against provers that had
/// already exited: `status: "proven"`, `available: false`, `bytes: 0`.
///
/// Both directions are pinned, because a status hardcoded the other way would
/// pass half of this.
#[tokio::test]
async fn an_epoch_with_no_proof_is_not_published_as_proven() {
    let stub = StubApi::start().await;
    let spool = tempfile::tempdir().expect("tempdir");
    let publisher = publisher(&stub.url(), spool.path());

    for (epoch, words) in [(300u64, &[][..]), (301, &[1u64, 2, 3, 4][..])] {
        let proof = zkasper_witness_gen::publish::proof_ref(
            epoch,
            Stage::StreamFinal,
            words,
            &[9; 4],
            &[0xAB; 8],
            Some("0xelf"),
        );
        publisher.epoch_closed(&ClosedEpoch {
            epoch,
            cost: EpochCost::default(),
            target_root: "0x00".into(),
            finalizes_epoch: epoch - 1,
            justified: serde_json::Value::Null,
            finalized: serde_json::Value::Null,
            accumulator: serde_json::Value::Null,
            latency: None,
            proof,
            public_inputs: serde_json::Value::Null,
        });
    }

    assert!(
        stub.wait_for(|s| s.events().len() >= 2).await,
        "the stub never saw both epochs close",
    );
    let events = stub.events();
    let closed = |epoch: u64| {
        events
            .iter()
            .find(|e| e["type"] == "epoch.closed" && e["epoch"] == epoch)
            .unwrap_or_else(|| panic!("epoch {epoch} never closed"))
    };

    let unproven = closed(300);
    assert_eq!(
        unproven["summary"]["proof"]["bytes"], 0,
        "the fixture has to be the case under test: {unproven}",
    );
    assert_ne!(
        unproven["summary"]["status"], "proven",
        "an epoch with no proof bytes must never claim to be proven: {unproven}",
    );
    assert_eq!(unproven["summary"]["status"], "unproven");

    let proven = closed(301);
    assert_eq!(proven["summary"]["proof"]["bytes"], 32);
    assert_eq!(
        proven["summary"]["status"], "proven",
        "an epoch with proof bytes still has to say so: {proven}",
    );
}

/// A proof handed around on its own says what to check it against.
///
/// The `vadcop_final` root a proof must be proved under stopped being a
/// constant of the pinned Zisk release on 2026-08-19, when upstream rebuilt
/// v1.1.0-alpha in place and changed it. A verifier who installs the tag today
/// derives a different root and refuses every proof this project has published,
/// so the anchor has to travel with the proof rather than be looked up — and it
/// has to read exactly as the manifest's does, or a reader comparing the two
/// learns nothing from them agreeing.
#[test]
fn a_proof_carries_the_anchor_it_was_proved_under() {
    let proof = zkasper_witness_gen::publish::proof_ref(
        469368,
        Stage::StreamFinal,
        &[1u64, 2, 3, 4],
        &[9; 4],
        &[0xAB; 8],
        Some("0xelf"),
    );
    let manifest = serde_json::to_value(VerifyAnchor::compiled()).expect("the anchor serializes");
    for field in ["vadcop_final_vk", "zisk_version", "zkasper_commit"] {
        assert_eq!(
            proof[field], manifest[field],
            "{field} must render as the manifest renders it: {proof}",
        );
    }
    assert_eq!(
        proof["vadcop_final_vk"],
        zkasper_witness_gen::publish::vk_hex(&zkasper_common::recursion::VADCOP_FINAL_VK),
        "the anchor must be the root this binary proves under, not a configured one: {proof}",
    );
}

/// An epoch with no proof bytes still names the build that would have proved
/// it. The anchor is a fact about this binary, not about a proof landing.
#[test]
fn an_unproven_proof_still_carries_the_anchor() {
    let proof = zkasper_witness_gen::publish::proof_ref(
        469368,
        Stage::StreamFinal,
        &[],
        &[9; 4],
        &[0xAB; 8],
        None,
    );
    assert_eq!(proof["available"], false, "{proof}");
    assert_eq!(
        proof["vadcop_final_vk"],
        zkasper_witness_gen::publish::vk_hex(&zkasper_common::recursion::VADCOP_FINAL_VK),
        "{proof}",
    );
}

/// The decoded public inputs carry every field the circuit committed.
///
/// `public_inputs` is a convenience over `public_bytes`, and a convenience that
/// silently drops a field is worse than none: step 4 of "Verifying a proof"
/// tells a stranger to compare `public_inputs.program_vk` against the key they
/// pinned, and until 2026-08-20 that field was not there to compare. It is the
/// last 32 bytes of `public_bytes` either way, so the check here is that the
/// decoded form agrees with the encoded one rather than that it exists.
#[test]
fn decoded_public_inputs_name_the_program_the_bytes_commit_to() {
    let program_vk = [0x1122_3344_5566_7788u64, 2, 3, 4];
    let stream = StreamFinalOutput {
        accumulator_commitment: [1; 4],
        next_accumulator_commitment: [2; 4],
        finalized_epoch: 469_367,
        finalized_root: [3; 32],
        finalized_state_root: [4; 32],
        justified_epoch: 469_368,
        justified_root: [5; 32],
        program_vk,
    };
    let justification = JustificationOutput {
        accumulator_commitment: [1; 4],
        committee_root: [2; 4],
        target_epoch: 469_368,
        target_root: [5; 32],
        attesting_balance: 22_000_000_000,
        slots_mask: 0xFFFF,
        justified: true,
        program_vk,
    };

    let tail = |bytes: Vec<u8>| zkasper_witness_gen::artifacts::hex0x(&bytes[bytes.len() - 32..]);
    assert_eq!(
        zkasper_witness_gen::publish::stream_final_public_inputs(&stream)["program_vk"],
        tail(stream.public_bytes()),
        "a stream final proof's decoded claim must name the program its bytes commit to",
    );
    assert_eq!(
        zkasper_witness_gen::publish::justification_public_inputs(&justification)["program_vk"],
        tail(justification.public_bytes()),
        "a justification read on its own must name the program its bytes commit to",
    );
    assert_eq!(
        zkasper_witness_gen::publish::stream_final_public_inputs(&stream)["program_vk"],
        zkasper_witness_gen::publish::vk_hex(&program_vk),
        "and must render as `verify.program_vk` does, so the two compare directly",
    );
}
