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

use zkasper_witness_gen::artifacts::EpochCost;
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
