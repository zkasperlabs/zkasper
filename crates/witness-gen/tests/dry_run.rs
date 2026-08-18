//! The dry run: the real `zkasperd`, against a beacon node that is not one.
//!
//! Everything else in this crate drives the orchestrator as a library, with the
//! beacon API replaced by a trait implementation. That leaves the binary itself
//! untested — its argument parsing, the chain it maps `--chain mainnet` onto,
//! the HTTP client, the JSON the client parses, and whether the whole thing
//! reaches a closed epoch without a hand on it. A month of continuous mainnet
//! proving starts with `zkasperd` being launched exactly once, so that is what
//! this launches.
//!
//! The chain is mainnet-shaped rather than tiny, because there is no way to tell
//! the binary otherwise: `--chain` takes `mainnet` or `gnosis` and there is no
//! config override. Thirty-two slots to an epoch, a depth-40 validators tree and
//! a depth-22 accumulator — all sparse, so what it costs is the twelve
//! validators rather than the four million the tree could hold.

mod common;

use common::mock_node::MockNode;
use common::stub_api::StubApi;
use common::SyntheticChain;

use serde_json::Value;

use zkasper_common::ChainConfig;

/// Twelve validators, one per slot, so 2/3 of the stake is in eight or nine of
/// them depending on where the balance drop has got to — partway through an
/// epoch that has thirty-two slots to spend.
const VALIDATORS: usize = 12;
const FIRST_EPOCH: u64 = 10;
const LAST_EPOCH: u64 = 13;
const SPE: u64 = ChainConfig::MAINNET.slots_per_epoch;

/// What a node on mainnet reports at `/eth/v1/beacon/genesis`. Twelve
/// validators and mainnet parameters do not make a run mainnet; this does.
const MAINNET_GENESIS_VALIDATORS_ROOT: [u8; 32] = [
    0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f, 0xdd, 0x4e,
    0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f, 0x51, 0x1b, 0xfe, 0x95,
];

#[tokio::test(flavor = "multi_thread")]
async fn test_the_daemon_follows_four_epochs_over_http() {
    // On mainnet's own genesis validators root, so this run is the one that is
    // allowed to publish `mainnet`. The companion test below is the same chain
    // on a root nothing recognises.
    let chain = SyntheticChain::new(ChainConfig::MAINNET, VALIDATORS, FIRST_EPOCH, LAST_EPOCH)
        .on_network(MAINNET_GENESIS_VALIDATORS_ROOT);
    let crossing = chain.slots_to_threshold(FIRST_EPOCH);
    assert!(
        crossing < VALIDATORS as u64,
        "the epoch has to have attesting slots left when the threshold crosses",
    );

    // The head sits one slot past the block that carries the last epoch over
    // 2/3, so every epoch of the run can be closed and the last one still has an
    // attestation the daemon held and did not need. A head at the end of the
    // epoch would not tell a trigger that fired early apart from one that ran
    // out of chain.
    let node = MockNode::spawn(
        &chain,
        LAST_EPOCH * SPE + chain.slots_to_threshold(LAST_EPOCH) + 1,
    )
    .await
    .expect("the mock node binds a port");
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");

    let run = daemon(&node, dir.path())
        .output()
        .await
        .expect("zkasperd runs");

    assert!(
        run.status.success(),
        "zkasperd exited with {}\n{}",
        run.status,
        transcript(&run),
    );

    let status: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("status.json")).expect("a manifest"))
            .expect("the manifest is JSON");

    // Bootstrapped where the node said it was finalized, and the accumulator
    // walked from there to the head one epoch diff at a time.
    assert_eq!(status["chain"], "mainnet", "{}", transcript(&run));
    assert_eq!(
        status["genesis_validators_root"],
        zkasper_witness_gen::artifacts::hex0x(&MAINNET_GENESIS_VALIDATORS_ROOT),
        "the label has to be published beside the root it was resolved from",
    );
    assert!(status["prover"]
        .as_str()
        .is_some_and(|prover| prover.starts_with("native")));
    assert_eq!(status["bootstrap_epoch"], FIRST_EPOCH);
    assert_eq!(status["accumulator"]["epoch"], LAST_EPOCH);
    assert_eq!(
        status["accumulator"]["total_active_balance"],
        chain.total_active_balance_at(LAST_EPOCH).to_string(),
        "the epoch diffs did not carry the balance change through",
    );
    assert!(out
        .join(format!("epoch-{FIRST_EPOCH:09}"))
        .join("bootstrap.bin")
        .exists());

    // Justified every epoch, and finalized every pair of consecutive ones.
    assert_eq!(status["justified_through"], LAST_EPOCH);
    assert_eq!(status["last_finalized"]["epoch"], LAST_EPOCH - 1);
    assert_eq!(
        status["last_finalized"]["root"],
        zkasper_witness_gen::artifacts::hex0x(&chain.checkpoint_root(LAST_EPOCH - 1)),
    );

    // The threshold fired partway through the epoch rather than at the end of
    // it. The first epoch after a bootstrap has nothing to finalize and goes
    // through the batch path, which proves one slot at a time — so its artifacts
    // are the record of where the daemon stopped counting.
    let first = out.join(format!("epoch-{FIRST_EPOCH:09}"));
    for slot in 0..SPE {
        assert_eq!(
            first
                .join(format!("slot_proof_{}.bin", FIRST_EPOCH * SPE + slot))
                .exists(),
            slot < crossing,
            "slot {slot} of epoch {FIRST_EPOCH} against a threshold at {crossing}",
        );
    }

    // And the epochs after it were closed by the streaming pipeline: one proof
    // over the attestation that crossed, with a measured latency behind it.
    for epoch in FIRST_EPOCH + 1..=LAST_EPOCH {
        assert!(
            out.join(format!("epoch-{epoch:09}"))
                .join("stream_final.bin")
                .exists(),
            "epoch {epoch} was not closed by a final proof",
        );
    }
    assert!(
        status["recent_stages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|stage| stage["stage"] == "stream_final"),
        "{}",
        transcript(&run),
    );
    let latency = &status["recent_latencies"][0];
    assert_eq!(latency["epoch"], FIRST_EPOCH + 1);
    assert_eq!(latency["tail"], 1, "one attestation on the critical path");
    assert!(
        latency["t2_minus_t_millis"].is_number(),
        "no measured T2 - T: {latency}",
    );
}

/// The daemon, pointed at the mock node, exactly as it will be pointed at a real
/// one. Only `--prover` changes when there is a GPU to prove on.
fn daemon(node: &MockNode, dir: &std::path::Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_zkasperd"));
    command
        .arg("--beacon-url")
        .arg(node.url())
        .arg("--db-path")
        .arg(dir.join("zkasperd.db"))
        .arg("--output-dir")
        .arg(dir.join("out"))
        .args(["--chain", "mainnet"])
        .args(["--prover", "native"])
        .args(["--mode", "streaming"])
        .args(["--no-gossip", "--once"]);
    command
}

/// What the daemon said, for a failure that would otherwise be a bare assert.
fn transcript(run: &std::process::Output) -> String {
    format!(
        "--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr),
    )
}

/// The same run again, this time publishing to an API.
///
/// This is the whole reason the dry run exists. On the day the GPU is rented the
/// only thing that changes is `--prover zisk --gpu`; everything the public
/// surface is made of — the events, their order, the measured `T2 - T`, the
/// manifest — has to have been produced by the real binary before then, and by
/// the real publishing path rather than by a test calling it directly.
#[tokio::test(flavor = "multi_thread")]
async fn test_the_daemon_publishes_the_whole_run() {
    // Left on the synthetic genesis validators root, which is the case this
    // test exists to pin: mainnet parameters and twelve validators publish as
    // `unrecognised`, because a flag cannot make a node mainnet.
    let chain = SyntheticChain::new(ChainConfig::MAINNET, VALIDATORS, FIRST_EPOCH, LAST_EPOCH);
    let node = MockNode::spawn(
        &chain,
        LAST_EPOCH * SPE + chain.slots_to_threshold(LAST_EPOCH) + 1,
    )
    .await
    .expect("the mock node binds a port");
    let api = StubApi::start().await;
    let dir = tempfile::tempdir().unwrap();

    let run = daemon(&node, dir.path())
        .args(["--prover-usd-per-hour", "0.51"])
        .args(["--api-url", &api.url()])
        .args(["--api-token", "dry-run"])
        .args(["--api-batch-millis", "100"])
        .args(["--api-progress-millis", "0"])
        .args(["--api-status-millis", "0"])
        .output()
        .await
        .expect("zkasperd runs");
    assert!(run.status.success(), "{}", transcript(&run));

    // The daemon exits without waiting for the API, so the last batch may still
    // be in flight when it does.
    api.wait_for(|api| {
        api.events()
            .iter()
            .any(|e| e["type"] == "epoch.closed" && e["epoch"] == LAST_EPOCH)
    })
    .await;

    let events = api.events();
    let kinds: Vec<&str> = events
        .iter()
        .map(|e| e["type"].as_str().expect("every event is typed"))
        .collect();
    for kind in [
        "epoch.opened",
        "stage.started",
        "stage.finished",
        "threshold.crossed",
        "threshold.fired",
        "proof.landed",
        "epoch.closed",
    ] {
        assert!(kinds.contains(&kind), "no {kind} in {kinds:?}");
    }
    assert!(
        events
            .windows(2)
            .all(|w| w[0]["seq"].as_u64() < w[1]["seq"].as_u64()),
        "the API must be able to order the run by sequence number alone",
    );
    assert!(
        events.iter().all(|e| e["unix_millis"].is_number()),
        "every event has to be placeable in time",
    );

    // Every stage the manifest recorded was also announced before it ran, so a
    // consumer can draw a proof in flight rather than only once it landed.
    let started: Vec<(&Value, &Value)> = events
        .iter()
        .filter(|e| e["type"] == "stage.started")
        .map(|e| (&e["epoch"], &e["stage"]))
        .collect();
    for finished in events.iter().filter(|e| e["type"] == "stage.finished") {
        assert!(
            started.contains(&(&finished["epoch"], &finished["stage"])),
            "{} at epoch {} finished without ever starting",
            finished["stage"],
            finished["epoch"],
        );
        assert!(
            finished["millis"].is_number(),
            "a finished stage has to carry what it cost: {finished}",
        );
    }

    // What the epoch cost the prover, which is the only input a price can be
    // built from. A native run proves nothing, so the milliseconds are zero and
    // the stage count is not: the point is that the fields are there and are
    // counted per epoch rather than derived downstream.
    let closed_epochs: Vec<&Value> = events
        .iter()
        .filter(|e| e["type"] == "epoch.closed")
        .collect();
    for closed in &closed_epochs {
        let summary = &closed["summary"];
        assert!(
            summary["stage_count"].as_u64().is_some_and(|n| n > 0),
            "an epoch closed without any stages: {summary}",
        );
        assert_eq!(
            summary["prover_millis_total"].as_u64(),
            Some(
                summary["prove_millis_total"]
                    .as_u64()
                    .expect("prove millis")
                    + summary["wrap_millis_total"].as_u64().expect("wrap millis")
            ),
            "prover time is proving and wrapping together: {summary}",
        );
    }

    // `T` and `T2`, in that order, with the latency the manifest measured.
    let closed = events
        .iter()
        .find(|e| e["type"] == "proof.landed" && e["epoch"] == FIRST_EPOCH + 1)
        .expect("the first streamed epoch landed a proof");
    assert_eq!(closed["proof"]["stage"], "stream_final");
    assert_eq!(
        closed["proof"]["available"], false,
        "a native run has no proof bytes, and must say so rather than imply some",
    );
    assert_eq!(closed["proof"]["program"], "zkasper-stream-final-guest");
    assert_eq!(
        closed["public_inputs"]["finalized_epoch"], FIRST_EPOCH,
        "the first streamed epoch finalizes the one the batch path justified",
    );
    assert!(closed["latency"]["t2_minus_t_millis"].is_number());
    assert!(
        closed["latency"]["threshold_unix_millis"].as_u64()
            <= closed["latency"]["proof_unix_millis"].as_u64(),
        "T2 cannot precede T: {}",
        closed["latency"],
    );

    // A witness-only run uploads nothing, because there is nothing to upload.
    assert!(
        !api.requests().iter().any(|r| r.path.contains("/proof/")),
        "a native run must not claim to have proof bytes",
    );

    // And the manifest went with it, so `/v1/status` has something to serve.
    let status = api
        .requests()
        .iter()
        .filter_map(|r| r.json().get("status").cloned())
        .rfind(|status| status.is_object())
        .expect("a status snapshot");
    assert_eq!(
        status["chain"], "unrecognised",
        "a synthetic node running mainnet parameters is not mainnet",
    );
    assert_eq!(
        status["prover_usd_per_hour"], 0.51,
        "the rate is a deployment fact, published as given",
    );
    assert_eq!(
        status["genesis_validators_root"],
        zkasper_witness_gen::artifacts::hex0x(&chain.genesis_validators_root),
    );
    assert_eq!(status["accumulator"]["epoch"], LAST_EPOCH);
    assert!(
        status["accumulator"]["total_active_balance"].is_string(),
        "balances are strings, or a JSON reader rounds mainnet's",
    );
}

/// The same run again, against the deployed API rather than a stub.
///
/// Ignored because it needs the network and the ingest token, and because it
/// wipes whatever the API is holding. Run it before pointing the daemon at a
/// real chain:
///
/// ```sh
/// ZKASPER_API_URL=https://api.zkasper.com \
/// ZKASPER_API_TOKEN=... \
/// cargo test --release --test dry_run -- --ignored --nocapture
/// ```
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_the_daemon_publishes_to_a_live_api() {
    let url = std::env::var("ZKASPER_API_URL").expect("ZKASPER_API_URL");
    let token = std::env::var("ZKASPER_API_TOKEN").expect("ZKASPER_API_TOKEN");
    let http = reqwest::Client::new();

    let reset = http
        .post(format!("{url}/v1/ingest/reset"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("reach the API");
    assert!(reset.status().is_success(), "reset: {}", reset.status());

    let chain = SyntheticChain::new(ChainConfig::MAINNET, VALIDATORS, FIRST_EPOCH, LAST_EPOCH);
    let node = MockNode::spawn(
        &chain,
        LAST_EPOCH * SPE + chain.slots_to_threshold(LAST_EPOCH) + 1,
    )
    .await
    .expect("the mock node binds a port");
    let dir = tempfile::tempdir().unwrap();

    let run = daemon(&node, dir.path())
        .args(["--api-url", &url])
        .args(["--api-token", &token])
        .args(["--api-batch-millis", "200"])
        .args(["--api-progress-millis", "0"])
        .args(["--api-status-millis", "0"])
        .args(["--api-daemon-id", "dry-run"])
        .output()
        .await
        .expect("zkasperd runs");
    assert!(run.status.success(), "{}", transcript(&run));

    // The daemon does not wait for the API on the way out, so give the last
    // batch the same second it would have had if the process kept running.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let status: Value = http
        .get(format!("{url}/v1/status"))
        .send()
        .await
        .expect("GET /v1/status")
        .json()
        .await
        .expect("status is JSON");
    assert_eq!(
        status["chain"], "unrecognised",
        "this run's node is synthetic, and the public API has to say so",
    );
    assert_eq!(status["accumulator"]["epoch"], LAST_EPOCH);
    assert_eq!(status["last_finalized"]["epoch"], LAST_EPOCH - 1);
    assert_eq!(status["service"]["stale"], false, "{status}");

    let epochs: Value = http
        .get(format!("{url}/v1/epochs?limit=10"))
        .send()
        .await
        .expect("GET /v1/epochs")
        .json()
        .await
        .expect("epochs are JSON");
    let listed = epochs["epochs"].as_array().expect("a list");
    assert_eq!(listed[0]["epoch"], LAST_EPOCH, "newest first: {epochs}");
    assert_eq!(listed[0]["status"], "proven");

    let detail: Value = http
        .get(format!("{url}/v1/epochs/{}", FIRST_EPOCH + 1))
        .send()
        .await
        .expect("GET /v1/epochs/{epoch}")
        .json()
        .await
        .expect("the epoch is JSON");
    assert_eq!(detail["latency"]["epoch"], FIRST_EPOCH + 1);
    assert!(detail["latency"]["t2_minus_t_millis"].is_number());
    assert_eq!(detail["public_inputs"]["finalized_epoch"], FIRST_EPOCH);
    assert_eq!(detail["verify"]["program"], "zkasper-stream-final-guest");
    assert!(
        detail["stages"]
            .as_array()
            .expect("stages")
            .iter()
            .any(|stage| stage["stage"] == "stream_final"),
        "{detail}",
    );

    // A native run has no bytes, and the API must not pretend otherwise.
    assert_eq!(
        http.get(format!("{url}/v1/proofs/{}", FIRST_EPOCH + 1))
            .send()
            .await
            .expect("GET /v1/proofs/{epoch}")
            .status(),
        reqwest::StatusCode::NOT_FOUND,
    );
}
