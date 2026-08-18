//! The publishing path, against an API that is up, then down, then back.
//!
//! What is being tested is not that a POST works. It is the property the whole
//! design rests on: an API that is unreachable costs the daemon nothing and
//! loses nothing. A proving service that stalls because its dashboard is down
//! has the dependency backwards.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use zkasper_witness_gen::prover::Stage;
use zkasper_witness_gen::publish::{DaemonInfo, PublishConfig, Publisher};

/// One request the stub API received.
#[derive(Clone, Debug)]
struct Received {
    path: String,
    authorization: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Received {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("stub received JSON")
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// An API that can be taken away and given back.
#[derive(Clone)]
struct StubApi {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<Received>>>,
    up: Arc<Mutex<bool>>,
}

impl StubApi {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let stub = Self {
            addr: listener.local_addr().expect("addr"),
            received: Arc::new(Mutex::new(Vec::new())),
            up: Arc::new(Mutex::new(true)),
        };
        let serving = stub.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let serving = serving.clone();
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 8192];
                    // Read until the headers are complete, then until the body is.
                    let (head_end, length) = loop {
                        let read = match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        buffer.extend_from_slice(&chunk[..read]);
                        if let Some(at) = find(&buffer, b"\r\n\r\n") {
                            break (at + 4, content_length(&buffer[..at]));
                        }
                    };
                    while buffer.len() < head_end + length {
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                        }
                    }

                    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
                    let mut lines = head.lines();
                    let path = lines
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or_default()
                        .to_string();
                    let headers: Vec<(String, String)> = lines
                        .filter_map(|line| line.split_once(": "))
                        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
                        .collect();

                    let up = *serving.up.lock().unwrap();
                    if up {
                        serving.received.lock().unwrap().push(Received {
                            path,
                            authorization: headers
                                .iter()
                                .find(|(k, _)| k == "authorization")
                                .map(|(_, v)| v.clone())
                                .unwrap_or_default(),
                            headers,
                            body: buffer[head_end..head_end + length].to_vec(),
                        });
                    }
                    let status = if up {
                        "200 OK"
                    } else {
                        "503 Service Unavailable"
                    };
                    let _ = socket
                        .write_all(
                            format!(
                                "HTTP/1.1 {status}\r\ncontent-length: 15\r\n\
                                 content-type: application/json\r\n\r\n{{\"ok\":{up}}}     "
                            )
                            .as_bytes(),
                        )
                        .await;
                });
            }
        });
        stub
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn take_down(&self) {
        *self.up.lock().unwrap() = false;
    }

    fn bring_up(&self) {
        *self.up.lock().unwrap() = true;
    }

    fn requests(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }

    /// Every event the stub has been told about, in arrival order.
    fn events(&self) -> Vec<Value> {
        self.requests()
            .iter()
            .filter(|r| r.path.ends_with("/v1/ingest"))
            .flat_map(|r| {
                r.json()["events"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
            })
            .collect()
    }

    async fn wait_for(&self, predicate: impl Fn(&Self) -> bool) -> bool {
        for _ in 0..200 {
            if predicate(self) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn content_length(head: &[u8]) -> usize {
    String::from_utf8_lossy(head)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0)
}

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
