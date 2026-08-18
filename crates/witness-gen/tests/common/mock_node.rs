//! A beacon node that speaks HTTP, so a test can drive the real `zkasperd`.
//!
//! [`super::MockBeaconApi`] stops short of the binary: it replaces
//! [`zkasper_witness_gen::beacon_api::BeaconApiClient`], so everything that
//! client does — the URLs it builds, the JSON it parses, the statuses it reads —
//! is exactly what a dry run against the daemon is supposed to exercise. This
//! serves the same synthetic chain over a socket instead.
//!
//! The server is a few dozen lines of `tokio::net` rather than a web framework:
//! the daemon only ever sends `GET`, the routes are known before the first
//! request, and a test dependency that has to be kept in step with the crate's
//! own is worse than the request line parser it saves.
//!
//! What is *not* served matters as much as what is. `/eth/v2/debug/beacon/
//! states/{id}` is absent, so the bootstrap 404s there and takes the synthetic
//! state-proof fallback — the same path `MockBeaconApi` takes by answering
//! `Ok(None)`. Slots with no block are absent too, so the daemon walks back over
//! them the way it does over a skipped slot on a real chain.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zkasper_witness_gen::artifacts::hex0x;
use zkasper_witness_gen::beacon_api::{
    AttestationResponse, CommitteeResponse, HeaderResponse, ValidatorResponse,
};

use super::{header_root, SyntheticChain};

const NOT_FOUND: &str = r#"{"code":404,"message":"Not found"}"#;
const NOT_ALLOWED: &str = r#"{"code":405,"message":"Method not allowed"}"#;

/// A beacon node listening on an ephemeral port, for the life of the test.
pub struct MockNode {
    port: u16,
    accepting: tokio::task::JoinHandle<()>,
}

impl Drop for MockNode {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

impl MockNode {
    /// Bind `127.0.0.1:0` and serve `chain` with the head at `head_slot`.
    pub async fn spawn(chain: &SyntheticChain, head_slot: u64) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let routes = Arc::new(routes(chain, head_slot));

        Ok(Self {
            port,
            accepting: tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(serve(stream, routes.clone()));
                }
            }),
        })
    }

    /// What to pass the daemon as `--beacon-url`.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

/// One connection, for as many requests as the client sends down it.
///
/// Keep-alive is worth the loop: the daemon makes a few hundred calls catching
/// up on four epochs and `reqwest` pools its connections, so a server that
/// answered one request per socket would spend the run in handshakes.
async fn serve(mut stream: TcpStream, routes: Arc<HashMap<String, String>>) {
    let mut buffered = Vec::new();
    while let Some(request) = read_request(&mut stream, &mut buffered).await {
        let mut words = request.split_whitespace();
        let method = words.next().unwrap_or_default();
        let target = words.next().unwrap_or_default();

        let (status, body) = if !matches!(method, "GET" | "HEAD") {
            ("405 Method Not Allowed", NOT_ALLOWED)
        } else if let Some(body) = routes.get(target) {
            ("200 OK", body.as_str())
        } else {
            ("404 Not Found", NOT_FOUND)
        };

        let head = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            body.len(),
        );
        if stream.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        if method != "HEAD" && stream.write_all(body.as_bytes()).await.is_err() {
            return;
        }
    }
}

/// Read one request line and its headers, leaving whatever followed them in
/// `buffered`. `None` once the client has hung up.
///
/// Only `GET` and `HEAD` are answered, and neither carries a body, so nothing
/// past the blank line belongs to this request.
async fn read_request(stream: &mut TcpStream, buffered: &mut Vec<u8>) -> Option<String> {
    loop {
        if let Some(end) = buffered.windows(4).position(|w| w == b"\r\n\r\n") {
            let request = String::from_utf8_lossy(&buffered[..end]).into_owned();
            buffered.drain(..end + 4);
            return Some(request);
        }
        let mut chunk = [0u8; 2048];
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(read) => buffered.extend_from_slice(&chunk[..read]),
        }
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// Every request the daemon can make of this chain, answered ahead of time.
///
/// Building the whole table up front is what makes 404 the default rather than a
/// case to remember: an endpoint the daemon must not find, and a slot that holds
/// no block, are both simply absent.
fn routes(chain: &SyntheticChain, head_slot: u64) -> HashMap<String, String> {
    let mut routes = HashMap::new();

    routes.insert(
        "/eth/v1/beacon/genesis".to_string(),
        json!({"data": {
            "genesis_time": "0",
            "genesis_validators_root": hex0x(&chain.genesis_validators_root),
            "genesis_fork_version": hex0x(&chain.fork_version),
        }})
        .to_string(),
    );
    routes.insert(
        "/eth/v1/beacon/headers/head".to_string(),
        header_json(&chain.header_at(head_slot)),
    );

    // The node's own view: it has finalized the first epoch of the run, which is
    // where a daemon given no `--bootstrap-slot` starts.
    let finalized = json!({
        "epoch": chain.first_epoch.to_string(),
        "root": hex0x(&chain.checkpoint_root(chain.first_epoch)),
    });
    routes.insert(
        "/eth/v1/beacon/states/head/finality_checkpoints".to_string(),
        json!({"execution_optimistic": false, "finalized": true, "data": {
            "previous_justified": finalized,
            "current_justified": finalized,
            "finalized": finalized,
        }})
        .to_string(),
    );

    for epoch in chain.epochs() {
        let boundary = epoch * chain.config.slots_per_epoch;
        let header = chain.header_at(boundary);
        let root = hex0x(&header_root(&header));

        routes.insert(
            format!("/eth/v1/beacon/states/{boundary}/validators"),
            validators_json(&chain.validators_at(epoch)),
        );
        routes.insert(
            format!("/eth/v1/beacon/states/{boundary}/committees?epoch={epoch}"),
            committees_json(&chain.committees_at(epoch)),
        );
        routes.insert(
            format!("/eth/v1/beacon/states/{boundary}/fork"),
            json!({"data": {
                "previous_version": hex0x(&chain.fork_version),
                "current_version": hex0x(&chain.fork_version),
                "epoch": "0",
            }})
            .to_string(),
        );
        routes.insert(
            format!("/eth/v1/beacon/blocks/{boundary}/root"),
            json!({"execution_optimistic": false, "finalized": true, "data": {"root": root}})
                .to_string(),
        );
        routes.insert(
            format!("/eth/v1/beacon/headers/{boundary}"),
            header_json(&header),
        );
        // Finalization looks the checkpoint's header up by its root, the way it
        // has to when the epoch's first slot holds no block.
        routes.insert(
            format!("/eth/v1/beacon/headers/{root}"),
            header_json(&header),
        );

        for index in 0..chain.keys.len() {
            routes.insert(
                format!(
                    "/eth/v2/beacon/blocks/{}/attestations",
                    boundary + index as u64 + 1,
                ),
                attestations_json(&[chain.attestation(epoch, index)]),
            );
        }
    }

    routes
}

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

fn validators_json(validators: &[ValidatorResponse]) -> String {
    json!({"execution_optimistic": false, "finalized": true, "data": validators
        .iter()
        .map(|v| json!({
            "index": v.index.to_string(),
            "balance": v.effective_balance.to_string(),
            "status": "active_ongoing",
            "validator": {
                "pubkey": hex0x(&v.pubkey),
                "withdrawal_credentials": hex0x(&v.withdrawal_credentials),
                "effective_balance": v.effective_balance.to_string(),
                "slashed": v.slashed,
                "activation_eligibility_epoch": v.activation_eligibility_epoch.to_string(),
                "activation_epoch": v.activation_epoch.to_string(),
                "exit_epoch": v.exit_epoch.to_string(),
                "withdrawable_epoch": v.withdrawable_epoch.to_string(),
            },
        }))
        .collect::<Vec<Value>>()})
    .to_string()
}

fn committees_json(committees: &[CommitteeResponse]) -> String {
    json!({"execution_optimistic": false, "finalized": true, "data": committees
        .iter()
        .map(|c| json!({
            "index": c.index.to_string(),
            "slot": c.slot.to_string(),
            "validators": c.validators.iter().map(u64::to_string).collect::<Vec<String>>(),
        }))
        .collect::<Vec<Value>>()})
    .to_string()
}

fn header_json(header: &HeaderResponse) -> String {
    json!({"execution_optimistic": false, "finalized": true, "data": {
        "root": hex0x(&header_root(header)),
        "canonical": true,
        "header": {
            "message": {
                "slot": header.slot.to_string(),
                "proposer_index": header.proposer_index.to_string(),
                "parent_root": hex0x(&header.parent_root),
                "state_root": hex0x(&header.state_root),
                "body_root": hex0x(&header.body_root),
            },
            "signature": hex0x(&[0u8; 96]),
        },
    }})
    .to_string()
}

/// One block's attestations, as a post-Electra node serves them: `data.index` is
/// pinned at zero and the committee an aggregate covers is named by
/// `committee_bits` instead.
fn attestations_json(attestations: &[AttestationResponse]) -> String {
    json!({"version": "fulu", "execution_optimistic": false, "finalized": true, "data": attestations
        .iter()
        .map(|a| json!({
            "aggregation_bits": hex0x(&a.aggregation_bits),
            "committee_bits": hex0x(&a.committee_bits),
            "signature": hex0x(&a.signature),
            "data": {
                "slot": a.data_slot.to_string(),
                "index": a.data_index.to_string(),
                "beacon_block_root": hex0x(&a.data_beacon_block_root),
                "source": {
                    "epoch": a.data_source_epoch.to_string(),
                    "root": hex0x(&a.data_source_root),
                },
                "target": {
                    "epoch": a.data_target_epoch.to_string(),
                    "root": hex0x(&a.data_target_root),
                },
            },
        }))
        .collect::<Vec<Value>>()})
    .to_string()
}
