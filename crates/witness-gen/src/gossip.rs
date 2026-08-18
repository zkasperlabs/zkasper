//! Attestation gossip, over the beacon node's event stream.
//!
//! # Why not blocks
//!
//! An attestation is gossiped in the slot it is made and included in a block one
//! or more slots later, so a daemon reading
//! `/eth/v2/beacon/blocks/{id}/attestations` sees everything at least a slot
//! late. Mainnet epoch 430529 puts a number on it: 99.98% of a slot's attesters
//! are already in the very next block, so essentially the whole slot existed on
//! gossip while the slot was still running and the block only redelivered it
//! 12 s later.
//!
//! # What the stream carries
//!
//! Two topics, and since Electra they carry different halves of gossip:
//!
//! - `attestation` — every *aggregate* the node validated. Aggregates travel the
//!   global `beacon_aggregate_and_proof` topic, so a node sees them whatever it
//!   is subscribed to. Verified against Lighthouse v8.2.1, which registers this
//!   event from `verify_aggregated_attestation_for_gossip` at every fork, and
//!   from the unaggregated path only before Electra.
//! - `single_attestation` — every *unaggregated* attestation the node validated,
//!   which is only the subnets it subscribes to. It arrives an aggregation
//!   interval — a third of a slot — before the aggregate that carries it, which
//!   is why zkasperd requires a node subscribed to every subnet. See the
//!   operational requirements in README.md.
//!
//! Subscribing to both is therefore correct across the fork boundary.
//!
//! # Duplicates, order and gaps
//!
//! Nothing here deduplicates: the same validator appears in many aggregates and
//! again as a single, and [`crate::attestation_collector::SlotStream`] already
//! converges on a per-slot attester set out of overlapping arrivals. Order does
//! not matter for the same reason — a slot is a set, not a sequence.
//!
//! A dropped connection does matter: attestations gossiped while the stream was
//! down are never delivered. The source reconnects, reports the outage, and the
//! orchestrator repairs it from blocks, which is the one thing the block-sourced
//! path is still for.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::beacon_api::{
    parse_attestation_entry, parse_single_attestation_entry, AttestationResponse,
};

/// Where a streaming epoch's attestations come from.
///
/// The orchestrator only ever asks for "whatever arrived since last time", so a
/// forked node that exposes attestations earlier — or an in-process source that
/// skips the API altogether — drops in here without the pipeline changing.
pub trait AttestationSource: Send + Sync {
    /// Attestations seen since the last call, in arrival order.
    fn drain(&self) -> Vec<AttestationResponse>;

    /// Whether the node announced a reorg since the last call, consuming the
    /// flag. A reorg can move a checkpoint root out from under an epoch that is
    /// already being collected, so the orchestrator re-resolves the root when
    /// this reports one.
    fn took_reorg(&self) -> bool;

    /// Whether the source was disconnected since the last call, consuming the
    /// flag. Attestations gossiped during the outage were not delivered and have
    /// to be repaired from blocks.
    fn took_gap(&self) -> bool;

    /// Attestations delivered, reconnections paid for, and times the node
    /// admitted it threw events away. Published in the manifest so an operator
    /// can see the daemon is on gossip at all, and whether the feed was whole.
    fn counters(&self) -> Counters;
}

/// What a source has delivered and what it has lost.
#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    pub attestations: u64,
    pub reconnects: u64,
    /// Times the node said it dropped events. Anything but zero means its SSE
    /// channel is too small for the volume — see `--http-sse-capacity-multiplier`.
    pub dropped: u64,
}

#[derive(Default)]
struct Shared {
    inbox: Mutex<Vec<AttestationResponse>>,
    reorged: AtomicBool,
    gapped: AtomicBool,
    delivered: AtomicU64,
    reconnects: AtomicU64,
    dropped: AtomicU64,
}

/// The beacon node's `/eth/v1/events` stream, read by a task of its own.
///
/// Reading it on a task rather than on the tick is the point: an attestation
/// lands in the inbox the millisecond the node validates it, and the trigger
/// sees it at the next evaluation rather than at the next poll.
pub struct EventStreamSource {
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl EventStreamSource {
    /// Connect to `base_url`'s event stream and start collecting.
    ///
    /// Returns immediately; the first attestations land within a slot. The task
    /// reconnects on its own, so a node restart costs a gap and not a daemon.
    pub fn connect(base_url: &str) -> Self {
        let url = format!(
            "{}/eth/v1/events?topics=attestation,single_attestation,chain_reorg",
            base_url.trim_end_matches('/'),
        );
        let shared = Arc::new(Shared::default());
        let task = tokio::spawn(follow(url, shared.clone()));
        Self { shared, task }
    }
}

impl Drop for EventStreamSource {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl AttestationSource for EventStreamSource {
    fn drain(&self) -> Vec<AttestationResponse> {
        std::mem::take(&mut self.shared.inbox.lock().expect("gossip inbox"))
    }

    fn took_reorg(&self) -> bool {
        self.shared.reorged.swap(false, Ordering::Relaxed)
    }

    fn took_gap(&self) -> bool {
        self.shared.gapped.swap(false, Ordering::Relaxed)
    }

    fn counters(&self) -> Counters {
        Counters {
            attestations: self.shared.delivered.load(Ordering::Relaxed),
            reconnects: self.shared.reconnects.load(Ordering::Relaxed),
            dropped: self.shared.dropped.load(Ordering::Relaxed),
        }
    }
}

/// Hold the stream open for as long as the daemon runs.
async fn follow(url: String, shared: Arc<Shared>) {
    // No *request* timeout — the stream is meant to stay open for the life of
    // the process — but an idle one, because a connection that has silently died
    // is indistinguishable from a quiet node until something says so. A slot's
    // attestations arrive every slot, so half a minute of nothing is a dead
    // stream and worth reconnecting for.
    let client = reqwest::Client::builder()
        .read_timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("a default reqwest client");

    loop {
        match read(&client, &url, &shared).await {
            Ok(()) => warn!("the beacon node closed the attestation event stream"),
            Err(e) => warn!(error = %e, "attestation event stream failed"),
        }
        shared.gapped.store(true, Ordering::Relaxed);
        shared.reconnects.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// One connection's worth of events, until it ends or fails.
async fn read(client: &reqwest::Client, url: &str, shared: &Shared) -> Result<()> {
    let mut response = client
        .get(url)
        .header("Accept", "text/event-stream")
        .send()
        .await
        .context("open the event stream")?
        .error_for_status()
        .context("the node refused the event stream")?;

    info!("following attestation gossip");

    // SSE frames are separated by a blank line and can be split across chunks,
    // so the tail of a chunk is carried into the next one.
    let mut buffered = String::new();
    while let Some(chunk) = response.chunk().await.context("read the event stream")? {
        buffered.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(end) = buffered.find("\n\n") {
            let frame = buffered[..end].to_string();
            buffered.drain(..end + 2);
            ingest(&frame, shared);
        }
    }
    Ok(())
}

/// One SSE frame: an `event:` name and a `data:` payload, or a comment.
fn ingest(frame: &str, shared: &Shared) {
    let mut topic = "";
    let mut payload = "";
    for line in frame.lines() {
        match line.split_once(':') {
            Some(("event", rest)) => topic = rest.trim(),
            Some(("data", rest)) => payload = rest.trim(),
            // A comment. Most are keep-alives and empty, but this is also how
            // the node admits it threw attestations away, and it is the only
            // notice it gives: Lighthouse's per-topic broadcast channel holds
            // `--http-sse-capacity-multiplier` x 16 messages — sixteen by
            // default, against a slot's thirty thousand — and a consumer that
            // falls behind gets `Lagged(n)` rendered as this comment while the
            // events themselves are gone. Silently losing attestations would
            // make the feed quietly incomplete, so it counts as a gap and the
            // epoch is repaired from blocks.
            Some(("", rest)) if rest.contains("dropped") => {
                warn!(comment = rest.trim(), "the node dropped gossip events");
                shared.dropped.fetch_add(1, Ordering::Relaxed);
                shared.gapped.store(true, Ordering::Relaxed);
                return;
            }
            _ => {}
        }
    }
    if payload.is_empty() {
        return;
    }

    if topic == "chain_reorg" {
        info!(event = %payload, "the node reported a reorg");
        shared.reorged.store(true, Ordering::Relaxed);
        return;
    }

    let Ok(entry) = serde_json::from_str::<serde_json::Value>(payload) else {
        debug!(topic, "unparseable event payload");
        return;
    };
    match match topic {
        "attestation" => parse_attestation_entry(&entry),
        "single_attestation" => parse_single_attestation_entry(&entry),
        _ => return,
    } {
        Ok(attestation) => {
            shared.delivered.fetch_add(1, Ordering::Relaxed);
            shared.inbox.lock().expect("gossip inbox").push(attestation);
        }
        Err(e) => debug!(topic, error = %e, "could not read an attestation event"),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::beacon_api::SingleAttester;

    /// The two shapes a post-Electra Lighthouse publishes, captured verbatim
    /// from `/eth/v1/events` on a live v8.2.1 node.
    const AGGREGATE: &str = r#"event:attestation
data:{"aggregation_bits":"0x008201","data":{"slot":"6235","index":"0","beacon_block_root":"0xefacd1b12af6a75809c400936228760529dc26a949ff3616a4b17049c0d41e4f","source":{"epoch":"20","root":"0x1cbe918e95f005aa8e83403b04da2ee0555770e6d4df7b845763611bf852399a"},"target":{"epoch":"779","root":"0xefacd1b12af6a75809c400936228760529dc26a949ff3616a4b17049c0d41e4f"}},"signature":"0xacb1603dee1c0cba739983f565fbad298eb1c9c9ee52f7b3bdd23b97da2e24db32056d4622abb733cbeffa3cbcc314420d181115c468bd0625bebf9b82a0b5c27b54c7414f3ff775f7054e641ffc41f5c64cd026eca5ff2bb32408c4b93fe571","committee_bits":"0x01"}"#;

    pub const SINGLE_DATA: &str = r#"{"committee_index":"2","attester_index":"64","data":{"slot":"6206","index":"0","beacon_block_root":"0xefacd1b12af6a75809c400936228760529dc26a949ff3616a4b17049c0d41e4f","source":{"epoch":"20","root":"0x1cbe918e95f005aa8e83403b04da2ee0555770e6d4df7b845763611bf852399a"},"target":{"epoch":"775","root":"0xefacd1b12af6a75809c400936228760529dc26a949ff3616a4b17049c0d41e4f"}},"signature":"0x83065ff726df9665c4d3bd252ab1dd03444138d63d03d8fc5d9abaf2029c639fd0d3c546cb839ea80efa0ce3efccc3be0b8c13f964126a771fc52f4aceabb4fdcefbb4a1ddbcb19317155be9ba86432d6f14883658ec1f4c7671af38a77648de"}"#;

    /// The same, as the node frames it.
    fn single() -> String {
        format!("event:single_attestation\ndata:{SINGLE_DATA}")
    }

    #[test]
    fn both_electra_topics_are_read() {
        let shared = Shared::default();
        ingest(AGGREGATE, &shared);
        ingest(&single(), &shared);

        let inbox = shared.inbox.lock().unwrap();
        assert_eq!(inbox.len(), 2);
        assert_eq!(inbox[0].data_slot, 6235);
        assert_eq!(inbox[0].committee_bits, vec![0x01]);
        assert!(inbox[0].single_attester.is_none());
        assert_eq!(
            inbox[1].single_attester,
            Some(SingleAttester {
                committee_index: 2,
                attester_index: 64,
            }),
        );
    }

    /// A frame split across two chunks is one event, not two broken ones.
    #[test]
    fn a_frame_split_across_chunks_survives() {
        let shared = Shared::default();
        let whole = format!("{AGGREGATE}\n\n");
        let mut buffered = String::new();

        for chunk in [&whole[..whole.len() / 2], &whole[whole.len() / 2..]] {
            buffered.push_str(chunk);
            while let Some(end) = buffered.find("\n\n") {
                let frame = buffered[..end].to_string();
                buffered.drain(..end + 2);
                ingest(&frame, &shared);
            }
        }
        assert_eq!(shared.inbox.lock().unwrap().len(), 1);
    }

    /// The whole path over a socket: connect, read a body that never ends, and
    /// hand an attestation on. What this pins that the frame tests do not is
    /// that [`EventStreamSource`] speaks HTTP to something.
    #[tokio::test]
    async fn the_source_reads_attestations_off_a_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("the source connects");
            let _ = socket.read(&mut [0u8; 4096]).await;
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: text/event-stream\r\n\
                         Connection: close\r\n\r\n\
                         {AGGREGATE}\n\n{}\n\n",
                        single()
                    )
                    .as_bytes(),
                )
                .await
                .expect("the body is written");
            // Held open, because a beacon node's event stream does not end.
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });

        let source = EventStreamSource::connect(&format!("http://127.0.0.1:{port}"));
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        let attestations = loop {
            let attestations = source.drain();
            if !attestations.is_empty() || Instant::now() > deadline {
                break attestations;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };

        assert_eq!(attestations.len(), 2, "{:?}", source.counters());
        assert_eq!(attestations[0].data_slot, 6235);
        assert_eq!(attestations[1].data_slot, 6206);
    }

    /// Against a real node, which is the only thing that settles what the
    /// stream actually delivers.
    ///
    /// ```sh
    /// BEACON_API_URL=http://localhost:5052 \
    ///   cargo test --release -p zkasper-witness-gen gossip -- --ignored --nocapture
    /// ```
    ///
    /// Post-Electra a node publishes aggregates on `attestation` and
    /// unaggregated attestations on `single_attestation`, and a node that is not
    /// subscribed to every subnet will show far fewer of the latter than the
    /// former implies. That is what this prints.
    #[tokio::test]
    #[ignore]
    async fn the_stream_delivers_attestations_from_a_live_node() {
        let url = std::env::var("BEACON_API_URL").expect("BEACON_API_URL");
        let source = EventStreamSource::connect(&url);
        tokio::time::sleep(std::time::Duration::from_secs(24)).await;

        let attestations = source.drain();
        let counters = source.counters();
        let singles = attestations
            .iter()
            .filter(|a| a.single_attester.is_some())
            .count();
        eprintln!(
            "{} attestations in 24 s: {singles} single, {} aggregate, \
             {} reconnects, {} drops",
            counters.attestations,
            attestations.len() - singles,
            counters.reconnects,
            counters.dropped,
        );
        assert!(
            counters.attestations > 0,
            "the node published no attestations"
        );
        assert_eq!(counters.reconnects, 0, "the stream did not stay up");
        assert_eq!(counters.dropped, 0, "the node's SSE channel is too small");
    }

    #[test]
    fn a_reorg_raises_the_flag_and_carries_no_attestation() {
        let shared = Shared::default();
        ingest(
            "event:chain_reorg\ndata:{\"slot\":\"200\",\"depth\":\"2\",\"epoch\":\"6\"}",
            &shared,
        );
        assert!(shared.reorged.swap(false, Ordering::Relaxed));
        assert!(shared.inbox.lock().unwrap().is_empty());
    }
}

/// What the event stream costs at mainnet volume.
///
/// A mainnet slot is about 30,030 unaggregated attestations. These are ignored
/// because they are measurements rather than assertions; run them with
///
/// ```sh
/// cargo test --release -p zkasper-witness-gen throughput -- --ignored --nocapture
/// ```
#[cfg(test)]
mod throughput {
    use std::time::Instant;

    use super::tests::SINGLE_DATA;
    use super::*;

    /// Attesters in one mainnet slot's committee, measured on epoch 430529.
    const SLOT_ATTESTERS: usize = 30_030;

    /// One slot's worth of `single_attestation` frames, with the indices varied
    /// so that no parser can memoise them.
    fn a_slot_of_frames() -> String {
        let mut out = String::with_capacity(SLOT_ATTESTERS * 640);
        for i in 0..SLOT_ATTESTERS {
            out.push_str("event:single_attestation\ndata:");
            out.push_str(
                &SINGLE_DATA
                    .replace(
                        "\"attester_index\":\"64\"",
                        &format!("\"attester_index\":\"{i}\""),
                    )
                    .replace(
                        "\"committee_index\":\"2\"",
                        &format!("\"committee_index\":\"{}\"", i % 64),
                    ),
            );
            out.push_str("\n\n");
        }
        out
    }

    #[test]
    #[ignore]
    fn json_frames_cost_this_much_to_parse() {
        let frames = a_slot_of_frames();
        let shared = Shared::default();

        let started = Instant::now();
        let mut buffered = frames.as_str();
        while let Some(end) = buffered.find("\n\n") {
            ingest(&buffered[..end], &shared);
            buffered = &buffered[end + 2..];
        }
        let elapsed = started.elapsed().as_secs_f64();

        let delivered = shared.delivered.load(Ordering::Relaxed);
        assert_eq!(delivered as usize, SLOT_ATTESTERS);
        eprintln!(
            "JSON frame -> AttestationResponse: {delivered} in {elapsed:.3} s = \
             {:.0}/s, {:.2} MB of wire for the slot, {:.2} MB/s",
            delivered as f64 / elapsed,
            frames.len() as f64 / 1e6,
            frames.len() as f64 / 1e6 / elapsed,
        );
    }

    /// The same attestations as fixed-size SSZ, which is what a forked endpoint
    /// would emit. A `SingleAttestation` is 240 bytes: two indices, a 128-byte
    /// `AttestationData` and a 96-byte signature, all at fixed offsets.
    #[test]
    #[ignore]
    fn ssz_records_cost_this_much_to_decode() {
        const SSZ_LEN: usize = 240;
        // Pseudorandom, so that nothing the decoder copies can be folded away
        // as a constant and the checksum below has to be paid for.
        let mut seed = 0x243f_6a88_85a3_08d3u64;
        let wire: Vec<u8> = (0..SLOT_ATTESTERS * SSZ_LEN)
            .map(|_| {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                (seed >> 33) as u8
            })
            .collect();

        let started = Instant::now();
        let mut decoded = 0usize;
        for record in wire.chunks_exact(SSZ_LEN) {
            let read = |at: usize| u64::from_le_bytes(record[at..at + 8].try_into().unwrap());
            let mut root = [0u8; 32];
            root.copy_from_slice(&record[32..64]);
            let mut signature = [0u8; 96];
            signature.copy_from_slice(&record[144..240]);
            let attestation = AttestationResponse {
                aggregation_bits: Vec::new(),
                committee_bits: Vec::new(),
                single_attester: Some(crate::beacon_api::SingleAttester {
                    committee_index: read(0),
                    attester_index: read(8),
                }),
                data_slot: read(16),
                data_index: read(24),
                data_beacon_block_root: root,
                data_source_epoch: read(64),
                data_source_root: root,
                data_target_epoch: read(104),
                data_target_root: root,
                signature,
            };
            decoded = decoded
                .wrapping_add(attestation.signature[95] as usize)
                .wrapping_add(attestation.data_beacon_block_root[31] as usize)
                .wrapping_add(attestation.data_slot as usize)
                .wrapping_add(
                    attestation
                        .single_attester
                        .expect("a single")
                        .attester_index as usize,
                );
        }
        let elapsed = started.elapsed().as_secs_f64();

        assert_ne!(decoded, 0);
        eprintln!(
            "SSZ record -> AttestationResponse: {SLOT_ATTESTERS} in {elapsed:.5} s = \
             {:.0}/s, {:.2} MB of wire for the slot, {:.2} MB/s",
            SLOT_ATTESTERS as f64 / elapsed,
            wire.len() as f64 / 1e6,
            wire.len() as f64 / 1e6 / elapsed,
        );
    }

    /// End to end over a socket, which is the number that decides whether the
    /// stock endpoint can carry a slot: the server writes as fast as the kernel
    /// takes it, and the source parses on a task of its own.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn a_whole_slot_over_a_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let frames = a_slot_of_frames();
        let bytes = frames.len();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = socket.read(&mut [0u8; 4096]).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            socket.write_all(frames.as_bytes()).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        });

        let started = Instant::now();
        let source = EventStreamSource::connect(&format!("http://127.0.0.1:{port}"));
        let mut collected = 0usize;
        while collected < SLOT_ATTESTERS && started.elapsed().as_secs() < 60 {
            collected += source.drain().len();
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        let elapsed = started.elapsed().as_secs_f64();

        assert_eq!(collected, SLOT_ATTESTERS);
        eprintln!(
            "socket -> inbox: {collected} in {elapsed:.3} s = {:.0}/s, {:.2} MB/s \
             (a mainnet slot is {SLOT_ATTESTERS} in about a second of burst)",
            collected as f64 / elapsed,
            bytes as f64 / 1e6 / elapsed,
        );
    }

    /// What summing a slot's unaggregated signatures costs the host.
    ///
    /// This is the work the singles path adds and the network-aggregate path
    /// does not: one G2 decompression and one projective add per attestation.
    /// It is off-circuit and so free in proving terms, but it is not free in
    /// wall-clock, and it only stays off the critical path because the collector
    /// sums as gossip arrives rather than at close.
    #[test]
    #[ignore]
    fn summing_a_slot_of_signatures_costs_this_much() {
        use blst::min_pk::{AggregateSignature, SecretKey, Signature};

        let key = SecretKey::key_gen(&[7u8; 32], &[]).expect("a key");
        let compressed = key.sign(b"an attestation", b"", b"").to_bytes();

        let started = Instant::now();
        let mut running = AggregateSignature::from_signature(
            &Signature::from_bytes(&compressed).expect("decompress"),
        );
        for _ in 1..SLOT_ATTESTERS {
            let signature = Signature::from_bytes(&compressed).expect("decompress");
            running.add_signature(&signature, false).expect("add");
        }
        let elapsed = started.elapsed().as_secs_f64();

        assert_eq!(running.to_signature().to_bytes().len(), 96);
        eprintln!(
            "sum {SLOT_ATTESTERS} signatures: {elapsed:.3} s = {:.1} us each, \
             {:.1}% of a 12 s slot on one core",
            elapsed * 1e6 / SLOT_ATTESTERS as f64,
            elapsed / 12.0 * 100.0,
        );
    }
}
