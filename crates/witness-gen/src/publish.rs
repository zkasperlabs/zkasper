//! Publishing stages to the public API as they happen.
//!
//! The daemon is the source of truth and the API is a mirror of it, so nothing
//! here may ever hold a proof up. Events go into a bounded queue and a
//! background task posts them; an API that is slow, unreachable or wrong costs
//! the queue and nothing else. A batch that cannot be posted is spooled to disk
//! and drained later, which is also what backfills an outage across a restart —
//! the spool is read back on startup before anything new is sent.
//!
//! Ordering is preserved the only way that survives an outage: once anything is
//! spooled, everything is spooled until the spool is empty again. A consumer
//! therefore sees the pipeline in the order it happened, late rather than
//! reordered.
//!
//! What the queue is allowed to lose is bounded on both ends: the channel drops
//! the newest event when it is full, and the spool drops its oldest batch when
//! it is. Both are counted and reported, because a publisher that silently lost
//! half an epoch is worse than one that says so.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use zkasper_common::types::{FinalizationOutput, JustificationOutput, StreamFinalOutput};

use crate::artifacts::{
    hex0x, hex_digest, now_unix_millis, write_atomic, EpochCost, StageTiming, Status,
};
use crate::prover::Stage;

/// Zisk release the guests are built against. Pinned in the workspace manifest;
/// published so a verifier knows which prover produced a proof.
pub const ZISK_VERSION: &str = "v1.1.0-alpha";

/// Longest a single request may take before the daemon gives up and spools.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest to wait between attempts to drain the spool.
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(60);

/// How to reach the API.
#[derive(Clone, Debug)]
pub struct PublishConfig {
    /// Base URL, without a trailing `/v1`.
    pub url: String,
    pub token: String,
    /// Identifies this daemon to the API. Events are deduplicated per daemon.
    pub daemon_id: String,
    pub spool_dir: PathBuf,
    /// How long events accumulate before a batch is posted.
    pub batch_interval: Duration,
    /// Floor on the interval between `epoch.progress` events.
    pub progress_interval: Duration,
    /// Floor on the interval between status snapshots.
    pub status_interval: Duration,
    /// Events held in memory before the newest are dropped.
    pub queue_capacity: usize,
    /// Events in one POST.
    pub max_batch: usize,
    /// Batches held on disk before the oldest are dropped.
    pub spool_capacity: usize,
}

impl PublishConfig {
    pub fn new(url: impl Into<String>, token: impl Into<String>, spool_dir: PathBuf) -> Self {
        Self {
            url: url.into(),
            token: token.into(),
            daemon_id: "zkasperd".to_string(),
            spool_dir,
            batch_interval: Duration::from_millis(1000),
            progress_interval: Duration::from_millis(6000),
            status_interval: Duration::from_millis(10000),
            queue_capacity: 4096,
            max_batch: 256,
            spool_capacity: 4096,
        }
    }
}

/// Which daemon produced the events, and what it was built from.
#[derive(Clone, Debug)]
pub struct DaemonInfo {
    pub id: String,
    pub chain: String,
    pub prover: String,
    pub pipeline: String,
}

impl DaemonInfo {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "chain": self.chain,
            "prover": self.prover,
            "pipeline": self.pipeline,
            "version": env!("CARGO_PKG_VERSION"),
            "commit": option_env!("ZKASPER_COMMIT").unwrap_or("unknown"),
            "zisk_version": ZISK_VERSION,
        })
    }
}

/// What publishing has cost so far. Reported in the manifest so an operator can
/// see the mirror falling behind without reading the API.
#[derive(Clone, Copy, Debug, Default)]
pub struct PublishCounters {
    pub posted: u64,
    pub spooled: u64,
    pub dropped: u64,
    pub pending: u64,
}

/// A proof, on its way to the API.
struct ProofUpload {
    epoch: u64,
    stage: String,
    bytes: Vec<u8>,
    program_vk: String,
    public_bytes: String,
    sha256: String,
}

enum Message {
    Event(Value),
    Status(Box<Value>),
    Proof(Box<ProofUpload>),
    /// Post everything held, then answer. What a daemon on its way out waits
    /// for, so the last epoch of a run is published rather than lost with the
    /// runtime that was about to be dropped.
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// Hands events to the background task that posts them.
pub struct Publisher {
    tx: mpsc::Sender<Message>,
    /// Repeated onto every epoch, so an epoch row says which daemon and which
    /// prover produced it without a join against anything.
    daemon: DaemonInfo,
    /// Monotonic, and monotonic across restarts too: it starts from the wall
    /// clock, so a daemon that restarts cannot reuse a sequence number the API
    /// has already stored under a different event.
    seq: AtomicU64,
    counters: Arc<Counters>,
    last_status: AtomicU64,
    last_progress: AtomicU64,
    status_interval_millis: u64,
    progress_interval_millis: u64,
}

#[derive(Default)]
struct Counters {
    posted: AtomicU64,
    spooled: AtomicU64,
    dropped: AtomicU64,
    pending: AtomicU64,
}

impl Publisher {
    /// Start publishing. The spool is picked up before anything new is sent, so
    /// a daemon that restarts during an outage resumes where it stopped.
    pub fn spawn(config: PublishConfig, daemon: DaemonInfo) -> Result<Arc<Self>> {
        let (tx, rx) = mpsc::channel(config.queue_capacity);
        let counters = Arc::new(Counters::default());
        let publisher = Arc::new(Self {
            tx,
            daemon: daemon.clone(),
            seq: AtomicU64::new(now_unix_millis().saturating_mul(1000)),
            counters: counters.clone(),
            last_status: AtomicU64::new(0),
            last_progress: AtomicU64::new(0),
            status_interval_millis: config.status_interval.as_millis() as u64,
            progress_interval_millis: config.progress_interval.as_millis() as u64,
        });

        let spool = Spool::open(&config.spool_dir, config.spool_capacity, counters.clone())?;
        info!(
            url = %config.url,
            daemon = %daemon.id,
            pending = spool.len(),
            "publishing to the zkasper API",
        );
        tokio::spawn(post_loop(
            Client::new(&config, daemon)?,
            spool,
            rx,
            config.batch_interval,
            config.max_batch,
        ));
        Ok(publisher)
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Queue an event, or count it as dropped. Never blocks, never fails.
    fn send(&self, message: Message) {
        if self.tx.try_send(message).is_err() {
            let dropped = self.counters.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped.is_power_of_two() {
                warn!(dropped, "the publish queue is full; events are being lost");
            }
        }
    }

    fn event(&self, kind: &str, epoch: u64, mut data: Value) {
        let object = data.as_object_mut().expect("event payloads are objects");
        object.insert("type".into(), json!(kind));
        object.insert("seq".into(), json!(self.next_seq()));
        object.insert("unix_millis".into(), json!(now_unix_millis()));
        object.insert("epoch".into(), json!(epoch));
        self.send(Message::Event(data));
    }

    /// True at most once per `interval`, for events that would otherwise fire
    /// several times a second.
    fn due(&self, last: &AtomicU64, interval_millis: u64) -> bool {
        let now = now_unix_millis();
        let previous = last.load(Ordering::Relaxed);
        now.saturating_sub(previous) >= interval_millis
            && last
                .compare_exchange(previous, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }

    pub fn epoch_opened(
        &self,
        epoch: u64,
        target_root: &[u8; 32],
        finalizes_epoch: u64,
        total_active_balance: u64,
        accumulator: Value,
    ) {
        self.event(
            "epoch.opened",
            epoch,
            json!({
                "target_root": hex0x(target_root),
                "finalizes_epoch": finalizes_epoch,
                "total_active_balance": total_active_balance.to_string(),
                "accumulator": accumulator,
                "chain": self.daemon.chain,
                "pipeline": self.daemon.pipeline,
                "prover": self.daemon.prover,
                "opened_unix_millis": now_unix_millis(),
            }),
        );
    }

    /// The weight climbing towards the threshold, at most once per progress
    /// interval — the events are cheap but the API's row budget is not.
    pub fn epoch_progress(&self, progress: &EpochProgress) {
        if !self.due(&self.last_progress, self.progress_interval_millis) {
            return;
        }
        self.event(
            "epoch.progress",
            progress.epoch,
            json!({
                "attesting_balance": progress.attesting_balance.to_string(),
                "total_active_balance": progress.total_active_balance.to_string(),
                "attesting_pct": percent(progress.attesting_balance, progress.total_active_balance),
                "threshold_pct": progress.threshold_pct,
                "folded_groups": progress.folded_groups,
                "slots_held": progress.slots_held,
                "head_slot": progress.head_slot,
            }),
        );
    }

    pub fn stage_started(&self, stage: Stage, epoch: u64, slot: Option<u64>, index: Option<usize>) {
        self.event(
            "stage.started",
            epoch,
            json!({ "stage": stage.as_str(), "slot": slot, "index": index }),
        );
    }

    pub fn stage_finished(&self, timing: &StageTiming) {
        self.event(
            "stage.finished",
            timing.epoch,
            json!({
                "stage": timing.stage,
                "slot": timing.slot,
                "index": timing.index,
                "millis": timing.millis,
                "prove_millis": timing.prove_millis,
                "wrap_millis": timing.wrap_millis,
                "witness": timing.artifact,
                "proof_bytes": timing.proof_bytes,
            }),
        );
    }

    pub fn threshold_crossed(
        &self,
        epoch: u64,
        threshold_unix_millis: u64,
        attesting_balance: u64,
        total_active_balance: u64,
    ) {
        self.event(
            "threshold.crossed",
            epoch,
            json!({
                "threshold_unix_millis": threshold_unix_millis,
                "attesting_balance": attesting_balance.to_string(),
                "total_active_balance": total_active_balance.to_string(),
                "attesting_pct": percent(attesting_balance, total_active_balance),
            }),
        );
    }

    pub fn threshold_fired(
        &self,
        epoch: u64,
        fired_unix_millis: u64,
        wait_millis: u64,
        tail: usize,
        tail_named: usize,
        late_groups: usize,
    ) {
        self.event(
            "threshold.fired",
            epoch,
            json!({
                "fired_unix_millis": fired_unix_millis,
                "wait_millis": wait_millis,
                "tail": tail,
                "tail_named": tail_named,
                "late_groups": late_groups,
            }),
        );
    }

    /// `T2`: a proof of the epoch exists. Carries everything a consumer needs to
    /// know what was proven; the bytes themselves follow on their own path.
    pub fn proof_landed(
        &self,
        epoch: u64,
        proof: Value,
        public_inputs: Value,
        latency: Option<Value>,
    ) {
        self.event(
            "proof.landed",
            epoch,
            json!({ "proof": proof, "public_inputs": public_inputs, "latency": latency }),
        );
    }

    /// The epoch is finished and on disk. Everything the API needs to index it
    /// is here, because the API is forbidden to derive any of it.
    pub fn epoch_closed(&self, closed: &ClosedEpoch) {
        self.event(
            "epoch.closed",
            closed.epoch,
            json!({
                "summary": {
                    "epoch": closed.epoch,
                    "status": "proven",
                    "chain": self.daemon.chain,
                    "pipeline": self.daemon.pipeline,
                    "prover": self.daemon.prover,
                    "target_root": closed.target_root,
                    "finalizes_epoch": closed.finalizes_epoch,
                    "closed_unix_millis": now_unix_millis(),
                    "justified": closed.justified,
                    "finalized": closed.finalized,
                    "accumulator": closed.accumulator,
                    "latency": closed.latency,
                    "proof": closed.proof,
                    "public_inputs": closed.public_inputs,
                    "stage_count": closed.cost.stage_count,
                    "prove_millis_total": closed.cost.prove_millis,
                    "wrap_millis_total": closed.cost.wrap_millis,
                    "prover_millis_total": closed.cost.prover_millis(),
                },
            }),
        );
    }

    pub fn epoch_abandoned(&self, epoch: u64, reason: &str) {
        self.event("epoch.abandoned", epoch, json!({ "reason": reason }));
    }

    /// The whole manifest, at most once per status interval. The API turns it
    /// into `/v1/status` and a `status` event.
    pub fn status(&self, status: &Status) {
        if !self.due(&self.last_status, self.status_interval_millis) {
            return;
        }
        match serde_json::to_value(status) {
            Ok(value) => self.send(Message::Status(Box::new(value))),
            Err(e) => warn!(error = %e, "could not serialize the status manifest"),
        }
    }

    /// Force the next `status` call to publish, whatever the interval says.
    pub fn status_now(&self, status: &Status) {
        self.last_status.store(0, Ordering::Relaxed);
        self.status(status);
    }

    /// The proof bytes, as the u64 words the prover produced, little-endian.
    ///
    /// A witness-only run has no words and uploads nothing; the epoch is still
    /// published, with a proof that says it is not available.
    pub fn proof_bytes(
        &self,
        epoch: u64,
        stage: Stage,
        words: &[u64],
        program_vk: &[u64; 4],
        public_bytes: &[u8],
    ) {
        if words.is_empty() {
            return;
        }
        let bytes = proof_to_bytes(words);
        self.send(Message::Proof(Box::new(ProofUpload {
            epoch,
            stage: stage.as_str().to_string(),
            sha256: hex0x(Sha256::digest(&bytes).as_slice()),
            bytes,
            program_vk: vk_hex(program_vk),
            public_bytes: hex0x(public_bytes),
        })));
    }

    /// Wait for everything queued to be posted or spooled.
    ///
    /// Only worth calling on the way out: publishing is fire-and-forget by
    /// design, and a caller that awaits it per event has put the API back on
    /// the critical path.
    pub async fn flush(&self) {
        let (ack, wait) = tokio::sync::oneshot::channel();
        if self.tx.send(Message::Flush(ack)).await.is_ok() {
            let _ = wait.await;
        }
    }

    pub fn counters(&self) -> PublishCounters {
        PublishCounters {
            posted: self.counters.posted.load(Ordering::Relaxed),
            spooled: self.counters.spooled.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
            pending: self.counters.pending.load(Ordering::Relaxed),
        }
    }
}

/// How far an epoch in flight has got.
pub struct EpochProgress {
    pub epoch: u64,
    pub attesting_balance: u64,
    pub total_active_balance: u64,
    pub threshold_pct: f64,
    pub folded_groups: usize,
    pub slots_held: usize,
    pub head_slot: u64,
}

/// An epoch that finished, as the API stores it.
pub struct ClosedEpoch {
    pub epoch: u64,
    /// What the prover spent on this epoch. Published as three numbers rather
    /// than a price: a reader multiplies by whatever an hour costs them.
    pub cost: EpochCost,
    pub target_root: String,
    pub finalizes_epoch: u64,
    pub justified: Value,
    pub finalized: Value,
    pub accumulator: Value,
    pub latency: Option<Value>,
    pub proof: Value,
    pub public_inputs: Value,
}

/// What is published about a proof, apart from its bytes.
///
/// `available` is false for a witness-only run: the timings are real, there is
/// simply nothing to verify. Everything else is what a verifier binds the proof
/// to — the program that produced it and the bytes it committed.
pub fn proof_ref(
    epoch: u64,
    stage: Stage,
    words: &[u64],
    program_vk: &[u64; 4],
    public_bytes: &[u8],
    elf_sha256: Option<&str>,
) -> Value {
    let bytes = proof_to_bytes(words);
    json!({
        "stage": stage.as_str(),
        "available": !words.is_empty(),
        "bytes": bytes.len(),
        "words": words.len(),
        "sha256": (!bytes.is_empty()).then(|| hex0x(Sha256::digest(&bytes).as_slice())),
        "program": stage.guest(),
        "program_vk": vk_hex(program_vk),
        "elf_sha256": elf_sha256,
        "public_bytes": hex0x(public_bytes),
        "url": format!("/v1/proofs/{epoch}"),
    })
}

/// The claim a streaming final proof makes, decoded.
pub fn stream_final_public_inputs(output: &StreamFinalOutput) -> Value {
    json!({
        "accumulator_commitment": hex_digest(&output.accumulator_commitment),
        "next_accumulator_commitment": hex_digest(&output.next_accumulator_commitment),
        "finalized_epoch": output.finalized_epoch,
        "finalized_root": hex0x(&output.finalized_root),
        "finalized_state_root": hex0x(&output.finalized_state_root),
        "justified_epoch": output.justified_epoch,
        "justified_root": hex0x(&output.justified_root),
    })
}

/// The claim a batch justification makes on its own, for the one epoch of a run
/// that has nothing before it to finalize.
pub fn justification_public_inputs(output: &JustificationOutput) -> Value {
    json!({
        "accumulator_commitment": hex_digest(&output.accumulator_commitment),
        "justified_epoch": output.target_epoch,
        "justified_root": hex0x(&output.target_root),
    })
}

/// The same, for the batch pipeline's finalization proof.
pub fn finalization_public_inputs(output: &FinalizationOutput) -> Value {
    json!({
        "accumulator_commitment": hex_digest(&output.accumulator_commitment),
        "finalized_epoch": output.finalized_epoch,
        "finalized_root": hex0x(&output.finalized_root),
        "finalized_state_root": hex0x(&output.finalized_state_root),
    })
}

/// The u64 words a proof is made of, little-endian, 8 bytes each.
pub fn proof_to_bytes(words: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(words.len() * 8);
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// A program verification key as the 32 bytes its four words make.
pub fn vk_hex(vk: &[u64; 4]) -> String {
    hex0x(&proof_to_bytes(vk))
}

fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    part as f64 * 100.0 / whole as f64
}

// ---------------------------------------------------------------------------
// The posting task
// ---------------------------------------------------------------------------

struct Client {
    http: reqwest::Client,
    ingest_url: String,
    proof_url: String,
    token: String,
    daemon: Value,
}

impl Client {
    fn new(config: &PublishConfig, daemon: DaemonInfo) -> Result<Self> {
        let base = config.url.trim_end_matches('/').to_string();
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .context("build the publishing HTTP client")?,
            ingest_url: format!("{base}/v1/ingest"),
            proof_url: format!("{base}/v1/ingest/proof"),
            token: config.token.clone(),
            daemon: daemon.to_json(),
        })
    }

    fn batch(&self, events: Vec<Value>, status: Option<Value>) -> Value {
        json!({ "daemon": self.daemon, "events": events, "status": status })
    }

    async fn post_batch(&self, body: &Value) -> bool {
        match self
            .http
            .post(&self.ingest_url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => true,
            Ok(response) => {
                warn!(status = %response.status(), "the API rejected an ingest batch");
                // A 4xx is the daemon's fault and will not fix itself, so it is
                // dropped rather than spooled forever. Anything else is the
                // API's, and is worth keeping.
                response.status().is_client_error()
            }
            Err(e) => {
                debug!(error = %e, "could not reach the API");
                false
            }
        }
    }

    async fn post_proof(&self, upload: &ProofUpload) -> bool {
        match self
            .http
            .post(format!("{}/{}", self.proof_url, upload.epoch))
            .bearer_auth(&self.token)
            .header("content-type", "application/octet-stream")
            .header("x-zkasper-stage", &upload.stage)
            .header("x-zkasper-program-vk", &upload.program_vk)
            .header("x-zkasper-public-bytes", &upload.public_bytes)
            .header("x-zkasper-sha256", &upload.sha256)
            .body(upload.bytes.clone())
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                info!(
                    epoch = upload.epoch,
                    bytes = upload.bytes.len(),
                    "published the proof",
                );
                true
            }
            Ok(response) => {
                warn!(
                    epoch = upload.epoch,
                    status = %response.status(),
                    "the API rejected a proof",
                );
                response.status().is_client_error()
            }
            Err(e) => {
                debug!(epoch = upload.epoch, error = %e, "could not upload a proof");
                false
            }
        }
    }
}

async fn post_loop(
    client: Client,
    mut spool: Spool,
    mut rx: mpsc::Receiver<Message>,
    batch_interval: Duration,
    max_batch: usize,
) {
    let mut events: Vec<Value> = Vec::new();
    let mut status: Option<Value> = None;
    let mut backoff = batch_interval;
    let mut next_drain = tokio::time::Instant::now();
    let mut deadline = tokio::time::Instant::now() + batch_interval;

    loop {
        tokio::select! {
            message = rx.recv() => match message {
                Some(Message::Event(event)) => events.push(event),
                Some(Message::Status(value)) => status = Some(*value),
                Some(Message::Proof(upload)) => {
                    if !spool.is_empty() || !client.post_proof(&upload).await {
                        spool.push_proof(&upload);
                    } else {
                        spool.counters.posted.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Some(Message::Flush(ack)) => {
                    flush(&client, &mut spool, &mut events, &mut status).await;
                    if !spool.is_empty() {
                        drain(&client, &mut spool).await;
                    }
                    let _ = ack.send(());
                }
                None => break,
            },
            _ = tokio::time::sleep_until(deadline) => {
                flush(&client, &mut spool, &mut events, &mut status).await;
                deadline = tokio::time::Instant::now() + batch_interval;
            }
        }

        if events.len() >= max_batch {
            flush(&client, &mut spool, &mut events, &mut status).await;
        }

        if tokio::time::Instant::now() >= next_drain && !spool.is_empty() {
            let drained = drain(&client, &mut spool).await;
            backoff = if drained {
                batch_interval
            } else {
                (backoff * 2).min(MAX_RETRY_BACKOFF)
            };
            next_drain = tokio::time::Instant::now() + backoff;
        }
    }

    flush(&client, &mut spool, &mut events, &mut status).await;
}

/// Post what has accumulated, or spool it.
///
/// Anything already spooled goes first: a batch that jumped the queue would
/// publish an epoch's end before its middle.
async fn flush(
    client: &Client,
    spool: &mut Spool,
    events: &mut Vec<Value>,
    status: &mut Option<Value>,
) {
    if events.is_empty() && status.is_none() {
        return;
    }
    let body = client.batch(std::mem::take(events), status.take());
    if !spool.is_empty() || !client.post_batch(&body).await {
        spool.push_batch(&body);
    } else {
        spool.counters.posted.fetch_add(1, Ordering::Relaxed);
    }
}

/// Send what is on disk, oldest first. Stops at the first failure so ordering
/// survives; returns whether everything went.
async fn drain(client: &Client, spool: &mut Spool) -> bool {
    while let Some(entry) = spool.front() {
        let sent = match &entry {
            SpoolEntry::Batch(path) => match std::fs::read(path) {
                Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                    Ok(body) => client.post_batch(&body).await,
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "dropping a damaged spool file");
                        true
                    }
                },
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "dropping an unreadable spool file");
                    true
                }
            },
            SpoolEntry::Proof(path) => match spool.read_proof(path) {
                Ok(upload) => client.post_proof(&upload).await,
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "dropping a damaged spooled proof");
                    true
                }
            },
        };
        if !sent {
            return false;
        }
        spool.pop();
        spool.counters.posted.fetch_add(1, Ordering::Relaxed);
    }
    true
}

// ---------------------------------------------------------------------------
// The spool
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum SpoolEntry {
    Batch(PathBuf),
    Proof(PathBuf),
}

/// Batches and proofs waiting on disk for an API that is not answering.
struct Spool {
    dir: PathBuf,
    queue: VecDeque<SpoolEntry>,
    capacity: usize,
    counters: Arc<Counters>,
    written: u64,
}

impl Spool {
    fn open(dir: &Path, capacity: usize, counters: Arc<Counters>) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create the publish spool at {}", dir.display()))?;
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .with_context(|| format!("read the publish spool at {}", dir.display()))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                path.extension().and_then(|e| e.to_str()) == Some("json")
                    && !path.to_string_lossy().ends_with(".tmp")
            })
            .collect();
        entries.sort();

        let mut spool = Self {
            dir: dir.to_path_buf(),
            queue: VecDeque::new(),
            capacity,
            counters,
            written: 0,
        };
        for path in entries {
            spool.queue.push_back(match is_proof(&path) {
                true => SpoolEntry::Proof(path),
                false => SpoolEntry::Batch(path),
            });
        }
        spool.update_pending();
        Ok(spool)
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn front(&self) -> Option<SpoolEntry> {
        self.queue.front().cloned()
    }

    fn pop(&mut self) {
        if let Some(entry) = self.queue.pop_front() {
            match entry {
                SpoolEntry::Batch(path) => {
                    let _ = std::fs::remove_file(path);
                }
                SpoolEntry::Proof(path) => {
                    let _ = std::fs::remove_file(path.with_extension("bin"));
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        self.update_pending();
    }

    /// Make room, dropping the oldest. A spool that has hit its cap has been
    /// down long enough that the newest events are the ones worth keeping.
    fn evict(&mut self) {
        while self.queue.len() >= self.capacity {
            self.pop();
            let dropped = self.counters.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped.is_power_of_two() {
                warn!(
                    dropped,
                    "the publish spool is full; the oldest batches are being dropped"
                );
            }
        }
    }

    fn name(&mut self, suffix: &str) -> PathBuf {
        self.written += 1;
        self.dir.join(format!(
            "{:013}-{:06}-{suffix}.json",
            now_unix_millis(),
            self.written,
        ))
    }

    fn push_batch(&mut self, body: &Value) {
        self.evict();
        let path = self.name("batch");
        match serde_json::to_vec(body).map_err(anyhow::Error::from) {
            Ok(bytes) => match write_atomic(&path, &bytes) {
                Ok(()) => {
                    self.queue.push_back(SpoolEntry::Batch(path));
                    self.counters.spooled.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => warn!(error = %e, "could not spool an ingest batch"),
            },
            Err(e) => warn!(error = %e, "could not serialize an ingest batch"),
        }
        self.update_pending();
    }

    fn push_proof(&mut self, upload: &ProofUpload) {
        self.evict();
        let path = self.name("proof");
        let header = json!({
            "epoch": upload.epoch,
            "stage": upload.stage,
            "program_vk": upload.program_vk,
            "public_bytes": upload.public_bytes,
            "sha256": upload.sha256,
        });
        if let Err(e) = write_atomic(&path.with_extension("bin"), &upload.bytes)
            .and_then(|()| write_atomic(&path, &serde_json::to_vec(&header)?))
        {
            warn!(epoch = upload.epoch, error = %e, "could not spool a proof");
            self.update_pending();
            return;
        }
        self.queue.push_back(SpoolEntry::Proof(path));
        self.counters.spooled.fetch_add(1, Ordering::Relaxed);
        self.update_pending();
    }

    fn read_proof(&self, path: &Path) -> Result<ProofUpload> {
        let header: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        let field = |name: &str| -> Result<String> {
            header[name]
                .as_str()
                .map(str::to_string)
                .with_context(|| format!("spooled proof has no {name}"))
        };
        Ok(ProofUpload {
            epoch: header["epoch"]
                .as_u64()
                .context("spooled proof has no epoch")?,
            stage: field("stage")?,
            bytes: std::fs::read(path.with_extension("bin"))?,
            program_vk: field("program_vk")?,
            public_bytes: field("public_bytes")?,
            sha256: field("sha256")?,
        })
    }

    fn update_pending(&self) {
        self.counters
            .pending
            .store(self.queue.len() as u64, Ordering::Relaxed);
    }
}

fn is_proof(path: &Path) -> bool {
    path.file_stem()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.ends_with("-proof"))
}
