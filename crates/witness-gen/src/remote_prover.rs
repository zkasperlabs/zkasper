//! Proving over the network.
//!
//! [`docs/architecture.md`](../../../docs/architecture.md) settles the topology:
//! the beacon node and `zkasperd` run on a stable machine, and the rented GPU
//! box runs a prover server and nothing else. This module is both ends of the
//! link between them — [`RemoteProver`], which implements [`Prover`] by asking
//! another process, and [`serve`], which answers.
//!
//! # Why the split is cheap
//!
//! Complement proving shrank the witnesses that sit on the critical path. A
//! group-proof witness is **728 bytes** and a stream-final witness **2,671
//! bytes**, against a stage floor of 3.640 s. Moving those over a socket costs
//! nothing that can be measured next to the proof they ask for. The one large
//! witness is the committee proof at about **115 MB**, and that proof has a full
//! epoch of lead time.
//!
//! # What the client computes and what it asks for
//!
//! The client runs the guest logic natively — exactly what a witness-only daemon
//! does — and asks the server only for the cryptography. So the public outputs
//! the orchestrator advances the accumulator on never come off the wire, an
//! unprovable witness is still caught where it is generated, and the proof that
//! comes back is checked with [`verify_child`] against the key the handshake
//! reported and the publics the local circuit committed. A server that returned
//! a proof of another program, or of different outputs, is caught by the client.
//!
//! # One connection, one proof at a time
//!
//! `proofman` serialises proof generation on one mutex, so a server proves one
//! thing at a time however many clients it has. The client therefore holds one
//! connection under a mutex and does not pipeline. Concurrency needs more
//! servers, and — because a warm GPU prover sizes its buffers to the free memory
//! of the card — more cards.
//!
//! # When the server disappears
//!
//! Failure behaviour matters more than throughput here. The daemon must keep
//! generating witnesses through an outage, and a dropped connection mid-epoch
//! must cost that epoch and not the process.
//!
//! - Verification keys are cached from the handshake, so [`Prover::program_vk`]
//!   keeps answering while the server is unreachable. It has to: the trait makes
//!   it infallible, and the witness builders bind it.
//! - A request that fails is retried once on a fresh connection, because a
//!   connection idle since the last epoch is usually discovered dead by the
//!   write that follows.
//! - A request that still fails spools the witness to disk and returns **the
//!   empty proof a witness-only run returns**. The daemon carries on: it holds
//!   the outputs its own circuits computed, so the accumulator still advances
//!   and the epoch is still published — without a proof. `write_proof` and
//!   `Publisher::proof_bytes` both skip an empty proof, so nothing claims an
//!   epoch was proven when it was not, and the manifest records `proof_bytes:
//!   0` for the stage.
//! - After a failed *connect* the client backs off, so an outage costs one
//!   connect attempt every `reconnect_backoff` rather than one per stage.
//! - A background thread drains the spool onto the same connection once it is
//!   back, oldest first, and writes the recovered proofs under `recovered/`.
//!
//! A witness the server *reached and refused* is a different thing and is an
//! error. The circuit rejected those bytes and will reject them again, so it is
//! reported where it happened rather than queued.
//!
//! This mirrors `crate::publish`, with one deliberate difference. The publisher
//! keeps strict order by spooling everything once anything is spooled, because a
//! consumer must see the pipeline in the order it happened. Proofs are not like
//! that: each is an independent artifact of one epoch, and a fresh one is worth
//! more than a stale one. So the backfill yields to live proving — it touches
//! the connection only when it can take it without waiting, and only after
//! `backfill_quiet` with no foreground proof — and the spool drains in the slack
//! between epochs rather than ahead of them.
//!
//! What an outage does cost is the epochs it spans. A parent stage binds its
//! children's proofs, so a stream-final witness built over an unproven group
//! cannot be proven — the server refuses it, and that is the error above. The
//! epoch is lost and the next one starts clean, which is what a daemon restart
//! costs anyway.
//!
//! # The wire
//!
//! Length-prefixed bincode frames over TCP: a little-endian `u32` length and
//! that many bytes. A `Hello` carrying a shared token opens the connection and a
//! `HelloReply` answers with the stages the server has set up and their keys.
//! After that it is `Request` and `Reply`, one for one.
//!
//! The token is sent in the clear, so run the link over a private network or a
//! tunnel. It authenticates the client to the server; what protects the daemon
//! from a bad server is `verify_child`, not the token.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use zkasper_common::bls::Fp12;
use zkasper_common::recursion::{verify_child, ProgramVk};
use zkasper_common::types::{
    AggregateOutput, AggregateWitness, CommitteeOutput, CommitteeWitness, EpochDiffOutput,
    EpochDiffWitness, FinalizationOutput, FinalizationWitness, GroupProofOutput,
    JustificationOutput, JustificationWitness, SlotProofOutput, SlotProofWitness,
    StreamFinalOutput, StreamFinalWitness,
};
use zkasper_common::ChainConfig;

use crate::artifacts::{now_unix_millis, write_atomic};
use crate::prover::{NativeProver, Proof, ProveCost, Prover, Stage};

/// Bumped when a frame changes meaning. A client and a server that disagree are
/// turned away at the handshake rather than at the first proof.
///
/// **[`Stage`] is part of the wire.** Bincode encodes an enum as its
/// discriminant index, so adding or removing a variant silently renumbers every
/// stage after it: a server built before the change advertises "2" meaning one
/// stage and a client built after it reads "2" as another. Nothing detects that
/// — the frame parses, the stage list looks plausible, and the client binds the
/// wrong program's verification key.
///
/// Version 2 is that change: `Stage::Bootstrap` was removed, which renumbered
/// everything. **Bump this whenever `Stage` gains or loses a variant**, so the
/// two ends refuse each other instead of misreading each other.
pub const PROTOCOL_VERSION: u32 = 2;

/// Cap on one frame. The committee witness is about 115 MB; nothing else is
/// close, and a length that claims more is a bad peer rather than a big proof.
pub const MAX_FRAME_BYTES: usize = 512 * 1024 * 1024;

// ---------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct Hello {
    pub version: u32,
    pub token: String,
}

/// A stage the server can prove, and what a proof of it binds to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramInfo {
    pub stage: Stage,
    pub vk: ProgramVk,
    pub elf_sha256: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HelloReply {
    Ready {
        prover: String,
        programs: Vec<ProgramInfo>,
    },
    Rejected(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Prove { stage: Stage, witness: Vec<u8> },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Reply {
    Proved {
        proof: Proof,
        cost: ProveCost,
    },
    /// The server reached the witness and would not prove it. Retrying sends the
    /// same bytes to the same circuit, so the client does not.
    Failed(String),
}

fn write_frame<T: Serialize>(w: &mut impl Write, value: &T) -> Result<()> {
    let bytes = bincode::serialize(value).context("serialize a frame")?;
    let len: u32 = bytes.len().try_into().context("frame is over 4 GB")?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&bytes)?;
    w.flush()?;
    Ok(())
}

fn read_frame<T: DeserializeOwned>(r: &mut impl Read) -> Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME_BYTES {
        bail!("a frame of {len} bytes is over the {MAX_FRAME_BYTES} byte cap");
    }
    let mut bytes = vec![0u8; len];
    r.read_exact(&mut bytes)?;
    bincode::deserialize(&bytes).context("deserialize a frame")
}

/// Compare without leaking where the difference is.
fn token_matches(expected: &str, given: &str) -> bool {
    let (a, b) = (expected.as_bytes(), given.as_bytes());
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

/// A peer that went away, as opposed to a frame this end could not make sense of.
fn is_disconnect(error: &anyhow::Error) -> bool {
    error.downcast_ref::<std::io::Error>().is_some_and(|e| {
        matches!(
            e.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
        )
    })
}

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------

/// How to run a prover server.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub token: String,
    /// Stages the prover was set up for. A stage that is not here has no
    /// verification key, and asking a prover for one panics.
    pub stages: Vec<Stage>,
    /// How long a connection may sit without a request before it is closed. The
    /// client reconnects on its next proof, so this costs a handshake and not an
    /// epoch.
    pub idle_timeout: Duration,
}

impl ServerConfig {
    pub fn new(token: impl Into<String>, stages: &[Stage]) -> Self {
        Self {
            token: token.into(),
            stages: stages.to_vec(),
            idle_timeout: Duration::from_secs(900),
        }
    }
}

/// Serve proofs until the listener fails.
///
/// The prover is shared rather than built per connection, because the whole
/// point of the server is that one `EmbeddedClient` stays resident: a second one
/// in the same process panics, and the flag that says so is never cleared. A
/// connection gets a thread, and `proofman`'s mutex is what serialises the
/// proving — there is no concurrency here to tune.
pub fn serve(listener: &TcpListener, prover: Arc<dyn Prover>, config: ServerConfig) -> Result<()> {
    info!(
        addr = %listener.local_addr().context("read the listen address")?,
        prover = prover.name(),
        stages = config.stages.len(),
        "prover server listening",
    );

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(e) => {
                warn!(error = %e, "could not accept a connection");
                continue;
            }
        };
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let prover = prover.clone();
        let config = config.clone();
        std::thread::spawn(move || {
            info!(peer, "client connected");
            match serve_client(stream, prover.as_ref(), &config) {
                Ok(()) => info!(peer, "client disconnected"),
                Err(e) => warn!(peer, error = %format!("{e:#}"), "connection ended"),
            }
        });
    }
    Ok(())
}

/// Answer one client until it goes away.
///
/// Split out of [`serve`] so a process that already has an accept loop — or a
/// test that needs to take the server away mid-epoch — can use the same
/// connection handling.
pub fn serve_client(
    mut stream: TcpStream,
    prover: &dyn Prover,
    config: &ServerConfig,
) -> Result<()> {
    let programs: Vec<ProgramInfo> = config
        .stages
        .iter()
        .map(|&stage| ProgramInfo {
            stage,
            vk: prover.program_vk(stage),
            elf_sha256: prover.program_digest(stage),
        })
        .collect();

    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(config.idle_timeout))?;

    let hello: Hello = read_frame(&mut stream).context("read the handshake")?;
    if hello.version != PROTOCOL_VERSION {
        let reason = format!(
            "this server speaks protocol {PROTOCOL_VERSION}, the client speaks {}",
            hello.version,
        );
        write_frame(&mut stream, &HelloReply::Rejected(reason.clone()))?;
        bail!(reason);
    }
    if !token_matches(&config.token, &hello.token) {
        write_frame(
            &mut stream,
            &HelloReply::Rejected("the token was not accepted".to_string()),
        )?;
        bail!("a client offered the wrong token");
    }
    write_frame(
        &mut stream,
        &HelloReply::Ready {
            prover: prover.name().to_string(),
            programs,
        },
    )?;

    loop {
        let request: Request = match read_frame(&mut stream) {
            Ok(request) => request,
            Err(e) if is_disconnect(&e) => return Ok(()),
            Err(e) => return Err(e.context("read a request")),
        };
        let Request::Prove { stage, witness } = request;
        let started = Instant::now();
        let reply = match prove_stage(prover, stage, &witness) {
            Ok(proof) => {
                info!(
                    stage = stage.as_str(),
                    witness_bytes = witness.len(),
                    words = proof.len(),
                    millis = started.elapsed().as_millis() as u64,
                    "proved for a client",
                );
                Reply::Proved {
                    proof,
                    cost: prover.last_cost().unwrap_or_default(),
                }
            }
            Err(e) => {
                warn!(stage = stage.as_str(), error = %format!("{e:#}"), "refused a witness");
                Reply::Failed(format!("{e:#}"))
            }
        };
        write_frame(&mut stream, &reply).context("write a reply")?;
    }
}

/// Deserialize a witness for `stage` and prove it.
///
/// The public output the prover computes is dropped: the client computed the
/// same one from the same witness before it sent anything, and that is the copy
/// the accumulator advances on.
fn prove_stage(prover: &dyn Prover, stage: Stage, witness: &[u8]) -> Result<Proof> {
    fn decode<T: DeserializeOwned>(stage: Stage, witness: &[u8]) -> Result<T> {
        bincode::deserialize(witness)
            .with_context(|| format!("deserialize a {} witness", stage.as_str()))
    }
    Ok(match stage {
        Stage::EpochDiff => prover.prove_epoch_diff(&decode(stage, witness)?)?.1,
        Stage::Committee => prover.prove_committee(&decode(stage, witness)?)?.1,
        Stage::SlotProof => prover.prove_slot(&decode(stage, witness)?)?.1,
        Stage::Justification => prover.prove_justification(&decode(stage, witness)?)?.1,
        Stage::Finalization => prover.prove_finalization(&decode(stage, witness)?)?.1,
        Stage::Group => prover.prove_group(&decode(stage, witness)?)?.2,
        Stage::Aggregate => prover.prove_aggregate(&decode(stage, witness)?)?.1,
        Stage::StreamFinal => prover.prove_stream_final(&decode(stage, witness)?)?.1,
    })
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// How to reach a prover server.
#[derive(Clone, Debug)]
pub struct RemoteProverConfig {
    pub chain: ChainConfig,
    /// `host:port`.
    pub addr: String,
    pub token: String,
    /// Stages this run will ask for. The handshake must offer all of them, so a
    /// server started for the wrong pipeline fails at startup and not at `T`.
    pub stages: Vec<Stage>,
    pub connect_timeout: Duration,
    /// Longest one proof may take. It bounds how long a server that has stopped
    /// answering can hold the pipeline, so it can be neither short enough to
    /// abandon good proofs nor long enough to hide a dead server.
    ///
    /// The slowest proof a run asks for is not the one on the critical path. A
    /// batch-path justification recursively verifies every slot proof of its
    /// epoch, and over ~22 of them that took more than ten minutes on an RTX
    /// 5090 (measured 2026-08-18). A timeout under the slowest proof does not
    /// fail — it retries, and the retry is just as slow, so the epoch never
    /// lands and the card spends its time on proofs nobody is waiting for.
    pub request_timeout: Duration,
    /// Held after a failed connect, so an outage costs one attempt per interval
    /// rather than one per stage.
    pub reconnect_backoff: Duration,
    /// Where unproven witnesses go when the server cannot be reached. `None`
    /// drops them, which loses the epoch's proof rather than delaying it.
    pub spool_dir: Option<PathBuf>,
    /// Witnesses held on disk before the oldest are dropped.
    pub spool_capacity: usize,
    /// The backfill leaves the connection alone until this long after the last
    /// foreground proof, so a live epoch never queues behind an old one.
    pub backfill_quiet: Duration,
    /// How often the backfill looks at the spool.
    pub backfill_interval: Duration,
    /// Largest witness that can be sent. A larger one is not spooled, because a
    /// retry of it fails identically for ever. Defaults to [`MAX_FRAME_BYTES`],
    /// which is what the far end will read.
    pub max_request_bytes: usize,
}

impl RemoteProverConfig {
    pub fn new(
        chain: ChainConfig,
        addr: impl Into<String>,
        token: impl Into<String>,
        stages: &[Stage],
    ) -> Self {
        Self {
            chain,
            addr: addr.into(),
            token: token.into(),
            stages: stages.to_vec(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(1800),
            reconnect_backoff: Duration::from_secs(5),
            spool_dir: None,
            spool_capacity: 256,
            backfill_quiet: Duration::from_secs(30),
            backfill_interval: Duration::from_secs(5),
            max_request_bytes: MAX_FRAME_BYTES,
        }
    }
}

/// What the link has cost so far.
#[derive(Clone, Copy, Debug, Default)]
pub struct RemoteCounters {
    pub proved: u64,
    /// Stages that got no proof because the server was unreachable.
    pub unproven: u64,
    /// Stages whose witness the server took and never answered for.
    ///
    /// Counted apart from the rest because it is a different fault. A server
    /// that is down refuses the connection; a server that accepts the witness
    /// and goes silent is a box under memory pressure, a proof slower than
    /// `request_timeout`, or a prover wedged on one — and only the last of
    /// those is fixed by waiting longer.
    pub timed_out: u64,
    pub spooled: u64,
    pub dropped: u64,
    pub recovered: u64,
    pub pending: u64,
}

#[derive(Default)]
struct Counters {
    proved: AtomicU64,
    unproven: AtomicU64,
    timed_out: AtomicU64,
    spooled: AtomicU64,
    dropped: AtomicU64,
    recovered: AtomicU64,
    pending: AtomicU64,
}

/// The one connection, and when it may next be rebuilt.
#[derive(Default)]
struct Link {
    stream: Option<TcpStream>,
    retry_at: Option<Instant>,
}

/// A witness the server never took, kept so the epoch can be proven late.
#[derive(Debug, Serialize, Deserialize)]
struct Spooled {
    stage: Stage,
    witness: Vec<u8>,
    /// What the local circuit committed. Kept so a recovered proof faces the
    /// same predicate the live path applies.
    publics: Vec<u8>,
    unix_millis: u64,
}

/// A bounded, ordered, on-disk queue of unproven witnesses.
struct Spool {
    dir: PathBuf,
    recovered: PathBuf,
    capacity: usize,
    queue: VecDeque<PathBuf>,
    written: u64,
}

impl Spool {
    fn open(dir: PathBuf, capacity: usize) -> Result<Self> {
        let recovered = dir.join("recovered");
        std::fs::create_dir_all(&recovered)
            .with_context(|| format!("create the prover spool at {}", dir.display()))?;
        // Names sort by time, so a restart resumes the queue in the order it was
        // written rather than in whatever order the directory reads back.
        let mut existing: Vec<PathBuf> = std::fs::read_dir(&dir)
            .with_context(|| format!("read the prover spool at {}", dir.display()))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| path.extension().is_some_and(|e| e == "req"))
            .collect();
        existing.sort();
        if !existing.is_empty() {
            info!(
                pending = existing.len(),
                dir = %dir.display(),
                "picked up witnesses an earlier run could not prove",
            );
        }
        Ok(Self {
            dir,
            recovered,
            capacity,
            queue: existing.into(),
            written: 0,
        })
    }

    fn push(&mut self, entry: &Spooled, counters: &Counters) {
        // A spool that has hit its cap has been down long enough that the newest
        // witnesses are the ones worth keeping.
        while self.queue.len() >= self.capacity {
            self.pop(counters);
            let dropped = counters.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped.is_power_of_two() {
                warn!(
                    dropped,
                    "the prover spool is full; the oldest witnesses are being dropped",
                );
            }
        }
        self.written += 1;
        let path = self.dir.join(format!(
            "{:013}-{:06}-{}.req",
            entry.unix_millis,
            self.written,
            entry.stage.as_str(),
        ));
        match bincode::serialize(entry)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| write_atomic(&path, &bytes))
        {
            Ok(()) => {
                self.queue.push_back(path);
                counters.spooled.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => warn!(error = %format!("{e:#}"), "could not spool a witness"),
        }
        counters
            .pending
            .store(self.queue.len() as u64, Ordering::Relaxed);
    }

    fn len(&self) -> u64 {
        self.queue.len() as u64
    }

    fn front(&self) -> Option<PathBuf> {
        self.queue.front().cloned()
    }

    fn pop(&mut self, counters: &Counters) {
        if let Some(path) = self.queue.pop_front() {
            let _ = std::fs::remove_file(path);
        }
        counters
            .pending
            .store(self.queue.len() as u64, Ordering::Relaxed);
    }
}

struct Inner {
    config: RemoteProverConfig,
    /// Cached at the handshake. `program_vk` is infallible on the trait and the
    /// witness builders bind it, so it has to answer through an outage.
    programs: Vec<ProgramInfo>,
    conn: Mutex<Link>,
    spool: Option<Mutex<Spool>>,
    last_cost: Mutex<Option<ProveCost>>,
    counters: Counters,
    /// Unix millis of the last foreground proof, so the backfill can stay out of
    /// a live epoch.
    last_foreground: AtomicU64,
}

/// Asks another process for proofs.
pub struct RemoteProver {
    inner: Arc<Inner>,
    /// Runs the guest logic, so every output the orchestrator acts on is
    /// computed here and none of them is taken from the server.
    native: NativeProver,
    stop: Arc<AtomicBool>,
}

impl RemoteProver {
    /// Connect, handshake, and start the backfill.
    ///
    /// This fails when the server is not there, on purpose: a daemon that cannot
    /// reach its prover at startup has been misconfigured, and learning that
    /// before the first beacon call is cheaper than learning it at `T`. The
    /// asymmetry is deliberate — a prover lost mid-run costs proofs and not the
    /// daemon, but one that was never there is a fault to report. The cost is
    /// that a daemon restarted *during* an outage cannot start until the server
    /// is back; its supervisor retries, and the store is untouched.
    pub fn connect(config: RemoteProverConfig) -> Result<Self> {
        let (stream, server, programs) = handshake(&config)?;
        for &stage in &config.stages {
            if !programs.iter().any(|p| p.stage == stage) {
                bail!(
                    "the prover at {} has no {} program; start the server with that stage",
                    config.addr,
                    stage.as_str(),
                );
            }
        }
        info!(
            addr = %config.addr,
            server,
            stages = programs.len(),
            "connected to the prover server",
        );

        let spool = config
            .spool_dir
            .clone()
            .map(|dir| Spool::open(dir, config.spool_capacity).map(Mutex::new))
            .transpose()?;
        let chain = config.chain.clone();
        let inner = Arc::new(Inner {
            config,
            programs,
            conn: Mutex::new(Link {
                stream: Some(stream),
                retry_at: None,
            }),
            spool,
            last_cost: Mutex::new(None),
            counters: Counters::default(),
            last_foreground: AtomicU64::new(now_unix_millis()),
        });

        if let Some(spool) = &inner.spool {
            let pending = spool.lock().unwrap().len();
            inner.counters.pending.store(pending, Ordering::Relaxed);
        }

        let stop = Arc::new(AtomicBool::new(false));
        if inner.spool.is_some() {
            let backfill = inner.clone();
            let stopped = stop.clone();
            std::thread::Builder::new()
                .name("prover-backfill".to_string())
                .spawn(move || backfill_loop(&backfill, &stopped))
                .context("start the prover backfill thread")?;
        }

        Ok(Self {
            inner,
            native: NativeProver::new(chain),
            stop,
        })
    }

    pub fn counters(&self) -> RemoteCounters {
        let c = &self.inner.counters;
        RemoteCounters {
            proved: c.proved.load(Ordering::Relaxed),
            unproven: c.unproven.load(Ordering::Relaxed),
            timed_out: c.timed_out.load(Ordering::Relaxed),
            spooled: c.spooled.load(Ordering::Relaxed),
            dropped: c.dropped.load(Ordering::Relaxed),
            recovered: c.recovered.load(Ordering::Relaxed),
            pending: c.pending.load(Ordering::Relaxed),
        }
    }
}

impl Drop for RemoteProver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Whether `error` is the connection going quiet rather than going away.
///
/// A read or write deadline on a socket surfaces as `WouldBlock` or
/// `TimedOut` depending on the platform, and both mean the same thing here: the
/// server has the witness and has said nothing since.
fn is_timeout(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )
        })
    })
}

/// Open a connection and learn what the server can prove.
fn handshake(config: &RemoteProverConfig) -> Result<(TcpStream, String, Vec<ProgramInfo>)> {
    let addr = config
        .addr
        .to_socket_addrs()
        .with_context(|| format!("resolve {}", config.addr))?
        .next()
        .with_context(|| format!("{} resolved to no address", config.addr))?;
    let mut stream = TcpStream::connect_timeout(&addr, config.connect_timeout)
        .with_context(|| format!("connect to the prover at {}", config.addr))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(config.request_timeout))?;
    stream.set_write_timeout(Some(config.request_timeout))?;

    write_frame(
        &mut stream,
        &Hello {
            version: PROTOCOL_VERSION,
            token: config.token.clone(),
        },
    )
    .context("send the handshake")?;
    match read_frame(&mut stream).context("read the handshake reply")? {
        HelloReply::Ready { prover, programs } => Ok((stream, prover, programs)),
        HelloReply::Rejected(reason) => {
            bail!(
                "the prover at {} refused this client: {reason}",
                config.addr
            )
        }
    }
}

impl Inner {
    fn program(&self, stage: Stage) -> &ProgramInfo {
        self.programs
            .iter()
            .find(|p| p.stage == stage)
            .unwrap_or_else(|| {
                panic!(
                    "the {} stage was not set up; add it to RemoteProverConfig::stages",
                    stage.as_str(),
                )
            })
    }

    /// Take the connection, rebuilding it if the last request broke it.
    fn dial<'a>(&self, link: &'a mut Link) -> Result<&'a mut TcpStream> {
        if link.stream.is_none() {
            if link.retry_at.is_some_and(|at| Instant::now() < at) {
                bail!(
                    "the prover at {} is down; waiting to reconnect",
                    self.config.addr
                );
            }
            match handshake(&self.config) {
                Ok((stream, server, programs)) => {
                    // A server that came back with different ELFs is a different
                    // program to every proof already published against the old
                    // keys. Refuse it rather than silently switch.
                    if programs != self.programs {
                        link.retry_at = Some(Instant::now() + self.config.reconnect_backoff);
                        bail!(
                            "the prover at {} came back with different programs; \
                             it is not the server this daemon started against",
                            self.config.addr,
                        );
                    }
                    info!(addr = %self.config.addr, server, "reconnected to the prover server");
                    link.stream = Some(stream);
                    link.retry_at = None;
                }
                Err(e) => {
                    link.retry_at = Some(Instant::now() + self.config.reconnect_backoff);
                    return Err(e);
                }
            }
        }
        Ok(link.stream.as_mut().expect("just connected"))
    }

    fn roundtrip(&self, link: &mut Link, request: &Request) -> Result<Reply> {
        let stream = self.dial(link)?;
        write_frame(stream, request)?;
        read_frame(stream)
    }

    /// One request, with one retry on a fresh connection.
    ///
    /// Proving is a pure function of the witness, so re-sending after a half
    /// written request costs a proof and never correctness.
    fn attempt(&self, link: &mut Link, request: &Request) -> Result<Reply> {
        match self.roundtrip(link, request) {
            Ok(reply) => Ok(reply),
            Err(first) => {
                if is_timeout(&first) {
                    self.counters.timed_out.fetch_add(1, Ordering::Relaxed);
                }
                link.stream = None;
                match self.roundtrip(link, request) {
                    Ok(reply) => Ok(reply),
                    Err(_) => {
                        link.stream = None;
                        Err(first)
                    }
                }
            }
        }
    }

    fn prove(&self, stage: Stage, witness: &impl Serialize, publics: &[u8]) -> Result<Proof> {
        self.prove_bytes(
            stage,
            bincode::serialize(witness).context("serialize witness")?,
            publics,
        )
    }

    fn prove_bytes(&self, stage: Stage, witness: Vec<u8>, publics: &[u8]) -> Result<Proof> {
        // A witness that cannot be framed can never be sent, so spooling it
        // would queue a retry that fails identically for ever -- and re-sending
        // it costs the link its whole bandwidth each time. Measured on mainnet
        // 2026-08-18: a bootstrap witness over 2,338,764 validators serializes
        // to 916 MB against this 512 MB cap.
        //
        // The empty proof is the same answer an outage gives, and the same one
        // a witness-only run gives: the daemon holds the outputs its own
        // circuits computed, so it keeps following the chain and the epoch is
        // published without a proof for this stage.
        if witness.len() > self.config.max_request_bytes {
            self.counters.unproven.fetch_add(1, Ordering::Relaxed);
            warn!(
                stage = stage.as_str(),
                witness_bytes = witness.len(),
                cap_bytes = self.config.max_request_bytes,
                "this witness is larger than one frame and cannot be proven remotely",
            );
            return Ok(Vec::new());
        }
        self.last_foreground
            .store(now_unix_millis(), Ordering::Relaxed);
        let started = Instant::now();
        let request = Request::Prove { stage, witness };
        let result = self.attempt(&mut self.conn.lock().unwrap(), &request);
        self.last_foreground
            .store(now_unix_millis(), Ordering::Relaxed);

        match result {
            Ok(Reply::Proved { proof, cost }) => {
                self.check(stage, &proof, publics)?;
                *self.last_cost.lock().unwrap() = Some(cost);
                self.counters.proved.fetch_add(1, Ordering::Relaxed);
                info!(
                    stage = stage.as_str(),
                    words = proof.len(),
                    prove_millis = cost.prove_millis,
                    wrap_millis = cost.wrap_millis,
                    round_trip_millis = started.elapsed().as_millis() as u64,
                    "proved remotely",
                );
                Ok(proof)
            }
            // The witness reached the circuit and the circuit said no. Spooling
            // it would only feed it back to the same circuit.
            Ok(Reply::Failed(reason)) => bail!(
                "the prover at {} refused the {} witness: {reason}",
                self.config.addr,
                stage.as_str(),
            ),
            // The server is not there. Keep the witness, and hand back the empty
            // proof a witness-only run would: the daemon has its own outputs, so
            // it keeps following the chain and the epoch is published without a
            // proof rather than not published at all.
            Err(e) => {
                let Request::Prove { witness, .. } = request;
                self.spool(stage, witness, publics, &e);
                Ok(Proof::new())
            }
        }
    }

    /// A proof is only a proof if this end accepts it, under the key the
    /// handshake reported and the publics the local circuit committed.
    fn check(&self, stage: Stage, proof: &Proof, publics: &[u8]) -> Result<()> {
        if !verify_child(proof, &self.program(stage).vk, publics) {
            bail!(
                "the {} proof from {} does not verify against its own program key and outputs",
                stage.as_str(),
                self.config.addr,
            );
        }
        Ok(())
    }

    fn spool(&self, stage: Stage, witness: Vec<u8>, publics: &[u8], error: &anyhow::Error) {
        self.counters.unproven.fetch_add(1, Ordering::Relaxed);
        let Some(spool) = &self.spool else {
            warn!(
                stage = stage.as_str(),
                error = %format!("{error:#}"),
                "the prover is unreachable and no spool is configured; this witness is lost",
            );
            return;
        };
        spool.lock().unwrap().push(
            &Spooled {
                stage,
                witness,
                publics: publics.to_vec(),
                unix_millis: now_unix_millis(),
            },
            &self.counters,
        );
        warn!(
            stage = stage.as_str(),
            pending = self.counters.pending.load(Ordering::Relaxed),
            error = %format!("{error:#}"),
            "the prover is unreachable; the witness was spooled and this stage has no proof",
        );
    }

    /// Prove one spooled witness, if the connection is free and the pipeline is
    /// not using it.
    fn backfill_once(&self) -> Result<()> {
        let Some(spool) = &self.spool else {
            return Ok(());
        };
        let Some(path) = spool.lock().unwrap().front() else {
            return Ok(());
        };
        let quiet = now_unix_millis().saturating_sub(self.last_foreground.load(Ordering::Relaxed));
        if quiet < self.config.backfill_quiet.as_millis() as u64 {
            return Ok(());
        }
        // Never wait for the connection: a fresh proof is worth more than any
        // number of stale ones.
        let Ok(mut link) = self.conn.try_lock() else {
            return Ok(());
        };

        let entry: Spooled = match std::fs::read(&path)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| bincode::deserialize(&bytes).map_err(anyhow::Error::from))
        {
            Ok(entry) => entry,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "dropping an unreadable spool entry");
                spool.lock().unwrap().pop(&self.counters);
                return Ok(());
            }
        };

        let request = Request::Prove {
            stage: entry.stage,
            witness: entry.witness,
        };
        match self.attempt(&mut link, &request)? {
            Reply::Proved { proof, .. } => {
                self.check(entry.stage, &proof, &entry.publics)?;
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("recovered");
                let recovered = spool.lock().unwrap().recovered.join(format!("{name}.bin"));
                write_atomic(&recovered, &bincode::serialize(&proof)?)?;
                write_atomic(&recovered.with_extension("publics"), &entry.publics)?;
                spool.lock().unwrap().pop(&self.counters);
                self.counters.recovered.fetch_add(1, Ordering::Relaxed);
                info!(
                    stage = entry.stage.as_str(),
                    path = %recovered.display(),
                    pending = self.counters.pending.load(Ordering::Relaxed),
                    "backfilled a proof the outage cost",
                );
            }
            // The circuit rejected it, so it will reject it again.
            Reply::Failed(reason) => {
                warn!(
                    stage = entry.stage.as_str(),
                    reason, "dropping a spooled witness the prover will not take",
                );
                spool.lock().unwrap().pop(&self.counters);
            }
        }
        Ok(())
    }
}

fn backfill_loop(inner: &Arc<Inner>, stop: &Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(inner.config.backfill_interval);
        if stop.load(Ordering::Relaxed) {
            return;
        }
        if let Err(e) = inner.backfill_once() {
            // The server is still away. The spool keeps its place and the next
            // pass tries again; `dial` holds the backoff.
            warn!(error = %format!("{e:#}"), "could not backfill a spooled witness");
        }
    }
}

impl Prover for RemoteProver {
    fn name(&self) -> &'static str {
        "remote (network prover)"
    }

    fn program_vk(&self, stage: Stage) -> ProgramVk {
        self.inner.program(stage).vk
    }

    fn program_digest(&self, stage: Stage) -> Option<String> {
        self.inner.program(stage).elf_sha256.clone()
    }

    fn health(&self) -> Option<crate::prover::ProverHealth> {
        let c = self.counters();
        Some(crate::prover::ProverHealth {
            proved: c.proved,
            unproven: c.unproven,
            timed_out: c.timed_out,
            spooled: c.spooled,
            recovered: c.recovered,
            dropped: c.dropped,
            pending: c.pending,
        })
    }

    fn last_cost(&self) -> Option<ProveCost> {
        *self.inner.last_cost.lock().unwrap()
    }

    fn prove_epoch_diff(&self, witness: &EpochDiffWitness) -> Result<(EpochDiffOutput, Proof)> {
        let (output, _) = self.native.prove_epoch_diff(witness)?;
        let proof = self
            .inner
            .prove(Stage::EpochDiff, witness, &output.public_bytes())?;
        Ok((output, proof))
    }

    fn prove_committee(&self, witness: &CommitteeWitness) -> Result<(CommitteeOutput, Proof)> {
        let (output, _) = self.native.prove_committee(witness)?;
        let proof = self
            .inner
            .prove(Stage::Committee, witness, &output.public_bytes())?;
        Ok((output, proof))
    }

    fn prove_slot(&self, witness: &SlotProofWitness) -> Result<(SlotProofOutput, Proof)> {
        let (output, _) = self.native.prove_slot(witness)?;
        let proof = self
            .inner
            .prove(Stage::SlotProof, witness, &output.public_bytes())?;
        Ok((output, proof))
    }

    fn prove_justification(
        &self,
        witness: &JustificationWitness,
    ) -> Result<(JustificationOutput, Proof)> {
        let (output, _) = self.native.prove_justification(witness)?;
        let proof = self
            .inner
            .prove(Stage::Justification, witness, &output.public_bytes())?;
        Ok((output, proof))
    }

    fn prove_finalization(
        &self,
        witness: &FinalizationWitness,
    ) -> Result<(FinalizationOutput, Proof)> {
        let (output, _) = self.native.prove_finalization(witness)?;
        let proof = self
            .inner
            .prove(Stage::Finalization, witness, &output.public_bytes())?;
        Ok((output, proof))
    }

    fn prove_group(&self, witness: &SlotProofWitness) -> Result<(GroupProofOutput, Fp12, Proof)> {
        let (output, miller, _) = self.native.prove_group(witness)?;
        let proof = self
            .inner
            .prove(Stage::Group, witness, &output.public_bytes())?;
        Ok((output, miller, proof))
    }

    fn prove_aggregate(&self, witness: &AggregateWitness) -> Result<(AggregateOutput, Proof)> {
        let (output, _) = self.native.prove_aggregate(witness)?;
        let proof = self
            .inner
            .prove(Stage::Aggregate, witness, &output.public_bytes())?;
        Ok((output, proof))
    }

    fn prove_stream_final(
        &self,
        witness: &StreamFinalWitness,
    ) -> Result<(StreamFinalOutput, Proof)> {
        let (output, _) = self.native.prove_stream_final(witness)?;
        let proof = self
            .inner
            .prove(Stage::StreamFinal, witness, &output.public_bytes())?;
        Ok((output, proof))
    }
}
