//! The network prover, against a server in the same test.
//!
//! The server runs a [`NativeProver`], so these cover the transport, the
//! handshake, the checking a returned proof goes through and — the part that
//! matters most — what the client does when the server is not there. What they
//! cannot cover is a real proof, which needs a GPU; `zisk_proof_tests` is that.

mod common;

use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::stream_fixture;

use zkasper_common::types::SlotProofWitness;
use zkasper_common::ChainConfig;
use zkasper_witness_gen::attestation_collector::SlotComplement;
use zkasper_witness_gen::prover::{NativeProver, Prover, Stage};
use zkasper_witness_gen::remote_prover::{
    serve_client, RemoteProver, RemoteProverConfig, ServerConfig, PROTOCOL_VERSION,
};
use zkasper_witness_gen::split_prover::SplitProver;
use zkasper_witness_gen::streaming;

const ACC_DEPTH: u32 = 4;
const TOKEN: &str = "a-shared-secret";
const STAGES: &[Stage] = &[Stage::Group, Stage::SlotProof];

fn chain() -> ChainConfig {
    ChainConfig {
        acc_tree_depth: ACC_DEPTH,
        ..ChainConfig::MAINNET
    }
}

fn witness() -> SlotProofWitness {
    witness_at(ACC_DEPTH)
}

fn witness_at(depth: u32) -> SlotProofWitness {
    let fixture = stream_fixture(depth);
    let units: Vec<&SlotComplement> = fixture.units[..2].iter().collect();
    streaming::group_witness(
        &fixture.context,
        &fixture.epoch.tree,
        &fixture.epoch.committees,
        &units,
    )
}

/// A server the test can take away.
///
/// It runs the real [`serve_client`] behind its own accept loop, so `stop` can
/// both stop accepting and cut the connections already open — which is what an
/// instance disappearing mid-epoch looks like from the daemon's side.
struct Server {
    addr: String,
    stages: Vec<Stage>,
    running: Arc<AtomicBool>,
    open: Arc<Mutex<Vec<TcpStream>>>,
}

impl Server {
    fn bind() -> Self {
        Self::bind_with(STAGES)
    }

    fn bind_with(stages: &[Stage]) -> Self {
        // Let the OS pick a port, then give it back: the accept loop binds it.
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();
        let mut server = Self {
            addr,
            stages: stages.to_vec(),
            running: Arc::new(AtomicBool::new(false)),
            open: Arc::new(Mutex::new(Vec::new())),
        };
        server.start();
        server
    }

    fn start(&mut self) {
        let listener = bind_retrying(&self.addr);
        listener.set_nonblocking(true).unwrap();
        self.running = Arc::new(AtomicBool::new(true));
        self.open = Arc::new(Mutex::new(Vec::new()));
        let running = self.running.clone();
        let open = self.open.clone();
        let config = ServerConfig::new(TOKEN, &self.stages);
        std::thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        open.lock().unwrap().push(stream.try_clone().unwrap());
                        let config = config.clone();
                        std::thread::spawn(move || {
                            let prover = NativeProver::new(chain());
                            let _ = serve_client(stream, &prover, &config);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        // The accept loop has to own the port before a client dials it.
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(&self.addr).is_err() {
            assert!(Instant::now() < deadline, "the test server never came up");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Stop accepting, and cut what is already connected.
    fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        for stream in self.open.lock().unwrap().drain(..) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(&self.addr).is_ok() {
            assert!(Instant::now() < deadline, "the test server never went away");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn restart(&mut self) {
        self.start();
    }
}

/// The accept loop drops the listener when it stops, but the kernel may hold
/// the port a moment longer.
fn bind_retrying(addr: &str) -> TcpListener {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpListener::bind(addr) {
            Ok(listener) => return listener,
            Err(e) => {
                assert!(Instant::now() < deadline, "could not bind {addr}: {e}");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn client(addr: &str, spool: Option<&Path>) -> RemoteProverConfig {
    RemoteProverConfig {
        spool_dir: spool.map(Path::to_path_buf),
        connect_timeout: Duration::from_millis(500),
        request_timeout: Duration::from_secs(20),
        reconnect_backoff: Duration::from_millis(50),
        backfill_quiet: Duration::from_millis(50),
        backfill_interval: Duration::from_millis(50),
        ..RemoteProverConfig::new(chain(), addr, TOKEN, STAGES)
    }
}

/// The whole point: a witness goes over the wire and a proof comes back that
/// this end accepts, with the outputs the local circuit computed.
#[test]
fn proves_over_the_wire() {
    let server = Server::bind();
    let prover = RemoteProver::connect(client(&server.addr, None)).expect("connect");

    let witness = witness();
    let (remote, _miller, _proof) = prover.prove_group(&witness).expect("group proof");
    let (local, _, _) = NativeProver::new(chain()).prove_group(&witness).unwrap();
    assert_eq!(remote.attesting_balance, local.attesting_balance);
    assert_eq!(remote.public_bytes(), local.public_bytes());

    // The second program on the same connection. One server serves every stage.
    let (slot, _) = prover.prove_slot(&witness).expect("slot proof");
    assert_eq!(slot.attesting_balance, local.attesting_balance);
    assert_eq!(prover.counters().proved, 2);
}

/// A client that cannot prove the token is not told what the keys are.
#[test]
fn refuses_a_bad_token() {
    let server = Server::bind();
    let Err(error) = RemoteProver::connect(RemoteProverConfig {
        token: "not-the-token".to_string(),
        ..client(&server.addr, None)
    }) else {
        panic!("a wrong token must not connect");
    };
    assert!(
        format!("{error:#}").contains("token"),
        "unexpected error: {error:#}",
    );
}

/// A daemon that cannot reach its prover at startup is misconfigured, and
/// finding that out before the first beacon call is the cheap moment.
#[test]
fn refuses_to_start_without_a_server() {
    let mut server = Server::bind();
    server.stop();
    assert!(
        RemoteProver::connect(client(&server.addr, None)).is_err(),
        "connecting to a closed port must fail",
    );
}

/// The failure that matters. The server goes away mid-run: the call fails, the
/// witness is kept, the keys keep answering, and nothing blocks for long.
#[test]
fn an_outage_costs_the_epoch_and_not_the_daemon() {
    let spool = tempfile::tempdir().unwrap();
    let mut server = Server::bind();
    let prover = RemoteProver::connect(client(&server.addr, Some(spool.path()))).expect("connect");
    let witness = witness();
    let (proven, _, _) = prover.prove_group(&witness).expect("the first proof");

    let vk = prover.program_vk(Stage::Group);
    server.stop();

    // Two epochs' worth of stages, against a prover that is not there. Each call
    // returns the outputs the local circuit computed and the empty proof of a
    // witness-only run, so the daemon keeps following the chain.
    let started = Instant::now();
    for _ in 0..4 {
        let (output, _, proof) = prover
            .prove_group(&witness)
            .expect("no proof, but no error");
        assert!(
            proof.is_empty(),
            "an unreachable server cannot return a proof"
        );
        assert_eq!(output.public_bytes(), proven.public_bytes());
    }
    // Fast, because the backoff means an outage costs one connect attempt per
    // interval rather than one per stage. The bound is loose enough for a loaded
    // CI box and far under the 8 x 500 ms of connect timeouts it replaces.
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "four calls into an outage took {:?}",
        started.elapsed(),
    );

    // The witness builders bind the verification key on every stage, so it has
    // to keep answering through an outage.
    assert_eq!(prover.program_vk(Stage::Group), vk);

    let counters = prover.counters();
    assert_eq!(counters.spooled, 4, "every lost witness must be kept");
    assert_eq!(counters.unproven, 4);
    assert_eq!(counters.pending, 4);
    assert_eq!(counters.dropped, 0);
    assert_eq!(spooled_files(spool.path()), 4);
}

/// Two provers, one stage each, and every proof lands on the right one.
///
/// One card cannot keep up with mainnet — an epoch cost 399 s of an RTX 5090
/// against the 384 s an epoch lasts — so a deployment splits the stages across
/// cards. What must not happen is a proof going to a prover that was never set
/// up for its stage: the key it binds would be another program's.
#[test]
fn routes_each_stage_to_its_own_prover() {
    let groups = Server::bind_with(&[Stage::Group]);
    let slots = Server::bind_with(&[Stage::SlotProof]);

    let split = SplitProver::new(
        Box::new(
            RemoteProver::connect(RemoteProverConfig {
                stages: vec![Stage::Group],
                ..client(&groups.addr, None)
            })
            .expect("connect to the group prover"),
        ),
        vec![(
            Stage::SlotProof,
            Box::new(
                RemoteProver::connect(RemoteProverConfig {
                    stages: vec![Stage::SlotProof],
                    ..client(&slots.addr, None)
                })
                .expect("connect to the slot prover"),
            ) as Box<dyn Prover>,
        )],
    )
    .expect("split");

    assert_eq!(split.routed(), vec!["slot_proof"]);

    // Each prover is set up for one stage only, so a misroute is not a subtle
    // wrong answer: asking a prover for a stage it never learned panics in
    // `program`, because the verification key it would bind does not exist.
    // Both calls returning at all is the routing working.
    let witness = witness();
    let (group, _, _) = split.prove_group(&witness).expect("group proof");
    let (slot, _) = split.prove_slot(&witness).expect("slot proof");

    let native = NativeProver::new(chain());
    assert_eq!(
        group.public_bytes(),
        native.prove_group(&witness).unwrap().0.public_bytes(),
    );
    assert_eq!(
        slot.attesting_balance,
        native.prove_slot(&witness).unwrap().0.attesting_balance,
    );

    // Both cards' counters, added up, because an operator wants to know the
    // service lost a proof rather than which card lost it.
    let health = split.health().expect("a network prover reports health");
    assert_eq!(health.proved, 2);
    assert_eq!(health.unproven, 0);
}

/// A witness too large to frame is not spooled, because a retry of it would
/// fail identically for ever and re-send the whole thing each time.
///
/// Found on mainnet 2026-08-18, on the since-deleted bootstrap stage: its
/// witness over 2,338,764 validators serialized to 916 MB against a 512 MB cap,
/// and the client queued it and kept trying. No stage is that large now, but the
/// rule is about the spool rather than about one witness, so it stays. The cap is
/// a config value here so the test does not need 512 MB.
#[test]
fn refuses_to_queue_a_witness_that_cannot_be_sent() {
    let spool = tempfile::tempdir().unwrap();
    let server = Server::bind();
    let prover = RemoteProver::connect(RemoteProverConfig {
        max_request_bytes: 64,
        ..client(&server.addr, Some(spool.path()))
    })
    .expect("connect");

    let witness = witness();
    let (output, _, proof) = prover
        .prove_group(&witness)
        .expect("no proof, but no error");
    assert!(proof.is_empty(), "it was never sent, so there is no proof");
    let (local, _, _) = NativeProver::new(chain()).prove_group(&witness).unwrap();
    assert_eq!(
        output.public_bytes(),
        local.public_bytes(),
        "the outputs are the local circuit's either way",
    );

    let counters = prover.counters();
    assert_eq!(counters.unproven, 1);
    assert_eq!(counters.spooled, 0, "a retry of it can never succeed");
    assert_eq!(counters.pending, 0);
    assert_eq!(counters.proved, 0, "nothing was ever sent");
    assert_eq!(spooled_files(spool.path()), 0);
}

/// The server comes back on the same address. The next proof reconnects without
/// anything having to restart, and the backlog drains behind it.
#[test]
fn reconnects_and_backfills_what_the_outage_cost() {
    let spool = tempfile::tempdir().unwrap();
    let mut server = Server::bind();
    let prover = RemoteProver::connect(client(&server.addr, Some(spool.path()))).expect("connect");
    let witness = witness();

    server.stop();
    for _ in 0..3 {
        prover
            .prove_group(&witness)
            .expect("no proof, but no error");
    }
    assert_eq!(prover.counters().pending, 3);

    server.restart();
    // The backoff from the last failed connect has to expire first.
    let deadline = Instant::now() + Duration::from_secs(10);
    while prover.counters().proved < 2 {
        assert!(Instant::now() < deadline, "never reconnected");
        prover.prove_group(&witness).expect("prove");
        std::thread::sleep(Duration::from_millis(50));
    }

    let deadline = Instant::now() + Duration::from_secs(30);
    while prover.counters().pending > 0 {
        assert!(
            Instant::now() < deadline,
            "the spool did not drain: {:?}",
            prover.counters(),
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(prover.counters().recovered, 3);
    assert_eq!(spooled_files(spool.path()), 0);
    assert_eq!(recovered_files(spool.path()), 3);
}

/// The spool is bounded on the far end too. A prover that has been away long
/// enough drops the oldest witnesses rather than the disk.
#[test]
fn the_spool_is_bounded() {
    let spool = tempfile::tempdir().unwrap();
    let mut server = Server::bind();
    let prover = RemoteProver::connect(RemoteProverConfig {
        spool_capacity: 2,
        // Nothing may drain while the cap is being measured.
        backfill_quiet: Duration::from_secs(3600),
        ..client(&server.addr, Some(spool.path()))
    })
    .expect("connect");
    let witness = witness();

    server.stop();
    for _ in 0..5 {
        prover
            .prove_group(&witness)
            .expect("no proof, but no error");
    }
    let counters = prover.counters();
    assert_eq!(counters.spooled, 5);
    assert_eq!(counters.dropped, 3);
    assert_eq!(counters.pending, 2);
    assert_eq!(spooled_files(spool.path()), 2);
}

/// A run that is restarted while the prover is still away picks the queue up
/// where it left it, in the order it was written.
#[test]
fn a_restart_picks_the_spool_back_up() {
    let spool = tempfile::tempdir().unwrap();
    let mut server = Server::bind();
    let witness = witness();
    {
        let prover =
            RemoteProver::connect(client(&server.addr, Some(spool.path()))).expect("connect");
        server.stop();
        for _ in 0..2 {
            prover
                .prove_group(&witness)
                .expect("no proof, but no error");
        }
    }

    server.restart();
    let prover =
        RemoteProver::connect(client(&server.addr, Some(spool.path()))).expect("reconnect");
    let deadline = Instant::now() + Duration::from_secs(30);
    while prover.counters().pending > 0 {
        assert!(
            Instant::now() < deadline,
            "the picked-up spool did not drain"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(prover.counters().recovered, 2);
    assert_eq!(recovered_files(spool.path()), 2);
}

/// A server built for one pipeline must not quietly serve another. The stage
/// that is missing has no verification key, and a witness that binds `[0; 4]`
/// would be proven against nothing.
#[test]
fn refuses_a_server_without_the_stages_this_run_needs() {
    let server = Server::bind_with(&[Stage::SlotProof]);
    let Err(error) = RemoteProver::connect(client(&server.addr, None)) else {
        panic!("a server without the group stage must not be accepted");
    };
    assert!(
        format!("{error:#}").contains("group"),
        "unexpected error: {error:#}",
    );
}

/// The version is in the handshake so a mismatch is one clear failure at
/// startup rather than a frame that deserializes into something plausible.
///
/// This assertion is a canary rather than a fact worth testing: it fails when
/// someone changes the version, which is the moment to check that they had to.
/// `Stage` is the trap. Bincode writes an enum as its discriminant index, so
/// removing a variant renumbers every stage after it and an old server's
/// "committee" becomes a new client's something-else — a frame that parses
/// into a plausible lie. Removing `Stage::Bootstrap` is why this is 2.
#[test]
fn the_protocol_version_is_checked() {
    assert_eq!(PROTOCOL_VERSION, 2);
}

/// Against a real prover server, holding a real warm prover.
///
/// Everything above runs the client against a [`NativeProver`], which returns an
/// empty proof: that covers the transport and the failure paths, and none of the
/// cryptography. This drives a `zkasper-prover-server` process — the one that
/// holds the GPU — and covers the rest: a real proof checked by `verify_child`
/// on the client's side, the warm gap measured across the wire, and an outage
/// and recovery against a server that really goes away and really comes back.
///
/// ```text
/// ZKASPER_PROVER_BIN=target/release/zkasper-prover-server ZKASPER_GPU=1 \
///   cargo test --release --test remote_prover_tests -- --ignored --nocapture
/// ```
#[test]
#[ignore = "needs a prover server binary and a Zisk proving key"]
fn proves_against_a_real_server() {
    let bin = std::env::var("ZKASPER_PROVER_BIN")
        .expect("set ZKASPER_PROVER_BIN to a zkasper-prover-server binary");
    let elf_dir = std::env::var("ZKASPER_ELF_DIR")
        .unwrap_or_else(|_| zkasper_witness_gen::prover::DEFAULT_ELF_DIR.to_string());
    let mainnet = ChainConfig::MAINNET;
    let witness = witness_at(zkasper_common::constants::ACC_TREE_DEPTH);

    let addr = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string();
    let spool = tempfile::tempdir().unwrap();
    let mut server = RealServer::spawn(&bin, &addr, &elf_dir);

    let prover = RemoteProver::connect(RemoteProverConfig {
        spool_dir: Some(spool.path().to_path_buf()),
        request_timeout: Duration::from_secs(600),
        backfill_quiet: Duration::from_secs(2),
        backfill_interval: Duration::from_secs(1),
        ..RemoteProverConfig::new(mainnet, &addr, TOKEN, STAGES)
    })
    .expect("connect to the prover server");

    let group_vk = prover.program_vk(Stage::Group);
    let slot_vk = prover.program_vk(Stage::SlotProof);
    assert_ne!(group_vk, slot_vk);

    let started = Instant::now();
    let (group, _miller, proof) = prover.prove_group(&witness).expect("group proof");
    let first = started.elapsed();
    assert!(
        !proof.is_empty(),
        "a real server must return proof words, not the native prover's empty proof",
    );
    assert!(zkasper_common::recursion::verify_child(
        &proof,
        &group_vk,
        &group.public_bytes(),
    ));
    assert!(!zkasper_common::recursion::verify_child(
        &proof,
        &slot_vk,
        &group.public_bytes(),
    ));

    // Same program, same connection, nothing re-initialised.
    let started = Instant::now();
    let (again, _, proof_again) = prover.prove_group(&witness).expect("second group proof");
    let second = started.elapsed();
    assert_eq!(again.public_bytes(), group.public_bytes());
    assert_eq!(proof_again.len(), proof.len());

    // A different program, still on the same warm prover.
    let started = Instant::now();
    let (slot, slot_proof) = prover.prove_slot(&witness).expect("slot proof");
    let third = started.elapsed();
    assert!(zkasper_common::recursion::verify_child(
        &slot_proof,
        &slot_vk,
        &slot.public_bytes(),
    ));
    println!(
        "REMOTE group={first:?} group_again={second:?} slot={third:?} cost={:?}",
        prover.last_cost(),
    );

    // The server disappears mid-run. The daemon keeps its outputs and loses only
    // the proof.
    server.kill();
    let (still, _, none) = prover
        .prove_group(&witness)
        .expect("no proof, but no error");
    assert!(none.is_empty());
    assert_eq!(still.public_bytes(), group.public_bytes());
    assert_eq!(prover.program_vk(Stage::Group), group_vk);
    assert_eq!(prover.counters().pending, 1);

    // And comes back. The next call reconnects, and the backfill proves what the
    // outage cost — the recovered proof faces the same `verify_child` the live
    // path applies, so a backfill that produced rubbish would fail here.
    server.respawn();
    let proved = prover.counters().proved;
    let deadline = Instant::now() + Duration::from_secs(600);
    while prover.counters().proved == proved {
        assert!(Instant::now() < deadline, "the server never came back");
        prover.prove_group(&witness).expect("prove");
        std::thread::sleep(Duration::from_secs(1));
    }
    while prover.counters().pending > 0 {
        assert!(Instant::now() < deadline, "the spool never drained");
        std::thread::sleep(Duration::from_secs(1));
    }
    assert_eq!(prover.counters().recovered, 1);
    assert_eq!(recovered_files(spool.path()), 1);
    println!("REMOTE counters={:?}", prover.counters());
}

/// The real server, as a child process this test can kill.
struct RealServer {
    bin: String,
    addr: String,
    elf_dir: String,
    child: Option<std::process::Child>,
}

impl RealServer {
    fn spawn(bin: &str, addr: &str, elf_dir: &str) -> Self {
        let mut server = Self {
            bin: bin.to_string(),
            addr: addr.to_string(),
            elf_dir: elf_dir.to_string(),
            child: None,
        };
        server.respawn();
        server
    }

    fn respawn(&mut self) {
        let mut command = std::process::Command::new(&self.bin);
        command
            .arg("--listen")
            .arg(&self.addr)
            .arg("--token")
            .arg(TOKEN)
            .arg("--elf-dir")
            .arg(&self.elf_dir)
            .arg("--stages")
            .arg("group,slot_proof");
        if std::env::var_os("ZKASPER_GPU").is_some() {
            command.arg("--gpu");
        }
        self.child = Some(command.spawn().expect("start the prover server"));

        // A cold `EmbeddedClient` is a minute of setup, so wait generously.
        let deadline = Instant::now() + Duration::from_secs(600);
        while TcpStream::connect(&self.addr).is_err() {
            assert!(
                Instant::now() < deadline,
                "the prover server never listened"
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        while TcpStream::connect(&self.addr).is_ok() {
            assert!(
                Instant::now() < deadline,
                "the prover server never went away"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for RealServer {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn spooled_files(dir: &Path) -> usize {
    count(dir, "req")
}

fn recovered_files(dir: &Path) -> usize {
    count(&dir.join("recovered"), "bin")
}

fn count(dir: &Path, extension: &str) -> usize {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == extension))
                .count()
        })
        .unwrap_or(0)
}
