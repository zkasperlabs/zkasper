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
    let fixture = stream_fixture(ACC_DEPTH);
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
    prover.prove_group(&witness).expect("the first proof");

    let vk = prover.program_vk(Stage::Group);
    server.stop();

    // Two epochs' worth of stages, against a prover that is not there.
    let started = Instant::now();
    for _ in 0..4 {
        assert!(prover.prove_group(&witness).is_err());
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
    assert_eq!(counters.pending, 4);
    assert_eq!(counters.dropped, 0);
    assert_eq!(spooled_files(spool.path()), 4);
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
        assert!(prover.prove_group(&witness).is_err());
    }
    assert_eq!(prover.counters().pending, 3);

    server.restart();
    // The backoff from the last failed connect has to expire first.
    let deadline = Instant::now() + Duration::from_secs(10);
    while prover.prove_group(&witness).is_err() {
        assert!(Instant::now() < deadline, "never reconnected");
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
        assert!(prover.prove_group(&witness).is_err());
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
            assert!(prover.prove_group(&witness).is_err());
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
#[test]
fn the_protocol_version_is_checked() {
    assert_eq!(PROTOCOL_VERSION, 1);
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
