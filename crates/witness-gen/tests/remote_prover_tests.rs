//! The network prover, against a server in the same test.
//!
//! The server runs a [`NativeProver`], so these cover the transport, the
//! handshake, the checking a returned proof goes through and — the part that
//! matters most — what the client does when the server is not there. What they
//! cannot cover is a real proof, which needs a GPU; `zisk_proof_tests` is that.

mod common;

use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::stream_fixture;

use zkasper_common::types::{CommitteeWitness, SlotProofWitness};
use zkasper_common::ChainConfig;
use zkasper_witness_gen::attestation_collector::SlotComplement;
use zkasper_witness_gen::committee_cache::{self, MemberCache, MemberTable};
use zkasper_witness_gen::prover::{NativeProver, Prover, Stage};
use zkasper_witness_gen::remote_prover::{
    serve_client, Hello, HelloReply, ProgramInfo, RemoteProver, RemoteProverConfig, Reply, Request,
    ServerConfig, PROTOCOL_VERSION,
};
use zkasper_witness_gen::split_prover::SplitProver;
use zkasper_witness_gen::streaming;

const ACC_DEPTH: u32 = 4;
const TOKEN: &str = "a-shared-secret";
const STAGES: &[Stage] = &[Stage::Group, Stage::SlotProof];

/// How long a prover may fail before the tests that check it expect a stop.
///
/// Short, because a test cannot wait out the ten minutes a deployment allows,
/// and the boundary is the same one either way: the first failure starts the
/// clock and never trips it, and a failure after the clock has run does.
const DEADLINE: Duration = Duration::from_millis(500);

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
    /// The keys this instance is holding. Replaced by `start`, so `restart`
    /// forgets them exactly as a new process would.
    members: Arc<MemberCache>,
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
            members: Arc::new(MemberCache::new()),
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
        self.members = Arc::new(MemberCache::new());
        let config = ServerConfig {
            members: self.members.clone(),
            ..ServerConfig::new(TOKEN, &self.stages)
        };
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

    // What the four calls cannot avoid: every stage runs its circuit locally
    // whether or not the prover answers, because the daemon advances on the
    // outputs its own circuits computed and not on the server's. So the floor
    // is four local runs, measured here rather than assumed -- it is 1.1 s a
    // call on an idle box and 3.4 s on a loaded one, which no constant spans.
    let floor = Instant::now();
    for _ in 0..4 {
        NativeProver::new(chain())
            .prove_group(&witness)
            .expect("the local circuit runs with or without a prover");
    }
    let floor = floor.elapsed();

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
    // An outage adds the spool write and the failed connect, and nothing else.
    // Measured 2026-08-19: the connect costs 16-137 us against a closed port and
    // the spool write 16-39 ms, against 1.1-3.4 s of circuit per call -- about
    // 3% on top of work that would have happened anyway.
    //
    // The bound is a multiple of the floor and not a constant over it, because
    // the noise scales with the floor too: two adjacent four-call blocks drift
    // 34% apart at load 38 on a 20-core box, which is 3.8 s when the floor is
    // 11 s and 0.2 s when it is idle. Twice the floor clears the worst drift
    // measured with half again to spare, and still fails long before an outage
    // could cost the daemon what the epoch costs.
    //
    // An absolute bound cannot work at all: the floor alone is 4.7-9.5 s on
    // this box. The 2 s that stood here was under the floor and could not pass
    // on any box -- and the 8 x 500 ms of connect timeouts it claimed to beat
    // were never paid either, because a closed port refuses at once and only a
    // host that drops SYNs reaches `connect_timeout`. That the outage waits on
    // nothing is asserted exactly, and load cannot move it, by `timed_out`.
    assert!(
        started.elapsed() < floor * 2,
        "four calls into an outage took {:?}, over twice the {:?} of local \
         circuit work they cannot avoid",
        started.elapsed(),
        floor,
    );

    // The witness builders bind the verification key on every stage, so it has
    // to keep answering through an outage.
    assert_eq!(prover.program_vk(Stage::Group), vk);

    let counters = prover.counters();
    assert_eq!(counters.spooled, 4, "every lost witness must be kept");
    assert_eq!(counters.unproven, 4);
    // A server that is down refuses the connection; nothing here waits one out.
    assert_eq!(counters.timed_out, 0, "an outage must not be waited out");
    assert_eq!(counters.pending, 4);
    assert_eq!(counters.dropped, 0);
    assert_eq!(spooled_files(spool.path()), 4);
}

/// A prover that is *away* must still be ridden out. The whole point of the
/// spool is that a server restarting on the far card costs proofs and not the
/// run, so the deadline that stops a daemon must not fire on a reconnect.
#[test]
fn a_prover_that_comes_back_is_ridden_out() {
    let spool = tempfile::tempdir().unwrap();
    let mut server = Server::bind();
    let prover = RemoteProver::connect(RemoteProverConfig {
        // Real enough to be checked, far longer than this outage lasts.
        unreachable_deadline: Duration::from_secs(60),
        ..client(&server.addr, Some(spool.path()))
    })
    .expect("connect");
    let witness = witness();

    server.stop();
    for _ in 0..3 {
        let (_, _, proof) = prover
            .prove_group(&witness)
            .expect("an outage is not a fault");
        assert!(proof.is_empty(), "there is nothing to prove against");
    }
    server.restart();

    let deadline = Instant::now() + Duration::from_secs(30);
    while prover.counters().proved == 0 {
        assert!(Instant::now() < deadline, "never reconnected");
        prover.prove_group(&witness).expect("still not a fault");
        std::thread::sleep(Duration::from_millis(50));
    }

    // And the clock reset with it: the outage that was is not held against the
    // next one.
    server.stop();
    prover
        .prove_group(&witness)
        .expect("the second outage starts from zero");
}

/// A prover that is *gone* is a stop condition, not a retry condition.
///
/// The GPU credit ran out on 2026-08-19 and both cards vanished. The daemon
/// spooled and retried into an empty socket for hours, filling the log and
/// making no progress, until it was stopped by hand: nothing exits, so the
/// supervisor's "NOT restarting" path — the one arrangement meant to make a
/// failure loud — never runs. Past the deadline the call fails instead, and the
/// error is what leaves the process.
#[test]
fn a_prover_that_never_comes_back_stops_the_daemon() {
    let spool = tempfile::tempdir().unwrap();
    let mut server = Server::bind();
    let prover = RemoteProver::connect(RemoteProverConfig {
        unreachable_deadline: DEADLINE,
        ..client(&server.addr, Some(spool.path()))
    })
    .expect("connect");
    let witness = witness();

    server.stop();
    // The first failure only starts the clock. One failure is not a verdict:
    // this is the call that must still ride a reconnect out.
    prover
        .prove_group(&witness)
        .expect("one failure is not a verdict");

    std::thread::sleep(2 * DEADLINE);
    let Err(error) = prover.prove_group(&witness) else {
        panic!("a prover that never came back never stopped the daemon");
    };
    let error = format!("{error:#}");

    // The message has to send the next reader to the card rather than to the
    // daemon, so it names the address and how long it was unreachable.
    assert!(error.contains(&server.addr), "unexpected error: {error}");
    assert!(
        error.contains("unreachable for"),
        "unexpected error: {error}"
    );
    assert!(
        error.contains("Check the prover server"),
        "the message must send the reader to the card: {error}",
    );

    // The witnesses are still kept: the next run picks the spool back up.
    assert!(spooled_files(spool.path()) > 0);

    // And the verdict is one-way. A card that comes back after the deadline has
    // already cost more epochs than a restart does, and whether to trust it
    // again is an operator's call rather than the process's.
    server.restart();
    assert!(
        prover.prove_group(&witness).is_err(),
        "a prover declared gone must stay gone",
    );
}

/// Two cards fail independently, and the message names the one that failed.
///
/// `--prover-route committee=<second card>` puts one stage on a second card.
/// Losing it must not be reported as losing the other: the operator is being
/// sent to a machine, and the wrong address costs the hours the last outage did.
#[test]
fn one_card_going_away_names_that_card() {
    let groups = Server::bind_with(&[Stage::Group]);
    let mut slots = Server::bind_with(&[Stage::SlotProof]);
    let group_spool = tempfile::tempdir().unwrap();
    let slot_spool = tempfile::tempdir().unwrap();

    let split = SplitProver::new(
        Box::new(
            RemoteProver::connect(RemoteProverConfig {
                stages: vec![Stage::Group],
                unreachable_deadline: DEADLINE,
                ..client(&groups.addr, Some(group_spool.path()))
            })
            .expect("connect to the group prover"),
        ),
        vec![(
            Stage::SlotProof,
            Box::new(
                RemoteProver::connect(RemoteProverConfig {
                    stages: vec![Stage::SlotProof],
                    unreachable_deadline: DEADLINE,
                    ..client(&slots.addr, Some(slot_spool.path()))
                })
                .expect("connect to the slot prover"),
            ) as Box<dyn Prover>,
        )],
    )
    .expect("split");

    let witness = witness();
    slots.stop();
    split
        .prove_slot(&witness)
        .expect("one failure is not a verdict");

    std::thread::sleep(2 * DEADLINE);
    let Err(error) = split.prove_slot(&witness) else {
        panic!("the lost card never stopped the run");
    };
    let error = format!("{error:#}");

    assert!(error.contains(&slots.addr), "unexpected error: {error}");
    assert!(
        !error.contains(&groups.addr),
        "the card that is up must not be named: {error}",
    );
    split
        .prove_group(&witness)
        .expect("the live card is unaffected by the dead one");
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

/// A server that holds the ELF and answers with nothing is a fault, not a
/// witness-only run.
///
/// An empty proof is a legitimate value everywhere else here — it is what a
/// witness-only build produces and what an outage hands back — and `check` will
/// not separate the cases, because off-target `verify_child` accepts an empty
/// proof so circuit logic can be exercised without a prover. What separates
/// them is the handshake: a server with no ELF digest has no prover, and one
/// that reported a digest for this stage said it could prove it. Taking its
/// empty answer for a proof is how an epoch reaches a consumer as `proven` with
/// nothing behind it, so it is refused where it arrives.
#[test]
fn an_empty_proof_from_a_real_prover_is_refused() {
    let spool = tempfile::tempdir().unwrap();
    let server = EmptyProver::bind();
    let prover = RemoteProver::connect(client(&server.addr, Some(spool.path()))).expect("connect");

    let error = format!(
        "{:#}",
        prover
            .prove_group(&witness())
            .expect_err("an empty proof from a prover that has an ELF is not a proof"),
    );
    assert!(error.contains("empty proof"), "unexpected error: {error}");
    assert!(error.contains(&server.addr), "unexpected error: {error}");

    // Not spooled: the same server would answer a retry the same way, which is
    // why a refusal is not spooled either.
    let counters = prover.counters();
    assert_eq!(counters.proved, 0, "nothing was proved");
    assert_eq!(counters.spooled, 0);
    assert_eq!(spooled_files(spool.path()), 0);
}

/// A server that speaks the protocol, reports an ELF for every stage, and
/// answers every witness with no proof at all.
///
/// Hand-rolled rather than a [`Prover`] behind [`serve_client`], because what
/// is under test is the claim the handshake makes and not any circuit: the
/// frames are a length and a bincode value, and there are three of them.
struct EmptyProver {
    addr: String,
}

impl EmptyProver {
    fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let native = NativeProver::new(chain());
        let programs: Vec<ProgramInfo> = STAGES
            .iter()
            .map(|&stage| ProgramInfo {
                stage,
                vk: native.program_vk(stage),
                elf_sha256: Some(format!("0x{}", "ab".repeat(32))),
            })
            .collect();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                let programs = programs.clone();
                std::thread::spawn(move || {
                    let Ok(hello) = read_frame::<Hello>(&mut stream) else {
                        return;
                    };
                    assert_eq!(hello.version, PROTOCOL_VERSION);
                    let ready = HelloReply::Ready {
                        prover: "a prover that answers with nothing".to_string(),
                        programs,
                        member_table: None,
                    };
                    if write_frame(&mut stream, &ready).is_err() {
                        return;
                    }
                    while read_frame::<Request>(&mut stream).is_ok() {
                        let reply = Reply::Proved {
                            proof: Vec::new(),
                            cost: Default::default(),
                        };
                        if write_frame(&mut stream, &reply).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self { addr }
    }
}

fn write_frame<T: serde::Serialize>(w: &mut impl std::io::Write, value: &T) -> std::io::Result<()> {
    let bytes = bincode::serialize(value).expect("serialize a frame");
    w.write_all(&(bytes.len() as u32).to_le_bytes())?;
    w.write_all(&bytes)?;
    w.flush()
}

fn read_frame<T: serde::de::DeserializeOwned>(r: &mut impl std::io::Read) -> std::io::Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let mut bytes = vec![0u8; u32::from_le_bytes(len) as usize];
    r.read_exact(&mut bytes)?;
    bincode::deserialize(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// A prover process can go sick without going away, and the second ask is what
/// says so.
///
/// On 2026-08-19 production died on one refusal: a committee witness of an
/// ordinary shape was refused with an assert in `VerifyFinalPol0`, and the same
/// witness proved cleanly against the same card once the server process there
/// had been restarted. The witness was never the variable. A run that is meant
/// to hold unattended for a day must survive that, so the witness is offered
/// once more before the refusal is believed.
#[test]
fn a_witness_refused_once_is_proved_on_the_second_ask() {
    let spool = tempfile::tempdir().unwrap();
    let server = FickleProver::bind(1);
    let prover = RemoteProver::connect(client(&server.addr, Some(spool.path()))).expect("connect");

    let witness = witness();
    let (output, _miller, _proof) = prover
        .prove_group(&witness)
        .expect("one refusal must not end the run");
    let (local, _, _) = NativeProver::new(chain()).prove_group(&witness).unwrap();
    assert_eq!(output.public_bytes(), local.public_bytes());

    assert_eq!(
        server.asked(),
        2,
        "the witness must be offered exactly twice"
    );
    let counters = prover.counters();
    assert_eq!(
        counters.proved, 1,
        "the second ask is a proof like any other"
    );
    assert_eq!(counters.spooled, 0, "a refusal is never spooled");
    assert_eq!(spooled_files(spool.path()), 0);
}

/// Two identical refusals are a bad witness, and a bad witness still stops the
/// run.
///
/// This is the property the retry is not allowed to cost. A witness the circuit
/// will not take poisons every epoch that folds it, and asking a third time
/// only turns a loud failure into a loop.
#[test]
fn a_witness_refused_twice_still_stops_the_run() {
    let spool = tempfile::tempdir().unwrap();
    let server = FickleProver::bind(usize::MAX);
    let prover = RemoteProver::connect(client(&server.addr, Some(spool.path()))).expect("connect");

    let error = format!(
        "{:#}",
        prover
            .prove_group(&witness())
            .expect_err("a witness the circuit refuses twice is a stop condition"),
    );
    assert!(error.contains("refused"), "unexpected error: {error}");
    assert!(error.contains(&server.addr), "unexpected error: {error}");
    assert!(error.contains(REFUSAL), "unexpected error: {error}");

    assert_eq!(server.asked(), 2, "a third ask would be a retry loop");
    let counters = prover.counters();
    assert_eq!(counters.proved, 0, "nothing was proved");
    assert_eq!(counters.spooled, 0, "a refusal is never spooled");
    assert_eq!(spooled_files(spool.path()), 0);
}

/// What the fickle server says when it refuses.
const REFUSAL: &str = "Error generating witness for instance id 0";

/// A server that refuses the first `refusals` witnesses and proves the rest.
///
/// Hand-rolled for the same reason [`EmptyProver`] is: what is under test is
/// the reply, and a [`NativeProver`] behind [`serve_client`] has no way to be
/// told to say no. It reports no ELF, so its empty proof is the legitimate
/// answer of a witness-only server rather than the fault `reject_empty` catches
/// — which is what every other server in this file does too.
struct FickleProver {
    addr: String,
    asked: Arc<AtomicUsize>,
}

impl FickleProver {
    fn bind(refusals: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let native = NativeProver::new(chain());
        let programs: Vec<ProgramInfo> = STAGES
            .iter()
            .map(|&stage| ProgramInfo {
                stage,
                vk: native.program_vk(stage),
                elf_sha256: None,
            })
            .collect();
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = asked.clone();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                let programs = programs.clone();
                let counter = counter.clone();
                std::thread::spawn(move || {
                    let Ok(hello) = read_frame::<Hello>(&mut stream) else {
                        return;
                    };
                    assert_eq!(hello.version, PROTOCOL_VERSION);
                    let ready = HelloReply::Ready {
                        prover: "a prover that is sick and then is not".to_string(),
                        programs,
                        member_table: None,
                    };
                    if write_frame(&mut stream, &ready).is_err() {
                        return;
                    }
                    while read_frame::<Request>(&mut stream).is_ok() {
                        let asked = counter.fetch_add(1, Ordering::Relaxed);
                        let reply = if asked < refusals {
                            Reply::Failed(format!(
                                "Proof error: {REFUSAL} [0:0] of type Recursive2"
                            ))
                        } else {
                            Reply::Proved {
                                proof: Vec::new(),
                                cost: Default::default(),
                            }
                        };
                        if write_frame(&mut stream, &reply).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self { addr, asked }
    }

    /// How many witnesses have reached the circuit.
    fn asked(&self) -> usize {
        self.asked.load(Ordering::Relaxed)
    }
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
/// into a plausible lie. Removing `Stage::Bootstrap` is why this became 2.
///
/// The witness and output types are the same trap in a different place: bincode
/// is positional, so a field added to one of them shifts everything after it and
/// an old peer reads a plausible lie again. `JustificationWitness` gaining a
/// previous link, and `JustificationOutput` gaining its running state, is why
/// this is 3.
///
/// 4 is the child-key change: every witness lost the program keys it used to
/// name, because the guests bake them now, and the three fold chains gained a
/// published `program_vk` for the one key a program cannot bake — its own. Four
/// witness types and three output types moved at once, which is exactly the
/// shape of frame an old peer would read as a plausible lie.
///
/// 5 is the proof itself: children are uncompressed `vadcop_final` proofs now,
/// so the program key sits one word later and a version-4 peer would read a
/// plausible lie out of the bytes rather than fail to parse them.
///
/// 6 is the committee member cache: a new `Request`, a new `Reply`, and a
/// `HelloReply` that reports which keys the server is holding. The last of
/// those is why this one cannot wait to be discovered at the first proof — a
/// version-5 `HelloReply` read by a version-6 client leaves the client
/// believing a server holds keys it has never seen, which is the one mistake
/// the cache exists to make impossible.
#[test]
fn the_protocol_version_is_checked() {
    assert_eq!(PROTOCOL_VERSION, 6);
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

// ---------------------------------------------------------------------------
// The committee member cache
// ---------------------------------------------------------------------------
//
// The committee witness is 95% public keys the far end already has, and the
// link is 1.61 MB/s. These cover the three things that have to hold for the
// keys to be left there safely: they cross once, a server that has forgotten
// them says so, and a witness rebuilt out of the wrong ones is refused rather
// than proven.

const COMMITTEE_STAGES: &[Stage] = &[Stage::Committee];

fn committee_witness() -> CommitteeWitness {
    stream_fixture(ACC_DEPTH).epoch.committees.witness.clone()
}

fn committee_client(addr: &str) -> RemoteProverConfig {
    RemoteProverConfig {
        stages: COMMITTEE_STAGES.to_vec(),
        ..client(addr, None)
    }
}

/// What one `ProveCommittee` request carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sent {
    every_key: bool,
    keys: usize,
    frame_bytes: usize,
}

/// A server that records what it is sent, and can be told to forget the keys
/// without dropping the connection.
///
/// It answers with the empty proof, which the client takes because no ELF
/// digest is offered — the same shape as a witness-only server. What is under
/// test here is the wire and not the cryptography.
struct Recorder {
    addr: String,
    sent: Arc<Mutex<Vec<Sent>>>,
    forget: Arc<AtomicBool>,
}

impl Recorder {
    fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let native = NativeProver::new(chain());
        let programs: Vec<ProgramInfo> = COMMITTEE_STAGES
            .iter()
            .map(|&stage| ProgramInfo {
                stage,
                vk: native.program_vk(stage),
                elf_sha256: None,
            })
            .collect();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let forget = Arc::new(AtomicBool::new(false));
        let (recorded, forgotten) = (sent.clone(), forget.clone());
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                let programs = programs.clone();
                let recorded = recorded.clone();
                let forgotten = forgotten.clone();
                std::thread::spawn(move || {
                    let Ok(hello) = read_frame::<Hello>(&mut stream) else {
                        return;
                    };
                    assert_eq!(hello.version, PROTOCOL_VERSION);
                    let ready = HelloReply::Ready {
                        prover: "a prover that writes down what it is sent".to_string(),
                        programs,
                        member_table: None,
                    };
                    if write_frame(&mut stream, &ready).is_err() {
                        return;
                    }
                    while let Ok(request) = read_frame::<Request>(&mut stream) {
                        let frame_bytes = bincode::serialized_size(&request).unwrap() as usize;
                        let Request::ProveCommittee { table, .. } = &request else {
                            panic!("the committee stage should not be sent whole");
                        };
                        recorded.lock().unwrap().push(Sent {
                            every_key: matches!(table, MemberTable::Full(_)),
                            keys: table.len(),
                            frame_bytes,
                        });
                        // Forgotten once, so the client's answer to it is what
                        // the next frame shows.
                        let reply = if forgotten.swap(false, Ordering::Relaxed) {
                            Reply::NeedMemberTable
                        } else {
                            Reply::Proved {
                                proof: Vec::new(),
                                cost: Default::default(),
                            }
                        };
                        if write_frame(&mut stream, &reply).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self { addr, sent, forget }
    }

    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }
}

/// The keys cross once. Everything after is the epoch's own columns.
///
/// This is the whole point of the change: at 1.61 MB/s the committee witness
/// was 70 s of wire on a budget with 90 s of margin, and it opened the epoch
/// just after the chain had already crossed two thirds.
#[test]
fn a_cold_prover_is_sent_every_key_and_a_warm_one_is_not() {
    let server = Recorder::bind();
    let prover = RemoteProver::connect(committee_client(&server.addr)).expect("connect");
    let witness = committee_witness();

    prover.prove_committee(&witness).expect("the first epoch");
    prover.prove_committee(&witness).expect("the second epoch");

    let sent = server.sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert!(sent[0].every_key, "a cold server is sent the table");
    assert_eq!(sent[0].keys, witness.members.len());
    assert!(!sent[1].every_key, "a warm server is not");
    assert_eq!(sent[1].keys, 0, "and nothing activated between the two");
    assert!(
        sent[1].frame_bytes * 4 < sent[0].frame_bytes,
        "the warm epoch should be a fraction of the cold one: {sent:?}",
    );
}

/// A server that has forgotten the keys says so, and is sent them.
///
/// The connection is deliberately kept up, because this is the case the
/// handshake cannot cover: a prover restarted between two epochs is caught when
/// the client redials, but one that lost its table any other way is only ever
/// found out by asking it to use it.
#[test]
fn a_prover_that_forgot_the_keys_is_sent_them_again() {
    let server = Recorder::bind();
    let prover = RemoteProver::connect(committee_client(&server.addr)).expect("connect");
    let witness = committee_witness();

    prover.prove_committee(&witness).expect("the first epoch");
    server.forget.store(true, Ordering::Relaxed);
    prover
        .prove_committee(&witness)
        .expect("the epoch still lands after the keys are asked for again");

    let sent = server.sent();
    assert_eq!(sent.len(), 3, "{sent:?}");
    assert!(sent[0].every_key, "cold");
    assert!(!sent[1].every_key, "warm, and refused");
    assert!(sent[2].every_key, "so the keys go again");
    assert_eq!(sent[2].keys, witness.members.len());

    // And the run is warm again afterwards rather than stuck resending.
    prover.prove_committee(&witness).expect("the third epoch");
    assert!(!server.sent()[3].every_key, "{:?}", server.sent());
}

/// A restarted prover is sent the keys off the handshake, without spending an
/// epoch's columns to find out.
#[test]
fn a_restarted_prover_is_sent_the_keys_without_asking() {
    let mut server = Server::bind_with(COMMITTEE_STAGES);
    let prover = RemoteProver::connect(committee_client(&server.addr)).expect("connect");
    let witness = committee_witness();

    prover.prove_committee(&witness).expect("the first epoch");
    let held = server.members.newest().expect("the server took the keys");

    // A new process on the same address, holding nothing.
    server.stop();
    server.restart();
    assert_eq!(server.members.newest(), None, "a restart forgets the table");

    prover
        .prove_committee(&witness)
        .expect("the epoch after a prover restart");
    assert_eq!(
        server.members.newest(),
        Some(held),
        "the same keys, so the same table",
    );
}

/// Two servers, two caches, and neither one's table is the other's.
///
/// `--prover-route committee=<second card>` puts the committee stage on its own
/// server, and a daemon that fails over to another one must send it the keys
/// rather than name a table that server has never held.
#[test]
fn a_second_prover_gets_its_own_table() {
    let first = Server::bind_with(COMMITTEE_STAGES);
    let second = Server::bind_with(COMMITTEE_STAGES);
    let witness = committee_witness();

    let to_first = RemoteProver::connect(committee_client(&first.addr)).expect("connect");
    to_first.prove_committee(&witness).expect("the first card");

    let to_second = RemoteProver::connect(committee_client(&second.addr)).expect("connect");
    to_second
        .prove_committee(&witness)
        .expect("the second card");

    assert_eq!(
        first.members.newest(),
        second.members.newest(),
        "the same keys either side, because it is the same epoch",
    );
    // Each card was sent them, rather than one being told the other holds them.
    assert!(first.members.newest().is_some());
    assert!(second.members.newest().is_some());
}

/// A witness rebuilt out of keys the client did not use is refused, not proven.
///
/// This is the backstop the whole scheme rests on. Everything above is about
/// keeping the far end's table right; this is what happens when it is wrong
/// anyway. The server hashes what it rebuilt against the digest the client
/// computed over the bytes it would have sent, so the alternative to a matching
/// digest is a refusal and never a proof of something else.
#[test]
fn a_rebuilt_witness_that_does_not_hash_to_the_clients_is_refused() {
    let server = Server::bind_with(COMMITTEE_STAGES);
    let witness = committee_witness();
    let delta = committee_cache::encode(&witness).expect("it encodes");
    let table = MemberTable::full(&witness.members);

    // The witness the client is claiming, which is not the one the columns
    // describe. A stale table on the far end lands in exactly this shape.
    let mut other = committee_witness();
    other.total_active_balance += 1;
    let claimed = committee_cache::witness_digest(&bincode::serialize(&other).unwrap());

    let mut stream = TcpStream::connect(&server.addr).unwrap();
    write_frame(
        &mut stream,
        &Hello {
            version: PROTOCOL_VERSION,
            token: TOKEN.to_string(),
        },
    )
    .unwrap();
    let reply: HelloReply = read_frame(&mut stream).unwrap();
    assert!(matches!(reply, HelloReply::Ready { .. }));

    write_frame(
        &mut stream,
        &Request::ProveCommittee {
            table,
            delta: Box::new(delta),
            witness_digest: claimed,
        },
    )
    .unwrap();
    match read_frame::<Reply>(&mut stream).unwrap() {
        Reply::Failed(reason) => assert!(
            reason.contains("not the one the client believes"),
            "the refusal should name the fault: {reason}",
        ),
        other => panic!("a witness that does not hash to its digest was not refused: {other:?}"),
    }
}

/// The far end can still be sent a committee witness whole, and it proves the
/// same thing.
///
/// The spool drains that way — a witness that waited out an outage names no
/// keys, because the server it eventually reaches has never heard of this run.
#[test]
fn a_committee_witness_sent_whole_is_still_served() {
    let server = Server::bind_with(COMMITTEE_STAGES);
    let witness = committee_witness();

    let mut stream = TcpStream::connect(&server.addr).unwrap();
    write_frame(
        &mut stream,
        &Hello {
            version: PROTOCOL_VERSION,
            token: TOKEN.to_string(),
        },
    )
    .unwrap();
    let _: HelloReply = read_frame(&mut stream).unwrap();

    write_frame(
        &mut stream,
        &Request::Prove {
            stage: Stage::Committee,
            witness: bincode::serialize(&witness).unwrap(),
        },
    )
    .unwrap();
    assert!(
        matches!(
            read_frame::<Reply>(&mut stream).unwrap(),
            Reply::Proved { .. }
        ),
        "a whole committee witness should still prove",
    );
    assert_eq!(
        server.members.newest(),
        None,
        "and it should not have put anything in the cache",
    );
}

// ---------------------------------------------------------------------------
// The native run a prover server does not need
// ---------------------------------------------------------------------------

/// Counts which of the two committee methods it was asked for.
///
/// Everything else goes straight through to a real [`NativeProver`], so the
/// server under test is the real one answering with real proofs.
struct CountingProver {
    inner: NativeProver,
    full: Arc<AtomicUsize>,
    only: Arc<AtomicUsize>,
}

impl Prover for CountingProver {
    fn name(&self) -> &'static str {
        "native (counting which committee method is asked for)"
    }

    fn program_vk(&self, stage: Stage) -> zkasper_common::recursion::ProgramVk {
        self.inner.program_vk(stage)
    }

    fn prove_committee(
        &self,
        witness: &CommitteeWitness,
    ) -> Result<(zkasper_common::types::CommitteeOutput, Vec<u64>), anyhow::Error> {
        self.full.fetch_add(1, Ordering::Relaxed);
        self.inner.prove_committee(witness)
    }

    fn prove_committee_only(&self, witness: &CommitteeWitness) -> Result<Vec<u64>, anyhow::Error> {
        self.only.fetch_add(1, Ordering::Relaxed);
        // Deliberately the default's body rather than `self.prove_committee`,
        // so the count says which the *caller* asked for.
        Ok(self.inner.prove_committee(witness)?.1)
    }

    fn prove_epoch_diff(
        &self,
        w: &zkasper_common::types::EpochDiffWitness,
    ) -> Result<(zkasper_common::types::EpochDiffOutput, Vec<u64>), anyhow::Error> {
        self.inner.prove_epoch_diff(w)
    }

    fn prove_slot(
        &self,
        w: &SlotProofWitness,
    ) -> Result<(zkasper_common::types::SlotProofOutput, Vec<u64>), anyhow::Error> {
        self.inner.prove_slot(w)
    }

    fn prove_justification(
        &self,
        w: &zkasper_common::types::JustificationWitness,
    ) -> Result<(zkasper_common::types::JustificationOutput, Vec<u64>), anyhow::Error> {
        self.inner.prove_justification(w)
    }

    fn prove_finalization(
        &self,
        w: &zkasper_common::types::FinalizationWitness,
    ) -> Result<(zkasper_common::types::FinalizationOutput, Vec<u64>), anyhow::Error> {
        self.inner.prove_finalization(w)
    }

    fn prove_group(
        &self,
        w: &SlotProofWitness,
    ) -> Result<
        (
            zkasper_common::types::GroupProofOutput,
            zkasper_common::bls::Fp12,
            Vec<u64>,
        ),
        anyhow::Error,
    > {
        self.inner.prove_group(w)
    }

    fn prove_aggregate(
        &self,
        w: &zkasper_common::types::AggregateWitness,
    ) -> Result<(zkasper_common::types::AggregateOutput, Vec<u64>), anyhow::Error> {
        self.inner.prove_aggregate(w)
    }

    fn prove_stream_final(
        &self,
        w: &zkasper_common::types::StreamFinalWitness,
    ) -> Result<(zkasper_common::types::StreamFinalOutput, Vec<u64>), anyhow::Error> {
        self.inner.prove_stream_final(w)
    }
}

/// A server asks for the proof and not for the outputs.
///
/// The outputs cost a full native run of the circuit — 13.39 s on the real
/// mainnet witness — and are dropped one line after they are produced. The
/// client computed them before it sent anything.
#[test]
fn a_server_does_not_compute_outputs_it_throws_away() {
    let full = Arc::new(AtomicUsize::new(0));
    let only = Arc::new(AtomicUsize::new(0));
    let witness = committee_witness();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (counted_full, counted_only) = (full.clone(), only.clone());
    std::thread::spawn(move || {
        let prover = CountingProver {
            inner: NativeProver::new(chain()),
            full: counted_full,
            only: counted_only,
        };
        let config = ServerConfig::new(TOKEN, COMMITTEE_STAGES);
        while let Ok((stream, _)) = listener.accept() {
            let _ = serve_client(stream, &prover, &config);
        }
    });

    let prover = RemoteProver::connect(committee_client(&addr)).expect("connect");
    prover.prove_committee(&witness).expect("cold");
    prover.prove_committee(&witness).expect("warm");

    assert_eq!(
        only.load(Ordering::Relaxed),
        2,
        "both epochs took the cheap path"
    );
    assert_eq!(
        full.load(Ordering::Relaxed),
        0,
        "no epoch asked the card for outputs nobody reads",
    );
}

/// A witness sent whole keeps the native run, because that path has no digest.
///
/// This is the spool draining after an outage, not an epoch waiting, so the
/// guard is worth its seconds there.
#[test]
fn a_committee_witness_sent_whole_still_runs_the_circuit() {
    let full = Arc::new(AtomicUsize::new(0));
    let only = Arc::new(AtomicUsize::new(0));
    let witness = committee_witness();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (counted_full, counted_only) = (full.clone(), only.clone());
    std::thread::spawn(move || {
        let prover = CountingProver {
            inner: NativeProver::new(chain()),
            full: counted_full,
            only: counted_only,
        };
        let config = ServerConfig::new(TOKEN, COMMITTEE_STAGES);
        while let Ok((stream, _)) = listener.accept() {
            let _ = serve_client(stream, &prover, &config);
        }
    });

    let mut stream = TcpStream::connect(&addr).unwrap();
    write_frame(
        &mut stream,
        &Hello {
            version: PROTOCOL_VERSION,
            token: TOKEN.to_string(),
        },
    )
    .unwrap();
    let _: HelloReply = read_frame(&mut stream).unwrap();
    write_frame(
        &mut stream,
        &Request::Prove {
            stage: Stage::Committee,
            witness: bincode::serialize(&witness).unwrap(),
        },
    )
    .unwrap();
    assert!(matches!(
        read_frame::<Reply>(&mut stream).unwrap(),
        Reply::Proved { .. }
    ));

    assert_eq!(
        full.load(Ordering::Relaxed),
        1,
        "the whole-witness path checks"
    );
    assert_eq!(only.load(Ordering::Relaxed), 0);
}

/// A prover that does not override it behaves exactly as it did.
#[test]
fn the_default_still_runs_the_circuit_and_still_rejects_a_bad_witness() {
    let native = NativeProver::new(chain());
    let witness = committee_witness();
    assert!(native.prove_committee_only(&witness).is_ok());

    // The circuit is still what answers, so a witness it will not take is still
    // refused by the default.
    let mut bad = committee_witness();
    bad.acc_root = [9, 9, 9, 9];
    assert!(native.prove_committee(&bad).is_err());
    assert!(
        native.prove_committee_only(&bad).is_err(),
        "the default is the old method with the outputs dropped",
    );
}

/// The overlap every restart has, and what it used to cost.
///
/// A daemon's socket outlives the process that opened it, so a replacement
/// starts while its predecessor is still connected and still proving. On
/// 2026-08-19 the server held one table: the outgoing daemon took the slot at
/// 23:35:23, and the incoming daemon's first witness two minutes later carried
/// all 961k keys again — 108 MB and 49 s, on a link that had just been cut to
/// 5 s. Neither daemon was at fault and neither log said so.
#[test]
fn a_daemon_starting_under_its_predecessor_does_not_cost_it_its_keys() {
    let server = Server::bind_with(COMMITTEE_STAGES);
    let witness = committee_witness();

    let outgoing = RemoteProver::connect(committee_client(&server.addr)).expect("connect");
    outgoing
        .prove_committee(&witness)
        .expect("the outgoing daemon's epoch");
    let table = server.members.newest().expect("the server took the keys");

    // The replacement starts while the first is still connected and proving.
    let incoming = RemoteProver::connect(committee_client(&server.addr)).expect("connect");
    incoming
        .prove_committee(&witness)
        .expect("the incoming daemon's first epoch");
    assert!(
        server.members.holds(&table),
        "the incoming daemon must not evict the table the outgoing one is using",
    );

    // Both are warm from here, and neither was asked for its keys again.
    outgoing
        .prove_committee(&witness)
        .expect("the outgoing daemon, still warm");
    incoming
        .prove_committee(&witness)
        .expect("the incoming daemon, warm");
    assert!(server.members.holds(&table));
}
