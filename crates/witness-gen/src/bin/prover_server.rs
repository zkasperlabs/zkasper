//! The process that owns the GPU.
//!
//! It builds one `zisk-sdk` `EmbeddedClient` and holds it for the life of the
//! process, then answers proof requests over the wire. That is not a style
//! choice: `ensure_single_instance()` panics on a second client per process and
//! never clears the flag, so a client cannot be dropped and rebuilt, and a cold
//! start costs 5.80 s against a 3.640 s stage floor. Everything the warm prover
//! is worth depends on this process staying up.
//!
//! Run it on the rented GPU machine, and `zkasperd --prover remote` against it
//! on the stable machine. See `crate::remote_prover` for the protocol and
//! `docs/architecture.md` for why the two are not the same box.
//!
//! ```text
//! ZKASPER_PROVER_TOKEN=... zkasper-prover-server --gpu --listen 0.0.0.0:9099 \
//!     --mode streaming
//! ```
//!
//! Built without `--features zisk-prover` it refuses to start, because a prover
//! server that cannot prove is worse than one that is not there: the daemon
//! would connect, bind empty verification keys and publish proofless epochs.

use std::net::TcpListener;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use tracing::info;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

use zkasper_witness_gen::orchestrator::Pipeline;
use zkasper_witness_gen::prover::Stage;
use zkasper_witness_gen::remote_prover::{serve, ServerConfig};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Batch,
    Streaming,
    /// Set every stage up. Costs a ROM setup and gigabytes of `~/.zisk/cache`
    /// per guest, and is what a server that outlives one daemon wants.
    All,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Chain {
    Mainnet,
    Gnosis,
}

#[derive(Parser, Debug)]
#[command(name = "zkasper-prover-server", about = "Serve Zisk proofs over TCP")]
struct Cli {
    /// Address to listen on. Bind it to a private interface: the token is sent
    /// in the clear.
    #[arg(long, default_value = "127.0.0.1:9099")]
    listen: String,

    /// Shared secret a client must present.
    #[arg(long, env = "ZKASPER_PROVER_TOKEN")]
    token: String,

    /// Which stages to set up.
    #[arg(long, default_value = "streaming")]
    mode: Mode,

    #[arg(long, default_value = "mainnet")]
    chain: Chain,

    /// Directory holding the guest ELFs.
    #[arg(long, default_value = zkasper_witness_gen::zisk_prover::DEFAULT_ELF_DIR)]
    #[cfg(feature = "zisk-prover")]
    elf_dir: std::path::PathBuf,

    /// Prove on the GPU. Without it this server proves on the CPU, whatever the
    /// box has.
    #[arg(long)]
    #[cfg(feature = "zisk-prover")]
    gpu: bool,

    /// Proving key directory. Defaults to Zisk's own, `~/.zisk/provingKey`.
    #[arg(long)]
    #[cfg(feature = "zisk-prover")]
    proving_key: Option<std::path::PathBuf>,

    /// How long a client connection may sit idle before it is closed.
    #[arg(long, default_value_t = 900)]
    idle_seconds: u64,
}

impl Chain {
    #[cfg(feature = "zisk-prover")]
    fn config(self) -> zkasper_common::ChainConfig {
        match self {
            Chain::Mainnet => zkasper_common::ChainConfig::MAINNET,
            Chain::Gnosis => zkasper_common::ChainConfig::GNOSIS,
        }
    }
}

impl Mode {
    fn stages(self) -> Vec<Stage> {
        match self {
            Mode::Batch => Pipeline::Batch.stages().to_vec(),
            Mode::Streaming => Pipeline::Streaming.stages().to_vec(),
            Mode::All => {
                let mut stages = Pipeline::Batch.stages().to_vec();
                for stage in Pipeline::Streaming.stages() {
                    if !stages.contains(stage) {
                        stages.push(*stage);
                    }
                }
                stages
            }
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .init();

    let stages = cli.mode.stages();
    let prover = build_prover(&cli, &stages)?;
    info!(
        prover = prover.name(),
        stages = stages.len(),
        "prover ready"
    );

    let listener = TcpListener::bind(&cli.listen)?;
    serve(
        &listener,
        prover,
        ServerConfig {
            idle_timeout: std::time::Duration::from_secs(cli.idle_seconds),
            ..ServerConfig::new(cli.token, &stages)
        },
    )
}

/// The one client, built before the socket is opened so a broken setup fails
/// here rather than at a daemon's first proof.
#[cfg(feature = "zisk-prover")]
fn build_prover(
    cli: &Cli,
    stages: &[Stage],
) -> Result<Arc<dyn zkasper_witness_gen::prover::Prover>> {
    use zkasper_witness_gen::zisk_prover::{ZiskProver, ZiskProverConfig};
    Ok(Arc::new(ZiskProver::new(ZiskProverConfig {
        elf_dir: cli.elf_dir.clone(),
        gpu: cli.gpu,
        proving_key: cli.proving_key.clone(),
        ..ZiskProverConfig::new(cli.chain.config(), stages)
    })?))
}

#[cfg(not(feature = "zisk-prover"))]
fn build_prover(
    _cli: &Cli,
    _stages: &[Stage],
) -> Result<Arc<dyn zkasper_witness_gen::prover::Prover>> {
    anyhow::bail!(
        "this binary was built without the `zisk-prover` feature; \
         rebuild with `cargo build --release --features zisk-prover`",
    )
}
