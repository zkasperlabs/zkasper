//! zkasperd — the continuous witness generator.
//!
//! Bootstraps an accumulator from a recent finalized state, then follows the
//! chain: one epoch diff per epoch, slot proofs as attestations arrive, a
//! justification the moment 2/3 is crossed, and a finalization when two
//! consecutive epochs justify.
//!
//! Built without `--features zisk-prover` it produces witnesses and no proofs;
//! with it, and `--prover zisk`, it produces real ones from a prover that is
//! initialised once and kept warm for the life of the process. See
//! `crate::prover` and `crate::zisk_prover`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use tracing::info;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

use zkasper_common::ChainConfig;
use zkasper_witness_gen::beacon_api::BeaconApiClient;
use zkasper_witness_gen::orchestrator::{Orchestrator, OrchestratorConfig, Pipeline};
use zkasper_witness_gen::prover::{NativeProver, Prover};

#[derive(Clone, Copy, ValueEnum)]
enum Chain {
    Mainnet,
    Gnosis,
}

/// Which pipeline to prove epochs with.
#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Batch,
    Streaming,
}

/// What produces the proofs.
#[derive(Clone, Copy, ValueEnum)]
enum Backend {
    /// Run the circuits, produce no proofs. Every witness is still checked by
    /// the logic that would prove it.
    Native,
    /// Real Zisk proofs, from one prover held open for the whole run.
    Zisk,
}

impl Chain {
    fn config(self) -> ChainConfig {
        match self {
            Chain::Mainnet => ChainConfig::MAINNET,
            Chain::Gnosis => ChainConfig::GNOSIS,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Chain::Mainnet => "mainnet",
            Chain::Gnosis => "gnosis",
        }
    }
}

#[derive(Parser)]
#[command(name = "zkasperd")]
#[command(about = "Continuous witness generation for zkasper finality proofs")]
struct Cli {
    /// Beacon node API URL
    #[arg(long, env = "BEACON_API_URL")]
    beacon_url: String,

    /// Persistent accumulator state
    #[arg(long, default_value = "zkasperd.db")]
    db_path: PathBuf,

    /// Directory for witness files and status.json
    #[arg(long, default_value = "zkasper-out")]
    output_dir: PathBuf,

    /// Target chain
    #[arg(long, default_value = "mainnet")]
    chain: Chain,

    /// Slot to bootstrap from. Defaults to the node's finalized checkpoint.
    /// Ignored when the state file already exists.
    #[arg(long)]
    bootstrap_slot: Option<u64>,

    /// Attestation signing domain (hex). Derived from the node's fork and
    /// genesis when not given.
    #[arg(long)]
    signing_domain: Option<String>,

    /// Seconds to wait after a poll that found nothing new
    #[arg(long, default_value_t = 4)]
    poll_seconds: u64,

    /// How many epochs past a checkpoint to keep looking for its attestations
    #[arg(long, default_value_t = 2)]
    attestation_lookahead_epochs: u64,

    /// Catch up to the node's head and exit, instead of following the chain
    #[arg(long)]
    once: bool,

    /// Pipeline to prove epochs with
    #[arg(long, default_value = "batch")]
    mode: Mode,

    /// What produces the proofs
    #[arg(long, default_value = "native")]
    prover: Backend,

    /// Directory holding the guest ELFs, for `--prover zisk`
    #[arg(long, default_value = zkasper_witness_gen::zisk_prover::DEFAULT_ELF_DIR)]
    #[cfg(feature = "zisk-prover")]
    elf_dir: PathBuf,

    /// Prove on the GPU. Without it the run measures the CPU.
    #[arg(long)]
    #[cfg(feature = "zisk-prover")]
    gpu: bool,

    /// Proving key directory. Defaults to Zisk's own, `~/.zisk/provingKey`.
    #[arg(long)]
    #[cfg(feature = "zisk-prover")]
    proving_key: Option<PathBuf>,
}

impl Cli {
    /// Build the prover this run was asked for.
    ///
    /// One prover, for the life of the process: see `crate::prover` on why that
    /// is the only shape worth measuring.
    #[cfg_attr(not(feature = "zisk-prover"), allow(unused_variables))]
    fn build_prover(&self, chain: ChainConfig, pipeline: Pipeline) -> Result<Box<dyn Prover>> {
        match self.prover {
            Backend::Native => Ok(Box::new(NativeProver::new(chain))),
            #[cfg(feature = "zisk-prover")]
            Backend::Zisk => {
                use zkasper_witness_gen::zisk_prover::{ZiskProver, ZiskProverConfig};
                Ok(Box::new(ZiskProver::new(ZiskProverConfig {
                    elf_dir: self.elf_dir.clone(),
                    gpu: self.gpu,
                    proving_key: self.proving_key.clone(),
                    ..ZiskProverConfig::new(chain, pipeline.stages())
                })?))
            }
            #[cfg(not(feature = "zisk-prover"))]
            Backend::Zisk => anyhow::bail!(
                "this binary was built without the `zisk-prover` feature; \
                 rebuild with `cargo build --release --features zisk-prover`",
            ),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .init();

    let pipeline = match cli.mode {
        Mode::Batch => Pipeline::Batch,
        Mode::Streaming => Pipeline::Streaming,
    };
    let config = OrchestratorConfig {
        db_path: cli.db_path.clone(),
        output_dir: cli.output_dir.clone(),
        bootstrap_slot: cli.bootstrap_slot,
        signing_domain: cli
            .signing_domain
            .as_deref()
            .map(parse_hex_bytes32)
            .transpose()?,
        poll_interval: Duration::from_secs(cli.poll_seconds),
        attestation_lookahead_epochs: cli.attestation_lookahead_epochs,
        pipeline,
        ..OrchestratorConfig::new(cli.chain.config(), cli.chain.name())
    };

    // Built before the first beacon call, so a missing ELF or proving key fails
    // now rather than after a bootstrap has already been paid for.
    let prover = cli.build_prover(cli.chain.config(), pipeline)?;

    info!(
        chain = %config.chain_name,
        db = %config.db_path.display(),
        out = %config.output_dir.display(),
        prover = prover.name(),
        "zkasperd starting",
    );

    let mut orchestrator =
        Orchestrator::open(BeaconApiClient::new(&cli.beacon_url), config, prover).await?;

    if cli.once {
        let ticks = orchestrator.catch_up().await?;
        info!(
            ticks = ticks.len(),
            epoch = orchestrator.state().cursor_epoch,
            "caught up",
        );
        return Ok(());
    }

    orchestrator.run().await
}

fn parse_hex_bytes32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).context("invalid hex")?;
    anyhow::ensure!(bytes.len() == 32, "expected 32 bytes, got {}", bytes.len());
    Ok(bytes.try_into().unwrap())
}
