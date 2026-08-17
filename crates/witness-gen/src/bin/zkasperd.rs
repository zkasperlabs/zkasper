//! zkasperd — the continuous witness generator.
//!
//! Bootstraps an accumulator from a recent finalized state, then follows the
//! chain: one epoch diff per epoch, slot proofs as attestations arrive, a
//! justification the moment 2/3 is crossed, and a finalization when two
//! consecutive epochs justify.
//!
//! It produces witnesses, not proofs. See `--help` and `crate::prover` for where
//! a real prover attaches.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use tracing::info;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

use zkasper_common::ChainConfig;
use zkasper_witness_gen::beacon_api::BeaconApiClient;
use zkasper_witness_gen::orchestrator::{Orchestrator, OrchestratorConfig};
use zkasper_witness_gen::prover::NativeProver;

#[derive(Clone, Copy, ValueEnum)]
enum Chain {
    Mainnet,
    Gnosis,
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

    let config = OrchestratorConfig {
        db_path: cli.db_path,
        output_dir: cli.output_dir,
        bootstrap_slot: cli.bootstrap_slot,
        signing_domain: cli
            .signing_domain
            .as_deref()
            .map(parse_hex_bytes32)
            .transpose()?,
        poll_interval: Duration::from_secs(cli.poll_seconds),
        attestation_lookahead_epochs: cli.attestation_lookahead_epochs,
        ..OrchestratorConfig::new(cli.chain.config(), cli.chain.name())
    };

    info!(
        chain = %config.chain_name,
        db = %config.db_path.display(),
        out = %config.output_dir.display(),
        "zkasperd starting",
    );

    let prover = Box::new(NativeProver::new(cli.chain.config()));
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
