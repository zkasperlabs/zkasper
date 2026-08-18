use zkasper_witness_gen::{
    beacon_api, db, epoch_state, init_point, network, orchestrator, prover, witness_epoch_diff,
    witness_slot_proof,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use zkasper_common::ChainConfig;

use beacon_api::{BeaconApi, BeaconApiClient};
use db::Db;
use epoch_state::EpochState;
use init_point::InitPoint;

#[derive(Clone, ValueEnum)]
enum Chain {
    Mainnet,
    Gnosis,
}

#[derive(Parser)]
#[command(name = "zkasper-witness-gen")]
#[command(about = "Witness generator for zkasper finality proofs")]
struct Cli {
    /// Beacon node API URL
    #[arg(long, env = "BEACON_API_URL")]
    beacon_url: String,

    /// Path for persistent state (Poseidon tree, cursor)
    #[arg(long, default_value = "zkasper.db")]
    db_path: String,

    /// Output directory for witness files
    #[arg(long, default_value = ".")]
    output_dir: String,

    /// Target chain
    #[arg(long, default_value = "mainnet")]
    chain: Chain,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build the initial Poseidon tree from a trusted init point.
    ///
    /// Take the init point with `zkasper-init-point`. This walks the registry it
    /// names and refuses to write anything unless the accumulator it builds is
    /// the one the file claims.
    Init {
        /// Init point JSON
        init_point: String,
    },
    /// Generate epoch diff witness between two epoch-boundary slots
    EpochDiff {
        /// Last slot of the previous epoch
        slot1: u64,
        /// Last slot of the current epoch
        slot2: u64,
    },
    /// Generate per-slot proof witnesses for a target checkpoint
    SlotProofs {
        /// The epoch of the checkpoint to prove
        epoch: u64,
        /// Target block root (hex, 0x-prefixed)
        #[arg(long)]
        target_root: String,
        /// Signing domain (hex, 0x-prefixed)
        #[arg(long)]
        signing_domain: String,
    },
    /// Continuous mode: watch for new finalized checkpoints and generate proofs
    Run,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let api = BeaconApiClient::new(&cli.beacon_url);
    let db = Db::new(&cli.db_path);
    let config = match cli.chain {
        Chain::Mainnet => ChainConfig::MAINNET,
        Chain::Gnosis => ChainConfig::GNOSIS,
    };

    match cli.command {
        Command::Init { init_point } => {
            let init = InitPoint::read(&init_point)?;
            eprintln!("starting from epoch {} of {}...", init.epoch, init.chain);

            let snapshot = init_point::open(&api, &config, &init.chain, &init).await?;

            db.save(
                &snapshot.tree,
                init.epoch,
                init.total_active_balance,
                init.num_validators,
            )?;
            eprintln!(
                "saved tree state: epoch={}, validators={}, total_active_balance={}",
                init.epoch, init.num_validators, init.total_active_balance,
            );
        }

        Command::EpochDiff { slot1, slot2 } => {
            eprintln!("epoch diff: slot {slot1} -> {slot2}...");

            let (mut tree, cursor_epoch, total_active_balance, _num_validators) =
                db.load()?.context("no saved state — run `init` first")?;

            eprintln!("loaded tree state: cursor_epoch={cursor_epoch}, total_active_balance={total_active_balance}");

            // TODO: persist EpochState to DB for incremental epoch diffs.
            // For now, use empty EpochState (forces slow recomputation path).
            let old_state = EpochState::empty(slot1, _num_validators);

            let (witness, _new_epoch_state, new_total_active_balance, new_num_validators) =
                witness_epoch_diff::build(
                    &api,
                    &config,
                    &mut tree,
                    &old_state,
                    slot2,
                    total_active_balance,
                )
                .await?;

            let new_epoch = witness.epoch_2;

            // Save updated tree
            db.save(
                &tree,
                new_epoch,
                new_total_active_balance,
                new_num_validators,
            )?;
            eprintln!("saved tree state: epoch={new_epoch}, validators={new_num_validators}, total_active_balance={new_total_active_balance}");

            // Serialize witness
            let output_path = format!("{}/epoch_diff_input.bin", cli.output_dir);
            let bytes = bincode::serialize(&witness).context("serialize epoch diff witness")?;
            std::fs::write(&output_path, bytes).context("write epoch diff witness")?;
            eprintln!(
                "wrote {output_path} ({} bytes)",
                std::fs::metadata(&output_path)?.len()
            );
        }

        Command::SlotProofs {
            epoch,
            target_root,
            signing_domain,
        } => {
            eprintln!("slot proofs for epoch {epoch}...");

            let (tree, _cursor_epoch, total_active_balance, _num_validators) = db
                .load()?
                .context("no saved state — run `init` + `epoch-diff` first")?;

            let target_root = parse_hex_bytes32(&target_root)?;
            let signing_domain = parse_hex_bytes32(&signing_domain)?;

            let boundary = (epoch * config.slots_per_epoch).to_string();
            let committees = std::sync::Arc::new(zkasper_witness_gen::committee::build(
                &api.get_committees(&boundary, epoch).await?,
                &api.get_validators(&boundary).await?,
                &tree,
                &config,
                epoch,
                epoch,
                total_active_balance,
            )?);

            let slot_witnesses = witness_slot_proof::build_per_slot(
                &api,
                &config,
                &tree,
                committees,
                epoch,
                target_root,
                total_active_balance,
                signing_domain,
            )
            .await?;

            eprintln!("built {} slot proof witnesses", slot_witnesses.len());

            // Serialize each slot witness
            for sw in &slot_witnesses {
                let output_path = format!("{}/slot_proof_input_{}.bin", cli.output_dir, sw.slot);
                let bytes =
                    bincode::serialize(&sw.witness).context("serialize slot proof witness")?;
                std::fs::write(&output_path, &bytes).context("write slot proof witness")?;
                eprintln!(
                    "  slot {}: {} bytes, {} absentees",
                    sw.slot,
                    bytes.len(),
                    sw.witness.slots[0].absentees.len(),
                );
            }

            // Also serialize the justification witness (aggregates slot outputs)
            // The slot proof outputs would come from running the provers,
            // but for now we can pre-build the justification metadata.
            let output_path = format!("{}/slot_proofs_metadata.bin", cli.output_dir);
            let metadata: Vec<(u64, u64)> = slot_witnesses
                .iter()
                .map(|sw| (sw.slot, sw.marginal_balance))
                .collect();
            let bytes = bincode::serialize(&metadata).context("serialize metadata")?;
            std::fs::write(&output_path, &bytes).context("write metadata")?;
            eprintln!("wrote {output_path} ({} bytes)", bytes.len(),);
        }

        Command::Run => {
            // Continuous mode lives in the `zkasperd` binary; this is the same
            // orchestrator with this command's flags, so the two cannot drift.
            let parameters = match cli.chain {
                Chain::Mainnet => "mainnet",
                Chain::Gnosis => "gnosis",
            };
            let (chain_name, genesis_validators_root) = network::resolve(&api, parameters).await?;
            let orchestrator_config = orchestrator::OrchestratorConfig {
                db_path: cli.db_path.into(),
                output_dir: cli.output_dir.into(),
                genesis_validators_root: Some(genesis_validators_root),
                ..orchestrator::OrchestratorConfig::new(config.clone(), chain_name)
            };
            orchestrator::Orchestrator::open(
                api,
                orchestrator_config,
                Box::new(prover::NativeProver::new(config)),
            )
            .await?
            .run()
            .await?;
        }
    }

    Ok(())
}

fn parse_hex_bytes32(s: &str) -> Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context("invalid hex")?;
    anyhow::ensure!(bytes.len() == 32, "expected 32 bytes, got {}", bytes.len());
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}
