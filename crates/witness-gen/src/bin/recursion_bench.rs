//! Measure what a recursive child verification costs, as a curve in child count.
//!
//! `ProverModel::recursion_verify_s` was a zero for as long as nothing could
//! measure it: the witness fixtures carry stub child proofs, and a guest rejects
//! an empty proof, so the only stages that exercise recursion could not be
//! proved at all without a real prover behind them. This binary is that prover.
//!
//! It builds a synthetic epoch, proves its committee and every slot of it for
//! real, and then proves one justification link per point of the sweep — the
//! same circuit the daemon runs, over a child count it varies. A point of `k`
//! verifies `k + 1` children: `k` slot proofs and the committee proof the
//! opening link carries.
//!
//! Read the *shape*, not one point. A fixed cost with a cheap per-child term
//! and a genuinely linear cost want different pipelines, and only a sweep tells
//! them apart.
//!
//! ```text
//! cargo run --release --features zisk-prover --bin recursion-bench -- --gpu
//! ```

#[cfg(not(feature = "zisk-prover"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("build with --features zisk-prover; there is nothing to measure without one")
}

#[cfg(feature = "zisk-prover")]
fn main() -> anyhow::Result<()> {
    bench::run()
}

#[cfg(feature = "zisk-prover")]
mod bench {
    use std::time::Instant;

    use anyhow::Result;
    use clap::Parser;
    use tracing_subscriber::EnvFilter;

    use zkasper_common::types::{SlotProofOutput, SlotProofWitness};
    use zkasper_common::ChainConfig;
    use zkasper_witness_gen::fixture::Epoch;
    use zkasper_witness_gen::prover::{Proof, Prover, Stage, DEFAULT_ELF_DIR};
    use zkasper_witness_gen::witness_justification;
    use zkasper_witness_gen::zisk_prover::{ZiskProver, ZiskProverConfig};

    #[derive(Parser, Debug)]
    #[command(
        name = "recursion-bench",
        about = "Measure recursive verification cost"
    )]
    struct Cli {
        /// Prove on the GPU. Without it the sweep measures the CPU, which is
        /// not the machine any of this runs on.
        #[arg(long)]
        gpu: bool,

        /// Child counts to sweep, as slot proofs per link. Each point costs one
        /// more link, so keep the list short and ordered.
        #[arg(long, value_delimiter = ',', default_value = "1,2,3,4,6,8,11,16,22")]
        children: Vec<usize>,

        /// Validators in each slot's committee. Small on purpose: this sweep is
        /// about recursion, and everything else should be floor.
        #[arg(long, default_value_t = 2)]
        per_slot: usize,

        /// Directory holding the guest ELFs.
        #[arg(long, default_value = DEFAULT_ELF_DIR)]
        elf_dir: String,
    }

    pub fn run() -> Result<()> {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
            .with_target(false)
            .init();

        let cli = Cli::parse();
        let slots = *cli.children.iter().max().expect("at least one point") as u64;
        let chain = ChainConfig::MAINNET;

        let mut config = ZiskProverConfig::new(
            chain,
            &[Stage::Committee, Stage::SlotProof, Stage::Justification],
        );
        config.gpu = cli.gpu;
        config.elf_dir = cli.elf_dir.clone().into();
        let prover = ZiskProver::new(config)?;

        // One synthetic epoch, `slots` committees of `per_slot`. The committee
        // proof and every slot proof below are real proofs of it, because a
        // recursion has nothing to verify otherwise.
        let epoch = Epoch::new(chain, 100, slots, cli.per_slot);

        let started = Instant::now();
        let (committee_output, committee_proof) =
            prover.prove_committee(&epoch.committees.witness)?;
        println!(
            "committee proof over {} members: {} ms",
            epoch.committees.witness.members.len(),
            started.elapsed().as_millis(),
        );

        let mut slot_outputs: Vec<SlotProofOutput> = Vec::new();
        let mut slot_proofs: Vec<Proof> = Vec::new();
        for slot in 0..slots {
            let complement = epoch.complement(slot, &[]);
            let witness = SlotProofWitness {
                accumulator_commitment: epoch.accumulator_commitment,
                committee_root: epoch.committees.root(),
                target_epoch: epoch.epoch,
                target_root: epoch.target_root,
                signing_domain: epoch.signing_domain,
                acc_root: epoch.acc_root,
                total_active_balance: epoch.total_active_balance,
                acc_multi_proof: epoch.tree.build_multi_proof(&complement.named_indices),
                committee_multi_proof: epoch.committees.multi_proof(&[slot]),
                slots: vec![complement.witness],
            };
            let (output, proof) = prover.prove_slot(&witness)?;
            println!(
                "slot proof {slot}: {} ms",
                prove_millis(&prover, Instant::now()),
            );
            slot_outputs.push(output);
            slot_proofs.push(proof);
        }

        let context = witness_justification::Context {
            accumulator_commitment: epoch.accumulator_commitment,
            acc_root: epoch.acc_root,
            target_epoch: epoch.epoch,
            target_root: epoch.target_root,
            total_active_balance: epoch.total_active_balance,
            slot_program_vk: prover.program_vk(Stage::SlotProof),
            committee_program_vk: prover.program_vk(Stage::Committee),
            justification_program_vk: prover.program_vk(Stage::Justification),
        };

        // The opening link at every width in the sweep: `k` slot proofs and the
        // committee proof, so `k + 1` children.
        println!("\nchildren\tslots\tprove_ms\twrap_ms");
        let mut rows: Vec<(f64, f64)> = Vec::new();
        for &k in &cli.children {
            let started = Instant::now();
            prover.prove_justification(&witness_justification::build(
                &context,
                Some(committee_output.clone()),
                committee_proof.clone(),
                None,
                Vec::new(),
                slot_outputs[..k].to_vec(),
                slot_proofs[..k].to_vec(),
            ))?;
            let millis = prove_millis(&prover, started);
            println!(
                "{}\t\t{k}\t{millis}\t\t{}",
                k + 1,
                prover.last_cost().map(|c| c.wrap_millis).unwrap_or(0),
            );
            rows.push(((k + 1) as f64, millis as f64 / 1000.0));
        }

        // The link the daemon runs after the epoch opens: one predecessor and
        // `width` slot proofs. Same child count, different children, which is
        // the check that the curve is about recursion and not about slots.
        let (opening_output, opening_proof) =
            prover.prove_justification(&witness_justification::build(
                &context,
                Some(committee_output),
                committee_proof,
                None,
                Vec::new(),
                slot_outputs[..1].to_vec(),
                slot_proofs[..1].to_vec(),
            ))?;
        for width in [1usize, 2, 4] {
            if 1 + width > slot_outputs.len() {
                continue;
            }
            let started = Instant::now();
            prover.prove_justification(&witness_justification::build(
                &context,
                None,
                Vec::new(),
                Some(opening_output.clone()),
                opening_proof.clone(),
                slot_outputs[1..1 + width].to_vec(),
                slot_proofs[1..1 + width].to_vec(),
            ))?;
            println!(
                "extending link, {} children: {} ms",
                width + 1,
                prove_millis(&prover, started),
            );
        }

        // Least squares over the sweep, so the report is a line and not a guess.
        let n = rows.len() as f64;
        let sx: f64 = rows.iter().map(|r| r.0).sum();
        let sy: f64 = rows.iter().map(|r| r.1).sum();
        let sxx: f64 = rows.iter().map(|r| r.0 * r.0).sum();
        let sxy: f64 = rows.iter().map(|r| r.0 * r.1).sum();
        let slope = (n * sxy - sx * sy) / (n * sxx - sx * sx);
        println!(
            "\nOLS over the sweep: {:.3} s + {slope:.3} s per child",
            (sy - slope * sx) / n,
        );

        Ok(())
    }

    /// The prover's own `Proof generated` time, falling back to wall clock.
    ///
    /// Wall clock includes the wrap and the witness handling either side of it,
    /// and the difference is the whole reason the daemon holds one warm prover.
    fn prove_millis(prover: &ZiskProver, started: Instant) -> u64 {
        prover
            .last_cost()
            .map(|c| c.prove_millis)
            .unwrap_or_else(|| started.elapsed().as_millis() as u64)
    }
}
