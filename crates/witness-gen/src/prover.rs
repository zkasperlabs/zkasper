//! Where proving plugs in.
//!
//! The orchestrator never talks to a prover directly, only to [`Prover`]:
//! witness in, `(public output, proof)` out.
//!
//! # One prover, many proofs
//!
//! Every method takes `&self`, and that is load-bearing rather than incidental.
//! Measured on an RTX 5090 against Zisk 1.0.0-alpha, a proof costs 19.52 s
//! before it computes anything — process startup and 30 GB of GPU allocation —
//! against 67,452,592 cost units per second once it is running. The SNARK wrap
//! makes the same point more sharply: `cargo-zisk wrap --minimal -g` takes
//! 18.4 s of which **0.192 s** is the compression.
//!
//! The streaming pipeline exists to make `T2 - T` one proof and a wrap. At
//! 0.75B cost units that is 11 s of real work, so two cold starts would be
//! four times the thing they are wrapped around, and the difference between
//! advertising 12 s and 50 s. An implementation must therefore hold the GPU
//! allocation open across proofs — one long-running process, or a pool of them,
//! serving many calls. Shelling out to `cargo-zisk` per proof is not an
//! acceptable implementation of this trait, and the trait is shaped so that it
//! does not have to be: `&self`, `Send + Sync`, no per-call setup hook.
//!
//! Until there is a GPU to run it on, [`NativeProver`] implements the trait by
//! running the guest's verification logic natively and returning an empty proof.
//! An empty proof is what `recursion::verify_child` accepts on a native target,
//! so justification and finalization still compose exactly as they will with
//! real proofs — the only thing missing is the cryptography.
//!
//! Running the circuit is not a formality. Every witness the daemon writes has
//! been through the guest logic that will later prove it, so a witness that
//! cannot be proven fails at the point it is generated rather than hours later
//! on a prover.

use std::panic::{catch_unwind, AssertUnwindSafe};

use anyhow::{anyhow, Result};

use zkasper_common::acc::Digest;
use zkasper_common::bls::Fp12;
use zkasper_common::recursion::ProgramVk;
use zkasper_common::types::{
    AggregateOutput, AggregateWitness, BootstrapWitness, EpochDiffOutput, EpochDiffWitness,
    FinalizationOutput, FinalizationWitness, GroupProofOutput, JustificationOutput,
    JustificationWitness, SlotProofOutput, SlotProofWitness, StreamFinalOutput, StreamFinalWitness,
};
use zkasper_common::ChainConfig;

/// A serialized Zisk proof, as the u64 words a parent proof verifies.
pub type Proof = Vec<u64>;

/// The proof stages, in the order the pipeline runs them.
///
/// `SlotProof`, `Justification` and `Finalization` are the whole-epoch path:
/// prove every slot, fold them once the epoch is over, pair two justifications.
/// `Group`, `Aggregate` and `StreamFinal` are the streaming path, which proves
/// the same thing as attestations arrive and collapses the tail into one proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Bootstrap,
    EpochDiff,
    SlotProof,
    Justification,
    Finalization,
    Group,
    Aggregate,
    StreamFinal,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Bootstrap => "bootstrap",
            Stage::EpochDiff => "epoch_diff",
            Stage::SlotProof => "slot_proof",
            Stage::Justification => "justification",
            Stage::Finalization => "finalization",
            Stage::Group => "group",
            Stage::Aggregate => "aggregate",
            Stage::StreamFinal => "stream_final",
        }
    }
}

/// Public output of the bootstrap stage.
#[derive(Clone, Copy, Debug)]
pub struct AccOutput {
    pub commitment: Digest,
    pub acc_root: Digest,
    pub total_active_balance: u64,
}

/// Turns a witness into a proof of that witness.
///
/// Implementors must return the same public outputs the circuit commits to —
/// the orchestrator checks the accumulator advance against them before writing
/// anything to disk, so an implementation that guesses is caught immediately.
pub trait Prover: Send + Sync {
    /// Short name, recorded in the status manifest.
    fn name(&self) -> &'static str;

    /// Verification key of the program that produces `stage`'s proofs.
    ///
    /// Aggregating stages bind their children to this, so a proof of a
    /// different program cannot be substituted.
    fn program_vk(&self, stage: Stage) -> ProgramVk;

    fn prove_bootstrap(&self, witness: &BootstrapWitness) -> Result<(AccOutput, Proof)>;
    fn prove_epoch_diff(&self, witness: &EpochDiffWitness) -> Result<(EpochDiffOutput, Proof)>;
    fn prove_slot(&self, witness: &SlotProofWitness) -> Result<(SlotProofOutput, Proof)>;
    fn prove_justification(
        &self,
        witness: &JustificationWitness,
    ) -> Result<(JustificationOutput, Proof)>;
    fn prove_finalization(
        &self,
        witness: &FinalizationWitness,
    ) -> Result<(FinalizationOutput, Proof)>;

    /// A group of slots, proven without finishing the pairing.
    ///
    /// Returns the Miller-loop accumulator alongside the output, because it is
    /// 576 bytes and the output is 256: the parent proof takes it as witness and
    /// checks it against the commitment in the output.
    fn prove_group(&self, witness: &SlotProofWitness) -> Result<(GroupProofOutput, Fp12, Proof)>;

    fn prove_aggregate(&self, witness: &AggregateWitness) -> Result<(AggregateOutput, Proof)>;

    fn prove_stream_final(
        &self,
        witness: &StreamFinalWitness,
    ) -> Result<(StreamFinalOutput, Proof)>;
}

/// Runs the guest logic natively and returns an empty proof.
///
/// This is the default: witness generation with a validity check, no
/// cryptography. Swap in a prover that shells out to `cargo-zisk` and the
/// orchestrator does not change.
pub struct NativeProver {
    config: ChainConfig,
}

impl NativeProver {
    pub fn new(config: ChainConfig) -> Self {
        Self { config }
    }
}

impl Prover for NativeProver {
    fn name(&self) -> &'static str {
        "native (witness only, no proofs)"
    }

    fn program_vk(&self, _stage: Stage) -> ProgramVk {
        // No ELF was built, so there is no verification key to bind to. The
        // native `verify_child` short-circuits on an empty proof before it looks
        // at the key.
        [0; 4]
    }

    fn prove_bootstrap(&self, witness: &BootstrapWitness) -> Result<(AccOutput, Proof)> {
        let (commitment, acc_root, total_active_balance) = run_circuit(Stage::Bootstrap, || {
            zkasper_bootstrap_guest::verify_bootstrap_with_depth(
                witness,
                self.config.validators_tree_depth,
                self.config.acc_tree_depth,
            )
        })?;
        Ok((
            AccOutput {
                commitment,
                acc_root,
                total_active_balance,
            },
            Proof::new(),
        ))
    }

    fn prove_epoch_diff(&self, witness: &EpochDiffWitness) -> Result<(EpochDiffOutput, Proof)> {
        let output = run_circuit(Stage::EpochDiff, || {
            zkasper_epoch_diff_guest::verify_epoch_diff_with_depth(
                witness,
                self.config.validators_tree_depth,
                self.config.acc_tree_depth,
            )
        })?;
        Ok((output, Proof::new()))
    }

    fn prove_slot(&self, witness: &SlotProofWitness) -> Result<(SlotProofOutput, Proof)> {
        let output = run_circuit(Stage::SlotProof, || {
            zkasper_slot_proof_guest::verify_slot_proof_with_depth(
                witness,
                self.config.acc_tree_depth,
            )
        })?;
        Ok((output, Proof::new()))
    }

    fn prove_justification(
        &self,
        witness: &JustificationWitness,
    ) -> Result<(JustificationOutput, Proof)> {
        let output = run_circuit(Stage::Justification, || {
            zkasper_justification_guest::verify_justification(witness)
        })?;
        Ok((output, Proof::new()))
    }

    fn prove_finalization(
        &self,
        witness: &FinalizationWitness,
    ) -> Result<(FinalizationOutput, Proof)> {
        let output = run_circuit(Stage::Finalization, || {
            zkasper_finalization_guest::verify_finalization(witness)
        })?;
        Ok((output, Proof::new()))
    }

    fn prove_group(&self, witness: &SlotProofWitness) -> Result<(GroupProofOutput, Fp12, Proof)> {
        let (output, miller) = run_circuit(Stage::Group, || {
            (
                zkasper_slot_proof_guest::verify_group_proof_with_depth(
                    witness,
                    self.config.acc_tree_depth,
                ),
                zkasper_slot_proof_guest::attest(witness, self.config.acc_tree_depth).miller,
            )
        })?;
        Ok((output, miller, Proof::new()))
    }

    fn prove_aggregate(&self, witness: &AggregateWitness) -> Result<(AggregateOutput, Proof)> {
        let output = run_circuit(Stage::Aggregate, || {
            zkasper_aggregation_guest::verify_aggregate_with_depth(
                witness,
                zkasper_common::dedup::tree_depth(self.config.acc_tree_depth),
            )
        })?;
        Ok((output, Proof::new()))
    }

    fn prove_stream_final(
        &self,
        witness: &StreamFinalWitness,
    ) -> Result<(StreamFinalOutput, Proof)> {
        let output = run_circuit(Stage::StreamFinal, || {
            zkasper_stream_final_guest::verify_stream_final_with_depth(
                witness,
                self.config.acc_tree_depth,
            )
        })?;
        Ok((output, Proof::new()))
    }
}

/// Run guest logic and turn its assertion failures into errors.
///
/// The guests assert rather than return, because inside a zkVM a failed
/// assertion is the only way to reject. A daemon cannot take that literally: an
/// unprovable witness for one epoch must not end the process.
fn run_circuit<T>(stage: Stage, f: impl FnOnce() -> T) -> Result<T> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|panic| {
        let reason = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or("unknown panic")
            .to_string();
        anyhow!("{} circuit rejected the witness: {reason}", stage.as_str())
    })
}
