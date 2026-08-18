//! Where proving plugs in.
//!
//! The orchestrator never talks to a prover directly, only to [`Prover`]:
//! witness in, `(public output, proof)` out. That is the whole contract, and it
//! is the same shape a real Zisk prover has — build the ELF, run
//! `cargo-zisk prove`, read back the proof words and the committed publics.
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
use zkasper_common::recursion::ProgramVk;
use zkasper_common::types::{
    BootstrapWitness, EpochDiffOutput, EpochDiffWitness, FinalizationOutput, FinalizationWitness,
    JustificationOutput, JustificationWitness, SlotProofOutput, SlotProofWitness,
};
use zkasper_common::ChainConfig;

/// A serialized Zisk proof, as the u64 words a parent proof verifies.
pub type Proof = Vec<u64>;

/// The five proof stages, in the order the pipeline runs them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Bootstrap,
    EpochDiff,
    SlotProof,
    Justification,
    Finalization,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Bootstrap => "bootstrap",
            Stage::EpochDiff => "epoch_diff",
            Stage::SlotProof => "slot_proof",
            Stage::Justification => "justification",
            Stage::Finalization => "finalization",
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
