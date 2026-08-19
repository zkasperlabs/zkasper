//! Where proving plugs in.
//!
//! The orchestrator never talks to a prover directly, only to [`Prover`]:
//! witness in, `(public output, proof)` out.
//!
//! # One prover, many proofs
//!
//! Every method takes `&self`, and that is load-bearing rather than incidental.
//! Measured on an RTX 5090 against Zisk 1.0.0-alpha over 87 warm proves, wall
//! clock exceeds the prover's own `Proof generated` by **13.49 s** —
//! `INITIALIZING_PROOFMAN` is 7.74 s +/- 0.71 of that and process start and
//! teardown are the rest. That is what a long-lived prover saves, per proof.
//! The SNARK wrap makes the same point more sharply: `cargo-zisk wrap
//! --minimal -g` takes 12.5 s of which **0.157 s** is the compression.
//!
//! The streaming pipeline exists to make `T2 - T` one proof and a wrap. The
//! measured floor of a zkasper stage is 7.18 s and the final proof of a mainnet
//! epoch is about 9 s, so two cold starts would be three times the thing they
//! are wrapped around. An implementation must therefore hold the GPU allocation
//! open across proofs — one long-running process, or a pool of them, serving
//! many calls. Shelling out to `cargo-zisk` per proof is not an acceptable
//! implementation of this trait, and the trait is shaped so that it does not
//! have to be: `&self`, `Send + Sync`, no per-call setup hook.
//!
//! Do not reintroduce the 19.52 s that used to be quoted here. It was a
//! regression intercept over wall clock that absorbed the per-proof floor as
//! well as the startup, so adding it to a floor term counts the floor twice.
//! See `scripts/time_model.py`.
//!
//! [`crate::zisk_prover::ZiskProver`] is that implementation — one embedded
//! `zisk-sdk` client, initialised once, proving for the life of the process. It
//! is behind the `zisk-prover` feature because it drags in the whole Zisk
//! proving stack, which needs a C++ toolchain and 47 GB of proving key.
//!
//! [`crate::remote_prover::RemoteProver`] is the same prover on another machine,
//! reached over a socket. It is the shape the deployment has, because the box
//! that holds the GPU must not also hold a beacon node, and it needs none of the
//! proving stack on the daemon's side.
//!
//! [`NativeProver`] implements the same trait by running the guest's
//! verification logic natively and returning an empty proof. An empty proof is
//! what `recursion::verify_child` accepts on a native target, so justification
//! and finalization still compose exactly as they will with real proofs — the
//! only thing missing is the cryptography. It is what the tests run against, and
//! what a witness-only deployment runs.
//!
//! Running the circuit is not a formality. Every witness the daemon writes has
//! been through the guest logic that will later prove it, so a witness that
//! cannot be proven fails at the point it is generated rather than hours later
//! on a prover.

use std::panic::{catch_unwind, AssertUnwindSafe};

use anyhow::{anyhow, Result};

use zkasper_common::bls::Fp12;
use zkasper_common::recursion::ProgramVk;
use zkasper_common::types::{
    AggregateOutput, AggregateWitness, CommitteeOutput, CommitteeWitness, EpochDiffOutput,
    EpochDiffWitness, FinalizationOutput, FinalizationWitness, GroupProofOutput,
    JustificationOutput, JustificationWitness, SlotProofOutput, SlotProofWitness,
    StreamFinalOutput, StreamFinalWitness,
};
use zkasper_common::ChainConfig;

/// Where `cargo-zisk build --release` leaves a guest ELF.
pub const DEFAULT_ELF_DIR: &str = "target/elf/riscv64ima-zisk-zkvm-elf/release";

/// A serialized Zisk proof, as the u64 words a parent proof verifies.
pub type Proof = Vec<u64>;

/// The proof stages, in the order the pipeline runs them.
///
/// `SlotProof`, `Justification` and `Finalization` are the whole-epoch path:
/// prove every slot, fold them once the epoch is over, pair two justifications.
/// `Group`, `Aggregate` and `StreamFinal` are the streaming path, which proves
/// the same thing as attestations arrive and collapses the tail into one proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Stage {
    EpochDiff,
    Committee,
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
            Stage::EpochDiff => "epoch_diff",
            Stage::Committee => "committee",
            Stage::SlotProof => "slot_proof",
            Stage::Justification => "justification",
            Stage::Finalization => "finalization",
            Stage::Group => "group",
            Stage::Aggregate => "aggregate",
            Stage::StreamFinal => "stream_final",
        }
    }

    /// Guest crate whose ELF proves this stage, and whose verification key a
    /// third party rebuilds to check a proof came from this circuit.
    pub fn guest(self) -> &'static str {
        match self {
            Stage::EpochDiff => "zkasper-epoch-diff-guest",
            Stage::Committee => "zkasper-committee-proof-guest",
            Stage::SlotProof => "zkasper-slot-proof-guest",
            Stage::Justification => "zkasper-justification-guest",
            Stage::Finalization => "zkasper-finalization-guest",
            Stage::Group => "zkasper-group-proof-guest",
            Stage::Aggregate => "zkasper-aggregation-guest",
            Stage::StreamFinal => "zkasper-stream-final-guest",
        }
    }

    pub const ALL: [Stage; 8] = [
        Stage::EpochDiff,
        Stage::Committee,
        Stage::SlotProof,
        Stage::Justification,
        Stage::Finalization,
        Stage::Group,
        Stage::Aggregate,
        Stage::StreamFinal,
    ];
}

/// The inverse of [`Stage::as_str`], so a stage list can be given on a command
/// line. Every ELF costs a ROM setup and gigabytes of `~/.zisk/cache`, so a
/// prover server is often started for fewer stages than a whole pipeline.
impl std::str::FromStr for Stage {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Stage::ALL
            .into_iter()
            .find(|stage| stage.as_str() == s)
            .ok_or_else(|| {
                anyhow!(
                    "unknown stage {s:?}; expected one of {}",
                    Stage::ALL.map(Stage::as_str).join(", "),
                )
            })
    }
}

/// How a prover that lives somewhere else is doing.
///
/// Every field is a count since the process started.
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct ProverHealth {
    pub proved: u64,
    /// Stages published without a proof, because the prover could not be
    /// reached or did not answer.
    pub unproven: u64,
    /// Stages whose witness the prover took and never answered for, as opposed
    /// to refusing the connection. A different fault, and a different fix.
    pub timed_out: u64,
    /// Witnesses held on disk for a prover that was not there.
    pub spooled: u64,
    /// Witnesses proved later, out of the spool.
    pub recovered: u64,
    /// Witnesses dropped because the spool filled before the prover returned.
    pub dropped: u64,
    /// Witnesses waiting in the spool now.
    pub pending: u64,
}

/// What a proof cost inside the prover.
///
/// The orchestrator times the whole stage, witness generation included; this is
/// the part of it that was cryptography. The two are published apart because a
/// `T2 - T` that folds them together cannot be checked against anything.
#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ProveCost {
    /// Producing the VADCOP final proof.
    pub prove_millis: u64,
    /// Compressing it. Nearly all of a cold `cargo-zisk wrap --minimal` is
    /// startup and device allocation; held warm, what is left is the 0.192 s of
    /// compression itself.
    pub wrap_millis: u64,
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
    /// A guest bakes the keys of the children it verifies, so this is not what
    /// binds them any more — [`crate::child_vks::check`] compares the two and
    /// refuses a prover holding different ELFs. What still reads it is the fold
    /// chains, which publish the key they verify each other under because a
    /// program cannot contain its own key.
    fn program_vk(&self, stage: Stage) -> ProgramVk;

    /// Which prover serves `stage`, for a caller that must not put two proofs
    /// on one card.
    ///
    /// One prover is one process holding one GPU and Proofman serialises
    /// proving on a mutex, so two stages that answer the same index queue and
    /// two that answer different ones run at once. A prover that is one card
    /// answers 0 to everything; [`crate::split_prover::SplitProver`] answers
    /// where it routes. The orchestrator asks rather than naming a stage of its
    /// own, because which stage goes where is configuration.
    fn route(&self, _stage: Stage) -> usize {
        0
    }

    /// What the last proof cost, for a prover that produces proofs.
    fn last_cost(&self) -> Option<ProveCost> {
        None
    }

    /// How proving has gone, for a prover that can fail apart from the daemon.
    ///
    /// `None` for one that cannot: a prover in this process fails by returning
    /// an error, and there is nothing to report between calls. A prover over a
    /// network can be down, or silent, or catching up on a backlog, and an
    /// operator has to be able to see which without reading the log.
    fn health(&self) -> Option<ProverHealth> {
        None
    }

    /// SHA-256 of the ELF that proves `stage`, when there is one. Published so
    /// a verifier can check it rebuilt the same binary before comparing keys.
    fn program_digest(&self, _stage: Stage) -> Option<String> {
        None
    }

    fn prove_epoch_diff(&self, witness: &EpochDiffWitness) -> Result<(EpochDiffOutput, Proof)>;
    fn prove_committee(&self, witness: &CommitteeWitness) -> Result<(CommitteeOutput, Proof)>;
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
/// cryptography. Swap in [`crate::zisk_prover::ZiskProver`] and the orchestrator
/// does not change.
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

    fn program_vk(&self, stage: Stage) -> ProgramVk {
        // No ELF was built, so there is nothing to derive a key from. The keys
        // the guests bake are still the right answer: the native `verify_child`
        // short-circuits on an empty proof before it looks at one, but the
        // circuits compare the key a fold chain publishes against the constant
        // whether or not there is a proof behind it.
        crate::child_vks::baked(stage).unwrap_or(zkasper_common::recursion::UNSET_VK)
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

    fn prove_committee(&self, witness: &CommitteeWitness) -> Result<(CommitteeOutput, Proof)> {
        let output = run_circuit(Stage::Committee, || {
            zkasper_common::committee::verify(
                &zkasper_common::committee::encode(witness),
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
            zkasper_finalization_guest::verify_finalization_with_slots(
                witness,
                self.config.slots_per_epoch,
            )
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
            zkasper_aggregation_guest::verify_aggregate(witness)
        })?;
        Ok((output, Proof::new()))
    }

    fn prove_stream_final(
        &self,
        witness: &StreamFinalWitness,
    ) -> Result<(StreamFinalOutput, Proof)> {
        let output = run_circuit(Stage::StreamFinal, || {
            zkasper_stream_final_guest::verify_stream_final_with(
                witness,
                self.config.acc_tree_depth,
                self.config.slots_per_epoch,
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
pub(crate) fn run_circuit<T>(stage: Stage, f: impl FnOnce() -> T) -> Result<T> {
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
