//! Real Zisk proofs, from one long-lived prover.
//!
//! [`crate::prover`] rules out shelling out to `cargo-zisk` per proof. Zisk
//! v1.0.0-alpha means it does not have to: `zisk-sdk`'s `EmbeddedClient` pays
//! for the proving key, the Vadcop setups and the prover's device buffers once,
//! in `build()`, and then serves `prove(&self, ..)` for the life of the process.
//! Proofman's per-proof `reset()` clears the proof slots and the device streams
//! and leaves the setups and the constant polynomials exactly where they are —
//! which is the 19.52 s this design exists to pay once instead of per proof.
//!
//! The SDK insists on the same shape from its own side: a second client in one
//! process panics with "Only one instance is allowed per process", and the flag
//! is never cleared, so a client cannot even be dropped and rebuilt. One
//! [`ZiskProver`] per daemon, shared, is the only thing that works.
//!
//! # What a proof is checked against
//!
//! Every proof goes through [`verify_child`] before it is returned, against the
//! stage's own program key and the public bytes the circuit committed. That is
//! the exact predicate an aggregating guest applies, so a proof that survives it
//! is one the next stage will accept — and a prover that returned a proof of
//! another program, or of different outputs, is caught where it happened rather
//! than a stage later.
//!
//! # Setup, and why the stage list is explicit
//!
//! A program's verification key falls out of its ROM merkle setup, which costs
//! minutes and gigabytes of `~/.zisk/cache` per ELF. The keys have to exist
//! before any witness is built, because the aggregating stages bind them, so
//! setup cannot be deferred to first use. [`ZiskProver::new`] therefore sets up
//! exactly the stages it is told the run will ask for, and treats a request for
//! any other as the configuration error it is.
//!
//! # Many programs, one at a time
//!
//! Setup is per-ELF but the client is not: it keeps a `HashMap` of set-up
//! programs, and `prove` takes the program per call. Switching from one guest to
//! the next costs an `Arc` swap of a cached ROM and a 32-byte read of that ROM's
//! Merkle root — nothing on the device is touched. So the eight stages of this
//! pipeline need one prover between them, not eight.
//!
//! What they cannot do is overlap. Proofman serializes every proof-generation
//! entry point on one mutex, so a second call blocks until the first returns.
//! Concurrency has to come from more processes — and since a GPU prover sizes its
//! buffers to fill the card, that means more cards. A fleet is sized by how many
//! proofs must be in flight at once, never by how many programs there are.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use sha2::Digest as _;
use tracing::info;
use zisk_sdk::{EmbeddedClient, GuestProgram, ProofKind, ProverClient, ZiskStdin};

use zkasper_common::bls::Fp12;
use zkasper_common::recursion::{verify_child, ProgramVk};
use zkasper_common::types::{
    AggregateOutput, AggregateWitness, CommitteeOutput, CommitteeWitness, EpochDiffOutput,
    EpochDiffWitness, FinalizationOutput, FinalizationWitness, GroupProofOutput,
    JustificationOutput, JustificationWitness, SlotProofOutput, SlotProofWitness,
    StreamFinalOutput, StreamFinalWitness,
};
use zkasper_common::ChainConfig;

use crate::prover::{run_circuit, Proof, ProveCost, Prover, Stage, DEFAULT_ELF_DIR};

/// How to build a [`ZiskProver`].
#[derive(Clone, Debug)]
pub struct ZiskProverConfig {
    pub chain: ChainConfig,
    /// Directory holding the guest ELFs.
    pub elf_dir: PathBuf,
    /// Prove on the GPU. Without it the run measures the CPU, whatever the box
    /// has, and the binary must have been built where CUDA was visible.
    pub gpu: bool,
    /// Proving key directory. `None` takes Zisk's own default, `~/.zisk/provingKey`.
    pub proving_key: Option<PathBuf>,
    /// Stages this prover will be asked for. See the module docs: each costs a
    /// ROM setup, so a run pays only for the pipeline it drives.
    pub stages: Vec<Stage>,
}

impl ZiskProverConfig {
    pub fn new(chain: ChainConfig, stages: &[Stage]) -> Self {
        Self {
            chain,
            elf_dir: PathBuf::from(DEFAULT_ELF_DIR),
            gpu: false,
            proving_key: None,
            stages: stages.to_vec(),
        }
    }
}

/// A guest ELF that has been through ROM setup, and the key that came out of it.
struct StageProgram {
    stage: Stage,
    program: GuestProgram,
    vk: ProgramVk,
    /// SHA-256 of the ELF, so a published proof says which binary made it.
    elf_sha256: String,
}

pub struct ZiskProver {
    client: EmbeddedClient,
    programs: Vec<StageProgram>,
    chain: ChainConfig,
    last_cost: Mutex<Option<ProveCost>>,
}

impl ZiskProver {
    pub fn new(config: ZiskProverConfig) -> Result<Self> {
        // The guests were compiled against the constants, not against a chain
        // config, so a chain whose trees are a different shape would be proven
        // by an ELF that disagrees with the witness it was handed.
        if config.chain.acc_tree_depth != zkasper_common::constants::ACC_TREE_DEPTH
            || config.chain.validators_tree_depth
                != zkasper_common::constants::VALIDATORS_TREE_DEPTH
        {
            bail!(
                "the guest ELFs are built for trees of depth {}/{}, but this chain uses {}/{}",
                zkasper_common::constants::VALIDATORS_TREE_DEPTH,
                zkasper_common::constants::ACC_TREE_DEPTH,
                config.chain.validators_tree_depth,
                config.chain.acc_tree_depth,
            );
        }

        let mut builder = ProverClient::embedded();
        if config.gpu {
            builder = builder.gpu();
        }
        if let Some(path) = &config.proving_key {
            builder = builder.proving_key(path);
        }

        let started = Instant::now();
        let client = builder
            .build()
            .map_err(|e| anyhow!("initialise the Zisk prover: {e}"))?;
        info!(
            gpu = config.gpu,
            millis = started.elapsed().as_millis() as u64,
            "prover initialised; this is the cost every later proof does not pay",
        );

        let programs = config
            .stages
            .iter()
            .map(|&stage| StageProgram::setup(&client, stage, &config.elf_dir))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            client,
            programs,
            chain: config.chain,
            last_cost: Mutex::new(None),
        })
    }

    fn program(&self, stage: Stage) -> &StageProgram {
        self.programs
            .iter()
            .find(|p| p.stage == stage)
            .unwrap_or_else(|| {
                panic!(
                    "the {} stage was not set up; add it to ZiskProverConfig::stages",
                    stage.as_str(),
                )
            })
    }

    /// Prove one witness, and check the proof says what the circuit said.
    fn prove(&self, stage: Stage, witness: &impl Serialize, publics: &[u8]) -> Result<Proof> {
        self.prove_input(
            stage,
            bincode::serialize(witness).context("serialize witness")?,
            publics,
        )
    }

    /// The same, for a guest whose witness is not bincode.
    fn prove_input(&self, stage: Stage, input: Vec<u8>, publics: &[u8]) -> Result<Proof> {
        let program = self.program(stage);
        let stdin = ZiskStdin::from_bytes(input);

        let started = Instant::now();
        let proven = self
            .client
            .prove(&program.program, stdin)
            .run_sync()
            .map_err(|e| anyhow!("{} proof: {e}", stage.as_str()))?;
        let prove_millis = started.elapsed().as_millis() as u64;

        // Compression is its own call rather than `prove(..).wrap(..)` so that
        // what it costs is visible. Both run on the client that is already warm,
        // which is the whole point: `cargo-zisk wrap --minimal` measures 18.4 s
        // of which 0.192 s is the compression.
        let started = Instant::now();
        let wrapped = self
            .client
            .wrap_proof(proven.get_proof(), ProofKind::VadcopFinalMinimal)
            .run_sync()
            .map_err(|e| anyhow!("compress the {} proof: {e}", stage.as_str()))?;
        let wrap_millis = started.elapsed().as_millis() as u64;

        let proof = wrapped
            .get_proof()
            .get_proof_u64()
            .map_err(|e| anyhow!("serialize the {} proof: {e}", stage.as_str()))?;

        if !verify_child(&proof, &program.vk, publics) {
            bail!(
                "the {} proof does not verify against its own program key and outputs",
                stage.as_str(),
            );
        }

        *self.last_cost.lock().unwrap() = Some(ProveCost {
            prove_millis,
            wrap_millis,
        });
        info!(
            stage = stage.as_str(),
            words = proof.len(),
            prove_millis,
            wrap_millis,
            "proved",
        );
        Ok(proof)
    }
}

impl StageProgram {
    fn setup(client: &EmbeddedClient, stage: Stage, elf_dir: &Path) -> Result<Self> {
        let path = elf_dir.join(stage.guest());
        let program = GuestProgram::from_uri(&path.display().to_string()).with_context(|| {
            format!(
                "load the {} guest ELF from {}; build it with \
                 `cargo-zisk build --release -p {}`",
                stage.as_str(),
                path.display(),
                stage.guest(),
            )
        })?;

        let started = Instant::now();
        client
            .setup(&program)
            .run_sync()
            .map_err(|e| anyhow!("ROM setup for the {} guest: {e}", stage.as_str()))?;

        // `vk()` takes the default hash mode, Poseidon1, which is the family
        // `zisklib::verify_zisk_proof` recurses under; a key from any other mode
        // would be rejected by every parent proof.
        let vk = program
            .vk()
            .map_err(|e| anyhow!("verification key for the {} guest: {e}", stage.as_str()))?;
        let vk: ProgramVk = vk.vk.try_into().map_err(|v: Vec<u64>| {
            anyhow!(
                "the {} guest's verification key is {} words, expected 4",
                stage.as_str(),
                v.len(),
            )
        })?;

        info!(
            stage = stage.as_str(),
            elf = %path.display(),
            millis = started.elapsed().as_millis() as u64,
            "program set up",
        );
        Ok(Self {
            stage,
            program,
            vk,
            elf_sha256: crate::artifacts::hex0x(
                sha2::Sha256::digest(std::fs::read(&path).context("read the guest ELF")?)
                    .as_slice(),
            ),
        })
    }
}

impl Prover for ZiskProver {
    fn name(&self) -> &'static str {
        "zisk (embedded, warm)"
    }

    fn program_vk(&self, stage: Stage) -> ProgramVk {
        self.program(stage).vk
    }

    fn program_digest(&self, stage: Stage) -> Option<String> {
        Some(self.program(stage).elf_sha256.clone())
    }

    fn last_cost(&self) -> Option<ProveCost> {
        *self.last_cost.lock().unwrap()
    }

    fn prove_epoch_diff(&self, witness: &EpochDiffWitness) -> Result<(EpochDiffOutput, Proof)> {
        let output = run_circuit(Stage::EpochDiff, || {
            zkasper_epoch_diff_guest::verify_epoch_diff_with_depth(
                witness,
                self.chain.validators_tree_depth,
                self.chain.acc_tree_depth,
            )
        })?;
        let proof = self.prove(Stage::EpochDiff, witness, &output.public_bytes())?;
        Ok((output, proof))
    }

    fn prove_committee(&self, witness: &CommitteeWitness) -> Result<(CommitteeOutput, Proof)> {
        let words = zkasper_common::committee::encode(witness);
        let output = run_circuit(Stage::Committee, || {
            zkasper_common::committee::verify(&words, self.chain.acc_tree_depth)
        })?;
        let proof = self.prove_input(
            Stage::Committee,
            zkasper_common::committee::to_bytes(&words),
            &output.public_bytes(),
        )?;
        Ok((output, proof))
    }

    fn prove_slot(&self, witness: &SlotProofWitness) -> Result<(SlotProofOutput, Proof)> {
        let output = run_circuit(Stage::SlotProof, || {
            zkasper_slot_proof_guest::verify_slot_proof_with_depth(
                witness,
                self.chain.acc_tree_depth,
            )
        })?;
        let proof = self.prove(Stage::SlotProof, witness, &output.public_bytes())?;
        Ok((output, proof))
    }

    fn prove_justification(
        &self,
        witness: &JustificationWitness,
    ) -> Result<(JustificationOutput, Proof)> {
        let output = run_circuit(Stage::Justification, || {
            zkasper_justification_guest::verify_justification(witness)
        })?;
        let proof = self.prove(Stage::Justification, witness, &output.public_bytes())?;
        Ok((output, proof))
    }

    fn prove_finalization(
        &self,
        witness: &FinalizationWitness,
    ) -> Result<(FinalizationOutput, Proof)> {
        let output = run_circuit(Stage::Finalization, || {
            zkasper_finalization_guest::verify_finalization_with_slots(
                witness,
                self.chain.slots_per_epoch,
            )
        })?;
        let proof = self.prove(Stage::Finalization, witness, &output.public_bytes())?;
        Ok((output, proof))
    }

    fn prove_group(&self, witness: &SlotProofWitness) -> Result<(GroupProofOutput, Fp12, Proof)> {
        let (output, miller) = run_circuit(Stage::Group, || {
            (
                zkasper_slot_proof_guest::verify_group_proof_with_depth(
                    witness,
                    self.chain.acc_tree_depth,
                ),
                zkasper_slot_proof_guest::attest(witness, self.chain.acc_tree_depth).miller,
            )
        })?;
        let proof = self.prove(Stage::Group, witness, &output.public_bytes())?;
        Ok((output, miller, proof))
    }

    fn prove_aggregate(&self, witness: &AggregateWitness) -> Result<(AggregateOutput, Proof)> {
        let output = run_circuit(Stage::Aggregate, || {
            zkasper_aggregation_guest::verify_aggregate(witness)
        })?;
        let proof = self.prove(Stage::Aggregate, witness, &output.public_bytes())?;
        Ok((output, proof))
    }

    fn prove_stream_final(
        &self,
        witness: &StreamFinalWitness,
    ) -> Result<(StreamFinalOutput, Proof)> {
        let output = run_circuit(Stage::StreamFinal, || {
            zkasper_stream_final_guest::verify_stream_final_with(
                witness,
                self.chain.acc_tree_depth,
                self.chain.slots_per_epoch,
            )
        })?;
        let proof = self.prove(Stage::StreamFinal, witness, &output.public_bytes())?;
        Ok((output, proof))
    }
}
