//! Several provers, one per group of stages.
//!
//! Proofman serialises proof generation on one mutex, so a prover server proves
//! one thing at a time however many clients it has, and a warm GPU prover sizes
//! its buffers to the free memory of the card — so two provers do not fit on one
//! card. Concurrency therefore needs more processes on more cards, and something
//! has to decide which proof goes where. This is that something.
//!
//! # Why one card is not enough
//!
//! Measured on mainnet epoch 469425, an RTX 5090, 2026-08-18. One epoch of the
//! streaming pipeline cost **399 s of one card** against the 384 s an epoch
//! lasts: epoch diff 30 s, committee 179 s, group proofs 33 s, stream final
//! 153 s.
//!
//! A daemon that has fallen behind therefore never catches up, and it cannot
//! escape by itself: the epochs it replays are the expensive ones, because a
//! replayed epoch folds nothing in advance and its final proof absorbs the whole
//! epoch at once.
//!
//! **The committee proof is what to move.** It is 179 s of the 399, it has a
//! full epoch of lead time by construction — a RANDAO mix from the end of epoch
//! E-2 fixes the committees of epoch E — and it is the one stage that never
//! touches `T2`. Moving it to a second card leaves about 220 s on the first,
//! which fits inside an epoch with room to spare.
//!
//! # What this does not do
//!
//! It does not make one proof faster, and it does not parallelise a stage across
//! cards. It routes whole stages to whole provers. Two proofs of *different*
//! stages can then be in flight at once; two of the same stage still queue.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{bail, Result};

use zkasper_common::bls::Fp12;
use zkasper_common::recursion::ProgramVk;
use zkasper_common::types::{
    AggregateOutput, AggregateWitness, CommitteeOutput, CommitteeWitness, EpochDiffOutput,
    EpochDiffWitness, FinalizationOutput, FinalizationWitness, GroupProofOutput,
    JustificationOutput, JustificationWitness, SlotProofOutput, SlotProofWitness,
    StreamFinalOutput, StreamFinalWitness,
};

use crate::prover::{Proof, ProveCost, Prover, ProverHealth, Stage};

/// Routes each stage to one of several provers.
pub struct SplitProver {
    /// Every prover this owns. The first is the one an unrouted stage uses.
    provers: Vec<Box<dyn Prover>>,
    routes: HashMap<Stage, usize>,
    /// Which prover answered last, so `last_cost` reports the proof the caller
    /// just asked for rather than whichever backend happens to be first.
    last: Mutex<usize>,
}

impl SplitProver {
    /// `default` takes every stage `routes` does not name.
    pub fn new(default: Box<dyn Prover>, routes: Vec<(Stage, Box<dyn Prover>)>) -> Result<Self> {
        let mut provers = vec![default];
        let mut map = HashMap::new();
        for (stage, prover) in routes {
            if map.insert(stage, provers.len()).is_some() {
                bail!("the {} stage was routed twice", stage.as_str());
            }
            provers.push(prover);
        }
        Ok(Self {
            provers,
            routes: map,
            last: Mutex::new(0),
        })
    }

    fn pick(&self, stage: Stage) -> &dyn Prover {
        let index = self.routes.get(&stage).copied().unwrap_or(0);
        *self.last.lock().unwrap() = index;
        &*self.provers[index]
    }

    /// Which stages go somewhere other than the default, for the log.
    pub fn routed(&self) -> Vec<&'static str> {
        let mut named: Vec<&'static str> = self.routes.keys().map(|s| s.as_str()).collect();
        named.sort_unstable();
        named
    }
}

impl Prover for SplitProver {
    fn name(&self) -> &'static str {
        "remote (network provers)"
    }

    fn program_vk(&self, stage: Stage) -> ProgramVk {
        self.pick(stage).program_vk(stage)
    }

    fn program_digest(&self, stage: Stage) -> Option<String> {
        self.pick(stage).program_digest(stage)
    }

    fn last_cost(&self) -> Option<ProveCost> {
        self.provers[*self.last.lock().unwrap()].last_cost()
    }

    /// Every prover's counters, added up. An operator wants to know the service
    /// lost a proof, not which card lost it; the log names the card.
    fn health(&self) -> Option<ProverHealth> {
        let mut total = ProverHealth::default();
        let mut any = false;
        for prover in &self.provers {
            let Some(h) = prover.health() else { continue };
            any = true;
            total.proved += h.proved;
            total.unproven += h.unproven;
            total.timed_out += h.timed_out;
            total.spooled += h.spooled;
            total.recovered += h.recovered;
            total.dropped += h.dropped;
            total.pending += h.pending;
        }
        any.then_some(total)
    }

    fn prove_epoch_diff(&self, witness: &EpochDiffWitness) -> Result<(EpochDiffOutput, Proof)> {
        self.pick(Stage::EpochDiff).prove_epoch_diff(witness)
    }

    fn prove_committee(&self, witness: &CommitteeWitness) -> Result<(CommitteeOutput, Proof)> {
        self.pick(Stage::Committee).prove_committee(witness)
    }

    fn prove_slot(&self, witness: &SlotProofWitness) -> Result<(SlotProofOutput, Proof)> {
        self.pick(Stage::SlotProof).prove_slot(witness)
    }

    fn prove_justification(
        &self,
        witness: &JustificationWitness,
    ) -> Result<(JustificationOutput, Proof)> {
        self.pick(Stage::Justification).prove_justification(witness)
    }

    fn prove_finalization(
        &self,
        witness: &FinalizationWitness,
    ) -> Result<(FinalizationOutput, Proof)> {
        self.pick(Stage::Finalization).prove_finalization(witness)
    }

    fn prove_group(&self, witness: &SlotProofWitness) -> Result<(GroupProofOutput, Fp12, Proof)> {
        self.pick(Stage::Group).prove_group(witness)
    }

    fn prove_aggregate(&self, witness: &AggregateWitness) -> Result<(AggregateOutput, Proof)> {
        self.pick(Stage::Aggregate).prove_aggregate(witness)
    }

    fn prove_stream_final(
        &self,
        witness: &StreamFinalWitness,
    ) -> Result<(StreamFinalOutput, Proof)> {
        self.pick(Stage::StreamFinal).prove_stream_final(witness)
    }
}
