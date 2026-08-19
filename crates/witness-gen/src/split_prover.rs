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
//! touches `T2`.
//!
//! # Routing alone changes nothing, and this is the trap
//!
//! Moving that stage to a second card takes its 179 s off the first card's
//! **duty cycle**. It does not take it out of the epoch's **wall-clock chain**,
//! because [`crate::orchestrator`] awaits the committee proof inline in
//! `open_epoch` and proves everything else on the calling task. Nothing is ever
//! in flight on two cards at once, so the cycle stays ~379 s whichever card
//! answers, and the gain is about 5 s an epoch rather than 175.
//!
//! An earlier version of this comment said moving it "leaves about 220 s on the
//! first card, which fits inside an epoch with room to spare". That is true of
//! duty cycle and false of cycle time, and the difference is the whole point: a
//! card was rented on the strength of it.
//!
//! **What makes the second card pay is starting epoch N+1's committee proof
//! during epoch N** and merely awaiting it at `open_epoch`. The lead time is
//! already there in the schedule; only the concurrency is missing. Until that
//! exists this type is plumbing waiting for a caller.
//!
//! # What this does not do
//!
//! It does not make one proof faster, and it does not parallelise a stage across
//! cards. It routes whole stages to whole provers. Two proofs of *different*
//! stages *could* then be in flight at once — once something issues them
//! concurrently; two of the same stage still queue.

use std::collections::HashMap;
use std::sync::Mutex;
use std::thread::{self, ThreadId};

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
    /// Which prover answered last **on each thread**, so `last_cost` reports the
    /// proof the caller just asked for rather than whichever backend happens to
    /// be first.
    ///
    /// Per thread because the orchestrator now proves two stages at once: the
    /// next epoch's opening on a blocking task, this epoch's groups and final
    /// proof on the runtime. A single slot would hand each of them the other's
    /// cost, and the whole point of routing is to be able to price the cards
    /// apart.
    last: Mutex<HashMap<ThreadId, usize>>,
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
            last: Mutex::new(HashMap::new()),
        })
    }

    fn pick(&self, stage: Stage) -> &dyn Prover {
        let index = self.routes.get(&stage).copied().unwrap_or(0);
        self.last
            .lock()
            .unwrap()
            .insert(thread::current().id(), index);
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

    fn route(&self, stage: Stage) -> usize {
        self.routes.get(&stage).copied().unwrap_or(0)
    }

    fn last_cost(&self) -> Option<ProveCost> {
        let index = self
            .last
            .lock()
            .unwrap()
            .get(&thread::current().id())
            .copied()
            .unwrap_or(0);
        self.provers[index].last_cost()
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
