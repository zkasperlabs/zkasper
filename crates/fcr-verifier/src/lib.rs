//! Confirming a block from published FCR batch proofs.
//!
//! The circuit publishes facts and never a verdict; this is where the verdict is
//! made. It is deliberately not a circuit — it is what a light client, a
//! contract, or anyone auditing the feed runs — and it holds **no arithmetic of
//! its own**. Every number it compares comes from
//! [`fast_confirmation_core`], which is Lighthouse's own implementation of the
//! fast confirmation rule extracted to a `no_std` crate. Retyping the rule here
//! is exactly how a prover and a client come to disagree about what "confirmed"
//! means without either looking wrong.
//!
//! # What this does not touch
//!
//! Nothing in the finality pipeline. It reads `FcrBatchOutput` and calls a
//! dependency; no finality circuit, guest, verkey or accumulator format is
//! involved.
//!
//! # Two terms are zero, and one of them is not conservative
//!
//! The specification's threshold carries `support_discount` and, inside the
//! adversarial budget, an `equivocation_score`. A circuit cannot see
//! `store.equivocating_indices`, so both are zero here.
//!
//! **For `support_discount` and for the threshold's own use of the equivocation
//! score, zero is the conservative choice** — it raises the bar.
//!
//! **For support it is not.** The specification also *excludes* equivocating
//! validators from the support sum, and a proof that cannot see the set cannot
//! exclude them, so published support may exceed what the rule would count. That
//! is an unenforced condition, not a conservative approximation, and it is
//! stated here rather than buried because it is the kind of thing a reviewer
//! finds first.

use fast_confirmation_core as spec;
use zkasper_common::acc::Digest;
use zkasper_common::types::FcrBatchOutput;

/// Why a run of batches is not a window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// No batches were supplied.
    Empty,
    /// Two batches disagree about the validator set they are counting against.
    AccumulatorMismatch,
    /// Two batches were proved against different committee roots. Two committee
    /// proofs of one epoch are two partitions, and the disjointness argument
    /// holds for one.
    CommitteeRootMismatch,
    /// Two batches disagree about the total active balance.
    TotalActiveBalanceMismatch,
    /// A batch does not continue the chain the batch before it left.
    ChainBroken { at_slot: u64 },
    /// A batch does not begin where the batch before it ended. A gap would let
    /// the window claim a threshold for slots it never counted.
    SlotGap { expected: u64, found: u64 },
    /// Support summed past `u64`.
    Overflow,
}

impl From<spec::ArithError> for Error {
    fn from(_: spec::ArithError) -> Self {
        Error::Overflow
    }
}

/// Chain parameters the rule needs and a proof does not carry.
#[derive(Debug, Clone, Copy)]
pub struct Params {
    pub slots_per_epoch: u64,
    /// `byzantine_threshold` as a percentage. The rule is stated at 25.
    pub byzantine_threshold: u64,
    /// `PROPOSER_SCORE_BOOST`, as a percentage of one committee's weight.
    pub proposer_score_boost: u64,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            slots_per_epoch: 32,
            byzantine_threshold: 25,
            proposer_score_boost: 40,
        }
    }
}

/// A contiguous run of batches, joined and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    pub accumulator_commitment: Digest,
    pub committee_root: Digest,
    pub total_active_balance: u64,
    /// First slot the window counts, and the last, inclusive.
    pub first_slot: u64,
    pub last_slot: u64,
    /// The head the window started from, and the head it ends at.
    pub parent_head_root: [u8; 32],
    pub head_root: [u8; 32],
    /// Slot of the last block proposed inside the window.
    pub head_slot: u64,
    /// Effective balance counted for the canonical chain across the window.
    pub support: u64,
}

impl Window {
    pub fn slot_count(&self) -> u64 {
        self.last_slot - self.first_slot + 1
    }
}

/// Join a run of batch proofs into one window.
///
/// The batches must be in slot order. Every join is checked: same validator set,
/// same committee root, same total active balance, each batch extending the
/// previous head and beginning where the previous batch ended.
pub fn accumulate(batches: &[FcrBatchOutput]) -> Result<Window, Error> {
    let (first, rest) = batches.split_first().ok_or(Error::Empty)?;

    let mut window = Window {
        accumulator_commitment: first.accumulator_commitment,
        committee_root: first.committee_root,
        total_active_balance: first.total_active_balance,
        first_slot: first.first_slot,
        last_slot: first.first_slot + first.slot_count - 1,
        parent_head_root: first.parent_head_root,
        head_root: first.head_root,
        head_slot: first.head_slot,
        support: first.support,
    };

    for batch in rest {
        if batch.accumulator_commitment != window.accumulator_commitment {
            return Err(Error::AccumulatorMismatch);
        }
        if batch.committee_root != window.committee_root {
            return Err(Error::CommitteeRootMismatch);
        }
        if batch.total_active_balance != window.total_active_balance {
            return Err(Error::TotalActiveBalanceMismatch);
        }
        if batch.parent_head_root != window.head_root {
            return Err(Error::ChainBroken {
                at_slot: batch.first_slot,
            });
        }
        let expected = window.last_slot + 1;
        if batch.first_slot != expected {
            return Err(Error::SlotGap {
                expected,
                found: batch.first_slot,
            });
        }

        window.support = window.support.checked_add(batch.support).ok_or(Error::Overflow)?;
        window.last_slot = batch.first_slot + batch.slot_count - 1;
        window.head_root = batch.head_root;
        window.head_slot = batch.head_slot;
    }

    Ok(window)
}

/// The specification's safety threshold for this window.
///
/// `parent_slot` is the slot of the block whose confirmation is being decided —
/// the window counts votes from `parent_slot + 1` onwards, as the rule does.
pub fn safety_threshold(
    window: &Window,
    parent_slot: u64,
    current_slot: u64,
    params: &Params,
) -> Result<u64, Error> {
    let t = window.total_active_balance;
    let spe = params.slots_per_epoch;

    let maximum_support = spec::estimate_committee_weight_between_slots(
        t,
        parent_slot.saturating_add(1),
        current_slot.saturating_sub(1),
        spe,
    )?;
    let proposer_score = spec::compute_proposer_score(t, spe, params.proposer_score_boost)?;
    let adversarial = spec::adversarial_weight(
        spec::max_adversarial_weight(maximum_support, params.byzantine_threshold)?,
        // No circuit sees `store.equivocating_indices`; see the module docs.
        0,
    );

    Ok(spec::safety_threshold(
        maximum_support,
        proposer_score,
        adversarial,
        // `support_discount` is zero for the same reason, and here that is the
        // conservative direction.
        0,
    )?)
}

/// Whether the window confirms its head, under the specification's own rule.
pub fn is_confirmed(
    window: &Window,
    parent_slot: u64,
    current_slot: u64,
    params: &Params,
) -> Result<bool, Error> {
    let threshold = safety_threshold(window, parent_slot, current_slot, params)?;
    // A proof of an optimistic or invalid payload is a fact this layer does not
    // hold; a caller that tracks execution status supplies it by refusing to ask.
    Ok(spec::is_one_confirmed(false, window.support, threshold))
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 42_328_615_000_000_000;

    fn batch(first_slot: u64, slot_count: u64, support: u64, parent: u8, head: u8) -> FcrBatchOutput {
        FcrBatchOutput {
            accumulator_commitment: [1, 2, 3, 4],
            committee_root: [5, 6, 7, 8],
            parent_head_root: [parent; 32],
            head_root: [head; 32],
            head_slot: first_slot + slot_count - 1,
            support,
            total_active_balance: T,
            first_slot,
            slot_count,
        }
    }

    #[test]
    fn batches_join_into_one_window() {
        let w = accumulate(&[
            batch(100, 2, 10, 0xaa, 0xbb),
            batch(102, 2, 20, 0xbb, 0xcc),
        ])
        .unwrap();
        assert_eq!(w.first_slot, 100);
        assert_eq!(w.last_slot, 103);
        assert_eq!(w.slot_count(), 4);
        assert_eq!(w.support, 30);
        assert_eq!(w.head_root, [0xcc; 32]);
        assert_eq!(w.parent_head_root, [0xaa; 32]);
    }

    #[test]
    fn a_gap_between_batches_is_refused() {
        let e = accumulate(&[
            batch(100, 2, 10, 0xaa, 0xbb),
            batch(103, 2, 20, 0xbb, 0xcc),
        ])
        .unwrap_err();
        assert_eq!(
            e,
            Error::SlotGap {
                expected: 102,
                found: 103
            }
        );
    }

    #[test]
    fn a_batch_that_does_not_extend_the_previous_head_is_refused() {
        let e = accumulate(&[
            batch(100, 2, 10, 0xaa, 0xbb),
            batch(102, 2, 20, 0x99, 0xcc),
        ])
        .unwrap_err();
        assert_eq!(e, Error::ChainBroken { at_slot: 102 });
    }

    /// Two committee proofs of one epoch are two partitions, and the
    /// disjointness argument is about one of them.
    #[test]
    fn batches_against_two_committee_roots_are_refused() {
        let mut second = batch(102, 2, 20, 0xbb, 0xcc);
        second.committee_root = [9, 9, 9, 9];
        let e = accumulate(&[batch(100, 2, 10, 0xaa, 0xbb), second]).unwrap_err();
        assert_eq!(e, Error::CommitteeRootMismatch);
    }

    /// The threshold over a one-slot window is roughly one committee's weight,
    /// plus the adversary's budget over the same window. Nothing here is our
    /// arithmetic: it is `fast_confirmation_core` end to end.
    #[test]
    fn a_one_slot_window_needs_about_one_committee_plus_the_budget() {
        let w = accumulate(&[batch(100, 1, 0, 0xaa, 0xbb)]).unwrap();
        let threshold = safety_threshold(&w, 99, 101, &Params::default()).unwrap();
        let committee = T / 32;
        assert!(threshold > committee / 2, "threshold {threshold}");
        assert!(threshold < committee * 2, "threshold {threshold}");
    }

    #[test]
    fn support_below_the_threshold_does_not_confirm() {
        let w = accumulate(&[batch(100, 1, 1_000, 0xaa, 0xbb)]).unwrap();
        assert!(!is_confirmed(&w, 99, 101, &Params::default()).unwrap());
    }

    /// A window long enough to cover the whole validator set: the estimator
    /// returns the total active balance rather than a per-slot multiple, so the
    /// bar stops growing and enough accumulated support clears it.
    #[test]
    fn a_long_window_with_the_set_behind_it_confirms() {
        let w = accumulate(&[batch(0, 32, T * 3 / 4, 0xaa, 0xbb)]).unwrap();
        assert!(is_confirmed(&w, 0, 33, &Params::default()).unwrap());
    }

    #[test]
    fn an_empty_run_is_not_a_window() {
        assert_eq!(accumulate(&[]).unwrap_err(), Error::Empty);
    }
}
