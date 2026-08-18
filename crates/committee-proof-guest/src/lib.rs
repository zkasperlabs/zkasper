//! Committee proof: one per epoch, off the critical path.
//!
//! Sums every slot's committee out of the accumulator so that every proof after
//! it can name absentees instead of attesters. [`zkasper_common::committee`]
//! carries the argument for what that establishes, and for why a wrong committee
//! assignment costs liveness rather than soundness.
//!
//! # Where it sits
//!
//! The committee for epoch `N` is fixed by a RANDAO mix that stops changing two
//! epochs earlier, so this proof can run a whole epoch ahead of the attestations
//! it serves — 384 seconds of slack against a modelled 169 s at mainnet scale.
//! It is also the only proof in the pipeline whose cost is a function of the
//! *whole active* validator set, which is exactly what buys every proof after it
//! a cost that is a function of the absentees.
//!
//! It is additive over validator index ranges — bucket sums add, and a validator
//! lands in one range — so splitting it across parallel proofs needs only a fold
//! that adds aggregates. That is not built yet.

pub use zkasper_common::committee::verify as verify_committee;
