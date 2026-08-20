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
//! that adds aggregates. That is not built, and at today's constants it should
//! not be. `ProverModel::committee_chunk_s` and `committee_fold_s` price it: on
//! the epoch-430529 fixture's 960,974 members two chunks are 144 s against 132 s
//! and eight are 175 s, because a chunk pays the stage floor again and the fold
//! pays a recursion a chunk. `T2 - T` does not move at any width, and on one card the
//! epoch opens on the committee proof, so a wider split opens it *later*. See
//! `BENCHMARKS.md`, "One card or two".
//!
//! What a split would also owe, if it is ever wanted: disjointness stops being
//! structural at the seams. Within a chunk the strictly-increasing scan still
//! gives it, but the fold has to publish and check each chunk's index range and
//! reject any overlap, and has to check that every chunk names the same
//! `accumulator_commitment` and `target_epoch` — two chunks of the same epoch
//! against two different accumulators are two partitions, and adding them
//! double-counts. Coverage is not owed: an omitted validator makes the summed
//! key too small and the pairing fails, which is the same liveness failure a
//! wrong assignment is.

pub use zkasper_common::committee::verify as verify_committee;
