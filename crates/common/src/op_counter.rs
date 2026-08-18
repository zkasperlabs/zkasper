//! Precompile operation counter and cost model.
//!
//! The weights below are measured, not estimated: `scripts/bench.py` runs each
//! primitive in a guest under `ziskemu -X` at two iteration counts and takes the
//! difference, so program setup and I/O cancel out. Re-run it after any Zisk
//! version bump — these numbers are properties of the prover, not of zkasper.
//!
//! The previous version of this file guessed 29,000 "constraints" for SHA-256
//! and 250 for Poseidon, from before either had a precompile. The real ratio is
//! 16x, not 116x, and both are now rounding errors next to BLS.
//!
//! # These are trace area, not time
//!
//! An RTX 5090 campaign against Zisk v1.0.0-alpha (`data/gpu_bench/`) measured
//! effective throughput on real guests spanning 18M to 249M cost units/s — a
//! 13.8x range — so [`OpCounts::cost`] must never be divided by a
//! units-per-second constant to get seconds. It is a comparison of *shapes*:
//! whether an accumulator node beats an SSZ node, whether batching a pairing
//! pays. For wall-clock, use `scripts/time_model.py` or
//! `zkasper_witness_gen::streaming::ProverModel`, which are denominated in
//! seconds and calibrated per work class.
//!
//! There used to be a `PROOF_BASE` here, 293,601,280, described as the cost
//! floor every proof pays. It is a compile-time constant in zisk's
//! `emulator/src/emu_costs.rs` that no part of the prover reads and that does
//! not describe the shipped proving key: an empty guest instantiates eleven
//! full AIRs totalling 1,447,034,880 trace cells, 4.93x that. Measured, an
//! empty guest proves in 4.843 s and a zkasper stage floor is 7.176 s. Those
//! are the numbers; the constant is gone rather than corrected, because a floor
//! in cost units cannot be converted to one in seconds.

use core::sync::atomic::{AtomicU64, Ordering};

/// Measured Zisk cost units, from `scripts/bench.py` against zisk v1.0.0-alpha.
pub mod cost {
    /// One accumulator node: a `syscall_poseidon2` plus state marshalling.
    pub const POSEIDON2: u64 = 3_033;
    /// One accumulator leaf: the same permutation over a packed G1 point.
    pub const ACC_LEAF: u64 = 3_979;
    /// One SHA-256 compression; an SSZ node is two of them.
    pub const SHA256F: u64 = 25_331;
    /// Add one public key into a running aggregate, through the raw curve-add
    /// precompile. `add_complete_safe_bls12_381` costs 67,854 for the same work
    /// because it re-validates both operands every call.
    pub const PUBKEY_AGGREGATE: u64 = 2_428;
    /// Decompress one 48-byte public key. Only bootstrap and epoch-diff pay it.
    pub const DECOMPRESS: u64 = 49_311;
    /// Hash one message to G2.
    pub const HASH_TO_CURVE: u64 = 18_594_521;
    /// The marginal cost of adding a pair to a multi-Miller-loop.
    ///
    /// Measured against zkasper's own loop, which does not re-validate its
    /// inputs. Through `pairing_check_safe_bls12_381` the same pair costs
    /// 39,299,537, the extra 6,076,715 being on-curve and subgroup checks the
    /// accumulator has already established.
    pub const MILLER_LOOP: u64 = 33_222_822;
    /// What any multi-Miller-loop costs before its first pair: 63 Fp12
    /// squarings, shared by every pair in the batch.
    pub const MILLER_BATCH: u64 = 39_633_399;
    /// Final exponentiation, paid once per multi-pairing however many pairs it
    /// has — and, with the streaming split, once per *epoch* rather than once
    /// per proof.
    pub const FINAL_EXP: u64 = 132_665_557;
    /// One Fp12 multiplication: folding another proof's Miller-loop accumulator
    /// into the running one. 180x cheaper than the final exponentiation it
    /// defers, which is the whole trade.
    pub const FP12_MUL: u64 = 737_503;
    /// Committing a Miller accumulator so it can cross a proof boundary.
    pub const COMMIT_FP12: u64 = 78_002;
    /// G2 subgroup check on a batch's summed signature.
    pub const G2_SUBGROUP: u64 = 8_219_617;
}

macro_rules! counters {
    ($($field:ident => $setter:ident, $static:ident;)*) => {
        $(static $static: AtomicU64 = AtomicU64::new(0);)*

        $(
            #[inline]
            pub fn $setter(n: u64) {
                $static.fetch_add(n, Ordering::Relaxed);
            }
        )*

        /// Raw precompile counts.
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct OpCounts {
            $(pub $field: u64,)*
        }

        pub fn snapshot() -> OpCounts {
            OpCounts { $($field: $static.load(Ordering::Relaxed),)* }
        }

        pub fn reset() {
            $($static.store(0, Ordering::Relaxed);)*
        }

        impl OpCounts {
            /// Counts accumulated since `before`.
            pub fn delta(&self, before: &OpCounts) -> OpCounts {
                OpCounts { $($field: self.$field - before.$field,)* }
            }
        }
    };
}

counters! {
    poseidon2 => inc_poseidon2_n, POSEIDON2;
    acc_leaf => inc_acc_leaf, ACC_LEAF_C;
    sha256f => inc_sha256f, SHA256F;
    pubkey_aggregate => inc_pubkey_aggregate, PUBKEY_AGGREGATE;
    hash_to_curve => inc_hash_to_curve, HASH_TO_CURVE;
    miller_loop => inc_miller_loop, MILLER_LOOP;
    miller_batch => inc_miller_batch, MILLER_BATCH;
    fp12_mul => inc_fp12_mul, FP12_MUL;
    commit_fp12 => inc_commit_fp12, COMMIT_FP12;
    g2_subgroup => inc_g2_subgroup, G2_SUBGROUP;
    final_exp => inc_final_exp, FINAL_EXP;
    decompress => inc_decompress, DECOMPRESS;
    recursive_verify => inc_recursive_verify_n, RECURSIVE_VERIFY;
}

#[inline]
pub fn inc_poseidon2() {
    inc_poseidon2_n(1);
}

#[inline]
pub fn inc_recursive_verify() {
    inc_recursive_verify_n(1);
}

impl OpCounts {
    /// Trace area these operations occupy, in Zisk cost units.
    ///
    /// Not seconds, and not convertible to seconds: see the module docs. It
    /// also counts nothing a guest spends in plain interpreted RISC-V, which on
    /// a witness-walking guest is two thirds of the real cost.
    pub fn cost(&self) -> u64 {
        self.poseidon2 * cost::POSEIDON2
            + self.acc_leaf * cost::ACC_LEAF
            + self.sha256f * cost::SHA256F
            + self.decompress * cost::DECOMPRESS
            + self.pubkey_aggregate * cost::PUBKEY_AGGREGATE
            + self.hash_to_curve * cost::HASH_TO_CURVE
            + self.miller_loop * cost::MILLER_LOOP
            + self.miller_batch * cost::MILLER_BATCH
            + self.fp12_mul * cost::FP12_MUL
            + self.commit_fp12 * cost::COMMIT_FP12
            + self.g2_subgroup * cost::G2_SUBGROUP
            + self.final_exp * cost::FINAL_EXP
    }

    /// Share of [`Self::cost`] spent on BLS.
    pub fn bls_fraction(&self) -> f64 {
        let bls = self.decompress * cost::DECOMPRESS
            + self.pubkey_aggregate * cost::PUBKEY_AGGREGATE
            + self.hash_to_curve * cost::HASH_TO_CURVE
            + self.miller_loop * cost::MILLER_LOOP
            + self.miller_batch * cost::MILLER_BATCH
            + self.fp12_mul * cost::FP12_MUL
            + self.commit_fp12 * cost::COMMIT_FP12
            + self.g2_subgroup * cost::G2_SUBGROUP
            + self.final_exp * cost::FINAL_EXP;
        let total = self.cost();
        if total == 0 {
            0.0
        } else {
            bls as f64 / total as f64
        }
    }
}

impl core::fmt::Display for OpCounts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "poseidon2={} acc_leaf={} sha256f={} decompress={} pubkeys={} h2c={} miller={}+{} \
             fp12_mul={} final_exp={} recursion={} => cost {}",
            self.poseidon2,
            self.acc_leaf,
            self.sha256f,
            self.decompress,
            self.pubkey_aggregate,
            self.hash_to_curve,
            self.miller_loop,
            self.miller_batch,
            self.fp12_mul,
            self.final_exp,
            self.recursive_verify,
            self.cost(),
        )
    }
}
