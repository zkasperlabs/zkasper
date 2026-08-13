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

use core::sync::atomic::{AtomicU64, Ordering};

/// Measured Zisk cost units, from `scripts/bench.py` against zisk v1.0.0-alpha.
pub mod cost {
    /// One accumulator node: a `syscall_poseidon2` plus state marshalling.
    pub const POSEIDON2: u64 = 3_033;
    /// One accumulator leaf: the same permutation over a packed G1 point.
    pub const ACC_LEAF: u64 = 3_979;
    /// One SHA-256 compression; an SSZ node is two of them.
    pub const SHA256F: u64 = 25_331;
    /// Add one public key into a running aggregate. The key arrives decompressed
    /// from the accumulator leaf, so this no longer includes a decompression.
    pub const PUBKEY_AGGREGATE: u64 = 67_854;
    /// Decompress one 48-byte public key. Only bootstrap and epoch-diff pay it.
    pub const DECOMPRESS: u64 = 49_311;
    /// Hash one message to G2.
    pub const HASH_TO_CURVE: u64 = 18_594_336;
    /// One Miller loop — the marginal cost of adding a pair to a multi-pairing.
    pub const MILLER_LOOP: u64 = 39_299_490;
    /// Final exponentiation, paid once per multi-pairing however many pairs it has.
    pub const FINAL_EXP: u64 = 169_455_773;

    /// Cost floor every proof pays regardless of what it computes. Roughly one
    /// pairing check, which is why small proofs are almost all overhead.
    pub const PROOF_BASE: u64 = 293_601_280;
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
    sha256f => inc_sha256f, SHA256F;
    pubkey_aggregate => inc_pubkey_aggregate, PUBKEY_AGGREGATE;
    hash_to_curve => inc_hash_to_curve, HASH_TO_CURVE;
    miller_loop => inc_miller_loop, MILLER_LOOP;
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
    /// Estimated Zisk cost of these operations, excluding the per-proof floor.
    pub fn cost(&self) -> u64 {
        self.poseidon2 * cost::POSEIDON2
            + self.sha256f * cost::SHA256F
            + self.decompress * cost::DECOMPRESS
            + self.pubkey_aggregate * cost::PUBKEY_AGGREGATE
            + self.hash_to_curve * cost::HASH_TO_CURVE
            + self.miller_loop * cost::MILLER_LOOP
            + self.final_exp * cost::FINAL_EXP
    }

    /// Share of [`Self::cost`] spent on BLS.
    pub fn bls_fraction(&self) -> f64 {
        let bls = self.decompress * cost::DECOMPRESS
            + self.pubkey_aggregate * cost::PUBKEY_AGGREGATE
            + self.hash_to_curve * cost::HASH_TO_CURVE
            + self.miller_loop * cost::MILLER_LOOP
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
            "poseidon2={} sha256f={} decompress={} pubkeys={} h2c={} miller={} final_exp={} \
             recursion={} => cost {}",
            self.poseidon2,
            self.sha256f,
            self.decompress,
            self.pubkey_aggregate,
            self.hash_to_curve,
            self.miller_loop,
            self.final_exp,
            self.recursive_verify,
            self.cost(),
        )
    }
}
