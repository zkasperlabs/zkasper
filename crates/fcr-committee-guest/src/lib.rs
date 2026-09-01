//! The committee proof FCR needs, and finality does not.
//!
//! # Why this exists beside the finality committee proof rather than inside it
//!
//! Finality's denominator is global — two thirds of the whole active balance,
//! summed over every bucket — so a partition the prover chose buys nothing
//! there, and its committee proof leaves the assignment as unproven witness.
//! **FCR's denominator is a bucket.** The moment a threshold is a fraction of
//! one slot's committee weight, a prover who picks the partition picks its own
//! denominator: concentrate the stake you control into bucket 1, have it all
//! vote, and 2.97% of total stake forges a one-slot confirmation with ordering,
//! pairing and leaf binding all passing.
//!
//! Proving the shuffle is the only thing that closes it. It could have been
//! fused into the finality committee proof, saving a pass over the validator
//! set — but that would move finality's ELF, and therefore its verification key,
//! and therefore every key baked into a guest that verifies it. So it is a
//! separate proof, on FCR's own card, and the finality pipeline does not know it
//! exists.
//!
//! # What pins the active set
//!
//! The shuffle is over the active set, so a prover who can change *which*
//! validators are in it can change every assignment. Three checks pin it, and
//! they are only sound together:
//!
//! 1. **indices strictly increase** — no validator opened twice;
//! 2. **every opened balance is non-zero** — the accumulator stores zero for an
//!    inactive validator, so this is what "active" means here;
//! 3. **the opened balances sum to `total_active_balance`** — which the
//!    accumulator commitment binds.
//!
//! Drop a validator and the sum falls short. Add an inactive one and the sum
//! still holds, but the set size moves and every shuffled position with it — so
//! (2) is not decoration, it is what makes (3) load-bearing.
//!
//! # The seed is published, not derived
//!
//! `get_seed` reads `state.randao_mixes`, an SSZ opening against a state root
//! this circuit does not hold. Rather than drag the state into the circuit, the
//! seed is an input and it is **published**, so a verifier ties it to a
//! finalization proof. A consumer that cannot do that has learned that *an*
//! assignment was computed correctly, not *which* one.
//!
//! # Cost
//!
//! This is the spec's `compute_shuffled_index` per validator: 90 rounds each,
//! and at mainnet scale that is the 10,207-second variant. It is here because it
//! is obviously the specification, and `shuffle-bench-guest` measured the two
//! faster ways of computing the same permutation — whole-set swap-or-not at
//! 115.3 s and bit-sliced at **44.2 s** — against `V_SELFTEST`, which holds them
//! to this transcription. The production guest swaps the kernel and keeps the
//! bindings above; the equivalence harness already exists.

extern crate alloc;

use alloc::vec::Vec;
use ziskos::syscalls::{syscall_sha256_f, SyscallSha256Params};
use zkasper_common::acc::Digest;
use zkasper_common::types::CommitteeAggregate;
use zkasper_fcr_types::{FcrCommitteeOutput, FcrCommitteeWitness};

/// `SHUFFLE_ROUND_COUNT`.
const ROUNDS: u8 = 90;

/// Prove the epoch's committee assignment and its per-slot sums.
pub fn verify_fcr_committee(
    witness: &FcrCommitteeWitness,
    slots_per_epoch: u64,
) -> FcrCommitteeOutput {
    verify_fcr_committee_with_depth(
        witness,
        slots_per_epoch,
        zkasper_common::constants::ACC_TREE_DEPTH,
    )
}

/// The same, with a configurable accumulator depth.
pub fn verify_fcr_committee_with_depth(
    witness: &FcrCommitteeWitness,
    slots_per_epoch: u64,
    acc_depth: u32,
) -> FcrCommitteeOutput {
    use zkasper_common::acc;
    use zkasper_common::bls::PointSum;
    use zkasper_common::committee;

    assert_eq!(
        acc::commitment(&witness.acc_root, witness.total_active_balance),
        witness.accumulator_commitment,
        "accumulator commitment mismatch",
    );
    assert!(!witness.active.is_empty(), "the active set is empty");
    assert!(
        slots_per_epoch <= committee::MAX_SLOTS,
        "committee tree holds {} slots",
        committee::MAX_SLOTS,
    );

    // (1) and (2), and the leaves for the opening.
    let mut leaves: Vec<(Digest, u64)> = Vec::with_capacity(witness.active.len());
    let mut summed: u64 = 0;
    let mut previous: Option<u64> = None;
    for v in &witness.active {
        if let Some(p) = previous {
            assert!(
                v.validator_index > p,
                "active set must be in increasing index order: {} followed {p}",
                v.validator_index,
            );
        }
        previous = Some(v.validator_index);
        assert!(
            v.active_effective_balance > 0,
            "validator {} is opened as active with no balance; the accumulator \
             stores zero for an inactive validator, so this would inflate the \
             set size and move every shuffled position",
            v.validator_index,
        );
        summed = summed
            .checked_add(v.active_effective_balance)
            .expect("active balances overflowed");
        leaves.push((
            acc::leaf(&v.pubkey, v.active_effective_balance),
            v.validator_index,
        ));
    }

    // (3) — with (1) and (2), this is what makes the set exactly the active set.
    assert_eq!(
        summed, witness.total_active_balance,
        "opened active balances do not sum to the committed total active balance",
    );

    assert_eq!(
        zkasper_common::merkle::batch_root(
            acc::compress,
            &leaves,
            &witness.acc_multi_proof.auxiliaries,
            acc_depth,
        ),
        witness.acc_root,
        "accumulator root mismatch",
    );

    // The assignment.
    let n = witness.active.len();
    let mut sums: Vec<Option<(PointSum, u64)>> = (0..slots_per_epoch).map(|_| None).collect();
    let pivots = pivots(&witness.seed, n);
    for (index, v) in witness.active.iter().enumerate() {
        let position = committee_position(index, n, &witness.seed, &pivots);
        let slot = slot_of_position(position, n, slots_per_epoch);
        // Lighthouse's own predicate, running inside the guest.
        assert!(
            fast_confirmation_core::counts_toward_support(
                v.active_effective_balance,
                false,
                false,
                true,
                true,
            ),
            "validator {} does not count toward support",
            v.validator_index,
        );
        let entry = sums[slot as usize].get_or_insert_with(|| (PointSum::default(), 0));
        entry
            .0
            .add(&v.pubkey)
            .expect("public key aggregation hit a shared x-coordinate");
        entry.1 += v.active_effective_balance;
    }

    let slots: Vec<Option<CommitteeAggregate>> = sums
        .into_iter()
        .map(|entry| {
            entry.map(|(keys, balance)| CommitteeAggregate {
                pubkey: keys
                    .get()
                    .expect("a slot's committee summed to the identity"),
                balance,
            })
        })
        .collect();

    FcrCommitteeOutput {
        accumulator_commitment: witness.accumulator_commitment,
        seed: witness.seed,
        epoch: witness.epoch,
        committee_root: committee::root(&slots),
        active_count: n as u64,
    }
}

/// Spec: the `pivot` of each shuffle round. Hoisted, because it does not depend
/// on the index being shuffled.
fn pivots(seed: &[u8; 32], n: usize) -> [u64; ROUNDS as usize] {
    let mut buf = [0u8; 33];
    buf[..32].copy_from_slice(seed);
    let mut out = [0u64; ROUNDS as usize];
    for (r, p) in out.iter_mut().enumerate() {
        buf[32] = r as u8;
        *p = u64::from_le_bytes(sha256_short(&buf)[0..8].try_into().unwrap()) % n as u64;
    }
    out
}

/// Where in the epoch's shuffled committee list a validator sits.
///
/// **This is the inverse of `compute_shuffled_index`, and the direction is the
/// whole point.** `compute_committee` reads
/// `indices[compute_shuffled_index(i, ...)]` for each committee position `i`, so
/// the spec maps *position to validator*. What a per-validator circuit needs is
/// the other way round, and swap-or-not inverts by running its rounds backwards
/// — the pivots are the same, only the order changes.
///
/// Applying the forward permutation here instead produces a committee root that
/// disagrees with the chain, which is how this was found.
fn committee_position(
    mut index: usize,
    n: usize,
    seed: &[u8; 32],
    pivots: &[u64; ROUNDS as usize],
) -> usize {
    let mut buf = [0u8; 37];
    buf[..32].copy_from_slice(seed);
    for r in (0..ROUNDS as usize).rev() {
        buf[32] = r as u8;
        let flip = (pivots[r] as usize + n - index) % n;
        let position = if index > flip { index } else { flip };
        buf[33..37].copy_from_slice(&((position / 256) as u32).to_le_bytes());
        let source = sha256_short(&buf);
        if (source[(position % 256) / 8] >> (position % 8)) & 1 == 1 {
            index = flip;
        }
    }
    index
}

/// Spec: `compute_shuffled_index`, transcribed. Only the tests call it — the
/// circuit needs [`committee_position`], its inverse — but it stays because the
/// inverse is only meaningful against it and the equivalence test checks both
/// directions against Lighthouse's reference.
#[cfg(test)]
fn shuffled_index(
    mut index: usize,
    n: usize,
    seed: &[u8; 32],
    pivots: &[u64; ROUNDS as usize],
) -> usize {
    let mut buf = [0u8; 37];
    buf[..32].copy_from_slice(seed);
    for (r, pivot) in pivots.iter().enumerate() {
        buf[32] = r as u8;
        let flip = (*pivot as usize + n - index) % n;
        let position = if index > flip { index } else { flip };
        buf[33..37].copy_from_slice(&((position / 256) as u32).to_le_bytes());
        let source = sha256_short(&buf);
        if (source[(position % 256) / 8] >> (position % 8)) & 1 == 1 {
            index = flip;
        }
    }
    index
}

/// Which slot a shuffled position attests in.
///
/// The epoch's committees are `slots_per_epoch` equal slices of the shuffled
/// list, so a position's slot is where its slice falls.
fn slot_of_position(p: usize, n: usize, slots_per_epoch: u64) -> u64 {
    let s = (slots_per_epoch * (p as u64 + 1) - 1) / n as u64;
    if s >= slots_per_epoch {
        slots_per_epoch - 1
    } else {
        s
    }
}

/// SHA-256 of a message that fits one block, through the precompile.
fn sha256_short(msg: &[u8]) -> [u8; 32] {
    const IV: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut block = [0u8; 64];
    block[..msg.len()].copy_from_slice(msg);
    block[msg.len()] = 0x80;
    block[56..64].copy_from_slice(&((msg.len() as u64) * 8).to_be_bytes());

    let mut input = [0u64; 8];
    for (i, word) in input.iter_mut().enumerate() {
        *word = u64::from_le_bytes(block[8 * i..8 * i + 8].try_into().unwrap());
    }
    let mut state = [
        IV[0] as u64 | (IV[1] as u64) << 32,
        IV[2] as u64 | (IV[3] as u64) << 32,
        IV[4] as u64 | (IV[5] as u64) << 32,
        IV[6] as u64 | (IV[7] as u64) << 32,
    ];
    syscall_sha256_f(&mut SyscallSha256Params {
        state: &mut state,
        input: &input,
    });

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[8 * i..8 * i + 4].copy_from_slice(&(state[i] as u32).to_be_bytes());
        out[8 * i + 4..8 * i + 8].copy_from_slice(&((state[i] >> 32) as u32).to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The transcription is held to Lighthouse's own `compute_shuffled_index`,
    /// which is the spec implementation the consensus tests run against.
    ///
    /// This is the check that matters: everything else in this file is bindings,
    /// and bindings on the wrong permutation prove the wrong thing.
    #[test]
    fn the_shuffle_is_the_reference_shuffle() {
        for seed_byte in [0u8, 7, 200] {
            let seed = [seed_byte; 32];
            for n in [1usize, 2, 3, 17, 64, 100, 513] {
                let pivots = pivots(&seed, n);
                for index in 0..n {
                    let ours = shuffled_index(index, n, &seed, &pivots);
                    let theirs =
                        swap_or_not_shuffle::compute_shuffled_index(index, n, &seed, ROUNDS)
                            .expect("reference refused a valid input");
                    assert_eq!(
                        ours, theirs,
                        "seed {seed_byte}, n {n}, index {index}: {ours} against {theirs}",
                    );
                }
            }
        }
    }

    /// A permutation, not merely a function: every position is hit once.
    #[test]
    fn the_assignment_is_a_permutation() {
        let seed = [3u8; 32];
        let n = 257;
        let pivots = pivots(&seed, n);
        let mut seen = alloc::vec![false; n];
        for index in 0..n {
            let p = committee_position(index, n, &seed, &pivots);
            assert!(!seen[p], "position {p} assigned twice");
            seen[p] = true;
        }
    }

    /// And it is the *inverse* of the reference, which is the direction
    /// `compute_committee` reads it in. Getting this backwards produces a
    /// committee root that disagrees with the chain and nothing else complains.
    #[test]
    fn committee_position_inverts_the_reference_shuffle() {
        for seed_byte in [1u8, 42] {
            let seed = [seed_byte; 32];
            for n in [2usize, 31, 128, 999] {
                let pivots = pivots(&seed, n);
                for index in 0..n {
                    let position = committee_position(index, n, &seed, &pivots);
                    let back =
                        swap_or_not_shuffle::compute_shuffled_index(position, n, &seed, ROUNDS)
                            .unwrap();
                    assert_eq!(back, index, "seed {seed_byte}, n {n}, index {index}");
                }
            }
        }
    }

    /// Every validator lands in exactly one slot, and every slot is used when
    /// the set is big enough to fill them.
    #[test]
    fn every_position_falls_in_one_slot_and_the_slots_are_covered() {
        let n = 1000;
        let mut per_slot = [0usize; 32];
        for p in 0..n {
            per_slot[slot_of_position(p, n, 32) as usize] += 1;
        }
        assert_eq!(per_slot.iter().sum::<usize>(), n);
        assert!(per_slot.iter().all(|&c| c > 0), "{per_slot:?}");
        // Slices differ by at most one, which is what "equal slices" means for
        // a count that does not divide.
        let (lo, hi) = (
            *per_slot.iter().min().unwrap(),
            *per_slot.iter().max().unwrap(),
        );
        assert!(hi - lo <= 1, "{lo}..{hi}");
    }

    #[test]
    fn a_single_validator_attests_in_one_slot() {
        assert_eq!(slot_of_position(0, 1, 32), 31);
    }
}
