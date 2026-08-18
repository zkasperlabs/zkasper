//! Per-slot committee aggregates: the universe a slot's attesters are the
//! complement of.
//!
//! # What this buys
//!
//! A slot proof used to open a Merkle path for every attester. A mainnet slot
//! committee is about 30,030 validators and roughly 99.7% of them attest, so
//! that is 29,940 openings to prove the overwhelmingly common case tens of
//! thousands of times. Publishing, per slot, the *summed* public key and the
//! *summed* effective balance of that slot's committee turns the slot proof
//! inside out:
//!
//! ```text
//! agg_pk  = committee_pubkey  − Σ(absentee pubkeys)
//! support = committee_balance − Σ(absentee balances)
//! ```
//!
//! and only the ~90 absentees are opened.
//!
//! # Why it is sound
//!
//! **The public key side is pinned by the signature.** The multi-pairing forces
//! `agg_pk` to be the sum of the keys that actually signed the message. Omit a
//! genuine absentee and `agg_pk` comes out too large; name someone who did
//! attest and it comes out too small; name a validator outside the committee and
//! it is not a subset sum of the committee at all. Every case leaves
//! `e(agg_pk, H(m))·e(−G, sig) ≠ 1`, and producing a different multiset with the
//! same sum is an aggregate-signature forgery. The aggregation bitfield
//! therefore never enters the circuit.
//!
//! **The balance side is not pinned by the signature**, and that is the part
//! that has to be got right by construction. Nothing about a signature
//! constrains a balance. What binds the two here is the accumulator leaf: it is
//! a single Poseidon2 hash over `(pubkey, active_effective_balance)`, so a
//! validator cannot contribute its key to `committee_pubkey` while contributing
//! some other balance to `committee_balance`. [`verify`] sums both from the same
//! opened leaf in the same pass, and the same is true of the absentees the slot
//! proof subtracts. An adversary who could move the two apart could set any
//! finality threshold they liked, so nothing in this module ever accepts a
//! balance that did not come out of a leaf preimage it hashed itself.
//!
//! # What committee membership does *not* have to be
//!
//! It does not have to be the real swap-or-not shuffle, and this proof does not
//! compute one. What soundness needs from the assignment is only that the slot
//! buckets are **pairwise disjoint**, which is structural here: leaves are
//! consumed in strictly increasing index order, so each validator is read once
//! and lands in exactly one bucket, whatever the witness claims.
//!
//! Given disjointness, a wrong assignment cannot inflate anything. Write `U_s`
//! for the bucket the prover assigned to slot `s` and `A_s` for the absentees it
//! names. The pairing forces `U_s \ A_s` to be exactly the validators who signed
//! slot `s`'s message, so `support_s` is their balance; the buckets are disjoint
//! and each slot is counted at most once downstream, so summing over slots
//! counts every validator at most once. A prover who fabricates the shuffle
//! therefore gets a bucket whose members did not sign the message it is paired
//! against, and produces no proof at all. **A wrong committee assignment is a
//! liveness failure, not a soundness failure** — which is why the assignment is
//! plain witness, why the RANDAO seed is not bound in-circuit, and why 90 rounds
//! of swap-or-not over a million validators stay off the prover entirely.
//!
//! The one thing the pipeline must not do is mix buckets from two different
//! committee proofs of the same epoch: two partitions of the same validator set
//! overlap, and the disjointness argument is about one partition. Every proof
//! downstream therefore carries [`CommitteeOutput::committee_root`] and binds it.

use alloc::vec::Vec;

use crate::acc::{self, Digest, G1Point};
use crate::bls::PointSum;
use crate::merkle::{batch_root, batch_root_columns};
use crate::types::{CommitteeAggregate, CommitteeOutput, CommitteeWitness};

/// Depth of the per-epoch committee tree: one leaf per slot in the epoch.
///
/// Five levels hold 32 slots, which is mainnet's `SLOTS_PER_EPOCH` exactly and
/// Gnosis's 16 with room to spare. Slots a chain does not have stay empty, and
/// an empty leaf cannot be opened as a committee because no aggregate hashes to
/// the zero digest.
pub const TREE_DEPTH: u32 = 5;

/// Slots a committee tree of [`TREE_DEPTH`] can hold.
pub const MAX_SLOTS: u64 = 1 << TREE_DEPTH;

/// Hash one slot's committee aggregate.
///
/// This is [`acc::leaf`] — the same `H(G1 point, u64)` an accumulator leaf is,
/// because a committee aggregate is exactly a summed public key and a summed
/// balance. Sharing the hash is safe: the two trees are checked against
/// different published roots, so a validator leaf that happened to equal a
/// committee leaf would only describe a one-member committee, which is a
/// committee a prover could have claimed anyway.
#[inline]
pub fn leaf(aggregate: &CommitteeAggregate) -> Digest {
    acc::leaf(&aggregate.pubkey, aggregate.balance)
}

/// Root of a committee tree over `slots`, indexed by slot within the epoch.
///
/// Slots with no committee are the zero digest.
pub fn root(slots: &[Option<CommitteeAggregate>]) -> Digest {
    assert!(
        slots.len() as u64 <= MAX_SLOTS,
        "committee tree holds {MAX_SLOTS} slots",
    );

    let mut level: Vec<Digest> = (0..MAX_SLOTS as usize)
        .map(|s| match slots.get(s).and_then(|c| c.as_ref()) {
            Some(aggregate) => leaf(aggregate),
            None => acc::ZERO,
        })
        .collect();

    for _ in 0..TREE_DEPTH {
        level = level
            .chunks_exact(2)
            .map(|pair| acc::compress(&pair[0], &pair[1]))
            .collect();
    }
    level[0]
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

/// Words the header spends before the first member.
const HEADER_WORDS: usize = 12;

/// Words one member spends: index, twelve public-key limbs, balance, slot.
const MEMBER_WORDS: usize = 15;

/// Words one digest spends.
const DIGEST_WORDS: usize = 4;

/// Lay a committee witness out as the flat word array [`verify`] reads.
///
/// ```text
/// [0..4)   accumulator_commitment
/// [4..8)   acc_root
/// [8]      target_epoch
/// [9]      total_active_balance
/// [10]     member count
/// [11]     auxiliary count
/// [12..]   members, MEMBER_WORDS each
/// [..]     auxiliaries, DIGEST_WORDS each
/// ```
///
/// This exists because framing is what the committee proof was actually made
/// of. A `CommitteeMember` is fifteen `u64`s and nothing else, and Zisk hands a
/// guest its input as an 8-byte-aligned slice, so at a million validators the
/// bincode witness was 115 MB of self-describing records decoded field by field
/// into a second 115 MB `Vec`. Measured under `ziskemu -X`, that cost 1,157
/// proven RISC-V steps a member, of which 829 were the decode. A fixed stride
/// with the counts up front lets the guest read every member where the prover
/// put it, and the same measurement comes out at 328.
pub fn encode(witness: &CommitteeWitness) -> Vec<u64> {
    let mut words = Vec::with_capacity(
        HEADER_WORDS
            + witness.members.len() * MEMBER_WORDS
            + witness.acc_multi_proof.auxiliaries.len() * DIGEST_WORDS,
    );
    words.extend_from_slice(&witness.accumulator_commitment);
    words.extend_from_slice(&witness.acc_root);
    words.push(witness.target_epoch);
    words.push(witness.total_active_balance);
    words.push(witness.members.len() as u64);
    words.push(witness.acc_multi_proof.auxiliaries.len() as u64);

    for member in &witness.members {
        words.push(member.validator_index);
        words.extend_from_slice(&member.pubkey);
        words.push(member.active_effective_balance);
        words.push(member.slot_in_epoch);
    }
    for auxiliary in &witness.acc_multi_proof.auxiliaries {
        words.extend_from_slice(auxiliary);
    }
    words
}

/// The same array as the bytes a witness file or a prover's stdin carries.
pub fn to_bytes(words: &[u64]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// Reinterpret a run of words as the fixed-stride records it holds.
///
/// Sound for any `[u64; N]`: it is `N` words with no padding, its alignment is
/// a `u64`'s, and every bit pattern is a valid one. This is what makes reading
/// a member free — the guest borrows it out of the input buffer rather than
/// copying it into one of its own.
fn records<const N: usize>(words: &[u64]) -> &[[u64; N]] {
    let (prefix, records, suffix) = unsafe { words.align_to::<[u64; N]>() };
    assert!(
        prefix.is_empty() && suffix.is_empty(),
        "committee witness is not a whole number of records",
    );
    records
}

/// Verify a committee proof: sum each slot's committee out of the accumulator.
///
/// The witness names every committee member once, in strictly increasing
/// validator-index order, with the leaf preimage that opens it, in the flat
/// layout [`encode`] writes. One batched multi-proof establishes that every one
/// of those leaves is in the accumulator; the same pass sums each slot's public
/// keys and balances. See the module docs for why the slot each member is
/// assigned to needs no proof of its own.
pub fn verify(witness: &[u64], acc_depth: u32) -> CommitteeOutput {
    assert!(
        witness.len() >= HEADER_WORDS,
        "committee witness is shorter than its header",
    );
    let accumulator_commitment: Digest = witness[0..4].try_into().expect("a digest is four words");
    let acc_root: Digest = witness[4..8].try_into().expect("a digest is four words");
    let target_epoch = witness[8];
    let member_count = witness[10] as usize;

    assert_eq!(
        acc::commitment(&acc_root, witness[9]),
        accumulator_commitment,
        "accumulator commitment mismatch",
    );

    let auxiliaries = HEADER_WORDS + member_count * MEMBER_WORDS;
    assert_eq!(
        witness.len(),
        auxiliaries + witness[11] as usize * DIGEST_WORDS,
        "committee witness does not hold the counts its header names",
    );

    let mut indices: Vec<u64> = Vec::with_capacity(member_count);
    let mut leaves: Vec<Digest> = Vec::with_capacity(member_count);
    let mut sums: Vec<PointSum> = alloc::vec![PointSum::default(); MAX_SLOTS as usize];
    let mut balances: Vec<u64> = alloc::vec![0u64; MAX_SLOTS as usize];

    let mut previous: Option<u64> = None;
    for member in records::<MEMBER_WORDS>(&witness[HEADER_WORDS..auxiliaries]) {
        let validator_index = member[0];
        let pubkey: &G1Point = member[1..13].try_into().expect("a point is twelve limbs");
        let active_effective_balance = member[13];
        let slot_in_epoch = member[14];

        // Strictly increasing is what makes the slot buckets disjoint: a
        // validator read once cannot land in two of them.
        if let Some(previous) = previous {
            assert!(
                validator_index > previous,
                "committee members must be strictly increasing: {validator_index} followed {previous}",
            );
        }
        previous = Some(validator_index);

        assert!(
            slot_in_epoch < MAX_SLOTS,
            "slot {slot_in_epoch} is past the {MAX_SLOTS} a committee tree holds",
        );

        // Key and balance come out of the one preimage the accumulator commits
        // to, so nothing can inflate the balance side on its own.
        indices.push(validator_index);
        leaves.push(acc::leaf(pubkey, active_effective_balance));
        let slot = slot_in_epoch as usize;
        sums[slot]
            .add(pubkey)
            .expect("committee aggregation hit a shared x-coordinate");
        balances[slot] += active_effective_balance;
    }

    assert_eq!(
        batch_root_columns(
            acc::compress,
            indices,
            leaves,
            records::<DIGEST_WORDS>(&witness[auxiliaries..]),
            acc_depth,
        ),
        acc_root,
        "accumulator root mismatch",
    );

    let slots: Vec<Option<CommitteeAggregate>> = sums
        .iter()
        .zip(&balances)
        .map(|(sum, &balance)| {
            sum.get()
                .map(|pubkey| CommitteeAggregate { pubkey, balance })
        })
        .collect();

    CommitteeOutput {
        accumulator_commitment,
        target_epoch,
        committee_root: root(&slots),
    }
}

/// Recompute a committee tree root from the slots a proof opened.
///
/// `opened` must be sorted by slot and strictly increasing. Returns the root the
/// caller compares against the one the committee proof published.
pub fn opened_root(opened: &[(u64, CommitteeAggregate)], auxiliaries: &[Digest]) -> Digest {
    let leaves: Vec<(Digest, u64)> = opened
        .iter()
        .map(|(slot, aggregate)| (leaf(aggregate), *slot))
        .collect();
    batch_root(acc::compress, &leaves, auxiliaries, TREE_DEPTH)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Committee aggregates as the tree sees them: a summed point and a summed
    /// balance, with no need for either to be a real sum here.
    fn aggregate(seed: u64, balance: u64) -> CommitteeAggregate {
        CommitteeAggregate {
            pubkey: [seed; 12],
            balance,
        }
    }

    #[test]
    fn a_slot_with_no_committee_is_the_zero_leaf() {
        assert_ne!(root(&[Some(aggregate(1, 32))]), root(&[None]));
    }

    #[test]
    fn the_root_binds_the_slot_a_committee_sits_at() {
        assert_ne!(
            root(&[Some(aggregate(1, 32)), None]),
            root(&[None, Some(aggregate(1, 32))]),
            "moving a committee between slots must change the root",
        );
    }

    /// The balance side is the one a signature could never catch, so the leaf has
    /// to be what catches it.
    #[test]
    fn the_root_binds_the_balance_as_well_as_the_key() {
        assert_ne!(
            root(&[Some(aggregate(1, 64))]),
            root(&[Some(aggregate(1, 65))]),
        );
    }

    /// The bytes a witness file carries and the words the guest reads have to
    /// be the same thing: Zisk hands the input in as an aligned byte slice and
    /// the guest views it as `u64`s without touching it.
    #[test]
    fn the_wire_format_is_the_word_array_little_endian() {
        let witness = CommitteeWitness {
            accumulator_commitment: [1, 2, 3, 4],
            target_epoch: 430529,
            acc_root: [5, 6, 7, 8],
            total_active_balance: 32_000_000_000,
            members: alloc::vec![crate::types::CommitteeMember {
                validator_index: 9,
                pubkey: [11; 12],
                active_effective_balance: 32_000_000_000,
                slot_in_epoch: 3,
            }],
            acc_multi_proof: crate::types::AccMultiProof {
                auxiliaries: alloc::vec![[12, 13, 14, 15]],
            },
        };
        let words = encode(&witness);

        assert_eq!(words.len(), HEADER_WORDS + MEMBER_WORDS + DIGEST_WORDS);
        assert_eq!(
            &words[10..12],
            &[1, 1],
            "the counts locate everything after"
        );
        assert_eq!(
            to_bytes(&words),
            words
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
    }

    /// The tree a slot proof opens against and the tree the committee proof
    /// publishes are the same tree, or nothing downstream could open anything.
    #[test]
    fn opening_every_slot_reproduces_the_root() {
        let slots = alloc::vec![
            Some(aggregate(1, 64)),
            None,
            Some(aggregate(3, 32)),
            Some(aggregate(4, 64)),
        ];
        let leaves: Vec<(Digest, u64)> = (0..MAX_SLOTS)
            .map(|s| {
                let digest = match slots.get(s as usize).and_then(|c| c.as_ref()) {
                    Some(aggregate) => leaf(aggregate),
                    None => acc::ZERO,
                };
                (digest, s)
            })
            .collect();

        assert_eq!(
            batch_root(acc::compress, &leaves, &[], TREE_DEPTH),
            root(&slots),
        );
    }
}
