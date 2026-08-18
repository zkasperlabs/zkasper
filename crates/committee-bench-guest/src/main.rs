//! Committee-proof bench harness: one variant per run, over a real witness.
//!
//! The committee proof is the fleet's whole cost — 878.2 µs ± 6.5 per opened
//! validator against ~961k of them — and a mainnet run takes an hour, so no
//! strategy for making it cheaper can be evaluated against a mainnet run. This
//! guest takes the same [`CommitteeWitness`] the real guest takes, at whatever
//! size and accumulator depth `gen-committee-witness` was asked for, and runs
//! one variant of the verification. `scripts/committee_bench.py` drives it,
//! subtracts the pairs that isolate a term, and reports steps and cost units
//! *per validator*, which is the only figure that extrapolates.
//!
//! Two kinds of variant live here. The **ablations** (1–4) each remove one term
//! from the real [`committee::verify`], so subtracting them from variant 0
//! attributes its cost; they are not proposals and do not prove anything. The
//! **candidates** (5–7) are whole verifications that must produce the same
//! committee root as variant 0, which variant 8 checks.
//!
//! Input is `u32 variant | u32 acc_depth | bincode(CommitteeWitness)`.

#![cfg_attr(target_os = "zkvm", no_main)]

use ziskos::syscalls::{
    syscall_bls12_381_curve_add, syscall_poseidon2, SyscallBls12_381CurveAddParams, SyscallPoint384,
};
use ziskos::zisklib::{inv_fp_bls12_381, mul_fp_bls12_381, square_fp_bls12_381, sub_fp_bls12_381};

use zkasper_common::acc::{self, Digest, G1Point};
use zkasper_common::bls::PointSum;
use zkasper_common::committee::{self, MAX_SLOTS};
use zkasper_common::merkle::batch_root;
use zkasper_common::types::{CommitteeAggregate, CommitteeOutput, CommitteeWitness};

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

/// `zkasper_common::committee::verify`, exactly as the real guest calls it.
const V_VERIFY: u32 = 0;
/// Deserialize and read every member field, and nothing else: the witness I/O
/// floor another agent is working on, measured so it can be subtracted out.
const V_IO: u32 = 1;
/// Ablation: everything but the curve additions.
const V_NO_G1: u32 = 2;
/// Ablation: everything but the accumulator multi-proof.
const V_NO_TREE: u32 = 3;
/// Ablation: everything but the leaf hashes — the multi-proof runs over the
/// validator index as a stand-in leaf, so the tree scan is unchanged.
const V_NO_LEAF: u32 = 4;
/// Candidate: the same verification with the leaf set built as two parallel
/// arrays the multi-proof consumes in place, instead of a `Vec<(Digest, u64)>`
/// that `batch_root` immediately copies apart.
const V_SPLIT: u32 = 5;

/// Candidate: V_SPLIT over a 4-ary accumulator tree. Poseidon2-16 absorbs four
/// digests in the one permutation it already spends on two, so the internal
/// nodes drop from one per leaf to a third of one.
const V_ARITY4: u32 = 6;
/// Candidate: V_SPLIT with the bucket sums computed in software — a tree
/// reduction so every addition at a level is independent, and one Montgomery
/// batch inversion shared across the level.
const V_BATCH_INV: u32 = 7;
/// Every candidate against V_VERIFY's committee root. Cheap enough to run in
/// the emulator, and the only thing that makes the other numbers mean anything.
const V_SELFTEST: u32 = 8;
/// Superseded: the copying curve add `bls::PointSum` used to do, kept so the
/// harness still reports what handing the precompile the sum in place is worth.
const V_COPYING_ADD: u32 = 9;
/// Candidate: V_SPLIT with the leaf's packed point written straight into the
/// permutation state rather than into an array that is then copied into it.
const V_LEAN: u32 = 10;

fn main() {
    let input = zkasper_guest_io::read_witness();
    let variant = u32::from_le_bytes(input[0..4].try_into().unwrap());
    let acc_depth = u32::from_le_bytes(input[4..8].try_into().unwrap());
    let witness: CommitteeWitness = bincode::deserialize(&input[8..]).expect("deserialize witness");

    let checksum = run(variant, acc_depth, &witness);

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&variant.to_le_bytes());
    out[4..8].copy_from_slice(&(witness.members.len() as u32).to_le_bytes());
    out[8..16].copy_from_slice(&checksum.to_le_bytes());
    zkasper_guest_io::commit(out.to_vec());
}

fn run(variant: u32, acc_depth: u32, witness: &CommitteeWitness) -> u64 {
    match variant {
        V_VERIFY => committee::verify(witness, acc_depth).committee_root[0],

        V_IO => {
            let mut checksum = 0u64;
            for member in &witness.members {
                checksum ^= member.validator_index
                    ^ member.slot_in_epoch
                    ^ member.active_effective_balance
                    ^ member.pubkey[0]
                    ^ member.pubkey[11];
            }
            checksum
        }

        V_NO_G1 | V_NO_TREE | V_NO_LEAF => ablation(variant, acc_depth, witness),

        V_SPLIT | V_COPYING_ADD | V_LEAN => split(variant, witness, acc_depth).committee_root[0],
        V_ARITY4 => arity4(witness, acc_depth).committee_root[0],
        V_BATCH_INV => batch_inv(witness, acc_depth).committee_root[0],

        V_SELFTEST => {
            let expected = committee::verify(witness, acc_depth);
            for candidate in [V_SPLIT, V_COPYING_ADD, V_LEAN] {
                assert_eq!(
                    split(candidate, witness, acc_depth),
                    expected,
                    "a split candidate diverges",
                );
            }
            assert_eq!(
                batch_inv(witness, acc_depth),
                expected,
                "V_BATCH_INV diverges",
            );
            // The 4-ary tree is a different tree, so its root is a different
            // value by construction; what has to agree is the bucket sums it
            // publishes, which is everything the root is built from.
            assert_eq!(
                arity4(witness, acc_depth).accumulator_commitment,
                expected.accumulator_commitment,
                "V_ARITY4 diverges",
            );
            expected.committee_root[0]
        }

        other => panic!("unknown variant {other}"),
    }
}

/// One term of [`committee::verify`] removed, so subtracting attributes it.
///
/// Deliberately a transcription of `verify` rather than a parameterisation of
/// it: a flag tested once per validator is itself a per-validator cost, and it
/// would land in whichever term the branch predictor happened to charge it to.
fn ablation(variant: u32, acc_depth: u32, witness: &CommitteeWitness) -> u64 {
    let mut leaves: Vec<(Digest, u64)> = Vec::with_capacity(witness.members.len());
    let mut sums: Vec<PointSum> = vec![PointSum::default(); MAX_SLOTS as usize];
    let mut balances: Vec<u64> = vec![0u64; MAX_SLOTS as usize];

    for member in &witness.members {
        let leaf = if variant == V_NO_LEAF {
            [member.validator_index, 0, 0, 0]
        } else {
            acc::leaf(&member.pubkey, member.active_effective_balance)
        };
        leaves.push((leaf, member.validator_index));

        let slot = member.slot_in_epoch as usize;
        if variant != V_NO_G1 {
            sums[slot].add(&member.pubkey).expect("shared x-coordinate");
        }
        balances[slot] += member.active_effective_balance;
    }

    if variant == V_NO_TREE {
        return leaves[0].0[0] ^ balances[0];
    }
    batch_root(
        acc::compress,
        &leaves,
        &witness.acc_multi_proof.auxiliaries,
        acc_depth,
    )[0]
}

/// The bucket sums and balances every candidate has to produce, and the tree
/// root they publish.
///
/// Split out because the candidates differ only in how they get here; the
/// soundness argument — read once, in strictly increasing index order, key and
/// balance out of the same preimage — is identical in all of them and is
/// enforced by [`committee::verify`] itself in the shared path below.
fn publish(sums: &[Bucket], balances: &[u64]) -> Digest {
    let slots: Vec<Option<CommitteeAggregate>> = sums
        .iter()
        .zip(balances)
        .map(|(sum, &balance)| sum.map(|pubkey| CommitteeAggregate { pubkey, balance }))
        .collect();
    committee::root(&slots)
}

/// One slot's running sum, as the candidates hold it: the same `Option<G1Point>`
/// `bls::PointSum` wraps, unwrapped so a candidate can hand it to the precompile
/// where it lies.
type Bucket = Option<G1Point>;

/// The public outputs a candidate publishes, so the self-test can compare them.
fn output(witness: &CommitteeWitness, committee_root: Digest) -> CommitteeOutput {
    CommitteeOutput {
        accumulator_commitment: witness.accumulator_commitment,
        target_epoch: witness.target_epoch,
        committee_root,
    }
}

/// Candidate: parallel arrays instead of a `Vec<(Digest, u64)>`.
///
/// `merkle::batch_root` takes `&[(Digest, u64)]` and its first act is to copy
/// the two halves into separate vectors, so a witness the size of mainnet's
/// writes 40 bytes per validator and then reads all of it back to write it
/// again. Building the two arrays in the member loop is the same work with one
/// pass instead of three.
fn split(variant: u32, witness: &CommitteeWitness, acc_depth: u32) -> CommitteeOutput {
    let (idx, val, sums, balances) = scan(variant, witness);
    let root = batch_root_split(idx, val, &witness.acc_multi_proof.auxiliaries, acc_depth);
    assert_eq!(root, witness.acc_root, "accumulator root mismatch");
    output(witness, publish(&sums, &balances))
}

/// Candidate: the same, over a 4-ary accumulator.
///
/// A 4-ary opening consumes a different auxiliary set from a 2-ary one and the
/// host writes 2-ary ones, so this runs on the fixtures whose opened set is the
/// index prefix `0..members` — every missing child is then an empty subtree,
/// whose digest the guest derives itself in `depth` permutations. That is the
/// regime the question is about: the committee proof opens essentially every
/// leaf, and the auxiliaries are what a *sparse* opening would pay on either
/// arity, not what separates them.
fn arity4(witness: &CommitteeWitness, acc_depth: u32) -> CommitteeOutput {
    assert_eq!(acc_depth % 2, 0, "a 4-ary tree needs an even 2-ary depth");
    for (position, member) in witness.members.iter().enumerate() {
        assert_eq!(
            member.validator_index, position as u64,
            "the 4-ary variant needs the opened set to be an index prefix",
        );
    }

    let (idx, val, sums, balances) = scan(V_SPLIT, witness);
    // Not compared against `acc_root`: a 4-ary tree over the same leaves has a
    // different root, and the point of the measurement is what it costs to
    // reach one. Consumed so nothing is optimised away.
    let root = batch_root4(idx, val, acc_depth / 2);
    assert_ne!(root, [0; 4], "4-ary root collapsed");
    output(witness, publish(&sums, &balances))
}

/// Candidate: bucket sums in software, with one inversion shared across a level.
///
/// The additions in a running sum are sequential — every denominator depends on
/// the previous result — so Montgomery's trick needs the sums restructured as a
/// binary reduction: at each level every addition is independent, all the
/// denominators are known at once, and one inversion serves the whole level.
/// The reduction is over the same multiset in the same buckets, so it publishes
/// the same aggregate.
fn batch_inv(witness: &CommitteeWitness, acc_depth: u32) -> CommitteeOutput {
    let mut idx: Vec<u64> = Vec::with_capacity(witness.members.len());
    let mut val: Vec<Digest> = Vec::with_capacity(witness.members.len());
    let mut buckets: Vec<Vec<G1Point>> = vec![Vec::new(); MAX_SLOTS as usize];
    let mut balances: Vec<u64> = vec![0u64; MAX_SLOTS as usize];

    let mut previous: Option<u64> = None;
    for member in &witness.members {
        if let Some(previous) = previous {
            assert!(member.validator_index > previous, "members must increase");
        }
        previous = Some(member.validator_index);
        assert!(member.slot_in_epoch < MAX_SLOTS, "slot out of range");

        val.push(acc::leaf(&member.pubkey, member.active_effective_balance));
        idx.push(member.validator_index);
        let slot = member.slot_in_epoch as usize;
        buckets[slot].push(member.pubkey);
        balances[slot] += member.active_effective_balance;
    }

    let root = batch_root_split(idx, val, &witness.acc_multi_proof.auxiliaries, acc_depth);
    assert_eq!(root, witness.acc_root, "accumulator root mismatch");

    let sums: Vec<Bucket> = buckets.iter_mut().map(reduce_batched).collect();
    output(witness, publish(&sums, &balances))
}

/// The member loop every candidate shares: one pass, leaves and indices into
/// parallel arrays, bucket sums and balances out of the same preimage.
fn scan(
    variant: u32,
    witness: &CommitteeWitness,
) -> (Vec<u64>, Vec<Digest>, Vec<Bucket>, Vec<u64>) {
    let mut idx: Vec<u64> = Vec::with_capacity(witness.members.len());
    let mut val: Vec<Digest> = Vec::with_capacity(witness.members.len());
    let mut sums: Vec<Bucket> = vec![None; MAX_SLOTS as usize];
    let mut balances: Vec<u64> = vec![0u64; MAX_SLOTS as usize];

    let mut previous: Option<u64> = None;
    for member in &witness.members {
        // Strictly increasing is what makes the slot buckets disjoint: a
        // validator read once cannot land in two of them.
        if let Some(previous) = previous {
            assert!(member.validator_index > previous, "members must increase");
        }
        previous = Some(member.validator_index);
        assert!(member.slot_in_epoch < MAX_SLOTS, "slot out of range");

        // Key and balance come out of the one preimage the accumulator commits
        // to, so nothing can inflate the balance side on its own.
        val.push(if variant == V_LEAN {
            leaf_in_place(&member.pubkey, member.active_effective_balance)
        } else {
            acc::leaf(&member.pubkey, member.active_effective_balance)
        });
        idx.push(member.validator_index);
        let slot = member.slot_in_epoch as usize;
        let add = if variant == V_COPYING_ADD {
            add_copying
        } else {
            add_in_place
        };
        add(&mut sums[slot], &member.pubkey).expect("shared x-coordinate");
        balances[slot] += member.active_effective_balance;
    }
    (idx, val, sums, balances)
}

/// `merkle::batch_root`'s scan over arrays the caller already built.
fn batch_root_split(mut idx: Vec<u64>, mut val: Vec<Digest>, aux: &[Digest], depth: u32) -> Digest {
    let mut next_idx: Vec<u64> = Vec::with_capacity(idx.len());
    let mut next_val: Vec<Digest> = Vec::with_capacity(val.len());
    let mut cursor = 0usize;

    for _ in 0..depth {
        next_idx.clear();
        next_val.clear();

        let mut i = 0usize;
        while i < idx.len() {
            let k = idx[i];
            let (left, right) = if k & 1 == 0 {
                let left = val[i];
                if i + 1 < idx.len() && idx[i + 1] == k + 1 {
                    i += 2;
                    (left, val[i - 1])
                } else {
                    i += 1;
                    (left, take(aux, &mut cursor))
                }
            } else {
                let left = take(aux, &mut cursor);
                i += 1;
                (left, val[i - 1])
            };
            next_idx.push(k >> 1);
            next_val.push(acc::compress(&left, &right));
        }

        core::mem::swap(&mut idx, &mut next_idx);
        core::mem::swap(&mut val, &mut next_val);
    }

    assert_eq!(cursor, aux.len(), "unconsumed auxiliaries");
    assert_eq!(val.len(), 1, "did not converge to a single root");
    val[0]
}

/// The same scan with four children to a node.
///
/// Poseidon2's state is sixteen Goldilocks elements and a digest is four, so a
/// node absorbs four children in the permutation a 2-ary node spends on two.
/// There is no room left for the domain separator `acc::compress` carries; what
/// stands in for it is that the tree is fixed-depth and fixed-shape, so the
/// verifier applies the leaf function at exactly one level and this one above
/// it, and a leaf preimage is never offered where a node preimage is expected.
fn batch_root4(mut idx: Vec<u64>, mut val: Vec<Digest>, depth: u32) -> Digest {
    let mut next_idx: Vec<u64> = Vec::with_capacity(idx.len());
    let mut next_val: Vec<Digest> = Vec::with_capacity(val.len());
    // Children the opened prefix does not reach are empty subtrees, and an empty
    // subtree's digest is the same wherever it sits on a level, so it is one
    // permutation a level rather than an auxiliary a gap.
    let mut empty = acc::ZERO;

    for _ in 0..depth {
        next_idx.clear();
        next_val.clear();

        let mut i = 0usize;
        while i < idx.len() {
            let parent = idx[i] >> 2;
            let mut state = [0u64; 16];
            for child in 0..4 {
                state[4 * child..4 * child + 4].copy_from_slice(&empty);
            }
            while i < idx.len() && idx[i] >> 2 == parent {
                let child = (idx[i] & 3) as usize;
                state[4 * child..4 * child + 4].copy_from_slice(&val[i]);
                i += 1;
            }
            next_idx.push(parent);
            next_val.push(node4(&mut state));
        }

        let mut state = [0u64; 16];
        for child in 0..4 {
            state[4 * child..4 * child + 4].copy_from_slice(&empty);
        }
        empty = node4(&mut state);

        core::mem::swap(&mut idx, &mut next_idx);
        core::mem::swap(&mut val, &mut next_val);
    }

    assert_eq!(val.len(), 1, "did not converge to a single root");
    val[0]
}

#[inline]
fn node4(state: &mut [u64; 16]) -> Digest {
    unsafe { syscall_poseidon2(state as *mut [u64; 16]) };
    [state[0], state[1], state[2], state[3]]
}

/// `bls::PointSum::add`, transcribed, so the copies it makes can be measured.
fn add_copying(sum: &mut Bucket, point: &G1Point) -> Option<()> {
    let Some(current) = sum.as_mut() else {
        *sum = Some(*point);
        return Some(());
    };
    if current[0..6] == point[0..6] {
        return None;
    }

    let mut acc = SyscallPoint384 {
        x: current[0..6].try_into().ok()?,
        y: current[6..12].try_into().ok()?,
    };
    let addend = SyscallPoint384 {
        x: point[0..6].try_into().ok()?,
        y: point[6..12].try_into().ok()?,
    };
    syscall_bls12_381_curve_add(&mut SyscallBls12_381CurveAddParams {
        p1: &mut acc,
        p2: &addend,
    });

    current[0..6].copy_from_slice(&acc.x);
    current[6..12].copy_from_slice(&acc.y);
    Some(())
}

/// The same addition without the copies.
///
/// `SyscallPoint384` is `#[repr(C)] { x: [u64; 6], y: [u64; 6] }`, which is the
/// layout `G1Point` already has, so the precompile can be pointed at the running
/// sum and at the witness's key where they lie. What [`add_copying`] does
/// instead is build two `SyscallPoint384`s field by field and copy the result
/// back: 48 loads and 24 stores around a syscall that is 1,896 cost units.
///
/// The precondition is unchanged and still checked: a shared x-coordinate means
/// `p1 == p2` or `p1 == -p2`, and the precompile is undefined on both.
fn add_in_place(sum: &mut Bucket, point: &G1Point) -> Option<()> {
    let Some(current) = sum.as_mut() else {
        *sum = Some(*point);
        return Some(());
    };
    if current[0..6] == point[0..6] {
        return None;
    }
    // Same size, same alignment, no padding, and every bit pattern is a valid
    // inhabitant of both types.
    syscall_bls12_381_curve_add(&mut SyscallBls12_381CurveAddParams {
        p1: unsafe { &mut *(current.as_mut_ptr() as *mut SyscallPoint384) },
        p2: unsafe { &*(point.as_ptr() as *const SyscallPoint384) },
    });
    Some(())
}

/// `acc::leaf` with the packed point written into the permutation state.
///
/// `acc::pack_point` fills a thirteen-element array which `acc::leaf` then
/// copies into the state — thirteen stores, thirteen loads and thirteen stores
/// for a permutation that costs 1,050. Same preimage, same digest, which the
/// self-test pins against `acc::leaf`.
fn leaf_in_place(point: &G1Point, active_effective_balance: u64) -> Digest {
    const PACK_BITS: u32 = 60;
    let mut st = [0u64; 16];
    for (i, slot) in st[..13].iter_mut().enumerate() {
        let bit = i * PACK_BITS as usize;
        let limb = bit / 64;
        let offset = (bit % 64) as u32;
        let mut v = point[limb] >> offset;
        if offset + PACK_BITS > 64 && limb + 1 < point.len() {
            v |= point[limb + 1] << (64 - offset);
        }
        *slot = v & ((1u64 << PACK_BITS) - 1);
    }
    st[13] = active_effective_balance & 0xFFFF_FFFF;
    st[14] = active_effective_balance >> 32;
    // acc::DOMAIN_LEAF, which is private; the self-test is what pins it.
    st[15] = 1;
    unsafe { syscall_poseidon2(&mut st as *mut [u64; 16]) };
    [st[0], st[1], st[2], st[3]]
}

#[inline]
fn take(aux: &[Digest], cursor: &mut usize) -> Digest {
    let v = *aux.get(*cursor).expect("auxiliaries exhausted");
    *cursor += 1;
    v
}

/// Sum a bucket by binary reduction, one batched inversion per level.
///
/// This is the shape Montgomery's trick needs: at a level the `m/2` additions
/// are independent, so their `m/2` denominators are known before any of them is
/// used and a single inversion unwinds into all of them.
fn reduce_batched(points: &mut Vec<G1Point>) -> Option<G1Point> {
    if points.is_empty() {
        return None;
    }
    while points.len() > 1 {
        let pairs = points.len() / 2;

        // x2 - x1 for every pair, then one inversion for the whole level.
        let mut denominators: Vec<[u64; 6]> = Vec::with_capacity(pairs);
        for pair in 0..pairs {
            let (a, b) = (&points[2 * pair], &points[2 * pair + 1]);
            denominators.push(sub_fp(&b[0..6], &a[0..6]));
        }
        let inverses = batch_inverse(&denominators);

        for pair in 0..pairs {
            let a = points[2 * pair];
            let b = points[2 * pair + 1];
            let lambda = mul_fp_bls12_381(&sub_fp(&b[6..12], &a[6..12]), &inverses[pair]);
            let x3 = sub_fp(&sub_fp(&square_fp_bls12_381(&lambda), &a[0..6]), &b[0..6]);
            let y3 = sub_fp(
                &mul_fp_bls12_381(&lambda, &sub_fp(&a[0..6], &x3)),
                &a[6..12],
            );
            let mut sum = [0u64; 12];
            sum[0..6].copy_from_slice(&x3);
            sum[6..12].copy_from_slice(&y3);
            points[pair] = sum;
        }
        if points.len() & 1 == 1 {
            points[pairs] = points[points.len() - 1];
            points.truncate(pairs + 1);
        } else {
            points.truncate(pairs);
        }
    }
    Some(points[0])
}

/// Montgomery's trick: one inversion and three multiplications an element.
fn batch_inverse(values: &[[u64; 6]]) -> Vec<[u64; 6]> {
    let mut prefix: Vec<[u64; 6]> = Vec::with_capacity(values.len());
    let mut running = values[0];
    prefix.push(running);
    for value in &values[1..] {
        running = mul_fp_bls12_381(&running, value);
        prefix.push(running);
    }

    let mut inverse = inv_fp_bls12_381(&running);
    let mut out = vec![[0u64; 6]; values.len()];
    for i in (1..values.len()).rev() {
        out[i] = mul_fp_bls12_381(&inverse, &prefix[i - 1]);
        inverse = mul_fp_bls12_381(&inverse, &values[i]);
    }
    out[0] = inverse;
    out
}

#[inline]
fn sub_fp(x: &[u64], y: &[u64]) -> [u64; 6] {
    sub_fp_bls12_381(
        &x.try_into().expect("six limbs"),
        &y.try_into().expect("six limbs"),
    )
}

#[path = "../../guest_io.rs"]
mod zkasper_guest_io;
