//! Precompile cost probe.
//!
//! Runs one primitive `n` times so its marginal cost can be read off the
//! emulator. Run each mode at two different `n` and subtract: the difference
//! divided by the difference in `n` is the per-operation cost with program
//! setup, input parsing and I/O cancelled out.
//!
//! Input is 8 bytes: `u32` mode, `u32` n, both little-endian.

#![cfg_attr(target_os = "zkvm", no_main)]

extern crate alloc;
use alloc::vec::Vec;

use ziskos::syscalls::{
    syscall_bls12_381_curve_add, syscall_poseidon2, syscall_sha256_f,
    SyscallBls12_381CurveAddParams, SyscallPoint384, SyscallSha256Params,
};
use ziskos::zisklib::scalar_mul_bls12_381;
use ziskos::zisklib::{
    add_complete_safe_bls12_381, decompress_bls12_381, hash_to_curve_g2_bls12_381,
    is_on_subgroup_twist_bls12_381, neg_bls12_381, pairing_check_safe_bls12_381,
};
use zkasper_common::acc;
use zkasper_common::ssz;

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

/// Compressed G1 generator, the standard BLS12-381 serialization.
const G1_GENERATOR_COMPRESSED: [u8; 48] = [
    0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac, 0x0f,
    0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58,
    0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
];

const MODE_BASELINE: u32 = 0;
const MODE_POSEIDON2: u32 = 1;
const MODE_ACC_COMPRESS: u32 = 2;
const MODE_ACC_LEAF: u32 = 3;
const MODE_SHA256_PAIR: u32 = 4;
const MODE_G1_DECOMPRESS: u32 = 5;
const MODE_G1_ADD: u32 = 6;
const MODE_HASH_TO_CURVE: u32 = 7;
const MODE_PAIRING_CHECK: u32 = 8;
/// `n` is the batch size, not an iteration count: one multi-pairing over `n`
/// pairs. Comparing two batch sizes isolates the marginal Miller loop from the
/// single final exponentiation.
const MODE_PAIRING_BATCH: u32 = 9;
/// Aggregation through the raw precompile, as `bls::aggregate_points` does it.
const MODE_G1_ADD_RAW: u32 = 10;
/// 4-ary accumulator node: Poseidon2-16 absorbs four 4-element digests in one
/// permutation, the same permutation a 2-ary node uses for half the fan-in.
const MODE_ACC_COMPRESS4: u32 = 19;
/// One SHA-256 compression on a short message, the shape every shuffle hash has.
const MODE_SHA256_ONE: u32 = 11;
/// `n` is the list size: a whole-list 90-round shuffle, hashes included.
const MODE_SHUFFLE_LIST: u32 = 12;
/// Same loop with the hashing stubbed out, to split loop cost from hash cost.
const MODE_SHUFFLE_LIST_NOHASH: u32 = 13;
/// `compute_shuffled_index` for one index at a time, 90 rounds each.
const MODE_SHUFFLED_INDEX: u32 = 14;

/// `n` trajectories with the 90 pivot hashes precomputed and shared.
const MODE_SHUFFLED_INDEX_BATCH: u32 = 16;
/// Native-only: check the optimized shuffle against a spec transcription.
const MODE_SHUFFLE_SELFTEST: u32 = 15;
/// Tuned whole-list shuffle: the source byte is fetched once per run of eight
/// positions instead of re-tested every iteration, and the swap skips bounds
/// checks. Same permutation as MODE_SHUFFLE_LIST.
const MODE_SHUFFLE_FAST: u32 = 17;
/// Native-only: assert the tuned shuffle matches the reference element-for-element.
const MODE_SHUFFLE_FAST_SELFTEST: u32 = 18;

/// One Fp12 multiplication: folding another proof's Miller accumulator into the
/// running one, which is what the streaming pipeline does instead of a pairing.
const MODE_FP12_MUL: u32 = 20;
/// The final exponentiation on its own, with no Miller loop in front of it.
const MODE_FINAL_EXP: u32 = 21;
/// `n` is the batch size: Miller loops only, no final exponentiation. Comparing
/// two batch sizes gives the marginal Miller loop; comparing against
/// MODE_PAIRING_BATCH at the same size gives the final exponentiation.
const MODE_MILLER_BATCH: u32 = 22;
/// Committing a Miller accumulator so it can cross a proof boundary.
const MODE_COMMIT_FP12: u32 = 23;
/// A one-pair Miller loop per iteration: the batch's fixed cost — 63 Fp12
/// squarings shared by every pair — plus one marginal loop.
const MODE_MILLER_ONE: u32 = 24;
/// G2 subgroup check, which every batch pays once on its summed signature.
const MODE_G2_SUBGROUP: u32 = 25;

const SHUFFLE_ROUND_COUNT: u8 = 90;

fn main() {
    let input = read_input();
    let mode = u32::from_le_bytes(input[0..4].try_into().unwrap());
    let n = u32::from_le_bytes(input[4..8].try_into().unwrap()) as usize;

    let checksum = run(mode, n);
    emit(mode, n, checksum);
}

fn run(mode: u32, n: usize) -> u64 {
    match mode {
        MODE_BASELINE => {
            // Loop overhead only, so it can be subtracted from the others.
            let mut acc = 0u64;
            for i in 0..n {
                acc = acc.wrapping_add(i as u64).rotate_left(1);
            }
            acc
        }

        MODE_POSEIDON2 => {
            let mut state = [0u64; 16];
            for i in 0..n {
                state[0] ^= i as u64;
                unsafe { syscall_poseidon2(&mut state as *mut [u64; 16]) };
            }
            state[0]
        }

        MODE_ACC_COMPRESS => {
            let mut d = [1u64, 2, 3, 4];
            for _ in 0..n {
                d = acc::compress(&d, &[5, 6, 7, 8]);
            }
            d[0]
        }

        MODE_ACC_LEAF => {
            let (mut point, _) =
                decompress_bls12_381(&G1_GENERATOR_COMPRESSED).expect("decompress");
            let mut out = 0u64;
            for i in 0..n {
                point[0] = i as u64;
                out ^= acc::leaf(&point, 32_000_000_000)[0];
            }
            out
        }

        MODE_SHA256_PAIR => {
            let mut h = [3u8; 32];
            for _ in 0..n {
                h = ssz::sha256_pair(&h, &[9u8; 32]);
            }
            u64::from_le_bytes(h[0..8].try_into().unwrap())
        }

        MODE_G1_DECOMPRESS => {
            let mut out = 0u64;
            for _ in 0..n {
                let (p, _) = decompress_bls12_381(&G1_GENERATOR_COMPRESSED).expect("decompress");
                out ^= p[0];
            }
            out
        }

        MODE_G1_ADD => {
            let (g, _) = decompress_bls12_381(&G1_GENERATOR_COMPRESSED).expect("decompress");
            // Start from 2G so no iteration hits the doubling or identity path.
            let mut sum = add_complete_safe_bls12_381(&g, &neg_bls12_381(&g)).expect("add");
            sum = add_complete_safe_bls12_381(&sum, &g).expect("add");
            for _ in 0..n {
                sum = add_complete_safe_bls12_381(&sum, &g).expect("add");
            }
            sum[0]
        }

        MODE_HASH_TO_CURVE => {
            let mut msg = [0u8; 32];
            let mut out = 0u64;
            for i in 0..n {
                msg[0] = i as u8;
                msg[1] = (i >> 8) as u8;
                let q = hash_to_curve_g2_bls12_381(&msg, zkasper_common::bls::ETH_BLS_DST);
                out ^= q[0];
            }
            out
        }

        MODE_PAIRING_CHECK => {
            // e(G, q) * e(-G, q) == 1: a real two-Miller-loop check plus one
            // final exponentiation, the exact shape of FastAggregateVerify.
            let (g, _) = decompress_bls12_381(&G1_GENERATOR_COMPRESSED).expect("decompress");
            let neg_g = neg_bls12_381(&g);
            let q = hash_to_curve_g2_bls12_381(b"zkasper-bench", zkasper_common::bls::ETH_BLS_DST);
            let mut out = 0u64;
            for _ in 0..n {
                let ok = pairing_check_safe_bls12_381(&[g, neg_g], &[q, q]).expect("pairing");
                out += ok as u64;
            }
            out
        }

        MODE_PAIRING_BATCH => {
            let (g, _) = decompress_bls12_381(&G1_GENERATOR_COMPRESSED).expect("decompress");
            let neg_g = neg_bls12_381(&g);
            let q = hash_to_curve_g2_bls12_381(b"zkasper-bench", zkasper_common::bls::ETH_BLS_DST);

            // Alternating G and -G against the same G2 point still multiplies to
            // one, so an even batch is a genuine accepting check.
            let mut g1 = alloc::vec::Vec::with_capacity(n);
            let mut g2 = alloc::vec::Vec::with_capacity(n);
            for i in 0..n {
                g1.push(if i % 2 == 0 { g } else { neg_g });
                g2.push(q);
            }
            pairing_check_safe_bls12_381(&g1, &g2).expect("pairing") as u64
        }

        MODE_FP12_MUL => {
            let f = miller_fixture(2);
            let mut acc = f;
            for _ in 0..n {
                acc = zkasper_common::bls::fp12_mul(&acc, &f);
            }
            acc[0]
        }

        MODE_FINAL_EXP => {
            let f = miller_fixture(2);
            let mut out = 0u64;
            for i in 0..n {
                // Perturb the input so nothing can be hoisted out of the loop.
                let mut g = f;
                g[0] ^= i as u64;
                out ^= zkasper_common::bls::final_exp_is_one(&g) as u64;
            }
            out
        }

        MODE_MILLER_BATCH => miller_fixture(n)[0],

        MODE_MILLER_ONE => {
            let (g, _) = decompress_bls12_381(&G1_GENERATOR_COMPRESSED).expect("decompress");
            let neg_g = neg_bls12_381(&g);
            let q = hash_to_curve_g2_bls12_381(b"zkasper-bench", zkasper_common::bls::ETH_BLS_DST);
            let mut out = 0u64;
            for i in 0..n {
                let p = if i % 2 == 0 { g } else { neg_g };
                out ^= zkasper_common::miller::miller_loop_batch(&[p], &[q])[0];
            }
            out
        }

        MODE_G2_SUBGROUP => {
            // Two genuine subgroup points, alternated so nothing is hoisted out
            // of the loop and every call is a real accepting check.
            let points = [
                hash_to_curve_g2_bls12_381(b"zkasper-bench-a", zkasper_common::bls::ETH_BLS_DST),
                hash_to_curve_g2_bls12_381(b"zkasper-bench-b", zkasper_common::bls::ETH_BLS_DST),
            ];
            let mut out = 0u64;
            for i in 0..n {
                out ^= is_on_subgroup_twist_bls12_381(&points[i % 2]) as u64;
            }
            out
        }

        MODE_COMMIT_FP12 => {
            let mut f = miller_fixture(2);
            let mut out = 0u64;
            for i in 0..n {
                f[0] ^= i as u64;
                out ^= zkasper_common::acc::commit_fp12(&f)[0];
            }
            out
        }

        MODE_G1_ADD_RAW => {
            // Same shape as MODE_G1_ADD, but driving the precompile directly
            // instead of going through add_complete_safe_bls12_381.
            let (g, _) = decompress_bls12_381(&G1_GENERATOR_COMPRESSED).expect("decompress");
            let addend = SyscallPoint384 {
                x: g[0..6].try_into().unwrap(),
                y: g[6..12].try_into().unwrap(),
            };
            // Start at 3G: the precompile rejects p1 == p2, and every later
            // iteration is (k)G + G with k >= 3.
            let start = scalar_mul_bls12_381(&g, &[3, 0, 0, 0]);
            let mut acc = SyscallPoint384 {
                x: start[0..6].try_into().unwrap(),
                y: start[6..12].try_into().unwrap(),
            };
            for _ in 0..n {
                syscall_bls12_381_curve_add(&mut SyscallBls12_381CurveAddParams {
                    p1: &mut acc,
                    p2: &addend,
                });
            }
            acc.x[0]
        }

        MODE_SHA256_ONE => {
            let mut msg = [0u8; 33];
            let mut out = 0u64;
            for i in 0..n {
                msg[0] = i as u8;
                msg[1] = (i >> 8) as u8;
                out ^= sha256_short(&msg)[0] as u64;
            }
            out
        }

        MODE_SHUFFLE_LIST | MODE_SHUFFLE_LIST_NOHASH => {
            let mut list: Vec<u32> = (0..n as u32).collect();
            shuffle_list(
                &mut list,
                SHUFFLE_ROUND_COUNT,
                &[7u8; 32],
                mode == MODE_SHUFFLE_LIST,
            );
            list[0] as u64 ^ list[n - 1] as u64
        }

        MODE_SHUFFLE_FAST => {
            let mut list: Vec<u32> = (0..n as u32).collect();
            shuffle_list_fast(&mut list, SHUFFLE_ROUND_COUNT, &[7u8; 32]);
            list[0] as u64 ^ list[n - 1] as u64
        }

        MODE_SHUFFLE_FAST_SELFTEST => {
            let mut a: Vec<u32> = (0..n as u32).collect();
            let mut b: Vec<u32> = (0..n as u32).collect();
            shuffle_list(&mut a, SHUFFLE_ROUND_COUNT, &[7u8; 32], true);
            shuffle_list_fast(&mut b, SHUFFLE_ROUND_COUNT, &[7u8; 32]);
            assert_eq!(a, b, "tuned shuffle diverges from the reference");
            a.iter().enumerate().fold(0u64, |acc, (i, v)| {
                acc ^ (*v as u64).wrapping_mul(i as u64 + 1)
            })
        }

        MODE_SHUFFLED_INDEX => {
            let mut out = 0u64;
            for i in 0..n {
                out ^= shuffled_index_single(i, 1_048_576, SHUFFLE_ROUND_COUNT, &[7u8; 32]) as u64;
            }
            out
        }

        MODE_SHUFFLED_INDEX_BATCH => {
            let index_count = 1_048_576usize;
            let seed = [7u8; 32];
            let mut buf = [0u8; 37];
            buf[..32].copy_from_slice(&seed);
            // The pivot of each round is the same for every validator, so it is
            // hoisted out of the per-validator loop: 90 hashes for the batch.
            let mut pivots = [0usize; SHUFFLE_ROUND_COUNT as usize];
            for r in 0..SHUFFLE_ROUND_COUNT {
                buf[32] = r;
                pivots[r as usize] =
                    (u64::from_le_bytes(sha256_short(&buf[..33])[0..8].try_into().unwrap())
                        % index_count as u64) as usize;
            }
            let mut out = 0u64;
            for v in 0..n {
                let mut index = v;
                // Reverse round order inverts the permutation: validator -> position.
                for step in 0..SHUFFLE_ROUND_COUNT {
                    let r = SHUFFLE_ROUND_COUNT - 1 - step;
                    let pivot = pivots[r as usize];
                    let flip = (pivot + index_count - index) % index_count;
                    let position = if index > flip { index } else { flip };
                    buf[32] = r;
                    buf[33..37].copy_from_slice(&((position / 256) as u32).to_le_bytes());
                    let source = sha256_short(&buf[..37]);
                    if (source[(position % 256) / 8] >> (position % 8)) & 1 == 1 {
                        index = flip;
                    }
                }
                out ^= index as u64;
            }
            out
        }

        MODE_SHUFFLE_SELFTEST => {
            let seed = [7u8; 32];
            let mut fast: Vec<u32> = (0..n as u32).collect();
            shuffle_list(&mut fast, SHUFFLE_ROUND_COUNT, &seed, true);
            let mut back: Vec<u32> = (0..n as u32).collect();
            shuffle_list_dir(&mut back, SHUFFLE_ROUND_COUNT, &seed, true, false);
            let slow = shuffle_naive(n, SHUFFLE_ROUND_COUNT, &seed);
            assert_eq!(
                back, slow,
                "reverse-round whole-list shuffle == spec permutation"
            );
            // The whole-list form permutes positions; the spec form reports, for
            // each starting index, where it ended up. They are inverses.
            let mut inv = alloc::vec![0u32; n];
            for (pos, &idx) in fast.iter().enumerate() {
                inv[idx as usize] = pos as u32;
            }
            let ok = inv == slow;
            let mut sig = 0u64;
            for (i, v) in fast.iter().enumerate().take(8) {
                sig |= (*v as u64) << (i * 8);
            }
            (ok as u64) << 63 | sig
        }

        MODE_ACC_COMPRESS4 => {
            let mut d = [1u64, 2, 3, 4];
            for _ in 0..n {
                let mut st = [0u64; 16];
                st[0..4].copy_from_slice(&d);
                st[4..8].copy_from_slice(&[5, 6, 7, 8]);
                st[8..12].copy_from_slice(&[9, 10, 11, 12]);
                st[12..16].copy_from_slice(&[13, 14, 15, 16]);
                unsafe { syscall_poseidon2(&mut st as *mut [u64; 16]) };
                d = [st[0], st[1], st[2], st[3]];
            }
            d[0]
        }

        _ => panic!("unknown mode {mode}"),
    }
}

/// A Miller-loop accumulator over `n` alternating pairs, which multiplies to one
/// after the final exponentiation.
fn miller_fixture(n: usize) -> [u64; 72] {
    let (g, _) = decompress_bls12_381(&G1_GENERATOR_COMPRESSED).expect("decompress");
    let neg_g = neg_bls12_381(&g);
    let q = hash_to_curve_g2_bls12_381(b"zkasper-bench", zkasper_common::bls::ETH_BLS_DST);

    let mut g1 = alloc::vec::Vec::with_capacity(n);
    let mut g2 = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        g1.push(if i % 2 == 0 { g } else { neg_g });
        g2.push(q);
    }
    zkasper_common::miller::miller_loop_batch(&g1, &g2)
}

// ---------------------------------------------------------------------------
// Shuffling probe (scratch, not for commit).
// ---------------------------------------------------------------------------

/// SHA-256 of a message shorter than 56 bytes: exactly one compression.
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
    let bits = (msg.len() as u64) * 8;
    block[56..64].copy_from_slice(&bits.to_be_bytes());

    let mut input = [0u64; 8];
    for i in 0..8 {
        input[i] = u64::from_le_bytes(block[8 * i..8 * i + 8].try_into().unwrap());
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

/// Whole-list swap-or-not shuffle, the standard optimized form: one pivot hash
/// per round and one source hash per 256 positions, shared across the round.
/// `hashing` off replaces the source with a fixed byte string so the loop cost
/// can be read separately from the hash cost.
fn shuffle_list(input: &mut [u32], rounds: u8, seed: &[u8; 32], hashing: bool) {
    shuffle_list_dir(input, rounds, seed, hashing, true)
}

fn shuffle_list_dir(input: &mut [u32], rounds: u8, seed: &[u8; 32], hashing: bool, forwards: bool) {
    let list_size = input.len();
    if list_size <= 1 {
        return;
    }
    let mut buf = [0u8; 37];
    buf[..32].copy_from_slice(seed);
    let fixed = [0xa5u8; 32];

    for step in 0..rounds {
        let r = if forwards { step } else { rounds - 1 - step };
        buf[32] = r;
        let pivot = if hashing {
            (u64::from_le_bytes(sha256_short(&buf[..33])[0..8].try_into().unwrap())
                % list_size as u64) as usize
        } else {
            (0x5a5a_5a5a_u64.wrapping_mul(r as u64 + 1) % list_size as u64) as usize
        };

        let hash_at = |pos_bucket: usize, buf: &mut [u8; 37]| -> [u8; 32] {
            if hashing {
                buf[33..37].copy_from_slice(&(pos_bucket as u32).to_le_bytes());
                sha256_short(&buf[..37])
            } else {
                fixed
            }
        };

        // Lower mirror: j walks down from pivot.
        let mirror = (pivot + 1) >> 1;
        let mut source = hash_at(pivot >> 8, &mut buf);
        let mut byte_v = source[(pivot & 0xff) >> 3];
        for i in 0..mirror {
            let j = pivot - i;
            if j & 0xff == 0xff {
                source = hash_at(j >> 8, &mut buf);
            }
            if j & 0x07 == 0x07 {
                byte_v = source[(j & 0xff) >> 3];
            }
            if (byte_v >> (j & 0x07)) & 1 == 1 {
                input.swap(i, j);
            }
        }

        // Upper mirror: j walks down from the end of the list.
        let mirror = (pivot + list_size + 1) >> 1;
        let end = list_size - 1;
        let mut source = hash_at(end >> 8, &mut buf);
        let mut byte_v = source[(end & 0xff) >> 3];
        for (loop_iter, i) in (pivot + 1..mirror).enumerate() {
            let j = end - loop_iter;
            if j & 0xff == 0xff {
                source = hash_at(j >> 8, &mut buf);
            }
            if j & 0x07 == 0x07 {
                byte_v = source[(j & 0xff) >> 3];
            }
            if (byte_v >> (j & 0x07)) & 1 == 1 {
                input.swap(i, j);
            }
        }
    }
}

/// Tuned form of [`shuffle_list`].
///
/// Same algorithm and same output; the difference is instruction count in the
/// inner loop, which is what a zkVM charges for. `j` descends, so consecutive
/// positions share a source byte while `j >> 3` holds. Fetching that byte once
/// per run of up to eight, rather than re-testing `j & 7 == 7` every iteration,
/// removes two branches and a load per position. Runs are aligned to 8 and 256
/// is a multiple of 8, so a run never straddles a hash boundary and the refresh
/// check stays at run start.
fn shuffle_list_fast(input: &mut [u32], rounds: u8, seed: &[u8; 32]) {
    let list_size = input.len();
    if list_size <= 1 {
        return;
    }
    let mut buf = [0u8; 37];
    buf[..32].copy_from_slice(seed);

    for r in 0..rounds {
        buf[32] = r;
        let pivot = (u64::from_le_bytes(sha256_short(&buf[..33])[0..8].try_into().unwrap())
            % list_size as u64) as usize;

        // Lower mirror: i ascends from 0, j descends from pivot.
        let mirror = (pivot + 1) >> 1;
        let mut source = {
            buf[33..37].copy_from_slice(&((pivot >> 8) as u32).to_le_bytes());
            sha256_short(&buf[..37])
        };
        let mut i = 0usize;
        while i < mirror {
            let j = pivot - i;
            if j & 0xff == 0xff {
                buf[33..37].copy_from_slice(&((j >> 8) as u32).to_le_bytes());
                source = sha256_short(&buf[..37]);
            }
            let byte_v = source[(j & 0xff) >> 3];
            let run = core::cmp::min((j & 7) + 1, mirror - i);
            for k in 0..run {
                if (byte_v >> ((j - k) & 7)) & 1 == 1 {
                    unsafe {
                        let a = *input.get_unchecked(i + k);
                        let b = *input.get_unchecked(j - k);
                        *input.get_unchecked_mut(i + k) = b;
                        *input.get_unchecked_mut(j - k) = a;
                    }
                }
            }
            i += run;
        }

        // Upper mirror: i ascends from pivot+1, j descends from the end.
        let mirror = (pivot + list_size + 1) >> 1;
        let end = list_size - 1;
        let mut source = {
            buf[33..37].copy_from_slice(&((end >> 8) as u32).to_le_bytes());
            sha256_short(&buf[..37])
        };
        let mut i = pivot + 1;
        let mut done = 0usize;
        while i < mirror {
            let j = end - done;
            if j & 0xff == 0xff {
                buf[33..37].copy_from_slice(&((j >> 8) as u32).to_le_bytes());
                source = sha256_short(&buf[..37]);
            }
            let byte_v = source[(j & 0xff) >> 3];
            let run = core::cmp::min((j & 7) + 1, mirror - i);
            for k in 0..run {
                if (byte_v >> ((j - k) & 7)) & 1 == 1 {
                    unsafe {
                        let a = *input.get_unchecked(i + k);
                        let b = *input.get_unchecked(j - k);
                        *input.get_unchecked_mut(i + k) = b;
                        *input.get_unchecked_mut(j - k) = a;
                    }
                }
            }
            i += run;
            done += run;
        }
    }
}

/// Spec-faithful `compute_shuffled_permutation`: no bucket cache, no mirror
/// trick. Every index pays its own source hash every round.
#[allow(dead_code)]
fn shuffle_naive(index_count: usize, rounds: u8, seed: &[u8; 32]) -> Vec<u32> {
    let mut indices: Vec<u32> = (0..index_count as u32).collect();
    let mut buf = [0u8; 37];
    buf[..32].copy_from_slice(seed);
    for r in 0..rounds {
        buf[32] = r;
        let pivot = (u64::from_le_bytes(sha256_short(&buf[..33])[0..8].try_into().unwrap())
            % index_count as u64) as usize;
        for slot in indices.iter_mut() {
            let x = *slot as usize;
            let flip = (pivot + index_count - x) % index_count;
            let position = if x > flip { x } else { flip };
            buf[33..37].copy_from_slice(&((position / 256) as u32).to_le_bytes());
            let source = sha256_short(&buf[..37]);
            let byte_v = source[(position % 256) / 8];
            if (byte_v >> (position % 8)) & 1 == 1 {
                *slot = flip as u32;
            }
        }
    }
    indices
}

/// `compute_shuffled_index` for a single index: 90 rounds, one pivot hash and
/// one source hash each, nothing shared.
fn shuffled_index_single(
    mut index: usize,
    index_count: usize,
    rounds: u8,
    seed: &[u8; 32],
) -> usize {
    let mut buf = [0u8; 37];
    buf[..32].copy_from_slice(seed);
    for r in 0..rounds {
        buf[32] = r;
        let pivot = (u64::from_le_bytes(sha256_short(&buf[..33])[0..8].try_into().unwrap())
            % index_count as u64) as usize;
        let flip = (pivot + index_count - index) % index_count;
        let position = if index > flip { index } else { flip };
        buf[33..37].copy_from_slice(&((position / 256) as u32).to_le_bytes());
        let source = sha256_short(&buf[..37]);
        let byte_v = source[(position % 256) / 8];
        if (byte_v >> (position % 8)) & 1 == 1 {
            index = flip;
        }
    }
    index
}

#[cfg(target_os = "zkvm")]
fn read_input() -> Vec<u8> {
    ziskos::io::read_slice().to_vec()
}

#[cfg(not(target_os = "zkvm"))]
fn read_input() -> Vec<u8> {
    let mut args = std::env::args().skip(1);
    let mode: u32 = args.next().expect("mode").parse().expect("mode");
    let n: u32 = args.next().expect("n").parse().expect("n");
    let mut v = Vec::with_capacity(8);
    v.extend_from_slice(&mode.to_le_bytes());
    v.extend_from_slice(&n.to_le_bytes());
    v
}

fn emit(mode: u32, n: usize, checksum: u64) {
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&mode.to_le_bytes());
    out[4..8].copy_from_slice(&(n as u32).to_le_bytes());
    out[8..16].copy_from_slice(&checksum.to_le_bytes());

    #[cfg(target_os = "zkvm")]
    ziskos::io::commit_slice(&out);
    #[cfg(not(target_os = "zkvm"))]
    println!("mode={mode} n={n} checksum={checksum:#018x}");
}
