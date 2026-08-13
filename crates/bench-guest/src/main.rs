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
    syscall_bls12_381_curve_add, syscall_poseidon2, SyscallBls12_381CurveAddParams, SyscallPoint384,
};
use ziskos::zisklib::scalar_mul_bls12_381;
use ziskos::zisklib::{
    add_complete_safe_bls12_381, decompress_bls12_381, hash_to_curve_g2_bls12_381, neg_bls12_381,
    pairing_check_safe_bls12_381,
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

        _ => panic!("unknown mode {mode}"),
    }
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
