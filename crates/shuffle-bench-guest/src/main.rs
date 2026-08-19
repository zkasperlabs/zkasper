//! Swap-or-not bench harness: what it costs to prove Ethereum's validator
//! shuffle inside a Zisk guest.
//!
//! The committee proof publishes one bucket per slot and lets both consumers
//! subtract absentees instead of opening every attester. Finality does not need
//! the bucketing to be the real shuffle, because its denominator is global. FCR
//! does: the moment the threshold is a fraction of one slot's committee weight,
//! a prover who picks the partition picks its own denominator. So the shuffle
//! has to be proven, and the only open question is the price.
//!
//! Every variant here computes, or checks, the same function: for each offset
//! `v` into the epoch's active set, the slot `v` attests in. [`V_SELFTEST`]
//! holds them to that — it runs the spec transcription and each candidate over
//! the same seed and asserts the assignments are equal element for element.
//!
//! Two sweep axes, because the variants do not all scale with the same thing.
//! `V_SPEC`, `V_SPEC_PIVOTS` and `V_TRAJ_BITMAP` process `param` indices out of
//! a domain of `n`, so their per-index cost is read by sweeping `param` with `n`
//! pinned at mainnet. The whole-set variants do work proportional to `n`, so
//! theirs is read by sweeping `n`. `scripts/shuffle_bench.py` knows which is
//! which.
//!
//! Input is `u64 variant | u64 n | u64 param`.

#![cfg_attr(target_os = "zkvm", no_main)]

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use ziskos::syscalls::{syscall_poseidon2, syscall_sha256_f, SyscallSha256Params};

#[cfg(target_os = "zkvm")]
ziskos::entrypoint!(main);

/// `SHUFFLE_ROUND_COUNT`. Consensus constant, not a tuning knob.
const ROUNDS: u8 = 90;
/// `SLOTS_PER_EPOCH`.
const SLOTS: usize = 32;
/// Bits a slot label needs, and therefore bitplanes [`V_BITSLICE`] carries.
const LABEL_BITS: usize = 5;

/// The spec, transcribed: `compute_shuffled_index` for `param` indices, each
/// paying its own pivot hash and its own source hash in all 90 rounds. This is
/// the baseline every other row is measured against.
const V_SPEC: u64 = 0;
/// The one hoist the spec's own note allows without changing the shape: the
/// pivot of a round is the same for every index, so 90 hashes serve the batch
/// instead of 90 per index. Still one source hash per index per round.
const V_SPEC_PIVOTS: u64 = 1;
/// The whole-set form every client implements: one pivot hash a round and one
/// source hash per 256 positions, with the list permuted in place. Run forwards
/// over the identity it yields, at index `v`, the position `v` shuffles to.
const V_LIST: u64 = 2;
/// The same permutation applied to 5-bit slot labels rather than 32-bit
/// indices, so the array is `n` bytes instead of `4n` and the answer is read
/// straight out of it.
const V_LABELS: u64 = 3;
/// The same again, bit-sliced: five bitplanes of `n` bits, one masked
/// exchange per 64 pairs per plane instead of 64 conditional element swaps.
const V_BITSLICE: u64 = 4;
/// Ablation: only the source bitmaps, all 90 rounds, over the half of the
/// domain a round can address. The fixed cost every sampling scheme pays.
const V_BITMAPS: u64 = 5;
/// Bitmaps plus `param` inverse trajectories read out of them — the check half
/// of the sampled scheme, whose cost per sample is what decides how many
/// samples are affordable.
const V_TRAJ_BITMAP: u64 = 6;
/// The commit half: walk a claimed assignment of `n` labels and absorb it into
/// a Poseidon2 sponge, which is what binds the assignment before the challenge
/// that samples it is drawn.
const V_CONSUME: u64 = 7;
/// Ablation for [`V_CONSUME`]: fill the array and commit nothing.
const V_FILL: u64 = 8;
/// Every variant, over the same seed, must produce the same assignment.
const V_SELFTEST: u64 = 9;
/// [`V_BITSLICE`] with the loops turned inside out: the round's swap masks are
/// built once into a scratch array, and each plane is then one tight walk over
/// them. Within a run the two windows advance by exactly one word a block and
/// the funnel offset never moves, so a plane pass re-derives nothing.
const V_BITSLICE_PLANES: u64 = 10;

const SEED: [u8; 32] = [7u8; 32];

fn main() {
    let input = read_input();
    let variant = u64::from_le_bytes(input[0..8].try_into().unwrap());
    let n = u64::from_le_bytes(input[8..16].try_into().unwrap()) as usize;
    let param = u64::from_le_bytes(input[16..24].try_into().unwrap()) as usize;

    let checksum = run(variant, n, param);
    emit(variant, n, param, checksum);
}

fn run(variant: u64, n: usize, param: usize) -> u64 {
    match variant {
        V_SPEC => {
            let mut out = 0u64;
            for i in 0..param {
                out = out.wrapping_add(spec_shuffled_index(i, n, true) as u64);
            }
            out
        }

        V_SPEC_PIVOTS => {
            let pivots = pivots(n);
            let mut out = 0u64;
            for v in 0..param {
                out = out.wrapping_add(traj_hashed(v, n, &pivots) as u64);
            }
            out
        }

        V_LIST => {
            let mut list: Vec<u32> = (0..n as u32).collect();
            shuffle_u32(&mut list, n);
            let mut out = 0u64;
            for (v, &p) in list.iter().enumerate() {
                out = out.wrapping_add((slot_of_position(p as usize, n) as u64) << (v & 7));
            }
            out
        }

        V_LABELS => {
            let mut labels = label_array(n);
            shuffle_u8(&mut labels, n);
            checksum_labels(&labels)
        }

        V_BITSLICE | V_BITSLICE_PLANES => {
            let mut planes = bitslice_init(n);
            if variant == V_BITSLICE {
                bitslice_shuffle(&mut planes, n);
            } else {
                bitslice_shuffle_planes(&mut planes, n);
            }
            let stride = planes.len() / LABEL_BITS;
            let mut out = 0u64;
            for v in 0..n {
                out = out.wrapping_add((bitslice_get(&planes, stride, v) as u64) << (v & 7));
            }
            out
        }

        V_BITMAPS => bitmaps(n).iter().fold(0u64, |a, &b| a ^ b as u64),

        V_TRAJ_BITMAP => {
            let maps = bitmaps(n);
            let pivots = pivots(n);
            let mut out = 0u64;
            for v in 0..param {
                out = out.wrapping_add(traj_bitmap(v, n, &pivots, &maps) as u64);
            }
            out
        }

        V_CONSUME | V_FILL => {
            // Stands in for the claimed assignment the fused committee guest
            // reads out of each member's witness record. The fill is charged to
            // both variants so the difference is the sponge alone.
            let mut labels = vec![0u8; n];
            let mut x = 0x9e37_79b9_7f4a_7c15u64;
            for slot in labels.iter_mut() {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *slot = ((x >> 59) & 31) as u8;
            }
            if variant == V_FILL {
                return labels.iter().fold(0u64, |a, &b| a.wrapping_add(b as u64));
            }
            let d = commit_assignment(&labels);
            d[0] ^ d[1] ^ d[2] ^ d[3]
        }

        V_SELFTEST => selftest(n),

        _ => panic!("unknown variant"),
    }
}

// ---------------------------------------------------------------------------
// The spec, and single-index trajectories
// ---------------------------------------------------------------------------

/// `compute_shuffled_index`, transcribed. `forwards` off runs the rounds in the
/// opposite order, which inverts the permutation: each round is an involution,
/// so reversing the composition order gives the inverse map, and that is the
/// direction a per-validator check needs — from a validator offset to the
/// position, and therefore the slot, it shuffles to.
fn spec_shuffled_index(mut index: usize, n: usize, forwards: bool) -> usize {
    let mut buf = [0u8; 37];
    buf[..32].copy_from_slice(&SEED);
    for step in 0..ROUNDS {
        let r = if forwards { step } else { ROUNDS - 1 - step };
        buf[32] = r;
        let pivot = (u64::from_le_bytes(sha256_short(&buf[..33])[0..8].try_into().unwrap())
            % n as u64) as usize;
        let flip = (pivot + n - index) % n;
        let position = if index > flip { index } else { flip };
        buf[33..37].copy_from_slice(&((position / 256) as u32).to_le_bytes());
        let source = sha256_short(&buf[..37]);
        if (source[(position % 256) / 8] >> (position % 8)) & 1 == 1 {
            index = flip;
        }
    }
    index
}

/// `(pivot + n - index) mod n`, without the division the spec's `%` compiles
/// to: the numerator is below `2n` by construction, so one conditional
/// subtraction reduces it.
#[inline(always)]
fn flip(pivot: usize, index: usize, n: usize) -> usize {
    let f = pivot + n - index;
    if f >= n {
        f - n
    } else {
        f
    }
}

/// The 90 round pivots, hoisted out of any per-index loop.
fn pivots(n: usize) -> [u32; ROUNDS as usize] {
    let mut buf = [0u8; 33];
    buf[..32].copy_from_slice(&SEED);
    let mut out = [0u32; ROUNDS as usize];
    for (r, p) in out.iter_mut().enumerate() {
        buf[32] = r as u8;
        *p = (u64::from_le_bytes(sha256_short(&buf)[0..8].try_into().unwrap()) % n as u64) as u32;
    }
    out
}

/// Inverse trajectory of one validator offset, hashing its source block itself
/// in every round: 90 compressions a validator.
fn traj_hashed(mut index: usize, n: usize, pivots: &[u32; ROUNDS as usize]) -> usize {
    let mut buf = [0u8; 37];
    buf[..32].copy_from_slice(&SEED);
    for step in 0..ROUNDS {
        let r = ROUNDS - 1 - step;
        buf[32] = r;
        let flip = flip(pivots[r as usize] as usize, index, n);
        let position = if index > flip { index } else { flip };
        buf[33..37].copy_from_slice(&((position >> 8) as u32).to_le_bytes());
        let source = sha256_short(&buf[..37]);
        if (source[(position & 0xff) >> 3] >> (position & 7)) & 1 == 1 {
            index = flip;
        }
    }
    index
}

/// The same trajectory read out of precomputed bitmaps: no hashing per sample,
/// one byte load a round.
fn traj_bitmap(mut index: usize, n: usize, pivots: &[u32; ROUNDS as usize], maps: &[u8]) -> usize {
    let stride = bitmap_stride(n);
    let mut base = (ROUNDS as usize - 1) * stride;
    for r in (0..ROUNDS as usize).rev() {
        let flip = flip(pivots[r] as usize, index, n);
        let position = if index > flip { index } else { flip };
        // `position` is below `n` and `base` walks the map a round at a time,
        // so the index is in range by construction.
        if (unsafe { *maps.get_unchecked(base + (position >> 3)) } >> (position & 7)) & 1 == 1 {
            index = flip;
        }
        base = base.wrapping_sub(stride);
    }
    index
}

// ---------------------------------------------------------------------------
// Whole-set forms
// ---------------------------------------------------------------------------

/// Slot of a position in the shuffled order. Committee boundaries are
/// `floor(s*n/32)`, so the slot of `p` is the largest `s` with
/// `floor(s*n/32) <= p`, which is `(32*(p+1) - 1) / n` capped at the last slot.
#[inline]
fn slot_of_position(p: usize, n: usize) -> u8 {
    let s = (SLOTS * (p + 1) - 1) / n;
    if s >= SLOTS {
        (SLOTS - 1) as u8
    } else {
        s as u8
    }
}

fn label_array(n: usize) -> Vec<u8> {
    let mut labels = vec![0u8; n];
    for (p, l) in labels.iter_mut().enumerate() {
        *l = slot_of_position(p, n);
    }
    labels
}

/// The two mirror runs of one round, each `(i0, j0, count)`, pairing `i0+k`
/// with `j0-k` for `k` below `count`. Every position below `n` is in exactly
/// one pair, and the swap bit of a pair is the source bit of its `j` side.
fn round_plan(pivot: usize, n: usize) -> [(usize, usize, usize); 2] {
    let lower = (pivot + 1) >> 1;
    let upper = ((pivot + n + 1) >> 1) - (pivot + 1);
    [(0, pivot, lower), (pivot + 1, n - 1, upper)]
}

/// Source bytes of a round, fetched one 256-position block at a time. A run of
/// 64 positions aligned to 64 never straddles a block, because 256 is a
/// multiple of 64, so a block is refreshed only at run boundaries.
struct Source {
    buf: [u8; 37],
    block: usize,
    bytes: [u8; 32],
}

impl Source {
    fn new(round: u8) -> Self {
        let mut buf = [0u8; 37];
        buf[..32].copy_from_slice(&SEED);
        buf[32] = round;
        Source {
            buf,
            block: usize::MAX,
            bytes: [0u8; 32],
        }
    }

    #[inline]
    fn byte(&mut self, position: usize) -> u8 {
        let block = position >> 8;
        if block != self.block {
            self.buf[33..37].copy_from_slice(&(block as u32).to_le_bytes());
            self.bytes = sha256_short(&self.buf);
            self.block = block;
        }
        self.bytes[(position & 0xff) >> 3]
    }

    /// The 64 source bits covering `[base, base+64)`, `base` aligned to 64, in
    /// position-ascending order.
    #[inline]
    fn word(&mut self, base: usize) -> u64 {
        let block = base >> 8;
        if block != self.block {
            self.buf[33..37].copy_from_slice(&(block as u32).to_le_bytes());
            self.bytes = sha256_short(&self.buf);
            self.block = block;
        }
        let b = (base & 0xff) >> 3;
        u64::from_le_bytes(self.bytes[b..b + 8].try_into().unwrap())
    }
}

macro_rules! whole_set_shuffle {
    ($name:ident, $ty:ty) => {
        /// One conditional swap per pair per round, over an array of `$ty`.
        fn $name(list: &mut [$ty], n: usize) {
            if n <= 1 {
                return;
            }
            let pivots = pivots(n);
            for r in 0..ROUNDS {
                let mut src = Source::new(r);
                for (i0, j0, count) in round_plan(pivots[r as usize] as usize, n) {
                    let mut k = 0usize;
                    while k < count {
                        let j = j0 - k;
                        let byte_v = src.byte(j);
                        let run = core::cmp::min((j & 7) + 1, count - k);
                        for t in 0..run {
                            if (byte_v >> ((j - t) & 7)) & 1 == 1 {
                                unsafe {
                                    let a = *list.get_unchecked(i0 + k + t);
                                    let b = *list.get_unchecked(j - t);
                                    *list.get_unchecked_mut(i0 + k + t) = b;
                                    *list.get_unchecked_mut(j - t) = a;
                                }
                            }
                        }
                        k += run;
                    }
                }
            }
        }
    };
}

whole_set_shuffle!(shuffle_u32, u32);
whole_set_shuffle!(shuffle_u8, u8);

// ---------------------------------------------------------------------------
// Bit-sliced form
// ---------------------------------------------------------------------------

#[inline]
fn rev64(mut x: u64) -> u64 {
    x = ((x & 0x5555_5555_5555_5555) << 1) | ((x >> 1) & 0x5555_5555_5555_5555);
    x = ((x & 0x3333_3333_3333_3333) << 2) | ((x >> 2) & 0x3333_3333_3333_3333);
    x = ((x & 0x0f0f_0f0f_0f0f_0f0f) << 4) | ((x >> 4) & 0x0f0f_0f0f_0f0f_0f0f);
    x = ((x & 0x00ff_00ff_00ff_00ff) << 8) | ((x >> 8) & 0x00ff_00ff_00ff_00ff);
    x = ((x & 0x0000_ffff_0000_ffff) << 16) | ((x >> 16) & 0x0000_ffff_0000_ffff);
    x.rotate_left(32)
}

/// Five bitplanes of the slot label, each `stride` words long with one word of
/// slack so a 64-bit window starting anywhere below `n` can be read whole.
fn bitslice_init(n: usize) -> Vec<u64> {
    let stride = n.div_ceil(64) + 1;
    let mut planes = vec![0u64; stride * LABEL_BITS];
    for p in 0..n {
        let label = slot_of_position(p, n) as u64;
        let (w, b) = (p >> 6, p & 63);
        for plane in 0..LABEL_BITS {
            planes[plane * stride + w] |= ((label >> plane) & 1) << b;
        }
    }
    planes
}

#[inline]
fn bitslice_get(planes: &[u64], stride: usize, p: usize) -> u8 {
    let (w, b) = (p >> 6, p & 63);
    let mut out = 0u8;
    for plane in 0..LABEL_BITS {
        out |= (((planes[plane * stride + w] >> b) & 1) as u8) << plane;
    }
    out
}

#[inline]
fn bitslice_swap_one(planes: &mut [u64], stride: usize, a: usize, b: usize) {
    let (wa, ba) = (a >> 6, a & 63);
    let (wb, bb) = (b >> 6, b & 63);
    for plane in 0..LABEL_BITS {
        let base = plane * stride;
        let x = (planes[base + wa] >> ba) & 1;
        let y = (planes[base + wb] >> bb) & 1;
        let t = x ^ y;
        planes[base + wa] ^= t << ba;
        planes[base + wb] ^= t << bb;
    }
}

fn bitslice_shuffle(planes: &mut [u64], n: usize) {
    if n <= 1 {
        return;
    }
    let stride = planes.len() / LABEL_BITS;
    let pivots = pivots(n);
    for r in 0..ROUNDS {
        let mut src = Source::new(r);
        for (i0, j0, count) in round_plan(pivots[r as usize] as usize, n) {
            // Pairs are (i0+k, j0-k). Blocks are cut so the descending side
            // lands on a whole word: the mask a block needs is then one aligned
            // slice of the source, and only the ascending side is funnelled.
            let head = core::cmp::min((j0 + 1) & 63, count);
            for k in 0..head {
                let j = j0 - k;
                if (src.byte(j) >> (j & 7)) & 1 == 1 {
                    bitslice_swap_one(planes, stride, i0 + k, j);
                }
            }
            let mut k = head;
            while k + 64 <= count {
                let jhi = j0 - k;
                let jlo = jhi - 63;
                // Mask, in k order: bit t is the source bit of position jhi-t.
                let m = rev64(src.word(jlo));
                let jw = jlo >> 6;
                let ilo = i0 + k;
                let (iw, off) = (ilo >> 6, ilo & 63);
                // Five planes, five word pairs, one shared mask. The bounds are
                // established by the pair structure — `i0+k+63 < j0-k-63` holds
                // for every block, so the two windows never share a word — and
                // checking them again five times a block is 13% of the loop.
                let ptr = planes.as_mut_ptr();
                unsafe {
                    if off == 0 {
                        for plane in 0..LABEL_BITS {
                            let xp = ptr.add(plane * stride + iw);
                            let jp = ptr.add(plane * stride + jw);
                            let (x, jword) = (*xp, *jp);
                            let t = (x ^ rev64(jword)) & m;
                            *jp = jword ^ rev64(t);
                            *xp = x ^ t;
                        }
                    } else {
                        let low = (1u64 << off) - 1;
                        for plane in 0..LABEL_BITS {
                            let xp = ptr.add(plane * stride + iw);
                            let jp = ptr.add(plane * stride + jw);
                            let (lo, hi, jword) = (*xp, *xp.add(1), *jp);
                            let x = (lo >> off) | (hi << (64 - off));
                            let t = (x ^ rev64(jword)) & m;
                            *jp = jword ^ rev64(t);
                            let xt = x ^ t;
                            *xp = (lo & low) | (xt << off);
                            *xp.add(1) = (hi & !low) | (xt >> (64 - off));
                        }
                    }
                }
                k += 64;
            }
            while k < count {
                let j = j0 - k;
                if (src.byte(j) >> (j & 7)) & 1 == 1 {
                    bitslice_swap_one(planes, stride, i0 + k, j);
                }
                k += 1;
            }
        }
    }
}

/// Plane-major form of [`bitslice_shuffle`], same permutation.
///
/// The block-major loop re-derives the mask, both word indices and the funnel
/// offset once per plane, and 60% of this guest's cost is the `Main` AIR, which
/// charges one row per executed instruction. Here a round's masks are built
/// once and each plane is a walk in which the ascending window, the descending
/// window and the mask array all advance by exactly one word a block.
fn bitslice_shuffle_planes(planes: &mut [u64], n: usize) {
    if n <= 1 {
        return;
    }
    let stride = planes.len() / LABEL_BITS;
    let pivots = pivots(n);
    let mut masks = vec![0u64; n / 128 + 2];
    for r in 0..ROUNDS {
        let mut src = Source::new(r);
        for (i0, j0, count) in round_plan(pivots[r as usize] as usize, n) {
            let head = core::cmp::min((j0 + 1) & 63, count);
            for k in 0..head {
                let j = j0 - k;
                if (src.byte(j) >> (j & 7)) & 1 == 1 {
                    bitslice_swap_one(planes, stride, i0 + k, j);
                }
            }
            let blocks = count.saturating_sub(head) / 64;
            for (b, m) in masks[..blocks].iter_mut().enumerate() {
                *m = rev64(src.word(j0 - head - 64 * b - 63));
            }
            let ilo = i0 + head;
            let (iw0, off) = (ilo >> 6, ilo & 63);
            let jw0 = (j0 - head - 63) >> 6;
            for plane in 0..LABEL_BITS {
                let base = plane * stride;
                bitslice_run(planes, base + iw0, base + jw0, off, &masks[..blocks]);
            }
            let mut k = head + blocks * 64;
            while k < count {
                let j = j0 - k;
                if (src.byte(j) >> (j & 7)) & 1 == 1 {
                    bitslice_swap_one(planes, stride, i0 + k, j);
                }
                k += 1;
            }
        }
    }
}

/// One plane's walk over a run's blocks. `xw` ascends and `jw` descends by one
/// word a block, and `off` is the funnel offset of the ascending window, fixed
/// for the whole run because blocks are 64 positions wide.
#[inline]
fn bitslice_run(planes: &mut [u64], xw: usize, jw: usize, off: usize, masks: &[u64]) {
    let ptr = planes.as_mut_ptr();
    unsafe {
        if off == 0 {
            let (mut xp, mut jp) = (ptr.add(xw), ptr.add(jw));
            for &m in masks {
                let (x, jword) = (*xp, *jp);
                let t = (x ^ rev64(jword)) & m;
                *jp = jword ^ rev64(t);
                *xp = x ^ t;
                xp = xp.add(1);
                jp = jp.sub(1);
            }
        } else {
            let (low, inv) = ((1u64 << off) - 1, 64 - off);
            let (mut xp, mut jp) = (ptr.add(xw), ptr.add(jw));
            for &m in masks {
                let (lo, hi, jword) = (*xp, *xp.add(1), *jp);
                let x = (lo >> off) | (hi << inv);
                let t = (x ^ rev64(jword)) & m;
                *jp = jword ^ rev64(t);
                let xt = x ^ t;
                *xp = (lo & low) | (xt << off);
                *xp.add(1) = (hi & !low) | (xt >> inv);
                xp = xp.add(1);
                jp = jp.sub(1);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Sampled scheme: bitmaps, and the commitment the challenge is drawn from
// ---------------------------------------------------------------------------

#[inline]
fn bitmap_stride(n: usize) -> usize {
    n.div_ceil(8)
}

/// The source bits of every round, over the whole domain. A round only ever
/// addresses the upper half of each mirror, so only those blocks are hashed;
/// the rest of the map is never read.
fn bitmaps(n: usize) -> Vec<u8> {
    let stride = bitmap_stride(n);
    let pivots = pivots(n);
    let mut out = vec![0u8; stride * ROUNDS as usize];
    for r in 0..ROUNDS {
        let mut buf = [0u8; 37];
        buf[..32].copy_from_slice(&SEED);
        buf[32] = r;
        let base = r as usize * stride;
        for (_, j0, count) in round_plan(pivots[r as usize] as usize, n) {
            if count == 0 {
                continue;
            }
            for block in ((j0 + 1 - count) >> 8)..=(j0 >> 8) {
                buf[33..37].copy_from_slice(&(block as u32).to_le_bytes());
                let bytes = sha256_short(&buf);
                let at = block * 32;
                let end = core::cmp::min(32, stride - at);
                out[base + at..base + at + end].copy_from_slice(&bytes[..end]);
            }
        }
    }
    out
}

/// Absorb a claimed assignment into a Poseidon2 sponge. Twelve 5-bit labels
/// pack into one 60-bit Goldilocks element and eight elements fill the rate, so
/// one permutation binds 96 validators.
fn commit_assignment(labels: &[u8]) -> [u64; 4] {
    let mut st = [0u64; 16];
    let mut rate = [0u64; 8];
    let (mut lane, mut shift) = (0usize, 0u32);
    for &l in labels {
        rate[lane] |= (l as u64) << shift;
        shift += 5;
        if shift == 60 {
            shift = 0;
            lane += 1;
            if lane == 8 {
                lane = 0;
                st[0..8].copy_from_slice(&rate);
                unsafe { syscall_poseidon2(&mut st as *mut [u64; 16]) };
                rate = [0u64; 8];
            }
        }
    }
    st[0..8].copy_from_slice(&rate);
    unsafe { syscall_poseidon2(&mut st as *mut [u64; 16]) };
    [st[0], st[1], st[2], st[3]]
}

fn checksum_labels(labels: &[u8]) -> u64 {
    let mut out = 0u64;
    for (v, &l) in labels.iter().enumerate() {
        out = out.wrapping_add((l as u64) << (v & 7));
    }
    out
}

// ---------------------------------------------------------------------------
// Selftest
// ---------------------------------------------------------------------------

fn selftest(n: usize) -> u64 {
    // The spec map, position -> validator offset, and the assignment it implies.
    let mut reference = vec![0u8; n];
    for p in 0..n {
        reference[spec_shuffled_index(p, n, true)] = slot_of_position(p, n);
    }

    let pivots = pivots(n);
    let maps = bitmaps(n);
    for (v, &want) in reference.iter().enumerate() {
        let by_hash = slot_of_position(traj_hashed(v, n, &pivots), n);
        assert!(by_hash == want, "hashed trajectory disagrees");
        let by_map = slot_of_position(traj_bitmap(v, n, &pivots, &maps), n);
        assert!(by_map == want, "bitmap trajectory disagrees");
        let by_spec = slot_of_position(spec_shuffled_index(v, n, false), n);
        assert!(by_spec == want, "reverse-round spec map disagrees");
    }

    let mut list: Vec<u32> = (0..n as u32).collect();
    shuffle_u32(&mut list, n);
    for (v, &p) in list.iter().enumerate() {
        assert!(
            slot_of_position(p as usize, n) == reference[v],
            "whole-set u32 shuffle disagrees"
        );
    }

    let mut labels = label_array(n);
    shuffle_u8(&mut labels, n);
    assert!(labels == reference, "whole-set label shuffle disagrees");

    let mut planes = bitslice_init(n);
    bitslice_shuffle(&mut planes, n);
    let stride = planes.len() / LABEL_BITS;
    for (v, &want) in reference.iter().enumerate() {
        assert!(
            bitslice_get(&planes, stride, v) == want,
            "bit-sliced shuffle disagrees"
        );
    }

    let mut planes = bitslice_init(n);
    bitslice_shuffle_planes(&mut planes, n);
    for (v, &want) in reference.iter().enumerate() {
        assert!(
            bitslice_get(&planes, stride, v) == want,
            "plane-major bit-sliced shuffle disagrees"
        );
    }

    checksum_labels(&reference)
}

// ---------------------------------------------------------------------------
// Plumbing
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

#[cfg(target_os = "zkvm")]
fn read_input() -> Vec<u8> {
    ziskos::io::read_slice().to_vec()
}

#[cfg(not(target_os = "zkvm"))]
fn read_input() -> Vec<u8> {
    let mut args = std::env::args().skip(1);
    let mut v = Vec::with_capacity(24);
    for _ in 0..3 {
        let x: u64 = args
            .next()
            .unwrap_or_else(|| "0".into())
            .parse()
            .expect("u64");
        v.extend_from_slice(&x.to_le_bytes());
    }
    v
}

fn emit(variant: u64, n: usize, param: usize, checksum: u64) {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&variant.to_le_bytes());
    out[8..16].copy_from_slice(&(n as u64).to_le_bytes());
    out[16..24].copy_from_slice(&(param as u64).to_le_bytes());
    out[24..32].copy_from_slice(&checksum.to_le_bytes());

    #[cfg(target_os = "zkvm")]
    ziskos::io::commit_slice(&out);
    #[cfg(not(target_os = "zkvm"))]
    println!("variant={variant} n={n} param={param} checksum={checksum:#018x}");
}
