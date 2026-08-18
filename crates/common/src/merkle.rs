//! Merkle verification, generic over the digest type and compression function.
//!
//! Used for both trees: the SSZ registry (SHA-256 over `[u8; 32]`) and the
//! accumulator (Poseidon2 over [`crate::acc::Digest`]).

use alloc::vec::Vec;

/// Recompute a root from a single leaf and its sibling path.
pub fn compute_root<T: Copy>(
    compress: impl Fn(&T, &T) -> T,
    leaf: &T,
    index: u64,
    siblings: &[T],
) -> T {
    let mut current = *leaf;
    let mut idx = index;
    for sibling in siblings {
        current = if idx & 1 == 0 {
            compress(&current, sibling)
        } else {
            compress(sibling, &current)
        };
        idx >>= 1;
    }
    current
}

/// Verify a single-leaf proof.
pub fn verify_proof<T: Copy + PartialEq>(
    compress: impl Fn(&T, &T) -> T,
    leaf: &T,
    index: u64,
    siblings: &[T],
    expected_root: &T,
) -> bool {
    compute_root(compress, leaf, index, siblings) == *expected_root
}

/// Recompute a root from many leaves at once, consuming only the sibling nodes
/// that the leaf set does not already determine.
///
/// `leaves` must be sorted by index and strictly increasing. Auxiliaries are
/// consumed bottom-up, and within a level in ascending parent order, left
/// child before right.
///
/// Each level is a linear scan over two flat vectors. The leaf set collapses as
/// it rises — for a set covering a large fraction of the tree, the upper levels
/// dominate and total work approaches the size of the tree rather than
/// `leaves * depth`.
pub fn batch_root<T: Copy>(
    compress: impl Fn(&T, &T) -> T,
    leaves: &[(T, u64)],
    aux: &[T],
    depth: u32,
) -> T {
    let mut idx: Vec<u64> = Vec::with_capacity(leaves.len());
    let mut val: Vec<T> = Vec::with_capacity(leaves.len());
    for (i, (v, k)) in leaves.iter().enumerate() {
        assert!(
            i == 0 || *k > idx[i - 1],
            "batch_root: leaves must be strictly increasing by index"
        );
        idx.push(*k);
        val.push(*v);
    }

    batch_root_columns(compress, idx, val, aux, depth)
}

/// The same, over columns the caller already holds and has already checked are
/// strictly increasing.
///
/// The committee proof walks a million members in one pass — asserting that
/// order as it goes, because the order is what makes its slot buckets disjoint
/// — and fills these two vectors while it does. Taking them directly spares it
/// a third vector of pairs for this function to take apart again, which at
/// mainnet scale is 38 MB of proven memory traffic for nothing.
pub fn batch_root_columns<T: Copy>(
    compress: impl Fn(&T, &T) -> T,
    mut idx: Vec<u64>,
    mut val: Vec<T>,
    aux: &[T],
    depth: u32,
) -> T {
    assert!(!idx.is_empty(), "batch_root: empty leaf set");

    let mut next_idx: Vec<u64> = Vec::with_capacity(idx.len());
    let mut next_val: Vec<T> = Vec::with_capacity(val.len());
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
            next_val.push(compress(&left, &right));
        }

        core::mem::swap(&mut idx, &mut next_idx);
        core::mem::swap(&mut val, &mut next_val);
    }

    assert_eq!(cursor, aux.len(), "batch_root: unconsumed auxiliaries");
    assert_eq!(
        val.len(),
        1,
        "batch_root: did not converge to a single root"
    );
    val[0]
}

#[inline]
fn take<T: Copy>(aux: &[T], cursor: &mut usize) -> T {
    let v = *aux.get(*cursor).expect("batch_root: auxiliaries exhausted");
    *cursor += 1;
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = a[i] ^ b[i].rotate_left(1);
        }
        out
    }

    /// Build a full depth-`d` tree and check `batch_root` against `compute_root`
    /// for every subset shape the scan has to handle.
    fn full_tree(depth: u32, leaves: &[[u8; 32]]) -> [u8; 32] {
        let mut level: Vec<[u8; 32]> = leaves.to_vec();
        for _ in 0..depth {
            level = level.chunks(2).map(|c| xor(&c[0], &c[1])).collect();
        }
        level[0]
    }

    /// Collect the auxiliaries a leaf subset needs, in consumption order.
    fn collect_aux(depth: u32, leaves: &[[u8; 32]], picked: &[u64]) -> Vec<[u8; 32]> {
        let mut levels: Vec<Vec<[u8; 32]>> = vec![leaves.to_vec()];
        for _ in 0..depth {
            let next = levels
                .last()
                .unwrap()
                .chunks(2)
                .map(|c| xor(&c[0], &c[1]))
                .collect();
            levels.push(next);
        }
        let mut idx: Vec<u64> = picked.to_vec();
        let mut aux = Vec::new();
        for level in levels.iter().take(depth as usize) {
            let mut next = Vec::new();
            let mut i = 0;
            while i < idx.len() {
                let k = idx[i];
                if k & 1 == 0 {
                    if i + 1 < idx.len() && idx[i + 1] == k + 1 {
                        i += 2;
                    } else {
                        aux.push(level[(k + 1) as usize]);
                        i += 1;
                    }
                } else {
                    aux.push(level[(k - 1) as usize]);
                    i += 1;
                }
                next.push(k >> 1);
            }
            next.dedup();
            idx = next;
        }
        aux
    }

    #[test]
    fn batch_root_matches_full_tree() {
        let depth = 4u32;
        let leaves: Vec<[u8; 32]> = (0..16u8).map(|i| [i + 1; 32]).collect();
        let root = full_tree(depth, &leaves);

        for picked in [
            vec![0u64],
            vec![15],
            vec![0, 1],
            vec![0, 2],
            vec![1, 2],
            vec![3, 4, 5],
            vec![0, 1, 2, 3, 4, 5, 6, 7],
            (0..16).collect::<Vec<u64>>(),
        ] {
            let set: Vec<([u8; 32], u64)> =
                picked.iter().map(|&k| (leaves[k as usize], k)).collect();
            let aux = collect_aux(depth, &leaves, &picked);
            assert_eq!(
                batch_root(xor, &set, &aux, depth),
                root,
                "subset {picked:?} failed"
            );
        }
    }

    #[test]
    fn single_leaf_path_agrees_with_batch() {
        let depth = 4u32;
        let leaves: Vec<[u8; 32]> = (0..16u8).map(|i| [i + 1; 32]).collect();
        let root = full_tree(depth, &leaves);
        let aux = collect_aux(depth, &leaves, &[6]);
        assert_eq!(compute_root(xor, &leaves[6], 6, &aux), root);
    }
}
