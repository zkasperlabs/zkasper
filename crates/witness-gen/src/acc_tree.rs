//! Host-side accumulator Merkle tree.
//!
//! Maintains a sparse tree in memory: only levels 0..dense_depth are stored,
//! with zero_hash chaining for the remaining levels up to the full depth.
//! Supports incremental leaf updates and Merkle proof extraction.

use rayon::prelude::*;
use zkasper_common::acc::{self, Digest, ZERO};
use zkasper_common::types::AccMultiProof;
use zkasper_common::types::ValidatorData;

/// Sparse accumulator Merkle tree stored level-by-level.
///
/// Only the dense portion (levels 0..dense_depth) is allocated.
/// The full tree root at `depth` is computed by chaining the dense root
/// through precomputed zero hashes for levels dense_depth..depth.
#[derive(Clone)]
pub struct AccTree {
    /// Full tree depth (e.g. 22 for ACC_TREE_DEPTH).
    pub(crate) depth: u32,
    /// Dense depth: only levels 0..dense_depth are stored.
    /// `dense_depth = ceil(log2(num_leaves))`, where num_leaves is rounded
    /// up to the next power of 2.
    pub(crate) dense_depth: u32,
    /// Nodes stored level-by-level. Level 0 = leaves, level `dense_depth` = dense root.
    /// Level d has `2^(dense_depth - d)` nodes.
    pub(crate) levels: Vec<Vec<Digest>>,
    /// Precomputed accumulator zero hashes for each level 0..=depth.
    /// zero_hashes[0] = [0;32], zero_hashes[d] = acc::compress(zh[d-1], zh[d-1])
    pub(crate) zero_hashes: Vec<Digest>,
}

/// Compute the smallest d such that 2^d >= n. Returns 0 for n <= 1.
fn ceil_log2(n: usize) -> u32 {
    if n <= 1 {
        return 0;
    }
    (n as u64).next_power_of_two().trailing_zeros()
}

/// Precompute accumulator zero hashes for levels 0..=depth.
fn compute_zero_hashes(depth: u32) -> Vec<Digest> {
    let mut zh = vec![ZERO; (depth + 1) as usize];
    for d in 1..=depth as usize {
        zh[d] = acc::compress(&zh[d - 1], &zh[d - 1]);
    }
    zh
}

impl AccTree {
    /// Build the tree from a list of validators at a given epoch.
    ///
    /// Only allocates the dense portion (2^ceil(log2(n)) leaves).
    /// The full root at `depth` is computed via zero_hash chaining.
    pub fn build(validators: &[ValidatorData], epoch: u64, depth: u32) -> Self {
        let zero_hashes = compute_zero_hashes(depth);

        let dense_depth = ceil_log2(validators.len()).max(1).min(depth);
        let dense_capacity = 1usize << dense_depth;

        // Compute leaves in parallel (only the dense portion)
        let mut leaves: Vec<Digest> = validators
            .par_iter()
            .map(|v| {
                let point = crate::pubkey::decompress(&v.pubkey.0)
                    .expect("validator has an invalid public key");
                acc::leaf(&point, v.active_effective_balance(epoch))
            })
            .collect();
        leaves.resize(dense_capacity, ZERO);

        // Build levels bottom-up (0..dense_depth), parallelizing large levels
        let mut levels = Vec::with_capacity((dense_depth + 1) as usize);
        levels.push(leaves);

        for d in 0..dense_depth as usize {
            let prev = &levels[d];
            let parents: Vec<Digest> = prev
                .par_chunks_exact(2)
                .map(|pair| acc::compress(&pair[0], &pair[1]))
                .collect();
            levels.push(parents);
        }

        Self {
            depth,
            dense_depth,
            levels,
            zero_hashes,
        }
    }

    /// Reconstruct from raw level data (for loading from DB).
    pub fn from_raw(levels: Vec<Vec<Digest>>, depth: u32, dense_depth: u32) -> Self {
        let zero_hashes = compute_zero_hashes(depth);
        Self {
            depth,
            dense_depth,
            levels,
            zero_hashes,
        }
    }

    /// Recompute every internal level from the leaves and check it matches.
    ///
    /// The accumulator is a chain: epoch N's root is only meaningful if epoch
    /// N-1's was right. A tree read back from disk is therefore checked to be a
    /// well-formed Merkle tree before anything is built on top of it, rather
    /// than trusted because the bytes deserialized.
    pub fn verify_consistent(&self) -> Result<(), String> {
        if self.levels.len() != self.dense_depth as usize + 1 {
            return Err(format!(
                "expected {} levels for dense_depth {}, got {}",
                self.dense_depth + 1,
                self.dense_depth,
                self.levels.len(),
            ));
        }
        if self.dense_depth > self.depth {
            return Err(format!(
                "dense_depth {} exceeds depth {}",
                self.dense_depth, self.depth,
            ));
        }
        for (d, level) in self.levels.iter().enumerate() {
            let expected = 1usize << (self.dense_depth as usize - d);
            if level.len() != expected {
                return Err(format!(
                    "level {d} has {} nodes, expected {expected}",
                    level.len(),
                ));
            }
        }
        for d in 0..self.dense_depth as usize {
            let recomputed: Vec<Digest> = self.levels[d]
                .par_chunks_exact(2)
                .map(|pair| acc::compress(&pair[0], &pair[1]))
                .collect();
            if recomputed != self.levels[d + 1] {
                return Err(format!("level {} does not hash to level {}", d, d + 1));
            }
        }
        Ok(())
    }

    /// Current root hash at the full tree depth.
    ///
    /// Chains the dense root through zero hashes for levels dense_depth..depth.
    pub fn root(&self) -> Digest {
        let mut current = self.levels[self.dense_depth as usize][0];
        for d in self.dense_depth..self.depth {
            current = acc::compress(&current, &self.zero_hashes[d as usize]);
        }
        current
    }

    /// Get Merkle proof siblings for a leaf at `index`.
    ///
    /// For levels 0..dense_depth, siblings come from stored data.
    /// For levels dense_depth..depth, siblings are zero_hashes.
    pub fn get_siblings(&self, index: u64) -> Vec<Digest> {
        let mut siblings = Vec::with_capacity(self.depth as usize);
        let mut idx = index as usize;

        // Dense levels: from stored data
        for d in 0..self.dense_depth as usize {
            let sibling_idx = idx ^ 1;
            siblings.push(self.levels[d][sibling_idx]);
            idx >>= 1;
        }

        // Sparse levels: zero hashes
        for d in self.dense_depth..self.depth {
            siblings.push(self.zero_hashes[d as usize]);
        }

        siblings
    }

    /// Build a multi-proof for the given leaf indices.
    ///
    /// Collects auxiliary sibling nodes bottom-up, left-to-right — the same
    /// order the verifier consumes them.
    /// Collect the auxiliary nodes a leaf set needs, in exactly the order
    /// [`zkasper_common::merkle::batch_root`] consumes them.
    ///
    /// Mirrors the circuit's scan: a flat pass per level, left child before
    /// right, ascending parent order. Keeping the two loops structurally
    /// identical is what guarantees the ordering agrees.
    pub fn build_multi_proof(&self, leaf_indices: &[u64]) -> AccMultiProof {
        let mut idx: Vec<u64> = leaf_indices.to_vec();
        idx.sort_unstable();
        idx.dedup();

        let mut auxiliaries = Vec::new();
        let mut next: Vec<u64> = Vec::with_capacity(idx.len());

        for level in 0..self.depth {
            next.clear();
            let mut i = 0usize;
            while i < idx.len() {
                let k = idx[i];
                if k & 1 == 0 {
                    if i + 1 < idx.len() && idx[i + 1] == k + 1 {
                        i += 2;
                    } else {
                        auxiliaries.push(self.get_node(level, k + 1));
                        i += 1;
                    }
                } else {
                    auxiliaries.push(self.get_node(level, k - 1));
                    i += 1;
                }
                next.push(k >> 1);
            }
            std::mem::swap(&mut idx, &mut next);
        }

        AccMultiProof { auxiliaries }
    }

    /// Get the hash of a node at a given level and index.
    fn get_node(&self, level: u32, idx: u64) -> Digest {
        if level < self.dense_depth {
            let level_data = &self.levels[level as usize];
            if (idx as usize) < level_data.len() {
                level_data[idx as usize]
            } else {
                self.zero_hashes[level as usize]
            }
        } else {
            self.zero_hashes[level as usize]
        }
    }

    /// Update a leaf and recompute the path to the dense root.
    /// Returns the siblings BEFORE the update (for the witness).
    ///
    /// The full root (via `root()`) is automatically correct after this call.
    pub fn update_leaf(&mut self, index: u64, new_leaf: Digest) -> Vec<Digest> {
        let siblings = self.get_siblings(index);

        // Update leaf
        self.levels[0][index as usize] = new_leaf;

        // Recompute path within dense portion
        let mut idx = index as usize;
        for d in 0..self.dense_depth as usize {
            let parent_idx = idx / 2;
            let left = self.levels[d][parent_idx * 2];
            let right = self.levels[d][parent_idx * 2 + 1];
            self.levels[d + 1][parent_idx] = acc::compress(&left, &right);
            idx = parent_idx;
        }

        siblings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkasper_common::types::BlsPubkey;

    fn dummy_validator(i: u8) -> ValidatorData {
        ValidatorData {
            pubkey: BlsPubkey(zkasper_common::test_utils::make_pubkey(i)),
            effective_balance: 32_000_000_000,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        }
    }

    #[test]
    fn test_build_small_tree() {
        let validators: Vec<_> = (0..4).map(dummy_validator).collect();
        let tree = AccTree::build(&validators, 100, 2); // depth 2 for 4 leaves
        let root = tree.root();
        assert_ne!(root, ZERO);
        assert_eq!(tree.dense_depth, 2);
        assert_eq!(tree.depth, 2);
    }

    #[test]
    fn test_update_leaf() {
        let validators: Vec<_> = (0..4).map(dummy_validator).collect();
        let mut tree = AccTree::build(&validators, 100, 2);
        let old_root = tree.root();

        let new_leaf = acc::leaf(&[99u64; 12], 16_000_000_000);
        let _siblings = tree.update_leaf(1, new_leaf);
        let new_root = tree.root();

        assert_ne!(old_root, new_root);
    }

    #[test]
    fn test_siblings_verify() {
        let validators: Vec<_> = (0..4).map(dummy_validator).collect();
        let tree = AccTree::build(&validators, 100, 2);

        for i in 0..4u64 {
            let leaf = tree.levels[0][i as usize];
            let siblings = tree.get_siblings(i);
            assert!(zkasper_common::merkle::verify_proof(
                acc::compress,
                &leaf,
                i,
                &siblings,
                &tree.root()
            ));
        }
    }

    #[test]
    fn test_sparse_tree_depth_22() {
        // Build a sparse tree with depth 22 (ACC_TREE_DEPTH) but only 100 validators.
        // This should NOT OOM (allocates ~256 leaves, not 2^22).
        let validators: Vec<_> = (0..100).map(dummy_validator).collect();
        let tree = AccTree::build(&validators, 100, 22);

        assert_eq!(tree.depth, 22);
        assert_eq!(tree.dense_depth, 7); // ceil(log2(100)) = 7 (2^7=128)
        assert_ne!(tree.root(), ZERO);

        // Verify siblings work at full depth
        let leaf = tree.levels[0][0];
        let siblings = tree.get_siblings(0);
        assert_eq!(siblings.len(), 22);

        // Verify merkle proof
        assert!(zkasper_common::merkle::verify_proof(
            acc::compress,
            &leaf,
            0,
            &siblings,
            &tree.root()
        ));
    }

    #[test]
    fn test_sparse_tree_matches_dense() {
        // Verify that a sparse tree (depth=10) with 4 validators produces
        // the same root as a tree built with depth=2 when we account for
        // the zero-hash chaining.
        let validators: Vec<_> = (0..4).map(dummy_validator).collect();
        let dense_tree = AccTree::build(&validators, 100, 2);
        let sparse_tree = AccTree::build(&validators, 100, 10);

        // The sparse root chains through zero_hashes[2..10]
        // The dense root is at depth 2
        // They should match because the sparse tree chains:
        //   root = dense_root -> zh[2] -> zh[3] -> ... -> zh[9]
        let mut expected_root = dense_tree.root();
        let zh = compute_zero_hashes(10);
        for z in zh.iter().take(10).skip(2) {
            expected_root = acc::compress(&expected_root, z);
        }
        assert_eq!(sparse_tree.root(), expected_root);
    }

    #[test]
    fn test_sparse_update_and_verify() {
        let validators: Vec<_> = (0..8).map(dummy_validator).collect();
        let mut tree = AccTree::build(&validators, 100, 20);
        let old_root = tree.root();

        // Update leaf 3
        let new_leaf = acc::leaf(&[99u64; 12], 16_000_000_000);
        let old_siblings = tree.update_leaf(3, new_leaf);
        let new_root = tree.root();

        assert_ne!(old_root, new_root);
        assert_eq!(old_siblings.len(), 20);

        // Verify new leaf with new root
        let new_siblings = tree.get_siblings(3);
        assert!(zkasper_common::merkle::verify_proof(
            acc::compress,
            &new_leaf,
            3,
            &new_siblings,
            &new_root
        ));
    }
}
