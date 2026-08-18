//! The counted-set tree: which validators an epoch has already counted.
//!
//! # Why this exists
//!
//! A validator may only contribute its balance once per epoch. The justification
//! proof enforced that by merging every slot's counted indices and scanning the
//! merged list, which is fine when one proof sees the whole epoch and hopeless
//! when the epoch is proven as a stream: the last proof in the chain would have
//! to re-read a million indices to know whether the *last* attestation's
//! attesters were already counted.
//!
//! A committed set with cheap non-membership fixes that. The running aggregate
//! carries a root; a proof that adds attesters opens only the leaves it touches,
//! shows their bits are clear, and sets them. Cost is proportional to what is
//! being added, not to what has accumulated — so the final proof, which adds one
//! marginal aggregate, pays for one marginal aggregate.
//!
//! # Shape
//!
//! One bit per validator index, 256 bits to a leaf, packed as eight `u32`
//! (32-bit values are always canonical Goldilocks elements, 64-bit words are
//! not). That makes the tree 8 levels shallower than the accumulator — depth 14
//! for a 2^22 index space — and, far more importantly, makes a large insert
//! cheap: 33,000 attesters in a slot land in at most 16,384 leaves, and adjacent
//! validator indices share one.
//!
//! The same set as a one-leaf-per-validator sparse tree would cost about 40x
//! more to insert, because every index would carry its own leaf hash and its own
//! near-the-bottom internal nodes.

use alloc::vec::Vec;

use ziskos::syscalls::syscall_poseidon2;

use crate::acc::Digest;
use crate::merkle::batch_root;

/// Validator indices per leaf.
pub const LEAF_BITS: u64 = 256;

/// `u32` words per leaf.
pub const LEAF_WORDS: usize = 8;

/// One leaf's bitmap.
pub type Bitmap = [u32; LEAF_WORDS];

/// An empty leaf.
pub const EMPTY_BITMAP: Bitmap = [0; LEAF_WORDS];

const DOMAIN_DEDUP_LEAF: u64 = 5;

/// Depth of the counted-set tree for an accumulator of depth `acc_depth`.
///
/// Eight levels shallower, because a leaf holds 256 indices. Saturating, so a
/// small test tree collapses to a single leaf rather than underflowing.
pub const fn tree_depth(acc_depth: u32) -> u32 {
    acc_depth.saturating_sub(LEAF_BITS.trailing_zeros())
}

/// Hash one leaf's bitmap.
pub fn leaf(bitmap: &Bitmap) -> Digest {
    let mut st = [0u64; 16];
    for (i, w) in bitmap.iter().enumerate() {
        st[i] = *w as u64;
    }
    st[15] = DOMAIN_DEDUP_LEAF;
    #[cfg(feature = "count-ops")]
    crate::op_counter::inc_poseidon2();
    unsafe { syscall_poseidon2(&mut st as *mut [u64; 16]) };
    [st[0], st[1], st[2], st[3]]
}

/// Root of a tree in which nothing has been counted yet.
pub fn empty_root(depth: u32) -> Digest {
    let mut node = leaf(&EMPTY_BITMAP);
    for _ in 0..depth {
        node = crate::acc::compress(&node, &node);
    }
    node
}

/// A batch opening of the counted-set tree.
///
/// `bitmaps` holds the current contents of each touched leaf, in ascending leaf
/// order, and `auxiliaries` the sibling nodes those leaves do not determine —
/// the same order [`crate::merkle::batch_root`] consumes them in.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct DedupProof {
    pub bitmaps: Vec<Bitmap>,
    pub auxiliaries: Vec<Digest>,
}

/// What a set of indices does to the tree.
pub struct Update {
    /// Root the opened leaves hash to *before* the update. The caller compares
    /// this against the root it expected; equality is what proves that none of
    /// `indices` was already counted, because a set bit would have changed the
    /// leaf.
    pub old_root: Digest,
    /// Root after every index in the batch is marked counted.
    pub new_root: Digest,
}

/// Open `indices` against the tree, prove none of them is already counted, and
/// compute the root that marking them all produces.
///
/// `indices` must be strictly increasing. Returns `None` if the proof is
/// malformed or if any index is already set — the latter being exactly the
/// double-count the epoch has to reject.
///
/// Both roots come out of one auxiliary list: the set of nodes a leaf set does
/// not determine depends on the leaf *positions*, which the update does not
/// change.
pub fn apply(indices: &[u64], proof: &DedupProof, depth: u32) -> Option<Update> {
    if indices.is_empty() {
        return None;
    }

    let mut old_leaves: Vec<(Digest, u64)> = Vec::with_capacity(proof.bitmaps.len());
    let mut new_leaves: Vec<(Digest, u64)> = Vec::with_capacity(proof.bitmaps.len());

    let mut cursor = 0usize;
    let mut i = 0usize;
    let mut previous: Option<u64> = None;

    while i < indices.len() {
        let leaf_index = indices[i] / LEAF_BITS;
        let old = *proof.bitmaps.get(cursor)?;
        let mut new = old;

        while i < indices.len() && indices[i] / LEAF_BITS == leaf_index {
            let index = indices[i];
            if let Some(p) = previous {
                if index <= p {
                    return None;
                }
            }
            previous = Some(index);

            let bit = (index % LEAF_BITS) as usize;
            let mask = 1u32 << (bit % 32);
            if new[bit / 32] & mask != 0 {
                // Already counted, either by an earlier proof in the chain or —
                // impossible given the strictly-increasing check above — twice
                // in this batch.
                return None;
            }
            new[bit / 32] |= mask;
            i += 1;
        }

        old_leaves.push((leaf(&old), leaf_index));
        new_leaves.push((leaf(&new), leaf_index));
        cursor += 1;
    }

    if cursor != proof.bitmaps.len() {
        return None;
    }

    Some(Update {
        old_root: batch_root(crate::acc::compress, &old_leaves, &proof.auxiliaries, depth),
        new_root: batch_root(crate::acc::compress, &new_leaves, &proof.auxiliaries, depth),
    })
}

/// Prove `indices` are *not* counted in the tree rooted at `root`, without
/// producing a new root.
///
/// This is the form the last proof in a chain uses: nothing is added after it,
/// so half the hashing in [`apply`] would be thrown away.
pub fn verify_absent(root: &Digest, indices: &[u64], proof: &DedupProof, depth: u32) -> bool {
    if indices.is_empty() {
        return proof.bitmaps.is_empty();
    }

    let mut leaves: Vec<(Digest, u64)> = Vec::with_capacity(proof.bitmaps.len());
    let mut cursor = 0usize;
    let mut i = 0usize;
    let mut previous: Option<u64> = None;

    while i < indices.len() {
        let leaf_index = indices[i] / LEAF_BITS;
        let Some(bitmap) = proof.bitmaps.get(cursor) else {
            return false;
        };

        while i < indices.len() && indices[i] / LEAF_BITS == leaf_index {
            let index = indices[i];
            if let Some(p) = previous {
                if index <= p {
                    return false;
                }
            }
            previous = Some(index);

            let bit = (index % LEAF_BITS) as usize;
            if bitmap[bit / 32] & (1u32 << (bit % 32)) != 0 {
                return false;
            }
            i += 1;
        }

        leaves.push((leaf(bitmap), leaf_index));
        cursor += 1;
    }

    cursor == proof.bitmaps.len()
        && batch_root(crate::acc::compress, &leaves, &proof.auxiliaries, depth) == *root
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Reference tree: dense, small depth, rebuilt from scratch every time.
    struct Reference {
        depth: u32,
        bitmaps: Vec<Bitmap>,
    }

    impl Reference {
        fn new(depth: u32) -> Self {
            Self {
                depth,
                bitmaps: vec![EMPTY_BITMAP; 1 << depth],
            }
        }

        fn root(&self) -> Digest {
            let mut level: Vec<Digest> = self.bitmaps.iter().map(leaf).collect();
            for _ in 0..self.depth {
                level = level
                    .chunks(2)
                    .map(|c| crate::acc::compress(&c[0], &c[1]))
                    .collect();
            }
            level[0]
        }

        fn touched(&self, indices: &[u64]) -> Vec<u64> {
            let mut leaves: Vec<u64> = indices.iter().map(|i| i / LEAF_BITS).collect();
            leaves.dedup();
            leaves
        }

        fn proof(&self, indices: &[u64]) -> DedupProof {
            let touched = self.touched(indices);
            let mut levels: Vec<Vec<Digest>> = vec![self.bitmaps.iter().map(leaf).collect()];
            for _ in 0..self.depth {
                let next = levels
                    .last()
                    .unwrap()
                    .chunks(2)
                    .map(|c| crate::acc::compress(&c[0], &c[1]))
                    .collect();
                levels.push(next);
            }

            let mut idx = touched.clone();
            let mut auxiliaries = Vec::new();
            for level in levels.iter().take(self.depth as usize) {
                let mut next = Vec::new();
                let mut i = 0;
                while i < idx.len() {
                    let k = idx[i];
                    if k & 1 == 0 {
                        if i + 1 < idx.len() && idx[i + 1] == k + 1 {
                            i += 2;
                        } else {
                            auxiliaries.push(level[(k + 1) as usize]);
                            i += 1;
                        }
                    } else {
                        auxiliaries.push(level[(k - 1) as usize]);
                        i += 1;
                    }
                    next.push(k >> 1);
                }
                next.dedup();
                idx = next;
            }

            DedupProof {
                bitmaps: touched.iter().map(|&l| self.bitmaps[l as usize]).collect(),
                auxiliaries,
            }
        }

        fn set(&mut self, indices: &[u64]) {
            for &i in indices {
                let bit = (i % LEAF_BITS) as usize;
                self.bitmaps[(i / LEAF_BITS) as usize][bit / 32] |= 1u32 << (bit % 32);
            }
        }
    }

    #[test]
    fn empty_root_matches_reference() {
        for depth in 0..4u32 {
            assert_eq!(empty_root(depth), Reference::new(depth).root());
        }
    }

    #[test]
    fn insert_chain_tracks_the_reference() {
        let depth = 3u32;
        let mut reference = Reference::new(depth);
        let mut root = empty_root(depth);
        assert_eq!(root, reference.root());

        for batch in [
            vec![0u64, 5, 300, 1000],
            vec![1, 2, 3, 700, 1900],
            vec![255, 256, 257],
        ] {
            let proof = reference.proof(&batch);
            let update = apply(&batch, &proof, depth).expect("apply");
            assert_eq!(update.old_root, root);
            assert!(verify_absent(&root, &batch, &proof, depth));

            reference.set(&batch);
            root = update.new_root;
            assert_eq!(root, reference.root());
        }
    }

    #[test]
    fn a_second_count_is_rejected() {
        let depth = 3u32;
        let mut reference = Reference::new(depth);
        let batch = vec![7u64, 9, 600];

        let proof = reference.proof(&batch);
        let root = apply(&batch, &proof, depth).unwrap().new_root;
        reference.set(&batch);

        let again = reference.proof(&[9u64]);
        assert!(apply(&[9], &again, depth).is_none());
        assert!(!verify_absent(&root, &[9], &again, depth));
        // A validator that was not counted still opens fine against the same root.
        let fresh = reference.proof(&[10u64]);
        assert!(verify_absent(&root, &[10], &fresh, depth));
    }

    #[test]
    fn unsorted_indices_are_rejected() {
        let reference = Reference::new(3);
        let proof = reference.proof(&[3u64, 1]);
        assert!(apply(&[3, 1], &proof, 3).is_none());
        assert!(!verify_absent(&empty_root(3), &[3, 1], &proof, 3));
    }

    #[test]
    fn depth_is_eight_levels_under_the_accumulator() {
        assert_eq!(tree_depth(crate::constants::ACC_TREE_DEPTH), 14);
    }
}
