//! SSZ hashing over the SHA-256 domain.
//!
//! `sha256_pair` is the hot path — every SSZ Merkle level and every container
//! hash_tree_root goes through it. It is expressed as two `syscall_sha256_f`
//! compressions with no allocation and no message-scheduling code: the first
//! block is the 64 bytes of input, the second is the fixed padding block for a
//! 64-byte message.

use ziskos::syscalls::{syscall_sha256_f, SyscallSha256Params};

use crate::merkle;
use crate::types::{BoundaryAnchor, SszMultiProof, ValidatorData};

/// SHA-256 initial hash values.
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

/// Padding block for a message of exactly 64 bytes: `0x80`, zeros, then the
/// bit length (512) as a big-endian u64 in the final 8 bytes.
const PAD_512: [u64; 8] = [0x80, 0, 0, 0, 0, 0, 0, 0x0002_0000_0000_0000];

/// SHA-256 of two concatenated 32-byte inputs — the SSZ Merkle compression.
pub fn sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    #[cfg(feature = "count-ops")]
    crate::op_counter::inc_sha256f(2);

    let mut state = [
        IV[0] as u64 | (IV[1] as u64) << 32,
        IV[2] as u64 | (IV[3] as u64) << 32,
        IV[4] as u64 | (IV[5] as u64) << 32,
        IV[6] as u64 | (IV[7] as u64) << 32,
    ];

    let mut block = [0u64; 8];
    for i in 0..4 {
        block[i] = u64::from_le_bytes(left[8 * i..8 * i + 8].try_into().unwrap());
        block[4 + i] = u64::from_le_bytes(right[8 * i..8 * i + 8].try_into().unwrap());
    }
    syscall_sha256_f(&mut SyscallSha256Params {
        state: &mut state,
        input: &block,
    });
    syscall_sha256_f(&mut SyscallSha256Params {
        state: &mut state,
        input: &PAD_512,
    });

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[8 * i..8 * i + 4].copy_from_slice(&(state[i] as u32).to_be_bytes());
        out[8 * i + 4..8 * i + 8].copy_from_slice(&((state[i] >> 32) as u32).to_be_bytes());
    }
    out
}

/// Merkleize 8 leaves (depth-3 binary tree, 7 hashes).
/// Used for the Validator container hash_tree_root.
pub fn validator_hash_tree_root(field_leaves: &[[u8; 32]; 8]) -> [u8; 32] {
    let n0 = sha256_pair(&field_leaves[0], &field_leaves[1]);
    let n1 = sha256_pair(&field_leaves[2], &field_leaves[3]);
    let n2 = sha256_pair(&field_leaves[4], &field_leaves[5]);
    let n3 = sha256_pair(&field_leaves[6], &field_leaves[7]);
    let n4 = sha256_pair(&n0, &n1);
    let n5 = sha256_pair(&n2, &n3);
    sha256_pair(&n4, &n5)
}

/// Compute both old and new validator hash tree roots, sharing intermediate
/// SHA-256 computations when subtrees are identical.
///
/// For activity-only mutations (no SSZ field changes), this does 7 hashes
/// instead of 14. For single-field changes (e.g. effective_balance), ~10
/// instead of 14.
pub fn validator_hash_tree_root_pair(
    old_leaves: &[[u8; 32]; 8],
    new_leaves: &[[u8; 32]; 8],
) -> ([u8; 32], [u8; 32]) {
    let (old_n0, new_n0) = shared_sha256_pair(
        &old_leaves[0],
        &old_leaves[1],
        &new_leaves[0],
        &new_leaves[1],
    );
    let (old_n1, new_n1) = shared_sha256_pair(
        &old_leaves[2],
        &old_leaves[3],
        &new_leaves[2],
        &new_leaves[3],
    );
    let (old_n2, new_n2) = shared_sha256_pair(
        &old_leaves[4],
        &old_leaves[5],
        &new_leaves[4],
        &new_leaves[5],
    );
    let (old_n3, new_n3) = shared_sha256_pair(
        &old_leaves[6],
        &old_leaves[7],
        &new_leaves[6],
        &new_leaves[7],
    );
    let (old_n4, new_n4) = shared_sha256_pair(&old_n0, &old_n1, &new_n0, &new_n1);
    let (old_n5, new_n5) = shared_sha256_pair(&old_n2, &old_n3, &new_n2, &new_n3);
    shared_sha256_pair(&old_n4, &old_n5, &new_n4, &new_n5)
}

/// Hash two pairs, but compute only once if both pairs are identical.
#[inline]
fn shared_sha256_pair(
    old_l: &[u8; 32],
    old_r: &[u8; 32],
    new_l: &[u8; 32],
    new_r: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    if old_l == new_l && old_r == new_r {
        let h = sha256_pair(new_l, new_r);
        (h, h)
    } else {
        (sha256_pair(old_l, old_r), sha256_pair(new_l, new_r))
    }
}

/// SSZ List hash_tree_root: `sha256(data_tree_root || le_pad32(length))`.
pub fn list_hash_tree_root(data_tree_root: &[u8; 32], length: u64) -> [u8; 32] {
    sha256_pair(data_tree_root, &u64_to_chunk(length))
}

/// Compute a SHA-256 Merkle root from leaf, index, and siblings.
pub fn compute_ssz_merkle_root(leaf: &[u8; 32], index: u64, siblings: &[[u8; 32]]) -> [u8; 32] {
    merkle::compute_root(sha256_pair, leaf, index, siblings)
}

/// Verify a SHA-256 Merkle proof.
pub fn verify_ssz_merkle_proof(
    leaf: &[u8; 32],
    index: u64,
    siblings: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    merkle::verify_proof(sha256_pair, leaf, index, siblings, root)
}

/// Recompute the SSZ root covering many leaves at once.
pub fn verify_ssz_multi_proof(
    leaves: &[([u8; 32], u64)],
    proof: &SszMultiProof,
    depth: u32,
) -> [u8; 32] {
    merkle::batch_root(sha256_pair, leaves, &proof.auxiliaries, depth)
}

/// `hash_tree_root(Checkpoint)` from its two fields.
pub fn checkpoint_leaf(epoch: u64, root: &[u8; 32]) -> [u8; 32] {
    sha256_pair(&u64_to_chunk(epoch), root)
}

/// The FFG link an attestation votes for, as one 32-byte digest.
///
/// A proof carries 256 public bytes and [`crate::types::AggregateOutput`]
/// already spends 248, so the source checkpoint cannot travel beside the target
/// root. Both checkpoints are leaves [`attestation_data_root`] already computes,
/// and hashing the pair binds all four fields in the bytes the target root used
/// to occupy on its own.
pub fn checkpoint_digest(
    source_epoch: u64,
    source_root: &[u8; 32],
    target_epoch: u64,
    target_root: &[u8; 32],
) -> [u8; 32] {
    sha256_pair(
        &checkpoint_leaf(source_epoch, source_root),
        &checkpoint_leaf(target_epoch, target_root),
    )
}

/// Compute `hash_tree_root(AttestationData)` from its constituent fields.
///
/// AttestationData is a 5-field SSZ container merkleized into an 8-leaf tree:
/// ```text
/// field[0] = le_pad32(slot)
/// field[1] = le_pad32(index)
/// field[2] = beacon_block_root
/// field[3] = hash_tree_root(source) = sha256(le_pad32(epoch) || root)
/// field[4] = hash_tree_root(target) = sha256(le_pad32(epoch) || root)
/// field[5..7] = zero
/// ```
pub fn attestation_data_root(
    slot: u64,
    index: u64,
    beacon_block_root: &[u8; 32],
    source_epoch: u64,
    source_root: &[u8; 32],
    target_epoch: u64,
    target_root: &[u8; 32],
) -> [u8; 32] {
    let zero = [0u8; 32];

    let field0 = u64_to_chunk(slot);
    let field1 = u64_to_chunk(index);
    let field2 = *beacon_block_root;
    let field3 = checkpoint_leaf(source_epoch, source_root);
    let field4 = checkpoint_leaf(target_epoch, target_root);

    // Depth-3 tree with 8 leaves (5 data + 3 zero)
    let n0 = sha256_pair(&field0, &field1);
    let n1 = sha256_pair(&field2, &field3);
    let n2 = sha256_pair(&field4, &zero);
    let n3 = sha256_pair(&zero, &zero);

    let n4 = sha256_pair(&n0, &n1);
    let n5 = sha256_pair(&n2, &n3);

    sha256_pair(&n4, &n5)
}

/// `hash_tree_root(BeaconBlockHeader)` from its five fields.
///
/// Spec order is `slot, proposer_index, parent_root, state_root, body_root`
/// (phase0/beacon-chain.md:473), so `state_root` is field 3. Five fields
/// merkleize into an eight-leaf tree, three of them zero.
pub fn block_header_root(
    slot: u64,
    proposer_index: u64,
    parent_root: &[u8; 32],
    state_root: &[u8; 32],
    body_root: &[u8; 32],
) -> [u8; 32] {
    let zero = [0u8; 32];
    let n0 = sha256_pair(&u64_to_chunk(slot), &u64_to_chunk(proposer_index));
    let n1 = sha256_pair(parent_root, state_root);
    let n2 = sha256_pair(body_root, &zero);
    let n3 = sha256_pair(&zero, &zero);
    sha256_pair(&sha256_pair(&n0, &n1), &sha256_pair(&n2, &n3))
}

/// Slots of history a `BeaconState` keeps: `SLOTS_PER_HISTORICAL_ROOT`.
pub const SLOTS_PER_HISTORICAL_ROOT: u64 = 8192;

/// `BeaconState` field indices of the two ring buffers, spec field order
/// (phase0/beacon-chain.md).
const BLOCK_ROOTS_FIELD: u64 = 5;
const STATE_ROOTS_FIELD: u64 = 6;

/// Depth of a `Vector[Root, 8192]`, plus the six levels of the 64-leaf state
/// tree above it.
const HISTORY_PROOF_DEPTH: usize = 13 + 6;

/// Recompute the `BeaconState` root that holds `entry` for `slot` in one of the
/// two ring buffers.
///
/// Both are `Vector[Root, SLOTS_PER_HISTORICAL_ROOT]`, so an entry sits thirteen
/// levels under one leaf of the state's own 64-leaf tree, and the index through
/// the joined tree is the field's leaf index followed by the slot's place in the
/// ring.
fn state_root_from_history(
    field: u64,
    slot: u64,
    entry: &[u8; 32],
    siblings: &[[u8; 32]],
) -> [u8; 32] {
    assert_eq!(
        siblings.len(),
        HISTORY_PROOF_DEPTH,
        "history proof is not the depth of a BeaconState ring buffer",
    );
    compute_ssz_merkle_root(
        entry,
        field * SLOTS_PER_HISTORICAL_ROOT + slot % SLOTS_PER_HISTORICAL_ROOT,
        siblings,
    )
}

/// Open the finalized epoch's boundary out of the justified checkpoint's state.
///
/// The finalized checkpoint's own header cannot do this. A checkpoint root is
/// the last block at or *before* the epoch's first slot, so when that slot is
/// empty the state the accumulator was built from is not that block's
/// post-state — it is the state the empty slots advanced it to, and no header
/// carries it. The justified checkpoint is the one block after the boundary
/// that this proof already trusts, because 2/3 of the stake signed its root as
/// their target, and a state records every slot it has passed: `block_roots`
/// gives the checkpoint at the boundary and `state_roots` gives the state at the
/// end of it, both defined for a skipped slot.
///
/// Opening the checkpoint root as well as the state root is what keeps the pair
/// together. Without it the finalized root would come from one chain and the
/// state root from another, and the proof would name a state the finalized
/// block never produced.
pub fn open_boundary(
    anchor: &BoundaryAnchor,
    finalized_epoch: u64,
    finalized_root: &[u8; 32],
    justified_root: &[u8; 32],
    boundary_state_root: &[u8; 32],
    slots_per_epoch: u64,
) {
    let h = &anchor.justified_header;
    assert_eq!(
        block_header_root(
            h.slot,
            h.proposer_index,
            &h.parent_root,
            &h.state_root,
            &h.body_root,
        ),
        *justified_root,
        "justified header does not hash to the justified root",
    );

    // A state records slot `n` from `n + 1` on and keeps it for 8192 slots. Both
    // ends matter: below the first the entry has not been written, above the
    // second it has been overwritten by a slot 8192 later, and either way the
    // ring index would open something other than the boundary asked for. On a
    // real chain the justified checkpoint is at most one epoch past it.
    let boundary_slot = finalized_epoch * slots_per_epoch;
    assert!(
        h.slot > boundary_slot && h.slot - boundary_slot <= SLOTS_PER_HISTORICAL_ROOT,
        "the justified checkpoint's state does not record the boundary it is asked to open",
    );

    assert_eq!(
        state_root_from_history(
            BLOCK_ROOTS_FIELD,
            boundary_slot,
            finalized_root,
            &anchor.block_roots_siblings,
        ),
        h.state_root,
        "the finalized checkpoint is not the block at the boundary of the justified chain",
    );
    assert_eq!(
        state_root_from_history(
            STATE_ROOTS_FIELD,
            boundary_slot,
            boundary_state_root,
            &anchor.state_roots_siblings,
        ),
        h.state_root,
        "the finalized epoch's accumulator was built from a different state than the boundary",
    );
}

/// Pad a u64 value to a 32-byte LE SSZ chunk.
pub fn u64_to_chunk(val: u64) -> [u8; 32] {
    let mut chunk = [0u8; 32];
    chunk[..8].copy_from_slice(&val.to_le_bytes());
    chunk
}

/// Verify that the SSZ field leaves are consistent with the claimed `ValidatorData`.
///
/// Checks:
/// - `field_leaves[0]` = `sha256(pubkey_chunks[0] || pubkey_chunks[1])`
/// - `pubkey_chunks` encode the raw pubkey bytes
/// - `field_leaves[2]` encodes `effective_balance`
/// - `field_leaves[5]` encodes `activation_epoch`
/// - `field_leaves[6]` encodes `exit_epoch`
///
/// Leaves 1, 3, 4, 7 are opaque (withdrawal_credentials, slashed,
/// activation_eligibility_epoch, withdrawable_epoch).
///
/// For a cheaper variant that skips the pubkey SHA-256 hash (when pubkey is
/// known to match another already-verified set), use [`verify_field_leaves_no_pubkey_hash`].
pub fn verify_field_leaves(
    data: &ValidatorData,
    field_leaves: &[[u8; 32]; 8],
    pubkey_chunks: &[[u8; 32]; 2],
) {
    // pubkey: field_leaves[0] = sha256(chunk0 || chunk1)
    let computed_pubkey_leaf = sha256_pair(&pubkey_chunks[0], &pubkey_chunks[1]);
    assert_eq!(
        field_leaves[0], computed_pubkey_leaf,
        "pubkey leaf mismatch"
    );

    // pubkey raw bytes match the chunks
    assert_eq!(
        &pubkey_chunks[0][..32],
        &data.pubkey.0[..32],
        "pubkey chunk 0 mismatch"
    );
    assert_eq!(
        &pubkey_chunks[1][..16],
        &data.pubkey.0[32..48],
        "pubkey chunk 1 mismatch"
    );
    // remaining 16 bytes of chunk 1 must be zero
    assert_eq!(
        &pubkey_chunks[1][16..],
        &[0u8; 16],
        "pubkey chunk 1 padding not zero"
    );

    // effective_balance
    assert_eq!(
        field_leaves[2],
        u64_to_chunk(data.effective_balance),
        "effective_balance leaf mismatch"
    );

    // activation_epoch
    assert_eq!(
        field_leaves[5],
        u64_to_chunk(data.activation_epoch),
        "activation_epoch leaf mismatch"
    );

    // exit_epoch
    assert_eq!(
        field_leaves[6],
        u64_to_chunk(data.exit_epoch),
        "exit_epoch leaf mismatch"
    );
}

/// Like [`verify_field_leaves`] but skips the pubkey SHA-256 hash.
///
/// Use when the pubkey leaf has already been verified elsewhere (e.g. the
/// new validator's field_leaves were verified with [`verify_field_leaves`]
/// and we know old_field_leaves[0] == new_field_leaves[0] because pubkeys
/// don't change for existing validators).
pub fn verify_field_leaves_no_pubkey_hash(
    data: &ValidatorData,
    field_leaves: &[[u8; 32]; 8],
    pubkey_chunks: &[[u8; 32]; 2],
) {
    // pubkey raw bytes match the chunks (no SHA-256 needed)
    assert_eq!(
        &pubkey_chunks[0][..32],
        &data.pubkey.0[..32],
        "pubkey chunk 0 mismatch"
    );
    assert_eq!(
        &pubkey_chunks[1][..16],
        &data.pubkey.0[32..48],
        "pubkey chunk 1 mismatch"
    );
    assert_eq!(
        &pubkey_chunks[1][16..],
        &[0u8; 16],
        "pubkey chunk 1 padding not zero"
    );

    assert_eq!(
        field_leaves[2],
        u64_to_chunk(data.effective_balance),
        "effective_balance leaf mismatch"
    );
    assert_eq!(
        field_leaves[5],
        u64_to_chunk(data.activation_epoch),
        "activation_epoch leaf mismatch"
    );
    assert_eq!(
        field_leaves[6],
        u64_to_chunk(data.exit_epoch),
        "exit_epoch leaf mismatch"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{make_field_leaves, make_pubkey_chunks, make_validator};

    /// SSZ zero-hash at depth 1 — sha256 of 64 zero bytes. Pins the hand-rolled
    /// two-block compression against the real SHA-256.
    #[test]
    fn sha256_pair_known_answer() {
        let expected: [u8; 32] = [
            0xf5, 0xa5, 0xfd, 0x42, 0xd1, 0x6a, 0x20, 0x30, 0x27, 0x98, 0xef, 0x6e, 0xd3, 0x09,
            0x97, 0x9b, 0x43, 0x00, 0x3d, 0x23, 0x20, 0xd9, 0xf0, 0xe8, 0xea, 0x98, 0x31, 0xa9,
            0x27, 0x59, 0xfb, 0x4b,
        ];
        assert_eq!(sha256_pair(&[0u8; 32], &[0u8; 32]), expected);
    }

    /// Second SSZ zero-hash, chaining the first — catches a wrong IV reload.
    #[test]
    fn sha256_pair_chains_correctly() {
        let z1 = sha256_pair(&[0u8; 32], &[0u8; 32]);
        let expected: [u8; 32] = [
            0xdb, 0x56, 0x11, 0x4e, 0x00, 0xfd, 0xd4, 0xc1, 0xf8, 0x5c, 0x89, 0x2b, 0xf3, 0x5a,
            0xc9, 0xa8, 0x92, 0x89, 0xaa, 0xec, 0xb1, 0xeb, 0xd0, 0xa9, 0x6c, 0xde, 0x60, 0x6a,
            0x74, 0x8b, 0x5d, 0x71,
        ];
        assert_eq!(sha256_pair(&z1, &z1), expected);
    }

    #[test]
    fn test_sha256_pair() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        let result = sha256_pair(&a, &b);
        assert_ne!(result, [0u8; 32]);
    }

    #[test]
    fn test_sha256_pair_not_commutative() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(sha256_pair(&a, &b), sha256_pair(&b, &a));
    }

    #[test]
    fn test_list_hash_tree_root() {
        let data_root = [1u8; 32];
        let result = list_hash_tree_root(&data_root, 100);
        assert_ne!(result, data_root);
    }

    #[test]
    fn test_list_hash_tree_root_different_lengths() {
        let data_root = [1u8; 32];
        let a = list_hash_tree_root(&data_root, 100);
        let b = list_hash_tree_root(&data_root, 101);
        assert_ne!(a, b);
    }

    #[test]
    fn test_u64_to_chunk() {
        let chunk = u64_to_chunk(32_000_000_000);
        assert_eq!(
            u64::from_le_bytes(chunk[..8].try_into().unwrap()),
            32_000_000_000
        );
        assert_eq!(&chunk[8..], &[0u8; 24]);
    }

    #[test]
    fn test_validator_hash_tree_root_deterministic() {
        let v = make_validator(1, 32);
        let leaves = make_field_leaves(&v);
        let a = validator_hash_tree_root(&leaves);
        let b = validator_hash_tree_root(&leaves);
        assert_eq!(a, b);
    }

    #[test]
    fn test_validator_hash_tree_root_changes_with_balance() {
        let v1 = make_validator(1, 32);
        let v2 = make_validator(1, 16);
        let a = validator_hash_tree_root(&make_field_leaves(&v1));
        let b = validator_hash_tree_root(&make_field_leaves(&v2));
        assert_ne!(a, b);
    }

    #[test]
    fn test_verify_field_leaves_valid() {
        let v = make_validator(5, 32);
        let leaves = make_field_leaves(&v);
        let chunks = make_pubkey_chunks(&v);
        // Should not panic
        verify_field_leaves(&v, &leaves, &chunks);
    }

    #[test]
    #[should_panic(expected = "effective_balance leaf mismatch")]
    fn test_verify_field_leaves_wrong_balance() {
        let v = make_validator(5, 32);
        let mut leaves = make_field_leaves(&v);
        // Tamper with the balance leaf
        leaves[2] = u64_to_chunk(16_000_000_000);
        let chunks = make_pubkey_chunks(&v);
        verify_field_leaves(&v, &leaves, &chunks);
    }

    #[test]
    #[should_panic(expected = "pubkey leaf mismatch")]
    fn test_verify_field_leaves_wrong_pubkey() {
        let v = make_validator(5, 32);
        let leaves = make_field_leaves(&v);
        let mut chunks = make_pubkey_chunks(&v);
        // Tamper with pubkey chunk
        chunks[0][0] = 0xFF;
        verify_field_leaves(&v, &leaves, &chunks);
    }

    #[test]
    fn test_ssz_merkle_proof_roundtrip() {
        let v0 = make_validator(0, 32);
        let v1 = make_validator(1, 32);
        let v2 = make_validator(2, 32);
        let v3 = make_validator(3, 32);

        let roots: Vec<_> = [&v0, &v1, &v2, &v3]
            .iter()
            .map(|v| validator_hash_tree_root(&make_field_leaves(v)))
            .collect();

        let (tree_root, siblings) = crate::test_utils::build_ssz_tree(&roots, 2);

        for (i, root) in roots.iter().enumerate() {
            assert!(
                verify_ssz_merkle_proof(root, i as u64, &siblings[i], &tree_root),
                "proof failed for leaf {i}"
            );
        }
    }

    /// The digest that carries an FFG link through a proof's public outputs has
    /// to move when any of the four fields it stands for moves. It replaces the
    /// target root in `AggregateOutput`, so anything it left unbound would be a
    /// field a prover could choose.
    #[test]
    fn a_checkpoint_digest_binds_both_checkpoints() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let base = checkpoint_digest(100, &a, 101, &b);

        assert_ne!(base, checkpoint_digest(99, &a, 101, &b));
        assert_ne!(base, checkpoint_digest(100, &b, 101, &b));
        assert_ne!(base, checkpoint_digest(100, &a, 102, &b));
        assert_ne!(base, checkpoint_digest(100, &a, 101, &a));
        // Not symmetric: a link from A to B is not a link from B to A.
        assert_ne!(base, checkpoint_digest(101, &b, 100, &a));
        assert_eq!(base, checkpoint_digest(100, &a, 101, &b));
    }
}
