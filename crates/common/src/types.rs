use alloc::boxed::Box;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::acc::{Digest, G1Point};

/// Merkle multi-proof: the sibling nodes a leaf set does not itself determine.
///
/// Ordered bottom-up, and within a level in ascending parent order, left child
/// before right — the order [`crate::merkle::batch_root`] consumes them in.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MultiProof<T> {
    pub auxiliaries: Vec<T>,
}

/// Multi-proof over the SSZ (SHA-256) tree.
pub type SszMultiProof = MultiProof<[u8; 32]>;

/// Multi-proof over the accumulator (Poseidon2-Goldilocks) tree.
pub type AccMultiProof = MultiProof<Digest>;

/// 48-byte BLS public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsPubkey(#[serde(with = "BigArray")] pub [u8; 48]);

/// 96-byte BLS signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlsSignature(#[serde(with = "BigArray")] pub [u8; 96]);

/// Minimal validator data — only the fields needed for zkasper.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorData {
    pub pubkey: BlsPubkey,
    /// Effective balance in Gwei.
    pub effective_balance: u64,
    pub activation_epoch: u64,
    pub exit_epoch: u64,
}

impl ValidatorData {
    /// Whether this validator is active at the given epoch.
    pub fn is_active(&self, epoch: u64) -> bool {
        self.activation_epoch <= epoch && epoch < self.exit_epoch
    }

    /// Returns `effective_balance` if active, else 0.
    pub fn active_effective_balance(&self, epoch: u64) -> u64 {
        if self.is_active(epoch) {
            self.effective_balance
        } else {
            0
        }
    }
}

/// Casper FFG checkpoint (epoch + block root).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub epoch: u64,
    pub root: [u8; 32],
}

// ---------------------------------------------------------------------------
// Witness types
// ---------------------------------------------------------------------------

/// One changed validator between two consecutive epochs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorMutation {
    pub validator_index: u64,
    /// True if this validator is new (not present in the old state).
    /// When true, the old leaf in both SSZ and accumulator trees is all-zeros.
    pub is_new: bool,
    pub old_data: ValidatorData,
    pub new_data: ValidatorData,
    /// 8 field-level SSZ hash-tree leaves for the Validator container.
    pub old_field_leaves: [[u8; 32]; 8],
    pub new_field_leaves: [[u8; 32]; 8],
    /// Raw pubkey split into 2x32-byte SSZ chunks (to verify field_leaves[0]).
    pub old_pubkey_chunks: [[u8; 32]; 2],
    pub new_pubkey_chunks: [[u8; 32]; 2],
    /// Accumulator Merkle siblings (depth = ACC_TREE_DEPTH).
    pub acc_siblings: Vec<Digest>,
}

/// Public outputs of an epoch-diff proof.
///
/// Names *both* endpoints of the transition, not just the new one. A diff that
/// only published where it arrived cannot be checked against where it was
/// supposed to start, so anything consuming a chain of diffs — the finalization
/// circuit, or an on-chain contract holding the current commitment — has to take
/// the link on trust. Publishing `prev_accumulator_commitment` makes the link
/// part of the statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochDiffOutput {
    // -- where this proof started --
    /// Commitment the diff started from: `H(acc_root_1, total_active_balance_1)`.
    pub prev_accumulator_commitment: Digest,
    pub state_root_1: [u8; 32],
    pub epoch_1: u64,

    // -- where it ends --
    /// Commitment the diff produced.
    pub accumulator_commitment: Digest,
    pub acc_root: Digest,
    pub total_active_balance: u64,
    pub state_root_2: [u8; 32],
    pub epoch_2: u64,
}

/// Witness for Proof 1: Epoch Diff.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochDiffWitness {
    // -- public inputs (bound by on-chain state) --
    pub state_root_1: [u8; 32],
    pub state_root_2: [u8; 32],
    pub acc_root_1: Digest,
    pub total_active_balance_1: u64,
    /// Epoch of state_root_1 (used for old is_active checks).
    pub epoch_1: u64,
    /// Epoch of state_root_2 (used for new is_active checks).
    pub epoch_2: u64,

    // -- SSZ proof: state_root -> validators data tree root --
    pub state_to_validators_siblings_1: Vec<[u8; 32]>,
    pub state_to_validators_siblings_2: Vec<[u8; 32]>,
    pub validators_list_length_1: u64,
    pub validators_list_length_2: u64,

    // -- mutations --
    pub mutations: Vec<ValidatorMutation>,

    // -- SSZ multi-proofs for validator trees --
    pub ssz_multi_proof_1: SszMultiProof,
    pub ssz_multi_proof_2: SszMultiProof,
}

/// A validator named in a witness, with the leaf preimage that opens it against
/// the accumulator.
///
/// Used for both halves of a complement: the absentees a slot subtracts, and the
/// signers of any attestation whose keys are enumerated rather than derived.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenedValidator {
    pub validator_index: u64,
    /// Decompressed public key, matching what the accumulator leaf commits to.
    pub pubkey: G1Point,
    pub active_effective_balance: u64,
}

/// One aggregated attestation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationWitness {
    // -- Raw AttestationData fields (circuit recomputes hash_tree_root) --
    pub data_slot: u64,
    pub data_index: u64,
    pub data_beacon_block_root: [u8; 32],
    pub data_source_epoch: u64,
    pub data_source_root: [u8; 32],
    pub data_target_epoch: u64,
    pub data_target_root: [u8; 32],
    /// Aggregate BLS signature over the signing root.
    pub signature: BlsSignature,
    /// Signers whose keys are enumerated and opened.
    ///
    /// Empty for the one aggregate per slot whose key is derived by complement —
    /// not enumerating it is the whole point of the scheme.
    pub attesting_validators: Vec<OpenedValidator>,
}

// ---------------------------------------------------------------------------
// Committee proof
// ---------------------------------------------------------------------------

/// One slot's committee, summed: the universe its attesters are the complement
/// of.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeAggregate {
    /// Sum of the committee's public keys.
    pub pubkey: G1Point,
    /// Sum of the committee's `active_effective_balance`.
    pub balance: u64,
}

/// One validator's committee assignment, with the leaf preimage that opens it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub validator_index: u64,
    pub pubkey: G1Point,
    pub active_effective_balance: u64,
    /// Slot within the epoch this validator is assigned to attest at.
    ///
    /// Plain witness, deliberately: see the `committee` module docs for why a
    /// wrong assignment costs liveness and never soundness.
    pub slot_in_epoch: u64,
}

/// Witness for the committee proof: one per epoch, entirely off the critical
/// path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeWitness {
    // -- public inputs --
    pub accumulator_commitment: Digest,
    pub target_epoch: u64,

    // -- private witness --
    pub acc_root: Digest,
    pub total_active_balance: u64,
    /// Every committee member, strictly increasing by validator index.
    pub members: Vec<CommitteeMember>,
    pub acc_multi_proof: AccMultiProof,
}

/// Public outputs of a committee proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeOutput {
    pub accumulator_commitment: Digest,
    pub target_epoch: u64,
    /// Root of the tree of per-slot [`CommitteeAggregate`]s.
    ///
    /// Every proof that counts a slot carries this, so a pipeline can never mix
    /// buckets from two different partitions of the same validator set.
    pub committee_root: Digest,
}

/// One attestation slot, proven by complement.
///
/// The committee aggregate is the universe; `secondary` and `absentees` name
/// everyone who is not a signer of `primary`; `primary`'s aggregate public key
/// is what is left over, and is never enumerated.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlotComplementWitness {
    /// Slot within the epoch, and the index of this committee's leaf.
    pub slot_in_epoch: u64,
    pub committee: CommitteeAggregate,
    /// The aggregates whose signer set is derived: the committee minus
    /// everything named below.
    ///
    /// All of them carry the same `AttestationData` — a slot's attesters usually
    /// arrive as several aggregates over one message — so they pair once, as one
    /// derived key against one hashed message, with their signatures summed.
    /// Their `attesting_validators` must be empty.
    pub primary: Vec<AttestationWitness>,
    /// Aggregates over a different message than `primary` — a minority head vote
    /// — whose signers are named and opened.
    pub secondary: Vec<AttestationWitness>,
    /// Committee members this proof counts no attestation for.
    pub absentees: Vec<OpenedValidator>,
}

// ---------------------------------------------------------------------------
// Slot-level proving types
// ---------------------------------------------------------------------------

/// Public outputs of a slot proof.
///
/// After recursive verification, the justification circuit sees only these values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotProofOutput {
    pub accumulator_commitment: Digest,
    /// Committee tree the slots below were counted against.
    pub committee_root: Digest,
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    /// Sum over the slots proven here of `committee_balance − absentee balances`.
    pub attesting_balance: u64,
    /// Which slots of the epoch this proof counted, one bit each.
    ///
    /// This is the whole of cross-slot deduplication. A committee proof assigns
    /// every validator to exactly one slot, so counting a slot at most once
    /// counts a validator at most once — a 32-bit mask where the old design
    /// needed a committed set over a million indices.
    pub slots_mask: u64,
}

/// Witness for a slot proof: the complement of one or more attestation slots.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlotProofWitness {
    // -- public inputs --
    pub accumulator_commitment: Digest,
    pub committee_root: Digest,
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    pub signing_domain: [u8; 32],

    // -- private witness --
    pub acc_root: Digest,
    pub total_active_balance: u64,
    /// Attestation slots, strictly increasing by `slot_in_epoch`.
    pub slots: Vec<SlotComplementWitness>,
    /// Opening of every validator named across `slots`, absentees and enumerated
    /// signers together.
    pub acc_multi_proof: AccMultiProof,
    /// Opening of each slot's committee aggregate against `committee_root`.
    pub committee_multi_proof: AccMultiProof,
}

/// Public outputs of a justification proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JustificationOutput {
    pub accumulator_commitment: Digest,
    pub target_epoch: u64,
    pub target_root: [u8; 32],
}

/// Witness for a justification proof (aggregates slot proofs).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JustificationWitness {
    // -- public inputs --
    pub accumulator_commitment: Digest,
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    pub total_active_balance: u64,

    /// Accumulator root behind `accumulator_commitment`.
    ///
    /// Present so the guest can rehash the commitment. Without it
    /// `total_active_balance` is a free scalar and the two-thirds gate below
    /// divides by whatever the prover chose.
    pub acc_root: Digest,

    /// Verification key of the slot-proof program. Bound into the justification
    /// output so the on-chain verifier can pin which program the slot proofs
    /// came from.
    pub slot_program_vk: crate::recursion::ProgramVk,
    /// Verification key of the committee program.
    pub committee_program_vk: crate::recursion::ProgramVk,

    /// The committee proof every slot proof counted against.
    pub committee: CommitteeOutput,
    pub committee_proof: Vec<u64>,

    // -- slot proof outputs, verified recursively --
    pub slot_proof_outputs: Vec<SlotProofOutput>,
    /// Zisk proof words per slot (empty in native testing mode).
    pub slot_proofs: Vec<Vec<u64>>,
}

/// The five fields of a `BeaconBlockHeader`, enough to recompute its root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeaderFields {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
}

/// The finalized epoch's boundary, opened out of the justified checkpoint's
/// state.
///
/// A checkpoint root is the last block at or *before* the epoch's first slot,
/// so when that slot is empty the checkpoint is an earlier block and the
/// boundary state is not its post-state: the state advanced through the empty
/// slots after it. Reading the boundary off a block header therefore only works
/// when the boundary slot holds a block, which is where a proof that reads it
/// off one stops dead — roughly once every hundred epochs on mainnet.
///
/// A beacon state records both values for every slot it has passed:
/// `block_roots[n % 8192]` is the last block at or before slot `n`, and
/// `state_roots[n % 8192]` is the state at the end of it. Both are defined for
/// a skipped slot, where a header is not. The justified checkpoint is the one
/// block after the boundary that 2/3 of the stake signed for, so its state is
/// the only one after the boundary this proof already trusts, and it is what
/// the two openings are rooted in.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoundaryAnchor {
    /// Header of the justified checkpoint block, checked against the root its
    /// epoch was justified for.
    pub justified_header: BlockHeaderFields,
    /// Siblings opening `block_roots[boundary_slot % 8192]`, bottom-up.
    pub block_roots_siblings: Vec<[u8; 32]>,
    /// Siblings opening `state_roots[boundary_slot % 8192]`, bottom-up.
    pub state_roots_siblings: Vec<[u8; 32]>,
}

/// Public outputs of a finalization proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizationOutput {
    /// Accumulator epoch E was justified against.
    pub accumulator_commitment: Digest,
    /// Accumulator epoch E+1 was justified against, proven to be the one above
    /// advanced by exactly the epoch diff E -> E+1.
    pub next_accumulator_commitment: Digest,
    pub finalized_epoch: u64,
    pub finalized_root: [u8; 32],
    /// Beacon state root at the first slot of the finalized epoch.
    ///
    /// This anchors the accumulator to the canonical chain. `epoch-diff` proves
    /// a registry delta between two states but cannot prove the second is the
    /// real successor of the first, so the accumulator advances optimistically.
    /// A consumer must require that every state root the chain passed through is
    /// later named by a finalization proof — which an attacker cannot forge
    /// without 2/3 of the real validator set attesting to their fabricated
    /// state. A branched accumulator can therefore never be confirmed.
    ///
    /// The circuit checks this against the epoch diff's `state_root_1`, so it is
    /// the same beacon state the diff advancing *into* the finalized epoch
    /// published as its `state_root_2`. A consumer can compare the two values
    /// directly. It is opened from the justified checkpoint's `state_roots`
    /// rather than read off the finalized block's header, so an epoch whose
    /// first slot is empty names the state the accumulator actually used. See
    /// [`BoundaryAnchor`].
    pub finalized_state_root: [u8; 32],
}

/// Witness for a finalization proof (pairs two consecutive justifications).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalizationWitness {
    /// Verification key of the justification program.
    pub justification_program_vk: crate::recursion::ProgramVk,
    /// Verification key of the epoch-diff program.
    pub epoch_diff_program_vk: crate::recursion::ProgramVk,
    /// The finalized epoch's boundary, opened out of the justified checkpoint.
    pub boundary: BoundaryAnchor,
    /// Justification outputs for epochs E and E+1.
    pub justification_outputs: Vec<JustificationOutput>,
    /// Zisk proof words for each justification (empty in native testing mode).
    pub justification_proofs: Vec<Vec<u64>>,
    /// Output of the epoch diff that carries the accumulator from E to E+1.
    pub epoch_diff_output: EpochDiffOutput,
    /// Zisk proof words for the epoch diff (empty in native testing mode).
    pub epoch_diff_proof: Vec<u64>,
}

// ---------------------------------------------------------------------------
// Public output encoding
// ---------------------------------------------------------------------------

use crate::recursion::PublicWriter;

impl SlotProofOutput {
    /// Bytes this proof commits to, and that the justification proof checks the
    /// child proof against.
    pub fn public_bytes(&self) -> Vec<u8> {
        PublicWriter::new()
            .digest(&self.accumulator_commitment)
            .digest(&self.committee_root)
            .u64(self.target_epoch)
            .bytes32(&self.target_root)
            .u64(self.attesting_balance)
            .u64(self.slots_mask)
            .finish()
    }
}

impl CommitteeOutput {
    pub fn public_bytes(&self) -> Vec<u8> {
        PublicWriter::new()
            .digest(&self.accumulator_commitment)
            .u64(self.target_epoch)
            .digest(&self.committee_root)
            .finish()
    }
}

impl EpochDiffOutput {
    pub fn public_bytes(&self) -> Vec<u8> {
        PublicWriter::new()
            .digest(&self.prev_accumulator_commitment)
            .bytes32(&self.state_root_1)
            .u64(self.epoch_1)
            .digest(&self.accumulator_commitment)
            .digest(&self.acc_root)
            .u64(self.total_active_balance)
            .bytes32(&self.state_root_2)
            .u64(self.epoch_2)
            .finish()
    }
}

impl JustificationOutput {
    pub fn public_bytes(&self) -> Vec<u8> {
        PublicWriter::new()
            .digest(&self.accumulator_commitment)
            .u64(self.target_epoch)
            .bytes32(&self.target_root)
            .finish()
    }
}

impl FinalizationOutput {
    pub fn public_bytes(&self) -> Vec<u8> {
        PublicWriter::new()
            .digest(&self.accumulator_commitment)
            .digest(&self.next_accumulator_commitment)
            .u64(self.finalized_epoch)
            .bytes32(&self.finalized_root)
            .bytes32(&self.finalized_state_root)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Streaming proof types
// ---------------------------------------------------------------------------

/// A Miller-loop accumulator in transit.
///
/// 72 limbs is past what serde derives for arrays, and past what a proof can
/// commit publicly, so it travels as private witness bound by a digest.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MillerAccumulator(#[serde(with = "BigArray")] pub crate::bls::Fp12);

impl Default for MillerAccumulator {
    fn default() -> Self {
        Self(crate::bls::FP12_ONE)
    }
}

/// Public outputs of a group proof.
///
/// A group proof is a slot proof that covers one or more slots and stops short
/// of the final exponentiation. Everything except `miller_commitment` means what
/// it does in [`SlotProofOutput`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupProofOutput {
    pub accumulator_commitment: Digest,
    pub committee_root: Digest,
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    pub attesting_balance: u64,
    pub slots_mask: u64,
    /// [`crate::acc::commit_fp12`] of this group's Miller-loop accumulator. The
    /// signatures are *not* verified here — they are verified by whichever proof
    /// finally runs the exponentiation over the product of every group's
    /// accumulator.
    pub miller_commitment: Digest,
}

/// Public outputs of an aggregation proof: the running state of one epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateOutput {
    pub accumulator_commitment: Digest,
    /// Committee tree every folded group counted against.
    pub committee_root: Digest,
    /// Accumulator the *previous* epoch was justified against, taken from the
    /// epoch diff that links the two.
    ///
    /// Verified once, by the fold that opens the epoch, because the diff is
    /// known at the epoch boundary — long before the last attestation. Carrying
    /// it here is what keeps that recursive verification off the critical path;
    /// the final proof only compares it against the justification it is turning
    /// into a finalization.
    pub previous_accumulator_commitment: Digest,
    /// The beacon state the previous epoch's accumulator was built from, from
    /// the same diff. The final proof pins the finalized block's state root to
    /// it, which is what lets a consumer check the accumulator chain against the
    /// finalizations it sees.
    pub anchor_state_root: [u8; 32],
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    /// Attesting balance accumulated so far, already deduplicated.
    pub attesting_balance: u64,
    /// Which slots of the epoch have been counted, one bit each.
    pub slots_mask: u64,
    /// Commitment to the product of every folded group's Miller accumulator.
    pub miller_commitment: Digest,
}

/// Witness for an aggregation proof: extend a running aggregate with finished
/// group proofs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregateWitness {
    // -- public inputs --
    pub accumulator_commitment: Digest,
    pub target_epoch: u64,
    pub target_root: [u8; 32],

    /// Verification key of the group-proof program.
    pub group_program_vk: crate::recursion::ProgramVk,
    /// Verification key of this program, so an aggregate can extend an aggregate.
    pub aggregate_program_vk: crate::recursion::ProgramVk,
    /// Verification key of the epoch-diff program.
    pub epoch_diff_program_vk: crate::recursion::ProgramVk,
    /// Verification key of the committee program.
    pub committee_program_vk: crate::recursion::ProgramVk,

    /// The diff that carried the accumulator from the previous epoch to this
    /// one. Required when `previous` is absent — the fold that opens an epoch is
    /// the one that establishes the link — and ignored afterwards, since later
    /// folds inherit it.
    pub epoch_diff: Option<EpochDiffOutput>,
    pub epoch_diff_proof: Vec<u64>,

    /// The committee proof for this epoch, on the same terms as the diff: the
    /// fold that opens the epoch verifies it, everything after inherits the root
    /// it published.
    pub committee: Option<CommitteeOutput>,
    pub committee_proof: Vec<u64>,

    /// The aggregate being extended. `None` opens the epoch: the counted set is
    /// empty and the Miller accumulator is 1.
    pub previous: Option<AggregateOutput>,
    pub previous_proof: Vec<u64>,
    /// Miller accumulator behind `previous.miller_commitment`.
    pub previous_miller: MillerAccumulator,

    /// Groups being folded in, with their proofs and Miller accumulators.
    pub groups: Vec<GroupProofOutput>,
    pub group_proofs: Vec<Vec<u64>>,
    pub group_millers: Vec<MillerAccumulator>,
}

/// A justification of the previous epoch, whichever program proved it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PreviousJustification {
    /// Produced by `justification-guest`, which folds whole-epoch slot proofs.
    Batch(JustificationOutput),
    /// Produced by `stream-final-guest` — the previous epoch of this pipeline.
    Stream(Box<StreamFinalOutput>),
}

impl PreviousJustification {
    /// Accumulator the justification it carries was proven against.
    pub fn accumulator_commitment(&self) -> Digest {
        match self {
            Self::Batch(o) => o.accumulator_commitment,
            Self::Stream(o) => o.next_accumulator_commitment,
        }
    }

    pub fn target_epoch(&self) -> u64 {
        match self {
            Self::Batch(o) => o.target_epoch,
            Self::Stream(o) => o.justified_epoch,
        }
    }

    pub fn target_root(&self) -> [u8; 32] {
        match self {
            Self::Batch(o) => o.target_root,
            Self::Stream(o) => o.justified_root,
        }
    }

    pub fn public_bytes(&self) -> Vec<u8> {
        match self {
            Self::Batch(o) => o.public_bytes(),
            Self::Stream(o) => o.public_bytes(),
        }
    }
}

/// Public outputs of the final proof of an epoch.
///
/// Carries both what it justified and what that justification finalizes, so the
/// next epoch's final proof can consume this one directly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamFinalOutput {
    /// Accumulator the finalized epoch was justified against. Same meaning, and
    /// same position in the encoding, as [`FinalizationOutput`]'s.
    pub accumulator_commitment: Digest,
    /// Accumulator the justified epoch was proven against, linked to the one
    /// above by the epoch diff this pipeline verified while streaming.
    pub next_accumulator_commitment: Digest,
    pub finalized_epoch: u64,
    pub finalized_root: [u8; 32],
    /// Beacon state root of the finalized block, opened from its header. See
    /// [`FinalizationOutput::finalized_state_root`].
    pub finalized_state_root: [u8; 32],
    /// The checkpoint this proof justified, published so the next epoch's final
    /// proof can consume this one as its previous justification.
    pub justified_epoch: u64,
    pub justified_root: [u8; 32],
}

/// Witness for the final proof of an epoch.
///
/// This is the only proof on the critical path, so it holds everything that
/// cannot be known before the last attestation arrives and nothing that can.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamFinalWitness {
    // -- public inputs --
    pub accumulator_commitment: Digest,
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    pub signing_domain: [u8; 32],

    // -- private --
    pub acc_root: Digest,
    pub total_active_balance: u64,

    pub group_program_vk: crate::recursion::ProgramVk,
    pub aggregate_program_vk: crate::recursion::ProgramVk,
    pub previous_program_vk: crate::recursion::ProgramVk,
    pub epoch_diff_program_vk: crate::recursion::ProgramVk,
    pub committee_program_vk: crate::recursion::ProgramVk,

    /// The epoch diff linking the previous epoch's accumulator to this one's.
    /// Only needed when there is no aggregate to inherit it from.
    pub epoch_diff: Option<EpochDiffOutput>,
    pub epoch_diff_proof: Vec<u64>,

    /// The committee proof for this epoch, on the same terms as the diff.
    pub committee: Option<CommitteeOutput>,
    pub committee_proof: Vec<u64>,

    /// Running aggregate for this epoch. `None` means the whole epoch is being
    /// proven inline, which only makes sense for tiny chains and tests.
    pub aggregate: Option<AggregateOutput>,
    pub aggregate_proof: Vec<u64>,
    pub aggregate_miller: MillerAccumulator,

    /// Group proofs that finished too late to be folded into `aggregate`.
    pub groups: Vec<GroupProofOutput>,
    pub group_proofs: Vec<Vec<u64>>,
    pub group_millers: Vec<MillerAccumulator>,

    /// The marginal slot that carries the epoch over the threshold, proven here
    /// rather than in a group proof of its own. One proof stage saved is one
    /// per-proof floor and one recursion saved from the only latency that
    /// matters.
    pub tail: Vec<SlotComplementWitness>,
    pub tail_acc_multi_proof: AccMultiProof,
    pub tail_committee_multi_proof: AccMultiProof,

    /// The previous epoch's justification, which this proof turns into a
    /// finalization.
    pub previous_justification: PreviousJustification,
    pub previous_justification_proof: Vec<u64>,
    /// The finalized epoch's boundary, opened out of the justified checkpoint.
    pub boundary: BoundaryAnchor,
}

impl GroupProofOutput {
    pub fn public_bytes(&self) -> Vec<u8> {
        PublicWriter::new()
            .digest(&self.accumulator_commitment)
            .digest(&self.committee_root)
            .u64(self.target_epoch)
            .bytes32(&self.target_root)
            .u64(self.attesting_balance)
            .u64(self.slots_mask)
            .digest(&self.miller_commitment)
            .finish()
    }
}

impl AggregateOutput {
    pub fn public_bytes(&self) -> Vec<u8> {
        PublicWriter::new()
            .digest(&self.accumulator_commitment)
            .digest(&self.committee_root)
            .digest(&self.previous_accumulator_commitment)
            .bytes32(&self.anchor_state_root)
            .u64(self.target_epoch)
            .bytes32(&self.target_root)
            .u64(self.attesting_balance)
            .u64(self.slots_mask)
            .digest(&self.miller_commitment)
            .finish()
    }
}

impl StreamFinalOutput {
    pub fn public_bytes(&self) -> Vec<u8> {
        PublicWriter::new()
            .digest(&self.accumulator_commitment)
            .digest(&self.next_accumulator_commitment)
            .u64(self.finalized_epoch)
            .bytes32(&self.finalized_root)
            .bytes32(&self.finalized_state_root)
            .u64(self.justified_epoch)
            .bytes32(&self.justified_root)
            .finish()
    }
}
