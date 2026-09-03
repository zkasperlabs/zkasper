//! One `on_fast_confirmation` transition of the Fast Confirmation Rule, run
//! by the same `fast_confirmation` crate Lighthouse delegates to, over:
//!
//! - the node's fork-choice nodes (`ForkChoiceStore`),
//! - every validator's latest vote (`Votes`),
//! - the registries the rule reads, one per epoch it references,
//! - the rule's own state before the slot.
//!
//! Nothing here stands in for a loop of the rule. The store, votes and
//! assignments are the rule's own traits implemented over witness data, and
//! `run` calls `FastConfirmationRule::on_fast_confirmation` once.
//!
//! The big arrays (votes, the base registry) sit behind the bincode header as
//! 8-byte-aligned blobs and are read in place; only the small header is parsed.

use core::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use fast_confirmation::{
    BalanceSourceData, Checkpoint, CheckpointAndBalance, Epoch, FastConfirmationRule,
    ForkChoiceStore, Hash256, Outcome, Slot, SlotAssignments, SlotAssignmentsError,
    SlotsPerEpoch, VoteTracker, Votes,
};
use serde::{Deserialize, Serialize};

pub const SLOTS_PER_EPOCH: u64 = 32;
pub type Spec = SlotsPerEpoch<SLOTS_PER_EPOCH>;

const SHUFFLE_ROUND_COUNT: u8 = 90;
const TARGET_COMMITTEE_SIZE: u64 = 128;
const MAX_COMMITTEES_PER_SLOT: u64 = 64;
pub const NO_VOTE: u32 = u32::MAX;
pub const NO_SLOT: u32 = u32::MAX;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Cp {
    pub epoch: u64,
    pub root: [u8; 32],
}

impl Cp {
    pub fn to_core(self) -> Checkpoint {
        Checkpoint {
            epoch: Epoch::new(self.epoch),
            root: Hash256(self.root),
        }
    }
    pub fn from_core(c: Checkpoint) -> Self {
        Cp {
            epoch: c.epoch.as_u64(),
            root: c.root.0,
        }
    }
}

/// `FastConfirmationRule`'s fields, registries named by index into
/// `Header::registries`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RuleState {
    pub confirmed_root: [u8; 32],
    pub previous_epoch_observed_justified: Cp,
    pub previous_epoch_observed_justified_registry: u32,
    pub current_epoch_observed_justified: Cp,
    pub current_epoch_observed_justified_registry: u32,
    pub previous_epoch_greatest_unrealized_checkpoint: Cp,
    pub previous_slot_head: [u8; 32],
    pub current_slot_head: [u8; 32],
    pub head_balance_registry: u32,
    pub last_update_slot: Option<u64>,
}

/// One proto-array node.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BlockNode {
    pub root: [u8; 32],
    pub slot: u64,
    pub parent: Option<u32>,
    pub justified_checkpoint: Cp,
    pub unrealized_justified_checkpoint: Option<Cp>,
    pub optimistic_or_invalid: bool,
}

/// A registry as a diff against the base blobs (registry 0 has no diff).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegistryHeader {
    pub epoch: u64,
    pub total_active_balance: u64,
    pub balance_changes: Vec<(u32, u64)>,
    pub slashed_toggles: Vec<u32>,
}

/// The attester seed of an epoch and the registry whose active set it shuffles.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EpochSeed {
    pub epoch: u64,
    pub seed: [u8; 32],
    pub registry: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Header {
    pub slot: u64,
    pub head_root: [u8; 32],
    pub finalized_checkpoint: Cp,
    pub unrealized_justified_checkpoint: Cp,
    pub byzantine_threshold: u64,
    pub proposer_score_boost: u64,
    pub state: RuleState,
    pub blocks: Vec<BlockNode>,
    /// Vote roots naming blocks the store no longer holds; indexed after `blocks`.
    pub extra_roots: Vec<[u8; 32]>,
    pub registries: Vec<RegistryHeader>,
    pub n_validators: u32,
    pub equivocating_indices: Vec<u64>,
    pub head_balance_update: Option<u32>,
    pub checkpoint_balance_update: Option<u32>,
    pub epoch_seeds: Vec<EpochSeed>,
}

/// The header plus the blobs, borrowed from the input.
pub struct Witness<'a> {
    pub header: Header,
    /// Per validator: index into blocks ++ extra_roots, or `NO_VOTE`.
    pub vote_roots: &'a [u32],
    /// Per validator: the attestation slot of the vote.
    pub vote_slots: &'a [u32],
    /// Registry 0, per validator: effective balance, 0 when inactive.
    pub balances: &'a [u64],
    /// Registry 0, bitset of slashed flags.
    pub slashed: &'a [u8],
}

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// `[u64 header_len][bincode header][pad][roots u32][pad][slots u32][pad][balances u64][pad][slashed u8]`
pub fn encode(
    header: &Header,
    vote_roots: &[u32],
    vote_slots: &[u32],
    balances: &[u64],
    slashed: &[u8],
) -> Vec<u8> {
    let n = header.n_validators as usize;
    assert_eq!(vote_roots.len(), n);
    assert_eq!(vote_slots.len(), n);
    assert_eq!(balances.len(), n);
    assert_eq!(slashed.len(), n.div_ceil(8));
    let hdr = bincode::serialize(header).expect("serialize header");
    let mut out = Vec::with_capacity(8 + hdr.len() + 24 * n + 64);
    out.extend_from_slice(&(hdr.len() as u64).to_le_bytes());
    out.extend_from_slice(&hdr);
    out.resize(align8(out.len()), 0);
    for r in vote_roots {
        out.extend_from_slice(&r.to_le_bytes());
    }
    out.resize(align8(out.len()), 0);
    for s in vote_slots {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out.resize(align8(out.len()), 0);
    for b in balances {
        out.extend_from_slice(&b.to_le_bytes());
    }
    out.resize(align8(out.len()), 0);
    out.extend_from_slice(slashed);
    out.resize(align8(out.len()), 0);
    out
}

impl<'a> Witness<'a> {
    pub fn decode(words: &'a [u64]) -> Result<Self, String> {
        let bytes: &[u8] = unsafe { words.align_to::<u8>().1 };
        let hdr_len = words.first().copied().ok_or("empty input")? as usize;
        let hdr = bytes.get(8..8 + hdr_len).ok_or("short header")?;
        let header: Header = bincode::deserialize(hdr).map_err(|e| e.to_string())?;
        let n = header.n_validators as usize;
        let mut off = align8(8 + hdr_len);
        let take = |off: &mut usize, len: usize| -> Result<&'a [u8], String> {
            let s = bytes.get(*off..*off + len).ok_or("short blob")?;
            *off = align8(*off + len);
            Ok(s)
        };
        let roots = take(&mut off, 4 * n)?;
        let slots = take(&mut off, 4 * n)?;
        let balances = take(&mut off, 8 * n)?;
        let slashed = take(&mut off, n.div_ceil(8))?;
        let (p, vote_roots, _) = unsafe { roots.align_to::<u32>() };
        let (q, vote_slots, _) = unsafe { slots.align_to::<u32>() };
        let (r, balances, _) = unsafe { balances.align_to::<u64>() };
        if !(p.is_empty() && q.is_empty() && r.is_empty()) {
            return Err("unaligned blob".into());
        }
        Ok(Witness {
            header,
            vote_roots,
            vote_slots,
            balances,
            slashed,
        })
    }

    fn slashed_bit(&self, i: usize) -> bool {
        (self.slashed[i / 8] >> (i % 8)) & 1 == 1
    }

    /// Materialize registry `idx`: the base blobs with the diff applied.
    pub fn registry(&self, idx: u32) -> BalanceSourceData {
        let r = &self.header.registries[idx as usize];
        let n = self.header.n_validators as usize;
        let mut effective_balances = self.balances.to_vec();
        let mut slashed: Vec<bool> = (0..n).map(|i| self.slashed_bit(i)).collect();
        for &(i, b) in &r.balance_changes {
            effective_balances[i as usize] = b;
        }
        for &i in &r.slashed_toggles {
            slashed[i as usize] = !slashed[i as usize];
        }
        BalanceSourceData {
            epoch: Epoch::new(r.epoch),
            total_active_balance: r.total_active_balance,
            effective_balances,
            slashed,
        }
    }

    /// Active validator indices of registry `idx`, in index order.
    fn active_indices(&self, idx: u32) -> Vec<u32> {
        let r = &self.header.registries[idx as usize];
        let changed: BTreeMap<u32, u64> = r.balance_changes.iter().copied().collect();
        (0..self.header.n_validators)
            .filter(|&i| {
                changed
                    .get(&i)
                    .copied()
                    .unwrap_or(self.balances[i as usize])
                    > 0
            })
            .collect()
    }

    pub fn registry_by_epoch(&self, epoch: u64) -> Option<u32> {
        self.header
            .registries
            .iter()
            .position(|r| r.epoch == epoch)
            .map(|i| i as u32)
    }
}

// ---------------------------------------------------------------- store

pub struct Store<'a> {
    nodes: &'a [BlockNode],
    index: BTreeMap<[u8; 32], u32>,
}

impl<'a> Store<'a> {
    pub fn new(nodes: &'a [BlockNode]) -> Self {
        let index = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.root, i as u32))
            .collect();
        Store { nodes, index }
    }

    #[inline(always)]
    fn node(&self, root: Hash256) -> Option<&BlockNode> {
        self.index.get(&root.0).map(|&i| &self.nodes[i as usize])
    }

    #[inline(always)]
    fn parent_of(&self, n: &BlockNode) -> Option<Hash256> {
        n.parent.map(|p| Hash256(self.nodes[p as usize].root))
    }
}

impl ForkChoiceStore for Store<'_> {
    fn block_slot(&self, root: Hash256) -> Option<Slot> {
        Some(Slot::new(self.node(root)?.slot))
    }
    fn parent_root(&self, root: Hash256) -> Option<Hash256> {
        self.parent_of(self.node(root)?)
    }
    fn slot_and_parent(&self, root: Hash256) -> Option<(Slot, Option<Hash256>)> {
        let n = self.node(root)?;
        Some((Slot::new(n.slot), self.parent_of(n)))
    }
    fn justified_checkpoint(&self, root: Hash256) -> Option<Checkpoint> {
        Some(self.node(root)?.justified_checkpoint.to_core())
    }
    fn unrealized_justified_checkpoint(&self, root: Hash256) -> Option<Checkpoint> {
        self.node(root)?.unrealized_justified_checkpoint.map(Cp::to_core)
    }
    fn is_optimistic_or_invalid(&self, root: Hash256) -> Option<bool> {
        Some(self.node(root)?.optimistic_or_invalid)
    }
}

// ---------------------------------------------------------------- votes

static ZERO_ROOT: [u8; 32] = [0; 32];

pub struct VoteView<'a> {
    roots: &'a [u32],
    slots: &'a [u32],
    table: &'a [[u8; 32]],
}

impl VoteView<'_> {
    #[inline(always)]
    fn root_of(&self, r: u32) -> &[u8; 32] {
        if r == NO_VOTE {
            &ZERO_ROOT
        } else {
            &self.table[r as usize]
        }
    }
}

impl Votes for VoteView<'_> {
    fn len(&self) -> usize {
        self.roots.len()
    }
    fn get(&self, index: usize) -> Option<VoteTracker> {
        (index < self.roots.len()).then(|| VoteTracker {
            current_root: Hash256(*self.root_of(self.roots[index])),
            current_slot: Slot::new(self.slots[index] as u64),
        })
    }
    #[inline(always)]
    fn root(&self, index: usize) -> Option<&[u8; 32]> {
        self.roots.get(index).map(|&r| self.root_of(r))
    }
    fn roots(&self) -> impl Iterator<Item = &[u8; 32]> + '_ {
        self.roots.iter().map(move |&r| self.root_of(r))
    }
}

// ---------------------------------------------------------------- assignments

/// `types::SlotAssignments`, derived on demand: the first question about an
/// epoch shuffles that epoch's active set with its seed, exactly as
/// `compute_committee` does, and tabulates every validator's attestation slot.
pub struct LazyAssignments<'a> {
    witness: &'a Witness<'a>,
    tables: RefCell<BTreeMap<u64, Vec<u32>>>,
}

impl<'a> LazyAssignments<'a> {
    pub fn new(witness: &'a Witness<'a>) -> Self {
        LazyAssignments {
            witness,
            tables: RefCell::new(BTreeMap::new()),
        }
    }

    fn ensure_table(&self, epoch: u64) -> Result<(), SlotAssignmentsError> {
        if self.tables.borrow().contains_key(&epoch) {
            return Ok(());
        }
        let seed = self
            .witness
            .header
            .epoch_seeds
            .iter()
            .find(|s| s.epoch == epoch)
            .ok_or(SlotAssignmentsError)?;
        let table = assignment_table(
            self.witness.active_indices(seed.registry),
            &seed.seed,
            epoch,
            self.witness.header.n_validators as usize,
        );
        self.tables.borrow_mut().insert(epoch, table);
        Ok(())
    }

    /// Every validator's attestation slot in `epoch` (`NO_SLOT` when inactive).
    pub fn table(&self, epoch: u64) -> Result<Vec<u32>, SlotAssignmentsError> {
        self.ensure_table(epoch)?;
        Ok(self.tables.borrow()[&epoch].clone())
    }
}

impl SlotAssignments for LazyAssignments<'_> {
    fn is_in_range(
        &self,
        validator_index: usize,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<bool, SlotAssignmentsError> {
        let (start, end) = (start_slot.as_u64(), end_slot.as_u64());
        for epoch in start / SLOTS_PER_EPOCH..=end / SLOTS_PER_EPOCH {
            self.ensure_table(epoch)?;
            let tables = self.tables.borrow();
            let s = *tables[&epoch]
                .get(validator_index)
                .ok_or(SlotAssignmentsError)?;
            if s != NO_SLOT && (s as u64) >= start && (s as u64) <= end {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// The spec's committee layout for one epoch: shuffle the active set, cut it
/// into `committees_per_slot * SLOTS_PER_EPOCH` consecutive committees.
pub fn assignment_table(active: Vec<u32>, seed: &[u8; 32], epoch: u64, n: usize) -> Vec<u32> {
    let len = active.len() as u64;
    let committees_per_slot = (len / SLOTS_PER_EPOCH / TARGET_COMMITTEE_SIZE)
        .clamp(1, MAX_COMMITTEES_PER_SLOT);
    let count = committees_per_slot * SLOTS_PER_EPOCH;
    let shuffled = shuffle_list(active, SHUFFLE_ROUND_COUNT, seed, false);
    let mut table = vec![NO_SLOT; n];
    let epoch_start = epoch * SLOTS_PER_EPOCH;
    for c in 0..count {
        let start = (len * c / count) as usize;
        let end = (len * (c + 1) / count) as usize;
        let slot = (epoch_start + c / committees_per_slot) as u32;
        for &v in &shuffled[start..end] {
            table[v as usize] = slot;
        }
    }
    table
}

/// Lighthouse's `shuffle_list`: the swap-or-not shuffle over a whole list.
/// With `forwards == false` the result at `i` is `input[compute_shuffled_index(i)]`,
/// the order `compute_committee` reads.
pub fn shuffle_list(mut input: Vec<u32>, rounds: u8, seed: &[u8; 32], forwards: bool) -> Vec<u32> {
    let list_size = input.len();
    if list_size == 0 {
        return input;
    }
    let mut buf = [0u8; 37];
    buf[..32].copy_from_slice(seed);
    let mut r = if forwards { 0 } else { rounds - 1 };
    loop {
        buf[32] = r;
        let pivot = (u64::from_le_bytes(sha256(&buf[..33])[..8].try_into().unwrap())
            % list_size as u64) as usize;

        let mirror = (pivot + 1) >> 1;
        buf[33..37].copy_from_slice(&((pivot >> 8) as u32).to_le_bytes());
        let mut source = sha256(&buf);
        let mut byte_v = source[(pivot & 0xff) >> 3];
        for i in 0..mirror {
            let j = pivot - i;
            if j & 0xff == 0xff {
                buf[33..37].copy_from_slice(&((j >> 8) as u32).to_le_bytes());
                source = sha256(&buf);
            }
            if j & 0x07 == 0x07 {
                byte_v = source[(j & 0xff) >> 3];
            }
            if (byte_v >> (j & 0x07)) & 1 == 1 {
                input.swap(i, j);
            }
        }

        let mirror = (pivot + list_size + 1) >> 1;
        let end = list_size - 1;
        buf[33..37].copy_from_slice(&((end >> 8) as u32).to_le_bytes());
        let mut source = sha256(&buf);
        let mut byte_v = source[(end & 0xff) >> 3];
        for (loop_iter, i) in ((pivot + 1)..mirror).enumerate() {
            let j = end - loop_iter;
            if j & 0xff == 0xff {
                buf[33..37].copy_from_slice(&((j >> 8) as u32).to_le_bytes());
                source = sha256(&buf);
            }
            if j & 0x07 == 0x07 {
                byte_v = source[(j & 0xff) >> 3];
            }
            if (byte_v >> (j & 0x07)) & 1 == 1 {
                input.swap(i, j);
            }
        }

        if forwards {
            r += 1;
            if r == rounds {
                break;
            }
        } else {
            if r == 0 {
                break;
            }
            r -= 1;
        }
    }
    input
}

// ---------------------------------------------------------------- hashing

pub fn sha256(data: &[u8]) -> [u8; 32] {
    #[cfg(target_os = "zkvm")]
    {
        sha256_syscall(data)
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        use sha2::Digest;
        sha2::Sha256::digest(data).into()
    }
}

#[cfg(target_os = "zkvm")]
fn sha256_syscall(data: &[u8]) -> [u8; 32] {
    use ziskos::syscalls::{syscall_sha256_f, SyscallSha256Params};
    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut state = [
        IV[0] as u64 | (IV[1] as u64) << 32,
        IV[2] as u64 | (IV[3] as u64) << 32,
        IV[4] as u64 | (IV[5] as u64) << 32,
        IV[6] as u64 | (IV[7] as u64) << 32,
    ];
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        let mut block = [0u64; 8];
        for (i, w) in block.iter_mut().enumerate() {
            *w = u64::from_le_bytes(chunk[8 * i..8 * i + 8].try_into().unwrap());
        }
        syscall_sha256_f(&mut SyscallSha256Params {
            state: &mut state,
            input: &block,
        });
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[8 * i..8 * i + 4].copy_from_slice(&(state[i] as u32).to_be_bytes());
        out[8 * i + 4..8 * i + 8].copy_from_slice(&((state[i] >> 32) as u32).to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------- run

#[derive(Debug, Clone)]
pub struct RuleOutput {
    pub slot: u64,
    pub head_root: [u8; 32],
    pub confirmed_root_before: [u8; 32],
    pub confirmed_root_after: [u8; 32],
    pub outcome: OutcomeBits,
    pub pre_state: RuleState,
    pub post_state: RuleState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutcomeBits {
    pub advanced: bool,
    pub restarted_from_justified: bool,
    pub reverted_to_finalized: bool,
    pub unconfirmed_support: Option<(u64, u64)>,
}

impl OutcomeBits {
    fn from_outcome(o: &Outcome) -> Self {
        OutcomeBits {
            advanced: o.advanced,
            restarted_from_justified: o.restarted_from_justified,
            reverted_to_finalized: o.reverted_to_finalized.is_some(),
            unconfirmed_support: o.unconfirmed_support,
        }
    }
    fn flags(&self) -> u64 {
        self.advanced as u64
            | (self.restarted_from_justified as u64) << 1
            | (self.reverted_to_finalized as u64) << 2
    }
}

pub fn state_digest(state: &RuleState) -> [u8; 32] {
    sha256(&bincode::serialize(state).expect("serialize state"))
}

impl RuleOutput {
    /// `slot ‖ head_root ‖ H(pre_state) ‖ H(post_state) ‖ confirmed_root ‖ flags`
    pub fn public_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(144);
        out.extend_from_slice(&self.slot.to_le_bytes());
        out.extend_from_slice(&self.head_root);
        out.extend_from_slice(&state_digest(&self.pre_state));
        out.extend_from_slice(&state_digest(&self.post_state));
        out.extend_from_slice(&self.confirmed_root_after);
        out.extend_from_slice(&self.outcome.flags().to_le_bytes());
        out
    }
}

/// Rebuild the rule from `header.state`, call `on_fast_confirmation` for
/// `header.slot`, and report the state it leaves behind.
pub fn run(w: &Witness<'_>) -> RuleOutput {
    let h = &w.header;
    let st = &h.state;

    let store = Store::new(&h.blocks);
    let table: Vec<[u8; 32]> = h
        .blocks
        .iter()
        .map(|b| b.root)
        .chain(h.extra_roots.iter().copied())
        .collect();
    let votes = VoteView {
        roots: w.vote_roots,
        slots: w.vote_slots,
        table: &table,
    };
    let equivocating: BTreeSet<u64> = h.equivocating_indices.iter().copied().collect();

    let mut rule = FastConfirmationRule::from_parts(
        Hash256(st.confirmed_root),
        CheckpointAndBalance::new(
            st.previous_epoch_observed_justified.to_core(),
            w.registry(st.previous_epoch_observed_justified_registry),
        ),
        CheckpointAndBalance::new(
            st.current_epoch_observed_justified.to_core(),
            w.registry(st.current_epoch_observed_justified_registry),
        ),
        st.previous_epoch_greatest_unrealized_checkpoint.to_core(),
        Hash256(st.previous_slot_head),
        Hash256(st.current_slot_head),
        h.byzantine_threshold,
        h.proposer_score_boost,
        LazyAssignments::new(w),
        w.registry(st.head_balance_registry),
        st.last_update_slot.map(Slot::new),
    );

    let outcome = rule
        .on_fast_confirmation::<Spec, _>(
            Hash256(h.head_root),
            &h.finalized_checkpoint.to_core(),
            &h.unrealized_justified_checkpoint.to_core(),
            Slot::new(h.slot),
            &store,
            &votes,
            &equivocating,
            h.head_balance_update.map(|i| w.registry(i)),
            LazyAssignments::new(w),
            h.checkpoint_balance_update.map(|i| w.registry(i)),
        )
        .unwrap_or_else(|e| panic!("on_fast_confirmation: {e:?}"));

    let reg = |epoch: Epoch| {
        w.registry_by_epoch(epoch.as_u64())
            .unwrap_or_else(|| panic!("no registry for epoch {}", epoch.as_u64()))
    };
    let post_state = RuleState {
        confirmed_root: rule.confirmed_root.0,
        previous_epoch_observed_justified: Cp::from_core(
            rule.previous_epoch_observed_justified.checkpoint(),
        ),
        previous_epoch_observed_justified_registry: reg(
            rule.previous_epoch_observed_justified.balances().epoch,
        ),
        current_epoch_observed_justified: Cp::from_core(
            rule.current_epoch_observed_justified.checkpoint(),
        ),
        current_epoch_observed_justified_registry: reg(
            rule.current_epoch_observed_justified.balances().epoch,
        ),
        previous_epoch_greatest_unrealized_checkpoint: Cp::from_core(
            rule.previous_epoch_greatest_unrealized_checkpoint,
        ),
        previous_slot_head: rule.previous_slot_head.0,
        current_slot_head: rule.current_slot_head.0,
        head_balance_registry: reg(rule.head_balance_source().epoch),
        last_update_slot: rule.last_update_slot().map(|s| s.as_u64()),
    };

    RuleOutput {
        slot: h.slot,
        head_root: h.head_root,
        confirmed_root_before: st.confirmed_root,
        confirmed_root_after: rule.confirmed_root.0,
        outcome: OutcomeBits::from_outcome(&outcome),
        pre_state: st.clone(),
        post_state,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spec's `compute_shuffled_index`.
    fn spec_shuffled_index(mut index: u64, count: u64, seed: &[u8; 32]) -> u64 {
        for round in 0..SHUFFLE_ROUND_COUNT {
            let mut b = Vec::with_capacity(37);
            b.extend_from_slice(seed);
            b.push(round);
            let pivot = u64::from_le_bytes(sha256(&b)[..8].try_into().unwrap()) % count;
            let flip = (pivot + count - index) % count;
            let position = index.max(flip);
            b.extend_from_slice(&((position / 256) as u32).to_le_bytes());
            let source = sha256(&b);
            let byte = source[((position % 256) / 8) as usize];
            if (byte >> (position % 8)) & 1 == 1 {
                index = flip;
            }
        }
        index
    }

    #[test]
    fn shuffle_list_matches_spec_index() {
        for (n, s) in [(1u32, 1u8), (2, 2), (7, 3), (100, 4), (1000, 5), (4097, 6)] {
            let seed = [s; 32];
            let input: Vec<u32> = (0..n).map(|i| i * 3 + 1).collect();
            let out = shuffle_list(input.clone(), SHUFFLE_ROUND_COUNT, &seed, false);
            for i in 0..n as u64 {
                let expect = input[spec_shuffled_index(i, n as u64, &seed) as usize];
                assert_eq!(out[i as usize], expect, "n={n} i={i}");
            }
        }
    }

    #[test]
    fn assignment_table_covers_every_active_validator_once() {
        let active: Vec<u32> = (0..5000).filter(|i| i % 3 != 0).collect();
        let table = assignment_table(active.clone(), &[9; 32], 7, 5000);
        let mut per_slot = [0u32; 32];
        for (v, &s) in table.iter().enumerate() {
            if active.contains(&(v as u32)) {
                assert!((7 * 32..8 * 32).contains(&(s as u64)), "v={v} slot={s}");
                per_slot[(s as u64 - 7 * 32) as usize] += 1;
            } else {
                assert_eq!(s, NO_SLOT);
            }
        }
        assert!(per_slot.iter().all(|&c| c > 0));
    }
}
