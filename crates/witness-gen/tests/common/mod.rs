// Shared test helpers; each test binary uses a different subset.
#![allow(dead_code)]

//! MockBeaconApi and test helpers for witness-gen integration tests.

pub mod mock_node;
pub mod stub_api;

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use anyhow::Result;

use zkasper_common::acc;
use zkasper_common::bls::{compute_domain, compute_signing_root, DOMAIN_BEACON_ATTESTER};
use zkasper_common::constants::FAR_FUTURE_EPOCH;
use zkasper_common::ssz::attestation_data_root;
use zkasper_common::types::{
    Checkpoint, EpochDiffOutput, JustificationOutput, PreviousJustification, ValidatorData,
};
use zkasper_common::ChainConfig;

use zkasper_witness_gen::artifacts::hex0x;
use zkasper_witness_gen::attestation_collector::SlotComplement;
use zkasper_witness_gen::beacon_api::{
    AttestationResponse, BeaconApi, ChainStatusApi, CommitteeResponse, FinalityCheckpoints,
    HeaderResponse, ValidatorResponse,
};
use zkasper_witness_gen::fixture::Epoch;
use zkasper_witness_gen::gossip::AttestationSource;
use zkasper_witness_gen::state_diff::SlotHistory;
use zkasper_witness_gen::streaming::StreamContext;

/// A mock beacon API that returns synthetic data for testing.
pub struct MockBeaconApi {
    /// Validators per slot: slot -> validators
    pub validators: HashMap<String, Vec<ValidatorResponse>>,
    /// Headers per slot
    pub headers: HashMap<String, HeaderResponse>,
    /// Attestations per block
    pub attestations: HashMap<String, Vec<AttestationResponse>>,
    /// Committees per (state_id, epoch)
    pub committees: HashMap<(String, u64), Vec<CommitteeResponse>>,
    /// Block roots per block_id. A slot missing from here reads as skipped.
    pub block_roots: HashMap<String, [u8; 32]>,
    /// Finality checkpoints per state_id
    pub finality: HashMap<String, FinalityCheckpoints>,
    pub genesis_validators_root: [u8; 32],
    pub fork_version: [u8; 4],
    /// Slots whose state this node will not serve, as a checkpoint-synced node
    /// stops serving what its split slot has moved past.
    pub unservable_states: HashSet<u64>,
    /// Every block_id `get_block_attestations` was called with, in order.
    ///
    /// Continuous mode is supposed to stop fetching blocks the moment the 2/3
    /// threshold is crossed, which is only observable by what it asked for.
    pub attestation_requests: Mutex<Vec<String>>,
    /// Head header, when a test moves it between ticks. Takes precedence over
    /// `headers["head"]`.
    pub head: Mutex<Option<HeaderResponse>>,
    /// Block root every `block_id` resolves to, when a test reorgs the chain
    /// under a daemon that is already collecting against the old one.
    pub reorged_to: Mutex<Option<[u8; 32]>>,
}

impl MockBeaconApi {
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            headers: HashMap::new(),
            attestations: HashMap::new(),
            committees: HashMap::new(),
            block_roots: HashMap::new(),
            finality: HashMap::new(),
            genesis_validators_root: [0xAA; 32],
            fork_version: [0x04, 0x00, 0x00, 0x00],
            unservable_states: HashSet::new(),
            attestation_requests: Mutex::new(Vec::new()),
            head: Mutex::new(None),
            reorged_to: Mutex::new(None),
        }
    }

    /// Block ids `get_block_attestations` was called with.
    pub fn requested_blocks(&self) -> Vec<String> {
        self.attestation_requests.lock().unwrap().clone()
    }

    /// Move the head, the way a node does between polls.
    ///
    /// Streaming only exists across ticks, and what changes between them is how
    /// much of the epoch the node has published, so a test that never moves the
    /// head is testing catch-up rather than streaming.
    pub fn set_head(&self, header: HeaderResponse) {
        *self.head.lock().unwrap() = Some(header);
    }

    /// Reorg every checkpoint onto `root`, or back onto the real chain.
    pub fn set_reorg(&self, root: Option<[u8; 32]>) {
        *self.reorged_to.lock().unwrap() = root;
    }

    /// Report the same finality checkpoints for every state id.
    pub fn set_finality(&mut self, finalized_epoch: u64, root: [u8; 32]) {
        let checkpoint = Checkpoint {
            epoch: finalized_epoch,
            root,
        };
        self.finality.insert(
            "head".to_string(),
            FinalityCheckpoints {
                previous_justified: checkpoint.clone(),
                current_justified: checkpoint.clone(),
                finalized: checkpoint,
            },
        );
    }
}

#[async_trait::async_trait]
impl ChainStatusApi for MockBeaconApi {
    async fn get_block_root(&self, block_id: &str) -> Result<Option<[u8; 32]>> {
        match *self.reorged_to.lock().unwrap() {
            Some(root) => Ok(Some(root)),
            None => Ok(self.block_roots.get(block_id).copied()),
        }
    }

    async fn get_genesis_validators_root(&self) -> Result<[u8; 32]> {
        Ok(self.genesis_validators_root)
    }

    async fn get_fork_version(&self, _state_id: &str) -> Result<[u8; 4]> {
        Ok(self.fork_version)
    }

    async fn get_finality_checkpoints(&self, state_id: &str) -> Result<FinalityCheckpoints> {
        self.finality
            .get(state_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no finality checkpoints for state_id={state_id}"))
    }
}

#[async_trait::async_trait]
impl BeaconApi for MockBeaconApi {
    async fn get_validators(&self, state_id: &str) -> Result<Vec<ValidatorResponse>> {
        // Word for word what a beacon node says, because that is the string the
        // daemon matches to tell a pruned state from a real fault.
        if let Ok(slot) = state_id.parse::<u64>() {
            anyhow::ensure!(
                !self.unservable_states.contains(&slot),
                "404 Not Found: NOT_FOUND: beacon state at slot {slot}",
            );
        }
        self.validators
            .get(state_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no validators for state_id={state_id}"))
    }

    async fn get_block_attestations(&self, block_id: &str) -> Result<Vec<AttestationResponse>> {
        self.attestation_requests
            .lock()
            .unwrap()
            .push(block_id.to_string());
        self.attestations
            .get(block_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no attestations for block_id={block_id}"))
    }

    async fn get_committees(&self, state_id: &str, epoch: u64) -> Result<Vec<CommitteeResponse>> {
        self.committees
            .get(&(state_id.to_string(), epoch))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no committees for state_id={state_id}, epoch={epoch}"))
    }

    async fn get_header(&self, block_id: &str) -> Result<HeaderResponse> {
        if block_id == "head" {
            if let Some(header) = self.head.lock().unwrap().clone() {
                return Ok(header);
            }
        }
        self.headers
            .get(block_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no header for block_id={block_id}"))
    }

    async fn get_state_ssz(&self, _state_id: &str) -> Result<Option<Vec<u8>>> {
        // Mock API doesn't have raw SSZ state — triggers synthetic state proof fallback
        Ok(None)
    }

    async fn get_state_root(&self, _state_id: &str) -> Result<Option<[u8; 32]>> {
        // No independent state root here; the caller reads the header instead.
        Ok(None)
    }
}

/// Convert a ValidatorData (test_utils format) to a ValidatorResponse (API format).
pub fn validator_data_to_response(data: &ValidatorData, index: u64) -> ValidatorResponse {
    ValidatorResponse {
        index,
        pubkey: data.pubkey.0,
        effective_balance: data.effective_balance,
        activation_epoch: data.activation_epoch,
        exit_epoch: data.exit_epoch,
        withdrawal_credentials: {
            let mut wc = [0u8; 32];
            wc[0] = 0x01; // ETH1 withdrawal prefix
            wc
        },
        slashed: false,
        activation_eligibility_epoch: 0,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    }
}

/// Build a HeaderResponse with a computed state root.
pub fn make_header(
    slot: u64,
    validators: &[ValidatorResponse],
    depth: u32,
    history: &SlotHistory,
) -> HeaderResponse {
    let state_root = compute_state_root_from_validators(validators, depth, history);
    HeaderResponse {
        slot,
        proposer_index: slot % 8,
        state_root,
        parent_root: [0u8; 32],
        body_root: [0u8; 32],
    }
}

/// The opening a finalization needs, out of the justified checkpoint's state.
///
/// `history` is what that state records for the boundary being finalized: the
/// checkpoint root there and the state root it produced.
pub fn make_boundary(
    justified: &HeaderResponse,
    validators: &[ValidatorResponse],
    depth: u32,
    history: &SlotHistory,
) -> zkasper_common::types::BoundaryAnchor {
    use zkasper_witness_gen::state_diff::{
        build_validator_roots, build_validators_ssz_tree, make_boundary_proof,
    };

    let validator_roots = build_validator_roots(validators);
    let (ssz_data_root, _) = build_validators_ssz_tree(&validator_roots, depth, &[]);
    let opened = make_boundary_proof(&ssz_data_root, validators.len() as u64, history);
    assert_eq!(
        opened.state_root, justified.state_root,
        "the opening is not out of the justified checkpoint's own state",
    );
    zkasper_common::types::BoundaryAnchor {
        justified_header: justified.fields(),
        block_roots_siblings: opened.block_roots_siblings,
        state_roots_siblings: opened.state_roots_siblings,
    }
}

/// The block root a header hashes to.
///
/// Checkpoint roots in these tests have to be the real roots of the headers the
/// mock serves: the finalization circuit opens the header and checks it against
/// the root the attesters signed, so an invented root would never verify.
pub fn header_root(header: &HeaderResponse) -> [u8; 32] {
    zkasper_common::ssz::block_header_root(
        header.slot,
        header.proposer_index,
        &header.parent_root,
        &header.state_root,
        &header.body_root,
    )
}

// ---------------------------------------------------------------------------
// Synthetic chain
// ---------------------------------------------------------------------------

pub type Key = (blst::min_pk::SecretKey, [u8; 48]);

pub const BALANCE_GWEI: u64 = 32_000_000_000;

fn generate_keys(n: usize) -> Vec<Key> {
    (0..n)
        .map(|i| {
            let mut ikm = [0u8; 32];
            ikm[0] = i as u8;
            ikm[1] = 0xAB;
            let sk = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
            let pk = sk.sk_to_pk().to_bytes();
            (sk, pk)
        })
        .collect()
}

/// A run of consecutive epochs with real keys, real signatures over real
/// attestation data, and headers whose roots are the roots the daemon resolves.
///
/// Served either in process as a [`MockBeaconApi`] or over HTTP by
/// [`mock_node::MockNode`], from the same construction — a dry run against the
/// real binary is only worth anything if it is the chain the in-process tests
/// already pin.
///
/// Validator 0 loses 1 ETH of effective balance every epoch. That is a field the
/// accumulator leaf commits to, so every epoch has a real mutation to diff *and*
/// lands on a different accumulator — the case finalization has to work across.
pub struct SyntheticChain {
    pub config: ChainConfig,
    pub keys: Vec<Key>,
    pub first_epoch: u64,
    pub last_epoch: u64,
    pub genesis_validators_root: [u8; 32],
    pub fork_version: [u8; 4],
    pub domain: [u8; 32],
}

impl SyntheticChain {
    pub fn new(config: ChainConfig, validators: usize, first_epoch: u64, last_epoch: u64) -> Self {
        assert!(
            validators as u64 <= config.slots_per_epoch,
            "{validators} validators do not fit one per slot in {} slots",
            config.slots_per_epoch,
        );
        let genesis_validators_root = [0xAA; 32];
        let fork_version = [0x04, 0x00, 0x00, 0x00];
        Self {
            domain: compute_domain(
                &DOMAIN_BEACON_ATTESTER,
                &fork_version,
                &genesis_validators_root,
            ),
            keys: generate_keys(validators),
            config,
            first_epoch,
            last_epoch,
            genesis_validators_root,
            fork_version,
        }
    }

    /// Put this chain on the network `root` identifies, so a daemon reading the
    /// node's genesis resolves that network's name. The signing domain moves
    /// with it, because the domain is derived from this root.
    pub fn on_network(mut self, root: [u8; 32]) -> Self {
        self.genesis_validators_root = root;
        self.domain = compute_domain(&DOMAIN_BEACON_ATTESTER, &self.fork_version, &root);
        self
    }

    pub fn epochs(&self) -> std::ops::RangeInclusive<u64> {
        self.first_epoch..=self.last_epoch
    }

    /// Validator set as of `epoch`.
    pub fn validators_at(&self, epoch: u64) -> Vec<ValidatorResponse> {
        self.keys
            .iter()
            .enumerate()
            .map(|(i, (_, pubkey))| ValidatorResponse {
                index: i as u64,
                pubkey: *pubkey,
                effective_balance: if i == 0 {
                    BALANCE_GWEI - epoch.saturating_sub(self.first_epoch) * 1_000_000_000
                } else {
                    BALANCE_GWEI
                },
                activation_epoch: 0,
                exit_epoch: FAR_FUTURE_EPOCH,
                withdrawal_credentials: {
                    let mut wc = [0u8; 32];
                    wc[0] = 0x01;
                    wc
                },
                slashed: false,
                activation_eligibility_epoch: 0,
                withdrawable_epoch: FAR_FUTURE_EPOCH,
            })
            .collect()
    }

    pub fn total_active_balance_at(&self, epoch: u64) -> u64 {
        self.validators_at(epoch)
            .iter()
            .map(|v| v.effective_balance)
            .sum()
    }

    /// Header of the block at `slot`, whose state root commits to the validator
    /// set of the epoch that slot falls in.
    pub fn header_at(&self, slot: u64) -> HeaderResponse {
        make_header(
            slot,
            &self.validators_at(slot / self.config.slots_per_epoch),
            self.config.validators_tree_depth,
            &self.history_at(slot),
        )
    }

    /// What the state at `slot` records about the epoch boundary before it.
    ///
    /// A real state carries 8192 slots of history; a synthetic one only has to
    /// carry the boundary a finalization will open out of it. The daemon runs
    /// the same induction — each epoch diff records what the diff before it
    /// produced — so the two agree slot for slot, starting from the bootstrap,
    /// which records nothing because nothing came before it.
    fn history_at(&self, slot: u64) -> SlotHistory {
        let spe = self.config.slots_per_epoch;
        if slot <= self.first_epoch * spe {
            return SlotHistory::default();
        }
        let previous = self.header_at(slot - spe);
        SlotHistory {
            slot: slot - spe,
            block_root: header_root(&previous),
            state_root: previous.state_root,
        }
    }

    /// The checkpoint root for `epoch`: the root of the block at its first slot.
    ///
    /// It has to be the real root of the header the chain serves, because the
    /// finalization circuit opens that header and checks it against the root the
    /// attesters signed over.
    pub fn checkpoint_root(&self, epoch: u64) -> [u8; 32] {
        header_root(&self.header_at(epoch * self.config.slots_per_epoch))
    }

    /// Committees for `epoch`, partitioning the validators across its slots one
    /// each.
    ///
    /// A committee proof only needs the slot buckets to be disjoint and to cover
    /// everyone it opens — who sits where is the node's shuffle, and getting it
    /// wrong costs liveness rather than soundness — so validator `i` attests at
    /// the epoch's slot `i`.
    pub fn committees_at(&self, epoch: u64) -> Vec<CommitteeResponse> {
        (0..self.keys.len() as u64)
            .map(|i| CommitteeResponse {
                slot: epoch * self.config.slots_per_epoch + i,
                index: 0,
                validators: vec![i],
            })
            .collect()
    }

    /// Validator `index`'s attestation to the epoch's slot `index`, signed for
    /// real. The block at the slot after it carries it — the earliest one that
    /// can, and the block the aggregator waits for before it closes the slot.
    pub fn attestation(&self, epoch: u64, index: usize) -> AttestationResponse {
        let slot = epoch * self.config.slots_per_epoch + index as u64;
        let target_root = self.checkpoint_root(epoch);
        let source_root = self.checkpoint_root(epoch - 1);
        let beacon_block_root = [0u8; 32];
        let signing_root = compute_signing_root(
            &attestation_data_root(
                slot,
                0,
                &beacon_block_root,
                epoch - 1,
                &source_root,
                epoch,
                &target_root,
            ),
            &self.domain,
        );

        AttestationResponse {
            // One validator per committee, so the aggregation bitfield is that
            // one bit plus the SSZ bitlist's length sentinel above it, and
            // `committee_bits` names the single committee — the shape a node has
            // served since Electra moved the index out of `AttestationData`.
            aggregation_bits: vec![0x03],
            committee_bits: vec![0x01],
            data_slot: slot,
            data_index: 0,
            data_beacon_block_root: beacon_block_root,
            data_source_epoch: epoch - 1,
            data_source_root: source_root,
            data_target_epoch: epoch,
            data_target_root: target_root,
            signature: self.keys[index]
                .0
                .sign(
                    &signing_root,
                    b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
                    &[],
                )
                .to_bytes(),
            single_attester: None,
        }
    }

    /// Attestation slots it takes to carry `epoch` over 2/3 of its own active
    /// balance.
    pub fn slots_to_threshold(&self, epoch: u64) -> u64 {
        let quorum = self.total_active_balance_at(epoch) as u128 * 2;
        let mut attesting = 0u128;
        for (i, validator) in self.validators_at(epoch).iter().enumerate() {
            attesting += validator.effective_balance as u128;
            if attesting * 3 >= quorum {
                return i as u64 + 1;
            }
        }
        panic!("the whole validator set does not reach 2/3 of itself");
    }

    /// This chain, in process, with the head at `head_slot`.
    pub fn mock(&self, head_slot: u64) -> MockBeaconApi {
        let mut mock = MockBeaconApi::new();
        mock.genesis_validators_root = self.genesis_validators_root;
        mock.fork_version = self.fork_version;

        for epoch in self.epochs() {
            let boundary = epoch * self.config.slots_per_epoch;
            let header = self.header_at(boundary);
            let target_root = header_root(&header);

            mock.validators
                .insert(boundary.to_string(), self.validators_at(epoch));
            mock.headers.insert(boundary.to_string(), header.clone());
            // Finalization looks the checkpoint's header up by its root, the way
            // it has to when the epoch's first slot holds no block.
            mock.headers.insert(hex0x(&target_root), header);
            mock.block_roots.insert(boundary.to_string(), target_root);
            mock.committees
                .insert((boundary.to_string(), epoch), self.committees_at(epoch));

            for index in 0..self.keys.len() {
                mock.attestations.insert(
                    (boundary + index as u64 + 1).to_string(),
                    vec![self.attestation(epoch, index)],
                );
            }
        }

        mock.headers
            .insert("head".to_string(), self.header_at(head_slot));
        mock.set_finality(self.first_epoch, self.checkpoint_root(self.first_epoch));
        mock
    }
}

// ---------------------------------------------------------------------------
// Streaming fixture
// ---------------------------------------------------------------------------

pub const STREAM_SLOTS: u64 = 8;
pub const STREAM_PER_SLOT: usize = 2;
pub const STREAM_BALANCE_GWEI: u64 = 32_000_000_000;
pub const STREAM_EPOCH: u64 = 10;

/// One epoch of a synthetic chain, shaped for the streaming pipeline.
///
/// Sixteen validators in eight committees of two, real BLS signatures. The
/// accumulator depth is a parameter because the circuit tests want a tree small
/// enough to run in a second, while anything proven by a real guest ELF has to
/// use the depth that ELF was compiled with.
pub struct StreamFixture {
    pub epoch: Epoch,
    pub context: StreamContext,
    pub units: Vec<SlotComplement>,
    pub previous: PreviousJustification,
}

pub fn stream_fixture(acc_depth: u32) -> StreamFixture {
    stream_fixture_from(Epoch::new(
        ChainConfig {
            acc_tree_depth: acc_depth,
            ..ChainConfig::MAINNET
        },
        STREAM_EPOCH,
        STREAM_SLOTS,
        STREAM_PER_SLOT,
    ))
}

/// The same epoch, with the boundary it finalizes left empty.
pub fn stream_fixture_empty_boundary(acc_depth: u32) -> StreamFixture {
    stream_fixture_from(Epoch::with_empty_boundary(
        ChainConfig {
            acc_tree_depth: acc_depth,
            ..ChainConfig::MAINNET
        },
        STREAM_EPOCH,
        STREAM_SLOTS,
        STREAM_PER_SLOT,
    ))
}

fn stream_fixture_from(epoch: Epoch) -> StreamFixture {
    let acc_depth = epoch.config.acc_tree_depth;

    // The diff that carried the accumulator from epoch E-1 to E. Its endpoints
    // are what tie the finalized epoch's justification to this one's.
    let previous_accumulator_commitment =
        acc::commitment(&[9, 9, 9, 9], epoch.total_active_balance);
    let context = StreamContext {
        accumulator_commitment: epoch.accumulator_commitment,
        acc_root: epoch.acc_root,
        total_active_balance: epoch.total_active_balance,
        target_epoch: STREAM_EPOCH,
        target_root: epoch.target_root,
        signing_domain: epoch.signing_domain,
        group_program_vk: [1; 4],
        aggregate_program_vk: [2; 4],
        previous_program_vk: [3; 4],
        epoch_diff_program_vk: [4; 4],
        committee_program_vk: [5; 4],
        epoch_diff: EpochDiffOutput {
            prev_accumulator_commitment: previous_accumulator_commitment,
            state_root_1: epoch.previous_state_root,
            epoch_1: STREAM_EPOCH - 1,
            accumulator_commitment: epoch.accumulator_commitment,
            acc_root: epoch.acc_root,
            total_active_balance: epoch.total_active_balance,
            state_root_2: [0xCD; 32],
            epoch_2: STREAM_EPOCH,
        },
        epoch_diff_proof: Vec::new(),
        committee: epoch.committees.output.clone(),
        committee_proof: Vec::new(),
        acc_depth,
    };

    StreamFixture {
        units: (0..STREAM_SLOTS)
            .map(|slot| epoch.complement(slot, &[]))
            .collect(),
        context,
        previous: PreviousJustification::Batch(JustificationOutput {
            accumulator_commitment: previous_accumulator_commitment,
            target_epoch: STREAM_EPOCH - 1,
            target_root: epoch.previous_root,
        }),
        epoch,
    }
}

/// Compute the synthetic state root from a set of validator responses.
fn compute_state_root_from_validators(
    validators: &[ValidatorResponse],
    depth: u32,
    history: &SlotHistory,
) -> [u8; 32] {
    use zkasper_witness_gen::state_diff::{
        build_validator_roots, build_validators_ssz_tree, make_state_proof,
    };

    let validator_roots = build_validator_roots(validators);
    let (ssz_data_root, _) = build_validators_ssz_tree(&validator_roots, depth, &[]);
    let (state_root, _) = make_state_proof(&ssz_data_root, validators.len() as u64, history);
    state_root
}

/// An attestation source a test publishes to by hand.
///
/// The real one is a task holding the node's event stream open; what the
/// orchestrator sees of either is the same drain, so a test can drive gossip
/// arrival exactly and without a beacon node.
#[derive(Clone, Default)]
pub struct FakeGossip(std::sync::Arc<Mutex<Vec<AttestationResponse>>>);

impl FakeGossip {
    /// Gossip these, as if the node had just validated them.
    pub fn publish(&self, attestations: Vec<AttestationResponse>) {
        self.0.lock().unwrap().extend(attestations);
    }
}

impl AttestationSource for FakeGossip {
    fn drain(&self) -> Vec<AttestationResponse> {
        std::mem::take(&mut self.0.lock().unwrap())
    }

    fn took_reorg(&self) -> bool {
        false
    }

    fn took_gap(&self) -> bool {
        false
    }

    fn counters(&self) -> zkasper_witness_gen::gossip::Counters {
        zkasper_witness_gen::gossip::Counters::default()
    }
}
