//! The finalized epoch's boundary, opened out of the justified checkpoint.
//!
//! A checkpoint root is the last block at or *before* the epoch's first slot, so
//! an empty first slot leaves the boundary state with no header to read it off.
//! The state of the justified checkpoint has both values in its ring buffers,
//! and it is the one state after the boundary the proof already trusts.

use anyhow::{Context, Result};
use tracing::warn;
use zkasper_common::ssz::list_hash_tree_root;
use zkasper_common::types::BoundaryAnchor;
use zkasper_common::ChainConfig;

use crate::beacon_api::BeaconApi;
use crate::epoch_state::EpochState;
use crate::ssz_state;
use crate::state_diff::{self, SlotHistory};

/// Build the anchor that ties the finalized epoch's boundary to the justified
/// checkpoint the attesters signed.
///
/// `boundary_state_root` is the state the finalized epoch's accumulator was
/// built from — the epoch diff's `state_root_1` — and the whole point of the
/// opening is to prove the chain recorded exactly that at the boundary.
pub async fn build(
    api: &impl BeaconApi,
    config: &ChainConfig,
    justified_root: &[u8; 32],
    finalized_epoch: u64,
    finalized_root: &[u8; 32],
    boundary_state_root: &[u8; 32],
    current: &EpochState,
) -> Result<BoundaryAnchor> {
    // Addressed by root rather than by slot, which is what makes this work for a
    // justified epoch whose own first slot was skipped.
    let justified_header = api
        .get_header(&crate::artifacts::hex0x(justified_root))
        .await
        .context("fetch the header of the justified checkpoint block")?
        .fields();

    let boundary_slot = finalized_epoch * config.slots_per_epoch;

    // Addressed by the header's own state root, and by its slot only if the node
    // will not answer that. A slot names whatever the node holds there now; a
    // state root names one state and nothing else, so a node whose view has
    // moved answers with nothing rather than with a state this proof would then
    // have to reject.
    let served = match api
        .get_state_ssz(&crate::artifacts::hex0x(&justified_header.state_root))
        .await?
    {
        Some(raw) => Some(raw),
        None => {
            api.get_state_ssz(&justified_header.slot.to_string())
                .await?
        }
    };

    let proof = match served {
        Some(raw) => {
            // The registry only carries over when the checkpoint block sits on
            // the boundary slot, which is the state the epoch diff just parsed.
            let known = (current.slot == justified_header.slot)
                .then(|| list_hash_tree_root(&current.ssz_data_root, current.num_validators));
            ssz_state::parse_boundary_proof(&raw, known, config, boundary_slot)?
        }
        None => {
            // A synthetic state anchors an epoch diff, whose state root the
            // accumulator chain defines for itself. It cannot anchor this one:
            // the circuit hashes these siblings and asserts the result equals
            // the justified header's own state root -- see
            // `zkasper_common::ssz::open_boundary` — and a state the chain
            // never produced does not hash to a root the chain signed.
            //
            // A fixture chain is the exception, because its header carries the
            // root this very call fabricates. So the fabrication is made and
            // then checked: coherent means a synthetic chain, and incoherent
            // means a real one whose state the node has dropped — which is the
            // one failure an operator can act on, and has to be named as that
            // rather than reported as a state root that disagreed.
            let synthetic = state_diff::make_boundary_proof(
                &current.ssz_data_root,
                current.num_validators,
                &SlotHistory {
                    slot: boundary_slot,
                    block_root: *finalized_root,
                    state_root: *boundary_state_root,
                },
            );
            anyhow::ensure!(
                synthetic.state_root == justified_header.state_root,
                "{} {} — the justified checkpoint's own state is the only state that opens \
                 the boundary 2/3 of the stake signed, and none other stands in for it",
                crate::beacon_api::STATE_NOT_SERVED,
                justified_header.slot,
            );
            warn!(
                slot = justified_header.slot,
                "the node does not serve the debug state endpoint; \
                 anchoring this boundary on a synthetic state",
            );
            synthetic
        }
    };

    // Everything the circuit will assert, asserted here first, so an epoch that
    // cannot be proven says which of the three values disagreed.
    anyhow::ensure!(
        proof.state_root == justified_header.state_root,
        "the state at slot {} is not the one the justified checkpoint produced",
        justified_header.slot,
    );
    anyhow::ensure!(
        proof.block_root == *finalized_root,
        "the justified chain has a different checkpoint at slot {boundary_slot}",
    );
    anyhow::ensure!(
        proof.boundary_state_root == *boundary_state_root,
        "the accumulator was built from a different state than slot {boundary_slot} produced",
    );

    Ok(BoundaryAnchor {
        justified_header,
        block_roots_siblings: proof.block_roots_siblings,
        state_roots_siblings: proof.state_roots_siblings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_api::{
        AttestationResponse, CommitteeResponse, HeaderResponse, ValidatorResponse,
    };

    const BOUNDARY_EPOCH: u64 = 469_468;
    const FINALIZED_ROOT: [u8; 32] = [0xAB; 32];
    const BOUNDARY_STATE_ROOT: [u8; 32] = [0xEE; 32];

    /// A node that serves headers, and whatever state it has been given.
    ///
    /// `state` is `None` for a node that has migrated the epoch past its split,
    /// and `Some` for one that answers with a state — including a state that
    /// does not match the header it serves for the same slot.
    struct Node {
        header: HeaderResponse,
        state: Option<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl BeaconApi for Node {
        async fn get_validators(&self, _state_id: &str) -> Result<Vec<ValidatorResponse>> {
            unreachable!("the boundary does not read the registry")
        }

        async fn get_block_attestations(
            &self,
            _block_id: &str,
        ) -> Result<Vec<AttestationResponse>> {
            unreachable!("the boundary does not read attestations")
        }

        async fn get_committees(
            &self,
            _state_id: &str,
            _epoch: u64,
        ) -> Result<Vec<CommitteeResponse>> {
            unreachable!("the boundary does not read committees")
        }

        async fn get_header(&self, _block_id: &str) -> Result<HeaderResponse> {
            Ok(self.header.clone())
        }

        async fn get_state_ssz(&self, _state_id: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.state.clone())
        }

        async fn get_state_root(&self, _state_id: &str) -> Result<Option<[u8; 32]>> {
            Ok(None)
        }
    }

    fn justified_slot(config: &ChainConfig) -> u64 {
        (BOUNDARY_EPOCH + 1) * config.slots_per_epoch
    }

    fn header(config: &ChainConfig, state_root: [u8; 32]) -> HeaderResponse {
        HeaderResponse {
            slot: justified_slot(config),
            proposer_index: 3,
            state_root,
            parent_root: [0x0A; 32],
            body_root: [0x0B; 32],
        }
    }

    fn current(config: &ChainConfig) -> EpochState {
        EpochState::empty(justified_slot(config), 0)
    }

    /// The root the synthetic fallback fabricates for this boundary.
    fn synthetic_root(config: &ChainConfig) -> [u8; 32] {
        let current = current(config);
        state_diff::make_boundary_proof(
            &current.ssz_data_root,
            current.num_validators,
            &SlotHistory {
                slot: BOUNDARY_EPOCH * config.slots_per_epoch,
                block_root: FINALIZED_ROOT,
                state_root: BOUNDARY_STATE_ROOT,
            },
        )
        .state_root
    }

    async fn build_against(api: &Node, config: &ChainConfig) -> Result<BoundaryAnchor> {
        build(
            api,
            config,
            &api.header.root(),
            BOUNDARY_EPOCH,
            &FINALIZED_ROOT,
            &BOUNDARY_STATE_ROOT,
            &current(config),
        )
        .await
    }

    /// A real chain whose state the node has dropped must be named as that.
    ///
    /// This is the crash of 2026-08-19, three times over: the node had migrated
    /// the justified checkpoint's state past its split, the fallback fabricated
    /// a state in its place, and the fabricated root could not equal a root the
    /// chain had signed. The run died saying the state disagreed, which reads as
    /// a consensus fault and sent an operator looking for one. What had happened
    /// is the one thing the daemon already knows how to say.
    #[tokio::test]
    async fn a_dropped_state_is_reported_as_a_dropped_state() {
        let config = ChainConfig::MAINNET;
        // Any root the fabrication does not produce; a real header carries one.
        let api = Node {
            header: header(&config, [0x77; 32]),
            state: None,
        };

        let error = build_against(&api, &config)
            .await
            .expect_err("a boundary cannot be opened out of a state nobody serves");
        let text = format!("{error:#}");

        assert!(
            text.contains(crate::beacon_api::STATE_NOT_SERVED),
            "the daemon has to recognise this as a dropped state, got: {text}",
        );
        assert!(
            !text.contains("is not the one the justified checkpoint produced"),
            "a state the node never served cannot be the state that disagreed, got: {text}",
        );
    }

    /// And a synthetic chain still opens, which is what the fixtures are.
    #[tokio::test]
    async fn a_synthetic_chain_still_anchors_on_its_own_state() {
        let config = ChainConfig::MAINNET;
        let api = Node {
            header: header(&config, synthetic_root(&config)),
            state: None,
        };

        let anchor = build_against(&api, &config)
            .await
            .expect("a chain whose header carries the fabricated root is coherent with it");
        assert_eq!(anchor.justified_header.slot, justified_slot(&config));
    }

    /// Whatever `build` hands back, the circuit has to accept.
    ///
    /// `zkasper_common::ssz::open_boundary` is what the finalization and
    /// stream-final guests run on this anchor, and it asserts rather than
    /// returns — so an anchor it rejects is a panic inside a proof rather than
    /// an error an operator can read. Both attempts at this bug on 2026-08-19
    /// broke this one invariant, in opposite directions, so it is asserted
    /// directly rather than through either of them.
    fn circuit_accepts(
        anchor: &BoundaryAnchor,
        justified_root: &[u8; 32],
        config: &ChainConfig,
    ) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            zkasper_common::ssz::open_boundary(
                anchor,
                BOUNDARY_EPOCH,
                &FINALIZED_ROOT,
                justified_root,
                &BOUNDARY_STATE_ROOT,
                config.slots_per_epoch,
            );
        }))
        .is_ok()
    }

    /// A node that serves a state contradicting its own header must not turn
    /// into an anchor the circuit then rejects.
    ///
    /// Failing is allowed here; handing back a fabrication is not. This is the
    /// case the synthetic fallback was extended to on 2026-08-19: the daemon
    /// stopped erroring and started panicking a stage later, inside
    /// `open_boundary`, having bought a committee proof to get there.
    #[tokio::test]
    async fn a_contradicting_state_never_becomes_an_anchor() {
        let config = ChainConfig::MAINNET;
        let history = SlotHistory {
            slot: BOUNDARY_EPOCH * config.slots_per_epoch,
            block_root: FINALIZED_ROOT,
            state_root: BOUNDARY_STATE_ROOT,
        };
        let api = Node {
            // A real header carries a root the served state does not hash to.
            header: header(&config, [0x77; 32]),
            state: Some(crate::ssz_state::empty_state_ssz(
                &config,
                justified_slot(&config),
                &history,
            )),
        };

        match build_against(&api, &config).await {
            Err(_) => {}
            Ok(anchor) => assert!(
                circuit_accepts(&anchor, &api.header.root(), &config),
                "build handed back an anchor the circuit panics on",
            ),
        }
    }

    /// The same invariant on the branch production actually takes.
    ///
    /// All five crashes of 2026-08-19 came through here: the node served no
    /// state at all. An anchor built from a fabricated state and a real header
    /// fails `open_boundary`'s first assertion — "the finalized checkpoint is
    /// not the block at the boundary of the justified chain" — which names its
    /// two operands misleadingly. It compares a state root recomputed from the
    /// anchor's own siblings against the header's, so it fires on the
    /// fabrication alone and says nothing about whether the epoch's data is
    /// self-consistent.
    #[tokio::test]
    async fn an_unserved_state_never_becomes_an_anchor() {
        let config = ChainConfig::MAINNET;
        let api = Node {
            header: header(&config, [0x77; 32]),
            state: None,
        };

        match build_against(&api, &config).await {
            Err(_) => {}
            Ok(anchor) => assert!(
                circuit_accepts(&anchor, &api.header.root(), &config),
                "build handed back an anchor the circuit panics on",
            ),
        }
    }

    /// And the fixture chain's anchor is one the circuit takes.
    #[tokio::test]
    async fn a_synthetic_chains_anchor_is_one_the_circuit_takes() {
        let config = ChainConfig::MAINNET;
        let api = Node {
            header: header(&config, synthetic_root(&config)),
            state: None,
        };

        let anchor = build_against(&api, &config)
            .await
            .expect("a chain whose header carries the fabricated root is coherent with it");
        assert!(circuit_accepts(&anchor, &api.header.root(), &config));
    }
}
