// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IZiskVerifier {
    function verify(
        bytes calldata proof,
        uint32[] calldata publicOutputs
    ) external view returns (bool);
}

/// @title ZkasperVerifier
/// @notice Tracks Ethereum beacon chain finality via ZK proofs of Casper FFG.
///
/// Public output layouts (uint32 arrays, little-endian packed):
///
///   Bootstrap:  [commitment(8), acc_root(8), total_active_balance(2),
///                state_root(8), epoch(2)]
///   EpochDiff:  [commitment_1(8), state_root_1(8), epoch_1(2),
///                commitment_2(8), acc_root_2(8), total_active_balance_2(2),
///                state_root_2(8), epoch_2(2)]
///   Finality:   [commitment_e(8), commitment_e1(8), finalized_epoch(2),
///                finalized_root(8), finalized_state_root(8)]
///   StreamFinal:the same 34 words, then [justified_epoch(2),
///                justified_root(8), program_vk(8)]
///
/// There is no stream-final entry point yet. Whoever adds one must also require
/// `program_vk` — words 44..51 — to equal the program key its verifier pins.
/// That is the key the proof verified the *previous* epoch's proof under, and a
/// stream final proof is the one recursion in the pipeline whose child program
/// no circuit is in a position to pin: a program cannot contain its own
/// verification key, and nothing but the next epoch's proof consumes this one.
/// Skip the check and the proof on chain is genuine while the epoch below it is
/// whatever the prover chose. See `docs/finality/assumptions.md`, "Which
/// program a child proof came from".
///
/// The accumulator_commitment is poseidon(poseidon_root, total_active_balance),
/// binding the Poseidon validator tree to the total active balance in one value.
contract ZkasperVerifier {
    IZiskVerifier public immutable epochDiffVerifier;
    IZiskVerifier public immutable finalityVerifier;
    IZiskVerifier public immutable bootstrapVerifier;


    // ---------------------------------------------------------------------
    // Public-output layout, in 32-bit words.
    //
    // These MUST match `PublicWriter` usage in the guest `main.rs` files.
    // They previously did not: the contract read the accumulator root where it
    // expected state_root_1, and the epoch where it expected the finalized
    // root. Nothing caught it because no proof was ever verified end to end.
    // A Digest is 4 u64 = 8 words; a bytes32 is 8 words; a u64 is 2 words.
    // ---------------------------------------------------------------------

    // bootstrap: commitment, acc_root, total_active_balance, state_root, epoch
    uint256 private constant BOOT_COMMITMENT = 0;
    uint256 private constant BOOT_STATE_ROOT = 18;

    // epoch-diff: commitment_1, state_root_1, epoch_1,
    //             commitment_2, acc_root_2, total_active_balance_2,
    //             state_root_2, epoch_2
    uint256 private constant DIFF_COMMITMENT_1 = 0;
    uint256 private constant DIFF_STATE_ROOT_1 = 8;
    uint256 private constant DIFF_COMMITMENT_2 = 18;
    uint256 private constant DIFF_STATE_ROOT_2 = 36;

    // finalization: commitment_e, commitment_e1, finalized_epoch,
    //               finalized_root, finalized_state_root
    uint256 private constant FIN_COMMITMENT = 0;
    uint256 private constant FIN_NEXT_COMMITMENT = 8;
    uint256 private constant FIN_ROOT = 18;
    uint256 private constant FIN_STATE_ROOT = 26;

    // Total words each layout occupies, so a short array cannot be read past.
    uint256 private constant BOOT_WORDS = 28;
    uint256 private constant DIFF_WORDS = 46;
    uint256 private constant FIN_WORDS = 34;

    bytes32 public accumulatorCommitment;
    bytes32 public latestStateRoot;
    bytes32 public latestFinalizedStateRoot;
    bytes32 public latestFinalizedBlockRoot;
    bool public initialized;

    event Bootstrapped(bytes32 stateRoot, bytes32 accumulatorCommitment);
    event EpochDiffVerified(bytes32 stateRoot2, bytes32 accumulatorCommitment);
    event FinalityVerified(bytes32 blockRoot);

    constructor(
        address _epochDiffVerifier,
        address _finalityVerifier,
        address _bootstrapVerifier
    ) {
        epochDiffVerifier = IZiskVerifier(_epochDiffVerifier);
        finalityVerifier = IZiskVerifier(_finalityVerifier);
        bootstrapVerifier = IZiskVerifier(_bootstrapVerifier);
    }

    /// @notice One-time initialization from a trusted state root.
    /// Public outputs: [commitment(8), acc_root(8), total_active_balance(2),
    ///                  state_root(8), epoch(2)]
    function bootstrap(
        bytes calldata proof,
        uint32[] calldata publicOutputs
    ) external {
        require(!initialized, "already initialized");
        require(publicOutputs.length >= BOOT_WORDS, "invalid outputs length");
        require(bootstrapVerifier.verify(proof, publicOutputs), "invalid proof");

        accumulatorCommitment = _extractBytes32(publicOutputs, BOOT_COMMITMENT);
        latestStateRoot = _extractBytes32(publicOutputs, BOOT_STATE_ROOT);
        initialized = true;

        emit Bootstrapped(latestStateRoot, accumulatorCommitment);
    }

    /// @notice Submit an epoch diff proof to advance the accumulator.
    /// Public outputs: [commitment_1(8), state_root_1(8), epoch_1(2),
    ///                  commitment_2(8), acc_root_2(8), total_active_balance_2(2),
    ///                  state_root_2(8), epoch_2(2)]
    function submitEpochDiff(
        bytes calldata proof,
        uint32[] calldata publicOutputs
    ) external {
        require(initialized, "not initialized");
        require(publicOutputs.length >= DIFF_WORDS, "invalid outputs length");
        require(epochDiffVerifier.verify(proof, publicOutputs), "invalid proof");

        // Bind BOTH endpoints. The proof now names the accumulator it started
        // from, so the chain is enforced on the commitment, not just the state
        // root — a proof built against a different accumulator is rejected here.
        require(
            _extractBytes32(publicOutputs, DIFF_COMMITMENT_1) == accumulatorCommitment,
            "epoch diff does not start from the current accumulator"
        );
        require(
            _extractBytes32(publicOutputs, DIFF_STATE_ROOT_1) == latestStateRoot,
            "state root 1 mismatch"
        );

        accumulatorCommitment = _extractBytes32(publicOutputs, DIFF_COMMITMENT_2);
        latestStateRoot = _extractBytes32(publicOutputs, DIFF_STATE_ROOT_2);

        emit EpochDiffVerified(latestStateRoot, accumulatorCommitment);
    }

    /// @notice Submit a finality proof.
    /// Public outputs: [commitment_e(8), commitment_e1(8), finalized_epoch(2),
    ///                  finalized_block_root(8), finalized_state_root(8)]
    function submitFinality(
        bytes calldata proof,
        uint32[] calldata publicOutputs
    ) external {
        require(initialized, "not initialized");
        require(publicOutputs.length >= FIN_WORDS, "invalid outputs length");
        require(finalityVerifier.verify(proof, publicOutputs), "invalid proof");

        // A finality proof spans two epochs, so it names two accumulators: the
        // one epoch E was justified against and the one E+1 was. Either may be
        // the accumulator this contract currently holds, depending on whether
        // the epoch diff between them has been submitted yet.
        require(
            _extractBytes32(publicOutputs, FIN_COMMITMENT) == accumulatorCommitment ||
                _extractBytes32(publicOutputs, FIN_NEXT_COMMITMENT) == accumulatorCommitment,
            "accumulator mismatch"
        );

        latestFinalizedBlockRoot = _extractBytes32(publicOutputs, FIN_ROOT);
        // Anchors the accumulator: the state root a real supermajority attested
        // to. A branched accumulator can never produce a matching value.
        latestFinalizedStateRoot = _extractBytes32(publicOutputs, FIN_STATE_ROOT);

        emit FinalityVerified(latestFinalizedBlockRoot);
    }

    function _extractBytes32(uint32[] calldata data, uint256 offset) internal pure returns (bytes32) {
        bytes32 result;
        for (uint256 i = 0; i < 8; i++) {
            result |= bytes32(uint256(data[offset + i])) << (i * 32);
        }
        return result;
    }
}
