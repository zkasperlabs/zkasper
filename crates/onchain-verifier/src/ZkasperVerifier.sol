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
///   Bootstrap:  [accumulator_commitment(8), state_root(8)]
///   EpochDiff:  [accumulator_commitment(8), state_root_1(8), state_root_2(8)]
///   Finality:   [accumulator_commitment(8), finalized_block_root(8)]
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

    // finalization: commitment, finalized_epoch, finalized_root, finalized_state_root
    uint256 private constant FIN_COMMITMENT = 0;
    uint256 private constant FIN_ROOT = 10;
    uint256 private constant FIN_STATE_ROOT = 18;

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
    /// Public outputs: [accumulator_commitment(8), state_root(8)]
    function bootstrap(
        bytes calldata proof,
        uint32[] calldata publicOutputs
    ) external {
        require(!initialized, "already initialized");
        require(publicOutputs.length >= 16, "invalid outputs length");
        require(bootstrapVerifier.verify(proof, publicOutputs), "invalid proof");

        accumulatorCommitment = _extractBytes32(publicOutputs, BOOT_COMMITMENT);
        latestStateRoot = _extractBytes32(publicOutputs, BOOT_STATE_ROOT);
        initialized = true;

        emit Bootstrapped(latestStateRoot, accumulatorCommitment);
    }

    /// @notice Submit an epoch diff proof to advance the accumulator.
    /// Public outputs: [accumulator_commitment(8), state_root_1(8), state_root_2(8)]
    function submitEpochDiff(
        bytes calldata proof,
        uint32[] calldata publicOutputs
    ) external {
        require(initialized, "not initialized");
        require(publicOutputs.length >= 24, "invalid outputs length");
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
    /// Public outputs: [accumulator_commitment(8), finalized_block_root(8)]
    function submitFinality(
        bytes calldata proof,
        uint32[] calldata publicOutputs
    ) external {
        require(initialized, "not initialized");
        require(publicOutputs.length >= 16, "invalid outputs length");
        require(finalityVerifier.verify(proof, publicOutputs), "invalid proof");

        bytes32 provenCommitment = _extractBytes32(publicOutputs, FIN_COMMITMENT);
        require(provenCommitment == accumulatorCommitment, "accumulator mismatch");

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
