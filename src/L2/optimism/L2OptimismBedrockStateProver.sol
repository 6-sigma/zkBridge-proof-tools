// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {OptimismBedrockStateProver as Prover} from "./../../library/optimism/OptimismBedrockStateProver.sol";
import {Types} from "./../../library/optimism/Types.sol";
import {ILightClient} from "./../ILightClient.sol";
import {CombinedProofVerifier} from "./../../MPT/CombinedProofVerifier.sol";

/// @notice Contract for verification of MPT inclusion inside Optimism Bedrock from within external other network
/// @author Perseverance - LimeChain
/// @dev Depends on an external contract - ILightClient - that is used for input of the bedrock anchored L1 state roots
/// @dev The verification happens in two stages.
/// @dev Stage 1 is verification that the output root exists inside the Optimism Bedrock Output Oracle via MPT Proof
/// @dev Stage 2 uses the state root inside the output root and performs MPT inclusion proving for data inside
library L2OptimismBedrockStateProver {


    uint256 public constant outputOracleOutputProofsSlotPosition = 3;

    /// @notice Internal method to verify that the output root corresponding to the output proof exists inside the Optimism Bedrock Output Oracle for the given index
    /// @param outputIndex The index to find the output proof at inside the Bedrock OutputOracle
    /// @param outputProof The MPT proof data to verify that the given output root is contained inside the OutputOracle for the expected index
    /// @return isValid if the output root is indeed there
    function proveOutputRoot(
        bytes32 l1StateRoot,
        address berdockOutputOracleAddress,
        uint256 outputIndex,
        Types.OutputRootMPTProof calldata outputProof
    ) internal pure returns (bool isValid) {

        // See https://github.com/ethereum-optimism/optimism/blob/develop/specs/proposals.md#l2-output-commitment-construction
        bytes32 calculatedOutputRoot = keccak256(
            abi.encode(
                Prover.versionByte,
                outputProof.outputRootProof.stateRoot,
                outputProof.outputRootProof.withdrawalStorageRoot,
                outputProof.outputRootProof.latestBlockhash
            )
        );

        // The data structure that bedrock saves in the array is 2 slots long thus finding the slot with the output proof requires (2 * index)
        uint256 targetSlot = uint256(
            keccak256(abi.encode(outputOracleOutputProofsSlotPosition))
        ) + (2 * outputIndex);

        return
            CombinedProofVerifier.verifyStateProof(
                l1StateRoot,
                berdockOutputOracleAddress,
                bytes32(targetSlot),
                uint256(calculatedOutputRoot),
                outputProof.optimismStateProofsBlob
            );
    }

    /// @notice Verifies that a certain expected value is located at the specified storage slot at the specified target account inside Optimism Bedrock
    /// @dev Performs both stages of verification.
    /// @param outputIndex The index to find the output proof at inside the Bedrock OutputOracle
    /// @param outputProof The MPT proof data to verify that the given output root is contained inside the OutputOracle for the expected index
    /// @param inclusionProof The MPT Inclusion proof to verify the expected value is found in the specified storage slot for the specified account inside Optimism
    /// @param expectedValue The expected value to be in the storage slot
    /// @return isValid if the expected value is indeed there
    function proveInOptimismState(
        bytes32 l1StateRoot,
        address berdockOutputOracleAddress,
        uint256 outputIndex,
        Types.OutputRootMPTProof calldata outputProof,
        Types.MPTInclusionProof calldata inclusionProof,
        uint256 expectedValue
    ) public view returns (bool isValid) {
        require(
            proveOutputRoot(l1StateRoot, berdockOutputOracleAddress, outputIndex, outputProof),
            "Optimism root state was not found in L1"
        );
        return
            Prover._proveInOptimismState(
                outputProof.outputRootProof.stateRoot,
                inclusionProof.target,
                inclusionProof.slotPosition,
                expectedValue,
                inclusionProof.proofsBlob
            );
    }
}
