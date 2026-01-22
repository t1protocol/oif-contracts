// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { LibAddress } from "../../../libs/LibAddress.sol";
import { MandateOutput, MandateOutputEncodingLib } from "../../../libs/MandateOutputEncodingLib.sol";
import { BaseInputOracle } from "../../../oracles/BaseInputOracle.sol";
import { IT1XChainReader } from "./external/xChain/IT1XChainReader.sol";

/**
 * @notice T1 Oracle
 *
 * Proves 7683 intent fills by reading remote chain function inside an offchain component running inside a TEE.
 *
 */
contract T1Oracle is BaseInputOracle {
    using LibAddress for address;

    /// @dev The fill record hash from xChainRead doesn't match the provided solver/timestamp preimage
    error InvalidPreimage(bytes32 expected, bytes32 provided);

    /// @dev The fill record is empty, meaning the intent was not filled
    error IntentNotFilled();

    IT1XChainReader public X_CHAIN_READER;

    mapping(uint256 => address) internal _remoteChainIdToApplication;

    constructor(
        address xChainReader
    ) {
        X_CHAIN_READER = IT1XChainReader(xChainReader);
    }

    function addRemoteApplication(address application, uint256 remoteChainId) external  {
        _remoteChainIdToApplication[remoteChainId] = application;
    }

    /**
     * @notice Proves an intent fill using xChainRead proof with solver-provided preimage.
     * @dev The xChainRead proof contains the result of calling `getFillRecord(orderId, output)` on the
     *      remote OutputSettlerSimple, which returns `keccak256(solver, timestamp)`. The solver must
     *      provide the preimage (solver, timestamp) to prove they filled the intent.
     * @param proof The encoded proof of read from T1XChainReader
     * @param remoteChainId The chain ID where the fill occurred
     * @param solver The solver's identifier (address as bytes32)
     * @param timestamp The timestamp when the fill occurred
     * @param orderId The order ID of the filled intent
     * @param output The MandateOutput that was filled
     */
    function receiveMessageWithPreimage(
        bytes calldata proof,
        uint32 remoteChainId,
        bytes32 solver,
        uint32 timestamp,
        bytes32 orderId,
        MandateOutput calldata output
    ) external {
        _processMessageWithPreimage(proof, remoteChainId, solver, timestamp, orderId, output);
    }

    /**
     * @notice Batch version of receiveMessageWithPreimage for multiple proofs.
     * @param proofs Array of encoded proofs of read
     * @param remoteChainId The chain ID where the fills occurred
     * @param solvers Array of solver identifiers
     * @param timestamps Array of fill timestamps
     * @param orderIds Array of order IDs
     * @param outputs Array of MandateOutputs that were filled
     */
    function receiveMessageWithPreimage(
        bytes[] calldata proofs,
        uint32 remoteChainId,
        bytes32[] calldata solvers,
        uint32[] calldata timestamps,
        bytes32[] calldata orderIds,
        MandateOutput[] calldata outputs
    ) external {
        uint256 numProofs = proofs.length;
        for (uint256 i; i < numProofs; ++i) {
            _processMessageWithPreimage(proofs[i], remoteChainId, solvers[i], timestamps[i], orderIds[i], outputs[i]);
        }
    }

    function _proofPayloadHash(
        bytes32 orderId,
        bytes32 solver,
        uint32 timestamp,
        MandateOutput memory mandateOutput
    ) internal pure returns (bytes32 outputHash) {
        return outputHash =
            keccak256(MandateOutputEncodingLib.encodeFillDescriptionMemory(solver, orderId, timestamp, mandateOutput));
    }

    /**
     * @dev Internal function to process a proof with solver-provided preimage.
     * @param proof The encoded proof of read
     * @param remoteChainId The chain ID where the fill occurred
     * @param solver The solver's identifier
     * @param timestamp The fill timestamp
     * @param orderId The order ID
     * @param output The MandateOutput that was filled
     */
    function _processMessageWithPreimage(
        bytes calldata proof,
        uint256 remoteChainId,
        bytes32 solver,
        uint32 timestamp,
        bytes32 orderId,
        MandateOutput calldata output
    ) internal {
        address remoteApplication = _remoteChainIdToApplication[remoteChainId];
        if (remoteApplication == address(0)) revert();

        // Verify the xChainRead proof - result is the return value of getFillRecord(orderId, output)
        // which is keccak256(abi.encodePacked(solver, timestamp))
        (, bytes memory result) = X_CHAIN_READER.verifyProofOfRead(proof);

        // Decode the fill record hash from the xChainRead result
        bytes32 fillRecordHash = abi.decode(result, (bytes32));

        // Empty fill record means the intent was not filled
        if (fillRecordHash == bytes32(0)) revert IntentNotFilled();

        // Verify the provided preimage matches the fill record hash
        bytes32 expectedFillRecordHash = keccak256(abi.encodePacked(solver, timestamp));
        if (fillRecordHash != expectedFillRecordHash) {
            revert InvalidPreimage(fillRecordHash, expectedFillRecordHash);
        }

        // Compute the full payload hash matching OIF's attestation format
        bytes32 payloadHash = _proofPayloadHash(orderId, solver, timestamp, output);

        // Store attestation with the proper payload hash
        bytes32 oracleIdentifier = address(this).toIdentifier();
        bytes32 applicationIdentifier = remoteApplication.toIdentifier();
        _attestations[remoteChainId][oracleIdentifier][applicationIdentifier][payloadHash] = true;

        emit OutputProven(remoteChainId, oracleIdentifier, applicationIdentifier, payloadHash);
    }
}
