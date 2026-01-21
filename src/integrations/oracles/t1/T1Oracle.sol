// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { LibAddress } from "../../../libs/LibAddress.sol";
import { Bytes } from "openzeppelin/utils/Bytes.sol";

import { MandateOutput, MandateOutputEncodingLib } from "../../../libs/MandateOutputEncodingLib.sol";

import { BaseInputOracle } from "../../../oracles/BaseInputOracle.sol";
import { OutputSettlerBase } from "../../../output/OutputSettlerBase.sol";
import {IT1XChainReader} from "./external/xChain/IT1XChainReader.sol";
import {ChainMap} from "../../../oracles/ChainMap.sol";

/**
 * @notice T1 Oracle
 * Proves fills by reading remote chain function inside an offchain component running inside a TEE
 */
contract T1Oracle is BaseInputOracle {
    using LibAddress for address;

    error WrongEventSignature();

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

    function receiveMessage(
        bytes calldata proof, uint32 remoteChainId
    ) external {
        _processMessage(proof, remoteChainId);
    }

    function receiveMessage(
        bytes[] calldata proofs, uint32 remoteChainId
    ) external {
        uint256 numProofs = proofs.length;
        for (uint256 i; i < numProofs; ++i) {
            _processMessage(proofs[i], remoteChainId);
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

    function _processMessage(
        bytes calldata proof, uint256 remoteChainId
    ) internal {
        (bytes32 requestId, bytes memory result) =
            X_CHAIN_READER.verifyProofOfRead(proof);

        // TODO verify that read result indeed says that intent was filled
        // TODO hash requestId to be stored as payload instead of storing it raw

        address remoteApplication = _remoteChainIdToApplication[remoteChainId];
        if (remoteApplication == address(0)) revert();

        _attestations[remoteChainId][address(this).toIdentifier()][remoteApplication.toIdentifier()][requestId] = true;

        emit OutputProven(remoteChainId, address(this).toIdentifier(), remoteApplication.toIdentifier(), requestId);
    }
}
