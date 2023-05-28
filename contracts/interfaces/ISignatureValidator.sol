// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.10;

interface ISignatureValidator {
    function isValidSignature(
        bytes32 _dataHash,
        bytes calldata _signature
    ) external view returns (bytes4);

    function isValidSignature(
        bytes memory _data,
        bytes memory _signature
    ) external view returns (bytes4);
}
