// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.10;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "./common/SignatureDecoder.sol";
import "./MultiSig.sol";
import "hardhat/console.sol";

contract SignatureValidator is Ownable, SignatureDecoder, IERC1271 {
    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant EIP1271_MAGIC_VALUE = 0x1626ba7e;

    // keccak256("SafeMessage(bytes message)");
    bytes32 private constant SAFE_MSG_TYPEHASH =
        0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca;

    address public multiSigAdd;

    constructor(address _multiSigAdd) {
        multiSigAdd = _multiSigAdd;
    }

    function setMultiSigAdd(address _multiSigAdd) external onlyOwner {
        multiSigAdd = _multiSigAdd;
    }

    /**
     * @notice Implementation of updated EIP-1271 signature validation method.
     * @param _dataHash Hash of the data signed
     * @param _signature Signature byte array associated with _dataHash
     * @return Updated EIP1271 magic value if signature is valid, otherwise 0x0
     */
    function isValidSignature(
        bytes32 _dataHash,
        bytes calldata _signature
    ) external view returns (bytes4) {
        bytes4 value = isValidSignature(abi.encode(_dataHash), _signature);
        return (value == EIP1271_MAGIC_VALUE) ? EIP1271_MAGIC_VALUE : bytes4(0);
    }

    /**
     * @notice Legacy EIP-1271 signature validation method.
     * @dev Implementation of ISignatureValidator (see `interfaces/ISignatureValidator.sol`)
     * @param _data Arbitrary length data signed.
     * @param _signature Signature byte array associated with _data.
     * @return The EIP-1271 magic value.
     */
    function isValidSignature(
        bytes memory _data,
        bytes memory _signature
    ) public view returns (bytes4) {
        // Caller should be a MultiSig
        MultiSig multiSig = MultiSig(multiSigAdd);
        bytes memory messageData = encodeMessageDataForMultiSig(multiSig, _data);
        console.log("messageData");
        console.logBytes(messageData);
        bytes32 messageHash = keccak256(messageData);
        console.log("isValid messageHash");
        console.logBytes32(messageHash);
        if (_signature.length == 0) {
            require(multiSig.signedMessages(messageHash) != 0, "Hash not approved");
        } else {
            multiSig.checkSignatures(messageHash, messageData, _signature);
        }
        return EIP1271_MAGIC_VALUE;
    }

    /**
     * @dev Returns the pre-image of the message hash (see getMessageHashForMultiSig).
     * @param multiSig MultiSig to which the message is targeted.
     * @param message Message that should be encoded.
     * @return Encoded message.
     */
    function encodeMessageDataForMultiSig(
        MultiSig multiSig,
        bytes memory message
    ) public view returns (bytes memory) {
        bytes32 safeMessageHash = keccak256(abi.encode(SAFE_MSG_TYPEHASH, keccak256(message)));
        console.log("safeMessageHash:");
        console.logBytes32(safeMessageHash);
        return
            abi.encodePacked(
                bytes1(0x19),
                bytes1(0x01),
                multiSig.domainSeparator(),
                safeMessageHash
            );
    }

    /**
     * @dev Returns hash of a message that can be signed by owners.
     * @param multisig MultiSig to which the message is targeted.
     * @param message Message that should be hashed.
     * @return Message hash.
     */
    function getMessageHashForMultiSig(
        MultiSig multisig,
        bytes memory message
    ) public view returns (bytes32) {
        return keccak256(encodeMessageDataForMultiSig(multisig, message));
    }
}
