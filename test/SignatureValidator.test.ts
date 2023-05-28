import web3 from "web3";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { BigNumber, Contract, ContractFactory } from "ethers";
// import { toEthSignedMessageHash } from "./helpers/sign";
import {
  EIP712_SAFE_MESSAGE_TYPE,
  buildSignatureBytes,
  calculateSafeMessageHash,
  preimageSafeMessageHash,
  buildContractSignature,
  signHash,
} from "./helpers/signature";
import { expect } from "chai";
import hre, { ethers } from "hardhat";

const { getSigners, constants } = ethers;

const toBN = (num: any) => BigNumber.from(num);

let user1: SignerWithAddress;
let user2: SignerWithAddress;
let user3: SignerWithAddress;

let SignatureValidator: ContractFactory;
let signatureValidator: Contract;
let MultiSig: ContractFactory;
let multiSig: Contract;

const TEST_MESSAGE = web3.utils.sha3("MyTestMessageExample");

describe("SignatureValidator", () => {
  beforeEach(async () => {
    await hre.network.provider.send("hardhat_reset");

    [user1, user2, user3] = await getSigners();

    SignatureValidator = await ethers.getContractFactory("SignatureValidator");
    signatureValidator = await SignatureValidator.deploy(constants.AddressZero);

    MultiSig = await ethers.getContractFactory("MultiSig");
    multiSig = await MultiSig.deploy([user1.address, user2.address, user3.address]);

    await signatureValidator.setMultiSigAdd(multiSig.address);
    console.log("user1.address", user1.address);
    console.log("user2.address", user2.address);
    console.log("user3.address", user3.address);
    console.log("signatureValidator.address", signatureValidator.address);
    console.log("multiSig.address", multiSig.address);
  });

  describe("Should verify the constructor inputs", () => {
    it("Should verify the signers", async () => {
      const signers = [user1.address, user2.address, user3.address];
      for (let i = 0; i < signers.length; i++) {
        const isValid = await multiSig.signers(signers[i]);
        expect(isValid).to.be.equal(true);
      }
    });

    it("Should verify the multisig address", async () => {
      const multiSigAdd = await signatureValidator.multiSigAdd();
      expect(multiSigAdd).to.be.equal(multiSig.address);
    });
  });

  describe("Should verify signatures", () => {
    it("Should allow to submit approvals of messages", async () => {
      const signers = [user1, user2, user3];
      for (let i = 0; i < signers.length; i++) {
        await multiSig.connect(signers[i]).approveMessage(TEST_MESSAGE);
        const alreadyApproved = await multiSig.alreadyApproved(signers[i].address, TEST_MESSAGE);
        expect(alreadyApproved).to.be.equal(true);
      }
      const numberApprovals = await multiSig.signedMessages(TEST_MESSAGE);
      expect(numberApprovals).to.be.equal(signers.length);
    });

    it.only("should return magic value if enough owners signed and allow a mix different signature types", async () => {
      const [validator, signerSafe] = [signatureValidator, multiSig];
      console.log("await chainId(): ", await chainId());
      const dataHash = ethers.utils.keccak256("0xbaddad");
      const typedDataSig = {
        signer: user1.address,
        data: await user1._signTypedData(
          { verifyingContract: validator.address, chainId: await chainId() },
          EIP712_SAFE_MESSAGE_TYPE,
          { message: dataHash }
        ),
      };
      extractSignatureComponents(typedDataSig.data, "typedData");

      // =================================================================
      console.log(
        "calculateSafeMessageHash(validator, dataHash, await chainId()): ",
        calculateSafeMessageHash(validator, dataHash, await chainId())
      );
      const ethSignSig = await signHash(user2, calculateSafeMessageHash(validator, dataHash, await chainId()));
      extractSignatureComponents(ethSignSig.data, "ethSignSig");
      // =================================================================
      const validatorPreImageMessage = preimageSafeMessageHash(validator, dataHash, await chainId());

      const signerSafeMessageHash = calculateSafeMessageHash(signerSafe, validatorPreImageMessage, await chainId());
      const signerSafeOwnerSignature = await signHash(user1, signerSafeMessageHash);
      const signerSafeSig = buildContractSignature(signerSafe.address, signerSafeOwnerSignature.data);
      extractSignatureComponents(signerSafeSig.data, "signerSafeSig");

      const finalSignature = buildSignatureBytes([typedDataSig, ethSignSig, signerSafeSig]);

      console.log("dataHash: ", dataHash);
      console.log("typedDataSig: ", typedDataSig);
      console.log("ethSignSig: ", ethSignSig);
      console.log("validatorPreImageMessage: ", validatorPreImageMessage);
      console.log("signerSafeMessageHash: ", signerSafeMessageHash);
      console.log("signerSafeOwnerSignature: ", signerSafeOwnerSignature);
      console.log("signerSafeSig: ", signerSafeSig);
      console.log("finalSignature: ", finalSignature);
      console.log("END");

      expect(await validator.callStatic["isValidSignature(bytes32,bytes)"](dataHash, finalSignature)).to.be.eq(
        "0x1626ba7e"
      );
    });
  });
});

export const chainId = async () => {
  return (await hre.ethers.provider.getNetwork()).chainId;
};

function extractSignatureComponents(signature: string, name: string) {
  const r = "0x" + signature.slice(2, 66);
  console.log(name, "r: ", r);
  const s = "0x" + signature.slice(66, 130);
  console.log(name, "s: ", s);
  const v = parseInt(signature.slice(130, 132), 16);
  console.log(name, "v: ", v);
  return { v, r, s };
}
