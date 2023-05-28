import { Contract, Wallet, utils, BigNumber, BigNumberish, Signer, PopulatedTransaction } from "ethers";
import { TypedDataSigner } from "@ethersproject/abstract-signer";
import { AddressZero } from "@ethersproject/constants";

export const EIP_DOMAIN = {
  EIP712Domain: [
    { type: "uint256", name: "chainId" },
    { type: "address", name: "verifyingContract" },
  ],
};

export const EIP712_SAFE_TX_TYPE = {
  // "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
  SafeTx: [
    { type: "address", name: "to" },
    { type: "uint256", name: "value" },
    { type: "bytes", name: "data" },
    { type: "uint8", name: "operation" },
    { type: "uint256", name: "safeTxGas" },
    { type: "uint256", name: "baseGas" },
    { type: "uint256", name: "gasPrice" },
    { type: "address", name: "gasToken" },
    { type: "address", name: "refundReceiver" },
    { type: "uint256", name: "nonce" },
  ],
};

export const EIP712_SAFE_MESSAGE_TYPE = {
  // "SafeMessage(bytes message)"
  SafeMessage: [{ type: "bytes", name: "message" }],
};

export interface MetaTransaction {
  to: string;
  value: string | number | BigNumber;
  data: string;
  operation: number;
}

export interface SafeTransaction extends MetaTransaction {
  safeTxGas: string | number;
  baseGas: string | number;
  gasPrice: string | number;
  gasToken: string;
  refundReceiver: string;
  nonce: string | number;
}

export interface SafeSignature {
  signer: string;
  data: string;
  // a flag to indicate if the signature is a contract signature and the data has to be appended to the dynamic part of signature bytes
  dynamic?: true;
}

export const calculateSafeDomainSeparator = (safe: Contract, chainId: BigNumberish): string => {
  return utils._TypedDataEncoder.hashDomain({ verifyingContract: safe.address, chainId });
};

export const preimageSafeMessageHash = (safe: Contract, message: string, chainId: BigNumberish): string => {
  return utils._TypedDataEncoder.encode({ verifyingContract: safe.address, chainId }, EIP712_SAFE_MESSAGE_TYPE, {
    message,
  });
};

export const calculateSafeMessageHash = (safe: Contract, message: string, chainId: BigNumberish): string => {
  return utils._TypedDataEncoder.hash({ verifyingContract: safe.address, chainId }, EIP712_SAFE_MESSAGE_TYPE, {
    message,
  });
};

export const safeSignTypedData = async (
  signer: Signer & TypedDataSigner,
  safe: Contract,
  safeTx: SafeTransaction,
  chainId?: BigNumberish
): Promise<SafeSignature> => {
  if (!chainId && !signer.provider) throw Error("Provider required to retrieve chainId");
  const cid = chainId || (await signer.provider!.getNetwork()).chainId;
  const signerAddress = await signer.getAddress();
  return {
    signer: signerAddress,
    data: await signer._signTypedData({ verifyingContract: safe.address, chainId: cid }, EIP712_SAFE_TX_TYPE, safeTx),
  };
};

export const signHash = async (signer: Signer, hash: string): Promise<SafeSignature> => {
  const typedDataHash = utils.arrayify(hash);
  const signerAddress = await signer.getAddress();
  return {
    signer: signerAddress,
    data: (await signer.signMessage(typedDataHash)).replace(/1b$/, "1f").replace(/1c$/, "20"),
  };
};

export const buildContractSignature = (signerAddress: string, signature: string): SafeSignature => {
  return {
    signer: signerAddress,
    data: signature,
    dynamic: true,
  };
};

export const buildSignatureBytes = (signatures: SafeSignature[]): string => {
  const SIGNATURE_LENGTH_BYTES = 65;
  signatures.sort((left, right) => left.signer.toLowerCase().localeCompare(right.signer.toLowerCase()));

  let signatureBytes = "0x";
  let dynamicBytes = "";
  for (const sig of signatures) {
    if (sig.dynamic) {
      /* 
                A contract signature has a static part of 65 bytes and the dynamic part that needs to be appended at the end of 
                end signature bytes.
                The signature format is
                Signature type == 0
                Constant part: 65 bytes
                {32-bytes signature verifier}{32-bytes dynamic data position}{1-byte signature type}
                Dynamic part (solidity bytes): 32 bytes + signature data length
                {32-bytes signature length}{bytes signature data}
            */
      const dynamicPartPosition = (signatures.length * SIGNATURE_LENGTH_BYTES + dynamicBytes.length / 2)
        .toString(16)
        .padStart(64, "0");
      const dynamicPartLength = (sig.data.slice(2).length / 2).toString(16).padStart(64, "0");
      const staticSignature = `${sig.signer.slice(2).padStart(64, "0")}${dynamicPartPosition}00`;
      const dynamicPartWithLength = `${dynamicPartLength}${sig.data.slice(2)}`;

      signatureBytes += staticSignature;
      dynamicBytes += dynamicPartWithLength;
    } else {
      signatureBytes += sig.data.slice(2);
    }
  }

  return signatureBytes + dynamicBytes;
};
