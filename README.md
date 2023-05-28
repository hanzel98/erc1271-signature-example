# Example implementation of ERC1271 Signatures

## Explanation

In order to create a digital signature for use on Ethereum-based blockchains, you generally need a secret private key which no one else knows. This is what makes your signature, yours (no one else can create the same signature without knowledge of the secret key).

Your Ethereum account (i.e. your externally-owned account/EOA) has a private key associated with it, and this is the private key that’s typically used when a website or dapp asks you for a signature (e.g. for “Log in with Ethereum”).

An app can verify a signature(opens in a new tab)↗ you create using a third-party library like ethers.js without knowing your private key(opens in a new tab)↗ and be confident that you were the one that created the signature.

In fact, because EOA digital signatures use public-key cryptography, they can be generated and verified off-chain! This is how gasless DAO voting works — instead of submitting votes on-chain, digital signatures can be created and verified off-chain using cryptographic libraries.

While EOA accounts have a private key, smart contract accounts do not have any sort of private or secret key (so "Log in with Ethereum", etc. cannot natively work with smart contract accounts).

## Considerations

These contracts implement simple mechanisms for handling the signers because this is not the main purpose of the example.
