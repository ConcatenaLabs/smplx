# smplx-sdk

The `smplx-sdk` crate is a standalone set of modules of a larger [Smplx](https://github.com/BlockstreamResearch/smplx) framework that can be used separately to interact with Simplicity smart contracts. 

It also streamlines building, signing, and broadcasting transactions. This copy works with Sequentia networks only, and refuses Liquid and Elements networks: see [SEQUENTIA.md](https://github.com/ConcatenaLabs/smplx/blob/master/SEQUENTIA.md).

## Functionality

- `signer` - Securely parse BIP39 mnemonics, manage keys, sign transactions, and work with confidential addresses.
- `provider` - Connect to existing Sequentia nodes via RPC or Esplora APIs to query UTXOs, read fee exchange rates and broadcast transactions.
- `transaction` - High-level builder abstractions over `FinalTransaction`, `UTXO`, `PartialInput`, and `PartialOutput`.
- `program` - Load and interact with Simplicity (`.simf`) smart contracts.
- `taptree` - Taproot trees with several leaves: Simplicity programs, tapscripts and data leaves, with each leaf's control block and a spend that names its leaf.

The `smplx-sdk` can be used as a standalone SDK, however, check out [Smplx](https://github.com/BlockstreamResearch/smplx) for a complete Simplicity development experience.

## Features

By default, `smplx-sdk` is wasm-incompatible with provider functionality turned on. Disable a `provider` feature to make the SDK wasm-compatible.

## Quick Start

Read [simplex/README.md](https://github.com/BlockstreamResearch/smplx/blob/master/README.md).

## Disclaimer

Secure DeFi. On Bitcoin.
