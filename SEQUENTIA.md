# Simplex on Sequentia

This repository is Simplex, Blockstream Research's framework for Simplicity
contracts, with support for [Sequentia](https://github.com/ConcatenaLabs/Sequentia):
a Bitcoin sidechain for asset tokenization and disintermediated exchanges, forked
from Elements, on which Simplicity is active. Everything in the upstream
[README](README.md) holds; this page covers what is different on Sequentia and how
to use it.

The history is upstream's, unaltered, with a small set of commits on top. Some are
generic (a fee-asset setting, an RPC-only provider, configurable regtest binaries,
a nextest fallback) and some are specific to Sequentia (the patched `elements`, the
networks, the regtest chain).

## What differs on Sequentia

| Area | On Sequentia |
|---|---|
| Transaction encoding | A Sequentia issuance carries one more byte than an Elements one, the asset's denomination. The workspace patches crates.io `elements` to the rust-elements that [SWK](https://github.com/ConcatenaLabs/SWK) vendors, with its `sequentia` feature on, so every transaction parses and serialises as the node does. A build of this repository speaks Sequentia's encoding only |
| Networks | `SimplicityNetwork::SequentiaTestnet` (address prefixes `tb` and, for confidential addresses, `tsqb`) and `SimplicityNetwork::SequentiaRegtest { policy_asset, genesis_hash }` for a local chain. The mainnet is not defined: its genesis is a placeholder until it launches |
| Fees | Fees are payable in any asset the node accepts. The signer pays in the asset set with `Signer::with_fee_asset`, or else in the one asset a transaction moves; when a transaction moves several assets and none is set, it refuses. No asset, the policy asset included, is a fallback. The fee is computed in the node's reference unit and converted at the node's exchange rate for that asset, rounding up; the rate comes from `Signer::with_fee_exchange_rate` or from the provider. Fees are charged on full weight, as a Sequentia node does by default |
| Change | Explicit. It is blinded only when the transaction spends a confidential input and has no other blinded output, because it cannot balance otherwise. An output is confidential only when the holder asks for it with a blinding key |
| Local chain | `sequentiad` runs two nodes: a Bitcoin-mode regtest parent and an `elementsregtest` custom chain anchored to it, so headers carry a Bitcoin anchor as on every live chain. Simplicity is active from genesis, addresses are unblinded and the open fee market is on. The chain is read over the node's RPC alone; no indexer runs |

## Using it in a project

Depend on this repository and declare the same patch. A `[patch]` applies only in
the workspace that declares it, so a project that leaves it out fails to build: the
crates.io `elements` has no `sequentia` feature.

```toml
[dependencies]
smplx-std = { git = "https://github.com/ConcatenaLabs/smplx" }

[patch.crates-io]
elements = { git = "https://github.com/ConcatenaLabs/SWK", rev = "87a9f5e7f98356a2c00712884019079566aacfec" }
```

The patch must name the same SWK commit as this repository's `Cargo.toml`.

In `Simplex.toml`, select the Sequentia chain for `simplex regtest` and `simplex test`:

```toml
[regtest]
chain = "sequentia"
node_bin = "/path/to/sequentiad"   # optional; default: sequentiad on PATH
```

`simplex test` then starts a fresh chain for each test, funds the configured
mnemonic with the chain's policy asset, mines a block after every broadcast, and
stops both nodes and deletes their data when the test ends. Data directories are
created under `target/simplex`, or under `SIMPLEX_REGTEST_DIR` when it is set.

`simplex regtest` keeps such a chain running and prints its RPC address and
credentials. To point `simplex test` at a node that is already running, give
`[test.rpc]` and no `[test.esplora]`; the chain's genesis and policy asset are read
from the node.

```toml
[test.rpc]
url = "<rpc url>"
username = "<rpc user>"
password = "<rpc password>"
```

A test that moves more than one asset names its fee asset:

```rust
let signer = context.random_signer().with_fee_asset(asset);
```

## Running the example

`examples/basic` is configured for a local Sequentia chain. One command builds the
`simplex` command line from this checkout and runs the example's tests:

```sh
scripts/sequentia-example.sh /path/to/Sequentia/src/sequentiad
```

It needs a `sequentiad` (built from the
[node repository](https://github.com/ConcatenaLabs/Sequentia), or from a Sequentia
Core release) and `cargo-nextest`. The two tests pay to a one-key Simplicity
program and spend it, then issue an asset and move confidential outputs.

## Things to know before writing a contract

The node's [Simplicity page](https://github.com/ConcatenaLabs/Sequentia/blob/master/doc/sequentia/simplicity.md)
covers the witness layout, the budget, the annex rule, activation on each chain and
the traps. Two of
the traps bite contracts written here:

- `jet::lbtc_asset()` returns Liquid's asset id, which names nothing on Sequentia.
- The four relative-timelock jets read the largest lock over every input, so a
  spender defeats them with an old coin of their own. Read the input's own
  sequence instead.

[`sequentia-contracts`](https://github.com/ConcatenaLabs/sequentia-contracts)
lints both, and carries the audited helpers and the contract descriptor.
