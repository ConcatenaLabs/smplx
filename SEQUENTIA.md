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
| Simplicity budget | A spend earns four weight units of execution budget per byte of its witness, plus 50, up to 4,000,050; Elements gives one. An annex of up to 100,000 bytes relays on a Simplicity leaf. The signer pads a program that costs more than its witness earns (see below) |
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

## Contracts with several leaves

A program built with `Program::new` pays to an output with one Simplicity leaf.
Most contracts need a tree: a program beside the data leaf that holds its
parameters, a tapscript exit with a delay beside a program, or several programs
under one output. `taptree::TapTree` describes the shape and
`taptree::ContractTree` fixes it under an internal key:

```rust
use simplex::taptree::{ContractTree, TapTree};

let tree = ContractTree::script_only(TapTree::branch(
    TapTree::branch(TapTree::simplicity("key", program), TapTree::data(&pk)),
    TapTree::tapscript("exit", exit_script),
))?;

let address = tree.address(network);
```

A leaf is a Simplicity program (leaf version `0xbe`), a tapscript (`0xc4`), or a
hidden node such as `TapTree::data`, the `TapData` hash a program reads back with
`jet::tappath`. `script_only` uses the internal key with no known discrete
logarithm, so the output has no key path; `ContractTree::new` takes any key.

A spend names its leaf:

- `tree.program("key")` is the program placed at its leaf. Spend it with a
  `ProgramInput` as any other program; its address and control block are the
  tree's.
- `tree.tapscript_input("exit", witness)` spends a tapscript leaf. `witness`
  lists what the script consumes, bottom of the stack first;
  `TapscriptWitness::Signature` is a signature by the input's key, which the
  signer fills in. Add it with `FinalTransaction::add_tapscript_input`, and set
  the input's sequence for a relative delay.

A program and its data leaf in one branch give the layout that
[`sequentia-contracts`](https://github.com/ConcatenaLabs/sequentia-contracts)
descriptors record: `jet::tappath(0)` is then the data leaf, wherever else the
branch sits. `examples/basic/tests/tree_test.rs` builds that branch with a
tapscript exit beside it and spends each leaf.

## The budget and padding

A Simplicity program carries a static bound on its cost, and a node runs it only
when that bound fits the budget its input's witness earns. Before it signs a
spend, the signer finalizes every program, compares each cost bound with the
budget its witness stack earns under the network's rule
(`SimplicityNetwork::simplicity_budget`), and pads a program that falls short
with the smallest annex that covers it: a last witness item tagged `0x50`, which
the program never reads. Beyond the largest annex that relays, it refuses the
spend with `SignerError::Budget`.

A full signature hash commits to every input's annex, so the signer fixes every
annex first and signs after: one pass learns each program's cost and size,
and, when one needs padding, a second signs with each annex in place.

To build a spend by hand, `ProgramTrait::finalize_spend` returns the witness
stack and the program's cost bound, and `BudgetRule::padding` the annex. Put the
annex in the input's `final_script_witness` before signing, so the signature
hash sees it, then append it to the stack. `examples/basic/tests/budget_test.rs`
does that for a program whose cost exceeds its unpadded budget: the spend is
refused without padding and one byte short of it, and accepted with it.

## Weight and fee before signing

`Signer::estimate_spend(&tx, fee_rate)` says what a spend will weigh and what
its fee will be, in atoms of the asset the fee is paid in, before the signer
makes the signatures that count. It works on a draft: the same inputs,
programs, padding and outputs, with placeholder amounts in the change and fee
outputs. Nothing whose size changes is left to signing: a Schnorr signature is
64 bytes, every ECDSA signature the signer makes is 71 with its sighash byte,
and a program's pruned form and padding do not depend on its signature. So
`finalize_strict(&tx, fee_rate)` returns a transaction of exactly the estimated
weight, with exactly the estimated fee, and the signer refuses one that would
weigh more than its fee was set for. The estimate also lists each Simplicity
input's cost bound, the budget its witness earns and its padding.

The fee rate is in the node's reference unit per 1,000 vbytes; the fee is that
amount converted into the fee asset at the node's exchange rate, rounded up.

## Running the example

`examples/basic` is configured for a local Sequentia chain. One command builds the
`simplex` command line from this checkout and runs the example's tests:

```sh
scripts/sequentia-example.sh /path/to/Sequentia/src/sequentiad
```

It needs a `sequentiad` (built from the
[node repository](https://github.com/ConcatenaLabs/Sequentia), or from a Sequentia
Core release) and `cargo-nextest`. The tests pay to a one-key Simplicity program
and spend it; issue an asset and move confidential outputs; pay to a tree with a
Simplicity leaf and a tapscript exit and spend it by each leaf, paying fees in
an asset they issue and checking each spend's estimate against the weight the
node reports; and spend a program that needs padding with and without it. Invalid spends are forced into
blocks as well as offered to the mempool, to show that consensus refuses them.

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
