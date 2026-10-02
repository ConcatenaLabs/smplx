# Simplex on Sequentia

This repository is Simplex, Blockstream Research's framework for Simplicity
contracts, with support for [Sequentia](https://github.com/ConcatenaLabs/Sequentia):
a Bitcoin sidechain for asset tokenization and disintermediated exchanges, forked
from Elements, on which Simplicity is active. The upstream [README](README.md) describes Simplex;
this page covers what is different on Sequentia and how to use it.

This copy works with Sequentia networks only. It speaks Sequentia's transaction
encoding, which differs from Liquid's and Elements' in every issuance, so it would
read, sign and broadcast a Liquid or Elements transaction wrongly. The signer, the
providers, the test context, the regtest runner, the command line and the wasm
bindings refuse a Liquid or Elements network with a message that says so. Use
upstream Simplex for Liquid.

The history is upstream's, unaltered, with a small set of commits on top. Some are
generic (a fee-asset setting, an RPC-only provider, configurable regtest binaries,
a nextest fallback) and some are specific to Sequentia (the patched `elements`, the
networks, the regtest chain).

## What differs on Sequentia

| Area | On Sequentia |
|---|---|
| Transaction encoding | A Sequentia issuance carries one more byte than an Elements one, the asset's denomination. The workspace patches crates.io `elements` to the rust-elements that [SWK](https://github.com/ConcatenaLabs/SWK) vendors, with its `sequentia` feature on, so every transaction parses and serialises as the node does. A build of this repository speaks Sequentia's encoding only |
| Networks | `SimplicityNetwork::SequentiaTestnet` (address prefixes `tb` and, for confidential addresses, `tsqb`) and `SimplicityNetwork::SequentiaRegtest { policy_asset, genesis_hash }` for a local chain. The mainnet is not defined: its genesis is a placeholder until it launches. The Liquid and Elements variants remain in the enum so upstream code builds, and are refused at runtime (`SimplicityNetwork::require_sequentia`) |
| Which node | A node reached over RPC is identified by asking it, never by a configuration key: a Sequentia node answers `getfeeexchangerates`, which no Elements node has, and its genesis says whether it runs the testnet or a local chain. Any other node is refused (`RpcError::NotSequentia`) |
| Fees | Fees are payable in any asset the node accepts. The signer pays in the asset set with `Signer::with_fee_asset`, or else in the one asset a transaction moves; when a transaction moves several assets and none is set, it refuses. A reissuance token and an asset the transaction creates are never chosen. No asset, the policy asset included, is a fallback. The fee is computed in the node's reference unit, `ceil(rate × vsize / 1000)` in integers as the node computes it, and converted at the node's exchange rate for that asset, rounding up. Fees are charged on full weight, as a Sequentia node does by default |
| Exchange rates | The signer reads the node's rate at every quote through a provider that has the table: `RpcProvider`, or `SimplexProvider` through its node. On the testnet that means a Sequentia node's RPC; an Esplora indexer has no rate table, and a signer with only an `EsploraProvider` refuses fees with `SignerError::NoFeeExchangeRateSource`. `Signer::with_fee_exchange_rate` sets a rate by hand for ten minutes (`FEE_EXCHANGE_RATE_OVERRIDE_LIFETIME`; `with_fee_exchange_rate_for` takes another lifetime), after which a fee in that asset is refused with `SignerError::FeeExchangeRateExpired` until the rate is set again. In a browser build the SDK has no clock, and a rate set by hand does not age |
| Sends | No asset is a default, so a send names its asset: `Signer::send`, which assumes the policy asset, is refused with `SignerError::AssetUnnamed`. Use `Signer::send_asset` |
| Simplicity budget | A spend earns four weight units of execution budget per byte of its witness, plus 50, up to 4,000,050; Elements gives one. An annex of up to 100,000 bytes relays on a Simplicity leaf. The signer pads a program that costs more than its witness earns (see below) |
| Change | Explicit. It is blinded only when the transaction spends a confidential input and has no other blinded output, because it cannot balance otherwise. An output is confidential only when the holder asks for it with a blinding key. Change is kept when the node would relay it and added to the fee only when it would not: see below |
| Keys | The signer keeps contract keys apart from wallet keys. Its wallet keys, under `m/84h/{coin}h/0h`, hold its funding and change and sign its own inputs. Simplicity programs and tapscript leaves are signed with contract keys under `m/8383h/{coin}h/0h` (`CONTRACT_KEY_PURPOSE`); `Signer::get_schnorr_public_key` is the one at `0/0` there, and an input's `derivation_path` is read relative to whichever account its kind uses. A contract key signs the transaction's signature hash or a tagged hash of it; it signs a `SigMessage::Custom` message only for a program declared with `Program::with_custom_sig_message`, and refuses otherwise with `SignerError::CustomSigMessageUndeclared` |
| Reissuance | Explicit tokens, Sequentia's default, reissue: the input's nonce is the token's asset blinding factor for a confidential token and the fixed non-null value one for an explicit token (`EXPLICIT_TOKEN_REISSUANCE_NONCE`), which the node accepts as the reissuance flag. A null nonce would make the node read a new issuance |
| Issuance denomination | Every issuance made through this framework has denomination 8: see the limit below |
| Local chain | `sequentiad` runs two nodes: a Bitcoin-mode regtest parent and an `elementsregtest` custom chain anchored to it, so headers carry a Bitcoin anchor as on every live chain. Simplicity is active from genesis, addresses are unblinded and the open fee market is on. Scripts are checked on one thread, so a block the node refuses names the script failure rather than a bare `block-validation-failed`. The chain is read over the node's RPC alone; no indexer runs |

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

`chain = "sequentia"` is the default, and the only chain the runner starts:
`chain = "elements"`, upstream's `elementsd` and `electrs`, is refused.

`simplex regtest` keeps such a chain running and prints its RPC address and
credentials. To point `simplex test` at a node that is already running, give
`[test.rpc]`; the network is read from the node, whatever `[regtest]` says, and a
node that is not Sequentia's is refused. This is also how to run on the testnet:
point `[test.rpc]` at a testnet node, which supplies the fee exchange rates. An
`[test.esplora]` alone names its network, and the only one accepted is
`SequentiaTestnet`; with no node beside it, it has no exchange rates, so fees need
`with_fee_exchange_rate`.

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
  `TapscriptWitness::Signature` is a signature by the input's contract key, which the
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

The annex is read as BIP 341 and the node read it: the last item of a witness
stack of two or more items, when it starts with `0x50`. A stack of one item has no
annex, whatever its first byte, so a key-path signature that starts with `0x50` on
another input is not one. While the signer signs, an input not yet signed holds
`[placeholder, annex]`, and the environment a signature hash is computed in is
built by `program::bip341_annexes`, which applies that rule to every input. The
Simplicity library on its own reads any last item starting with `0x50` as an annex;
[docs/upstream/simplicity-lang-get-annex.md](docs/upstream/simplicity-lang-get-annex.md)
is the report on it.

To build a spend by hand, `ProgramTrait::finalize_spend` returns the witness
stack and the program's cost bound, and `BudgetRule::padding` the annex. Put each
input's annex in its `final_script_witness` before signing, so the signature hash
sees it: the input being signed may hold it alone, every other input as
`[placeholder, annex]`. Then append it to the stack. `examples/basic/tests/budget_test.rs`
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

## Change and dust

The node calls an explicit output dust when it is worth less than spending it
would cost at the dust relay fee: `ceil(dust_relay_fee × size / 1000)` reference
units, where `size` is the output's serialized size plus 67 bytes for a witness
program or 148 for any other script, converted into the output's asset at its
exchange rate, rounding up. The threshold is valued, not counted: for a P2WPKH
change at the default dust relay fee of 100 per 1,000 vbytes it is 14 atoms of an
asset at par, one atom of an asset worth a thousand reference units an atom, and
1,400 atoms of one worth a hundredth (`FeeAsset::dust_threshold`).

The signer keeps change at or above that threshold, and adds change below it, and
only below it, to the fee. So the change it keeps always relays, and no more than
the threshold's worth is ever given up. The node takes `-dustrelayfee` only as a
debug option and reports it over no RPC; the signer assumes the default, and
`Signer::with_dust_relay_fee` tells it another. Dust is a relay rule: a block
holding a dust output is valid. `examples/basic/tests/change_test.rs` checks each
threshold against the node, in three assets of different value.

## Parity with the node

The signer costs a program and sizes its padding with `simplicity-lang`'s Rust jet
table, and runs it with the C library `simplicity-sys` bundles; the node runs its
own copy of that library. The `Parity` workflow runs
[`sequentia-contracts`](https://github.com/ConcatenaLabs/sequentia-contracts)'
parity gate on this repository's `Cargo.lock` against the node's `src/simplicity`:
every C file, and every jet's name, cost and commitment root, must match. It also
runs `scripts/check-simplicity-pins.sh`, which requires `simplicityhl`,
`simplicity-lang` and `simplicity-sys` to be the versions `sequentia-contracts`
pins. To run both by hand, with the two repositories checked out beside this one:

```sh
python3 ../sequentia-contracts/parity/parity_gate.py --node ../Sequentia/src/simplicity --manifest-path Cargo.toml
scripts/check-simplicity-pins.sh Cargo.lock ../sequentia-contracts/Cargo.lock
```

## Limits

- **Issuance denomination.** A Sequentia issuance carries the asset's
  denomination, and the node reads it from the transaction, but a PSET has no
  field for it, so every issuance this framework builds has the default, 8. An
  issuer who wants another denomination builds the issuance outside the PSET path
  today. Lifting the limit needs a denomination on `IssuanceInput`, carried
  through the PSET in a proprietary field (or set on the extracted transaction
  before signing, since the signature hash commits to the issuance), and a test
  that a node reports the denomination chosen.

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
node reports; spend a program that needs padding with and without it, and two
padded programs beside a tapscript leaf in one transaction; sign a program beside
a key-path input whose signature starts with `0x50`; keep or give up change at the
node's dust threshold in three assets of different value; reissue from an explicit
token; and read the network from a node configured under another name. Invalid
spends are forced into blocks as well as offered to the mempool, to show that
consensus refuses them, and each refusal is checked for the reason it was meant to
have. Each signature is also offered where it must not count: over another coin, on
the other leaf of the tree, on another chain, and with its padding altered.

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
