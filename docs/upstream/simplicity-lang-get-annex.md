# `get_annex` reads an annex from a one-item witness stack

A report for the maintainers of the `simplicity-lang` crate (rust-simplicity), written here
because this repository opens nothing upstream. It is ready to be filed as an issue as it
stands.

## Summary

`simplicity-lang` builds the transaction environment a Simplicity program runs in, and the
`sig_all_hash` it signs, from a Rust transaction. For every input it reads the annex with
`get_annex` in `src/jet/elements/c_env.rs`:

```rust
/// If the last item in the witness stack is an annex, return the data following the 0x50 byte.
fn get_annex(in_witness: &elements::TxInWitness) -> Option<&[u8]> {
    let last_item = in_witness.script_witness.last()?;
    if *last_item.first()? == TAPROOT_ANNEX_PREFIX {
        Some(&last_item[1..])
    } else {
        None
    }
}
```

BIP 341 defines the annex as the last item of a witness stack **of at least two items** whose
first byte is `0x50`. The Elements interpreter, which builds the same environment on the node
side, applies that rule:

```cpp
if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) {
```

`get_annex` has no length condition, so it also reads an annex from a stack of one item. The two
sides then commit different annex sets to `sig_all_hash`, and a signature made with the Rust
library fails on the node.

The function is the same in versions 0.8.0 and 0.9.0.

## When it bites

A taproot key-path spend has a one-item witness: the 64- or 65-byte Schnorr signature. About one
signature in 256 starts with `0x50`. If a Simplicity input is signed while another input of the
same transaction already carries such a key-path signature, the Rust library hashes that
signature as the other input's annex and the node does not. The program's `bip_0340_verify` on
`sig_all_hash` then fails on the node with `Assertion failed inside jet`, in the mempool and in a
block alike.

The same transaction signed before the key-path witness is in place, or beside a key-path
signature that does not start with `0x50`, is accepted. A regtest test of all three cases is in
`examples/basic/tests/annex_test.rs`.

The lax reading also hides a second trap. A signer that puts each other input's annex in place
alone, as `[annex]`, before signing (the annex has to be there, since `sig_all_hash` commits to
every input's annex) gets a hash the node agrees with only because of this behaviour. Should the
library adopt the BIP 341 rule, every such signer would silently start producing signatures the
node refuses for transactions with more than one padded input.

## Reproduction

Two inputs: input 0 a Simplicity program, input 1 anything. Compute the environment for input 0
with input 1's witness set to `[sig]` where `sig` is 64 bytes starting `0x50`, and again with
input 1's witness empty. BIP 341 and the node give the same `sig_all_hash` for both; the library
gives two different ones. `the_signature_hash_reads_annexes_as_bip341_does` in
`crates/sdk/src/program/core.rs` is this test; with the work-around below removed it fails on its
first assertion.

## Suggested fix

Apply the BIP 341 condition in `get_annex`:

```rust
fn get_annex(in_witness: &elements::TxInWitness) -> Option<&[u8]> {
    let stack = &in_witness.script_witness;
    if stack.len() < 2 {
        return None;
    }
    let last_item = stack.last()?;
    if *last_item.first()? == TAPROOT_ANNEX_PREFIX {
        Some(&last_item[1..])
    } else {
        None
    }
}
```

A release note should say that a caller that placed a lone annex on another input before signing
must now place it after at least one other item.

## What this repository does meanwhile

It does not rely on either reading. Before it builds an environment, `bip341_annexes` in
`crates/sdk/src/program/core.rs` empties every witness stack of fewer than two items, so the
library sees exactly the annexes the node will. The input being signed may hold its own annex
alone, as a placeholder; that one is kept, behind an empty item, since a Simplicity spend always
has four items before its annex. The signer gives every input it has not signed yet the stack
`[placeholder, annex]`. Spends built this way hash the same under the current library and under
one that adopts the fix above.
