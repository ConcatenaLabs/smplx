//! A contract tree with a Simplicity leaf and a tapscript exit, paid to and spent by each path on
//! a local chain. Each refused spend is forced into a block, so consensus refuses it and not only
//! the mempool's policy.
//!
//!     output = P2TR(NUMS, TapBranch(TapBranch(TapLeaf_0xbe(one_key), TapData(PK)),
//!                                   TapLeaf_0xc4(<EXIT_BLOCKS> CSV DROP <PK> CHECKSIG)))
//!
//! The program and its data leaf keep the fixed-root layout, so `jet::tappath(0)` is still the
//! data leaf; the exit sits one level up.

use simplex::simplicityhl::elements::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
use simplex::simplicityhl::elements::script::Builder;
use simplex::simplicityhl::elements::{Script, Sequence, Transaction};

use simplex::signer::Signer;
use simplex::taptree::{ContractTree, TapTree};
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature, TapscriptWitness, UTXO,
};

use simplex_example::artifacts::one_key::OneKeyProgram;
use simplex_example::artifacts::one_key::derived_one_key::{OneKeyArguments, OneKeyWitness};

/// The exit's relative delay, in blocks.
const EXIT_BLOCKS: u16 = 5;
/// What each payment to the tree carries.
const AMOUNT: u64 = 100_000;

fn exit_script(pk: &[u8; 32]) -> Script {
    Builder::new()
        .push_int(i64::from(EXIT_BLOCKS))
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_slice(pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn key_or_exit(signer: &Signer) -> anyhow::Result<ContractTree> {
    let pk = signer.get_schnorr_public_key().serialize();
    let one_key = OneKeyProgram::new(&OneKeyArguments {}).as_ref().clone();

    Ok(ContractTree::script_only(TapTree::branch(
        TapTree::branch(TapTree::simplicity("key", one_key), TapTree::data(&pk)),
        TapTree::tapscript("exit", exit_script(&pk)),
    ))?)
}

fn key_spend(tree: &ContractTree, signer: &Signer, coin: UTXO) -> anyhow::Result<FinalTransaction> {
    let witness = OneKeyWitness {
        pk: signer.get_schnorr_public_key().serialize(),
        sig: [0; 64],
    };
    let mut ft = FinalTransaction::new();

    ft.add_program_input(
        PartialInput::new(coin),
        ProgramInput::new(Box::new(tree.program("key")?), Box::new(witness)),
        RequiredSignature::Witness("SIG".to_string()),
    );

    Ok(ft)
}

fn exit_spend(tree: &ContractTree, coin: UTXO) -> anyhow::Result<FinalTransaction> {
    let mut ft = FinalTransaction::new();

    ft.add_tapscript_input(
        PartialInput::new(coin).with_sequence(Sequence::from_height(EXIT_BLOCKS)),
        tree.tapscript_input("exit", vec![TapscriptWitness::Signature])?,
    );

    Ok(ft)
}

/// Asks the mempool, then forces `tx` into a block; both must refuse it. Returns their messages.
fn refused(utils: &simplex::NetworkUtils, what: &str, tx: &Transaction) -> anyhow::Result<()> {
    let rpc = utils.rpc();
    let mempool = rpc.test_mempool_accept(tx)?;
    let block = rpc.generate_block_with(std::slice::from_ref(tx))?;

    println!("REFUSED {what}: mempool: {mempool:?}; block: {block:?}");
    anyhow::ensure!(mempool.is_err(), "{what}: the mempool accepted it");
    anyhow::ensure!(block.is_err(), "{what}: a block holding it was accepted");

    Ok(())
}

/// Forces `tx` into a block and requires the node to take it.
fn accepted(utils: &simplex::NetworkUtils, what: &str, tx: &Transaction) -> anyhow::Result<()> {
    let rpc = utils.rpc();

    rpc.test_mempool_accept(tx)?
        .map_err(|reason| anyhow::anyhow!("{what}: the mempool refused it: {reason}"))?;
    rpc.generate_block_with(std::slice::from_ref(tx))?
        .map_err(|reason| anyhow::anyhow!("{what}: the block was refused: {reason}"))?;

    let (weight, block) = rpc.transaction_weight(&tx.txid())?;
    anyhow::ensure!(block.is_some(), "{what}: not confirmed");
    println!(
        "ACCEPTED {what}: txid {}, weight {weight}, vsize {}",
        tx.txid(),
        tx.vsize()
    );

    Ok(())
}

#[simplex::test]
fn tree_test(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let provider = context.get_default_provider();
    let network = *context.get_network();
    let utils = context.get_network_utils();

    let tree = key_or_exit(signer)?;
    let script = tree.script_pubkey();
    println!("tree output {}", tree.address(&network));

    // Three coins in one payment, so they confirm in one block.
    let mut payment = FinalTransaction::new();
    for _ in 0..3 {
        payment.add_output(PartialOutput::new(script.clone(), AMOUNT, network.policy_asset()));
    }
    signer.broadcast(&payment)?.wait()?;
    let confirmed_at = utils.rpc().height()?;

    let mut coins = provider.fetch_scripthash_utxos(&script)?;
    coins.sort_by_key(|coin| coin.outpoint);
    anyhow::ensure!(
        coins.len() == 3,
        "expected three coins at the tree, found {}",
        coins.len()
    );

    // The Simplicity leaf.
    let (by_key, _) = signer.finalize(&key_spend(&tree, signer, coins[0].clone())?)?;
    let (other_coin, _) = signer.finalize(&key_spend(&tree, signer, coins[1].clone())?)?;

    // Another transaction's witness: a signature over a different coin's spend.
    let mut replayed = other_coin.clone();
    replayed.input[0].witness = by_key.input[0].witness.clone();
    refused(&utils, "key leaf with a signature over another transaction", &replayed)?;

    // The program revealed under the exit leaf's control block.
    let mut wrong_leaf = by_key.clone();
    let stack = &mut wrong_leaf.input[0].witness.script_witness;
    *stack.last_mut().unwrap() = tree.control_block("exit")?.serialize();
    refused(&utils, "key leaf under the exit's control block", &wrong_leaf)?;

    accepted(&utils, "key leaf", &by_key)?;

    // The tapscript exit, one block before its delay ends, then with a broken signature, then
    // once the delay has passed.
    utils.mine_until_height(confirmed_at + u64::from(EXIT_BLOCKS) - 2)?;
    let (early, _) = signer.finalize(&exit_spend(&tree, coins[2].clone())?)?;
    refused(&utils, "exit one block before its delay ends", &early)?;

    utils.mine_until_height(confirmed_at + u64::from(EXIT_BLOCKS) - 1)?;
    let (by_exit, _) = signer.finalize(&exit_spend(&tree, coins[2].clone())?)?;

    let mut forged = by_exit.clone();
    forged.input[0].witness.script_witness[0][0] ^= 0x01;
    refused(&utils, "exit with a broken signature", &forged)?;

    accepted(&utils, "exit leaf", &by_exit)?;

    Ok(())
}
