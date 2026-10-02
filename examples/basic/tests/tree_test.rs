//! A contract tree with a Simplicity leaf and a tapscript exit, paid to and spent by each path on
//! a local chain. Each refused spend is forced into a block, so consensus refuses it and not only
//! the mempool's policy.
//!
//!     output = P2TR(NUMS, TapBranch(TapBranch(TapLeaf_0xbe(one_key), TapData(PK)),
//!                                   TapLeaf_0xc4(<EXIT_BLOCKS> CSV DROP <PK> CHECKSIG)))
//!
//! The program and its data leaf keep the fixed-root layout, so `jet::tappath(0)` is still the
//! data leaf; the exit sits one level up.
//!
//! Each signature is also offered where it must not count: over another coin, on the other leaf,
//! and on another chain. The node runs with one script-checking thread, so a refused block names
//! the script failure, and each refusal is checked for the reason it was meant to have.
//!
//! The coins are an asset the test issues, valued by the node at three reference units an atom,
//! and each spend pays its fee in that asset. The signer's estimate of each spend, made before it
//! signs, must equal the weight the node reports once the spend is confirmed, and its fee must be
//! the reference fee converted into the asset's own atoms.

use simplex::simplicityhl::elements::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
use simplex::simplicityhl::elements::script::Builder;
use simplex::simplicityhl::elements::{Script, Sequence, Transaction};

use simplex::provider::SimplicityNetwork;
use simplex::signer::{Signer, SignerTrait, SpendEstimate};
use simplex::simplicityhl::elements::AssetId;
use simplex::simplicityhl::elements::pset::PartiallySignedTransaction;
use simplex::taptree::{ContractTree, TapTree};
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature, SigMessage, TapscriptWitness, UTXO,
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

/// Asks the mempool, then forces `tx` into a block; both must refuse it, and the block for
/// `reason`. A refusal for any other reason fails the test: it would prove nothing.
fn refused(utils: &simplex::NetworkUtils, what: &str, tx: &Transaction, reason: &str) -> anyhow::Result<()> {
    let rpc = utils.rpc();
    let mempool = rpc.test_mempool_accept(tx)?;
    let block = rpc.generate_block_with(std::slice::from_ref(tx))?;

    println!("REFUSED {what}: mempool: {mempool:?}; block: {block:?}");
    anyhow::ensure!(mempool.is_err(), "{what}: the mempool accepted it");
    match block {
        Ok(_) => anyhow::bail!("{what}: a block holding it was accepted"),
        Err(message) => anyhow::ensure!(
            message.contains(reason),
            "{what}: the block was refused, but not for {reason:?}: {message}"
        ),
    }

    Ok(())
}

/// A partially signed copy of `tx`, carrying the outputs its inputs spend, from which a signature
/// over `tx` can be made again.
fn reopened(tx: &Transaction, spent: &[&UTXO]) -> PartiallySignedTransaction {
    let mut pst = PartiallySignedTransaction::from_tx(tx.clone());

    for (input, coin) in pst.inputs_mut().iter_mut().zip(spent) {
        input.witness_utxo = Some(coin.txout.clone());
    }

    pst
}

/// Forces `tx` into a block and requires the node to take it. Returns the weight the node reports.
fn accepted(utils: &simplex::NetworkUtils, what: &str, tx: &Transaction) -> anyhow::Result<u64> {
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

    Ok(weight)
}

/// The node's value of one atom of the issued asset, in reference units, and the exchange rate
/// that says so (atoms of the reference unit per 10^8).
const GOLD_VALUE: u64 = 3;
const GOLD_RATE: u64 = GOLD_VALUE * 100_000_000;

/// Issues an asset to the signer and has the node accept fees in it at `GOLD_RATE`.
fn issue_gold(signer: &Signer, utils: &simplex::NetworkUtils) -> anyhow::Result<AssetId> {
    let funding = signer.get_utxos_asset(signer.get_provider()?.get_network().policy_asset())?;
    let mut ft = FinalTransaction::new();

    let issued = ft.add_issuance_input(
        PartialInput::new(funding[0].clone()),
        IssuanceInput::new_issuance(10_000_000, 0, [7; 32]),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        10_000_000,
        issued.asset_id,
    ));
    signer.broadcast(&ft)?.wait()?;

    let rpc = utils.rpc();
    let mut rates = rpc.call("getfeeexchangerates", &[])?;
    rates[issued.asset_id.to_string()] = GOLD_RATE.into();
    rpc.call("setfeeexchangerates", &[rates, false.into()])?;

    Ok(issued.asset_id)
}

/// Estimates a spend, then signs it at the same fee rate, and checks that the fee is the
/// reference fee in the asset's own atoms.
fn estimated_and_signed(
    signer: &Signer,
    ft: &FinalTransaction,
    fee_rate: f32,
    gold: AssetId,
) -> anyhow::Result<(SpendEstimate, Transaction)> {
    let estimate = signer.estimate_spend(ft, fee_rate)?;
    let (tx, fee) = signer.finalize_strict(ft, fee_rate)?;

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]
    let reference_fee = (estimate.vsize as f32 * fee_rate / 1000.0).ceil() as u64;

    println!(
        "ESTIMATE weight {}, vsize {}, fee {} atoms of the fee asset ({reference_fee} reference units)",
        estimate.weight, estimate.vsize, estimate.fee
    );
    anyhow::ensure!(estimate.fee_asset == gold, "the fee is not paid in the asset moved");
    anyhow::ensure!(estimate.fee == fee, "estimated fee {} but signed {fee}", estimate.fee);
    anyhow::ensure!(
        fee == reference_fee.div_ceil(GOLD_VALUE),
        "fee {fee} is not {reference_fee} reference units in atoms worth {GOLD_VALUE}"
    );
    anyhow::ensure!(
        estimate.weight == tx.weight(),
        "estimated {} WU, signed {}",
        estimate.weight,
        tx.weight()
    );

    Ok((estimate, tx))
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

    let gold = issue_gold(signer, &utils)?;
    let fee_rate = provider.fetch_fee_rate(1)?;
    println!("fee rate {fee_rate} reference units per 1,000 vbytes");

    // Three coins in one payment, so they confirm in one block.
    let mut payment = FinalTransaction::new();
    for _ in 0..3 {
        payment.add_output(PartialOutput::new(script.clone(), AMOUNT, gold));
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
    let (key_estimate, by_key) =
        estimated_and_signed(signer, &key_spend(&tree, signer, coins[0].clone())?, fee_rate, gold)?;
    let (other_coin, _) = signer.finalize(&key_spend(&tree, signer, coins[1].clone())?)?;

    // Another transaction's witness: a signature over a different coin's spend.
    let mut replayed = other_coin.clone();
    replayed.input[0].witness = by_key.input[0].witness.clone();
    refused(
        &utils,
        "key leaf with a signature over another transaction",
        &replayed,
        "Assertion failed inside jet",
    )?;

    // The program revealed under the exit leaf's control block.
    let mut wrong_leaf = by_key.clone();
    let stack = &mut wrong_leaf.input[0].witness.script_witness;
    *stack.last_mut().unwrap() = tree.control_block("exit")?.serialize();
    refused(
        &utils,
        "key leaf under the exit's control block",
        &wrong_leaf,
        "Witness program hash mismatch",
    )?;

    // The other signatures over these coins, offered where they must not count. A signer with the
    // same keys on a chain with another genesis signs the key leaf; the exit leaf's signature over
    // a valid key-leaf spend stands in for the program's.
    let elsewhere = Signer::from_mnemonic(
        &context.get_config().mnemonic,
        SimplicityNetwork::SequentiaRegtest {
            policy_asset: network.policy_asset(),
            genesis_hash: SimplicityNetwork::SequentiaTestnet.genesis_block_hash(),
        },
    )
    .with_fee_exchange_rate(gold, GOLD_RATE);
    anyhow::ensure!(elsewhere.get_schnorr_public_key() == signer.get_schnorr_public_key());

    let (key_elsewhere, _) = elsewhere.finalize_strict(&key_spend(&tree, &elsewhere, coins[1].clone())?, fee_rate)?;
    refused(
        &utils,
        "key leaf signed for another chain",
        &key_elsewhere,
        "Assertion failed inside jet",
    )?;

    let pk = signer.get_schnorr_public_key().serialize();
    let mut exit_sig_on_key = other_coin.clone();
    let exit_sig = signer.sign_tapscript(
        &reopened(&other_coin, &[&coins[1]]),
        0,
        &exit_script(&pk),
        &network,
        None,
    )?;
    // The one-key program's witness is its two values, the key and then the signature.
    let program_witness = &mut exit_sig_on_key.input[0].witness.script_witness[0];
    anyhow::ensure!(
        program_witness.len() == 96 && program_witness[..32] == pk,
        "the program's witness is not the key and the signature"
    );
    program_witness[32..].copy_from_slice(&exit_sig.serialize());
    refused(
        &utils,
        "key leaf carrying the exit leaf's signature over the same transaction",
        &exit_sig_on_key,
        "Assertion failed inside jet",
    )?;

    let key_weight = accepted(&utils, "key leaf", &by_key)?;
    anyhow::ensure!(
        key_weight == key_estimate.weight as u64,
        "key leaf: the node reports {key_weight} WU"
    );

    // The tapscript exit, one block before its delay ends, then with a broken signature, then
    // once the delay has passed.
    utils.mine_until_height(confirmed_at + u64::from(EXIT_BLOCKS) - 2)?;
    let (early, _) = signer.finalize(&exit_spend(&tree, coins[2].clone())?)?;
    refused(
        &utils,
        "exit one block before its delay ends",
        &early,
        "bad-txns-nonfinal",
    )?;

    utils.mine_until_height(confirmed_at + u64::from(EXIT_BLOCKS) - 1)?;
    let (exit_estimate, by_exit) = estimated_and_signed(signer, &exit_spend(&tree, coins[2].clone())?, fee_rate, gold)?;

    let mut forged = by_exit.clone();
    forged.input[0].witness.script_witness[0][0] ^= 0x01;
    refused(
        &utils,
        "exit with a broken signature",
        &forged,
        "Invalid Schnorr signature",
    )?;

    let (exit_elsewhere, _) = elsewhere.finalize_strict(&exit_spend(&tree, coins[2].clone())?, fee_rate)?;
    refused(
        &utils,
        "exit signed for another chain",
        &exit_elsewhere,
        "Invalid Schnorr signature",
    )?;

    let mut key_sig_on_exit = by_exit.clone();
    let key_sig = signer.sign_program(
        &reopened(&by_exit, &[&coins[2]]),
        &tree.program("key")?,
        0,
        &network,
        None,
        &SigMessage::Sighash,
    )?;
    key_sig_on_exit.input[0].witness.script_witness[0] = key_sig.serialize().to_vec();
    refused(
        &utils,
        "exit carrying the key leaf's signature over the same transaction",
        &key_sig_on_exit,
        "Invalid Schnorr signature",
    )?;

    let exit_weight = accepted(&utils, "exit leaf", &by_exit)?;
    anyhow::ensure!(
        exit_weight == exit_estimate.weight as u64,
        "exit leaf: the node reports {exit_weight} WU"
    );

    Ok(())
}
