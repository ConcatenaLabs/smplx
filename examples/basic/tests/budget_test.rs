//! A program that costs more than its witness earns, spent on a local chain without padding, one
//! byte short of its padding, with exactly its padding, and as the signer pads it. Each refused
//! spend is forced into a block, so consensus refuses it and not only the mempool's policy.

use simplex::program::{BudgetRule, ProgramTrait, WitnessTrait};
use simplex::provider::SimplicityNetwork;
use simplex::signer::{Signer, SignerTrait};
use simplex::simplicityhl::elements::pset::PartiallySignedTransaction;
use simplex::simplicityhl::elements::{Script, Transaction};
use simplex::taptree::{ContractTree, TapTree};
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature, SigMessage, UTXO,
};

use simplex_example::artifacts::costly_key::CostlyKeyProgram;
use simplex_example::artifacts::costly_key::derived_costly_key::{CostlyKeyArguments, CostlyKeyWitness};

/// What each payment to the contract carries.
const AMOUNT: u64 = 100_000;
/// The fee of the spends built by hand, in the coin's own asset.
const FEE: u64 = 5_000;
/// The fee of the spends carrying the largest annex that relays.
const LARGE_FEE: u64 = 40_000;

fn costly_key(signer: &Signer) -> anyhow::Result<ContractTree> {
    let pk = signer.get_schnorr_public_key().serialize();
    let program = CostlyKeyProgram::new(&CostlyKeyArguments {}).as_ref().clone();

    Ok(ContractTree::script_only(TapTree::branch(
        TapTree::simplicity("costly", program),
        TapTree::data(&pk),
    ))?)
}

fn witness(signer: &Signer, sig: [u8; 64]) -> CostlyKeyWitness {
    CostlyKeyWitness {
        pk: signer.get_schnorr_public_key().serialize(),
        sig,
    }
}

/// The coin spent back to the signer with an explicit fee: the outputs are fixed, so the witness
/// is the only thing that changes between the variants below.
fn by_hand(tree: &ContractTree, signer: &Signer, coin: UTXO, fee: u64) -> anyhow::Result<PartiallySignedTransaction> {
    let asset = coin.asset();
    let mut ft = FinalTransaction::new();

    ft.add_program_input(
        PartialInput::new(coin),
        ProgramInput::new(Box::new(tree.program("costly")?), Box::new(witness(signer, [0; 64]))),
        RequiredSignature::Witness("SIG".to_string()),
    );
    ft.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        AMOUNT - fee,
        asset,
    ));
    ft.add_output(PartialOutput::new(Script::new(), fee, asset));

    Ok(ft.extract_pst().0)
}

/// Signs input 0 with `annex` in place (a full signature hash commits to it) and finalizes it.
/// Returns the transaction and the program's witness stack without the annex.
fn signed(
    tree: &ContractTree,
    signer: &Signer,
    network: &SimplicityNetwork,
    mut pst: PartiallySignedTransaction,
    annex: Option<&[u8]>,
) -> anyhow::Result<(Transaction, simplex::program::FinalizedSpend)> {
    let program = tree.program("costly")?;

    pst.inputs_mut()[0].final_script_witness = annex.map(|annex| vec![annex.to_vec()]);

    let sig = signer.sign_program(&pst, &program, 0, network, None, &SigMessage::Sighash)?;
    let values = witness(signer, sig.serialize()).build_witness();
    let spend = program.finalize_spend(&pst, &values, 0, network)?;

    let mut stack = spend.stack.clone();
    stack.extend(annex.map(<[u8]>::to_vec));
    pst.inputs_mut()[0].final_script_witness = Some(stack);

    Ok((pst.extract_tx()?, spend))
}

/// The node's message for a program that costs more than its witness earns.
const OVER_BUDGET: &str = "Program's execution cost could exceed budget";

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

fn accepted(utils: &simplex::NetworkUtils, what: &str, tx: &Transaction) -> anyhow::Result<u64> {
    let rpc = utils.rpc();

    rpc.test_mempool_accept(tx)?
        .map_err(|reason| anyhow::anyhow!("{what}: the mempool refused it: {reason}"))?;
    rpc.generate_block_with(std::slice::from_ref(tx))?
        .map_err(|reason| anyhow::anyhow!("{what}: the block was refused: {reason}"))?;

    let (weight, block) = rpc.transaction_weight(&tx.txid())?;
    anyhow::ensure!(block.is_some(), "{what}: not confirmed");
    println!("ACCEPTED {what}: weight {weight}, vsize {}", tx.vsize());

    Ok(weight)
}

#[simplex::test]
fn budget_test(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let provider = context.get_default_provider();
    let network = *context.get_network();
    let utils = context.get_network_utils();
    let rule: BudgetRule = network.simplicity_budget();

    let tree = costly_key(signer)?;
    let script = tree.script_pubkey();

    // Three coins in one payment, so they confirm in one block.
    let mut payment = FinalTransaction::new();
    for _ in 0..3 {
        payment.add_output(PartialOutput::new(script.clone(), AMOUNT, network.policy_asset()));
    }
    signer.broadcast(&payment)?.wait()?;

    let mut coins = provider.fetch_scripthash_utxos(&script)?;
    coins.sort_by_key(|coin| coin.outpoint);
    anyhow::ensure!(coins.len() == 3, "expected three coins, found {}", coins.len());

    // Unpadded: the program costs more than its witness earns.
    let pst = by_hand(&tree, signer, coins[0].clone(), FEE)?;
    let (unpadded, spend) = signed(&tree, signer, &network, pst.clone(), None)?;
    let plain = rule.report(spend.cost, &spend.stack);
    println!(
        "COST {} milli-WU; unpadded witness {} bytes earns {} WU",
        plain.cost_milliweight, plain.witness_bytes, plain.budget
    );
    anyhow::ensure!(
        !rule.covers(spend.cost, &spend.stack),
        "the program fits its unpadded budget"
    );
    refused(&utils, "unpadded", &unpadded, OVER_BUDGET)?;

    // The smallest annex that covers the cost, and one byte less.
    let annex = rule
        .padding(spend.cost, &spend.stack)?
        .expect("the program needs padding");
    let (short, _) = signed(&tree, signer, &network, pst.clone(), Some(&annex[..annex.len() - 1]))?;
    refused(
        &utils,
        &format!("annex of {} bytes, one short", annex.len() - 1),
        &short,
        OVER_BUDGET,
    )?;

    let (padded, padded_spend) = signed(&tree, signer, &network, pst, Some(&annex))?;
    let mut stack = padded_spend.stack.clone();
    stack.push(annex.clone());
    let report = rule.report(padded_spend.cost, &stack);
    println!(
        "PADDED annex {} bytes; witness {} bytes earns {} WU for a cost of {} milli-WU",
        report.annex_bytes, report.witness_bytes, report.budget, report.cost_milliweight
    );

    // The signature commits to the annex: padding altered after signing breaks it, so a relay
    // cannot strip or change the budget a spend paid for.
    let mut altered = padded.clone();
    let stack = &mut altered.input[0].witness.script_witness;
    *stack.last_mut().unwrap().last_mut().unwrap() ^= 0x01;
    refused(
        &utils,
        "annex altered after signing",
        &altered,
        "Assertion failed inside jet",
    )?;

    accepted(&utils, &format!("annex of {} bytes", annex.len()), &padded)?;

    // The signer pads by itself, with the same annex, and its estimate made before signing
    // counts the padding: it is the weight the node reports.
    let mut ft = FinalTransaction::new();
    ft.add_program_input(
        PartialInput::new(coins[1].clone()),
        ProgramInput::new(Box::new(tree.program("costly")?), Box::new(witness(signer, [0; 64]))),
        RequiredSignature::Witness("SIG".to_string()),
    );
    let fee_rate = provider.fetch_fee_rate(1)?;
    let estimate = signer.estimate_spend(&ft, fee_rate)?;
    let (by_signer, fee) = signer.finalize_strict(&ft, fee_rate)?;
    let carried = by_signer.input[0]
        .witness
        .script_witness
        .last()
        .cloned()
        .unwrap_or_default();
    anyhow::ensure!(
        carried == annex,
        "the signer padded with {} bytes, not {}",
        carried.len(),
        annex.len()
    );
    println!(
        "SIGNER padded with {} bytes; estimate: weight {}, fee {}, budgets {:?}",
        carried.len(),
        estimate.weight,
        estimate.fee,
        estimate.budgets
    );
    anyhow::ensure!(estimate.fee == fee, "estimated fee {} but signed {fee}", estimate.fee);
    anyhow::ensure!(
        estimate.budgets.first().map(|(_, budget)| budget.annex_bytes) == Some(annex.len()),
        "the estimate does not report the padding"
    );
    let weight = accepted(&utils, "padded by the signer", &by_signer)?;
    anyhow::ensure!(
        weight == estimate.weight as u64,
        "estimated {} WU, the node reports {weight}",
        estimate.weight
    );

    // The largest annex that relays, and one byte more: the limit is the mempool's, not consensus'.
    let pst = by_hand(&tree, signer, coins[2].clone(), LARGE_FEE)?;
    let mut largest = vec![0u8; rule.max_standard_annex];
    largest[0] = annex[0];
    let (at_limit, _) = signed(&tree, signer, &network, pst.clone(), Some(&largest))?;
    let at_limit_verdict = utils.rpc().test_mempool_accept(&at_limit)?;
    println!("MEMPOOL annex of {} bytes: {at_limit_verdict:?}", largest.len());
    anyhow::ensure!(at_limit_verdict.is_ok(), "the largest standard annex did not relay");

    largest.push(0);
    let (over_limit, _) = signed(&tree, signer, &network, pst, Some(&largest))?;
    let over_verdict = utils.rpc().test_mempool_accept(&over_limit)?;
    println!("MEMPOOL annex of {} bytes: {over_verdict:?}", largest.len());
    anyhow::ensure!(over_verdict.is_err(), "an annex above the limit relayed");
    accepted_in_block_only(&utils, &format!("annex of {} bytes", largest.len()), &over_limit)?;

    Ok(())
}

/// Forces into a block a transaction the mempool refuses, and requires the block to be accepted.
fn accepted_in_block_only(utils: &simplex::NetworkUtils, what: &str, tx: &Transaction) -> anyhow::Result<()> {
    let block = utils.rpc().generate_block_with(std::slice::from_ref(tx))?;

    println!("BLOCK {what}: {block:?}");
    anyhow::ensure!(block.is_ok(), "{what}: the block was refused");

    Ok(())
}
