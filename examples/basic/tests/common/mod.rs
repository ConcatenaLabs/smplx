//! Helpers shared by the example tests: offering a transaction to the node and forcing it into a
//! block, with the reason for a refusal checked.

#![allow(dead_code)]

use simplex::signer::{Signer, SignerTrait};
use simplex::simplicityhl::elements::pset::PartiallySignedTransaction;
use simplex::simplicityhl::elements::{AssetId, Transaction};
use simplex::transaction::UTXO;

/// Asks the mempool, then forces `tx` into a block; both must refuse it, and the block for
/// `reason`. A refusal for any other reason fails the test: it would prove nothing.
pub fn refused(utils: &simplex::NetworkUtils, what: &str, tx: &Transaction, reason: &str) -> anyhow::Result<()> {
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

/// The mempool must refuse `tx` for `reason`, a relay rule that a block does not apply.
pub fn not_relayed(utils: &simplex::NetworkUtils, what: &str, tx: &Transaction, reason: &str) -> anyhow::Result<()> {
    let mempool = utils.rpc().test_mempool_accept(tx)?;

    println!("NOT RELAYED {what}: mempool: {mempool:?}");
    match mempool {
        Ok(()) => anyhow::bail!("{what}: the mempool accepted it"),
        Err(message) => anyhow::ensure!(
            message.contains(reason),
            "{what}: the mempool refused it, but not for {reason:?}: {message}"
        ),
    }

    Ok(())
}

/// The mempool must take `tx`; it is not mined.
pub fn relayed(utils: &simplex::NetworkUtils, what: &str, tx: &Transaction) -> anyhow::Result<()> {
    utils
        .rpc()
        .test_mempool_accept(tx)?
        .map_err(|reason| anyhow::anyhow!("{what}: the mempool refused it: {reason}"))?;
    println!("RELAYED {what}");

    Ok(())
}

/// The mempool must take `tx` and a block holding it must be accepted. Returns the weight the
/// node reports for it. The block is forced even when the mempool refuses, so a failure names
/// both reasons.
pub fn accepted(utils: &simplex::NetworkUtils, what: &str, tx: &Transaction) -> anyhow::Result<u64> {
    let rpc = utils.rpc();
    let mempool = rpc.test_mempool_accept(tx)?;
    let block = rpc.generate_block_with(std::slice::from_ref(tx))?;

    if mempool.is_err() || block.is_err() {
        anyhow::bail!("{what}: refused; mempool: {mempool:?}; block: {block:?}");
    }

    let (weight, block) = rpc.transaction_weight(&tx.txid())?;
    anyhow::ensure!(block.is_some(), "{what}: not confirmed");
    println!("ACCEPTED {what}: weight {weight}, vsize {}", tx.vsize());

    Ok(weight)
}

/// Signs every input of `pst` as a wallet input at the signer's own address.
pub fn sign_wallet_inputs(signer: &Signer, mut pst: PartiallySignedTransaction) -> anyhow::Result<Transaction> {
    for index in 0..pst.inputs().len() {
        let (public_key, signature) = signer.sign_input(&pst, index, None)?;
        let mut raw = signature.serialize_der().to_vec();
        raw.push(0x01);
        pst.inputs_mut()[index].final_script_witness = Some(vec![raw, public_key.to_bytes()]);
    }

    Ok(pst.extract_tx()?)
}

/// The signer's coins of `asset` worth exactly `amount`.
pub fn coins_of(signer: &Signer, asset: AssetId, amount: u64) -> anyhow::Result<Vec<UTXO>> {
    let mut coins: Vec<UTXO> = signer
        .get_utxos_asset(asset)?
        .into_iter()
        .filter(|coin| coin.amount() == amount)
        .collect();
    coins.sort_by_key(|coin| coin.outpoint);

    Ok(coins)
}

/// Sets the node's exchange rate for `asset`: atoms of the reference unit per 10^8 atoms of it.
pub fn set_fee_rate(utils: &simplex::NetworkUtils, asset: AssetId, rate: u64) -> anyhow::Result<()> {
    let rpc = utils.rpc();
    let mut rates = rpc.call("getfeeexchangerates", &[])?;
    rates[asset.to_string()] = rate.into();
    rpc.call("setfeeexchangerates", &[rates, false.into()])?;

    Ok(())
}
