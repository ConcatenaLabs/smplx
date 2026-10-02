//! Change and dust, in three fee assets valued differently by the node.
//!
//! The node calls an explicit output dust when it is worth less than spending it would cost at
//! the dust relay fee: `ceil(dust_relay_fee × (output size + 67) / 1000)` reference units for a
//! witness output, converted into the output's asset at the node's exchange rate. The signer keeps
//! change at or above that threshold, in the fee asset's own atoms, and adds change below it to
//! the fee. Each case is checked against the node: the change the signer keeps relays, and a
//! change one atom smaller is refused by the mempool as `dust`.
//!
//! Dust is a relay rule, not a consensus one: a block holding a dust output is valid. So these
//! refusals are asked of the mempool only, and every transaction the signer builds is also mined.

mod common;

use simplex::signer::Signer;
use simplex::simplicityhl::elements::{AssetId, Script, Transaction};
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature, UTXO};

use common::{accepted, coins_of, not_relayed, relayed, set_fee_rate, sign_wallet_inputs};

/// The scale of the node's exchange rates: an asset whose rate is this is valued at par.
const PAR: u64 = 100_000_000;

/// Pays `count` coins of `amount` of `asset` to the signer, in one transaction.
fn coins(signer: &Signer, asset: AssetId, amount: u64, count: usize) -> anyhow::Result<Vec<UTXO>> {
    let mut ft = FinalTransaction::new();
    for _ in 0..count {
        ft.add_output(PartialOutput::new(signer.get_address().script_pubkey(), amount, asset));
    }
    signer.broadcast(&ft)?.wait()?;

    let coins = coins_of(signer, asset, amount)?;
    anyhow::ensure!(
        coins.len() >= count,
        "expected {count} coins of {amount}, found {}",
        coins.len()
    );

    Ok(coins)
}

/// Issues `amount` of a new asset to the signer, with no reissuance token.
fn issue(signer: &Signer, amount: u64, entropy: [u8; 32]) -> anyhow::Result<AssetId> {
    let policy = signer.get_provider()?.get_network().policy_asset();
    let mut funding = signer.get_utxos_asset(policy)?;
    funding.sort_by_key(|coin| std::cmp::Reverse(coin.amount()));

    let mut ft = FinalTransaction::new();
    let issued = ft.add_issuance_input(
        PartialInput::new(funding[0].clone()),
        IssuanceInput::new_issuance(amount, 0, entropy),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        amount,
        issued.asset_id,
    ));
    signer.broadcast(&ft)?.wait()?;

    Ok(issued.asset_id)
}

/// A spend of `coin` paying `pay` of its asset to `to`; the signer adds change and fee.
fn spend(coin: &UTXO, to: &Script, pay: u64) -> FinalTransaction {
    let mut ft = FinalTransaction::new();
    ft.add_input(PartialInput::new(coin.clone()), RequiredSignature::NativeEcdsa);
    ft.add_output(PartialOutput::new(to.clone(), pay, coin.asset()));
    ft
}

/// The same spend built by hand: `change` back to the signer and the rest as the fee.
fn by_hand(signer: &Signer, coin: &UTXO, to: &Script, pay: u64, change: u64) -> anyhow::Result<Transaction> {
    let asset = coin.asset();
    let mut ft = spend(coin, to, pay);
    ft.add_output(PartialOutput::new(signer.get_address().script_pubkey(), change, asset));
    ft.add_output(PartialOutput::new(Script::new(), coin.amount() - pay - change, asset));

    sign_wallet_inputs(signer, ft.extract_pst().0)
}

/// The amounts of `tx`'s outputs, in order, with the fee output last.
fn amounts(tx: &Transaction) -> Vec<u64> {
    tx.output
        .iter()
        .map(|output| output.value.explicit().unwrap_or(0))
        .collect()
}

/// The signer's spend of `coin` that leaves `surplus` atoms beyond the fee it needs with change.
/// At or above `threshold` the surplus is kept as change; below it, it joins the fee.
fn check_surplus(
    signer: &Signer,
    utils: &simplex::NetworkUtils,
    coin: &UTXO,
    to: &Script,
    fee_rate: f32,
    surplus: u64,
    threshold: u64,
) -> anyhow::Result<()> {
    let probe = signer.estimate_spend(&spend(coin, to, coin.amount() / 2), fee_rate)?;
    anyhow::ensure!(probe.change, "a spend of half the coin keeps change");

    let pay = coin.amount() - probe.fee - surplus;
    let (tx, fee) = signer.finalize_strict(&spend(coin, to, pay), fee_rate)?;
    let what = format!("surplus {surplus} (threshold {threshold}): outputs {:?}", amounts(&tx));

    if surplus >= threshold {
        anyhow::ensure!(
            amounts(&tx) == vec![pay, surplus, probe.fee],
            "{what}: expected [{pay}, {surplus} change, {} fee]",
            probe.fee
        );
        anyhow::ensure!(tx.output[1].script_pubkey == signer.get_address().script_pubkey());
    } else {
        anyhow::ensure!(
            amounts(&tx) == vec![pay, coin.amount() - pay],
            "{what}: expected no change and the surplus in the fee"
        );
        anyhow::ensure!(fee == coin.amount() - pay);
    }

    accepted(utils, &what, &tx)?;

    Ok(())
}

/// The node's threshold for `coin`'s asset, found from the node: a change of `threshold` atoms
/// relays and one of `threshold - 1` is dust.
fn check_threshold(
    signer: &Signer,
    utils: &simplex::NetworkUtils,
    coin: &UTXO,
    to: &Script,
    threshold: u64,
) -> anyhow::Result<()> {
    let pay = coin.amount() / 2;

    relayed(
        utils,
        &format!("a change of {threshold} atoms, by hand"),
        &by_hand(signer, coin, to, pay, threshold)?,
    )?;
    if threshold > 1 {
        not_relayed(
            utils,
            &format!("a change of {} atoms, by hand", threshold - 1),
            &by_hand(signer, coin, to, pay, threshold - 1)?,
            "dust",
        )?;
    }

    Ok(())
}

/// The fee asset valued at par, as the chain's seed rate values its policy asset: the threshold
/// for a P2WPKH change is ceil(100 × (66 + 67) / 1000) = 14 atoms.
#[simplex::test]
fn change_at_par(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let utils = context.get_network_utils();
    let to = context.random_signer().get_address().script_pubkey();
    let fee_rate = context.get_default_provider().fetch_fee_rate(1)?;
    let seq = context.get_network().policy_asset();

    let coins = coins(signer, seq, 100_000, 4)?;

    check_threshold(signer, &utils, &coins[0], &to, 14)?;
    for (coin, surplus) in coins[1..].iter().zip([12, 13, 14]) {
        check_surplus(signer, &utils, coin, &to, fee_rate, surplus, 14)?;
    }

    Ok(())
}

/// An asset worth 1,000 reference units an atom: the threshold is one atom, so a spend with ten
/// atoms beyond its payment keeps nine as change and pays a one-atom fee.
#[simplex::test]
fn change_in_a_dear_asset(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let utils = context.get_network_utils();
    let to = context.random_signer().get_address().script_pubkey();
    let fee_rate = context.get_default_provider().fetch_fee_rate(1)?;

    let gold = issue(signer, 10_000_000, [7; 32])?;
    set_fee_rate(&utils, gold, 1_000 * PAR)?;
    let coins = coins(signer, gold, 1_000, 2)?;

    let (tx, fee) = signer.finalize_strict(&spend(&coins[0], &to, 990), fee_rate)?;
    println!(
        "dear asset, ten atoms over the payment: outputs {:?}, fee {fee}",
        amounts(&tx)
    );
    anyhow::ensure!(
        amounts(&tx) == vec![990, 9, 1],
        "expected [990] [9 change] [1 fee], got {:?}",
        amounts(&tx)
    );
    accepted(&utils, "dear asset: [990] [9 change] [1 fee]", &tx)?;
    check_threshold(signer, &utils, &coins[1], &to, 1)?;

    Ok(())
}

/// An asset worth a hundredth of a reference unit an atom: the threshold is 1,400 atoms.
#[simplex::test]
fn change_in_a_cheap_asset(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let utils = context.get_network_utils();
    let to = context.random_signer().get_address().script_pubkey();
    let fee_rate = context.get_default_provider().fetch_fee_rate(1)?;

    let lead = issue(signer, 100_000_000, [8; 32])?;
    set_fee_rate(&utils, lead, PAR / 100)?;
    let coins = coins(signer, lead, 1_000_000, 3)?;

    check_threshold(signer, &utils, &coins[0], &to, 1_400)?;
    check_surplus(signer, &utils, &coins[1], &to, fee_rate, 1_399, 1_400)?;
    check_surplus(signer, &utils, &coins[2], &to, fee_rate, 1_400, 1_400)?;

    Ok(())
}
