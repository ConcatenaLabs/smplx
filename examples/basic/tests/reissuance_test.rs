//! Reissuance from an explicit reissuance token, Sequentia's default.
//!
//! A reissuance input carries a nonce that marks it as a reissuance rather than a new issuance.
//! For a confidential token that nonce is the token's asset blinding factor; for an explicit token
//! the node accepts any non-null value. The signer writes a fixed non-null nonce for an explicit
//! token, and never chooses the token, or an asset the transaction creates, as the fee asset.
//!
//! The same reissuance with a null nonce is read by the node as a new issuance of an asset nobody
//! declared, and a block holding it is refused with `bad-txns-in-ne-out`.

mod common;

use simplex::signer::SignerError;
use simplex::simplicityhl::elements::secp256k1_zkp::Tweak;
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

use common::{accepted, refused, sign_wallet_inputs};

#[simplex::test]
fn reissuance_test(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let utils = context.get_network_utils();
    let fee_rate = context.get_default_provider().fetch_fee_rate(1)?;
    let seq = context.get_network().policy_asset();
    let me = signer.get_address().script_pubkey();

    // An asset of 1,000 atoms with one explicit reissuance token.
    let mut funding = signer.get_utxos_asset(seq)?;
    funding.sort_by_key(|coin| std::cmp::Reverse(coin.amount()));
    let mut issuance = FinalTransaction::new();
    let issued = issuance.add_issuance_input(
        PartialInput::new(funding[0].clone()),
        IssuanceInput::new_issuance(1_000, 1, [9; 32]),
        RequiredSignature::NativeEcdsa,
    );
    issuance.add_output(PartialOutput::new(me.clone(), 1_000, issued.asset_id));
    issuance.add_output(PartialOutput::new(me.clone(), 1, issued.inflation_asset_id));
    signer.broadcast(&issuance)?.wait()?;

    let token = signer.get_utxos_asset(issued.inflation_asset_id)?.remove(0);
    anyhow::ensure!(
        token.txout.asset.is_explicit() && token.txout.value.explicit() == Some(1),
        "the token is explicit"
    );

    // Reissue 500, returning the token.
    let mut reissuance = FinalTransaction::new();
    reissuance.add_issuance_input(
        PartialInput::new(token.clone()),
        IssuanceInput::new_reissuance(500, issued.asset_entropy.to_byte_array()),
        RequiredSignature::NativeEcdsa,
    );
    reissuance.add_output(PartialOutput::new(me.clone(), 1, issued.inflation_asset_id));
    reissuance.add_output(PartialOutput::new(me.clone(), 500, issued.asset_id));

    // Named, the signer adds coins of the fee asset and signs.
    let payer = context
        .create_signer(&context.get_config().mnemonic)
        .with_fee_asset(seq);
    let (tx, fee) = payer.finalize(&reissuance)?;
    let nonce = tx.input[0].asset_issuance.asset_blinding_nonce;
    println!("reissuance from an explicit token: fee {fee}, nonce {nonce:?}");
    anyhow::ensure!(nonce != Tweak::from_inner([0; 32])?, "the nonce is null");
    accepted(&utils, "reissuance from an explicit token", &tx)?;

    // With no fee asset named, the token is not a candidate, nor is the asset reissued.
    let unnamed = signer.estimate_fee(&reissuance, fee_rate);
    println!("fee asset left to the signer: {unnamed:?}");
    anyhow::ensure!(
        matches!(unnamed, Err(SignerError::FeeAssetUnset(_))),
        "the signer chose a fee asset for a reissuance that moves only its token: {unnamed:?}"
    );

    let reissued: u64 = signer
        .get_utxos_asset(issued.asset_id)?
        .iter()
        .map(simplex::transaction::UTXO::amount)
        .sum();
    anyhow::ensure!(reissued == 1_500, "the signer holds {reissued} of the asset, not 1,500");
    let tokens = signer.get_utxos_asset(issued.inflation_asset_id)?;
    anyhow::ensure!(tokens.len() == 1 && tokens[0].amount() == 1, "the token came back");

    // The same reissuance with a null nonce, which the node reads as a new issuance.
    let token = tokens[0].clone();
    let fee_coin = {
        let mut coins = signer.get_utxos_asset(seq)?;
        coins.sort_by_key(|coin| std::cmp::Reverse(coin.amount()));
        coins.remove(0)
    };
    let mut by_hand = FinalTransaction::new();
    by_hand.add_issuance_input(
        PartialInput::new(token),
        IssuanceInput::new_reissuance(500, issued.asset_entropy.to_byte_array()),
        RequiredSignature::NativeEcdsa,
    );
    by_hand.add_input(PartialInput::new(fee_coin.clone()), RequiredSignature::NativeEcdsa);
    by_hand.add_output(PartialOutput::new(me.clone(), 1, issued.inflation_asset_id));
    by_hand.add_output(PartialOutput::new(me.clone(), 500, issued.asset_id));
    by_hand.add_output(PartialOutput::new(me.clone(), fee_coin.amount() - 1_000, seq));
    by_hand.add_output(PartialOutput::new(
        simplex::simplicityhl::elements::Script::new(),
        1_000,
        seq,
    ));

    let (pst, _) = by_hand.extract_pst();
    let mut null = pst.clone();
    null.inputs_mut()[0].issuance_blinding_nonce = Some(Tweak::from_inner([0; 32])?);
    refused(
        &utils,
        "reissuance with a null nonce",
        &sign_wallet_inputs(signer, null)?,
        "bad-txns-in-ne-out",
    )?;

    // The control: the same transaction as the signer builds it, nonce and all, is mined.
    accepted(
        &utils,
        "the same reissuance with the signer's nonce",
        &sign_wallet_inputs(signer, pst)?,
    )?;

    Ok(())
}
