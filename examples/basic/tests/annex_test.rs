//! Annexes and the signature hash.
//!
//! A full signature hash over a Simplicity input commits to the annex of every input. The node
//! reads an input's annex by BIP 341: the last item of a witness stack of two or more items,
//! when that item starts with `0x50`. A stack of one item has no annex, whatever its first byte;
//! a key-path signature is such a stack, and about one in 256 starts with `0x50`.
//!
//! - Two Simplicity inputs that each need padding, beside a tapscript input: the signer fixes
//!   every annex before it signs, and the node accepts the spend at the weight estimated.
//! - A Simplicity input signed beside a key-path input whose signature starts with `0x50`, with
//!   that signature already in the transaction: the signature hash the signer computes reads no
//!   annex there, as the node does, and the spend is accepted. So are the two controls: signed
//!   before the key-path signature is in place, and beside a key-path signature that does not
//!   start with `0x50`.

mod common;

use simplex::program::{ProgramTrait, WitnessTrait};
use simplex::signer::SignerTrait;
use simplex::simplicityhl::elements::hashes::Hash as _;
use simplex::simplicityhl::elements::opcodes::all::OP_CHECKSIG;
use simplex::simplicityhl::elements::schnorr::TapTweak;
use simplex::simplicityhl::elements::script::Builder;
use simplex::simplicityhl::elements::secp256k1_zkp::{Keypair, Message, Secp256k1};
use simplex::simplicityhl::elements::sighash::{Prevouts, SighashCache};
use simplex::simplicityhl::elements::{Address, SchnorrSighashType, Script};
use simplex::taptree::{ContractTree, TapTree};
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature, SigMessage, TapscriptWitness,
};

use simplex_example::artifacts::costly_key::CostlyKeyProgram;
use simplex_example::artifacts::costly_key::derived_costly_key::{CostlyKeyArguments, CostlyKeyWitness};
use simplex_example::artifacts::one_key::OneKeyProgram;
use simplex_example::artifacts::one_key::derived_one_key::{OneKeyArguments, OneKeyWitness};

use common::accepted;

const AMOUNT: u64 = 100_000;
const ANNEX_TAG: u8 = 0x50;

#[simplex::test]
fn two_padded_inputs_and_a_tapscript_leaf(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let provider = context.get_default_provider();
    let network = *context.get_network();
    let utils = context.get_network_utils();
    let seq = network.policy_asset();
    let pk = signer.get_schnorr_public_key().serialize();

    let costly = CostlyKeyProgram::new(&CostlyKeyArguments {}).as_ref().clone();
    let leaf = Builder::new().push_slice(&pk).push_opcode(OP_CHECKSIG).into_script();
    let tree = ContractTree::script_only(TapTree::branch(
        TapTree::branch(TapTree::simplicity("costly", costly), TapTree::data(&pk)),
        TapTree::tapscript("sig", leaf),
    ))?;
    let script = tree.script_pubkey();

    let mut payment = FinalTransaction::new();
    for _ in 0..3 {
        payment.add_output(PartialOutput::new(script.clone(), AMOUNT, seq));
    }
    signer.broadcast(&payment)?.wait()?;
    let mut coins = provider.fetch_scripthash_utxos(&script)?;
    coins.sort_by_key(|coin| coin.outpoint);
    anyhow::ensure!(coins.len() == 3, "expected three coins, found {}", coins.len());

    let mut ft = FinalTransaction::new();
    for coin in &coins[..2] {
        ft.add_program_input(
            PartialInput::new(coin.clone()),
            ProgramInput::new(
                Box::new(tree.program("costly")?),
                Box::new(CostlyKeyWitness { pk, sig: [0; 64] }),
            ),
            RequiredSignature::Witness("SIG".to_string()),
        );
    }
    ft.add_tapscript_input(
        PartialInput::new(coins[2].clone()),
        tree.tapscript_input("sig", vec![TapscriptWitness::Signature])?,
    );
    ft.add_output(PartialOutput::new(
        context.random_signer().get_address().script_pubkey(),
        250_000,
        seq,
    ));

    let fee_rate = provider.fetch_fee_rate(1)?;
    let estimate = signer.estimate_spend(&ft, fee_rate)?;
    let (tx, fee) = signer.finalize_strict(&ft, fee_rate)?;

    for (index, input) in tx.input.iter().enumerate() {
        let stack = &input.witness.script_witness;
        let last = stack.last().cloned().unwrap_or_default();
        println!(
            "input {index}: {} witness items, last item {} bytes, first byte {:02x}",
            stack.len(),
            last.len(),
            last.first().copied().unwrap_or(0)
        );
        if index < 2 {
            anyhow::ensure!(stack.len() == 5 && last[0] == ANNEX_TAG, "input {index} is padded");
        }
    }
    anyhow::ensure!(estimate.budgets.len() == 2, "two Simplicity inputs reported");
    anyhow::ensure!(estimate.fee == fee && estimate.weight == tx.weight());

    let weight = accepted(&utils, "two padded inputs and a tapscript leaf", &tx)?;
    anyhow::ensure!(
        weight == u64::try_from(estimate.weight)?,
        "estimated {} WU, the node reports {weight}",
        estimate.weight
    );

    Ok(())
}

#[simplex::test]
fn a_key_path_signature_is_not_an_annex(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let provider = context.get_default_provider();
    let network = *context.get_network();
    let utils = context.get_network_utils();
    let seq = network.policy_asset();
    let secp = Secp256k1::new();
    let pk = signer.get_schnorr_public_key().serialize();

    let one_key = OneKeyProgram::new(&OneKeyArguments {}).as_ref().clone();
    let tree = ContractTree::script_only(TapTree::branch(TapTree::simplicity("key", one_key), TapTree::data(&pk)))?;
    let program = tree.program("key")?;

    // A key-path P2TR coin at a key unrelated to the signer.
    let keypair = Keypair::from_seckey_slice(&secp, &[0x42; 32])?;
    let key_path = Address::p2tr(
        &secp,
        keypair.x_only_public_key().0,
        None,
        None,
        network.address_params(),
    );

    let run = |label: &str, key_path_first: bool, starts_with_tag: bool| -> anyhow::Result<()> {
        let mut payment = FinalTransaction::new();
        payment.add_output(PartialOutput::new(tree.script_pubkey(), AMOUNT, seq));
        payment.add_output(PartialOutput::new(key_path.script_pubkey(), AMOUNT, seq));
        signer.broadcast(&payment)?.wait()?;
        let simplicity_coin = provider
            .fetch_scripthash_utxos(&tree.script_pubkey())?
            .pop()
            .ok_or_else(|| anyhow::anyhow!("no coin at the program"))?;
        let key_path_coin = provider
            .fetch_scripthash_utxos(&key_path.script_pubkey())?
            .pop()
            .ok_or_else(|| anyhow::anyhow!("no coin at the key"))?;

        let mut ft = FinalTransaction::new();
        ft.add_program_input(
            PartialInput::new(simplicity_coin.clone()),
            ProgramInput::new(Box::new(program.clone()), Box::new(OneKeyWitness { pk, sig: [0; 64] })),
            RequiredSignature::Witness("SIG".to_string()),
        );
        ft.add_input(PartialInput::new(key_path_coin.clone()), RequiredSignature::None);
        ft.add_output(PartialOutput::new(
            context.random_signer().get_address().script_pubkey(),
            2 * AMOUNT - 1_000,
            seq,
        ));
        ft.add_output(PartialOutput::new(Script::new(), 1_000, seq));
        let (mut pst, _) = ft.extract_pst();

        // The key-path signature of input 1, ground until its first byte is, or is not, 0x50.
        let unsigned = pst.extract_tx()?;
        let prevouts = vec![simplicity_coin.txout.clone(), key_path_coin.txout.clone()];
        let sighash = SighashCache::new(&unsigned).taproot_key_spend_signature_hash(
            1,
            &Prevouts::All(&prevouts),
            SchnorrSighashType::Default,
            network.genesis_block_hash(),
        )?;
        let tweaked = keypair.tap_tweak(&secp, None).to_inner();
        let message = Message::from_digest(sighash.to_byte_array());
        let mut grinds = 0u64;
        let key_path_sig = loop {
            let mut aux = [0u8; 32];
            aux[..8].copy_from_slice(&grinds.to_le_bytes());
            let sig = secp.sign_schnorr_with_aux_rand(&message, &tweaked, &aux).serialize();
            if (sig[0] == ANNEX_TAG) == starts_with_tag {
                break sig;
            }
            grinds += 1;
        };

        if key_path_first {
            pst.inputs_mut()[1].final_script_witness = Some(vec![key_path_sig.to_vec()]);
        }
        let sig = signer.sign_program(&pst, &program, 0, &network, None, &SigMessage::Sighash)?;
        let values = OneKeyWitness {
            pk,
            sig: sig.serialize(),
        }
        .build_witness();
        let spend = program.finalize_spend(&pst, &values, 0, &network)?;
        pst.inputs_mut()[0].final_script_witness = Some(spend.stack);
        pst.inputs_mut()[1].final_script_witness = Some(vec![key_path_sig.to_vec()]);

        accepted(
            &utils,
            &format!(
                "{label} (key-path signature starts {:02x}, {grinds} grinds)",
                key_path_sig[0]
            ),
            &pst.extract_tx()?,
        )?;

        Ok(())
    };

    run("signed before the key-path signature is in place", false, true)?;
    run(
        "signed after a key-path signature starting 0x50 is in place",
        true,
        true,
    )?;
    run(
        "control: signed after a key-path signature not starting 0x50",
        true,
        false,
    )?;

    Ok(())
}
