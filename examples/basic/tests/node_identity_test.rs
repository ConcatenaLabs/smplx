//! A Sequentia node is known by what it answers, not by what a configuration calls it.
//!
//! A test configuration that points at this chain's node over RPC, and calls the chain Elements,
//! still gets the Sequentia network the node runs: the node answers `getfeeexchangerates`, which
//! no Elements node has. A transaction that moves only an issued asset then pays its fee in that
//! asset, as on any Sequentia network, and never in the policy asset.

mod common;

use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::Script;
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

use common::{accepted, set_fee_rate};

#[simplex::test]
fn a_sequentia_node_is_known_from_the_node(context: simplex::TestContext) -> anyhow::Result<()> {
    let network = *context.get_network();
    let utils = context.get_network_utils();
    let rpc = utils.rpc();
    let (Some(user), Some(password)) = rpc.auth.clone().get_user_pass()? else {
        anyhow::bail!("the node has a user and a password");
    };

    // The misconfiguration: this Sequentia node, named an Elements chain.
    let path = std::env::temp_dir().join(format!("smplx-node-identity-{}.toml", std::process::id()));
    std::fs::write(
        &path,
        format!(
            "mnemonic = \"{}\"\nbitcoins = 1\n\n[rpc]\nurl = \"{}\"\nusername = \"{user}\"\npassword = \"{password}\"\n\n[regtest]\nchain = \"elements\"\n",
            context.get_config().mnemonic,
            rpc.url
        ),
    )?;
    let other = simplex::TestContext::new(path.clone());
    std::fs::remove_file(&path)?;
    let other = other?;

    println!("network read from the node: {:?}", other.get_network());
    anyhow::ensure!(
        matches!(other.get_network(), SimplicityNetwork::SequentiaRegtest { .. }),
        "the node was not taken for a Sequentia network"
    );
    anyhow::ensure!(*other.get_network() == network, "a different network was read");

    // A transaction that moves only an issued asset pays its fee in it.
    let signer = other.get_default_signer();
    let policy = network.policy_asset();
    let mut funding = signer.get_utxos_asset(policy)?;
    funding.sort_by_key(|coin| std::cmp::Reverse(coin.amount()));
    let mut issuance = FinalTransaction::new();
    let gold = issuance
        .add_issuance_input(
            PartialInput::new(funding[0].clone()),
            IssuanceInput::new_issuance(1_000_000, 0, [5; 32]),
            RequiredSignature::NativeEcdsa,
        )
        .asset_id;
    issuance.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        1_000_000,
        gold,
    ));
    signer.broadcast(&issuance)?.wait()?;
    set_fee_rate(&utils, gold, 100_000_000)?;

    let mut ft = FinalTransaction::new();
    ft.add_output(PartialOutput::new(
        context.random_signer().get_address().script_pubkey(),
        400_000,
        gold,
    ));
    let (tx, fee) = signer.finalize(&ft)?;
    let fee_output = tx
        .output
        .iter()
        .find(|output| output.script_pubkey == Script::new())
        .ok_or_else(|| anyhow::anyhow!("no fee output"))?;
    println!("fee {fee}, paid in {:?}", fee_output.asset.explicit());
    anyhow::ensure!(
        fee_output.asset.explicit() == Some(gold),
        "the fee is not paid in the asset moved"
    );
    anyhow::ensure!(
        tx.output.iter().all(|output| output.asset.explicit() == Some(gold)),
        "a transaction moving only the issued asset touched another"
    );
    accepted(
        &utils,
        "fee in the asset moved, through a node configured as Elements",
        &tx,
    )?;

    Ok(())
}
