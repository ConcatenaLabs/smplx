use std::time::Duration;

use smplx_sdk::provider::ElementsRpc;
use smplx_sdk::provider::SimplexProvider;
use smplx_sdk::provider::SimplicityNetwork;
use smplx_sdk::signer::Signer;
use smplx_sdk::utils::btc2sat;

use super::RegtestConfig;
use super::client::RegtestClient;
use super::error::RegtestError;
use super::sequentia::SequentiaRegtestClient;
use smplx_sdk::provider::RpcProvider;

pub struct Regtest {}

impl Regtest {
    /// Initializes an Elements regtest environment (`elementsd` and `electrs`), upstream's
    /// local chain. This build refuses it, since it speaks Sequentia's transaction encoding
    /// only: run [`Self::sequentia_from_config`] instead (`chain = "sequentia"`).
    ///
    /// # Errors
    /// Returns `RegtestError::UnsupportedNetwork` always.
    pub fn from_config(config: &RegtestConfig) -> Result<(RegtestClient, Signer), RegtestError> {
        SimplicityNetwork::default_regtest().require_sequentia()?;

        let client = RegtestClient::new(config);

        let provider = Box::new(SimplexProvider::new(
            client.esplora_url(),
            client.rpc_url(),
            client.auth(),
            SimplicityNetwork::default_regtest(),
        ));

        let signer = Signer::new(config.mnemonic.as_str(), provider);

        Self::prepare_signer(&client, &signer, config.bitcoins)?;

        Ok((client, signer))
    }

    /// Starts a Sequentia regtest chain and returns it with a signer funded on it.
    ///
    /// The signer reads the chain through the node's RPC alone ([`RpcProvider`]), and a block is
    /// mined after each broadcast.
    ///
    /// # Errors
    /// Returns a `RegtestError` if a node fails to start or a call to it fails.
    pub fn sequentia_from_config(config: &RegtestConfig) -> Result<(SequentiaRegtestClient, Signer), RegtestError> {
        let client = SequentiaRegtestClient::new(config)?;
        let provider = Box::new(RpcProvider::new(
            client.rpc_url(),
            client.auth(),
            client.network(),
            true,
        )?);
        let signer = Signer::new(config.mnemonic.as_str(), provider);

        client.fund(&signer.get_address().to_string(), btc2sat(config.bitcoins))?;

        Ok((client, signer))
    }

    fn prepare_signer(client: &RegtestClient, signer: &Signer, bitcoins: u64) -> Result<(), RegtestError> {
        let rpc_provider = ElementsRpc::new(client.rpc_url(), client.auth())?;

        rpc_provider.generate_blocks(1)?;
        rpc_provider.rescan_blockchain(None, None)?;
        rpc_provider.sweep_initialfreecoins()?;
        rpc_provider.generate_blocks(100)?;

        rpc_provider.send_to_address(&signer.get_address(), btc2sat(bitcoins), None)?;
        rpc_provider.generate_blocks(1)?;

        // wait for electrs to index
        let mut attempts = 0;

        loop {
            if !(signer.get_utxos()?).is_empty() {
                break;
            }

            attempts += 1;

            assert!(attempts <= 100, "Electrs failed to index the sweep after 10 seconds");

            std::thread::sleep(Duration::from_millis(100));
        }

        Ok(())
    }
}
