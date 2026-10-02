use std::path::PathBuf;

use electrsd::bitcoind::bitcoincore_rpc::Auth;

use smplx_regtest::Regtest;
use smplx_regtest::client::RegtestClient;
use smplx_regtest::sequentia::SequentiaRegtestClient;

use smplx_sdk::global::GlobalConfig;
use smplx_sdk::provider::{
    ElementsRpc, EsploraProvider, ProviderError, ProviderInfo, ProviderTrait, RpcProvider, SimplexProvider,
    SimplicityNetwork, UnsupportedNetwork,
};
use smplx_sdk::signer::Signer;
use smplx_sdk::utils::random_mnemonic;

use crate::config::TestConfig;
use crate::error::TestError;
use crate::network_utils::NetworkUtils;

#[allow(dead_code)]
pub struct TestContext {
    _client: Option<RegtestClient>,
    _sequentia: Option<SequentiaRegtestClient>,
    // the chain is read over node RPC alone, with no Esplora
    rpc_only: bool,
    // since providers can't be cloned, we need this variable to create new signers
    _provider_info: ProviderInfo,
    config: TestConfig,
    signer: Signer,
}

impl TestContext {
    pub fn new(config_path: PathBuf) -> Result<Self, TestError> {
        let config = TestConfig::from_file(&config_path)?;

        // error is ignored because we assume that all tests use the same verbosity
        let _ = GlobalConfig::set_global_config(config.verbosity);

        let (signer, provider_info, client, sequentia) = Self::setup(&config)?;
        let rpc_only = provider_info.esplora_url.is_empty();

        Ok(Self {
            _client: client,
            _sequentia: sequentia,
            rpc_only,
            _provider_info: provider_info,
            config,
            signer,
        })
    }

    pub fn create_signer(&self, mnemonic: &str) -> Signer {
        let provider: Box<dyn ProviderTrait> = if self.rpc_only {
            Box::new(
                RpcProvider::new(
                    self._provider_info.elements_url.clone().unwrap(),
                    self._provider_info.auth.clone().unwrap(),
                    *self.get_network(),
                    true,
                )
                .expect("the node answered when the context was set up"),
            )
        } else if self._provider_info.elements_url.is_some() {
            // local regtest or external regtest
            Box::new(SimplexProvider::new(
                self._provider_info.esplora_url.clone(),
                self._provider_info.elements_url.clone().unwrap(),
                self._provider_info.auth.clone().unwrap(),
                *self.get_network(),
            ))
        } else {
            // external esplora
            Box::new(EsploraProvider::new(
                self._provider_info.esplora_url.clone(),
                *self.get_network(),
            ))
        };

        Signer::new(mnemonic, provider)
    }

    pub fn random_signer(&self) -> Signer {
        self.create_signer(random_mnemonic().as_str())
    }

    pub fn get_default_signer(&self) -> &Signer {
        &self.signer
    }

    /// # Panics
    /// Panics when the signer was built without a provider, which a test context never is.
    pub fn get_default_provider(&self) -> &dyn ProviderTrait {
        self.signer
            .get_provider()
            .expect("a test context always has a provider")
    }

    pub fn get_config(&self) -> &TestConfig {
        &self.config
    }

    /// # Panics
    /// Panics when the signer was built without a provider, which a test context never is.
    pub fn get_network(&self) -> &SimplicityNetwork {
        self.get_default_provider().get_network()
    }

    pub fn get_network_utils(&self) -> NetworkUtils {
        assert!(
            self._client.is_some() || self._sequentia.is_some(),
            "Network utils only available in Regtest network"
        );

        let regtest_rpc = ElementsRpc::new(
            self._provider_info.elements_url.clone().unwrap(),
            self._provider_info.auth.clone().unwrap(),
        )
        .expect("Failed to create rpc client for network utils");

        let network = *self.get_network();
        let reader: Box<dyn ProviderTrait> = if self.rpc_only {
            Box::new(
                RpcProvider::new(
                    self._provider_info.elements_url.clone().unwrap(),
                    self._provider_info.auth.clone().unwrap(),
                    network,
                    false,
                )
                .expect("Failed to create rpc provider for network utils"),
            )
        } else {
            Box::new(EsploraProvider::new(self._provider_info.esplora_url.clone(), network))
        };

        NetworkUtils::new(regtest_rpc, reader)
    }

    #[allow(clippy::type_complexity)]
    fn setup(
        config: &TestConfig,
    ) -> Result<
        (
            Signer,
            ProviderInfo,
            Option<RegtestClient>,
            Option<SequentiaRegtestClient>,
        ),
        TestError,
    > {
        let mut sequentia: Option<SequentiaRegtestClient> = None;
        let client: Option<RegtestClient>;
        let provider_info: ProviderInfo;
        let signer: Signer;

        match config.esplora.clone() {
            Some(esplora) => match config.rpc.clone() {
                Some(rpc) => {
                    // an external node with an Esplora beside it; the chain is read from the node
                    let auth = Auth::UserPass(rpc.username, rpc.password);
                    let network = Self::network_from_node(&rpc.url, &auth)?;
                    let provider = Box::new(SimplexProvider::new(
                        esplora.url.clone(),
                        rpc.url.clone(),
                        auth.clone(),
                        network,
                    ));

                    provider_info = ProviderInfo {
                        esplora_url: esplora.url,
                        elements_url: Some(rpc.url),
                        auth: Some(auth),
                    };
                    signer = Signer::new(config.mnemonic.as_str(), provider);
                    client = None;
                }
                None => {
                    // external esplora network
                    let network = match esplora.network.as_str() {
                        "SequentiaTestnet" => SimplicityNetwork::SequentiaTestnet,
                        "Liquid" => return Err(UnsupportedNetwork(SimplicityNetwork::Liquid).into()),
                        "LiquidTestnet" => return Err(UnsupportedNetwork(SimplicityNetwork::LiquidTestnet).into()),
                        "ElementsRegtest" => {
                            return Err(UnsupportedNetwork(SimplicityNetwork::default_regtest()).into());
                        }
                        other => return Err(TestError::BadNetworkName(other.to_string())),
                    };
                    let provider = Box::new(EsploraProvider::new(esplora.url.clone(), network));

                    provider_info = ProviderInfo {
                        esplora_url: esplora.url,
                        elements_url: None,
                        auth: None,
                    };
                    signer = Signer::new(config.mnemonic.as_str(), provider);
                    client = None;
                }
            },
            None => match (config.rpc.clone(), config.to_regtest_config()) {
                (Some(rpc), _) => {
                    // an external node read over RPC alone; the chain is read from the node
                    let auth = Auth::UserPass(rpc.username, rpc.password);
                    let network = Self::network_from_node(&rpc.url, &auth)?;
                    let provider = Box::new(
                        RpcProvider::new(rpc.url.clone(), auth.clone(), network, true).map_err(ProviderError::from)?,
                    );

                    provider_info = ProviderInfo {
                        esplora_url: String::new(),
                        elements_url: Some(rpc.url),
                        auth: Some(auth),
                    };
                    signer = Signer::new(config.mnemonic.as_str(), provider);
                    client = None;
                }
                (None, regtest) if regtest.chain == smplx_regtest::RegtestChain::Sequentia => {
                    // simplex inner Sequentia chain, read over RPC alone
                    let (sequentia_client, regtest_signer) = Regtest::sequentia_from_config(&regtest)?;

                    provider_info = ProviderInfo {
                        esplora_url: String::new(),
                        elements_url: Some(sequentia_client.rpc_url()),
                        auth: Some(sequentia_client.auth()),
                    };
                    signer = regtest_signer;
                    client = None;
                    sequentia = Some(sequentia_client);
                }
                (None, regtest) => {
                    // upstream's Elements regtest, which this build refuses
                    let (regtest_client, regtest_signer) = Regtest::from_config(&regtest)?;

                    provider_info = ProviderInfo {
                        esplora_url: regtest_client.esplora_url(),
                        elements_url: Some(regtest_client.rpc_url()),
                        auth: Some(regtest_client.auth()),
                    };
                    signer = regtest_signer;
                    client = Some(regtest_client);
                }
            },
        }

        Ok((signer, provider_info, client, sequentia))
    }

    /// Reads a node's chain from the node itself, never from a configuration key: a Sequentia
    /// node answers `getfeeexchangerates`, and its genesis says which Sequentia network it runs.
    /// Any other node is refused, so a misconfigured one is never treated as Elements.
    fn network_from_node(url: &str, auth: &Auth) -> Result<SimplicityNetwork, TestError> {
        let rpc = ElementsRpc::new(url.to_string(), auth.clone()).map_err(ProviderError::from)?;

        Ok(rpc.sequentia_network().map_err(ProviderError::from)?)
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        if let Some(x) = &mut self._client {
            let _ = x.kill();
        }

        if let Some(x) = &mut self._sequentia {
            x.kill();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn invalid_network_returns_error() {
        let config = r#"
            mnemonic = "exist carry drive collect lend cereal occur much tiger just involve mean"
            bitcoins = 10000

            [esplora]
            url = "http://localhost:3000"
            network = "InvalidNetwork"
        "#;

        let path = std::env::temp_dir().join("smplx_test_invalid_network.toml");
        fs::write(&path, config).unwrap();

        let result = TestContext::new(path);
        let Err(e) = result else {
            panic!("expected BadNetworkName error")
        };
        assert!(
            matches!(e, TestError::BadNetworkName(ref s) if s == "InvalidNetwork"),
            "expected BadNetworkName, got: {e}"
        );
    }

    #[test]
    fn liquid_and_elements_networks_are_refused() {
        for (name, network) in [
            ("Liquid", SimplicityNetwork::Liquid),
            ("LiquidTestnet", SimplicityNetwork::LiquidTestnet),
            ("ElementsRegtest", SimplicityNetwork::default_regtest()),
        ] {
            let config = format!(
                r#"
                mnemonic = "exist carry drive collect lend cereal occur much tiger just involve mean"
                bitcoins = 10000

                [esplora]
                url = "http://localhost:3000"
                network = "{name}"
            "#
            );

            let path = std::env::temp_dir().join(format!("smplx_test_refused_{name}_{}.toml", std::process::id()));
            fs::write(&path, config).unwrap();

            let Err(e) = TestContext::new(path.clone()) else {
                panic!("{name} was accepted")
            };
            let _ = fs::remove_file(path);
            assert!(
                matches!(e, TestError::Unsupported(refused) if refused == UnsupportedNetwork(network)),
                "{name}: expected the network refused, got: {e}"
            );
        }
    }

    #[test]
    fn an_elements_regtest_is_refused() {
        let config = r#"
            mnemonic = "exist carry drive collect lend cereal occur much tiger just involve mean"
            bitcoins = 10000

            [regtest]
            chain = "elements"
        "#;

        let path = std::env::temp_dir().join(format!("smplx_test_elements_regtest_{}.toml", std::process::id()));
        fs::write(&path, config).unwrap();

        let Err(e) = TestContext::new(path.clone()) else {
            panic!("an Elements regtest was started")
        };
        let _ = fs::remove_file(path);
        assert!(
            e.to_string().contains("Sequentia's transaction encoding only"),
            "expected the Elements regtest refused, got: {e}"
        );
    }
}
