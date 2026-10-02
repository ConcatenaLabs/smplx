use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::error::RegtestError;

pub const DEFAULT_REGTEST_MNEMONIC: &str = "exist carry drive collect lend cereal occur much tiger just involve mean";
pub const DEFAULT_BITCOINS: u64 = 10_000_000;

/// The chain a local regtest runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegtestChain {
    /// `elementsd` and `electrs` on a Liquid regtest chain.
    #[default]
    Elements,
    /// `sequentiad` on an anchored Sequentia custom chain, read over RPC with no indexer.
    Sequentia,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RegtestConfig {
    /// The chain to run.
    pub chain: RegtestChain,
    pub mnemonic: String,
    pub bitcoins: u64,
    pub rpc_port: Option<u16>,
    pub esplora_port: Option<u16>,
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
    /// The node binary. Unset, it is looked up on `PATH` by its default name.
    pub node_bin: Option<PathBuf>,
    /// The indexer binary. Unset, it is looked up on `PATH` by its default name.
    pub electrs_bin: Option<PathBuf>,
}

impl RegtestConfig {
    /// Loads a `RegtestConfig` from a specified TOML file.
    ///
    /// # Errors
    /// Returns a `RegtestError` if the file cannot be opened, read, or if the contents are not valid TOML.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, RegtestError> {
        let mut content = String::new();
        let mut file = OpenOptions::new().read(true).open(path)?;

        file.read_to_string(&mut content)?;

        Ok(toml::from_str(&content)?)
    }
}

impl Default for RegtestConfig {
    fn default() -> Self {
        Self {
            chain: RegtestChain::Elements,
            mnemonic: DEFAULT_REGTEST_MNEMONIC.to_string(),
            bitcoins: DEFAULT_BITCOINS,
            rpc_port: None,
            esplora_port: None,
            rpc_user: None,
            rpc_password: None,
            node_bin: None,
            electrs_bin: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_config_is_loaded_and_defaults_are_safe() {
        let path = std::env::temp_dir().join(format!("smplx-regtest-config-{}.toml", std::process::id()));
        std::fs::write(
            &path,
            r#"
                mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                bitcoins = 42
                rpc_port = 18443
                esplora_port = 3000
                rpc_user = "user"
                rpc_password = "password"
                node_bin = "/opt/elements/bin/elementsd"
                chain = "sequentia"
            "#,
        )
        .expect("regtest config should be writable");

        let loaded = RegtestConfig::from_file(&path).expect("regtest config should load");
        let defaults = RegtestConfig::default();

        assert_eq!(loaded.bitcoins, 42);
        assert_eq!(loaded.rpc_port, Some(18443));
        assert_eq!(loaded.esplora_port, Some(3000));
        assert_eq!(loaded.rpc_user.as_deref(), Some("user"));
        assert_eq!(loaded.rpc_password.as_deref(), Some("password"));
        assert_eq!(
            loaded.node_bin.as_deref(),
            Some(Path::new("/opt/elements/bin/elementsd"))
        );
        assert!(loaded.electrs_bin.is_none());
        assert_eq!(loaded.chain, RegtestChain::Sequentia);
        assert_eq!(defaults.chain, RegtestChain::Elements);
        assert!(defaults.rpc_port.is_none());
        assert!(defaults.esplora_port.is_none());

        let _ = std::fs::remove_file(path);
    }
}
