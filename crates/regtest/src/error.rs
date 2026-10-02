use std::io;

use smplx_sdk::provider::RpcError;
use smplx_sdk::signer::SignerError;

#[derive(thiserror::Error, Debug)]
pub enum RegtestError {
    #[error(transparent)]
    Rpc(#[from] RpcError),

    #[error(transparent)]
    Signer(#[from] SignerError),

    #[error("Failed to terminate elements")]
    ElementsTermination(),

    #[error("Failed to terminate electrs")]
    ElectrsTermination(),

    #[error("Failed to deserialize config: '{0}'")]
    ConfigDeserialize(#[from] toml::de::Error),

    #[error("io error occurred: '{0}'")]
    Io(#[from] io::Error),

    #[error("Failed to start the node: {0}")]
    NodeStart(String),

    #[error("Node call `{0}` failed: {1}")]
    NodeCall(String, String),
}
