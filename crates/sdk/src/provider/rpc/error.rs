/// Errors that can occur when calling JSON-RPC methods on a Bitcoin Core or Elements node.
#[derive(thiserror::Error, Debug)]
pub enum RpcError {
    /// Transparent wrapper mapping underlying errors generated directly from the Core/Elements RPC node client.
    #[error(transparent)]
    ElementsRpcError(#[from] bitcoincore_rpc::Error),

    /// Error indicating the requested Elements RPC call succeeded but the resulting JSON data payload did not map to the expected type or structure.
    #[error("Elements RPC returned an unexpected value for call {0}")]
    ElementsRpcUnexpectedReturn(String),

    /// Error indicating the node is not a Sequentia node: it does not answer `getfeeexchangerates`.
    #[error(
        "The node at {0} does not answer `getfeeexchangerates`, so it is not a Sequentia node. \
         This build of Simplex works with Sequentia only"
    )]
    NotSequentia(String),

    /// Error indicating a network this build refuses.
    #[error(transparent)]
    UnsupportedNetwork(#[from] crate::provider::UnsupportedNetwork),

    /// Error thrown when an invalid hex string fails to parse back into an exact byte array sequence.
    #[error("Failed to decode hex value to array, {0}")]
    BitcoinHashesHex(#[from] bitcoin_hashes::hex::HexToArrayError),
}
