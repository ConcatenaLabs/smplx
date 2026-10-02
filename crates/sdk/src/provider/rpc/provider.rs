use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::time::Duration;

use bitcoincore_rpc::{Auth, RpcApi};

use serde_json::{Value, json};

use simplicityhl::elements::encode;
use simplicityhl::elements::{Address, AssetId, OutPoint, Script, Transaction, Txid};

use crate::provider::SimplicityNetwork;
use crate::provider::core::ProviderTrait;
use crate::provider::error::ProviderError;
use crate::transaction::{TxReceipt, UTXO};

use super::elements::ElementsRpc;
use super::error::RpcError;

/// Confirmation targets reported by [`RpcProvider::fetch_fee_estimates`].
const FEE_TARGETS: [u32; 7] = [1, 2, 3, 6, 12, 25, 144];

/// A provider backed by a node's JSON-RPC interface alone, with no indexer.
///
/// Unspent outputs are found with `scantxoutset`, which reads the node's UTXO set, so an
/// output appears once it is confirmed. Transactions are read with `getrawtransaction`, which
/// needs `-txindex=1` for any transaction that is not the node wallet's own. With
/// `mine_on_broadcast` set, every broadcast is followed by one block, as on a local regtest.
#[derive(Debug)]
pub struct RpcProvider {
    /// The node's RPC client.
    pub rpc: ElementsRpc,
    network: SimplicityNetwork,
    mine_on_broadcast: bool,
}

impl RpcProvider {
    /// Connects to the node at `url`.
    ///
    /// # Errors
    /// Returns an `RpcError` if the client cannot be created or the node does not answer.
    pub fn new(url: String, auth: Auth, network: SimplicityNetwork, mine_on_broadcast: bool) -> Result<Self, RpcError> {
        Ok(Self {
            rpc: ElementsRpc::new(url, auth)?,
            network,
            mine_on_broadcast,
        })
    }

    fn call(&self, method: &str, args: &[Value]) -> Result<Value, ProviderError> {
        self.rpc
            .inner
            .call::<Value>(method, args)
            .map_err(|e| ProviderError::Rpc(RpcError::from(e)))
    }

    fn unexpected(method: &str) -> ProviderError {
        ProviderError::Rpc(RpcError::ElementsRpcUnexpectedReturn(method.to_string()))
    }

    /// The node's floor on a fee rate, in the fee rate's unit per vbyte: the larger of its relay
    /// fee and its mempool's minimum.
    fn fee_rate_floor(&self) -> Result<f64, ProviderError> {
        let relay = self.call("getnetworkinfo", &[])?["relayfee"].as_f64().unwrap_or(0.0);
        let mempool = self.call("getmempoolinfo", &[])?["mempoolminfee"]
            .as_f64()
            .unwrap_or(0.0);

        // Both are quoted per 1,000 vbytes in whole coins.
        Ok(relay.max(mempool) * 100_000_000.0 / 1_000.0)
    }
}

impl ProviderTrait for RpcProvider {
    fn get_network(&self) -> &SimplicityNetwork {
        &self.network
    }

    fn broadcast_transaction(&self, tx: &Transaction) -> Result<TxReceipt<'_>, ProviderError> {
        let result = self.call("sendrawtransaction", &[encode::serialize_hex(tx).into()]);

        let txid = match result {
            Ok(value) => value
                .as_str()
                .ok_or_else(|| Self::unexpected("sendrawtransaction"))
                .and_then(|s| Txid::from_str(s).map_err(|e| ProviderError::InvalidTxid(e.to_string())))?,
            Err(ProviderError::Rpc(RpcError::ElementsRpcError(e))) => {
                return Err(ProviderError::BroadcastRejected {
                    status: 0,
                    url: self.rpc.url.clone(),
                    message: e.to_string(),
                });
            }
            Err(e) => return Err(e),
        };

        if self.mine_on_broadcast {
            self.rpc.generate_blocks(1)?;
        }

        Ok(TxReceipt::new(self, txid))
    }

    fn wait(&self, txid: &Txid) -> Result<(), ProviderError> {
        for _ in 0..100 {
            if let Ok(tx) = self.call("getrawtransaction", &[txid.to_string().into(), true.into()])
                && tx["confirmations"].as_u64().unwrap_or(0) >= 1
            {
                return Ok(());
            }

            std::thread::sleep(Duration::from_millis(100));
        }

        Err(ProviderError::Confirmation())
    }

    fn fetch_tip_height(&self) -> Result<u32, ProviderError> {
        let height = self.call("getblockcount", &[])?;

        height
            .as_u64()
            .and_then(|h| u32::try_from(h).ok())
            .ok_or_else(|| Self::unexpected("getblockcount"))
    }

    fn fetch_tip_block_hash(&self) -> Result<String, ProviderError> {
        let hash = self.call("getbestblockhash", &[])?;

        hash.as_str()
            .map(ToString::to_string)
            .ok_or_else(|| Self::unexpected("getbestblockhash"))
    }

    fn fetch_tip_timestamp(&self) -> Result<u64, ProviderError> {
        let hash = self.fetch_tip_block_hash()?;
        let header = self.call("getblockheader", &[hash.into()])?;

        header["time"]
            .as_u64()
            .ok_or_else(|| Self::unexpected("getblockheader"))
    }

    fn fetch_block_hash_at_height(&self, block_height: u32) -> Result<String, ProviderError> {
        let hash = self.call("getblockhash", &[block_height.into()])?;

        hash.as_str()
            .map(ToString::to_string)
            .ok_or_else(|| Self::unexpected("getblockhash"))
    }

    fn fetch_block_txids(&self, block_hash: &str) -> Result<Vec<Txid>, ProviderError> {
        let block = self.call("getblock", &[block_hash.into(), 1.into()])?;

        block["tx"]
            .as_array()
            .ok_or_else(|| Self::unexpected("getblock"))?
            .iter()
            .map(|t| {
                t.as_str()
                    .ok_or_else(|| Self::unexpected("getblock"))
                    .and_then(|s| Txid::from_str(s).map_err(|e| ProviderError::InvalidTxid(e.to_string())))
            })
            .collect()
    }

    fn fetch_transaction(&self, txid: &Txid) -> Result<Transaction, ProviderError> {
        let raw = self.call("getrawtransaction", &[txid.to_string().into()])?;
        let raw = raw.as_str().ok_or_else(|| Self::unexpected("getrawtransaction"))?;
        let bytes = hex::decode(raw).map_err(|e| ProviderError::Deserialize(e.to_string()))?;

        encode::deserialize(&bytes).map_err(|e| ProviderError::Deserialize(e.to_string()))
    }

    fn fetch_address_utxos(&self, address: &Address) -> Result<Vec<UTXO>, ProviderError> {
        self.fetch_scripthash_utxos(&address.script_pubkey())
    }

    fn fetch_scripthash_utxos(&self, script: &Script) -> Result<Vec<UTXO>, ProviderError> {
        let descriptor = format!("raw({})", hex::encode(script.as_bytes()));
        let scan = self.call("scantxoutset", &["start".into(), json!([descriptor])])?;

        let unspents = scan["unspents"]
            .as_array()
            .ok_or_else(|| Self::unexpected("scantxoutset"))?;

        let mut outpoints = Vec::with_capacity(unspents.len());

        for unspent in unspents {
            let txid = unspent["txid"]
                .as_str()
                .ok_or_else(|| Self::unexpected("scantxoutset"))?;
            let vout = unspent["vout"]
                .as_u64()
                .ok_or_else(|| Self::unexpected("scantxoutset"))?;
            let txid = Txid::from_str(txid).map_err(|e| ProviderError::InvalidTxid(e.to_string()))?;
            let vout = u32::try_from(vout).map_err(|_| Self::unexpected("scantxoutset"))?;

            outpoints.push(OutPoint::new(txid, vout));
        }

        let mut transactions = HashMap::new();

        for txid in outpoints.iter().map(|p| p.txid).collect::<HashSet<_>>() {
            transactions.insert(txid, self.fetch_transaction(&txid)?);
        }

        outpoints
            .into_iter()
            .map(|outpoint| {
                let txout = transactions[&outpoint.txid]
                    .output
                    .get(outpoint.vout as usize)
                    .ok_or_else(ProviderError::BadResponse)?
                    .clone();

                Ok(UTXO {
                    outpoint,
                    txout,
                    secrets: None,
                })
            })
            .collect()
    }

    fn fetch_fee_estimates(&self) -> Result<HashMap<String, f64>, ProviderError> {
        let floor = self.fee_rate_floor()?;
        let mut estimates = HashMap::new();

        for target in FEE_TARGETS {
            // A node with too little history returns no `feerate`; the floor then stands.
            let estimate = self
                .call("estimatesmartfee", &[target.into()])
                .ok()
                .and_then(|v| v["feerate"].as_f64())
                .map_or(0.0, |per_kvb| per_kvb * 100_000_000.0 / 1_000.0);

            estimates.insert(target.to_string(), estimate.max(floor));
        }

        Ok(estimates)
    }

    fn has_fee_exchange_rates(&self) -> bool {
        true
    }

    fn fetch_fee_exchange_rate(&self, asset: AssetId) -> Result<Option<u64>, ProviderError> {
        Ok(self.rpc.fee_exchange_rate(asset)?)
    }
}
